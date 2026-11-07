package com.vg.run

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Late-delivered FCM wake suppression (2026-10-14) — pure-policy tests for
 * [PushWakeFreshness.shouldSuppressWake] and its strict stamp parser. The rule:
 * suppress ONLY when the wake was positively sent more than the margin before the
 * last complete inbox sweep began; every ambiguous input shows the banner.
 */
class PushWakeFreshnessTest {

    private val margin = PushWakeFreshness.MARGIN_MS
    private val sweep = 1_760_371_140_000L          // a realistic epoch-ms sweep start
    private val now = sweep + 22L * 3_600_000L      // the wake lands ~22 h later

    @Test
    fun absentSentTime_showsTheBanner() {
        assertFalse(PushWakeFreshness.shouldSuppressWake(0L, sweep, now, margin))
        assertFalse(PushWakeFreshness.shouldSuppressWake(-1L, sweep, now, margin))
    }

    @Test
    fun absentLastSweep_showsTheBanner() {
        val sent = sweep - 3_600_000L
        assertFalse(PushWakeFreshness.shouldSuppressWake(sent, 0L, now, margin))
        assertFalse(PushWakeFreshness.shouldSuppressWake(sent, -5L, now, margin))
    }

    @Test
    fun freshWake_sentAfterTheSweep_showsTheBanner() {
        assertFalse(PushWakeFreshness.shouldSuppressWake(sweep + 60_000L, sweep, now, margin))
    }

    @Test
    fun staleWake_sentWellBeforeTheSweep_isSuppressed() {
        // The 2026-10-14 incident shape: sent 15:04, sweep at 15:59, delivered next day.
        val sent = sweep - 55L * 60_000L
        assertTrue(PushWakeFreshness.shouldSuppressWake(sent, sweep, now, margin))
    }

    @Test
    fun wakeWithinTheMargin_showsTheBanner() {
        assertFalse(PushWakeFreshness.shouldSuppressWake(sweep - 60_000L, sweep, now, margin))
        // Exactly at the margin is still "in doubt".
        assertFalse(PushWakeFreshness.shouldSuppressWake(sweep - margin, sweep, now, margin))
        // One ms past it is the first suppressed value.
        assertTrue(PushWakeFreshness.shouldSuppressWake(sweep - margin - 1L, sweep, now, margin))
    }

    @Test
    fun futureSkewedSentTime_showsTheBanner() {
        // FCM's clock (or ours) is wrong by more than the margin: the two events
        // cannot be ordered, so nothing is suppressed.
        val sent = now + margin + 1L
        assertFalse(PushWakeFreshness.shouldSuppressWake(sent, now + 2L * margin + 10L, now, margin))
        assertFalse(PushWakeFreshness.shouldSuppressWake(sent, sweep, now, margin))
    }

    @Test
    fun futureStampedSweep_suppressesNothing() {
        // Phone clock was ahead when the stamp was written, then corrected back
        // (or the value was planted far in the future): not evidence of anything.
        val futureSweep = now + margin + 1L
        assertFalse(PushWakeFreshness.shouldSuppressWake(sweep, futureSweep, now, margin))
        assertFalse(PushWakeFreshness.shouldSuppressWake(1L, Long.MAX_VALUE, now, margin))
    }

    @Test
    fun extremeValues_doNotOverflowIntoASuppression() {
        assertFalse(PushWakeFreshness.shouldSuppressWake(Long.MAX_VALUE, Long.MAX_VALUE, Long.MAX_VALUE, margin))
        assertFalse(PushWakeFreshness.shouldSuppressWake(1L, sweep, now, -1L))
    }

    @Test
    fun productionMargin_isFiveMinutes() {
        assertEquals(5L * 60_000L, PushWakeFreshness.MARGIN_MS)
    }

    @Test
    fun parseStamp_isStrict() {
        assertEquals(sweep, PushWakeFreshness.parseStamp(sweep.toString()))
        assertNull(PushWakeFreshness.parseStamp(null))
        assertNull(PushWakeFreshness.parseStamp(""))
        assertNull(PushWakeFreshness.parseStamp("0"))
        assertNull(PushWakeFreshness.parseStamp("+123"))
        assertNull(PushWakeFreshness.parseStamp("-123"))
        assertNull(PushWakeFreshness.parseStamp(" 123"))
        assertNull(PushWakeFreshness.parseStamp("12a3"))
        assertNull(PushWakeFreshness.parseStamp("١٢٣"))      // Arabic-Indic digits
        assertNull(PushWakeFreshness.parseStamp("99999999999999999999"))  // 20 digits
        assertNull(PushWakeFreshness.parseStamp("9999999999999999999"))   // 19 digits, > Long.MAX
    }

    // -----------------------------------------------------------------------
    // Edge cases added 2026-10-15 — every one of them must FAIL TOWARD SHOWING
    // the banner. The gate's only `true` is "positively sent more than the
    // margin before the last complete sweep began".
    // -----------------------------------------------------------------------

    @Test
    fun absentNow_showsTheBanner() {
        // A wall clock of 0 / negative is not a clock we can order anything by.
        val sent = sweep - 3_600_000L
        assertFalse(PushWakeFreshness.shouldSuppressWake(sent, sweep, 0L, margin))
        assertFalse(PushWakeFreshness.shouldSuppressWake(sent, sweep, -1L, margin))
    }

    @Test
    fun sentTimeInOurFuture_withinTheMargin_isOrderedNormally() {
        // ≤ margin ahead of our clock is tolerated skew; the ordering test still
        // runs and a wake "sent" after the sweep is of course shown.
        val sent = now + margin
        assertFalse(PushWakeFreshness.shouldSuppressWake(sent, sweep, now, margin))
        assertFalse(PushWakeFreshness.shouldSuppressWake(sent, now, now, margin))
    }

    @Test
    fun sentTimeInOurFuture_beyondTheMargin_showsTheBanner_evenAgainstAFarFutureSweep() {
        // Both inputs implausible: nothing can be concluded, so nothing is dropped.
        val sent = now + margin + 1L
        assertFalse(PushWakeFreshness.shouldSuppressWake(sent, sent + margin + 1L, now, margin))
        assertFalse(PushWakeFreshness.shouldSuppressWake(sent, Long.MAX_VALUE, now, margin))
    }

    @Test
    fun lastSweepMinusSentTime_exactlyTheMargin_showsTheBanner() {
        assertFalse(PushWakeFreshness.shouldSuppressWake(sweep - margin, sweep, now, margin))
    }

    @Test
    fun lastSweepMinusSentTime_oneMsPastTheMargin_isSuppressed() {
        assertTrue(PushWakeFreshness.shouldSuppressWake(sweep - margin - 1L, sweep, now, margin))
    }

    @Test
    fun wakeSentAfterTheSweep_showsTheBanner_regardlessOfDeliveryDelay() {
        // The whole point: a wake for a message that landed AFTER the sweep is
        // never a "notification with no message", however late FCM delivers it.
        for (sentAfterSweep in listOf(1L, 1_000L, 60_000L, 3_600_000L, 20L * 3_600_000L)) {
            val sent = sweep + sentAfterSweep
            assertFalse(
                "sent $sentAfterSweep ms after the sweep must show",
                PushWakeFreshness.shouldSuppressWake(sent, sweep, sent + 22L * 3_600_000L, margin),
            )
        }
    }

    @Test
    fun clockSteppedBack_byLessThanTheMargin_betweenStampAndWake_showsAWakeSentAfterTheSweep() {
        // The phone's clock was `step` ahead when the sweep was stamped and has
        // since been corrected. A wake sent `a` after the sweep in REAL time, under
        // the corrected clock: sweep - sent = step - a ≤ margin ⇒ shown, for ANY
        // delivery delay d, as long as step ≤ margin.
        val realSweep = 1_760_371_140_000L
        for (step in listOf(1L, 60_000L, margin - 1L, margin)) {
            val stamped = realSweep + step
            for (a in listOf(1L, 30_000L, 10L * 60_000L)) {
                val sent = realSweep + a
                for (d in listOf(0L, 1_000L, 10L * 60_000L, 20L * 3_600_000L)) {
                    assertFalse(
                        "step=$step a=$a d=$d: a wake sent after the sweep must show",
                        PushWakeFreshness.shouldSuppressWake(sent, stamped, sent + d, margin),
                    )
                }
            }
        }
    }

    @Test
    fun clockSteppedBack_byMoreThanTheMargin_aStampStillInOurFuture_suppressesNothing() {
        // A stamp more than the margin ahead of our clock is not evidence about
        // anything that happened (a planted value looks the same).
        val stamped = now + margin + 1L
        assertFalse(PushWakeFreshness.shouldSuppressWake(now - 60_000L, stamped, now, margin))
        assertFalse(PushWakeFreshness.shouldSuppressWake(now - 24L * 3_600_000L, stamped, now, margin))
        assertFalse(PushWakeFreshness.shouldSuppressWake(1L, stamped, now, margin))
    }

    @Test
    fun clockSteppedForward_betweenStampAndWake_showsAWakeSentAfterTheSweep() {
        // The phone's clock was BEHIND at stamp time and later corrected forward:
        // the stamp is EARLIER than the truth, which can only ever suppress less.
        val realSweep = 1_760_371_140_000L
        val stamped = realSweep - 24L * 3_600_000L
        assertFalse(PushWakeFreshness.shouldSuppressWake(realSweep + 1L, stamped, realSweep + 2L, margin))
        // …and a genuinely stale wake (sent long before even the understated
        // stamp) is still caught.
        assertTrue(PushWakeFreshness.shouldSuppressWake(stamped - 3_600_000L, stamped, realSweep, margin))
    }

    // -----------------------------------------------------------------------
    // The production composition the FCM service runs: raw stamp string →
    // strict parse → gate at MARGIN_MS. Same fail direction.
    // -----------------------------------------------------------------------

    @Test
    fun staleWakeFromStamp_absentOrUnparseableStamp_showsTheBanner() {
        val staleSent = sweep - 3_600_000L   // would be suppressed under a valid stamp
        for (raw in listOf(null, "", "0", "-1", "abc", " $sweep", "$sweep ", "+$sweep", "1e12", "١٢٣",
            "99999999999999999999")) {
            assertFalse("raw stamp [$raw] must show", PushWakeFreshness.staleWakeFromStamp(raw, staleSent, now))
        }
    }

    @Test
    fun staleWakeFromStamp_validStamp_appliesTheProductionMargin() {
        val raw = sweep.toString()
        // The incident shape: sent 55 min before the sweep, delivered ~22 h later.
        assertTrue(PushWakeFreshness.staleWakeFromStamp(raw, sweep - 55L * 60_000L, now))
        // At the margin: shown. Past it: suppressed.
        assertFalse(PushWakeFreshness.staleWakeFromStamp(raw, sweep - PushWakeFreshness.MARGIN_MS, now))
        assertTrue(PushWakeFreshness.staleWakeFromStamp(raw, sweep - PushWakeFreshness.MARGIN_MS - 1L, now))
        // Sent after the sweep: shown.
        assertFalse(PushWakeFreshness.staleWakeFromStamp(raw, sweep + 1L, now))
        // FCM supplied no sentTime (0): shown.
        assertFalse(PushWakeFreshness.staleWakeFromStamp(raw, 0L, now))
    }

    @Test
    fun staleWakeFromStamp_plantedFarFutureStamp_showsTheBanner() {
        assertFalse(PushWakeFreshness.staleWakeFromStamp(Long.MAX_VALUE.toString(), sweep, now))
        assertFalse(PushWakeFreshness.staleWakeFromStamp((now + PushWakeFreshness.MARGIN_MS + 1L).toString(), sweep, now))
    }
}

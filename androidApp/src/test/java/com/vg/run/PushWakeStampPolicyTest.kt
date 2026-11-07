package com.vg.run

import com.vg.run.PushWakeFreshness.SweepStampAction
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Late-delivered FCM wake suppression (2026-10-14) — the STAMP policy.
 *
 * [PushWakeFreshness.sweepStampAction] is the pure decision `RunViewModel`'s
 * control-poll cycle feeds (through [PushWakeFreshness.recordInboxSweep]) at the
 * end of every cycle. It was lifted out of the inline `RunViewModel` logic on
 * 2026-10-15 with identical semantics so these rules are pinnable without a
 * `Context`; `PushWakeFreshnessWiringSourceTest` pins that the ViewModel still
 * hands it the right facts (the cycle START time, the sweep-completeness
 * callback, the control-pass flag).
 *
 * Every rule fails toward NOT stamping — a missing stamp costs one stale banner,
 * a wrong stamp costs a real one.
 */
class PushWakeStampPolicyTest {

    private val t0 = 1_760_371_140_000L
    private val interval = PushWakeFreshness.MIN_REWRITE_INTERVAL_MS

    private fun decide(
        level: NotificationLevel = NotificationLevel.VENDOR_PUSH,
        sweepComplete: Boolean = true,
        controlPassRan: Boolean = true,
        sweepStartedAtMs: Long = t0,
        lastRecordedMs: Long? = null,
        wipedInProcess: Boolean = false,
    ) = PushWakeFreshness.sweepStampAction(
        level, sweepComplete, controlPassRan, sweepStartedAtMs, lastRecordedMs, wipedInProcess,
    )

    // -- the happy path ------------------------------------------------------

    @Test
    fun vendorPush_completeSweep_controlPassRan_noPriorStamp_writes() {
        assertEquals(SweepStampAction.WRITE, decide())
    }

    @Test
    fun productionRewriteInterval_isSixtySeconds() {
        assertEquals(60_000L, PushWakeFreshness.MIN_REWRITE_INTERVAL_MS)
    }

    // -- not VENDOR_PUSH → no stamp (and the self-clean) -----------------------

    @Test
    fun notVendorPush_neverWrites_andClearsOnACompleteSweep() {
        for (level in NotificationLevel.entries.filter { it != NotificationLevel.VENDOR_PUSH }) {
            assertEquals("level $level must self-clean", SweepStampAction.CLEAR, decide(level = level))
        }
    }

    @Test
    fun notVendorPush_onAnIncompleteSweep_doesNothing() {
        // The self-clean rides a COMPLETE sweep only, exactly as shipped: an
        // incomplete sweep under OFF leaves the stamp alone (it is harmless there
        // — the FCM service never consults it unless the level is VENDOR_PUSH).
        for (level in NotificationLevel.entries.filter { it != NotificationLevel.VENDOR_PUSH }) {
            assertEquals(SweepStampAction.NONE, decide(level = level, sweepComplete = false))
            assertEquals(SweepStampAction.NONE, decide(level = level, controlPassRan = false))
        }
    }

    // -- incomplete → no stamp -------------------------------------------------

    @Test
    fun incompleteSweep_doesNotStamp() {
        assertEquals(SweepStampAction.NONE, decide(sweepComplete = false))
    }

    @Test
    fun controlPassThrew_doesNotStamp() {
        assertEquals(SweepStampAction.NONE, decide(controlPassRan = false))
    }

    @Test
    fun incompleteSweep_doesNotClearAnExistingStampEither() {
        // A stamp from an earlier complete sweep stays — it is still true that
        // every inbox had been observed as of THAT start time.
        assertEquals(SweepStampAction.NONE, decide(sweepComplete = false, lastRecordedMs = t0 - 3_600_000L))
    }

    // -- throttle ----------------------------------------------------------------

    @Test
    fun lessThanSixtySecondsSinceTheLastStamp_doesNotRewrite() {
        assertEquals(SweepStampAction.NONE, decide(sweepStartedAtMs = t0, lastRecordedMs = t0))
        assertEquals(SweepStampAction.NONE, decide(sweepStartedAtMs = t0 + 1L, lastRecordedMs = t0))
        assertEquals(SweepStampAction.NONE, decide(sweepStartedAtMs = t0 + interval - 1L, lastRecordedMs = t0))
    }

    @Test
    fun exactlySixtySecondsSinceTheLastStamp_rewrites() {
        assertEquals(SweepStampAction.WRITE, decide(sweepStartedAtMs = t0 + interval, lastRecordedMs = t0))
        assertEquals(SweepStampAction.WRITE, decide(sweepStartedAtMs = t0 + 90_000L, lastRecordedMs = t0))
    }

    @Test
    fun aSweepStartEarlierThanTheStoredStamp_isWritten() {
        // Backward clock step between two cycles: the stamp moves EARLIER, which
        // can only ever suppress less. Not throttled, not refused.
        assertEquals(SweepStampAction.WRITE, decide(sweepStartedAtMs = t0 - 1L, lastRecordedMs = t0))
        assertEquals(SweepStampAction.WRITE, decide(sweepStartedAtMs = t0 - 24L * 3_600_000L, lastRecordedMs = t0))
    }

    // -- the recorded value is the START, and must be a clock ----------------------

    @Test
    fun nonPositiveSweepStart_isNeverWritten() {
        assertEquals(SweepStampAction.NONE, decide(sweepStartedAtMs = 0L))
        assertEquals(SweepStampAction.NONE, decide(sweepStartedAtMs = -1L))
        assertEquals(SweepStampAction.NONE, decide(sweepStartedAtMs = Long.MIN_VALUE))
    }

    @Test
    fun theThrottleIsMeasuredOnSweepStarts_notOnAnyOtherClock() {
        // The signature takes no "now": with identical starts the answer cannot
        // depend on how long the sweep took, so the value written is always the
        // START the caller captured before its first request.
        assertEquals(SweepStampAction.WRITE, decide(sweepStartedAtMs = t0 + interval, lastRecordedMs = t0))
        assertEquals(SweepStampAction.NONE, decide(sweepStartedAtMs = t0 + interval - 1L, lastRecordedMs = t0))
    }

    // -- after an in-process wipe → never ------------------------------------------

    @Test
    fun afterAnInProcessWipe_nothingIsWrittenOrRemoved_forAnyInput() {
        for (level in NotificationLevel.entries) {
            for (complete in listOf(true, false)) {
                for (ran in listOf(true, false)) {
                    for (prev in listOf<Long?>(null, t0 - 3_600_000L, t0)) {
                        assertEquals(
                            "wiped: level=$level complete=$complete ran=$ran prev=$prev",
                            SweepStampAction.NONE,
                            decide(
                                level = level, sweepComplete = complete, controlPassRan = ran,
                                sweepStartedAtMs = t0 + interval, lastRecordedMs = prev, wipedInProcess = true,
                            ),
                        )
                    }
                }
            }
        }
    }

    // -- exhaustive shape --------------------------------------------------------------

    @Test
    fun writeOnlyEverHappens_underVendorPush_onACompleteSweep_withTheControlPassRun_andNoWipe() {
        for (level in NotificationLevel.entries) {
            for (complete in listOf(true, false)) {
                for (ran in listOf(true, false)) {
                    for (wiped in listOf(true, false)) {
                        for (prev in listOf<Long?>(null, t0 - 3_600_000L)) {
                            val action = decide(
                                level = level, sweepComplete = complete, controlPassRan = ran,
                                sweepStartedAtMs = t0, lastRecordedMs = prev, wipedInProcess = wiped,
                            )
                            val mayWrite = level == NotificationLevel.VENDOR_PUSH && complete && ran && !wiped
                            val mayClear = level != NotificationLevel.VENDOR_PUSH && complete && ran && !wiped
                            val expected = when {
                                mayWrite -> SweepStampAction.WRITE
                                mayClear -> SweepStampAction.CLEAR
                                else -> SweepStampAction.NONE
                            }
                            assertEquals(
                                "level=$level complete=$complete ran=$ran wiped=$wiped prev=$prev",
                                expected, action,
                            )
                        }
                    }
                }
            }
        }
    }
}

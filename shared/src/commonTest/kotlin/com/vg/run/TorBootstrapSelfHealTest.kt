package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Table-driven guard on the iOS stuck-bootstrap self-heal policy
 * ([TorBootstrapSelfHeal]).
 *
 * The property under test is a BUDGET, not a feature: every `true` from
 * [TorBootstrapSelfHeal.shouldDiscardTorState] costs the user a forced entry-guard
 * re-sample (an anonymity cost — guards are meant to be sticky), so the tests
 * below pin the three independent gates that bound it (N-strikes, stuck-HIGH
 * shape, wall-clock floor) and the fail-safe direction of the parser.
 */
class TorBootstrapSelfHealTest {

    private fun crumb(failures: Int, stuck: Int, lastDiscardDay: Long? = null) =
        BootstrapBreadcrumb(failures, stuck, lastDiscardDay)

    // ------------------------------------------------------------------
    // shouldDiscardTorState
    // ------------------------------------------------------------------

    @Test
    fun discardRequiresAllThreeGates() {
        val today = 20_000L
        // (failures, stuckPercent, lastDiscardDay, expected, why)
        val cases = listOf(
            // --- N-strikes gate -------------------------------------------------
            Triple(crumb(0, 100), false, "no failures at all"),
            Triple(crumb(1, 100), false, "one bad session is not evidence"),
            Triple(
                crumb(TorBootstrapSelfHeal.MIN_CONSECUTIVE_FAILURES_FOR_DISCARD - 1, 100),
                false,
                "one short of the strike threshold",
            ),
            Triple(
                crumb(TorBootstrapSelfHeal.MIN_CONSECUTIVE_FAILURES_FOR_DISCARD, 100),
                true,
                "exactly at the strike threshold, stuck at 100%",
            ),
            Triple(crumb(50, 100), true, "far past the threshold"),
            // --- stuck-HIGH shape gate -----------------------------------------
            Triple(crumb(10, 0), false, "stuck at 0% — network is eating Tor, a discard cannot help"),
            Triple(crumb(10, 10), false, "the production incident's stuck-LOW shape"),
            Triple(crumb(10, 25), false, "classic IPv6/NAT64 stall shape — still stuck-LOW"),
            Triple(
                crumb(10, TorBootstrapSelfHeal.STUCK_HIGH_PERCENT - 1),
                false,
                "one percent below the stuck-HIGH floor",
            ),
            Triple(
                crumb(10, TorBootstrapSelfHeal.STUCK_HIGH_PERCENT),
                true,
                "exactly at the stuck-HIGH floor",
            ),
            Triple(crumb(10, 95), true, "guards/circuit trouble — the repairable shape"),
        )
        for ((b, expected, why) in cases) {
            assertEquals(
                expected,
                TorBootstrapSelfHeal.shouldDiscardTorState(b, today),
                "shouldDiscardTorState($b, today=$today): $why",
            )
        }
    }

    @Test
    fun firstEverDiscardHasAVacuouslySatisfiedFloor() {
        // lastDiscardEpochDay == null: nothing to rate-limit against, so the
        // wall-clock floor must NOT block the very first discard. This is the
        // clause most likely to be "simplified" into a brick-the-feature bug
        // (e.g. `today - (last ?: today) >= 5`, which never fires).
        val b = crumb(TorBootstrapSelfHeal.MIN_CONSECUTIVE_FAILURES_FOR_DISCARD, 95, null)
        assertTrue(TorBootstrapSelfHeal.shouldDiscardTorState(b, todayEpochDay = 0L))
        assertTrue(TorBootstrapSelfHeal.shouldDiscardTorState(b, todayEpochDay = 20_000L))
    }

    @Test
    fun wallClockFloorBlocksAtFourDaysAndPassesAtFive() {
        val lastDiscard = 20_000L
        val b = crumb(9, 95, lastDiscard)
        // Same day, and every day up to one short of the floor: refused.
        for (delta in 0L until TorBootstrapSelfHeal.MIN_DAYS_BETWEEN_DISCARDS) {
            assertFalse(
                TorBootstrapSelfHeal.shouldDiscardTorState(b, lastDiscard + delta),
                "a discard $delta day(s) after the previous one must be refused " +
                    "(floor = ${TorBootstrapSelfHeal.MIN_DAYS_BETWEEN_DISCARDS} days)",
            )
        }
        assertTrue(
            TorBootstrapSelfHeal.shouldDiscardTorState(
                b, lastDiscard + TorBootstrapSelfHeal.MIN_DAYS_BETWEEN_DISCARDS
            ),
            "exactly at the floor the discard is allowed",
        )
        assertTrue(TorBootstrapSelfHeal.shouldDiscardTorState(b, lastDiscard + 365))
    }

    @Test
    fun aBackwardClockNeverUnlocksAnExtraDiscard() {
        // NTP correction / timezone / restored backup: today reads EARLIER than
        // the recorded discard day. The delta goes negative, so the floor holds.
        // A user-movable clock must only ever DELAY guard rotation, never grant it.
        val b = crumb(9, 95, lastDiscardDay = 20_000L)
        assertFalse(TorBootstrapSelfHeal.shouldDiscardTorState(b, todayEpochDay = 19_000L))
        assertFalse(TorBootstrapSelfHeal.shouldDiscardTorState(b, todayEpochDay = 0L))
    }

    @Test
    fun garbageBreadcrumbNeverDiscards() {
        // parse() rejecting garbage means parseOrEmpty() hands the caller EMPTY,
        // and EMPTY must be inert on every decision.
        val fromGarbage = TorBootstrapSelfHeal.parseOrEmpty("not-a-breadcrumb")
        assertEquals(TorBootstrapSelfHeal.EMPTY, fromGarbage)
        assertFalse(TorBootstrapSelfHeal.shouldDiscardTorState(fromGarbage, 20_000L))
        assertFalse(TorBootstrapSelfHeal.shouldSuggestReboot(fromGarbage.consecutiveFailures))
    }

    // ------------------------------------------------------------------
    // shouldSuggestReboot
    // ------------------------------------------------------------------

    @Test
    fun rebootHintFiresAtThreeRegardlessOfShape() {
        val cases = listOf(
            0 to false,
            1 to false,
            2 to false,
            TorBootstrapSelfHeal.MIN_CONSECUTIVE_FAILURES_FOR_REBOOT_HINT to true,
            4 to true,
            99 to true,
        )
        for ((failures, expected) in cases) {
            assertEquals(
                expected,
                TorBootstrapSelfHeal.shouldSuggestReboot(failures),
                "shouldSuggestReboot($failures)",
            )
        }
    }

    @Test
    fun rebootHintIsReachableFromStuckLow() {
        // The whole point of the shape-INDEPENDENCE: the production incident
        // (stuck at 10% forever, only a device reboot cleared it) must reach the
        // reboot hint even though it can never reach a state discard.
        val stuckLow = crumb(TorBootstrapSelfHeal.MIN_CONSECUTIVE_FAILURES_FOR_REBOOT_HINT, 10)
        assertTrue(TorBootstrapSelfHeal.shouldSuggestReboot(stuckLow.consecutiveFailures))
        assertFalse(
            TorBootstrapSelfHeal.shouldDiscardTorState(stuckLow, 20_000L),
            "stuck-LOW must never discard state, at any strike count",
        )
        val stuckLowMany = crumb(50, 10)
        assertTrue(TorBootstrapSelfHeal.shouldSuggestReboot(stuckLowMany.consecutiveFailures))
        assertFalse(TorBootstrapSelfHeal.shouldDiscardTorState(stuckLowMany, 20_000L))
    }

    // ------------------------------------------------------------------
    // isFailedAttempt
    // ------------------------------------------------------------------

    @Test
    fun failedAttemptScoring() {
        val floor = TorBootstrapSelfHeal.MIN_FAILED_ATTEMPT_DWELL_SECONDS
        // (reachedBootstrapping, reachedConnected, dwellSeconds, expected, why)
        data class Case(
            val bootstrapping: Boolean,
            val connected: Boolean,
            val dwell: Int,
            val expected: Boolean,
            val why: String,
        )
        val cases = listOf(
            Case(false, false, 3600, false, "Tor never started this session — no evidence"),
            Case(true, true, 3600, false, "connected: a success, however slow"),
            Case(true, true, 1, false, "connected almost instantly"),
            Case(true, false, 0, false, "opened and closed immediately"),
            Case(true, false, 10, false, "the ten-second glance — must score ZERO"),
            Case(true, false, floor - 1, false, "one second short of the dwell floor"),
            Case(true, false, floor, true, "exactly at the dwell floor"),
            Case(true, false, 600, true, "ten foreground minutes, never connected"),
        )
        for (c in cases) {
            assertEquals(
                c.expected,
                TorBootstrapSelfHeal.isFailedAttempt(c.bootstrapping, c.connected, c.dwell),
                "isFailedAttempt(bootstrapping=${c.bootstrapping}, connected=${c.connected}, " +
                    "dwell=${c.dwell}): ${c.why}",
            )
        }
    }

    @Test
    fun fiveGlancesAWeekScoreZeroFailures() {
        // The regression this exists to stop: casual open-and-leave usage must
        // never accumulate a discard budget.
        var b = TorBootstrapSelfHeal.EMPTY
        repeat(5) {
            if (TorBootstrapSelfHeal.isFailedAttempt(
                    reachedBootstrapping = true, reachedConnected = false, foregroundDwellSeconds = 10
                )
            ) {
                b = TorBootstrapSelfHeal.recordFailure(b, 10)
            }
        }
        assertEquals(0, b.consecutiveFailures)
        assertFalse(TorBootstrapSelfHeal.shouldSuggestReboot(b.consecutiveFailures))
        assertFalse(TorBootstrapSelfHeal.shouldDiscardTorState(b, 20_000L))
    }

    // ------------------------------------------------------------------
    // serialize / parse
    // ------------------------------------------------------------------

    @Test
    fun serializeParseRoundTrips() {
        val samples = listOf(
            TorBootstrapSelfHeal.EMPTY,
            crumb(1, 0, null),
            crumb(5, 95, null),
            crumb(0, 0, 20_123L),
            crumb(7, 100, 0L),
        )
        for (b in samples) {
            val encoded = TorBootstrapSelfHeal.serialize(b)
            assertEquals(b, TorBootstrapSelfHeal.parse(encoded), "round trip of $b (\"$encoded\")")
        }
    }

    @Test
    fun serializeUsesDayGranularityOnly() {
        // Forensic-residue constraint: this record lives OUTSIDE the vault, so it
        // must not carry a millisecond "when did you last use Rún" timestamp.
        val encoded = TorBootstrapSelfHeal.serialize(crumb(2, 90, 20_123L))
        assertEquals("v1:2:90:20123", encoded)
        // A day number is 5 digits for the next ~250 years; anything with a
        // 13-digit epoch-millis field would fail this.
        assertTrue(encoded.split(':')[3].length <= 7, "day field must be a DAY number, not millis")
    }

    @Test
    fun parseRejectsGarbageAndReturnsNull() {
        val garbage = listOf(
            null,
            "",
            "   ",
            "v1",
            "v1:1:2",                 // truncated
            "v1:1:2:3:4",             // extra field
            "v2:1:2:-",               // unknown format tag
            "1:2:-",                  // missing tag
            "v1:x:2:-",               // non-numeric failures
            "v1:1:y:-",               // non-numeric percent
            "v1:1:2:z",               // non-numeric day
            "v1:-1:2:-",              // negative failures
            "v1:1:-5:-",              // negative percent
            "v1:1:101:-",             // percent out of range
            "v1:99999999:50:-",       // implausible failure count
            "v1:1:90:99999999999",    // implausible epoch day
            "v1:1:90:-1",             // negative epoch day
            "\u0000\u0001binary",
        )
        for (raw in garbage) {
            assertNull(TorBootstrapSelfHeal.parse(raw), "parse(${raw?.let { "\"$it\"" } ?: "null"})")
            assertEquals(
                TorBootstrapSelfHeal.EMPTY,
                TorBootstrapSelfHeal.parseOrEmpty(raw),
                "parseOrEmpty must substitute the inert EMPTY record",
            )
        }
    }

    @Test
    fun parseToleratesSurroundingWhitespace() {
        assertEquals(crumb(3, 90, 20_000L), TorBootstrapSelfHeal.parse("  v1:3:90:20000\n"))
    }

    // ------------------------------------------------------------------
    // transitions
    // ------------------------------------------------------------------

    @Test
    fun transitionsPreserveTheRateLimitAndClearTheStreak() {
        val start = crumb(0, 0, lastDiscardDay = 20_000L)

        val failed = TorBootstrapSelfHeal.recordFailure(start, 95)
        assertEquals(1, failed.consecutiveFailures)
        assertEquals(95, failed.lastStuckPercent)
        assertEquals(
            20_000L, failed.lastDiscardEpochDay,
            "a failure must not touch the guard-rotation rate limit",
        )

        val succeeded = TorBootstrapSelfHeal.recordSuccess(failed)
        assertEquals(0, succeeded.consecutiveFailures)
        assertEquals(
            20_000L, succeeded.lastDiscardEpochDay,
            "one success must NOT hand out a fresh discard budget — the floor is a " +
                "rate limit on guard rotation, not part of the failure evidence",
        )

        val discarded = TorBootstrapSelfHeal.recordDiscard(failed, todayEpochDay = 20_010L)
        assertEquals(0, discarded.consecutiveFailures)
        assertEquals(0, discarded.lastStuckPercent)
        assertEquals(20_010L, discarded.lastDiscardEpochDay)
        assertFalse(
            TorBootstrapSelfHeal.shouldDiscardTorState(discarded, 20_010L),
            "a discard must immediately disarm itself — no discard loop",
        )
    }

    @Test
    fun recordFailureClampsAnAbsurdPercent() {
        assertEquals(100, TorBootstrapSelfHeal.recordFailure(TorBootstrapSelfHeal.EMPTY, 250).lastStuckPercent)
        assertEquals(0, TorBootstrapSelfHeal.recordFailure(TorBootstrapSelfHeal.EMPTY, -7).lastStuckPercent)
    }

    @Test
    fun theProductionIncidentTraceStuckHighEventuallyDiscardsOnce() {
        // Five relaunches, each a >=60 s foreground wait that stalls at 95%.
        var b = TorBootstrapSelfHeal.EMPTY
        val day = 20_000L
        repeat(5) { i ->
            assertFalse(
                TorBootstrapSelfHeal.shouldDiscardTorState(b, day),
                "no discard before the ${i + 1}th failure is recorded",
            )
            assertTrue(
                TorBootstrapSelfHeal.isFailedAttempt(
                    reachedBootstrapping = true, reachedConnected = false, foregroundDwellSeconds = 120
                )
            )
            b = TorBootstrapSelfHeal.recordFailure(b, 95)
        }
        assertTrue(TorBootstrapSelfHeal.shouldSuggestReboot(b.consecutiveFailures))
        assertTrue(TorBootstrapSelfHeal.shouldDiscardTorState(b, day), "the 6th launch discards")

        // The 6th launch discards, then fails five more times on the SAME day —
        // the wall-clock floor must refuse a second discard.
        b = TorBootstrapSelfHeal.recordDiscard(b, day)
        repeat(5) { b = TorBootstrapSelfHeal.recordFailure(b, 95) }
        assertFalse(
            TorBootstrapSelfHeal.shouldDiscardTorState(b, day),
            "at most one forced guard rotation per ${TorBootstrapSelfHeal.MIN_DAYS_BETWEEN_DISCARDS}-day window",
        )
        assertTrue(
            TorBootstrapSelfHeal.shouldDiscardTorState(
                b, day + TorBootstrapSelfHeal.MIN_DAYS_BETWEEN_DISCARDS
            )
        )
    }
}

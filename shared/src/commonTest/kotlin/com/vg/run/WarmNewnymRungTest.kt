package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// WARM-TRANSPORT NEWNYM RUNG (2026-10-07).
//
// Field case (Samsung A13): a session whose relay had answered many times went
// dark mid-session — every 10 s warm probe timed out, Tor stayed at 100 % — and
// the first NEWNYM came ~140 s in, from RunViewModel.startRelayStallWatch (100 s
// after the 3-miss hysteresis flip). The cold rung could not help: it retires at
// the first answer. This rung is its complement for a WARM transport.
//
// Pinned here because both platform ladders (Android
// RunViewModel.maybeFireWarmNewnym, iOS AppState.maybeFireWarmNewnym via
// IosAppController.warmNewnymDue) call this ONE predicate + ledger:
//   • warm transport only — never on a transport the cold rung owns;
//   • first fire: ≥ 3 consecutive full-budget timeouts spanning ≥ 28 s;
//   • repeat: ≥ 2 FRESH timeouts and ≥ 40 s after the previous fire;
//   • ≤ 2 per dark run, ≤ 6 per rolling hour (the anonymity budget).
// ---------------------------------------------------------------------------

class WarmNewnymRungTest {

    private fun due(
        warm: Boolean = true,
        timeouts: Int = MessageManager.WARM_NEWNYM_MIN_TIMEOUTS,
        darkForMs: Long = MessageManager.WARM_NEWNYM_MIN_DARK_MS,
        sinceLastFireMs: Long = 0L,
        firesThisRun: Int = 0,
        firesInWindow: Int = 0,
    ) = MessageManager.shouldFireWarmNewnym(
        warmTransport = warm,
        consecutiveFullBudgetTimeouts = timeouts,
        darkForMs = darkForMs,
        msSinceLastFireThisRun = sinceLastFireMs,
        firesThisRun = firesThisRun,
        firesInWindow = firesInWindow,
    )

    // -----------------------------------------------------------------------
    // (1) The numbers.
    // -----------------------------------------------------------------------

    @Test
    fun theRungsConstantsAreTheDecidedNumbers() {
        assertEquals(3, MessageManager.WARM_NEWNYM_MIN_TIMEOUTS)
        assertEquals(28_000L, MessageManager.WARM_NEWNYM_MIN_DARK_MS)
        assertEquals(2, MessageManager.WARM_NEWNYM_REPEAT_MIN_TIMEOUTS)
        assertEquals(40_000L, MessageManager.WARM_NEWNYM_REPEAT_MS)
        assertEquals(2, MessageManager.WARM_NEWNYM_MAX_PER_RUN)
        assertEquals(6, MessageManager.WARM_NEWNYM_MAX_PER_WINDOW)
        assertEquals(3_600_000L, MessageManager.WARM_NEWNYM_WINDOW_MS)
        // Three back-to-back warm timeouts (iOS conversation loops) must be able
        // to satisfy the dark floor even when each returns a slack early.
        val threeTightTimeouts = MessageManager.WARM_NEWNYM_MIN_TIMEOUTS *
            (MessageManager.RELAY_HEALTH_TIMEOUT_SECONDS * 1_000L - MessageManager.PROBE_TIMEOUT_SLACK_MS)
        assertTrue(MessageManager.WARM_NEWNYM_MIN_DARK_MS <= threeTightTimeouts)
        // …and the rung must beat the field case's 140 s by a wide margin: on the
        // 8–12 s heartbeat the first fire lands at the end of the 2nd failed cycle.
        val secondCycleEndWorstMs = 4 * MessageManager.RELAY_HEALTH_TIMEOUT_SECONDS * 1_000L +
            MessageManager.RELAY_HEALTH_BASE_MS + MessageManager.RELAY_HEALTH_JITTER_MS
        assertTrue(secondCycleEndWorstMs <= 60_000L, "first warm fire within a minute of the outage")
    }

    // -----------------------------------------------------------------------
    // (2) Warm vs cold — exact complement of the cold rung.
    // -----------------------------------------------------------------------

    @Test
    fun aColdTransportNeverFires_thatIsTheColdRungsJob() {
        assertFalse(due(warm = false))
        assertFalse(due(warm = false, timeouts = 99, darkForMs = 600_000L))
    }

    @Test
    fun aWarmWedgedTransportFires() {
        assertTrue(due())
    }

    // -----------------------------------------------------------------------
    // (3) First-fire evidence: timeouts AND span.
    // -----------------------------------------------------------------------

    @Test
    fun theFirstFireNeedsThreeFullBudgetTimeouts() {
        assertFalse(due(timeouts = 0, darkForMs = 600_000L))
        assertFalse(due(timeouts = 1, darkForMs = 600_000L))
        assertFalse(due(timeouts = 2, darkForMs = 600_000L), "one failed cycle is not yet evidence")
        assertTrue(due(timeouts = 3, darkForMs = 600_000L))
        assertTrue(due(timeouts = 9, darkForMs = 600_000L))
    }

    @Test
    fun theFirstFireNeedsTheDarkSpan() {
        assertFalse(due(darkForMs = MessageManager.WARM_NEWNYM_MIN_DARK_MS - 1))
        assertTrue(due(darkForMs = MessageManager.WARM_NEWNYM_MIN_DARK_MS))
        assertFalse(due(darkForMs = -1L), "a negative span fails closed")
    }

    // -----------------------------------------------------------------------
    // (4) Repeat: fresh evidence and spacing.
    // -----------------------------------------------------------------------

    @Test
    fun theRepeatNeedsFreshTimeoutsAndFortySeconds() {
        val spacing = MessageManager.WARM_NEWNYM_REPEAT_MS
        assertFalse(due(firesThisRun = 1, timeouts = 1, sinceLastFireMs = spacing))
        assertTrue(due(firesThisRun = 1, timeouts = 2, sinceLastFireMs = spacing))
        assertFalse(due(firesThisRun = 1, timeouts = 9, sinceLastFireMs = spacing - 1))
        assertFalse(due(firesThisRun = 1, timeouts = 9, sinceLastFireMs = -1L), "negative fails closed")
    }

    // -----------------------------------------------------------------------
    // (5) Budgets.
    // -----------------------------------------------------------------------

    @Test
    fun atMostTwoPerDarkRun() {
        assertFalse(due(firesThisRun = 2, timeouts = 9, sinceLastFireMs = 600_000L, darkForMs = 600_000L))
        assertFalse(due(firesThisRun = 7, timeouts = 9, sinceLastFireMs = 600_000L))
        assertFalse(due(firesThisRun = -1), "a corrupt counter fails closed")
    }

    @Test
    fun atMostSixPerRollingHour() {
        assertTrue(due(firesInWindow = 5))
        assertFalse(due(firesInWindow = 6))
        assertFalse(due(firesInWindow = 60))
        assertFalse(due(firesInWindow = -1), "a corrupt counter fails closed")
    }

    // -----------------------------------------------------------------------
    // (6) The ledger.
    // -----------------------------------------------------------------------

    @Test
    fun theLedgerReArmsThePerRunBudgetOnANewRunButNotTheWindow() {
        val l = WarmNewnymLedger()
        l.syncRun(1_000L)
        l.noteFired(10_000L); l.noteFired(60_000L)
        assertEquals(2, l.firesThisRun)
        assertEquals(2, l.firesInWindow(60_000L))
        assertEquals(30_000L, l.msSinceLastFireThisRun(90_000L))
        l.syncRun(1_000L)
        assertEquals(2, l.firesThisRun, "same run key: nothing re-arms")
        l.syncRun(200_000L)
        assertEquals(0, l.firesThisRun, "a new dark run re-arms the per-run budget")
        assertEquals(0L, l.msSinceLastFireThisRun(210_000L))
        assertEquals(2, l.firesInWindow(210_000L), "the hourly budget is NOT re-armed by a new run")
    }

    @Test
    fun theWindowSlides() {
        val l = WarmNewnymLedger()
        l.syncRun(0L)
        repeat(6) { l.noteFired(it * 1_000L) }
        assertEquals(6, l.firesInWindow(10_000L))
        assertEquals(6, l.firesInWindow(MessageManager.WARM_NEWNYM_WINDOW_MS - 1))
        assertEquals(5, l.firesInWindow(MessageManager.WARM_NEWNYM_WINDOW_MS))
        assertEquals(0, l.firesInWindow(MessageManager.WARM_NEWNYM_WINDOW_MS + 10_000L))
    }

    @Test
    fun retiringARunSpendsThePerRunBudgetOnly() {
        val l = WarmNewnymLedger()
        l.syncRun(5L)
        l.retireRun()
        assertEquals(MessageManager.WARM_NEWNYM_MAX_PER_RUN, l.firesThisRun)
        assertEquals(0, l.firesInWindow(10L), "nothing reached Tor, no window budget spent")
        l.syncRun(6L)
        assertEquals(0, l.firesThisRun, "the next dark run may try again")
    }

    // -----------------------------------------------------------------------
    // (7) The transport seam both platforms call — the field timeline replayed.
    // -----------------------------------------------------------------------

    private fun warmManager(): MessageManager {
        val mgr = MessageManager(InMemoryVault(), "http://relay.test", FakeRelayHttp.warm())
        assertTrue(mgr.isRelayReachable(), "the relay's by-design 404 is a completed round-trip")
        assertTrue(mgr.hasCompletedRelayRoundTrip())
        return mgr
    }

    @Test
    fun theFieldTimelineFiresAtTheSecondFailedCycleThenAgainAndThenStops() {
        val mgr = warmManager()
        val l = WarmNewnymLedger()
        // Outage starts at t=0 (ms on the warm-rung clock). Warm cycles: 2 × 10 s
        // attempts + ~10 s heartbeat. The platform asks at the end of each cycle.
        mgr.noteProbeTimedOut(0L); mgr.noteProbeTimedOut(10_000L)
        assertFalse(mgr.warmNewnymDueAt(l, 20_000L), "cycle 1: two timeouts are not evidence yet")
        mgr.noteProbeTimedOut(30_000L); mgr.noteProbeTimedOut(40_000L)
        assertTrue(mgr.warmNewnymDueAt(l, 50_000L), "cycle 2 end (~50 s): fire — was ~140 s")
        mgr.noteWarmNewnymFiredAt(l, 50_000L)
        assertEquals(0, mgr.consecutiveFullBudgetProbeTimeouts(), "a fire clears the run")
        assertFalse(mgr.warmNewnymDueAt(l, 50_000L), "same evidence cannot fire twice (iOS's extra loops)")
        mgr.noteProbeTimedOut(60_000L); mgr.noteProbeTimedOut(70_000L)
        assertFalse(mgr.warmNewnymDueAt(l, 80_000L), "30 s after the fire: spacing not met")
        mgr.noteProbeTimedOut(90_000L); mgr.noteProbeTimedOut(100_000L)
        assertTrue(mgr.warmNewnymDueAt(l, 110_000L))
        mgr.noteWarmNewnymFiredAt(l, 110_000L)
        repeat(10) { mgr.noteProbeTimedOut(120_000L + it * 10_000L) }
        assertFalse(mgr.warmNewnymDueAt(l, 600_000L), "two per dark run, then the heavy ladders own it")
    }

    @Test
    fun anAnswerEndsTheDarkRunAndTheNextRunGetsAFreshPerRunBudget() {
        val mgr = warmManager()
        val l = WarmNewnymLedger()
        repeat(4) { mgr.noteProbeTimedOut(it * 10_000L) }
        assertTrue(mgr.warmNewnymDueAt(l, 50_000L)); mgr.noteWarmNewnymFiredAt(l, 50_000L)
        repeat(4) { mgr.noteProbeTimedOut(60_000L + it * 10_000L) }
        assertTrue(mgr.warmNewnymDueAt(l, 110_000L)); mgr.noteWarmNewnymFiredAt(l, 110_000L)
        mgr.noteProbeAnswered()
        assertFalse(mgr.warmNewnymDueAt(l, 120_000L), "answering: no dark run, nothing to rescue")
        repeat(4) { mgr.noteProbeTimedOut(500_000L + it * 10_000L) }
        assertTrue(mgr.warmNewnymDueAt(l, 550_000L), "a NEW dark run re-arms the per-run budget")
    }

    @Test
    fun theHourlyBudgetHoldsAcrossDarkRuns() {
        val mgr = warmManager()
        val l = WarmNewnymLedger()
        var t = 0L
        repeat(3) {
            repeat(4) { mgr.noteProbeTimedOut(t); t += 10_000L }
            assertTrue(mgr.warmNewnymDueAt(l, t)); mgr.noteWarmNewnymFiredAt(l, t)
            t += 40_000L
            repeat(2) { mgr.noteProbeTimedOut(t); t += 10_000L }
            assertTrue(mgr.warmNewnymDueAt(l, t)); mgr.noteWarmNewnymFiredAt(l, t)
            mgr.noteProbeAnswered()
            t += 60_000L
        }
        repeat(4) { mgr.noteProbeTimedOut(t); t += 10_000L }
        assertFalse(mgr.warmNewnymDueAt(l, t), "6 fires inside the hour: the 4th dark run gets none")
        assertTrue(
            // The first fire was at t = 40 s; the window drops it an hour later.
            mgr.warmNewnymDueAt(l, 40_000L + MessageManager.WARM_NEWNYM_WINDOW_MS),
            "once the oldest fire leaves the window, one more is allowed",
        )
    }

    @Test
    fun aFastFailureBreaksTheTimeoutRunButNotTheDarkSpan() {
        val mgr = warmManager()
        val l = WarmNewnymLedger()
        mgr.noteProbeTimedOut(0L); mgr.noteProbeTimedOut(10_000L)
        mgr.noteProbeFailedFast()
        assertEquals(0, mgr.consecutiveFullBudgetProbeTimeouts())
        mgr.noteProbeTimedOut(20_000L); mgr.noteProbeTimedOut(30_000L)
        assertFalse(mgr.warmNewnymDueAt(l, 40_000L), "only two consecutive timeouts after the break")
        mgr.noteProbeTimedOut(40_000L)
        assertTrue(mgr.warmNewnymDueAt(l, 50_000L), "the span still counts from the first timeout at t=0")
    }

    @Test
    fun aColdTransportIsNeverWarmRungEvidence_evenWithTimeouts() {
        val mgr = MessageManager(InMemoryVault(), "http://relay.test", FakeRelayHttp.dead())
        assertFalse(mgr.hasCompletedRelayRoundTrip())
        repeat(6) { mgr.noteProbeTimedOut(it * 20_000L) }
        assertFalse(mgr.warmNewnymDueAt(WarmNewnymLedger(), 600_000L), "cold: the cold rung's business")
    }

    @Test
    fun realProbes_fastFailuresNeverStartADarkRun_andAnAnsweringTransportIsNotDark() {
        val cold = MessageManager(InMemoryVault(), "http://relay.test", FakeRelayHttp.dead())
        repeat(3) { assertFalse(cold.isRelayReachable()) }
        assertEquals(0, cold.consecutiveFullBudgetProbeTimeouts())
        assertEquals(0L, cold.warmDarkForSeconds(), "fast failures never start a dark run")
        assertEquals(0L, warmManager().warmDarkForSeconds(), "an answering transport is not dark")
    }
}

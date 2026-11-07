package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// COLD-TRANSPORT NEWNYM RUNG.
//
// The measured tail of a slow connect is NOT bootstrap and NOT circuit build:
// the HS descriptor lands in ~5 s, an intro/rendezvous circuit is built in
// 5–15 s, and then the INTRODUCTION never completes. The session then burns 20 s
// probes on fresh STREAMS over the same wedged circuit — rotating a stream
// rotates neither the circuit nor the descriptor — until either Tor abandons the
// introduction point itself 60–75 s later, or a `SIGNAL NEWNYM` purges the HS
// client state (observed to recover in < 5 s).
//
// So the rung fires EARLY, on wall time, and stops fast. Every gate is pinned
// here because both platform ladders (Android RunViewModel.maybeFireEarlyNewnym,
// iOS AppState.maybeFireEarlyNewnym via IosAppController.earlyNewnymDue) call
// this ONE function — a divergence between the platforms can only happen if this
// file stops being the decision.
//
// The properties:
//   • COLD ONLY — once the session has had ONE relay answer the rung is retired
//     for good (a later stall belongs to the heavier, session-aware ladders);
//   • ≥ 35 s from the CONNECT ANCHOR, which this rung never moves (the connect
//     report must keep measuring launch → first answer);
//   • ≥ 2 consecutive FULL-BUDGET probe timeouts — a fast failure is a broken
//     transport, which NEWNYM cannot fix;
//   • at most 2 per session, the second not before ~80 s: more would be
//     introduction-point hammering.
// ---------------------------------------------------------------------------

class EarlyNewnymRungTest {

    private fun due(
        cold: Boolean = true,
        timeouts: Int = MessageManager.EARLY_NEWNYM_MIN_TIMEOUTS,
        sinceAnchorMs: Long = MessageManager.EARLY_NEWNYM_FIRST_MS,
        fired: Int = 0,
    ) = MessageManager.shouldFireEarlyNewnym(
        coldTransport = cold,
        consecutiveFullBudgetTimeouts = timeouts,
        msSinceConnectAnchor = sinceAnchorMs,
        newnymsFiredThisSession = fired,
    )

    // -----------------------------------------------------------------------
    // (1) The numbers themselves — they are the product decision.
    // -----------------------------------------------------------------------

    @Test
    fun theRungsConstantsAreTheStudysNumbers() {
        // 35 s: the descriptor arrives in ~5 s and a healthy intro+rendezvous
        // completes within ~30 s of it, so earlier would throw away work that was
        // about to succeed; later hands the user Tor's own 60–75 s abandon.
        assertEquals(35_000L, MessageManager.EARLY_NEWNYM_FIRST_MS)
        // ~80 s: one full cold cycle (2 × 20 s + the fast retry) after the first
        // fire, still ahead of Android's 100 s restart rung.
        assertEquals(80_000L, MessageManager.EARLY_NEWNYM_SECOND_MS)
        // Two, never more: no introduction-point hammering.
        assertEquals(2, MessageManager.EARLY_NEWNYM_MAX_FIRES)
        // One lone timeout is also what a slow-but-alive rendezvous looks like.
        assertEquals(2, MessageManager.EARLY_NEWNYM_MIN_TIMEOUTS)
        // The first fire cannot land before a cold cycle has produced its
        // evidence: 2 full-budget attempts at HEALTH_HTTP_TIMEOUT_SECONDS.
        assertTrue(
            MessageManager.EARLY_NEWNYM_FIRST_MS >=
                MessageManager.EARLY_NEWNYM_MIN_TIMEOUTS * MessageManager.HEALTH_HTTP_TIMEOUT_SECONDS * 1_000L - 5_000L,
            "the 35 s floor must be reachable by real evidence, not by the clock alone",
        )
    }

    // -----------------------------------------------------------------------
    // (2) Cold vs warm — the rung is retired by the first relay answer.
    // -----------------------------------------------------------------------

    @Test
    fun aWarmSessionNeverFires_whateverElseIsTrue() {
        assertFalse(due(cold = false))
        assertFalse(due(cold = false, timeouts = 99, sinceAnchorMs = 600_000L))
        assertFalse(due(cold = false, timeouts = 99, sinceAnchorMs = 600_000L, fired = 1))
    }

    @Test
    fun aColdWedgedSessionFires() {
        assertTrue(due())
    }

    // -----------------------------------------------------------------------
    // (3) Boundaries: the wall-clock floors.
    // -----------------------------------------------------------------------

    @Test
    fun theFirstFireIsExactlyAtTheThirtyFiveSecondFloor() {
        assertFalse(due(sinceAnchorMs = MessageManager.EARLY_NEWNYM_FIRST_MS - 1))
        assertTrue(due(sinceAnchorMs = MessageManager.EARLY_NEWNYM_FIRST_MS))
        assertTrue(due(sinceAnchorMs = MessageManager.EARLY_NEWNYM_FIRST_MS + 1))
    }

    @Test
    fun theSecondFireIsExactlyAtTheEightySecondFloor() {
        // The 35 s floor is long past, but the SECOND fire has its own.
        assertFalse(due(sinceAnchorMs = MessageManager.EARLY_NEWNYM_FIRST_MS, fired = 1))
        assertFalse(due(sinceAnchorMs = MessageManager.EARLY_NEWNYM_SECOND_MS - 1, fired = 1))
        assertTrue(due(sinceAnchorMs = MessageManager.EARLY_NEWNYM_SECOND_MS, fired = 1))
    }

    @Test
    fun aNegativeElapsedFailsClosed() {
        // Cannot happen on either platform's monotonic clock; if it ever does,
        // the rung must not fire.
        assertFalse(due(sinceAnchorMs = -1L))
        assertFalse(due(sinceAnchorMs = -600_000L))
    }

    // -----------------------------------------------------------------------
    // (4) Boundaries: the evidence.
    // -----------------------------------------------------------------------

    @Test
    fun fewerThanTwoConsecutiveFullBudgetTimeoutsIsNotEvidence() {
        assertFalse(due(timeouts = 0, sinceAnchorMs = 600_000L))
        assertFalse(due(timeouts = 1, sinceAnchorMs = 600_000L))
        assertTrue(due(timeouts = 2, sinceAnchorMs = 600_000L))
        assertTrue(due(timeouts = 7, sinceAnchorMs = 600_000L))
    }

    @Test
    fun onlyAFullBudgetTimeoutCountsAsEvidence() {
        // The same 250 ms slack the PROBE_TIMEOUT connection-log line has always
        // used: the transport returns a hair before the deadline it was given.
        val budget = MessageManager.HEALTH_HTTP_TIMEOUT_SECONDS
        assertTrue(MessageManager.isFullBudgetProbeTimeout(budget * 1_000L, budget))
        assertTrue(
            MessageManager.isFullBudgetProbeTimeout(
                budget * 1_000L - MessageManager.PROBE_TIMEOUT_SLACK_MS, budget
            )
        )
        assertFalse(
            MessageManager.isFullBudgetProbeTimeout(
                budget * 1_000L - MessageManager.PROBE_TIMEOUT_SLACK_MS - 1, budget
            )
        )
        // A refused/broken stream comes back instantly — NEWNYM cannot fix that,
        // so it must never look like a wedged introduction point.
        assertFalse(MessageManager.isFullBudgetProbeTimeout(12L, budget))
        assertFalse(MessageManager.isFullBudgetProbeTimeout(0L, budget))
    }

    // -----------------------------------------------------------------------
    // (5) The cap: two per session, then the heavier ladders own it.
    // -----------------------------------------------------------------------

    @Test
    fun theRungIsCappedAtTwoFiresPerSession() {
        assertTrue(due(sinceAnchorMs = 600_000L, fired = 0))
        assertTrue(due(sinceAnchorMs = 600_000L, fired = 1))
        assertFalse(
            due(sinceAnchorMs = 600_000L, fired = MessageManager.EARLY_NEWNYM_MAX_FIRES),
            "no introduction-point hammering: two fires per session and no more",
        )
        assertFalse(due(sinceAnchorMs = 600_000L, fired = 9))
        // A platform that latches the counter past the cap (control channel down)
        // must also stay retired.
        assertFalse(due(sinceAnchorMs = 600_000L, fired = -1), "a corrupt counter fails closed")
    }

    // -----------------------------------------------------------------------
    // (6) The transport seam both platforms actually call.
    // -----------------------------------------------------------------------

    @Test
    fun aFreshTransportHasNoEvidenceAndNeverFires() {
        val mgr = MessageManager(InMemoryVault(), "http://relay.test", FakeRelayHttp.dead())
        assertFalse(mgr.hasCompletedRelayRoundTrip(), "a fresh transport has proven nothing")
        assertEquals(0, mgr.consecutiveFullBudgetProbeTimeouts())
        assertFalse(mgr.earlyNewnymDue(600_000L, 0), "cold, but no full-budget timeouts yet")
    }

    @Test
    fun aFastFailingTransportNeverBuildsAnEvidenceRun() {
        // Instant failures (SOCKS refused, mock relay down) are NOT a wedged
        // introduction point, so they must never accumulate toward the rung.
        val mgr = MessageManager(InMemoryVault(), "http://relay.test", FakeRelayHttp.dead())
        repeat(3) { assertFalse(mgr.isRelayReachable()) }
        assertEquals(
            0, mgr.consecutiveFullBudgetProbeTimeouts(),
            "a probe that failed fast must break the run, not advance it",
        )
        assertFalse(mgr.earlyNewnymDue(600_000L, 0))
    }

    @Test
    fun theFirstRelayAnswerRetiresTheRungOnTheTransportItself() {
        val mgr = MessageManager(InMemoryVault(), "http://relay.test", FakeRelayHttp.warm())
        assertTrue(mgr.isRelayReachable(), "the relay's by-design 404 is a completed round-trip")
        assertTrue(mgr.hasCompletedRelayRoundTrip())
        assertFalse(mgr.earlyNewnymDue(600_000L, 0), "never after the session's first answer")
    }

    @Test
    fun notingAFireClearsTheEvidenceRun() {
        // The second fire must rest on FRESH timeouts, never on the ones that
        // caused the first — this is also what keeps iOS's three concurrent
        // probe loops from double-firing the same rung.
        val mgr = MessageManager(InMemoryVault(), "http://relay.test", FakeRelayHttp.dead())
        mgr.noteEarlyNewnymFired()
        assertEquals(0, mgr.consecutiveFullBudgetProbeTimeouts())
        assertFalse(mgr.earlyNewnymDue(600_000L, 1))
    }
    // -----------------------------------------------------------------------
    // (7) C5 floor fix (2026-10-09): the FLOOR follows the cold rung's own
    // fires, the CAP the shared count. Field run: a warm-up
    // rotation used to push the cold rung's only remaining fire to 80 s.
    // -----------------------------------------------------------------------

    private fun dueSplit(sinceAnchorMs: Long, shared: Int, cold: Int, timeouts: Int = 2) =
        MessageManager.shouldFireEarlyNewnym(
            coldTransport = true,
            consecutiveFullBudgetTimeouts = timeouts,
            msSinceConnectAnchor = sinceAnchorMs,
            newnymsFiredThisSession = shared,
            coldRungFiresThisSession = cold,
        )

    @Test
    fun afterAWarmupRotation_theColdRungsFirstFireKeepsTheThirtyFiveSecondFloor() {
        // shared = 1 (the warm-up spent it), cold = 0: still the FIRST cold fire.
        assertFalse(dueSplit(MessageManager.EARLY_NEWNYM_FIRST_MS - 1, shared = 1, cold = 0))
        assertTrue(dueSplit(MessageManager.EARLY_NEWNYM_FIRST_MS, shared = 1, cold = 0))
        assertTrue(dueSplit(41_000L, shared = 1, cold = 0), "the android1 / A20e shape fires at ~41 s, not 80 s")
    }

    @Test
    fun theColdRungsSecondFireKeepsTheEightySecondFloor() {
        assertFalse(dueSplit(MessageManager.EARLY_NEWNYM_SECOND_MS - 1, shared = 1, cold = 1))
        assertTrue(dueSplit(MessageManager.EARLY_NEWNYM_SECOND_MS, shared = 1, cold = 1))
    }

    @Test
    fun theSharedCapStillHolds_whateverTheColdCountSays() {
        assertFalse(dueSplit(600_000L, shared = 2, cold = 0), "warm-up + one cold-or-warm-up fire = 2: capped")
        assertFalse(dueSplit(600_000L, shared = 2, cold = 1))
        assertFalse(dueSplit(600_000L, shared = 2, cold = 2))
    }

    @Test
    fun aCorruptColdCount_failsClosed() {
        assertFalse(dueSplit(600_000L, shared = 0, cold = -1))
        assertFalse(dueSplit(600_000L, shared = 0, cold = 1), "cold fires can never exceed the shared count")
    }

    @Test
    fun theWarmupRotation_stillResetsTheEvidenceRun() {
        // The cold fire after a warm-up rotation still needs two FRESH timeouts.
        assertFalse(dueSplit(600_000L, shared = 1, cold = 0, timeouts = 1))
        val mgr = MessageManager(InMemoryVault(), "http://relay.test", FakeRelayHttp.dead())
        mgr.noteEarlyNewnymFired()
        assertFalse(mgr.earlyNewnymDue(600_000L, 1, 0))
    }

    @Test
    fun theTwoArgumentSeam_keepsTheOldSingleCounterBehaviour() {
        assertFalse(due(sinceAnchorMs = MessageManager.EARLY_NEWNYM_SECOND_MS - 1, fired = 1))
        assertTrue(dueSplit(MessageManager.EARLY_NEWNYM_SECOND_MS - 1, shared = 1, cold = 0))
    }
}

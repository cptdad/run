package com.vg.run

import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// The iOS unlock-time check of a cached SOCKS port (UnlockPortCheck). The one
// rule that matters most: only a SILENT control channel is "dead" — any answer,
// including a different port or an empty listener list, means tor_main is alive
// and must never latch relaunch-required. Inputs are driven through the real
// SocksPortRedirect so `resolved` is what the app would compute.
// ---------------------------------------------------------------------------

class UnlockPortCheckTest {

    private val old = 56716
    private val new = 56721
    private val other = 56800

    @BeforeTest fun clean() = SocksPortRedirect.reset()
    @AfterTest fun cleanAfter() = SocksPortRedirect.reset()

    private fun decide(published: Int, answered: Boolean, answeredPort: Int): UnlockPortCheck.Verdict =
        UnlockPortCheck.decide(published, SocksPortRedirect.resolve(published), answered, answeredPort)

    @Test fun matchIsConfirmed() {
        assertEquals(UnlockPortCheck.Verdict.CONFIRMED, decide(old, answered = true, answeredPort = old))
    }

    @Test fun differentPortWithCompletedRedirectIsConfirmed() {
        SocksPortRedirect.beginMove(old)
        assertTrue(SocksPortRedirect.completeMove(old, new))
        assertEquals(UnlockPortCheck.Verdict.CONFIRMED, decide(old, answered = true, answeredPort = new))
    }

    @Test fun differentPortWhileMoveInFlightIsMovingNotDead() {
        // The field failure: toggle sent, readback not concluded, unlock checks now.
        SocksPortRedirect.beginMove(old)
        val v = decide(old, answered = true, answeredPort = new)
        assertEquals(UnlockPortCheck.Verdict.MOVING, v)
        assertTrue(UnlockPortCheck.shouldWait(v))
    }

    @Test fun emptyAnswerWhileMoveInFlightIsMoving() {
        SocksPortRedirect.beginMove(old)
        assertEquals(UnlockPortCheck.Verdict.MOVING, decide(old, answered = true, answeredPort = 0))
    }

    @Test fun differentPortTheRedirectDoesNotKnowIsUntrackedNotDead() {
        val v = decide(old, answered = true, answeredPort = new)
        assertEquals(UnlockPortCheck.Verdict.UNTRACKED_PORT, v)
        assertTrue(UnlockPortCheck.shouldWait(v))
    }

    @Test fun portDifferentFromTheRedirectTargetIsUntracked() {
        SocksPortRedirect.beginMove(old)
        SocksPortRedirect.completeMove(old, new)
        assertEquals(UnlockPortCheck.Verdict.UNTRACKED_PORT, decide(old, answered = true, answeredPort = other))
    }

    @Test fun answeredEmptyIsNoListenerNotDead() {
        val v = decide(old, answered = true, answeredPort = 0)
        assertEquals(UnlockPortCheck.Verdict.NO_LISTENER, v)
        assertTrue(UnlockPortCheck.shouldWait(v))
    }

    @Test fun silentIsDead() {
        assertEquals(UnlockPortCheck.Verdict.DEAD, decide(old, answered = false, answeredPort = 0))
        // Even mid-move: a channel that never answers is a dead tor_main.
        SocksPortRedirect.beginMove(old)
        assertEquals(UnlockPortCheck.Verdict.DEAD, decide(old, answered = false, answeredPort = 0))
    }

    @Test fun publishedZeroHasNothingToAuthenticate() {
        assertEquals(UnlockPortCheck.Verdict.NO_CACHED_PORT, decide(0, answered = true, answeredPort = new))
        assertEquals(UnlockPortCheck.Verdict.NO_CACHED_PORT, decide(0, answered = false, answeredPort = 0))
    }

    @Test fun republishedPortIsConfirmed() {
        // iOS re-publishes the new port about a circuit after the toggle.
        SocksPortRedirect.beginMove(old)
        SocksPortRedirect.completeMove(old, new)
        assertEquals(UnlockPortCheck.Verdict.CONFIRMED, decide(new, answered = true, answeredPort = new))
    }

    @Test fun onlySilenceIsDead() {
        for (published in listOf(0, old)) for (answered in listOf(true, false)) for (port in listOf(0, old, new)) {
            val v = decide(published, answered, port)
            assertEquals(published > 0 && !answered, v == UnlockPortCheck.Verdict.DEAD, "p=$published a=$answered port=$port")
        }
    }

    @Test fun waitAndSettleTable() {
        assertFalse(UnlockPortCheck.shouldWait(UnlockPortCheck.Verdict.CONFIRMED))
        assertFalse(UnlockPortCheck.shouldWait(UnlockPortCheck.Verdict.DEAD))
        assertFalse(UnlockPortCheck.shouldWait(UnlockPortCheck.Verdict.NO_CACHED_PORT))
        assertEquals(UnlockPortCheck.Settle.WIRE_FAIL_CLOSED, UnlockPortCheck.settleAfterWait(UnlockPortCheck.Verdict.MOVING, false))
        assertEquals(UnlockPortCheck.Settle.ADOPT_REPORTED_PORT, UnlockPortCheck.settleAfterWait(UnlockPortCheck.Verdict.UNTRACKED_PORT, false))
        assertNull(UnlockPortCheck.settleAfterWait(UnlockPortCheck.Verdict.DEAD, false))
        assertNull(UnlockPortCheck.settleAfterWait(UnlockPortCheck.Verdict.CONFIRMED, true))
    }

    /** Folds a wait's per-poll verdicts the way AppState does, then settles. */
    private fun settleRun(vararg polls: UnlockPortCheck.Verdict): UnlockPortCheck.Settle? {
        var every = true
        for (v in polls) every = every && v == UnlockPortCheck.Verdict.NO_LISTENER
        return UnlockPortCheck.settleAfterWait(polls.last(), every)
    }

    @Test fun noListenerForTheWholeWaitLatches() {
        val run = Array(UnlockPortCheck.RECHECK_BUDGET) { UnlockPortCheck.Verdict.NO_LISTENER }
        assertEquals(UnlockPortCheck.Settle.LATCH_DEAD, settleRun(*run))
    }

    @Test fun noListenerThenAListenerNeverLatches() {
        // A listener seen mid-wait means CONFIRMED and the wait ends; a later empty
        // run that exhausts the wait was not empty throughout.
        assertEquals(UnlockPortCheck.Settle.BLOCK_THEN_WIRE, settleRun(
            UnlockPortCheck.Verdict.NO_LISTENER, UnlockPortCheck.Verdict.UNTRACKED_PORT, UnlockPortCheck.Verdict.NO_LISTENER))
    }

    @Test fun mixedMovingAndNoListenerNeverLatches() {
        // The toggle's own empty window: the listener closed while the redirect is
        // blocked (MOVING), then an empty answer.
        assertEquals(UnlockPortCheck.Settle.BLOCK_THEN_WIRE, settleRun(
            UnlockPortCheck.Verdict.MOVING, UnlockPortCheck.Verdict.NO_LISTENER, UnlockPortCheck.Verdict.NO_LISTENER))
        assertEquals(UnlockPortCheck.Settle.WIRE_FAIL_CLOSED, settleRun(
            UnlockPortCheck.Verdict.NO_LISTENER, UnlockPortCheck.Verdict.MOVING))
    }

    @Test fun waitIsBoundedByCountAndWallClock() {
        assertFalse(UnlockPortCheck.waitExhausted(attempt = 1, elapsedMs = 0))
        assertTrue(UnlockPortCheck.waitExhausted(attempt = UnlockPortCheck.RECHECK_BUDGET, elapsedMs = 0))
        // Slow polls (3 s query timeouts) hit the wall-clock cap long before the count.
        assertTrue(UnlockPortCheck.waitExhausted(attempt = 5, elapsedMs = 14_600))
        assertFalse(UnlockPortCheck.waitExhausted(attempt = 5, elapsedMs = 10_000))
    }
}

package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The "Almost there" (scan-back) pairing screen and the control-sweep cadence.
 *
 * Reproduces the 2026-09-27 field report (e2e `pairing-two-scan.multi.spec.ts`,
 * measured 69 s on a hermetic relay): the peer's inbox announce lands on the relay
 * within a second, but the waiting side only learns of it on the NEXT idle control
 * sweep — 60–90 s away — because nothing on that screen armed the fast cadence and
 * nothing could wake a loop already asleep in its idle wait.
 *
 * Two shared pieces close it, and both platforms consume them identically:
 *  - [MessageManager.notePairingAwaitingPeer]: the screen ticks it while the
 *    scan-back state is showing; the first tick of a visit is PROGRESS (a local,
 *    user-attended event), later ticks are bare arms, so the episode ceiling
 *    still bounds one visit.
 *  - [MessageManager.controlPollIdleWaitShouldEnd]: the platform loops sleep in
 *    slices and ask it each slice; an IDLE wait ends the moment the window opens,
 *    a FAST wait is never cut (no 1 s busy cadence).
 */
class PairingWaitCadenceTest {

    private fun manager(clock: () -> Long): MessageManager =
        MessageManager(InMemoryVault(), "http://relay.test", FakeRelayHttp.allVerbs(HttpResult(code = 503, body = null, isSuccess = false))).also { it.controlConvergenceClockMs = clock }

    @Test
    fun scanBackScreen_armsTheFastCadence() {
        var clock = 1_000_000L
        val mgr = manager { clock }
        assertFalse(mgr.isControlConverging(), "a fresh manager idles")

        mgr.notePairingAwaitingPeer()
        assertTrue(mgr.isControlConverging(), "the waiting screen must open the fast window")
        assertTrue(
            mgr.controlPollDelayMs(convergingNow = false) < MessageManager.CONTROL_POLL_IDLE_BASE_MS,
            "the next sweep after the announce lands must be seconds away, not 60–90 s",
        )
    }

    @Test
    fun idleWait_endsWhenTheScreenArms_fastWaitIsNeverCut() {
        var clock = 1_000_000L
        val mgr = manager { clock }
        val idle = mgr.controlPollDelayMs(convergingNow = false)
        assertTrue(idle >= MessageManager.CONTROL_POLL_IDLE_BASE_MS)
        // The loop is asleep in its idle wait; nothing has happened.
        assertFalse(mgr.controlPollIdleWaitShouldEnd(idle), "a quiet idle wait runs its course")

        // The user reaches the scan-back screen mid-sleep.
        clock += 20_000L
        mgr.notePairingAwaitingPeer()
        assertTrue(mgr.controlPollIdleWaitShouldEnd(idle), "an idle wait must end the moment the window opens")

        // A FAST wait chosen while converging must not be shortened into a 1 s busy loop.
        val fast = mgr.controlPollDelayMs(convergingNow = false)
        assertTrue(fast < MessageManager.CONTROL_POLL_IDLE_BASE_MS)
        assertFalse(mgr.controlPollIdleWaitShouldEnd(fast), "only IDLE waits are interruptible")
    }

    @Test
    fun oneVisit_isBoundedByTheEpisodeCeiling() {
        // The screen ticks every second. Only the FIRST tick of a visit is progress;
        // a user who leaves the screen up for an hour gets the fast cadence for the
        // episode ceiling and then the idle loop — the same bound peer noise gets.
        var clock = 1_000_000L
        val mgr = manager { clock }
        mgr.notePairingAwaitingPeer()
        var ticks = 0
        while (ticks < (MessageManager.CONTROL_FAST_EPISODE_MAX_MS / 1_000L).toInt() + 30) {
            clock += 1_000L
            mgr.notePairingAwaitingPeer()
            ticks++
        }
        assertFalse(mgr.isControlConverging(), "ticking the screen must not hold the fast cadence open forever")
    }

    @Test
    fun aNewVisit_afterAQuietGap_startsAFreshEpisode() {
        var clock = 1_000_000L
        val mgr = manager { clock }
        // Exhaust one episode on a long first visit.
        mgr.notePairingAwaitingPeer()
        repeat((MessageManager.CONTROL_FAST_EPISODE_MAX_MS / 1_000L).toInt() + 30) {
            clock += 1_000L
            mgr.notePairingAwaitingPeer()
        }
        assertFalse(mgr.isControlConverging())
        // The user leaves; the window lapses; they come back and pair someone else.
        clock += MessageManager.CONTROL_CONVERGENCE_WINDOW_MS + 1
        mgr.notePairingAwaitingPeer()
        assertTrue(mgr.isControlConverging(), "a new visit is a new local event — fresh episode")
    }

    @Test
    fun aNewVisit_insideAnExhaustedEpisode_isProgress() {
        // Peer noise ran the episode out while the window stayed open (arms < 60 s
        // apart). The user then opens Add contact: that is a LOCAL, attended event
        // — the first tick of the visit re-anchors like our own control send would.
        var clock = 1_000_000L
        val mgr = manager { clock }
        mgr.noteControlActivity(progress = false)
        repeat(30) { clock += 50_000L; mgr.noteControlActivity(progress = false) }
        assertFalse(mgr.isControlConverging(), "peer noise exhausted the episode")

        clock += 10_000L
        mgr.notePairingAwaitingPeer()
        assertTrue(mgr.isControlConverging(), "the first tick of a pairing visit is progress")
        // …and the ticks that follow inside the same visit are bare arms.
        clock += 1_000L
        mgr.notePairingAwaitingPeer()
        assertEquals(true, mgr.isControlConverging())
    }
}

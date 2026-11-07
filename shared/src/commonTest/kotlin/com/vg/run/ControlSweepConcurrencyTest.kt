package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// FIX 3a / 3b (2026-09-16) — control-sweep latency on a phone with many
// contacts.
//
// OBSERVED on a real device: `RELAY control poll done: 6-20 contacts in
// 13.9 / 15.6 / 15.3 / 15.5 s` on a ~34 s cadence — ≈45 % of the whole
// foreground session inside a sweep — against `1-5 contacts in 0.7 s` on a
// phone with fewer contacts. The sweep peeked each contact's control inbox
// SERIALLY over Tor (~0.9 s each) with a 100–400 ms jitter sleep between them.
//
// What this file pins:
//   • the PEEK phase fans out, bounded at CONTROL_PEEK_CONCURRENCY;
//   • the DRAIN never does — `pollControlMessages` persists counters, applies
//     announces and steps the ratchet, and VaultDatabase thread-safety under
//     genuinely concurrent access is unproven on both platforms;
//   • the FIRST pass after connect stays serial (cold circuit, shared with the
//     health probe);
//   • every peek-first guarantee ControlPeekFirstTest pins is unchanged on the
//     concurrent path: only a peek that POSITIVELY answered 0 skips the drain,
//     every UNKNOWN still drains, and the blocked-contact filter still holds;
//   • the steady-state cadence is the new 60–90 s.
// ---------------------------------------------------------------------------

/** A distinct valid 32-char control-inbox id per contact. */
private fun ctlInboxFor(n: Int) = ("ctl$n".padEnd(32, 'A')).take(32)

private val SWEEP_CAP = "R".repeat(43)

/**
 * Thread-safe control relay double with a CONCURRENCY PROBE.
 *
 * A `/peek` blocks until [wantConcurrent] peeks are simultaneously inside it,
 * or until [waitBudgetMs] elapses — so "the fan-out really ran" is an assertion
 * that passes immediately when it did and fails fast (never hangs) when it did
 * not. A bare `GET /inbox/{id}` (the destructive drain) never probes: the drain
 * is required to stay sequential.
 */
private class SweepRelay(
    /** inboxId → pending count the peek reports; absent ⇒ a 404 (UNKNOWN). */
    val peekPending: MutableMap<String, Int> = mutableMapOf(),
    /** Raised between sweeps so a SERIAL pass never sits out the budget. */
    var wantConcurrent: Int = 1,
    private val waitBudgetMs: Long = 2_000L,
) : PeekCountRelay(
    textPending = peekPending,
    drainUnknown = RELAY_EMPTY_DRAIN,
    putReply = HttpResult(code = 200, body = "", isSuccess = true),
    deleteReply = HttpResult(code = 200, body = "", isSuccess = true),
) {
    val peeks: Int get() = requests.count { it.url.endsWith("/peek") }
    val drains: Int get() = drainRequests().size

    fun peekedInboxes(): List<String> = requests.filter { it.url.endsWith("/peek") }.map { "${it.method} ${it.url}" }

    override fun whilePeekInFlight() {
        val deadline = currentTimeMillis() + waitBudgetMs
        while (peeksInFlight < wantConcurrent && currentTimeMillis() < deadline) {
            sleepMillis(5L)
        }
    }
}

private fun seedSweepContacts(vault: InMemoryVault, count: Int): List<String> {
    val ids = mutableListOf<String>()
    for (n in 0 until count) {
        val contactId = "c$n"
        ids.add(contactId)
        vault.insertContact(ContactRecord(contactId, generateSecureRandom(32), 1, "A-$contactId", 0L))
        vault.insertInboxId(
            InboxIdRecord(
                inboxId = ctlInboxFor(n), contactId = contactId, createdAt = 1L,
                expiresAt = Long.MAX_VALUE, direction = MessageManager.DIR_INBOUND_CTL, cap = SWEEP_CAP,
            )
        )
    }
    return ids
}

class ControlSweepConcurrencyTest {

    // -- the gate ------------------------------------------------------------

    @Test
    fun concurrency_isOneUntilTheRelayHasAnsweredOnce() {
        val gm = GroupManager(InMemoryVault()) { null }
        // THE FIRST PASS AFTER CONNECT STAYS SERIAL: it shares a cold circuit
        // with the health probe, and the 2026-09-11 connect-UX work depends on
        // that ordering. A three-wide burst onto a circuit that has not answered
        // once is the 6a0c138 failure.
        assertEquals(
            1,
            gm.controlPeekConcurrency(contactCount = 16, converging = false, firstRelayAnswerSeen = false),
        )
        assertEquals(
            GroupManager.CONTROL_PEEK_CONCURRENCY,
            gm.controlPeekConcurrency(contactCount = 16, converging = false, firstRelayAnswerSeen = true),
        )
    }

    @Test
    fun concurrency_isOneWhileConvergingAndForASingleContact() {
        val gm = GroupManager(InMemoryVault()) { null }
        // While converging the peek is skipped entirely — every contact drains,
        // and a drain is vault-heavy and stays sequential.
        assertEquals(
            1,
            gm.controlPeekConcurrency(contactCount = 16, converging = true, firstRelayAnswerSeen = true),
        )
        // Nothing to parallelise; a one-contact device keeps the old code path.
        assertEquals(
            1,
            gm.controlPeekConcurrency(contactCount = 1, converging = false, firstRelayAnswerSeen = true),
        )
        assertTrue(GroupManager.CONTROL_PEEK_CONCURRENCY in 2..4, "3–4 in flight, per the brief")
    }

    // -- the fan-out ---------------------------------------------------------

    @Test
    fun steadyStateSweep_peeksInParallelAndDrainsNothingWhenEveryInboxIsEmpty() {
        val vault = InMemoryVault()
        seedSweepContacts(vault, 6)
        val relay = SweepRelay()
        for (n in 0 until 6) relay.peekPending[ctlInboxFor(n)] = 0
        val mgr = MessageManager(vault, "http://relay.test", relay)
        val gm = GroupManager(vault) { mgr }

        // Pass 1 is the FIRST pass: serial, and it latches the round-trip.
        assertFalse(mgr.hasCompletedRelayRoundTrip())
        gm.pollAllControls()
        assertEquals(6, relay.peeks)
        assertEquals(0, relay.drains, "an answered 0 must still skip the DESTRUCTIVE drain")
        assertTrue(mgr.hasCompletedRelayRoundTrip(), "a /peek that answered IS a completed round-trip")
        assertEquals(1, relay.peakConcurrentPeeks, "the connect-time pass must stay strictly sequential")

        // Pass 2 is steady state: the peeks fan out, bounded.
        relay.wantConcurrent = 2
        gm.pollAllControls()
        assertEquals(12, relay.peeks, "every contact is still peeked exactly once per sweep")
        assertEquals(0, relay.drains)
        assertTrue(relay.peakConcurrentPeeks >= 2, "the peek phase must actually run in parallel")
        assertTrue(
            relay.peakConcurrentPeeks <= GroupManager.CONTROL_PEEK_CONCURRENCY,
            "…and never wider than the bound: ${relay.peakConcurrentPeeks}",
        )
    }

    @Test
    fun steadyStateSweep_drainsOnlyTheInboxesThatPositivelyReportedTraffic() {
        val vault = InMemoryVault()
        seedSweepContacts(vault, 4)
        val relay = SweepRelay()
        relay.peekPending[ctlInboxFor(0)] = 0
        relay.peekPending[ctlInboxFor(1)] = 3      // has traffic ⇒ drain
        relay.peekPending[ctlInboxFor(2)] = 0
        // contact 3 is deliberately ABSENT ⇒ the peek 404s ⇒ UNKNOWN ⇒ drain.
        val mgr = MessageManager(vault, "http://relay.test", relay)
        val gm = GroupManager(vault) { mgr }

        gm.pollAllControls()                       // pass 1: serial, latches the round-trip
        val peeksAfterFirst = relay.peeks
        val drainsAfterFirst = relay.drains
        assertEquals(4, peeksAfterFirst)
        assertEquals(2, drainsAfterFirst, "the pending one and the UNKNOWN one")

        relay.wantConcurrent = 2
        gm.pollAllControls()                       // pass 2: parallel peek phase
        assertEquals(8, relay.peeks, "one peek per contact per sweep, parallel or not")
        assertEquals(
            4, relay.drains,
            "UNKNOWN (404) still DRAINS on the concurrent path — treating it as empty would starve delivery",
        )
        assertTrue(relay.peakConcurrentPeeks >= 2)
    }

    @Test
    fun steadyStateSweep_neverPeeksABlockedContactsInbox() {
        // The block set severs the polling relationship, not just
        // the row display. The fan-out is fed the already-filtered contact list,
        // so this must hold on the concurrent path too.
        val vault = InMemoryVault()
        seedSweepContacts(vault, 4)
        val relay = SweepRelay()
        for (n in 0 until 4) relay.peekPending[ctlInboxFor(n)] = 0
        val mgr = MessageManager(vault, "http://relay.test", relay)
        val gm = GroupManager(vault) { mgr }
        gm.blockedContacts = { setOf("c2") }

        gm.pollAllControls()                       // pass 1 (serial)
        relay.wantConcurrent = 2
        gm.pollAllControls()                       // pass 2 (parallel)

        assertEquals(6, relay.peeks, "3 unblocked contacts × 2 sweeps")
        assertTrue(
            relay.peekedInboxes().none { it.contains(ctlInboxFor(2)) },
            "a blocked contact's control inbox must never be probed",
        )
        assertEquals(0, relay.drains)
    }

    @Test
    fun convergingSweep_skipsThePeekEntirelyOnBothPaths() {
        val vault = InMemoryVault()
        seedSweepContacts(vault, 4)
        val relay = SweepRelay()
        for (n in 0 until 4) relay.peekPending[ctlInboxFor(n)] = 0
        val mgr = MessageManager(vault, "http://relay.test", relay)
        val gm = GroupManager(vault) { mgr }

        gm.pollAllControls()                       // latch the round-trip
        val peeksBefore = relay.peeks
        val drainsBefore = relay.drains

        mgr.noteControlActivity(progress = true)
        assertTrue(mgr.isControlConverging())
        gm.pollAllControls()

        assertEquals(peeksBefore, relay.peeks, "while converging the probe is pure added latency")
        assertEquals(drainsBefore + 4, relay.drains, "every contact drains instead")
    }

    // -- FIX 3b: the steady-state cadence ------------------------------------

    @Test
    fun idleControlCadence_isSixtyToNinetySeconds() {
        assertEquals(60_000L, MessageManager.CONTROL_POLL_IDLE_BASE_MS)
        assertEquals(30_000, MessageManager.CONTROL_POLL_IDLE_JITTER_MS)
        val mgr = MessageManager(InMemoryVault(), "http://relay.test", SweepRelay())
        repeat(20) {
            val delay = mgr.controlPollDelayMs(convergingNow = false)
            assertTrue(delay in 60_000L until 90_000L, "idle control delay was $delay")
        }
        // The FAST window a convergence round-trip opens is untouched — a
        // join→roster→resolve chain must still settle in seconds.
        mgr.noteControlActivity(progress = true)
        val fast = mgr.controlPollDelayMs(convergingNow = false)
        assertTrue(fast < MessageManager.CONTROL_POLL_IDLE_BASE_MS, "fast cadence was $fast")
    }
}

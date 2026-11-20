package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// The legacy compensator's answered-zero heal versus OUR OWN drain lease
// (2026-11-18). A leased blob is invisible to /peek, so while one of our drains
// holds a lease on a contact's TEXT inbox, a peek answering 0 does not prove the
// inbox is empty: the lease can still end without the blob being deleted (an ack
// lost over Tor, a partial commit, an abandoned screen poll) and the blob comes
// back. If the heal had removed the legacy unit meanwhile, that returning group
// text would light the CONTACT row. Alice is the receiver; Bob is a legacy peer
// (no group inbox), so his group texts ride Alice's text inbox and his notices
// carry no `gi`.
// ---------------------------------------------------------------------------

/** Transparent over [inner], except that it can LOSE the answer to Alice's next text
 *  drain: the relay serves it (and leases the blobs), the client sees a transport error. */
private class LosingResponseRelay(val inner: LeasingRelay) : RelayHttp by inner {
    var loseNextTextDrain = false
    override fun get(url: String, headers: Map<String, String>, timeoutSeconds: Int): HttpResult {
        val r = inner.get(url, headers, timeoutSeconds)
        if (loseNextTextDrain && url.contains("/inbox/$LA_IN_A?lease=1")) {
            loseNextTextDrain = false
            throw RuntimeException("simulated lost response")
        }
        return r
    }
}

private class LeaseHealHarness {
    // Process-wide state (lease ledger + uncommitted-legacy registry): start clean —
    // other suites drain contact `c1` too, and a stale uncommitted drain there would
    // hold this harness's first screen poll for a round. FIRST, before any manager is
    // built: a manager captures the receive session at construction.
    @Suppress("unused") private val freshSession = MessageManager.endProcessReceiveSession()
    val la = LaHarness(ratchet = false)
    val losing = LosingResponseRelay(la.relay)
    /** Alice's receiving manager, over [losing] (transparent unless asked to lose). */
    val aliceRecv = MessageManager(la.alice, "http://relay.test", losing).syncAcks()
    val gm = GroupManager(la.alice) { aliceRecv }
    private val myMemberId = bytesToHex(ByteArray(8) { 1 })
    private val peerMemberId = bytesToHex(ByteArray(8) { 2 })
    val gid = GroupManager.newGroupId()

    init {
        la.alice.insertGroup(GroupRecord(gid, "crew", 1, adminMemberId = myMemberId, myMemberId = myMemberId, createdAt = 0L))
        la.alice.insertGroupMember(GroupMemberRecord(gid, myMemberId, contactId = null, addedAt = 0L))
        la.alice.insertGroupMember(GroupMemberRecord(gid, peerMemberId, contactId = LA, addedAt = 0L))
    }

    private fun hash() = GroupManager.membershipHash(gid, 1, listOf(myMemberId, peerMemberId))

    fun bobSendsGroupText(text: String) =
        assertEquals(MessageManager.GroupTextRoute.MAIN, la.bobMgr.sendGroupTextRouted(LA, gid, hash(), text))

    fun bobSendsLegacyNotice() = assertTrue(
        la.bobMgr.sendGroupControl(LA, gid, GroupManager.KIND_ACTIVITY, "{}", hash(), noPush = true)
    )

    fun bobSendsDirect(text: String) = assertTrue(la.bobMgr.sendMessage(LA, text))

    /** The group screen's poll: the legacy text is drained UNDER A LEASE. */
    fun groupScreenPoll(expect: List<String> = listOf("crew")): PendingDrain<GroupMessage> {
        val d = gm.pollGroupPending(gid)
        assertEquals(expect, d.messages.map { it.text })
        return d
    }
}

class LegacyHealLeaseTest {

    @Test
    fun aLostAckLease_isNotHealedAway_soTheReturningGroupTextStaysOffTheContactRow() {
        if (!aeadUp()) return
        val h = LeaseHealHarness()
        h.bobSendsGroupText("crew")
        val d = h.groupScreenPoll()           // consumed() runs here: the tally is 0
        h.la.relay.failAcks = true
        d.commit()                            // shown + persisted, but the ack is lost
        h.la.relay.failAcks = false
        h.bobSendsLegacyNotice()
        h.gm.pollAllControls()                // the notice lands: legacy tally 1
        assertEquals(0, h.la.relay.visible(LA_IN_A), "precondition: the blob is leased, so /peek answers 0")
        assertEquals(emptyMap(), h.gm.contactUnreadCounts())

        h.la.relay.expireLeases()             // the lease runs out without an ack: the blob is back
        assertEquals(1, h.la.relay.visible(LA_IN_A))
        assertEquals(emptyMap(), h.gm.contactUnreadCounts(), "a group text must never light the contact row")
    }

    @Test
    fun anAbandonedScreenPoll_isNotHealedAway_soTheReleasedGroupTextStaysOffTheContactRow() {
        if (!aeadUp()) return
        val h = LeaseHealHarness()
        h.bobSendsGroupText("crew")
        val d = h.groupScreenPoll()
        h.bobSendsLegacyNotice()
        h.gm.pollAllControls()
        assertEquals(emptyMap(), h.gm.contactUnreadCounts())   // peeks 0: the blob is leased

        d.abandon()                           // the user left mid-poll: the lease is released at once
        assertEquals(1, h.la.relay.visible(LA_IN_A))
        assertEquals(emptyMap(), h.gm.contactUnreadCounts(), "a group text must never light the contact row")
    }

    @Test
    fun aSettledLease_stillLetsTheZeroHeal_soThe1to1TextAfterItLights() {
        // The original defect must stay fixed when the lease ends the normal way.
        if (!aeadUp()) return
        val h = LeaseHealHarness()
        h.bobSendsGroupText("crew")
        h.groupScreenPoll().commit()          // shown, persisted, acked: the blob is deleted
        assertEquals(0, h.la.relay.total(LA_IN_A))
        h.bobSendsLegacyNotice()
        h.gm.pollAllControls()                // the late notice: a leftover unit
        assertEquals(emptyMap(), h.gm.contactUnreadCounts())   // answered 0, no lease outstanding: heals

        h.bobSendsDirect("private")
        assertEquals(mapOf(LA to 1), h.gm.contactUnreadCounts())
    }

    @Test
    fun aLostAckLease_alsoKeepsTheNonZeroClampFromWritingBack() {
        // Two legacy group texts leased by a screen poll whose ack is lost, both
        // notices late (legacy tally 2), then a real 1:1 text: the sweep sees depth 1.
        // Clamping the tally to that depth would leave one returning group text
        // unsubtracted once the lease ends.
        if (!aeadUp()) return
        val h = LeaseHealHarness()
        h.bobSendsGroupText("crew")
        h.bobSendsGroupText("crew")
        val d = h.groupScreenPoll(listOf("crew", "crew"))
        h.la.relay.failAcks = true
        d.commit()
        h.la.relay.failAcks = false
        h.bobSendsLegacyNotice()
        h.bobSendsLegacyNotice()
        h.gm.pollAllControls()
        h.bobSendsDirect("private")
        assertEquals(1, h.la.relay.visible(LA_IN_A))
        h.gm.contactUnreadCounts()

        h.la.relay.expireLeases()
        assertEquals(3, h.la.relay.visible(LA_IN_A))
        assertEquals(mapOf(LA to 1), h.gm.contactUnreadCounts(), "exactly the one 1:1 text, never a group text")
    }

    @Test
    fun aLostAckLease_stopsBlockingTheHealOnceTheGuardHasRunOut() {
        // The guard is bounded: a lease whose ack was lost stops counting after
        // TextLeaseLedger.LEASE_GUARD_MS (the relay's own lease has ended by then).
        if (!aeadUp()) return
        val h = LeaseHealHarness()
        var now = 1_000_000L
        TextLeaseLedger.clockMs = { now }
        try {
            h.bobSendsGroupText("crew")
            val d = h.groupScreenPoll()
            h.la.relay.failAcks = true
            d.commit()
            h.la.relay.failAcks = false
            h.bobSendsLegacyNotice()
            h.gm.pollAllControls()
            // The lease runs out; the next screen poll gets the duplicate back, drops
            // it (already persisted) and acks it away under a NEW token.
            h.la.relay.expireLeases()
            h.groupScreenPoll(expect = emptyList()).commit()
            assertEquals(0, h.la.relay.total(LA_IN_A))

            now += TextLeaseLedger.LEASE_GUARD_MS
            assertEquals(emptyMap(), h.gm.contactUnreadCounts())   // answered 0, guard over: heals
            h.bobSendsDirect("private")
            assertEquals(mapOf(LA to 1), h.gm.contactUnreadCounts())
        } finally {
            TextLeaseLedger.clockMs = { GroupUnreadTally.monotonicNowMs() }
            TextLeaseLedger.scrub()
        }
    }

    @Test
    fun aLostDrainResponse_isTreatedAsAPossibleLease_soTheReturningGroupTextStaysOffTheContactRow() {
        // The relay SERVED the screen's leasing GET (the blob is now leased and hidden
        // from /peek) but the answer never reached the client. Nothing was consumed,
        // nothing will be acked; the lease ends on its own and the blob comes back.
        if (!aeadUp()) return
        val h = LeaseHealHarness()
        h.bobSendsGroupText("crew")
        h.losing.loseNextTextDrain = true
        h.groupScreenPoll(expect = emptyList())
        assertEquals(0, h.la.relay.visible(LA_IN_A), "precondition: served and leased")
        h.bobSendsLegacyNotice()
        h.gm.pollAllControls()
        assertEquals(emptyMap(), h.gm.contactUnreadCounts())

        h.la.relay.expireLeases()
        assertEquals(1, h.la.relay.visible(LA_IN_A))
        assertEquals(emptyMap(), h.gm.contactUnreadCounts(), "a group text must never light the contact row")
    }

    @Test
    fun aDrainInFlightAcrossTheSessionEnd_cannotWriteTheLedgerBack() {
        // The lock / wipe lands while the GET is on the wire (Android: on a manager
        // nobody scrubbed). Its lease must not be recorded into the next session.
        if (!aeadUp()) return
        val h = LeaseHealHarness()
        h.bobSendsDirect("hi")
        h.la.relay.beforeGet = { url ->
            if (url.contains("/inbox/$LA_IN_A?lease=1")) MessageManager.endProcessReceiveSession()
        }
        val d = h.aliceRecv.pollMessagesPending(LA)
        h.la.relay.beforeGet = null
        assertEquals(listOf("hi"), d.messages.map { it.text }, "precondition: blobs came back under a lease")
        assertFalse(TextLeaseLedger.blocksHeal(LA, Long.MIN_VALUE))
        d.abandon()
    }

    @Test
    fun theProcessWideEnd_discardsAnUncommittedLegacyDrainOfAManagerNobodyScrubbed() {
        // Android drops the manager without a scrub on Tor Failed/Idle; the lock that
        // follows calls MessageManager.endProcessReceiveSession(). A stale screen's
        // late commit must then persist nothing and ack nothing — what scrubInMemory
        // does for a manager that still exists.
        if (!aeadUp()) return
        val h = LeaseHealHarness()
        h.bobSendsDirect("hi")
        val before = h.la.textBaseline()
        val d = h.aliceRecv.pollMessagesPending(LA)
        assertEquals(listOf("hi"), d.messages.map { it.text })
        h.la.relay.ackPosts.clear()
        MessageManager.endProcessReceiveSession()
        d.commit()
        assertEquals(before, h.la.textBaseline(), "no legacy baseline written after the session end")
        assertTrue(h.la.relay.acksFor(LA_IN_A).isEmpty(), "no ack sent after the session end")
    }

    @Test
    fun withoutTheSessionEnd_thatCommitDoesPersistAndAck() {
        // Anti-vacuity for the test above.
        if (!aeadUp()) return
        val h = LeaseHealHarness()
        h.bobSendsDirect("hi")
        val before = h.la.textBaseline()
        val d = h.aliceRecv.pollMessagesPending(LA)
        h.la.relay.ackPosts.clear()
        d.commit()
        assertTrue(h.la.textBaseline() > before)
        assertFalse(h.la.relay.acksFor(LA_IN_A).isEmpty())
    }
}

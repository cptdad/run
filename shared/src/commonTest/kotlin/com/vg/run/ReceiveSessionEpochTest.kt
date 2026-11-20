package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// The receive-session epoch a MessageManager captures at construction
// (TextLeaseLedger.sessionEpoch): after a lock / wipe ended that session the
// manager writes neither the lease ledger nor the uncommitted-legacy registry —
// also when nobody scrubbed it (Android drops it unscrubbed on Tor Failed/Idle) —
// while a manager built in the SAME session (a reconnect) keeps everything.
// Alice receives over a LeasingRelay; contact `c1` is a legacy (non-ratchet) pairing,
// so every pending drain carries a legacy baseline and registers.
// ---------------------------------------------------------------------------

class ReceiveSessionEpochTest {

    /** A fresh session first, THEN the managers (they capture it at construction). */
    private fun harness(): LaHarness {
        MessageManager.endProcessReceiveSession()
        return LaHarness(ratchet = false)
    }

    private val leaseGet = "/inbox/$LA_IN_A?lease=1"

    @Test
    fun aDrainProcessedAfterTheSessionEnd_leavesTheLegacyRegistryEmpty_andItsCommitDoesNothing() {
        if (!aeadUp()) return
        val la = harness()
        assertTrue(la.bobMgr.sendMessage(LA, "hi"))
        // The lock / wipe lands while the GET is on the wire; the manager is NOT scrubbed.
        la.relay.beforeGet = { url -> if (url.contains(leaseGet)) MessageManager.endProcessReceiveSession() }
        val d = la.aliceMgr.pollMessagesPending(LA)
        la.relay.beforeGet = null
        assertEquals(listOf("hi"), d.messages.map { it.text }, "precondition: the drain completed after the end")
        assertEquals(0, MessageManager.pendingLegacyCountForTest(), "a stale manager re-registered a pending drain")
        val before = la.textBaseline()
        la.relay.ackPosts.clear()
        d.commit()
        assertEquals(before, la.textBaseline(), "no baseline written from an ended session")
        assertTrue(la.relay.acksFor(LA_IN_A).isEmpty(), "no ack sent from an ended session")
    }

    @Test
    fun aFetchBegunByAPreEndManagerAfterTheClear_leavesTheLedgerEmpty() {
        if (!aeadUp()) return
        val la = harness()
        val stale = la.aliceMgr
        MessageManager.endProcessReceiveSession()     // the session ends; `stale` was never scrubbed
        assertTrue(la.bobMgr.sendMessage(LA, "hi"))
        // Tor is being stopped: the GET fails (an "unseen" outcome would keep a mark).
        la.relay.beforeGet = { url -> if (url.contains(leaseGet)) throw RuntimeException("tor stopped") }
        stale.pollMessagesPending(LA)
        la.relay.beforeGet = null
        assertFalse(TextLeaseLedger.blocksHeal(LA, Long.MIN_VALUE), "a contact id was written into the ended session")
    }

    @Test
    fun aManagerBuiltAfterTheClear_recordsNormally() {
        if (!aeadUp()) return
        val la = harness()
        MessageManager.endProcessReceiveSession()     // the previous session ends …
        val fresh = MessageManager(la.alice, "http://relay.test", la.relay).syncAcks()   // … the next one begins
        assertTrue(la.bobMgr.sendMessage(LA, "hi"))
        val d = fresh.pollMessagesPending(LA)
        assertEquals(listOf("hi"), d.messages.map { it.text })
        assertEquals(1, MessageManager.pendingLegacyCountForTest())
        assertTrue(TextLeaseLedger.blocksHeal(LA, Long.MIN_VALUE), "the lease is recorded")
        la.relay.ackPosts.clear()
        d.commit()
        assertEquals(0, MessageManager.pendingLegacyCountForTest())
        assertFalse(la.relay.acksFor(LA_IN_A).isEmpty())
    }

    @Test
    fun aSameSessionReconnect_keepsThePendingLegacyDrainAndTheLeaseRecord() {
        if (!aeadUp()) return
        val la = harness()
        assertTrue(la.bobMgr.sendMessage(LA, "hi"))
        val d = la.aliceMgr.pollMessagesPending(LA)
        assertEquals(1, MessageManager.pendingLegacyCountForTest())
        // Tor Failed → Connected: the old manager is dropped WITHOUT a scrub and a new
        // one is built — no session end in between.
        val reconnected = MessageManager(la.alice, "http://relay.test", la.relay).syncAcks()
        assertEquals(1, MessageManager.pendingLegacyCountForTest(), "the pending drain survives the reconnect")
        assertTrue(TextLeaseLedger.blocksHeal(LA, Long.MIN_VALUE), "…and so does its lease record")
        // The old screen's commit still persists and acks.
        val before = la.textBaseline()
        la.relay.ackPosts.clear()
        d.commit()
        assertTrue(la.textBaseline() > before)
        assertFalse(la.relay.acksFor(LA_IN_A).isEmpty())
        // …and the new manager records its own drains.
        assertTrue(la.bobMgr.sendMessage(LA, "again"))
        val d2 = reconnected.pollMessagesPending(LA)
        assertEquals(listOf("again"), d2.messages.map { it.text })
        assertEquals(1, MessageManager.pendingLegacyCountForTest())
        d2.commit()
    }
}

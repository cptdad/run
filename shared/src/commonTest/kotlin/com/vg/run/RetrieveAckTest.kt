package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// Retrieve-ack (2026-11-03): the client side of the leasing drain.
//
//   GET /inbox/{id}?lease=1 → {"blobs":[…],"ids":[…],"token":"…"}, nothing deleted,
//   the blobs hidden (leased) until POST /ack deletes the processed ids and
//   releases the rest of that token at once.
//
// Pinned here over a relay double that implements exactly that contract
// (relay `retrieveCore` / `authenticatedAck`, see docs/RELAY_SPEC.md):
//   • every drain leases and acks EXACTLY the blobs it processed (rejected ones
//     included), never the cutoff tail or the blobs past the per-poll cap;
//   • a deferred sealed-control wire is acked (the vault copy is the one retried);
//   • the conversation screens' PendingDrain: no commit ⇒ no persist + no ack ⇒ the
//     messages come back; commit ⇒ persist then ack; idempotent; abandon releases;
//   • a newer screen poll that finds an older one uncommitted loses nothing;
//   • a re-delivery after a LOST ack is dropped on the ratchet AND the legacy path,
//     labelled "re-delivery" in the log;
//   • the group fan-out and a sweep send ONE ack batch; bodies split at 64 items /
//     256 ids;
//   • an old relay that ignores ?lease=1 (deleted at fetch) keeps today's semantics.
// ---------------------------------------------------------------------------

private inline fun <T> laWithLogs(block: () -> T): T {
    val was = LoggingState.enabled
    LoggingState.enabled = true
    LogBuffer.clear()
    try { return block() } finally { LoggingState.enabled = was; LogBuffer.clear() }
}

private fun laLogs(): List<String> = LogBuffer.getAll().map { it.message }

// The relay double ([LeasingRelay]), [syncAcks], [LaHarness] and the LA_* ids live in
// support/LeasingRelay.kt.

class RetrieveAckTest {

    @Test
    fun everyDrainLeases_andAcksExactlyTheBlobsItProcessed_rejectedOnesIncluded() {
        if (!aeadUp()) return
        val h = LaHarness(ratchet = false)
        assertTrue(h.bobMgr.sendMessage(LA, "x"))
        h.relay.deliver(LA_IN_A, ByteArray(10))                   // malformed: processed, refused
        assertTrue(h.bobMgr.sendMessage(LA, "y"))
        val all = h.relay.idsOf(LA_IN_A)

        assertEquals(listOf("x", "y"), h.aliceMgr.pollMessages(LA).map { it.text })
        assertTrue(h.relay.getUrls.last().endsWith("/inbox/$LA_IN_A?lease=1"), "the bare (deleting) GET is never used")
        val acks = h.relay.acksFor(LA_IN_A)
        assertEquals(1, acks.size)
        assertEquals(all.toSet(), acks.single().delete.toSet(), "accepted AND rejected blobs are acked")
        assertEquals(0, h.relay.total(LA_IN_A))
    }

    @Test
    fun theRatchetCutoffTail_isNotAcked_andTheNextDrainDeliversIt() {
        if (!aeadUp()) return
        val h = LaHarness(ratchet = true)
        val magic = MessageManager.RATCHET_WIRE_MAGIC
        repeat(RatchetManager.MAX_CONSECUTIVE_FAILURES_PER_BATCH) {
            h.relay.deliver(LA_IN_A, magic + ByteArray(40) + generateSecureRandom(48))
        }
        val junk = h.relay.idsOf(LA_IN_A)
        assertTrue(h.bobMgr.sendMessage(LA, "behind the junk"))

        assertEquals(emptyList(), h.aliceMgr.pollMessages(LA).map { it.text })
        assertEquals(junk.toSet(), h.relay.acksFor(LA_IN_A).single().delete.toSet(), "only the processed junk is deleted")
        assertEquals(1, h.relay.visible(LA_IN_A), "the cutoff tail is RELEASED at once by the ack, not lost")
        assertEquals(listOf("behind the junk"), h.aliceMgr.pollMessages(LA).map { it.text })
        assertEquals(0, h.relay.total(LA_IN_A))
    }

    @Test
    fun blobsBeyondThePerPollCap_areNotAcked_andComeBack() {
        if (!aeadUp()) return
        val h = LaHarness(ratchet = false)
        repeat(MessageManager.MAX_BLOBS_PER_POLL + 2) { h.relay.deliver(LA_IN_A, ByteArray(5)) }
        val ids = h.relay.idsOf(LA_IN_A)
        h.aliceMgr.pollMessages(LA)
        val deleted = h.relay.acksFor(LA_IN_A).flatMap { it.delete }
        assertEquals(ids.take(MessageManager.MAX_BLOBS_PER_POLL).toSet(), deleted.toSet())
        assertEquals(2, h.relay.visible(LA_IN_A), "the tail past the cap used to be silently lost")
    }

    @Test
    fun aDeferredSealedControlWire_isAcked_andKeptInTheVault() {
        if (!aeadUp()) return
        val h = LaHarness(ratchet = true)
        repeat(DoubleRatchet.MAX_SKIPPED_STORE + 2) { assertTrue(h.bobMgr.sendMessage(LA, "u$it")) }
        assertTrue(h.bobMgr.sendGroupControl(LA, LA_GID, GroupManager.KIND_ROSTER, LA_ROSTER, LA_HASH, noPush = true))
        assertTrue(h.aliceMgr.pollControlMessages(LA).isEmpty(), "precondition: deferred behind the backlog")
        assertNotNull(h.alice.getMeta(MessageManager.drCtlDeferredKey(LA)))
        assertEquals(0, h.relay.total(LA_CTL_A), "DEFERRED is processed: the relay copy is acked")
    }

    // -- the conversation screens: PendingDrain --------------------------------

    @Test
    fun aScreenDrainThatIsNeverCommitted_persistsNothing_acksNothing_andTheMessageComesBack_ratchet() {
        if (!aeadUp()) return
        val h = LaHarness(ratchet = true)
        assertTrue(h.bobMgr.sendMessage(LA, "seen or not"))
        val state = h.ratchetState()
        val pd = h.aliceMgr.pollMessagesPending(LA)
        assertEquals(listOf("seen or not"), pd.messages.map { it.text })
        assertEquals(state, h.ratchetState(), "the ratchet advance must not be persisted before commit")
        assertTrue(h.relay.ackPosts.isEmpty(), "nothing acked before commit")
        assertEquals(1, h.relay.total(LA_IN_A))

        h.newSession()                                     // home / swipe / lock: no commit
        h.relay.expireLeases()
        assertEquals(listOf("seen or not"), h.aliceMgr.pollMessages(LA).map { it.text }, "re-delivered and decrypted again")
    }

    @Test
    fun aScreenDrainThatIsNeverCommitted_persistsNothing_andTheMessageComesBack_legacy() {
        if (!aeadUp()) return
        val h = LaHarness(ratchet = false)
        assertTrue(h.bobMgr.sendMessage(LA, "legacy"))
        val baseline = h.textBaseline()
        val pd = h.aliceMgr.pollMessagesPending(LA)
        assertEquals(listOf("legacy"), pd.messages.map { it.text })
        assertEquals(baseline, h.textBaseline(), "the anti-replay baseline must not move before commit")
        h.newSession()
        h.relay.expireLeases()
        assertEquals(listOf("legacy"), h.aliceMgr.pollMessages(LA).map { it.text })
    }

    @Test
    fun commit_persistsThenAcks_andIsIdempotent() {
        if (!aeadUp()) return
        val h = LaHarness(ratchet = true)
        assertTrue(h.bobMgr.sendMessage(LA, "on screen"))
        val state = h.ratchetState()
        val pd = h.aliceMgr.pollMessagesPending(LA)
        pd.commit()
        assertTrue(state != h.ratchetState(), "commit persists the advance")
        assertEquals(1, h.relay.ackPosts.size)
        assertEquals(0, h.relay.total(LA_IN_A))
        pd.commit(); pd.abandon()
        assertEquals(1, h.relay.ackPosts.size, "a second commit / a late abandon does nothing")
        assertTrue(h.aliceMgr.pollMessages(LA).isEmpty())
    }

    @Test
    fun commit_legacy_persistsTheBaseline() {
        if (!aeadUp()) return
        val h = LaHarness(ratchet = false)
        assertTrue(h.bobMgr.sendMessage(LA, "one"))
        val pd = h.aliceMgr.pollMessagesPending(LA)
        val before = h.textBaseline()
        pd.commit()
        assertTrue(h.textBaseline() > before)
        assertEquals(0, h.relay.total(LA_IN_A))
    }

    @Test
    fun abandon_releasesTheLeaseAtOnce_andTheNextPollShowsTheMessage() {
        if (!aeadUp()) return
        val h = LaHarness(ratchet = true)
        assertTrue(h.bobMgr.sendMessage(LA, "left mid-poll"))
        val pd = h.aliceMgr.pollMessagesPending(LA)
        pd.abandon()
        assertEquals(1, h.relay.visible(LA_IN_A), "released now, not after the 60 s lease")
        val again = h.aliceMgr.pollMessagesPending(LA)
        assertEquals(listOf("left mid-poll"), again.messages.map { it.text })
        again.commit()
        assertEquals(0, h.relay.total(LA_IN_A))
    }

    @Test
    fun aNewerScreenPoll_overAnUncommittedOne_losesNothing_ratchet() {
        if (!aeadUp()) return
        val h = LaHarness(ratchet = true)
        assertTrue(h.bobMgr.sendMessage(LA, "r1"))
        val stale = h.aliceMgr.pollMessagesPending(LA)       // the screen left mid-poll; never shown
        assertEquals(listOf("r1"), stale.messages.map { it.text })
        assertTrue(h.bobMgr.sendMessage(LA, "r2"))
        val p2 = h.aliceMgr.pollMessagesPending(LA)
        assertEquals(listOf("r2"), p2.messages.map { it.text })
        p2.commit()
        stale.commit()                                       // a late commit of the stale one is harmless
        val p3 = h.aliceMgr.pollMessagesPending(LA)
        assertEquals(listOf("r1"), p3.messages.map { it.text }, "the stale poll's message is shown, not lost")
        p3.commit()
        assertEquals(0, h.relay.total(LA_IN_A))
    }

    @Test
    fun aNewerScreenPoll_overAnUncommittedOne_losesNothing_legacy() {
        if (!aeadUp()) return
        val h = LaHarness(ratchet = false)
        assertTrue(h.bobMgr.sendMessage(LA, "L1"))
        val stale = h.aliceMgr.pollMessagesPending(LA)
        assertEquals(listOf("L1"), stale.messages.map { it.text })
        assertTrue(h.bobMgr.sendMessage(LA, "L2"))
        val p2 = h.aliceMgr.pollMessagesPending(LA)
        assertTrue(p2.messages.isEmpty(), "held one round so both counters meet in ONE sorted drain")
        p2.commit()
        val p3 = h.aliceMgr.pollMessagesPending(LA)
        assertEquals(listOf("L1", "L2"), p3.messages.map { it.text })
        p3.commit()
        assertEquals(0, h.relay.total(LA_IN_A))
    }

    @Test
    fun aControlSweepWhileAScreenHoldsAnUncommittedAdvance_leavesItsSealedControlForLater() {
        if (!aeadUp()) return
        val h = LaHarness(ratchet = true)
        assertTrue(h.bobMgr.sendMessage(LA, "t"))
        assertTrue(h.bobMgr.sendGroupControl(LA, LA_GID, GroupManager.KIND_ROSTER, LA_ROSTER, LA_HASH, noPush = true))
        val pd = h.aliceMgr.pollMessagesPending(LA)
        assertEquals(listOf("t"), pd.messages.map { it.text })
        assertTrue(h.aliceMgr.pollControlMessages(LA).isEmpty(), "rule 3: no ratchet work over an unshown advance")
        assertEquals(1, h.relay.visible(LA_CTL_A), "the sealed roster was left on the relay (not acked)")
        pd.commit()
        assertEquals(listOf(GroupManager.KIND_ROSTER), h.aliceMgr.pollControlMessages(LA).map { it.controlKind })
        assertEquals(0, h.relay.total(LA_CTL_A))
    }

    @Test
    fun aSendWhileAScreenDrainIsUncommitted_discardsIt_andTheMessageComesBack() {
        if (!aeadUp()) return
        val h = LaHarness(ratchet = true)
        assertTrue(h.bobMgr.sendMessage(LA, "racing the reply"))
        val pd = h.aliceMgr.pollMessagesPending(LA)
        assertTrue(h.aliceMgr.sendMessage(LA, "reply"))      // rule 4
        pd.commit()                                          // the advance is gone: nothing persisted
        assertEquals(listOf("racing the reply"), h.aliceMgr.pollMessages(LA).map { it.text }, "shown twice at worst, never lost")
        assertEquals(listOf("reply"), h.bobMgr.pollMessages(LA).map { it.text })
    }

    // -- re-delivery after a lost ack -----------------------------------------

    @Test
    fun aRedeliveryAfterALostAck_isDropped_andLabelled_legacy() {
        if (!aeadUp()) return
        val h = LaHarness(ratchet = false)
        assertTrue(h.bobMgr.sendMessage(LA, "once"))
        h.relay.failAcks = true
        assertEquals(listOf("once"), h.aliceMgr.pollMessages(LA).map { it.text })
        h.relay.failAcks = false
        h.relay.expireLeases()
        laWithLogs {
            assertTrue(h.aliceMgr.pollMessages(LA).isEmpty(), "the re-delivery is a duplicate and is dropped")
            assertTrue(laLogs().any { "re-delivery after a lost ack" in it }, laLogs().toString())
            assertFalse(laLogs().any { "(replay/dup)" in it })
        }
        assertEquals(0, h.relay.total(LA_IN_A), "…and acked this time")
    }

    @Test
    fun aRedeliveryAfterALostAck_isDropped_andLabelled_ratchet() {
        if (!aeadUp()) return
        val h = LaHarness(ratchet = true)
        assertTrue(h.bobMgr.sendMessage(LA, "once"))
        h.relay.failAcks = true
        assertEquals(listOf("once"), h.aliceMgr.pollMessages(LA).map { it.text })
        h.relay.failAcks = false
        h.relay.expireLeases()
        laWithLogs {
            assertTrue(h.aliceMgr.pollMessages(LA).isEmpty())
            assertTrue(laLogs().any { "likely re-delivery after a lost ack" in it }, laLogs().toString())
        }
        assertEquals(0, h.relay.total(LA_IN_A))
    }

    @Test
    fun anOldRelayThatIgnoresTheLease_keepsTodaysSemantics() {
        if (!aeadUp()) return
        val h = LaHarness(ratchet = false)
        h.relay.leasing = false
        assertTrue(h.bobMgr.sendMessage(LA, "deleted at fetch"))
        val before = h.textBaseline()
        val pd = h.aliceMgr.pollMessagesPending(LA)
        assertEquals(listOf("deleted at fetch"), pd.messages.map { it.text })
        assertTrue(h.textBaseline() > before, "nothing to wait for: committed inline, exactly as before")
        pd.commit()
        assertTrue(h.relay.ackPosts.isEmpty(), "no lease, no ack")
    }

    @Test
    fun noIdentifierInAnyRetrieveAckLogLine() {
        if (!aeadUp()) return
        val h = LaHarness(ratchet = true)
        laWithLogs {
            assertTrue(h.bobMgr.sendMessage(LA, "m"))
            h.relay.failAcks = true
            h.aliceMgr.pollMessagesPending(LA).commit()
            val lines = laLogs().filter { "retrieve-ack" in it || "re-delivery" in it || "uncommitted" in it }
            assertTrue(lines.isNotEmpty())
            for (l in lines) {
                assertFalse(LA_IN_A in l || LA_RCAP in l || LA in l.split(' '), "identifier in: $l")
                assertFalse(Regex("z[0-9]+q+").containsMatchIn(l), "blob id / token in: $l")
            }
        }
    }

    // -- batching ---------------------------------------------------------------

    @Test
    fun ackBodies_splitAt64Items_and256IdsPerItem_underTheByteCeiling() {
        val mgr = MessageManager(InMemoryVault(), "http://relay.test", LeasingRelay())
        val tok = "t".repeat(22)
        val items = (0 until 70).map { i ->
            MessageManager.AckItem(("i$i").padEnd(32, 'A'), LA_RCAP, tok, listOf(("d$i").padEnd(22, 'x')), "k$i")
        } + MessageManager.AckItem("w".repeat(32), LA_RCAP, tok, List(600) { ("e$it").padEnd(22, 'y') }, "big")
        val chunks = mgr.chunkAcks(items)
        assertTrue(chunks.all { it.size <= MessageManager.ACK_BATCH_MAX_ITEMS })
        assertTrue(chunks.flatten().all { it.deleteIds.size <= MessageManager.ACK_MAX_IDS_PER_ITEM })
        assertEquals(70 + 600, chunks.flatten().sumOf { it.deleteIds.size }, "nothing dropped by the split")
        assertTrue(chunks.all { mgr.ackBody(it).length <= MessageManager.ACK_BATCH_MAX_BODY_BYTES })
        val body = mgr.ackBody(listOf(items[0]))
        assertEquals("""{"v":1,"items":[{"id":"${items[0].inboxId}","rc":"$LA_RCAP","token":"$tok","delete":["${items[0].deleteIds[0]}"]}]}""", body)
    }

    @Test
    fun aMalformedLeaseFromTheRelay_isNeverEchoedIntoAnAck() {
        if (!aeadUp()) return
        val bad = FakeRelayHttp(
            onPost = { HttpResult(200, "{}", true) },
            onGet = { HttpResult(200, """{"blobs":["AAAA"],"ids":["x\",\"injected"],"token":"tttttttttttttttttttttt"}""", true) },
            onPut = { HttpResult(200, "{}", true) },
        )
        val v = InMemoryVault()
        v.insertContact(ContactRecord(contactId = LA, sharedSecret = generateSecureRandom(32), trustLevel = 0, alias = "p", aliasLastRotated = 0))
        v.insertInboxId(InboxIdRecord(LA_IN_A, LA, 0L, Long.MAX_VALUE, "inbound", LA_RCAP))
        val mgr = MessageManager(v, "http://relay.test", bad).syncAcks()
        mgr.pollMessages(LA)
        assertFalse(bad.requestsOf("POST").any { it.url.endsWith("/ack") }, "ids that are not 22-char base64url never reach an ack body")
    }
}

/** The group fan-out and the control sweep send ONE ack batch for every inbox they drained. */
class RetrieveAckGroupTest {

    private fun inbox(tag: String) = ("la$tag".padEnd(32, 'A')).take(32)

    private inner class Group(val peers: List<String>) {
        val relay = LeasingRelay()
        val bVault = InMemoryVault()
        val bMgr = MessageManager(bVault, "http://relay.test", relay).syncAcks()
        val bGm = GroupManager(bVault) { bMgr }
        val gid = GroupManager.newGroupId()
        val txtToB = peers.associateWith { inbox("${it}tb") }
        val senders = peers.associateWith { InMemoryVault().let { v -> v to MessageManager(v, "http://relay.test", relay).syncAcks() } }

        init {
            val me = "00000000000000b0"
            bVault.insertGroup(GroupRecord(gid, "crew", 1, adminMemberId = me, myMemberId = me, createdAt = 0L))
            bVault.insertGroupMember(GroupMemberRecord(gid, me, contactId = null, addedAt = 0L))
            peers.forEachIndexed { i, peer ->
                val secret = generateSecureRandom(32)
                val toPeer = inbox("${peer}ta")
                bVault.insertContact(ContactRecord(peer, secret, 1, peer.uppercase(), 0L))
                bVault.insertInboxId(InboxIdRecord(txtToB.getValue(peer), peer, 1L, Long.MAX_VALUE, "inbound", LA_RCAP))
                bVault.insertInboxId(InboxIdRecord(toPeer, peer, 1L, Long.MAX_VALUE, "outbound", LA_RCAP))
                bVault.insertGroupMember(GroupMemberRecord(gid, "00000000000000a$i", contactId = peer, addedAt = 0L))
                val sv = senders.getValue(peer).first
                sv.insertContact(ContactRecord("b", secret, 1, "B", 0L))
                sv.insertInboxId(InboxIdRecord(txtToB.getValue(peer), "b", 1L, Long.MAX_VALUE, "outbound", LA_RCAP))
                sv.insertInboxId(InboxIdRecord(toPeer, "b", 1L, Long.MAX_VALUE, "inbound", LA_RCAP))
            }
        }

        fun send(peer: String, text: String) = assertTrue(senders.getValue(peer).second.sendMessage("b", text))
    }

    @Test
    fun theGroupFanOut_acksEveryMemberInbox_inOneBatch() {
        if (!aeadUp()) return
        val g = Group(listOf("p1", "p2"))
        g.send("p1", "one"); g.send("p2", "two")
        assertEquals(setOf("one", "two"), g.bGm.pollGroup(g.gid).map { it.text }.toSet())
        assertEquals(1, g.relay.ackPosts.size, "one POST /ack for the whole fan-out")
        assertEquals(g.txtToB.values.toSet(), g.relay.ackPosts.single().map { it.inboxId }.toSet())
        assertTrue(g.txtToB.values.all { g.relay.total(it) == 0 })
    }

    @Test
    fun theGroupScreenPoll_isUncommittedUntilShown_thenOneBatch() {
        if (!aeadUp()) return
        val g = Group(listOf("p1", "p2"))
        g.send("p1", "one"); g.send("p2", "two")
        val pd = g.bGm.pollGroupPending(g.gid)
        assertEquals(setOf("one", "two"), pd.messages.map { it.text }.toSet())
        assertTrue(g.relay.ackPosts.isEmpty(), "nothing acked before the screen shows it")
        pd.commit()
        assertEquals(1, g.relay.ackPosts.size)
        assertEquals(g.txtToB.values.toSet(), g.relay.ackPosts.single().map { it.inboxId }.toSet())
        assertTrue(g.txtToB.values.all { g.relay.total(it) == 0 })
    }

    @Test
    fun theOneToOneScreenPoll_abandoned_bringsEverythingBack() {
        if (!aeadUp()) return
        val g = Group(listOf("p1"))
        g.send("p1", "dm")
        val pd = g.bGm.pollDirectPending("p1")
        assertEquals(listOf("dm"), pd.messages.map { it.text })
        pd.abandon()
        val again = g.bGm.pollDirectPending("p1")
        assertEquals(listOf("dm"), again.messages.map { it.text })
        again.commit()
        assertEquals(0, g.relay.total(g.txtToB.getValue("p1")))
    }
}

package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// GROUP-FANOUT (2026-10-06): a group poll's inbox GETs run CONCURRENTLY (at most
// GROUP_POLL_FETCH_CONCURRENCY in flight) so a group poll no longer takes
// 60 s × inboxes on a dead circuit; every vault/ratchet read and write stays
// SERIAL, in member order, after the fetches. Pinned at both layers: the pure
// bounded fan-out helper, and a real group poll over a relay double that delays
// (and for one member, throws on) its GETs.
// ---------------------------------------------------------------------------

private fun foNow(): Long = currentTimeMillis()

class BoundedParallelBlockingTest {

    @Test
    fun completesInRoughlyTheSlowestItem_notTheSumOfThem() {
        val delays = listOf(600L, 600L, 600L)
        val t0 = foNow()
        val out = boundedParallelBlocking(delays, GroupManager.GROUP_POLL_FETCH_CONCURRENCY) { d ->
            sleepMillis(d); d
        }
        val elapsed = foNow() - t0
        assertEquals(delays, out)
        assertTrue(elapsed < 1_400, "concurrent: ~600 ms expected, sequential would be 1800 ms (took $elapsed ms)")
    }

    @Test
    fun resultsComeBackInInputOrder_whateverOrderTheyFinishIn() {
        val delays = listOf(500L, 300L, 100L, 0L)   // finish order is the reverse
        val out = boundedParallelBlocking(delays.indices.toList(), 4) { i -> sleepMillis(delays[i]); "r$i" }
        assertEquals(listOf("r0", "r1", "r2", "r3"), out)
    }

    @Test
    fun oneThrowingItem_isNullAndTheOthersStillComeBack() {
        val out = boundedParallelBlocking(listOf(1, 2, 3), 3) { i ->
            if (i == 2) throw IllegalStateException("socket reset")
            i * 10
        }
        assertEquals(listOf(10, null, 30), out)
    }

    @Test
    fun neverExceedsTheCap() {
        val lock = SyncLock()
        var inFlight = 0
        var peak = 0
        boundedParallelBlocking((1..8).toList(), 3) {
            lock.withLock { inFlight++; if (inFlight > peak) peak = inFlight }
            sleepMillis(150)
            lock.withLock { inFlight-- }
            it
        }
        assertTrue(peak <= 3, "at most 3 in flight, saw $peak")
        assertTrue(peak >= 2, "and genuinely concurrent, saw $peak")
    }
}

private const val FO_CAP = "QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ"
private fun foInbox(tag: String) = ("fo$tag".padEnd(32, 'A')).take(32)

/** Append / destructive drain, with a per-inbox GET delay and a per-inbox GET throw. */
private class FoRelay : InboxQueueRelay(
    strict = true,
    postReply = HttpResult(202, "", true),
    putReply = HttpResult(202, "", true),
    deleteReply = HttpResult(200, "", true),
) {
    fun depth(id: String): Int = pending(id)
    override fun nonInboxRoute(method: String, url: String, body: ByteArray, headers: Map<String, String>) =
        if (method == "POST") HttpResult(404, """{"error":"no"}""", false) else null
}

/** B is a member of a group with [peers]; each peer is paired with B over text + group inboxes. */
private class FoGroup(val peers: List<String>) {
    val relay = FoRelay()
    val bVault = InMemoryVault()
    val bMgr = MessageManager(bVault, "http://relay.test", relay)
    val bGm = GroupManager(bVault) { bMgr }
    val gid = GroupManager.newGroupId()
    val txtToB = peers.associateWith { foInbox("${it}tb") }
    val grpToB = peers.associateWith { foInbox("${it}gb") }
    val senders = peers.associateWith { peer ->
        val v = InMemoryVault()
        v to MessageManager(v, "http://relay.test", relay)
    }

    init {
        val me = "00000000000000b0"
        bVault.insertGroup(GroupRecord(gid, "crew", 1, adminMemberId = me, myMemberId = me, createdAt = 0L))
        bVault.insertGroupMember(GroupMemberRecord(gid, me, contactId = null, addedAt = 0L))
        peers.forEachIndexed { i, peer ->
            val secret = generateSecureRandom(32)
            val toPeerTxt = foInbox("${peer}ta"); val toPeerGrp = foInbox("${peer}ga")
            relay.declare(txtToB.getValue(peer), grpToB.getValue(peer), toPeerTxt, toPeerGrp)
            bVault.insertContact(ContactRecord(peer, secret, 1, peer.uppercase(), 0L))
            bVault.insertInboxId(InboxIdRecord(txtToB.getValue(peer), peer, 1L, Long.MAX_VALUE, "inbound", FO_CAP))
            bVault.insertInboxId(InboxIdRecord(grpToB.getValue(peer), peer, 1L, Long.MAX_VALUE, MessageManager.DIR_INBOUND_GRP, FO_CAP))
            bVault.insertInboxId(InboxIdRecord(toPeerTxt, peer, 1L, Long.MAX_VALUE, "outbound", FO_CAP))
            bVault.insertGroupMember(GroupMemberRecord(gid, "00000000000000a$i", contactId = peer, addedAt = 0L))
            val sv = senders.getValue(peer).first
            sv.insertContact(ContactRecord("b", secret, 1, "B", 0L))
            sv.insertInboxId(InboxIdRecord(txtToB.getValue(peer), "b", 1L, Long.MAX_VALUE, "outbound", FO_CAP))
            sv.insertInboxId(InboxIdRecord(toPeerTxt, "b", 1L, Long.MAX_VALUE, "inbound", FO_CAP))
        }
    }

    fun send(peer: String, text: String) = assertTrue(senders.getValue(peer).second.sendMessage("b", text))
}

class GroupPollFanoutTest {

    @Test
    fun aGroupPollFetchesItsMembersConcurrently_andIngestsEachMemberSerially_inOrder() {
        if (!aeadUp()) return
        val g = FoGroup(listOf("p1", "p2", "p3"))
        for (p in g.peers) {
            g.send(p, "$p-1"); g.send(p, "$p-2")
            g.relay.getDelayMs[g.txtToB.getValue(p)] = 600L
        }

        val t0 = foNow()
        val items = g.bGm.pollGroup(g.gid)
        val elapsed = foNow() - t0

        // 3 delayed text GETs (+3 instant group GETs): sequential ≥ 1800 ms.
        assertTrue(elapsed < 1_500, "the fan-out must overlap the GETs (took $elapsed ms)")
        assertEquals(6, items.size)
        assertTrue(items.all { it.kind == ReceivedItemKind.PRIVATE })
        // Serial, member-ordered ingest: each member's items are contiguous and in
        // their own send order — no interleaving across members.
        val bySender = items.map { it.senderContactId }
        assertEquals(bySender.distinct().flatMap { s -> listOf(s, s) }, bySender)
        for (p in g.peers) assertEquals(listOf("$p-1", "$p-2"), items.filter { it.senderContactId == p }.map { it.text })
    }

    @Test
    fun oneMembersFailingFetch_leavesTheOtherMembersIngested() {
        if (!aeadUp()) return
        val g = FoGroup(listOf("p1", "p2", "p3"))
        for (p in g.peers) g.send(p, "hello from $p")
        g.relay.throwOnGet += g.txtToB.getValue("p2")

        val items = g.bGm.pollGroup(g.gid)

        assertEquals(setOf("hello from p1", "hello from p3"), items.map { it.text }.toSet())
        assertEquals(1, g.relay.depth(g.txtToB.getValue("p2")), "the failed GET burned nothing")
        assertEquals(0, g.relay.depth(g.txtToB.getValue("p1")))
        assertNull(items.firstOrNull { it.senderContactId == "p2" })

        // The next poll (the circuit is back) picks p2's message up.
        g.relay.throwOnGet.clear()
        assertEquals(listOf("hello from p2"), g.bGm.pollGroup(g.gid).map { it.text })
    }
}

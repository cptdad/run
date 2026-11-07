package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// POLL-HANDOFF-1 (2026-10-02) + the RE-ADD delivery regression it was found under.
//
// A device-run cross:multi3 (groups.cross3.multi.spec.ts step 8) failed twice with
// `android: group message "welcome back" never received` right after the admin
// re-added a member that had left. The relay journals split the two occurrences:
//
//  - 2026-09-30 19:07Z: the admin's own circuit stalled mid-fan-out (its 1–2 s
//    group-conversation drains stop at 19:07:21 and never resume), so the A20e's
//    copy never reached the relay and was counted FAILED — sender transport, not a
//    membership predicate (the roster to the same member went out 18 s earlier).
//  - 2026-10-02 09:46Z: the admin DID post the text to the A13's group inbox
//    (09:46:41) and the A13 DRAINED it (09:46:50, blobsReturned=1) — on the poll
//    its group screen had orphaned when the harness opened Group Info and came
//    back (09:46:25 / 09:46:26). A drain is destructive and the poll RETURNED its
//    messages to a cancelled consumer: gone for good.
//
// So the re-add path itself is pinned end-to-end here (two real devices, real
// crypto, a relay double that really destroys what a GET returns), and the bug is
// pinned at the API that lost the message: a conversation poll whose consumer is
// gone must leave what it drained PARKED for the next poll.
// ---------------------------------------------------------------------------

private fun phInbox(tag: String) = ("ph$tag".padEnd(32, 'A')).take(32)
private const val PH_CAP = "QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ"

/**
 * Relay double: append, non-destructive peek, DESTRUCTIVE drain. An inbox it has
 * never been told about answers 404 on every route. Thread-safe.
 */
private class PhRelay : InboxQueueRelay(
    strict = true,
    peek = true,
    postReply = HttpResult(202, "", true),
    putReply = HttpResult(202, "", true),
    deleteReply = HttpResult(200, "", true),
) {
    fun depth(id: String): Int = pending(id)
    override fun nonInboxRoute(method: String, url: String, body: ByteArray, headers: Map<String, String>) =
        if (method == "POST") HttpResult(404, """{"error":"no"}""", false)   // no batch, no mint
        else HttpResult(404, "up", false)
}

/**
 * Admin A and member B, paired over all THREE inbox pairs (text, control, group),
 * each with its own vault, MessageManager and GroupManager — so every membership
 * step below is the production protocol (invite → consent → join → roster), not a
 * seeded row.
 */
private class PhPair {
    val shared = generateSecureRandom(32)
    // Inboxes OWNED by B (A posts into them) …
    val txtToB = phInbox("btxt"); val ctlToB = phInbox("bctl"); val grpToB = phInbox("bgrp")
    // … and by A.
    val txtToA = phInbox("atxt"); val ctlToA = phInbox("actl"); val grpToA = phInbox("agrp")

    val relay = PhRelay()
    val aVault = InMemoryVault()
    val aMgr = MessageManager(aVault, "http://relay.test", relay)
    val aGm = GroupManager(aVault) { aMgr }
    val bVault = InMemoryVault()
    val bMgr = MessageManager(bVault, "http://relay.test", relay)
    val bGm = GroupManager(bVault) { bMgr }

    init {
        relay.declare(txtToB, ctlToB, grpToB, txtToA, ctlToA, grpToA)
        wire(aVault, peer = "b", alias = "B",
            outTxt = txtToB, outCtl = ctlToB, outGrp = grpToB, inTxt = txtToA, inCtl = ctlToA, inGrp = grpToA)
        wire(bVault, peer = "a", alias = "A",
            outTxt = txtToA, outCtl = ctlToA, outGrp = grpToA, inTxt = txtToB, inCtl = ctlToB, inGrp = grpToB)
    }

    private fun wire(
        v: InMemoryVault, peer: String, alias: String,
        outTxt: String, outCtl: String, outGrp: String, inTxt: String, inCtl: String, inGrp: String,
    ) {
        v.insertContact(ContactRecord(peer, shared, 1, alias, 0L))
        v.insertInboxId(InboxIdRecord(outTxt, peer, 1L, Long.MAX_VALUE, "outbound", PH_CAP))
        v.insertInboxId(InboxIdRecord(outCtl, peer, 1L, Long.MAX_VALUE, MessageManager.DIR_OUTBOUND_CTL, PH_CAP))
        v.insertInboxId(InboxIdRecord(outGrp, peer, 1L, Long.MAX_VALUE, MessageManager.DIR_OUTBOUND_GRP, PH_CAP))
        v.insertInboxId(InboxIdRecord(inTxt, peer, 1L, Long.MAX_VALUE, "inbound", PH_CAP))
        v.insertInboxId(InboxIdRecord(inCtl, peer, 1L, Long.MAX_VALUE, MessageManager.DIR_INBOUND_CTL, PH_CAP))
        v.insertInboxId(InboxIdRecord(inGrp, peer, 1L, Long.MAX_VALUE, MessageManager.DIR_INBOUND_GRP, PH_CAP))
    }

    /** B receives A's invite over its control sweep and CONSENTS (GROUP-1). */
    fun bJoins(gid: String) {
        bGm.pollAllControls()
        assertTrue(bGm.acceptInvite(gid), "B must hold A's parked invite and be able to accept it")
    }

    /** A applies B's join, then B applies A's resulting roster. */
    fun converge() {
        aGm.pollAllControls()
        bGm.pollAllControls()
    }

    /** A creates a 2-member group with B, and B joins it. */
    fun groupWithB(): String {
        val gid = assertNotNull(aGm.createGroup("crew", listOf("b")))
        bJoins(gid)
        converge()
        assertResolvedBothWays(gid)
        return gid
    }

    fun memberIdOfB(gid: String) = aVault.getGroupMembers(gid).first { it.contactId == "b" }.memberId

    fun assertResolvedBothWays(gid: String) {
        assertTrue(aVault.getGroupMembers(gid).any { it.contactId == "b" }, "admin: B is a resolved member")
        assertTrue(bVault.getGroupMembers(gid).any { it.contactId == "a" }, "member: the admin is a resolved member")
    }
}

class GroupPollHandoffTest {

    // --- the step-8 path itself: leave / kick → re-add → send ---------------

    @Test
    fun readdAfterLeave_theAdminsNextGroupText_reachesTheRejoinedMember() {
        if (!aeadUp()) return
        val p = PhPair()
        val gid = p.groupWithB()

        // Step 6: B leaves; the admin applies it.
        p.bGm.leaveGroup(gid)
        assertNull(p.bVault.getGroup(gid), "B's local group is gone")
        p.aGm.pollAllControls()
        assertTrue(p.aVault.getGroupMembers(gid).none { it.contactId == "b" }, "admin dropped B")

        // Step 8: the admin re-adds B; B consents; join → roster converge.
        assertTrue(p.aGm.addMember(gid, "b"), "re-adding a former member must be allowed")
        p.bJoins(gid)
        p.converge()
        p.assertResolvedBothWays(gid)

        val sent = p.aGm.sendGroupMessage(gid, "welcome back")
        assertEquals(GroupSendResult(1, 1), sent, "the fan-out must include — and deliver to — the re-added member")
        assertEquals(1, p.relay.depth(p.grpToB), "…on B's GROUP inbox")

        val got = p.bGm.pollGroup(gid)
        assertEquals(listOf("welcome back"), got.map { it.text })
        assertEquals("a", got.single().senderContactId)
    }

    @Test
    fun readdAfterKick_theAdminsNextGroupText_reachesTheRejoinedMember() {
        if (!aeadUp()) return
        val p = PhPair()
        val gid = p.groupWithB()

        assertTrue(p.aGm.removeMember(gid, p.memberIdOfB(gid)))
        p.bGm.pollAllControls()   // B applies its final roster
        assertNull(p.bVault.getGroup(gid), "the kicked member's group is gone")

        assertTrue(p.aGm.addMember(gid, "b"))
        p.bJoins(gid)
        p.converge()
        p.assertResolvedBothWays(gid)

        assertEquals(GroupSendResult(1, 1), p.aGm.sendGroupMessage(gid, "welcome back"))
        assertEquals(listOf("welcome back"), p.bGm.pollGroup(gid).map { it.text })
    }

    // --- POLL-HANDOFF-1: an orphaned drain must not destroy what it fetched --

    @Test
    fun anOrphanedGroupDrain_parksTheMessage_andTheNextOpenShowsIt() {
        if (!aeadUp()) return
        val p = PhPair()
        val gid = p.groupWithB()
        assertEquals(GroupSendResult(1, 1), p.aGm.sendGroupMessage(gid, "welcome back"))

        // The screen's poll is orphaned (Group Info opened / back pressed / the task
        // was cancelled): the blocking drain still runs to completion, and nobody
        // takes its result.
        p.bGm.pollGroupIntoBuffer(gid)
        assertEquals(0, p.relay.depth(p.grpToB), "the drain really burned the blob on the relay")
        assertEquals(1, p.bGm.groupUnreadCounts()[gid], "a parked message keeps the group's dot lit")

        // The next open (a fresh consumer) gets it.
        p.bGm.pollGroupIntoBuffer(gid)
        assertEquals(listOf("welcome back"), p.bGm.takeGroupScreenItems(gid).map { it.text })
        assertTrue(p.bGm.takeGroupScreenItems(gid).isEmpty(), "taken exactly once")
    }

    @Test
    fun oracle_aDiscardedListReturningPoll_reallyDestroysTheMessage() {
        // Anti-vacuity: the pre-fix screens consumed pollGroup's RETURN VALUE. A
        // consumer that is gone discards it — and the message is unrecoverable, which
        // is exactly why the screens now use the IntoBuffer + drain hand-off.
        if (!aeadUp()) return
        val p = PhPair()
        val gid = p.groupWithB()
        assertEquals(GroupSendResult(1, 1), p.aGm.sendGroupMessage(gid, "welcome back"))

        @Suppress("UNUSED_VARIABLE") val discarded = p.bGm.pollGroup(gid)
        assertEquals(0, p.relay.depth(p.grpToB))
        assertTrue(p.bGm.pollGroup(gid).isEmpty(), "nothing left anywhere: the old shape loses it")
    }

    @Test
    fun parkedMessagesKeepTheirOrder_acrossAnOrphanedAndALivePoll() {
        if (!aeadUp()) return
        val p = PhPair()
        val gid = p.groupWithB()
        assertEquals(GroupSendResult(1, 1), p.aGm.sendGroupMessage(gid, "one"))
        p.bGm.pollGroupIntoBuffer(gid)                      // orphaned
        assertEquals(GroupSendResult(1, 1), p.aGm.sendGroupMessage(gid, "two"))

        assertEquals(listOf("one", "two"), p.bGm.pollGroup(gid).map { it.text },
            "parked first, then fresh — the same order the list-returning poll always had")
    }

    @Test
    fun anOrphaned1to1Drain_leavesTheMessageForThatScreen_andTheNextPollShowsIt() {
        if (!aeadUp()) return
        val p = PhPair()
        assertTrue(p.aMgr.sendMessage("b", "just for you"))

        p.bGm.pollDirectIntoBuffer("a")                     // orphaned
        assertEquals(0, p.relay.depth(p.txtToB), "the drain really burned the blob on the relay")

        assertEquals(listOf("just for you"), p.bGm.pollDirect("a").map { it.text })
        assertTrue(p.bGm.takeDirectScreenItems("a").isEmpty(), "taken exactly once")
    }

    // --- NO-PARK (2026-10-06) ----------------------------------
    // A fetched message is shown in the screen whose poll fetched it, marked —
    // never held in RAM for "its" conversation (that buffer died on lock/relaunch
    // after the relay had already burned the blob).

    @Test
    fun a1to1FetchedByTheGroupPoll_isShownInTheGroupAsPRIVATE_neverAsAGroupText_andNothingIsParked() {
        if (!aeadUp()) return
        val p = PhPair()
        val gid = p.groupWithB()
        assertTrue(p.aMgr.sendMessage("b", "first 1:1 while b sits in the group"))

        val items = p.bGm.pollGroup(gid)
        assertEquals(0, p.relay.depth(p.txtToB), "the relay already deleted the blob")

        val priv = items.single()
        assertEquals(ReceivedItemKind.PRIVATE, priv.kind)
        assertTrue(priv.isPrivate)
        assertEquals("a", priv.senderContactId)
        assertEquals("A", priv.senderAlias)
        assertEquals("first 1:1 while b sits in the group", priv.text)
        assertTrue(priv.dedupeId.isNotEmpty())
        assertTrue(items.none { it.kind == ReceivedItemKind.OWN }, "never surfaced as a group text")

        // Nothing parked for the 1:1 — neither for a take nor for its next poll.
        assertTrue(p.bGm.takeDirectScreenItems("a").isEmpty())
        assertTrue(p.bGm.pollDirect("a").isEmpty(), "the 1:1 screen must not show it a second time")
        assertNull(p.bGm.groupUnreadCounts()[gid], "a PRIVATE item never lights the group dot")
    }

    @Test
    fun anOrphanedGroupPoll_countsOnlyItsOwnGroupTexts_onTheGroupDot() {
        if (!aeadUp()) return
        val p = PhPair()
        val gid = p.groupWithB()
        assertTrue(p.aMgr.sendMessage("b", "private"))
        p.bGm.pollGroupIntoBuffer(gid)                      // orphaned: a PRIVATE item is left untaken
        assertNull(p.bGm.groupUnreadCounts()[gid], "an untaken PRIVATE item is not a group message")

        assertEquals(GroupSendResult(1, 1), p.aGm.sendGroupMessage(gid, "crew"))
        p.bGm.pollGroupIntoBuffer(gid)                      // orphaned again, now with an OWN text
        assertEquals(1, p.bGm.groupUnreadCounts()[gid], "only the OWN group text counts")

        val taken = p.bGm.takeGroupScreenItems(gid)
        assertEquals(listOf(ReceivedItemKind.PRIVATE, ReceivedItemKind.OWN), taken.map { it.kind })
        assertEquals(listOf("private", "crew"), taken.map { it.text })
    }

    @Test
    fun aGroupTextFetchedByThe1to1Poll_isShownThereAsGROUP_ECHO_neverAsA1to1_andNothingIsParked() {
        if (!aeadUp()) return
        val p = PhPair()
        val gid = p.groupWithB()
        assertEquals(GroupSendResult(1, 1), p.aGm.sendGroupMessage(gid, "crew"))
        p.bGm.pollAllControls()                             // B applies A's KIND_ACTIVITY notice
        assertEquals(1, p.bGm.groupUnreadCounts()[gid], "precondition: the notice lit the group dot")

        val items = p.bGm.pollDirect("a")
        assertEquals(0, p.relay.depth(p.grpToB), "the relay already deleted the blob")

        val echo = items.single()
        assertEquals(ReceivedItemKind.GROUP_ECHO, echo.kind)
        assertEquals(gid, echo.groupId)
        assertEquals("crew", echo.groupName)
        assertEquals("crew", echo.text)
        assertEquals("a", echo.contactId)
        assertTrue(items.none { it.kind == ReceivedItemKind.OWN }, "never surfaced as a 1:1 text")

        // Nothing parked for the group, and its dot has nothing left to point at.
        assertTrue(p.bGm.takeGroupScreenItems(gid).isEmpty())
        assertNull(p.bGm.groupUnreadCounts()[gid], "the echo was shown — the group dot goes dark")
        assertTrue(p.bGm.pollGroup(gid).isEmpty(), "the group screen must not show it a second time")
    }

    @Test
    fun aTextOfAnotherGroup_fetchedByAGroupPoll_isShownThereAsGROUP_ECHO() {
        if (!aeadUp()) return
        val p = PhPair()
        val g1 = p.groupWithB()
        val g2 = assertNotNull(p.aGm.createGroup("second", listOf("b")))
        p.bJoins(g2)
        p.converge()
        p.assertResolvedBothWays(g2)

        assertEquals(GroupSendResult(1, 1), p.aGm.sendGroupMessage(g2, "in the second"))
        val echo = p.bGm.pollGroup(g1).single()
        assertEquals(ReceivedItemKind.GROUP_ECHO, echo.kind)
        assertEquals(g2, echo.groupId)
        assertEquals("second", echo.groupName)
        assertEquals("a", echo.senderContactId)
        assertTrue(p.bGm.pollGroup(g2).isEmpty(), "nothing parked for the second group")
    }

    @Test
    fun aRepeatedPoll_neverResurfacesAnItem_andDedupeIdsAreStableAndDistinct() {
        if (!aeadUp()) return
        val p = PhPair()
        val gid = p.groupWithB()
        assertTrue(p.aMgr.sendMessage("b", "one"))
        assertEquals(GroupSendResult(1, 1), p.aGm.sendGroupMessage(gid, "two"))

        val first = p.bGm.pollGroup(gid)
        assertEquals(setOf("one", "two"), first.map { it.text }.toSet())
        assertEquals(first.size, first.map { it.kind to it.dedupeId }.toSet().size, "kind + dedupeId key every item uniquely")
        assertTrue(first.all { it.dedupeId.isNotEmpty() })

        assertTrue(p.bGm.pollGroup(gid).isEmpty(), "a repeated poll surfaces nothing again")
        assertTrue(p.bGm.pollDirect("a").isEmpty(), "…and neither does the other screen")
    }
}

class GroupUnreadTallyEchoPinTest {

    @Test
    fun aGroupEchoGivesBackOneUnit_flooredAtZero() {
        if (!aeadUp()) return
        val p = PhPair()
        val gid = p.groupWithB()
        // ONE notice (with the first text) but TWO group texts on B's group inbox.
        assertEquals(GroupSendResult(1, 1), p.aGm.sendGroupMessage(gid, "first"))
        val g = assertNotNull(p.aVault.getGroup(gid))
        val hash = GroupManager.membershipHash(gid, g.epoch, p.aVault.getGroupMembers(gid).map { it.memberId })
        assertEquals(MessageManager.GroupTextRoute.GRP, p.aMgr.sendGroupTextRouted("b", gid, hash, "second"))
        p.bGm.pollAllControls()
        assertEquals(1, p.bGm.groupUnreadCounts()[gid], "precondition: one notice, one unit")

        val items = p.bGm.pollDirect("a")
        assertEquals(listOf(ReceivedItemKind.GROUP_ECHO, ReceivedItemKind.GROUP_ECHO), items.map { it.kind })
        assertNull(p.bGm.groupUnreadCounts()[gid], "two echoes give back one unit, floored at zero")

        // A negative residue would swallow the next notice's unit and read 0.
        assertTrue(
            p.aMgr.sendGroupControl(
                "b", gid, GroupManager.KIND_ACTIVITY, GroupManager.ACTIVITY_BODY_GRP, hash, noPush = true,
            )
        )
        p.bGm.pollAllControls()
        assertEquals(1, p.bGm.groupUnreadCounts()[gid], "the floor left no negative residue")
    }
}

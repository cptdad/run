package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// RÚN-07 — one screenshot notifies every conversation whose text was on the
// captured screen: the open conversation plus the origin of each foreign row
// (owner decision 2026-11-23; the inline rows themselves stay).
//
// Pinned here:
//  - the plan: one notice per distinct conversation, blocked contacts excluded,
//    a group not on this phone addressed to the row's sender (the inviter) only;
//  - end to end over a local relay stub with real envelopes: each receiver stores
//    each notice under the conversation whose text was captured (1:1 / group A /
//    group B / the invited group), never under the capturer's open screen;
//  - best-effort: a failed screenshot is neither queued nor retried, and a later
//    screenshot from another screen reaches exactly its own conversations.
// ---------------------------------------------------------------------------

private fun srMember(seed: Int) = bytesToHex(ByteArray(8) { (seed * 7 + it).toByte() })

class ScreenshotNoticePlanTest {

    private val groupA = LocalGroupTargets(listOf("x", "y"), "hashA")
    private val groupB = LocalGroupTargets(listOf("x"), "hashB")

    private fun plan(origins: List<ScreenshotOrigin>, blocked: Set<String> = emptySet()) =
        planScreenshotNotices(
            origins, blocked,
            contactExists = { it in setOf("x", "y", "inviter") },
            localGroup = { when (it) { "A" -> groupA; "B" -> groupB; else -> null } },
            invitePendingFrom = { gid, sender -> gid == "C" && sender == "inviter" },
        )

    @Test
    fun aGroupScreen_withAPrivateRow_anEchoRow_andAnInvitedRow_notifiesEachConversationOnce() {
        val p = plan(listOf(
            ScreenshotOrigin("A", true, ""),          // the open group
            ScreenshotOrigin("x", false, "x"),        // a private row from x …
            ScreenshotOrigin("x", false, "x"),        // … our private reply to x
            ScreenshotOrigin("B", true, "x"),         // a group-B row
            ScreenshotOrigin("B", true, "x"),         // another group-B row
            ScreenshotOrigin("C", true, "inviter"),   // a row of a group we are only invited to
        ))
        assertEquals(
            listOf(
                ScreenshotNoticeTarget.Direct("x"),
                ScreenshotNoticeTarget.Group("A", listOf("x", "y"), "hashA"),
                ScreenshotNoticeTarget.Group("B", listOf("x"), "hashB"),
                ScreenshotNoticeTarget.InvitedGroup("C", "inviter"),
            ),
            p,
        )
    }

    @Test
    fun aOneToOneScreen_withAGroupRow_notifiesTheContactAndTheGroup() {
        val p = plan(listOf(ScreenshotOrigin("y", false, "y"), ScreenshotOrigin("A", true, "y")))
        assertEquals(listOf(ScreenshotNoticeTarget.Direct("y"), ScreenshotNoticeTarget.Group("A", listOf("x", "y"), "hashA")), p)
    }

    @Test
    fun aRowOfTheOpenConversationItself_doesNotDoubleIt() {
        val p = plan(listOf(ScreenshotOrigin("B", true, ""), ScreenshotOrigin("B", true, "x")))
        assertEquals(listOf(ScreenshotNoticeTarget.Group("B", listOf("x"), "hashB")), p)
    }

    @Test
    fun blockedContacts_areExcluded_fromEveryKindOfNotice() {
        val p = plan(
            listOf(
                ScreenshotOrigin("A", true, ""),
                ScreenshotOrigin("y", false, "y"),
                ScreenshotOrigin("C", true, "y"),
            ),
            blocked = setOf("y"),
        )
        assertEquals(listOf(ScreenshotNoticeTarget.Group("A", listOf("x"), "hashA")), p)
    }

    @Test
    fun aGroupThatIsNotHere_withoutAParkedInviteFromThatSender_isToldNothing() {
        // A group we LEFT or DECLINED whose rows are still on screen, and a row of the
        // invited group C from someone who is not its inviter.
        assertTrue(plan(listOf(ScreenshotOrigin("left", true, "x"), ScreenshotOrigin("C", true, "x"))).isEmpty())
    }

    @Test
    fun aGroupWithEveryMemberBlocked_anUnknownContact_andAGoneGroupWithNoSender_sendNothing() {
        assertTrue(plan(listOf(ScreenshotOrigin("B", true, "")), blocked = setOf("x")).isEmpty())
        assertTrue(plan(listOf(ScreenshotOrigin("stranger", false, "stranger"))).isEmpty())
        assertTrue(plan(listOf(ScreenshotOrigin("gone", true, ""))).isEmpty())
    }
}

/** A relay stub whose POSTs can be made to fail at the transport (nothing stored). */
private class SrRelay : InboxQueueRelay() {
    var down = false
    var postsTried = 0
    override fun post(url: String, body: ByteArray, contentType: String, headers: Map<String, String>, timeoutSeconds: Int): HttpResult {
        postsTried++
        if (down) throw IllegalStateException("circuit died")
        return super.post(url, body, contentType, headers, timeoutSeconds)
    }
}

/**
 * The capturer ("me") paired with X and Y. Groups: A = {me, X, Y}, B = {me, X} on
 * every phone that is in them; C exists only on X (X invited me; I have not joined).
 * Each receiver has its own vault, MessageManager and GroupManager.
 */
private class SrWorld {
    val relay = SrRelay()
    val gidA = GroupManager.newGroupId()
    val gidB = GroupManager.newGroupId()
    private val me = srMember(1); private val mx = srMember(2); private val my = srMember(3)

    val meVault = InMemoryVault()
    val meMgr = MessageManager(meVault, "http://relay.test", relay).also { it.sendRetrySleep = {} }
    var transportUp = true
    val meGm = GroupManager(meVault) { if (transportUp) meMgr else null }.also { it.interSendJitter = {} }

    val xVault = InMemoryVault()
    val xMgr = MessageManager(xVault, "http://relay.test", relay)
    val xGm = GroupManager(xVault) { xMgr }.also { it.interSendJitter = {} }
    val yVault = InMemoryVault()
    val yMgr = MessageManager(yVault, "http://relay.test", relay)
    val yGm = GroupManager(yVault) { yMgr }

    init {
        pair("x", xVault, "X")
        pair("y", yVault, "Y")
        // The capturer's groups (A, B); C is only an invite here, so no row.
        group(meVault, gidA, me, listOf(me to null, mx to "x", my to "y"))
        group(meVault, gidB, me, listOf(me to null, mx to "x"))
        // X's view: A and B. (Group C, the one X invites me to, is created for real by
        // [xInvitesMe]: X's createGroup records me as a member and an obligation.)
        group(xVault, gidA, mx, listOf(me to "me", mx to null, my to null))
        group(xVault, gidB, mx, listOf(me to "me", mx to null))
        // Y's view: A only.
        group(yVault, gidA, my, listOf(me to "me", mx to null, my to null))
    }

    private fun inbox(tag: String) = ("sr$tag".padEnd(32, 'A')).take(32)

    private fun pair(peer: String, peerVault: InMemoryVault, alias: String) {
        val secret = generateSecureRandom(32)
        val cap = "C".repeat(43)
        meVault.insertContact(ContactRecord(peer, secret, 1, alias, 0L))
        peerVault.insertContact(ContactRecord("me", secret, 1, "Me", 0L))
        // me → peer (the peer's inbound inboxes) and peer → me.
        meVault.insertInboxId(InboxIdRecord(inbox("${peer}t"), peer, 1L, Long.MAX_VALUE, "outbound", cap))
        meVault.insertInboxId(InboxIdRecord(inbox("${peer}c"), peer, 1L, Long.MAX_VALUE, MessageManager.DIR_OUTBOUND_CTL, cap))
        peerVault.insertInboxId(InboxIdRecord(inbox("${peer}t"), "me", 1L, Long.MAX_VALUE, "inbound", cap))
        peerVault.insertInboxId(InboxIdRecord(inbox("${peer}c"), "me", 1L, Long.MAX_VALUE, MessageManager.DIR_INBOUND_CTL, cap))
        peerVault.insertInboxId(InboxIdRecord(inbox("m${peer}t"), "me", 1L, Long.MAX_VALUE, "outbound", cap))
        meVault.insertInboxId(InboxIdRecord(inbox("m${peer}t"), peer, 1L, Long.MAX_VALUE, "inbound", cap))
        peerVault.insertInboxId(InboxIdRecord(inbox("m${peer}c"), "me", 1L, Long.MAX_VALUE, MessageManager.DIR_OUTBOUND_CTL, cap))
        meVault.insertInboxId(InboxIdRecord(inbox("m${peer}c"), peer, 1L, Long.MAX_VALUE, MessageManager.DIR_INBOUND_CTL, cap))
    }

    private fun group(v: InMemoryVault, gid: String, mine: String, members: List<Pair<String, String?>>) {
        v.insertGroup(GroupRecord(gid, "g", 1, adminMemberId = members.first().first, myMemberId = mine, createdAt = 0L))
        for ((mid, cid) in members) v.insertGroupMember(GroupMemberRecord(gid, mid, cid, 0L))
    }

    /** X creates group C with me; I receive the invite and leave it unanswered ("Later"). */
    fun xInvitesMe(): String {
        val gid = assertNotNull(xGm.createGroup("c", listOf("me")), "X can create C")
        meGm.ingest("x", meMgr.pollControlMessages("x"), wantGroupId = null, background = true)
        assertTrue(meGm.pendingInvites().any { it.groupId == gid && it.inviterContactId == "x" }, "precondition: X's invite is parked here")
        assertEquals(null, meVault.getGroup(gid), "precondition: C is not on the capturer's phone")
        return gid
    }

    /** The receiver drains its control inbox from "me" and applies it, like the sweep. */
    fun receive(mgr: MessageManager, gm: GroupManager) {
        val received = mgr.pollControlMessages("me")
        gm.ingest("me", received, wantGroupId = null, background = true)
        // A 1:1 notice is applied by the transport and persisted when the conversation
        // layer collects it (every poll entry point / drain does).
        gm.drainScreenshotNotices("me")
    }

    /** conversationId → how many notices from "me" a receiver has stored. */
    fun stored(gm: GroupManager, vararg conversations: String): Map<String, Int> =
        conversations.associateWith { c -> gm.screenshotNotices(c).count { it.senderContactId == "me" } }
}

class ScreenshotNoticeRoutingE2eTest {

    @Test
    fun aGroupScreen_withAPrivateRow_andAnotherGroupsRow_reachesEachConversation_attributedToIt() {
        if (!aeadUp()) return
        val w = SrWorld()
        val outcome = w.meGm.sendScreenshotNotices(listOf(
            ScreenshotOrigin(w.gidA, true, ""),     // open: group A
            ScreenshotOrigin("x", false, "x"),      // a private row from X
            ScreenshotOrigin(w.gidB, true, "x"),    // a group-B row from X
        ))
        assertEquals(ScreenshotNoticeOutcome(3, 3), outcome)
        w.receive(w.xMgr, w.xGm); w.receive(w.yMgr, w.yGm)
        assertEquals(mapOf("me" to 1, w.gidA to 1, w.gidB to 1), w.stored(w.xGm, "me", w.gidA, w.gidB),
            "X: one notice in each captured conversation — its 1:1, group A and group B")
        assertEquals(mapOf("me" to 0, w.gidA to 1), w.stored(w.yGm, "me", w.gidA),
            "Y is only in A: told about A, nothing else")
    }

    @Test
    fun aOneToOneScreen_withAGroupRow_reachesTheContactAndTheGroup() {
        if (!aeadUp()) return
        val w = SrWorld()
        val outcome = w.meGm.sendScreenshotNotices(listOf(
            ScreenshotOrigin("y", false, "y"),      // open: the 1:1 with Y
            ScreenshotOrigin(w.gidA, true, "y"),    // a group-A row Y sent
        ))
        assertEquals(ScreenshotNoticeOutcome(2, 2), outcome)
        w.receive(w.xMgr, w.xGm); w.receive(w.yMgr, w.yGm)
        assertEquals(mapOf("me" to 1, w.gidA to 1), w.stored(w.yGm, "me", w.gidA))
        assertEquals(mapOf("me" to 0, w.gidA to 1, w.gidB to 0), w.stored(w.xGm, "me", w.gidA, w.gidB),
            "X saw nothing of the 1:1 with Y: only the group-A notice")
    }

    @Test
    fun anInvitedGroupsRow_isReportedToTheInviter_inThatGroup_andChangesNothingElseThere() {
        if (!aeadUp()) return
        val w = SrWorld()
        val gidC = w.xInvitesMe()
        // X adds a second member, so X's roster goes to me and X records an AWAITING-ACK
        // obligation for me in C (a delivered invite alone leaves none). An empty-hash
        // notice must neither acknowledge it nor mark me not-in-sync (which would
        // re-roster someone who has not joined).
        w.xVault.insertContact(ContactRecord("z", generateSecureRandom(32), 1, "Z", 0L))
        w.xVault.insertInboxId(InboxIdRecord(("srzout".padEnd(32, 'A')).take(32), "z", 1L, Long.MAX_VALUE, "outbound", "C".repeat(43)))
        w.xVault.insertInboxId(InboxIdRecord(("srzin".padEnd(32, 'A')).take(32), "z", 1L, Long.MAX_VALUE, "inbound", "C".repeat(43)))
        assertTrue(w.xGm.addMember(gidC, "z"), "precondition: X re-rosters C")
        val obligationKey = GroupMetaKeys.CTL_PEND_PREFIX + gidC + ":me"
        val obligation = w.xVault.getMeta(obligationKey)
        assertNotNull(obligation, "precondition: X holds the invite obligation for me")
        val outcome = w.meGm.sendScreenshotNotices(listOf(
            ScreenshotOrigin(w.gidA, true, ""),
            ScreenshotOrigin(gidC, true, "x"),      // a row of C, fetched before I answered
        ))
        assertEquals(ScreenshotNoticeOutcome(2, 2), outcome)
        w.receive(w.xMgr, w.xGm); w.receive(w.yMgr, w.yGm)
        assertEquals(mapOf(gidC to 1, w.gidA to 1, "me" to 0), w.stored(w.xGm, gidC, w.gidA, "me"),
            "the inviter stores it under the invited group, where the captured text belongs")
        assertEquals(mapOf(w.gidA to 1), w.stored(w.yGm, w.gidA))
        assertEquals(obligation, w.xVault.getMeta(obligationKey), "the invite obligation is untouched (no false acknowledgement)")
        assertFalse(w.xGm.isUnconvergedForTest(gidC, "me"), "I am not marked not-in-sync (no re-roster)")
    }

    @Test
    fun aGroupNotOnThisPhone_withNoParkedInvite_isToldNothing() {
        if (!aeadUp()) return
        val w = SrWorld()
        // Rows of a group we left / declined are still on screen: no invite is parked.
        val gone = GroupManager.newGroupId()
        val outcome = w.meGm.sendScreenshotNotices(listOf(ScreenshotOrigin(w.gidA, true, ""), ScreenshotOrigin(gone, true, "x")))
        assertEquals(ScreenshotNoticeOutcome(1, 1), outcome, "only the open group")
        w.receive(w.xMgr, w.xGm)
        assertEquals(mapOf(w.gidA to 1, gone to 0), w.stored(w.xGm, w.gidA, gone))
    }

    @Test
    fun aBlockedContact_isToldNothing_whateverRowsAreOnScreen() {
        if (!aeadUp()) return
        val w = SrWorld()
        w.meGm.blockedContacts = { setOf("y") }
        w.meGm.sendScreenshotNotices(listOf(
            ScreenshotOrigin(w.gidA, true, ""),
            ScreenshotOrigin("y", false, "y"),
        ))
        w.receive(w.xMgr, w.xGm); w.receive(w.yMgr, w.yGm)
        assertEquals(mapOf(w.gidA to 1), w.stored(w.xGm, w.gidA))
        assertEquals(mapOf("me" to 0, w.gidA to 0), w.stored(w.yGm, "me", w.gidA), "a blocked contact gets no notice at all")
    }

    @Test
    fun aFailedScreenshot_isNotRetried_andALaterOneReachesOnlyItsOwnConversations() {
        if (!aeadUp()) return
        val w = SrWorld()
        // Screenshot 1, in group B's screen, while the circuit is dead: every send fails.
        w.relay.down = true
        val first = w.meGm.sendScreenshotNotices(listOf(ScreenshotOrigin(w.gidB, true, "")))
        assertEquals(ScreenshotNoticeOutcome(1, 0), first)
        val triedWhileDown = w.relay.postsTried
        // Screenshot 2, in the 1:1 with Y, transport healthy again.
        w.relay.down = false
        val second = w.meGm.sendScreenshotNotices(listOf(ScreenshotOrigin("y", false, "y")))
        assertEquals(ScreenshotNoticeOutcome(1, 1), second)
        assertEquals(triedWhileDown + 1, w.relay.postsTried, "screenshot 2 sent exactly its own one notice — nothing of screenshot 1 was retried with it")
        w.receive(w.xMgr, w.xGm); w.receive(w.yMgr, w.yGm)
        assertEquals(mapOf(w.gidB to 0, "me" to 0), w.stored(w.xGm, w.gidB, "me"), "the failed group-B notice is dropped, never delivered later")
        assertEquals(mapOf("me" to 1, w.gidA to 0), w.stored(w.yGm, "me", w.gidA), "the later notice lands in its own conversation only")
        // And with no transport at all: nothing is sent, nothing is kept for later.
        w.transportUp = false
        assertEquals(ScreenshotNoticeOutcome(1, 0), w.meGm.sendScreenshotNotices(listOf(ScreenshotOrigin(w.gidA, true, ""))))
        w.transportUp = true
        val before = w.relay.postsTried
        w.meGm.sendScreenshotNotices(listOf(ScreenshotOrigin("x", false, "x")))
        assertEquals(before + 1, w.relay.postsTried)
        w.receive(w.xMgr, w.xGm)
        assertEquals(mapOf("me" to 1, w.gidA to 0), w.stored(w.xGm, "me", w.gidA))
    }

    @Test
    fun theOldSingleGroupEntryPoint_stillNotifiesJustThatGroup() {
        if (!aeadUp()) return
        val w = SrWorld()
        w.meGm.sendGroupScreenshotNotice(w.gidB)
        w.receive(w.xMgr, w.xGm); w.receive(w.yMgr, w.yGm)
        assertEquals(mapOf(w.gidB to 1, w.gidA to 0, "me" to 0), w.stored(w.xGm, w.gidB, w.gidA, "me"))
        assertEquals(mapOf(w.gidA to 0), w.stored(w.yGm, w.gidA))
    }
}

package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// RÚN-05 — what burns on conversation close, and when.
//
// The rules pinned here (docs/vault-relay-internals.md, "What a conversation
// buffer holds and when it burns"):
//  1. After the session scrub (lock / background / wipe) the buffers REFUSE every
//     write, so a poll or callback that finishes late can never park plaintext in
//     the ended session's GroupManager (the iOS detached poll holds the old one).
//  2. A waiting text whose sender is not confirmed (unresolved member / no invite
//     yet) expires after PENDING_UNRESOLVED_GROUP_TEXT_TTL_MS: never delivered after
//     that (enforced on read) and physically dropped by the control sweep even when
//     nothing else happens (also with no transport).
//  3. A text the relay delivers twice (an abandoned screen poll, then the
//     re-delivery) is parked ONCE, keyed on the blob identity (ReceivedMessage.blobKey),
//     because a ratchet decrypt gets a fresh dedupeId every time.
//  4. A confirmed sender's waiting text stays until a screen shows AND commits it,
//     across any number of close / reopen; a lock discards it.
// ---------------------------------------------------------------------------

private fun clSeedContact(vault: InMemoryVault, contactId: String, secret: ByteArray = generateSecureRandom(32)) {
    vault.insertContact(ContactRecord(contactId, secret, 1, "A-$contactId", 0L))
}

private class ClFixture(val vault: ClVault, val gm: GroupManager, val gid: String, val bob: String) {
    fun hash(): String {
        val g = vault.getGroup(gid)!!
        return GroupManager.membershipHash(gid, g.epoch, vault.getGroupMembers(gid).map { it.memberId })
    }
    fun resolveBob() = vault.insertGroupMember(GroupMemberRecord(gid, bob, "bob-contact", addedAt = 0L))
    fun bobText(text: String, blobKey: String = "", dedupeId: String = "") =
        ReceivedMessage(text, 0L, counter = 1, groupId = gid, membershipHash = hash(), dedupeId = dedupeId, blobKey = blobKey)
}

/** A vault that can be "closed" the way a closed iOS vault reads: no rows. */
private open class ClVault : InMemoryVault() {
    var closed = false
    override fun getGroup(groupId: String): GroupRecord? = if (closed) null else super.getGroup(groupId)
    override fun getGroupMembers(groupId: String): List<GroupMemberRecord> =
        if (closed) emptyList() else super.getGroupMembers(groupId)
}

private fun inviteBody(name: String, adm: String, me: String, vararg others: String): String {
    val mem = (listOf(adm, me) + others).joinToString(",") { jsonEscapeString(it) }
    return """{"n":${jsonEscapeString(name)},"ep":1,"adm":${jsonEscapeString(adm)},"you":${jsonEscapeString(me)},"mem":[$mem]}"""
}

/** Joined via a real invite from "admin-contact"; bob's slot is UNRESOLVED (contactId null). */
private fun clFixture(): ClFixture {
    val vault = ClVault()
    clSeedContact(vault, "admin-contact")
    clSeedContact(vault, "bob-contact")
    val gm = GroupManager(vault) { null }
    val gid = GroupManager.newGroupId()
    val adm = groupMemberId(10); val me = groupMemberId(20); val bob = groupMemberId(30)
    gm.handleControl("admin-contact", gid, GroupManager.KIND_INVITE, inviteBody("crew", adm, me, bob))
    assertTrue(gm.acceptInvite(gid))
    return ClFixture(vault, gm, gid, bob)
}

class ConversationBufferLifetimeTest {

    // --- 1. no write after the session scrub --------------------------------

    @Test
    fun aLatePollAfterTheScrub_parksNothing_inAnyBuffer() {
        val f = clFixture()
        f.gm.scrubInMemory()
        // What a drain that decrypted before the lock and runs ingest after it would do:
        // an unresolved sender's text (unresolved-sender buffer) …
        f.gm.ingest("bob-contact", listOf(f.bobText("late-1")), wantGroupId = f.gid)
        // … a text for a group this device does not know (awaiting-invite buffer) …
        f.gm.ingest(
            "admin-contact",
            listOf(ReceivedMessage("late-2", 0L, counter = 2, groupId = GroupManager.newGroupId(), membershipHash = "h")),
            wantGroupId = null,
        )
        // … and a background route into a screen buffer.
        f.gm.ingest(
            "admin-contact", listOf(ReceivedMessage("late-3", 0L, counter = 3)),
            wantGroupId = null, bufferAll = true, background = true,
        )
        assertEquals(0, f.gm.heldTextCountForTest(), "an ended session's buffers must refuse every write")
        f.resolveBob()
        assertEquals(0, f.gm.pollGroup(f.gid).size, "nothing parked after the scrub can surface later")
    }

    @Test
    fun theIosClosedVaultPath_afterTheScrub_parksNothing() {
        // A closed iOS vault answers "no rows": acceptGroupText then sees no group, no
        // RAM invite (scrubbed) and parks the text "awaiting its invite". Sealed, it must not.
        val f = clFixture()
        val text = f.bobText("after-close")
        f.vault.closed = true
        f.gm.scrubInMemory()
        f.gm.ingest("bob-contact", listOf(text), wantGroupId = f.gid)
        assertEquals(0, f.gm.heldTextCountForTest())
    }

    // --- 4. displayed / waiting text across close, reopen and lock -----------

    @Test
    fun aWaitingText_survivesCloseAndReopen_isShownOnce_andCannotReappear() {
        val f = clFixture()
        f.gm.ingest("bob-contact", listOf(f.bobText("wait", blobKey = "w:1", dedupeId = "dr-1")), wantGroupId = f.gid)
        f.resolveBob()
        // First open: shown, but the screen closes before it commits (abandon).
        val first = f.gm.pollGroupPending(f.gid)
        assertEquals(listOf("wait"), first.messages.map { it.text })
        first.abandon()
        // Reopen: still there — a confirmed sender's waiting text is kept until shown.
        val second = f.gm.pollGroupPending(f.gid)
        assertEquals(listOf("wait"), second.messages.map { it.text })
        second.commit()
        // Shown and committed: it can never come back from any buffer.
        assertTrue(f.gm.pollGroupPending(f.gid).messages.isEmpty(), "a shown text must not reappear")
        assertEquals(0, f.gm.heldTextCountForTest())
    }

    @Test
    fun aWaitingText_isDiscardedByTheLock_andNothingReappearsAfterIt() {
        val f = clFixture()
        f.gm.ingest("bob-contact", listOf(f.bobText("wait", blobKey = "w:1")), wantGroupId = f.gid)
        f.resolveBob()
        assertEquals(listOf("wait"), f.gm.pollGroupPending(f.gid).messages.map { it.text })   // shown, never committed
        f.gm.scrubInMemory()
        assertTrue(f.gm.pollGroupPending(f.gid).messages.isEmpty(), "the lock discards every waiting text")
        assertEquals(0, f.gm.heldTextCountForTest())
    }

    // --- 2. expiry: on read, and by the sweep with no other event ------------

    @Test
    fun theExpiry_isEnforcedByTheControlSweep_withNoOtherEvent_andNoTransport() {
        val f = clFixture()
        f.gm.clockMs = { 1_000L }
        f.gm.ingest("bob-contact", listOf(f.bobText("unresolved")), wantGroupId = f.gid)
        f.gm.ingest(
            "admin-contact",
            listOf(ReceivedMessage("awaiting", 0L, counter = 2, groupId = GroupManager.newGroupId(), membershipHash = "h")),
            wantGroupId = null,
        )
        assertEquals(2, f.gm.heldTextCountForTest(), "precondition: both texts are waiting")
        f.gm.clockMs = { 1_000L + GroupManager.PENDING_UNRESOLVED_GROUP_TEXT_TTL_MS }
        f.gm.pollAllControls()
        assertEquals(2, f.gm.heldTextCountForTest(), "at exactly the TTL both are still live")
        f.gm.clockMs = { 1_000L + GroupManager.PENDING_UNRESOLVED_GROUP_TEXT_TTL_MS + 1 }
        // The control sweep with NO transport (GroupManager(vault) { null }) and nothing else
        // happening: no roster, no group open, no new arrival.
        f.gm.pollAllControls()
        assertEquals(0, f.gm.heldTextCountForTest(), "expired waiting texts must be dropped by the sweep itself")
    }

    @Test
    fun anExpiredAwaitingInviteText_isNotDelivered_whenItsInviteArrives() {
        val f = clFixture()
        val gid2 = GroupManager.newGroupId()
        f.gm.clockMs = { 1_000L }
        f.gm.ingest(
            "admin-contact",
            listOf(ReceivedMessage("too-late", 0L, counter = 2, groupId = gid2, membershipHash = "h")),
            wantGroupId = null,
        )
        f.gm.clockMs = { 1_000L + GroupManager.PENDING_UNRESOLVED_GROUP_TEXT_TTL_MS + 1 }
        f.gm.handleControl("admin-contact", gid2, GroupManager.KIND_INVITE, inviteBody("later", groupMemberId(40), groupMemberId(50)))
        assertTrue(f.gm.takeDirectScreenItems("admin-contact").isEmpty(), "an expired text is never delivered")
    }

    // --- 3. a re-delivered blob is parked once -------------------------------

    @Test
    fun aReDeliveredUnresolvedText_isParkedOnce() {
        val f = clFixture()
        // The abandoned poll's decrypt, then the re-delivery's: same blob, fresh ratchet id.
        f.gm.ingest("bob-contact", listOf(f.bobText("once", blobKey = "w:abc", dedupeId = "dr-1")), wantGroupId = f.gid)
        f.gm.ingest("bob-contact", listOf(f.bobText("once", blobKey = "w:abc", dedupeId = "dr-2")), wantGroupId = f.gid)
        assertEquals(1, f.gm.heldTextCountForTest())
        f.resolveBob()
        assertEquals(listOf("once"), f.gm.pollGroup(f.gid).map { it.text }, "one blob, one delivery")
    }

    @Test
    fun twoDifferentTexts_withNoBlobKey_areBothKept() {
        // An empty key (control / test / system messages) never dedupes anything.
        val f = clFixture()
        f.gm.ingest("bob-contact", listOf(f.bobText("same"), f.bobText("same")), wantGroupId = f.gid)
        f.resolveBob()
        assertEquals(2, f.gm.pollGroup(f.gid).size)
    }

    @Test
    fun theSameKeyFromAnotherSender_isNotADuplicate() {
        // A legacy key is the sender's own counter, so it is unique only per sender.
        val f = clFixture()
        clSeedContact(f.vault, "carol-contact")
        f.gm.ingest("bob-contact", listOf(f.bobText("from bob", blobKey = "l:g:5")), wantGroupId = f.gid)
        f.gm.ingest(
            "carol-contact",
            listOf(ReceivedMessage("from carol", 0L, counter = 5, groupId = f.gid, membershipHash = f.hash(), blobKey = "l:g:5")),
            wantGroupId = f.gid,
        )
        // carol is no member at all, so hers is held (resolution in flight) or dropped —
        // either way bob's must still be there.
        f.resolveBob()
        assertTrue(f.gm.pollGroup(f.gid).any { it.text == "from bob" })
    }

    @Test
    fun aReDeliveredText_whoseParkedCopyAlreadyResolved_isShownOnce() {
        val f = clFixture()
        f.gm.ingest("bob-contact", listOf(f.bobText("twice?", blobKey = "w:def", dedupeId = "dr-1")), wantGroupId = f.gid)
        f.resolveBob()
        // The relay hands the blob back (the first poll was never committed) and a poll
        // decrypts it again — now from a resolved sender, so it is shown fresh …
        val fresh = f.gm.ingest("bob-contact", listOf(f.bobText("twice?", blobKey = "w:def", dedupeId = "dr-2")), wantGroupId = f.gid)
        assertEquals(1, fresh.group.size)
        // … and the parked copy must not be delivered as well.
        assertEquals(0, f.gm.pollGroup(f.gid).size, "the parked copy of the same blob is dropped")
    }

    @Test
    fun aReDeliveredAwaitingInviteText_goesToTheNewestScreen_withARefreshedTtl() {
        val f = clFixture()
        val gid2 = GroupManager.newGroupId()
        fun copy(d: String) = ReceivedMessage("first words", 0L, counter = 2, groupId = gid2, membershipHash = "h", dedupeId = d, blobKey = "w:new")
        // Fetched first by the inviter's 1:1 screen (then abandoned) …
        f.gm.clockMs = { 1_000L }
        f.gm.ingest("admin-contact", listOf(copy("dr-1")), wantGroupId = null)
        // … then 8 min later by group screen f.gid, whose drain is the one that commits.
        f.gm.clockMs = { 1_000L + 8 * 60_000L }
        f.gm.ingest("admin-contact", listOf(copy("dr-2")), wantGroupId = f.gid)
        assertEquals(1, f.gm.heldTextCountForTest(), "held once")
        // The invite lands 11 min after the FIRST fetch (past its TTL, within the second's).
        f.gm.clockMs = { 1_000L + 11 * 60_000L }
        f.gm.handleControl("admin-contact", gid2, GroupManager.KIND_INVITE, inviteBody("later", groupMemberId(40), groupMemberId(50)))
        assertTrue(f.gm.takeDirectScreenItems("admin-contact").isEmpty(), "not handed to the closed 1:1 screen")
        assertEquals(listOf("first words"), f.gm.takeGroupScreenItems(f.gid).map { it.text }, "handed to the newest screen that fetched it")
    }

    @Test
    fun aReDeliveredInvitedGroupText_isShownOnce() {
        val f = clFixture()
        val gid2 = GroupManager.newGroupId()
        // Fetched by the inviter's 1:1 before the invite arrived: held, awaiting it.
        f.gm.ingest(
            "admin-contact",
            listOf(ReceivedMessage("hello group", 0L, counter = 2, groupId = gid2, membershipHash = "h", dedupeId = "dr-1", blobKey = "w:inv")),
            wantGroupId = null,
        )
        // The invite lands: the held text is handed to the 1:1 screen's buffer …
        f.gm.handleControl("admin-contact", gid2, GroupManager.KIND_INVITE, inviteBody("later", groupMemberId(40), groupMemberId(50)))
        // … and the same blob is decrypted again by the 1:1 screen (re-delivery).
        val fresh = f.gm.ingest(
            "admin-contact",
            listOf(ReceivedMessage("hello group", 0L, counter = 2, groupId = gid2, membershipHash = "h", dedupeId = "dr-2", blobKey = "w:inv")),
            wantGroupId = null,
        )
        assertEquals(1, fresh.direct.size, "shown once, fresh")
        assertTrue(f.gm.takeDirectScreenItems("admin-contact").isEmpty(), "the held copy of the same blob is dropped")
    }
}

/**
 * Member B with an UNRESOLVED co-member p1 (resolution in flight), over the leasing
 * relay: p1 sends a real group text on its text inbox, B's screens poll uncommitted.
 */
private class LeaseGroup {
    val relay = LeasingRelay()
    val bVault = InMemoryVault()
    val bMgr = MessageManager(bVault, "http://relay.test", relay).syncAcks()
    val bGm = GroupManager(bVault) { bMgr }
    val pVault = InMemoryVault()
    val pMgr = MessageManager(pVault, "http://relay.test", relay).syncAcks()
    val gid = GroupManager.newGroupId()
    private val me = groupMemberId(60); private val p1Slot = groupMemberId(61)
    val txtToB = ("lgtb".padEnd(32, 'A')).take(32)
    private val txtToP = ("lgtp".padEnd(32, 'A')).take(32)

    init {
        val secret = generateSecureRandom(32)
        bVault.insertContact(ContactRecord("p1", secret, 1, "P1", 0L))
        bVault.insertInboxId(InboxIdRecord(txtToB, "p1", 1L, Long.MAX_VALUE, "inbound", LA_RCAP))
        bVault.insertInboxId(InboxIdRecord(txtToP, "p1", 1L, Long.MAX_VALUE, "outbound", LA_RCAP))
        pVault.insertContact(ContactRecord("b", secret, 1, "B", 0L))
        pVault.insertInboxId(InboxIdRecord(txtToB, "b", 1L, Long.MAX_VALUE, "outbound", LA_RCAP))
        pVault.insertInboxId(InboxIdRecord(txtToP, "b", 1L, Long.MAX_VALUE, "inbound", LA_RCAP))
        bVault.insertGroup(GroupRecord(gid, "crew", 1, adminMemberId = me, myMemberId = me, createdAt = 0L))
        bVault.insertGroupMember(GroupMemberRecord(gid, me, contactId = null, addedAt = 0L))
        bVault.insertGroupMember(GroupMemberRecord(gid, p1Slot, contactId = null, addedAt = 0L))   // p1, unresolved
    }

    fun hash(): String {
        val g = bVault.getGroup(gid)!!
        return GroupManager.membershipHash(gid, g.epoch, bVault.getGroupMembers(gid).map { it.memberId })
    }
    fun p1Sends(text: String) = assertTrue(pMgr.sendGroupText("b", gid, hash(), text))
    fun resolveP1() = bVault.insertGroupMember(GroupMemberRecord(gid, p1Slot, contactId = "p1", addedAt = 0L))
}

/** RÚN-05 review follow-up: a re-delivered held text keeps a LIVE copy, wherever it ends up. */
class HeldReDeliveryTest {

    @Test
    fun aCommittedReDelivery_restartsTheTtl_soTheTextStillArrives() {
        if (!aeadUp()) return
        val g = LeaseGroup()
        val ttl = GroupManager.PENDING_UNRESOLVED_GROUP_TEXT_TTL_MS
        g.p1Sends("T")
        // Poll A at t0 (the 1:1 screen): p1 is unconfirmed, so T is held. The user leaves.
        g.bGm.clockMs = { 1_000L }
        val a = g.bGm.pollDirectPending("p1")
        assertTrue(a.messages.isEmpty()); assertEquals(1, g.bGm.heldTextCountForTest())
        a.abandon()
        // Poll B at t0 + 8 min gets the SAME blob and COMMITS: the relay copy is gone.
        g.bGm.clockMs = { 1_000L + 8 * 60_000L }
        val b = g.bGm.pollDirectPending("p1")
        b.commit()
        assertEquals(0, g.relay.total(g.txtToB), "precondition: B acked T, the held copy is now the only one")
        assertEquals(1, g.bGm.heldTextCountForTest(), "held once, not twice")
        // p1 is confirmed TTL − 1 ms after B (i.e. past the first decrypt's TTL).
        g.bGm.clockMs = { 1_000L + 8 * 60_000L + ttl - 1 }
        g.resolveP1()
        assertEquals(listOf("T"), g.bGm.pollGroup(g.gid).map { it.text }, "the TTL runs from B, the decrypt that consumed the relay copy")
    }

    @Test
    fun aFreshCopyInAnAbandonedDrain_doesNotLoseTheTextItDisplaced() {
        if (!aeadUp()) return
        val g = LeaseGroup()
        g.p1Sends("T")
        val a = g.bGm.pollDirectPending("p1")                 // held (p1 unconfirmed) …
        a.abandon()                                          // … and the relay keeps it
        g.resolveP1()
        // The re-delivery is now shown FRESH (as an echo in the 1:1), which drops the
        // held copy — and then that screen is closed before it commits.
        val b = g.bGm.pollDirectPending("p1")
        assertEquals(listOf("T"), b.messages.map { it.text })
        assertEquals(0, g.bGm.heldTextCountForTest(), "the held copy gave way to the fresh one")
        b.abandon()
        // Nothing was acked, so the relay hands T out again: the group shows it.
        val c = g.bGm.pollGroupPending(g.gid)
        assertEquals(listOf("T"), c.messages.map { it.text }, "not lost")
        c.commit()
        assertEquals(0, g.relay.total(g.txtToB))
    }
}

/** The blob identity the buffers dedupe on survives a re-decrypt of the same blob. */
class ReceivedBlobKeyTest {

    @Test
    fun ratchet_theSameBlobDecryptedTwice_keepsItsKey_whileTheUiIdChanges() {
        if (!aeadUp()) return
        val h = LaHarness(ratchet = true)
        assertTrue(h.bobMgr.sendMessage(LA, "r"))
        val first = h.aliceMgr.pollMessagesPending(LA)
        val a = first.messages.single()
        first.abandon()
        val second = h.aliceMgr.pollMessagesPending(LA)
        val b = second.messages.single()
        assertTrue(a.dedupeId.startsWith("dr-"), "precondition: a ratchet receive")
        assertNotEquals(a.dedupeId, b.dedupeId, "precondition: the UI id is fresh on every decrypt")
        assertTrue(a.blobKey.isNotEmpty(), "a decrypted text carries its blob identity")
        assertEquals(a.blobKey, b.blobKey, "the same blob keeps its identity across a re-delivery")
        second.commit()
        assertTrue(h.bobMgr.sendMessage(LA, "r"))
        val third = h.aliceMgr.pollMessagesPending(LA)
        val c = third.messages.single()
        third.commit()
        assertNotEquals(a.blobKey, c.blobKey, "another blob (same text) has another identity")
    }

    @Test
    fun legacy_theSameBlobDecryptedTwice_keepsItsKey() {
        if (!aeadUp()) return
        val h = LaHarness(ratchet = false)
        assertTrue(h.bobMgr.sendMessage(LA, "l"))
        val first = h.aliceMgr.pollMessagesPending(LA)
        val a = first.messages.single()
        first.abandon()
        val second = h.aliceMgr.pollMessagesPending(LA)
        val b = second.messages.single()
        // Settle it: an uncommitted legacy part lives in a PROCESS-wide registry.
        second.commit()
        assertTrue(a.blobKey.isNotEmpty())
        assertEquals(a.blobKey, b.blobKey)
    }
}

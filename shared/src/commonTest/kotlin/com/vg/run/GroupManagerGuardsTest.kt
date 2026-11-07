package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// GroupManager guard / validation / admin-operation coverage.
//
// Complements GroupManagerTest.kt (which covers the receive-side happy paths
// + crypto helpers). This file fills the gaps: every admin-op guard
// (createGroup/addMember/removeMember/transferAdmin), the additional
// handleInvite/handleJoin/handleRoster validation branches, and the
// ordering/handoff behaviours that recent bugs lived in.
//
// Almost all of these drive the protocol with a NULL transport: createGroup,
// addMember, removeMember, transferAdmin and the receive handlers all PERSIST
// to the vault BEFORE any network fan-out, and fanOutControl with no transport
// is a logged no-op. So local persistence + guard outcomes are observable with
// zero crypto. The two tests that must observe an actual SEND (the
// transfer-handoff regression lock, and leaveGroup's local-first ordering) go
// through real AES-GCM and are bridge-guarded like the other crypto tests
// (skipped on the iOS unit-test target where the Swift bridge isn't installed).
// ---------------------------------------------------------------------------

private fun gMemberId(seed: Int) = bytesToHex(ByteArray(8) { (seed + it).toByte() })

private fun seedPairedContact(vault: InMemoryVault, contactId: String, secret: ByteArray = generateSecureRandom(32)) {
    vault.insertContact(
        ContactRecord(
            contactId = contactId, sharedSecret = secret,
            trustLevel = 1, alias = "A-$contactId", aliasLastRotated = 0L,
        )
    )
    // Unique well-formed inbox ids per contact, derived from the id index so
    // 60+ contacts never collide (hashCode-derived ids can).
    val base = contactId.encodeToByteArray().fold(0) { a, b -> a * 31 + b }.toUInt().toString(16).padStart(8, '0')
    vault.insertInboxId(InboxIdRecord(
        inboxId = ("in$base".padEnd(32, 'A')).take(32), contactId = contactId,
        createdAt = 1L, expiresAt = Long.MAX_VALUE, direction = "inbound", cap = "A".repeat(43),
    ))
    vault.insertInboxId(InboxIdRecord(
        inboxId = ("ou$base".padEnd(32, 'B')).take(32), contactId = contactId,
        createdAt = 1L, expiresAt = Long.MAX_VALUE, direction = "outbound", cap = "B".repeat(43),
    ))
    // A dedicated control inbox so post-v7 control fan-out has a channel.
    vault.insertInboxId(InboxIdRecord(
        inboxId = ("oc$base".padEnd(32, 'C')).take(32), contactId = contactId,
        createdAt = 1L, expiresAt = Long.MAX_VALUE, direction = MessageManager.DIR_OUTBOUND_CTL, cap = "C".repeat(43),
    ))
}

/** A contact that is healthy-but-pending (inbound only, no outbound) — NOT
 *  fully paired, so it cannot be a group member. */
private fun seedPendingContact(vault: InMemoryVault, contactId: String) {
    vault.insertContact(
        ContactRecord(contactId, generateSecureRandom(32), 1, "A-$contactId", 0L)
    )
    val base = contactId.encodeToByteArray().fold(0) { a, b -> a * 31 + b }.toUInt().toString(16).padStart(8, '0')
    vault.insertInboxId(InboxIdRecord(
        inboxId = ("in$base".padEnd(32, 'A')).take(32), contactId = contactId,
        createdAt = 1L, expiresAt = Long.MAX_VALUE, direction = "inbound", cap = "A".repeat(43),
    ))
}

// ===========================================================================
// createGroup guards + local persistence
// ===========================================================================

class GroupCreateGuardsTest {
    private val noTransport: () -> MessageManager? = { null }

    @Test
    fun createGroup_emptyMembers_returnsNull() {
        val vault = InMemoryVault()
        val gm = GroupManager(vault, noTransport)
        assertNull(gm.createGroup("crew", emptyList()))
        assertEquals(0, vault.groups.size)
    }

    @Test
    fun createGroup_sizeCapExceeded_returnsNull() {
        // 64 members + self = 65 > MAX_GROUP_MEMBERS. The size guard runs before
        // any contact lookup, so the ids need not even exist.
        val vault = InMemoryVault()
        val gm = GroupManager(vault, noTransport)
        val tooMany = (0 until GroupManager.MAX_GROUP_MEMBERS).map { "c-$it" }
        assertNull(gm.createGroup("crew", tooMany))
        assertEquals(0, vault.groups.size)
    }

    @Test
    fun createGroup_unknownContact_returnsNull() {
        val vault = InMemoryVault()
        val gm = GroupManager(vault, noTransport)
        assertNull(gm.createGroup("crew", listOf("ghost")))
        assertEquals(0, vault.groups.size)
    }

    @Test
    fun createGroup_memberNotFullyPaired_returnsNull() {
        val vault = InMemoryVault()
        seedPairedContact(vault, "c-ok")
        seedPendingContact(vault, "c-pending")     // inbound only — cannot receive an invite
        val gm = GroupManager(vault, noTransport)
        assertNull(gm.createGroup("crew", listOf("c-ok", "c-pending")))
        // Fail closed: not even the half with the OK contact is persisted.
        assertEquals(0, vault.groups.size)
        assertEquals(0, vault.groupMembers.size)
    }

    @Test
    fun createGroup_happyPath_persistsLocallyEvenWithoutTransport() {
        // fanOutControl is a no-op with a null transport, but the LOCAL group
        // must still be fully written — that is what makes the admin a member
        // of its own group immediately.
        val vault = InMemoryVault()
        seedPairedContact(vault, "c-bob")
        seedPairedContact(vault, "c-carol")
        val gm = GroupManager(vault, noTransport)

        val gid = gm.createGroup("crew", listOf("c-bob", "c-carol"))
        assertNotNull(gid)
        val g = vault.getGroup(gid)!!
        assertEquals(1L, g.epoch)
        assertTrue(g.isAdmin)
        assertEquals(g.myMemberId, g.adminMemberId)

        val members = vault.getGroupMembers(gid)
        assertEquals(3, members.size)                                   // self + 2
        assertEquals(g.myMemberId, members.first { it.contactId == null }.memberId)
        assertEquals(setOf("c-bob", "c-carol"), members.mapNotNull { it.contactId }.toSet())
        // Every minted memberId is a distinct 16-hex string.
        val ids = members.map { it.memberId }
        assertEquals(3, ids.toSet().size)
        assertTrue(ids.all { GroupManager.isValidMemberId(it) })
    }

    @Test
    fun createGroup_truncatesOverlongName() {
        val vault = InMemoryVault()
        seedPairedContact(vault, "c-bob")
        val gm = GroupManager(vault, noTransport)
        val longName = "x".repeat(GroupManager.MAX_GROUP_NAME_CHARS + 50)
        val gid = gm.createGroup(longName, listOf("c-bob"))!!
        assertEquals(GroupManager.MAX_GROUP_NAME_CHARS, vault.getGroup(gid)!!.name.length)
    }
}

// ===========================================================================
// addMember / removeMember / transferAdmin guards + local persistence
// ===========================================================================

class GroupAdminOpsTest {
    private val noTransport: () -> MessageManager? = { null }

    /** An admin-side group with two resolved members, built via createGroup
     *  (persists locally even with no transport). */
    private fun adminGroup(vault: InMemoryVault): String {
        seedPairedContact(vault, "c-bob")
        seedPairedContact(vault, "c-carol")
        val gm = GroupManager(vault, noTransport)
        return gm.createGroup("crew", listOf("c-bob", "c-carol"))!!
    }

    @Test
    fun addMember_groupMissing_returnsFalse() {
        val vault = InMemoryVault()
        val gm = GroupManager(vault, noTransport)
        assertFalse(gm.addMember(GroupManager.newGroupId(), "c-bob"))
    }

    @Test
    fun addMember_notAdmin_returnsFalse() {
        // A member-side group (joined via invite — isAdmin == false).
        val vault = InMemoryVault()
        seedPairedContact(vault, "admin-contact")
        val gm = GroupManager(vault, noTransport)
        val gid = GroupManager.newGroupId()
        val adm = gMemberId(10); val me = gMemberId(20)
        gm.handleControl(
            "admin-contact", gid, GroupManager.KIND_INVITE,
            """{"n":"crew","ep":1,"adm":${jsonEscapeString(adm)},"you":${jsonEscapeString(me)},"mem":[${jsonEscapeString(adm)},${jsonEscapeString(me)}]}""",
        )
        gm.acceptInvite(gid)   // consent gate: join the parked invite
        seedPairedContact(vault, "c-new")
        assertFalse(gm.addMember(gid, "c-new"))
    }

    @Test
    fun addMember_contactNotPaired_returnsFalse() {
        val vault = InMemoryVault()
        val gid = adminGroup(vault)
        val gm = GroupManager(vault, noTransport)
        seedPendingContact(vault, "c-pending")
        assertFalse(gm.addMember(gid, "c-pending"))
    }

    @Test
    fun addMember_alreadyMember_returnsFalse() {
        val vault = InMemoryVault()
        val gid = adminGroup(vault)
        val gm = GroupManager(vault, noTransport)
        assertFalse(gm.addMember(gid, "c-bob"))
        assertEquals(3, vault.getGroupMembers(gid).size)
    }

    @Test
    fun addMember_sizeCapExceeded_returnsFalse() {
        // Build a 64-member group by hand (self admin + 63 unresolved rows),
        // then a 65th add must be refused — the size guard, last in the chain.
        val vault = InMemoryVault()
        val gm = GroupManager(vault, noTransport)
        val gid = GroupManager.newGroupId()
        val me = gMemberId(1)
        vault.insertGroup(GroupRecord(gid, "big", 1, adminMemberId = me, myMemberId = me, createdAt = 0L))
        vault.insertGroupMember(GroupMemberRecord(gid, me, null, 0L))
        for (i in 2..GroupManager.MAX_GROUP_MEMBERS) {
            vault.insertGroupMember(GroupMemberRecord(gid, gMemberId(i * 7), null, 0L))
        }
        assertEquals(GroupManager.MAX_GROUP_MEMBERS, vault.getGroupMembers(gid).size)
        seedPairedContact(vault, "c-new")
        assertFalse(gm.addMember(gid, "c-new"))
    }

    @Test
    fun addMember_happyPath_bumpsEpoch_andAddsRow() {
        val vault = InMemoryVault()
        val gid = adminGroup(vault)
        val gm = GroupManager(vault, noTransport)
        seedPairedContact(vault, "c-dave")
        assertTrue(gm.addMember(gid, "c-dave"))
        assertEquals(2L, vault.getGroup(gid)!!.epoch)
        assertEquals(4, vault.getGroupMembers(gid).size)
        assertTrue(vault.getGroupMembers(gid).any { it.contactId == "c-dave" })
    }

    @Test
    fun removeMember_notAdmin_returnsFalse() {
        val vault = InMemoryVault()
        seedPairedContact(vault, "admin-contact")
        val gm = GroupManager(vault, noTransport)
        val gid = GroupManager.newGroupId()
        val adm = gMemberId(10); val me = gMemberId(20); val bob = gMemberId(30)
        gm.handleControl(
            "admin-contact", gid, GroupManager.KIND_INVITE,
            """{"n":"crew","ep":1,"adm":${jsonEscapeString(adm)},"you":${jsonEscapeString(me)},"mem":[${jsonEscapeString(adm)},${jsonEscapeString(me)},${jsonEscapeString(bob)}]}""",
        )
        gm.acceptInvite(gid)   // consent gate: join the parked invite
        assertFalse(gm.removeMember(gid, bob))
        assertEquals(3, vault.getGroupMembers(gid).size)
    }

    @Test
    fun removeMember_self_returnsFalse() {
        val vault = InMemoryVault()
        val gid = adminGroup(vault)
        val gm = GroupManager(vault, noTransport)
        val me = vault.getGroup(gid)!!.myMemberId
        assertFalse(gm.removeMember(gid, me))
        assertEquals(3, vault.getGroupMembers(gid).size)
    }

    @Test
    fun removeMember_unknownMember_returnsFalse() {
        val vault = InMemoryVault()
        val gid = adminGroup(vault)
        val gm = GroupManager(vault, noTransport)
        assertFalse(gm.removeMember(gid, gMemberId(99)))
        assertEquals(3, vault.getGroupMembers(gid).size)
    }

    @Test
    fun removeMember_happyPath_removesRow_bumpsEpoch() {
        val vault = InMemoryVault()
        val gid = adminGroup(vault)
        val gm = GroupManager(vault, noTransport)
        val bobMember = vault.getGroupMembers(gid).first { it.contactId == "c-bob" }.memberId
        assertTrue(gm.removeMember(gid, bobMember))
        assertEquals(2L, vault.getGroup(gid)!!.epoch)
        assertEquals(2, vault.getGroupMembers(gid).size)
        assertTrue(vault.getGroupMembers(gid).none { it.memberId == bobMember })
    }

    @Test
    fun transferAdmin_notAdmin_returnsFalse() {
        val vault = InMemoryVault()
        seedPairedContact(vault, "admin-contact")
        val gm = GroupManager(vault, noTransport)
        val gid = GroupManager.newGroupId()
        val adm = gMemberId(10); val me = gMemberId(20)
        gm.handleControl(
            "admin-contact", gid, GroupManager.KIND_INVITE,
            """{"n":"crew","ep":1,"adm":${jsonEscapeString(adm)},"you":${jsonEscapeString(me)},"mem":[${jsonEscapeString(adm)},${jsonEscapeString(me)}]}""",
        )
        gm.acceptInvite(gid)   // consent gate: join the parked invite
        assertFalse(gm.transferAdmin(gid, adm))
    }

    @Test
    fun transferAdmin_toSelf_returnsFalse() {
        val vault = InMemoryVault()
        val gid = adminGroup(vault)
        val gm = GroupManager(vault, noTransport)
        assertFalse(gm.transferAdmin(gid, vault.getGroup(gid)!!.myMemberId))
    }

    @Test
    fun transferAdmin_unknownMember_returnsFalse() {
        val vault = InMemoryVault()
        val gid = adminGroup(vault)
        val gm = GroupManager(vault, noTransport)
        assertFalse(gm.transferAdmin(gid, gMemberId(99)))
        assertTrue(vault.getGroup(gid)!!.isAdmin)
    }

    @Test
    fun transferAdmin_happyPath_demotesUs_andBumpsEpoch() {
        val vault = InMemoryVault()
        val gid = adminGroup(vault)
        markAllMembersJoined(vault, gid)   // transferAdmin refuses while a join is pending
        val gm = GroupManager(vault, noTransport)
        val bobMember = vault.getGroupMembers(gid).first { it.contactId == "c-bob" }.memberId
        assertTrue(gm.transferAdmin(gid, bobMember))
        val g = vault.getGroup(gid)!!
        assertEquals(bobMember, g.adminMemberId)
        assertEquals(2L, g.epoch)
        assertFalse(g.isAdmin)   // we persisted ourselves out of the role
    }
}

// ===========================================================================
// transferAdmin handoff MUST still send the final roster (regression lock).
//
// The bug: transferAdmin persists the new admin first, so by the time
// broadcastRoster runs we are no longer admin; broadcastRoster's !isAdmin
// guard silently dropped the one roster that moves the authority, freezing
// the group with a phantom admin. The handoff flag exists to send it anyway.
// This pins the SEND, not just the local demotion the unit test above checks.
// ===========================================================================

class GroupTransferHandoffSendTest {

    @Test
    fun transferAdmin_emitsHandoffRoster_eventThoughWeAreNoLongerAdmin() {
        if (!aeadUp()) return
        val vault = InMemoryVault()
        seedPairedContact(vault, "c-bob")
        seedPairedContact(vault, "c-carol")
        val http = RecordingRelayHttp()
        // createGroup fan-out: 2 invites. transferAdmin: 1 roster per resolved
        // member (2) PLUS the FIX-A self-join to the new admin (1). Script generous
        // successes so nothing returns the -1 stub.
        repeat(8) { http.script(HttpResult(code = 202, body = "", isSuccess = true)) }
        val mgr = MessageManager(vault, "http://relay.test", http as RelayHttp)
        val gm = GroupManager(vault) { mgr }

        val gid = gm.createGroup("crew", listOf("c-bob", "c-carol"))!!
        val callsAfterCreate = http.calls.size
        assertEquals(2, callsAfterCreate, "createGroup sends one invite per member")
        markAllMembersJoined(vault, gid)   // transferAdmin refuses while a join is pending

        val bobMember = vault.getGroupMembers(gid).first { it.contactId == "c-bob" }.memberId
        assertTrue(gm.transferAdmin(gid, bobMember))

        // The handoff roster MUST fan out to the resolved members even though we
        // demoted ourselves before broadcasting (pre-fix: zero new calls — the
        // !isAdmin guard swallowed the broadcast). FIX A adds a self-join to the NEW
        // admin so it can redistribute our resolution tags post-handoff: 2 roster
        // copies (bob + carol) + 1 self-join (to bob) = 3.
        val handoffCalls = http.calls.size - callsAfterCreate
        assertEquals(3, handoffCalls, "handoff roster (2) + self-join to the new admin (1)")
    }
}

// ===========================================================================
// handleInvite — additional validation branches
// ===========================================================================

class GroupInviteGuardsTest {
    private val noTransport: () -> MessageManager? = { null }

    private fun gm(vault: InMemoryVault): GroupManager {
        seedPairedContact(vault, "admin-contact")
        return GroupManager(vault, noTransport)
    }

    private fun invite(adm: String, you: String, mem: List<String>, ep: Long = 1, name: String = "crew"): String {
        val memJson = mem.joinToString(",") { jsonEscapeString(it) }
        return """{"n":${jsonEscapeString(name)},"ep":$ep,"adm":${jsonEscapeString(adm)},"you":${jsonEscapeString(you)},"mem":[$memJson]}"""
    }

    @Test
    fun invite_alreadyMember_isIgnored() {
        val vault = InMemoryVault()
        val g = gm(vault)
        val gid = GroupManager.newGroupId()
        val adm = gMemberId(1); val me = gMemberId(2)
        g.handleControl("admin-contact", gid, GroupManager.KIND_INVITE, invite(adm, me, listOf(adm, me), name = "first"))
        // GROUP-1 consent gate: the invite is PARKED, not auto-joined — accept it.
        assertNull(vault.getGroup(gid))
        assertTrue(g.acceptInvite(gid))
        assertEquals("first", vault.getGroup(gid)!!.name)
        // A second invite for the SAME group (already a member) must not overwrite.
        g.handleControl("admin-contact", gid, GroupManager.KIND_INVITE, invite(adm, me, listOf(adm, me), ep = 9, name = "second"))
        assertEquals("first", vault.getGroup(gid)!!.name)
        assertEquals(1L, vault.getGroup(gid)!!.epoch)
    }

    @Test
    fun invite_admEqualsYou_isRejected() {
        val vault = InMemoryVault()
        val g = gm(vault)
        val gid = GroupManager.newGroupId()
        val x = gMemberId(1)
        g.handleControl("admin-contact", gid, GroupManager.KIND_INVITE, invite(x, x, listOf(x)))
        assertNull(vault.getGroup(gid))
    }

    @Test
    fun invite_admNotInMemberList_isRejected() {
        val vault = InMemoryVault()
        val g = gm(vault)
        val gid = GroupManager.newGroupId()
        val adm = gMemberId(1); val me = gMemberId(2)
        g.handleControl("admin-contact", gid, GroupManager.KIND_INVITE, invite(adm, me, listOf(me)))
        assertNull(vault.getGroup(gid))
    }

    @Test
    fun invite_youNotInMemberList_isRejected() {
        val vault = InMemoryVault()
        val g = gm(vault)
        val gid = GroupManager.newGroupId()
        val adm = gMemberId(1); val me = gMemberId(2)
        g.handleControl("admin-contact", gid, GroupManager.KIND_INVITE, invite(adm, me, listOf(adm)))
        assertNull(vault.getGroup(gid))
    }

    @Test
    fun invite_epochZero_isRejected() {
        val vault = InMemoryVault()
        val g = gm(vault)
        val gid = GroupManager.newGroupId()
        val adm = gMemberId(1); val me = gMemberId(2)
        g.handleControl("admin-contact", gid, GroupManager.KIND_INVITE, invite(adm, me, listOf(adm, me), ep = 0))
        assertNull(vault.getGroup(gid))
    }

    @Test
    fun invite_epochAboveMax_isRejected() {
        // An invite seeding a near-Long.MAX epoch is rejected, so it
        // can't later overflow the roster upper-bound compare (g.epoch + advance).
        val vault = InMemoryVault()
        val g = gm(vault)
        val gid = GroupManager.newGroupId()
        val adm = gMemberId(1); val me = gMemberId(2)
        g.handleControl("admin-contact", gid, GroupManager.KIND_INVITE,
            invite(adm, me, listOf(adm, me), ep = Long.MAX_VALUE))
        assertNull(vault.getGroup(gid))
        g.handleControl("admin-contact", gid, GroupManager.KIND_INVITE,
            invite(adm, me, listOf(adm, me), ep = GroupManager.MAX_GROUP_EPOCH + 1))
        assertNull(vault.getGroup(gid))
        // The cap itself is a valid epoch — parked, then accepted.
        g.handleControl("admin-contact", gid, GroupManager.KIND_INVITE,
            invite(adm, me, listOf(adm, me), ep = GroupManager.MAX_GROUP_EPOCH))
        assertTrue(g.acceptInvite(gid))
        assertEquals(GroupManager.MAX_GROUP_EPOCH, vault.getGroup(gid)!!.epoch)
    }

    @Test
    fun invite_memberListTooLarge_isRejected() {
        val vault = InMemoryVault()
        val g = gm(vault)
        val gid = GroupManager.newGroupId()
        val adm = gMemberId(1); val me = gMemberId(2)
        val mem = (0..GroupManager.MAX_GROUP_MEMBERS).map { gMemberId(100 + it) } + listOf(adm, me)
        g.handleControl("admin-contact", gid, GroupManager.KIND_INVITE, invite(adm, me, mem))
        assertNull(vault.getGroup(gid))
    }

    @Test
    fun invite_truncatesOverlongName() {
        val vault = InMemoryVault()
        val g = gm(vault)
        val gid = GroupManager.newGroupId()
        val adm = gMemberId(1); val me = gMemberId(2)
        val longName = "z".repeat(GroupManager.MAX_GROUP_NAME_CHARS + 40)
        g.handleControl("admin-contact", gid, GroupManager.KIND_INVITE, invite(adm, me, listOf(adm, me), name = longName))
        assertTrue(g.acceptInvite(gid))
        assertEquals(GroupManager.MAX_GROUP_NAME_CHARS, vault.getGroup(gid)!!.name.length)
    }

    @Test
    fun invite_nameWithQuotesAndBackslashes_roundTrips() {
        val vault = InMemoryVault()
        val g = gm(vault)
        val gid = GroupManager.newGroupId()
        val adm = gMemberId(1); val me = gMemberId(2)
        val tricky = """a"b\c"""
        g.handleControl("admin-contact", gid, GroupManager.KIND_INVITE, invite(adm, me, listOf(adm, me), name = tricky))
        assertTrue(g.acceptInvite(gid))
        assertEquals(tricky, vault.getGroup(gid)!!.name)
    }
}

// ===========================================================================
// handleJoin — admin stores a member's tags (and its guards)
// ===========================================================================

class GroupJoinHandlingTest {
    private val noTransport: () -> MessageManager? = { null }

    private fun adminGroup(vault: InMemoryVault): Pair<GroupManager, String> {
        seedPairedContact(vault, "c-bob")
        seedPairedContact(vault, "c-carol")
        val gm = GroupManager(vault, noTransport)
        return gm to gm.createGroup("crew", listOf("c-bob", "c-carol"))!!
    }

    private fun joinBody(you: String, tags: List<String>): String {
        val tagJson = tags.joinToString(",") { jsonEscapeString(it) }
        return """{"you":${jsonEscapeString(you)},"tags":[$tagJson]}"""
    }

    @Test
    fun join_happyPath_storesTags() {
        val vault = InMemoryVault()
        val (gm, gid) = adminGroup(vault)
        val bobMember = vault.getGroupMembers(gid).first { it.contactId == "c-bob" }.memberId
        // Join tags are "sym:bound" pairs.
        val tags = listOf("${gMemberId(40)}:${gMemberId(41)}", "${gMemberId(50)}:${gMemberId(51)}")
        gm.handleControl("c-bob", gid, GroupManager.KIND_JOIN, joinBody(bobMember, tags))
        val stored = vault.getGroupMembers(gid).first { it.memberId == bobMember }.tags
        assertEquals(tags.joinToString(";"), stored)
    }

    @Test
    fun rosterBroadcast_isRateLimitedPerMemberAndGroup() {
        // The member-triggered roster fan-out is throttled to
        // one per MIN_ROSTER_INTERVAL_MS per (group, member), regardless of tag
        // content — so attacker-varied padding can't force a fan-out each join.
        val vault = InMemoryVault()
        val gm = GroupManager(vault, noTransport)
        val gid = GroupManager.newGroupId()
        val iv = GroupManager.MIN_ROSTER_INTERVAL_MS

        assertTrue(gm.rosterBroadcastAllowed(gid, "m", 1_000L), "first is allowed")
        assertFalse(gm.rosterBroadcastAllowed(gid, "m", 5_000L), "within interval denied")
        assertFalse(gm.rosterBroadcastAllowed(gid, "m", 1_000L + iv - 1), "still within interval denied")
        assertTrue(gm.rosterBroadcastAllowed(gid, "m", 1_000L + iv), "after interval allowed again")
        // Independent per member and per group.
        assertTrue(gm.rosterBroadcastAllowed(gid, "other", 5_000L), "different member is independent")
        assertTrue(gm.rosterBroadcastAllowed(GroupManager.newGroupId(), "m", 5_000L), "different group is independent")
        // A backward clock jump resets the throttle rather than freezing it.
        assertTrue(gm.rosterBroadcastAllowed(gid, "m", 100L), "backward clock jump resets")
    }

    @Test
    fun join_fromNonMemberContact_isDropped() {
        val vault = InMemoryVault()
        val (gm, gid) = adminGroup(vault)
        seedPairedContact(vault, "mallory")
        gm.handleControl("mallory", gid, GroupManager.KIND_JOIN, joinBody(gMemberId(40), listOf(gMemberId(41))))
        // No member row gained tags.
        assertTrue(vault.getGroupMembers(gid).all { it.tags.isEmpty() })
    }

    @Test
    fun join_memberIdMismatch_isDropped() {
        val vault = InMemoryVault()
        val (gm, gid) = adminGroup(vault)
        // c-bob claims c-carol's assigned memberId — refused.
        val carolMember = vault.getGroupMembers(gid).first { it.contactId == "c-carol" }.memberId
        gm.handleControl("c-bob", gid, GroupManager.KIND_JOIN, joinBody(carolMember, listOf(gMemberId(40))))
        assertTrue(vault.getGroupMembers(gid).all { it.tags.isEmpty() })
    }

    @Test
    fun join_invalidTagFormat_isDropped() {
        val vault = InMemoryVault()
        val (gm, gid) = adminGroup(vault)
        val bobMember = vault.getGroupMembers(gid).first { it.contactId == "c-bob" }.memberId
        gm.handleControl("c-bob", gid, GroupManager.KIND_JOIN, joinBody(bobMember, listOf("NOT-16-HEX")))
        assertTrue(vault.getGroupMembers(gid).first { it.memberId == bobMember }.tags.isEmpty())
    }

    @Test
    fun join_onNonAdminDevice_isDropped() {
        // A member-side group can't process joins.
        val vault = InMemoryVault()
        seedPairedContact(vault, "admin-contact")
        val gm = GroupManager(vault, noTransport)
        val gid = GroupManager.newGroupId()
        val adm = gMemberId(10); val me = gMemberId(20)
        gm.handleControl(
            "admin-contact", gid, GroupManager.KIND_INVITE,
            """{"n":"crew","ep":1,"adm":${jsonEscapeString(adm)},"you":${jsonEscapeString(me)},"mem":[${jsonEscapeString(adm)},${jsonEscapeString(me)}]}""",
        )
        gm.handleControl("admin-contact", gid, GroupManager.KIND_JOIN, joinBody(adm, listOf(gMemberId(40))))
        assertTrue(vault.getGroupMembers(gid).all { it.tags.isEmpty() })
    }
}

// ===========================================================================
// handleRoster — additional validation + resolution branches
// ===========================================================================

class GroupRosterHandlingTest {
    private val noTransport: () -> MessageManager? = { null }

    /** Member-side fixture joined via invite (admin + me + bob). */
    private class F(val vault: InMemoryVault, val gm: GroupManager, val gid: String,
                    val adm: String, val me: String, val bob: String)

    private fun joined(): F {
        val vault = InMemoryVault()
        seedPairedContact(vault, "admin-contact")
        val gm = GroupManager(vault, noTransport)
        val gid = GroupManager.newGroupId()
        val adm = gMemberId(10); val me = gMemberId(20); val bob = gMemberId(30)
        gm.handleControl(
            "admin-contact", gid, GroupManager.KIND_INVITE,
            """{"n":"crew","ep":1,"adm":${jsonEscapeString(adm)},"you":${jsonEscapeString(me)},"mem":[${jsonEscapeString(adm)},${jsonEscapeString(me)},${jsonEscapeString(bob)}]}""",
        )
        gm.acceptInvite(gid)   // consent gate: join the parked invite
        return F(vault, gm, gid, adm, me, bob)
    }

    private fun roster(adm: String, entries: List<String>, ep: Long = 2, name: String = "crew"): String {
        val mem = entries.joinToString(",") { jsonEscapeString(it) }
        return """{"n":${jsonEscapeString(name)},"ep":$ep,"adm":${jsonEscapeString(adm)},"mem":[$mem]}"""
    }

    @Test
    fun roster_adminNotInEntries_isRejected() {
        val f = joined()
        // adm absent from the entry set → rejected, epoch unchanged.
        f.gm.handleControl("admin-contact", f.gid, GroupManager.KIND_ROSTER,
            roster(f.adm, listOf("${f.me}:", "${f.bob}:")))
        assertEquals(1L, f.vault.getGroup(f.gid)!!.epoch)
    }

    @Test
    fun roster_malformedEntry_isRejectedWhole() {
        val f = joined()
        // One entry has a colon at the wrong offset (not position 16) — the
        // count-mismatch guard drops the whole roster.
        f.gm.handleControl("admin-contact", f.gid, GroupManager.KIND_ROSTER,
            roster(f.adm, listOf("${f.adm}:", "${f.me}:", "bogus:tag")))
        assertEquals(1L, f.vault.getGroup(f.gid)!!.epoch)
        assertEquals(3, f.vault.getGroupMembers(f.gid).size)
    }

    @Test
    fun roster_removesDepartedMember() {
        val f = joined()
        // A valid roster that no longer lists bob → bob's row is deleted.
        f.gm.handleControl("admin-contact", f.gid, GroupManager.KIND_ROSTER,
            roster(f.adm, listOf("${f.adm}:", "${f.me}:")))
        assertEquals(2L, f.vault.getGroup(f.gid)!!.epoch)
        assertEquals(2, f.vault.getGroupMembers(f.gid).size)
        assertTrue(f.vault.getGroupMembers(f.gid).none { it.memberId == f.bob })
    }

    @Test
    fun roster_boundTagUnderWrongSlot_doesNotResolve() {
        // Bob's resolution tag is BOUND to bob's memberId. A
        // malicious admin copying that same tag under a DIFFERENT slot (ghost)
        // can NOT mis-bind: the resolver recomputes the bound tag with the ghost
        // slot's id, which no longer matches. So bob resolves only at HIS slot and
        // ghost stays unresolved — one contact still backs at most one member.
        val f = joined()
        val bobSecret = generateSecureRandom(32)
        seedPairedContact(f.vault, "bob-contact", bobSecret)
        val bound = GroupManager.boundTag(bobSecret, f.gid, f.bob)
        val ghost = gMemberId(77)
        f.gm.handleControl("admin-contact", f.gid, GroupManager.KIND_ROSTER,
            roster(f.adm, listOf("${f.adm}:", "${f.me}:", "${f.bob}:$bound", "$ghost:$bound")))
        val members = f.vault.getGroupMembers(f.gid)
        assertEquals("bob-contact", members.first { it.memberId == f.bob }.contactId)
        assertNull(members.firstOrNull { it.memberId == ghost }?.contactId, "ghost slot must NOT resolve to bob")
        assertEquals(1, members.count { it.contactId == "bob-contact" })
    }
}

// ===========================================================================
// handleLeave (admin re-roster) + leaveGroup local-first ordering
// ===========================================================================

class GroupLeaveSemanticsTest {
    private val noTransport: () -> MessageManager? = { null }

    @Test
    fun handleLeave_toAdmin_removesSender_andBumpsEpoch() {
        // Admin-side group; a resolved member leaves → its row goes and the
        // admin bumps the epoch (re-roster fans out, no-op here).
        val vault = InMemoryVault()
        seedPairedContact(vault, "c-bob")
        seedPairedContact(vault, "c-carol")
        val gm = GroupManager(vault, noTransport)
        val gid = gm.createGroup("crew", listOf("c-bob", "c-carol"))!!
        assertEquals(1L, vault.getGroup(gid)!!.epoch)

        gm.handleControl("c-bob", gid, GroupManager.KIND_LEAVE, "{}")
        assertEquals(2L, vault.getGroup(gid)!!.epoch)
        assertEquals(2, vault.getGroupMembers(gid).size)
        assertTrue(vault.getGroupMembers(gid).none { it.contactId == "c-bob" })
    }

    @Test
    fun leaveGroup_deletesLocallyBeforeFanout_andFiresCallbackOnce() {
        if (!aeadUp()) return
        val vault = InMemoryVault()
        seedPairedContact(vault, "c-bob")
        seedPairedContact(vault, "c-carol")
        val http = RecordingRelayHttp()
        repeat(8) { http.script(HttpResult(code = 202, body = "", isSuccess = true)) }
        val mgr = MessageManager(vault, "http://relay.test", http as RelayHttp)
        val gm = GroupManager(vault) { mgr }
        val gid = gm.createGroup("crew", listOf("c-bob", "c-carol"))!!
        val callsAfterCreate = http.calls.size

        var callbackFires = 0
        var groupGoneAtCallback = false
        var noSendsYetAtCallback = false
        gm.leaveGroup(gid) {
            callbackFires++
            // The local delete must already be visible...
            groupGoneAtCallback = vault.getGroup(gid) == null
            // ...and NO leave notice may have been sent yet (local-first).
            noSendsYetAtCallback = http.calls.size == callsAfterCreate
        }

        assertEquals(1, callbackFires)
        assertTrue(groupGoneAtCallback, "group must be deleted before the callback")
        assertTrue(noSendsYetAtCallback, "callback must fire before any leave notice is sent")
        assertNull(vault.getGroup(gid))
        // The notices DO go out afterwards (one per resolved member).
        assertEquals(2, http.calls.size - callsAfterCreate)
    }

    @Test
    fun leaveGroup_overload_withoutCallback_stillDeletes() {
        val vault = InMemoryVault()
        seedPairedContact(vault, "c-bob")
        val gm = GroupManager(vault, noTransport)
        val gid = gm.createGroup("crew", listOf("c-bob"))!!
        gm.leaveGroup(gid)
        assertNull(vault.getGroup(gid))
        assertEquals(0, vault.getGroupMembers(gid).size)
    }
}

// ===========================================================================
// handleInvite — GROUP-1 forced-join cap + rate-limit
// ===========================================================================

class GroupInviteForcedJoinTest {
    private val noTransport: () -> MessageManager? = { null }

    private fun invite(adm: String, you: String, mem: List<String>, ep: Long = 1, name: String = "crew"): String {
        val memJson = mem.joinToString(",") { jsonEscapeString(it) }
        return """{"n":${jsonEscapeString(name)},"ep":$ep,"adm":${jsonEscapeString(adm)},"you":${jsonEscapeString(you)},"mem":[$memJson]}"""
    }

    /** Fire one INVITE for a fresh group from [inviter]. Returns the groupId. */
    private fun pushInvite(g: GroupManager, inviter: String): String {
        val gid = GroupManager.newGroupId()
        val adm = gMemberId(1); val me = gMemberId(2)
        g.handleControl(inviter, gid, GroupManager.KIND_INVITE, invite(adm, me, listOf(adm, me)))
        return gid
    }

    private fun isParked(g: GroupManager, gid: String) = g.pendingInvites().any { it.groupId == gid }
    private fun pendingFrom(g: GroupManager, contact: String) =
        g.pendingInvites().count { it.inviterContactId == contact }

    @Test
    fun invite_parksForConsent_doesNotAutoJoin() {
        // GROUP-1 consent gate: an invite must NOT auto-join or disclose tags —
        // it parks until the user accepts.
        val vault = InMemoryVault()
        seedPairedContact(vault, "friend")
        val g = GroupManager(vault, noTransport)

        val gid = pushInvite(g, "friend")
        assertNull(vault.getGroup(gid), "invite must NOT auto-join")
        assertEquals(1, g.pendingInvites().size)
        assertEquals("friend", g.pendingInvites().first().inviterContactId)

        assertTrue(g.acceptInvite(gid), "accept joins the group")
        assertNotNull(vault.getGroup(gid))
        assertTrue(g.pendingInvites().isEmpty(), "prompt cleared after accept")
    }

    @Test
    fun invite_decline_dropsWithoutJoining() {
        val vault = InMemoryVault()
        seedPairedContact(vault, "friend")
        val g = GroupManager(vault, noTransport)

        val gid = pushInvite(g, "friend")
        assertEquals(1, g.pendingInvites().size)
        g.declineInvite(gid)
        assertTrue(g.pendingInvites().isEmpty())
        assertNull(vault.getGroup(gid))
        assertFalse(g.acceptInvite(gid), "accepting a declined invite is a no-op")
        assertNull(vault.getGroup(gid))
    }

    @Test
    fun invite_forcedGroupCap_perContact() {
        val vault = InMemoryVault()
        seedPairedContact(vault, "spammer")
        val g = GroupManager(vault, noTransport)

        // The cap-th invite still parks; the one past it is dropped.
        repeat(GroupManager.MAX_FORCED_GROUPS_PER_CONTACT) { pushInvite(g, "spammer") }
        assertEquals(GroupManager.MAX_FORCED_GROUPS_PER_CONTACT, g.pendingInvites().size)

        val overflowGid = pushInvite(g, "spammer")
        assertFalse(isParked(g, overflowGid), "invite past the per-contact cap must not park")
        assertEquals(GroupManager.MAX_FORCED_GROUPS_PER_CONTACT, g.pendingInvites().size)
    }

    @Test
    fun invite_cap_countsPendingPlusJoined() {
        // The cap bounds pending + already-joined together: accepting some parked
        // invites does not free cap slots (they became joined groups).
        val vault = InMemoryVault()
        seedPairedContact(vault, "spammer")
        val g = GroupManager(vault, noTransport)

        val gids = (0 until GroupManager.MAX_FORCED_GROUPS_PER_CONTACT).map { pushInvite(g, "spammer") }
        // Accept half — they convert pending → joined, still counting toward the cap.
        gids.take(gids.size / 2).forEach { assertTrue(g.acceptInvite(it)) }
        val overflowGid = pushInvite(g, "spammer")
        assertFalse(isParked(g, overflowGid), "joined groups still count toward the per-contact cap")
    }

    @Test
    fun invite_cap_isPerContact_notGlobal() {
        val vault = InMemoryVault()
        seedPairedContact(vault, "spammer")
        seedPairedContact(vault, "friend")
        val g = GroupManager(vault, noTransport)

        // Max out one contact...
        repeat(GroupManager.MAX_FORCED_GROUPS_PER_CONTACT) { pushInvite(g, "spammer") }
        assertFalse(isParked(g, pushInvite(g, "spammer")))
        // ...a DIFFERENT contact is unaffected.
        val friendGid = pushInvite(g, "friend")
        assertTrue(isParked(g, friendGid), "the cap must be per-contact, not global")
    }

    @Test
    fun invite_rateLimit_survivesDecline() {
        // Isolates the time-window rate-limit from the standing cap: fill the
        // window, then DECLINE every parked invite so the cap reads 0. A further
        // invite in the same window must still be dropped by the rate-limit (else
        // churning invite+decline would re-harvest tags without bound).
        val vault = InMemoryVault()
        seedPairedContact(vault, "spammer")
        val g = GroupManager(vault, noTransport)

        val gids = (0 until GroupManager.MAX_INVITES_PER_WINDOW).map { pushInvite(g, "spammer") }
        assertEquals(GroupManager.MAX_INVITES_PER_WINDOW, g.pendingInvites().size)
        gids.forEach { g.declineInvite(it) }
        assertEquals(0, pendingFrom(g, "spammer"))

        val afterDecline = pushInvite(g, "spammer")
        assertFalse(isParked(g, afterDecline), "rate-limit must hold even after the cap is freed by decline")
    }

    // "admin" is TRUST-ON-FIRST-INVITE. A co-member who re-invites a
    // victim after they leave/are-removed (deleteGroup drops the group row, but the
    // group_admin tombstone SURVIVES) can install itself as the victim's admin-of-
    // record. handleInvite must FLAG a re-invite naming a different admin so the
    // consent UI warns instead of the victim silently "rejoining" under an attacker.
    @Test
    fun reInviteFromDifferentContact_afterLeave_isFlaggedAsAdminMismatch() {
        if (!aeadUp()) return   // acceptInvite computes group tags (crypto)
        val vault = InMemoryVault()
        seedPairedContact(vault, "admin")
        seedPairedContact(vault, "attacker")
        val g = GroupManager(vault, noTransport)
        val gid = GroupManager.newGroupId()
        val admM = gMemberId(1); val me = gMemberId(2)

        // 1) The real admin invites us → accept → group + admin tombstone recorded.
        g.handleControl("admin", gid, GroupManager.KIND_INVITE, invite(admM, me, listOf(admM, me)))
        assertFalse(
            g.pendingInvites().single { it.groupId == gid }.adminMismatch,
            "the FIRST invite for a group is never flagged (no prior admin)",
        )
        assertTrue(g.acceptInvite(gid))
        assertEquals("admin", vault.getMeta("group_admin:$gid"), "acceptInvite records the first admin")

        // 2) We leave / are removed → deleteGroup. The tombstone must SURVIVE.
        vault.deleteGroup(gid)
        assertNull(vault.getGroup(gid))
        assertEquals("admin", vault.getMeta("group_admin:$gid"), "tombstone must survive deleteGroup")

        // 3) The attacker re-invites us for the SAME group, naming ITSELF admin.
        val attM = gMemberId(3)
        g.handleControl("attacker", gid, GroupManager.KIND_INVITE, invite(attM, me, listOf(attM, me)))
        val reinvite = g.pendingInvites().single { it.groupId == gid }
        assertTrue(reinvite.adminMismatch, "a re-invite from a DIFFERENT contact must be flagged (eclipse)")
        assertEquals("A-admin", reinvite.priorAdminAlias, "the original admin's alias is surfaced to consent")
    }

    // Companion: a legitimate re-add by the SAME admin must NOT be flagged.
    @Test
    fun reInviteFromSameAdmin_afterLeave_isNotFlagged() {
        if (!aeadUp()) return
        val vault = InMemoryVault()
        seedPairedContact(vault, "admin")
        val g = GroupManager(vault, noTransport)
        val gid = GroupManager.newGroupId()
        val admM = gMemberId(1); val me = gMemberId(2)
        g.handleControl("admin", gid, GroupManager.KIND_INVITE, invite(admM, me, listOf(admM, me)))
        assertTrue(g.acceptInvite(gid))
        vault.deleteGroup(gid)
        g.handleControl("admin", gid, GroupManager.KIND_INVITE, invite(admM, me, listOf(admM, me)))
        assertFalse(
            g.pendingInvites().single { it.groupId == gid }.adminMismatch,
            "a re-invite from the same admin is legitimate and must not be flagged",
        )
    }

    // A transient failure reading the admin-of-record tombstone must not hide the
    // eclipse warning: it fails toward "cannot verify" (flagged, no prior alias).
    @Test
    fun anUnreadableAdminTombstone_failsTowardTheWarning() {
        var failTombstone = false
        val vault = object : InMemoryVault() {
            override fun getMeta(key: String): String? {
                if (failTombstone && key.startsWith("group_admin:")) throw RuntimeException("transient")
                return super.getMeta(key)
            }
        }
        seedPairedContact(vault, "attacker")
        val g = GroupManager(vault, noTransport)
        val gid = GroupManager.newGroupId()
        vault.putMeta("group_admin:$gid", "admin")      // a prior admin this read cannot see
        failTombstone = true
        val attM = gMemberId(3); val me = gMemberId(2)
        g.handleControl("attacker", gid, GroupManager.KIND_INVITE, invite(attM, me, listOf(attM, me)))
        val parked = g.pendingInvites().single { it.groupId == gid }
        assertTrue(parked.adminMismatch, "an unverifiable admin-of-record must be flagged, never silently passed")
        assertNull(parked.priorAdminAlias, "no alias can be claimed for an admin that could not be read")
    }
}

// ===========================================================================
// The admin tombstone must exist for groups THIS DEVICE
// created (createGroup previously never wrote one — acceptInvite was the sole
// writer), and must track a LEGITIMATE transferAdmin (both the sending and the
// receiving side) so a re-invite by the properly-transferred-to admin is not
// flagged while a re-invite by anyone else still is.
// ===========================================================================

class GroupSelfCreatedAdminTombstoneTest {
    private val noTransport: () -> MessageManager? = { null }

    private fun invite(adm: String, you: String, mem: List<String>, ep: Long = 1, name: String = "crew"): String {
        val memJson = mem.joinToString(",") { jsonEscapeString(it) }
        return """{"n":${jsonEscapeString(name)},"ep":$ep,"adm":${jsonEscapeString(adm)},"you":${jsonEscapeString(you)},"mem":[$memJson]}"""
    }

    private fun roster(adm: String, entries: List<String>, ep: Long = 2, name: String = "crew"): String {
        val mem = entries.joinToString(",") { jsonEscapeString(it) }
        return """{"n":${jsonEscapeString(name)},"ep":$ep,"adm":${jsonEscapeString(adm)},"mem":[$mem]}"""
    }

    @Test
    fun createGroup_writesSelfAdminTombstone() {
        val vault = InMemoryVault()
        seedPairedContact(vault, "c-bob")
        val gm = GroupManager(vault, noTransport)
        val gid = gm.createGroup("crew", listOf("c-bob"))!!
        assertEquals(
            GroupManager.SELF_ADMIN_MARKER, vault.getMeta("group_admin:$gid"),
            "createGroup must record itself as admin-of-record so a later eclipse re-invite is detectable",
        )
    }

    @Test
    fun createGroup_thenLeave_reinviteByExMember_isFlaggedAsAdminMismatch() {
        // Victim creates the group (crypto-free — no acceptInvite involved).
        val vault = InMemoryVault()
        seedPairedContact(vault, "c-bob")
        val gm = GroupManager(vault, noTransport)
        val gid = gm.createGroup("crew", listOf("c-bob"))!!

        // Victim leaves / the group is torn down locally; the tombstone survives.
        vault.deleteGroup(gid)
        assertNull(vault.getGroup(gid))
        assertEquals(GroupManager.SELF_ADMIN_MARKER, vault.getMeta("group_admin:$gid"))

        // Ex-member "c-bob" re-invites the victim for the SAME groupId, naming itself admin.
        val admM = gMemberId(1); val me = gMemberId(2)
        gm.handleControl("c-bob", gid, GroupManager.KIND_INVITE, invite(admM, me, listOf(admM, me)))
        val reinvite = gm.pendingInvites().single { it.groupId == gid }
        assertTrue(reinvite.adminMismatch, "re-invite of a self-created group by a non-creator must be flagged")
        // "self" never resolves to a real contact's alias — the consent UI (both
        // platforms) already degrades to the generic ⚠️ text when this is null.
        assertNull(reinvite.priorAdminAlias)
    }

    @Test
    fun transferAdmin_movesTombstoneToNewAdmin() {
        val vault = InMemoryVault()
        seedPairedContact(vault, "c-bob")
        val gm = GroupManager(vault, noTransport)
        val gid = gm.createGroup("crew", listOf("c-bob"))!!
        markAllMembersJoined(vault, gid)   // transferAdmin refuses while a join is pending
        val bobMember = vault.getGroupMembers(gid).first { it.contactId == "c-bob" }.memberId

        assertTrue(gm.transferAdmin(gid, bobMember))
        assertEquals(
            "c-bob", vault.getMeta("group_admin:$gid"),
            "transferAdmin must move the tombstone to the new admin's contactId",
        )
    }

    @Test
    fun transferAdmin_thenReinviteByNewAdmin_isNotFlagged() {
        // Creator hands off admin to c-bob; the group is later torn down. A
        // re-invite BY c-bob (the legitimately transferred-to admin) must NOT
        // be flagged, even though the group was originally self-created.
        val vault = InMemoryVault()
        seedPairedContact(vault, "c-bob")
        val gm = GroupManager(vault, noTransport)
        val gid = gm.createGroup("crew", listOf("c-bob"))!!
        markAllMembersJoined(vault, gid)   // transferAdmin refuses while a join is pending
        val bobMember = vault.getGroupMembers(gid).first { it.contactId == "c-bob" }.memberId
        assertTrue(gm.transferAdmin(gid, bobMember))
        vault.deleteGroup(gid)

        val admM = gMemberId(5); val me = gMemberId(6)
        gm.handleControl("c-bob", gid, GroupManager.KIND_INVITE, invite(admM, me, listOf(admM, me)))
        assertFalse(
            gm.pendingInvites().single { it.groupId == gid }.adminMismatch,
            "a re-invite from the (legitimately transferred-to) new admin must not be flagged",
        )
    }

    @Test
    fun transferAdmin_thenReinviteByAThirdParty_isStillFlagged() {
        // After a legitimate transfer to c-bob, a re-invite from anyone ELSE
        // (not the tombstoned admin) must still be flagged.
        val vault = InMemoryVault()
        seedPairedContact(vault, "c-bob")
        seedPairedContact(vault, "c-mallory")
        val gm = GroupManager(vault, noTransport)
        val gid = gm.createGroup("crew", listOf("c-bob", "c-mallory"))!!
        markAllMembersJoined(vault, gid)   // transferAdmin refuses while a join is pending
        val bobMember = vault.getGroupMembers(gid).first { it.contactId == "c-bob" }.memberId
        assertTrue(gm.transferAdmin(gid, bobMember))
        vault.deleteGroup(gid)

        val admM = gMemberId(7); val me = gMemberId(8)
        gm.handleControl("c-mallory", gid, GroupManager.KIND_INVITE, invite(admM, me, listOf(admM, me)))
        assertTrue(
            gm.pendingInvites().single { it.groupId == gid }.adminMismatch,
            "a re-invite from anyone other than the tombstoned admin must be flagged",
        )
    }

    // Receive-side sibling of transferAdmin_movesTombstoneToNewAdmin: a MEMBER
    // (not the admin) who witnesses a legitimate admin-transfer roster (channel-
    // authenticated as coming from the CURRENT admin) must update its OWN
    // tombstone the same way — otherwise the member-side half of this fix would
    // be a no-op for everyone except the admin performing the handoff.
    @Test
    fun handleRoster_legitimateAdminTransfer_updatesOurOwnTombstone() {
        val vault = InMemoryVault()
        seedPairedContact(vault, "admin-contact")
        val gm = GroupManager(vault, noTransport)
        val gid = GroupManager.newGroupId()
        val adm = gMemberId(10); val me = gMemberId(20); val bob = gMemberId(30)
        // Member-side group state, as if we'd already accepted an invite from
        // admin-contact (built directly — crypto-free, mirrors
        // GroupAdminOpsTest.addMember_sizeCapExceeded_returnsFalse's style).
        vault.insertGroup(GroupRecord(gid, "crew", epoch = 1, adminMemberId = adm, myMemberId = me, createdAt = 0L))
        vault.insertGroupMember(GroupMemberRecord(gid, adm, "admin-contact", 0L))
        vault.insertGroupMember(GroupMemberRecord(gid, me, null, 0L))
        vault.insertGroupMember(GroupMemberRecord(gid, bob, null, 0L))
        vault.putMeta("group_admin:$gid", "admin-contact")

        val bobSecret = generateSecureRandom(32)
        seedPairedContact(vault, "bob-contact", bobSecret)
        val bound = GroupManager.boundTag(bobSecret, gid, bob)

        // The CURRENT admin (admin-contact) transfers authority to bob and
        // resolves bob's contact in the same roster.
        gm.handleControl(
            "admin-contact", gid, GroupManager.KIND_ROSTER,
            roster(bob, listOf("$adm:", "$me:", "$bob:$bound")),
        )

        assertEquals(bob, vault.getGroup(gid)!!.adminMemberId)
        assertEquals(
            "bob-contact", vault.getMeta("group_admin:$gid"),
            "a legitimate admin transfer observed via roster must move OUR tombstone to the new admin",
        )

        // Group later torn down (leave/removal); tombstone survives.
        vault.deleteGroup(gid)

        // The NEW admin (bob-contact) re-inviting us is legitimate — not flagged.
        val admM2 = gMemberId(40); val me2 = gMemberId(41)
        gm.handleControl("bob-contact", gid, GroupManager.KIND_INVITE, invite(admM2, me2, listOf(admM2, me2)))
        assertFalse(
            gm.pendingInvites().single { it.groupId == gid }.adminMismatch,
            "re-invite from the LEGITIMATELY transferred-to admin must not be flagged",
        )
    }

    // Companion: the OLD admin re-inviting after a legitimate transfer must now
    // BE flagged — authority genuinely moved away from them.
    @Test
    fun handleRoster_legitimateAdminTransfer_oldAdminReinviteIsNowFlagged() {
        val vault = InMemoryVault()
        seedPairedContact(vault, "admin-contact")
        val gm = GroupManager(vault, noTransport)
        val gid = GroupManager.newGroupId()
        val adm = gMemberId(10); val me = gMemberId(20); val bob = gMemberId(30)
        vault.insertGroup(GroupRecord(gid, "crew", epoch = 1, adminMemberId = adm, myMemberId = me, createdAt = 0L))
        vault.insertGroupMember(GroupMemberRecord(gid, adm, "admin-contact", 0L))
        vault.insertGroupMember(GroupMemberRecord(gid, me, null, 0L))
        vault.insertGroupMember(GroupMemberRecord(gid, bob, null, 0L))
        vault.putMeta("group_admin:$gid", "admin-contact")

        val bobSecret = generateSecureRandom(32)
        seedPairedContact(vault, "bob-contact", bobSecret)
        val bound = GroupManager.boundTag(bobSecret, gid, bob)
        gm.handleControl(
            "admin-contact", gid, GroupManager.KIND_ROSTER,
            roster(bob, listOf("$adm:", "$me:", "$bob:$bound")),
        )
        vault.deleteGroup(gid)

        val admM2 = gMemberId(50); val me2 = gMemberId(51)
        gm.handleControl("admin-contact", gid, GroupManager.KIND_INVITE, invite(admM2, me2, listOf(admM2, me2)))
        assertTrue(
            gm.pendingInvites().single { it.groupId == gid }.adminMismatch,
            "the OLD admin re-inviting after a legitimate transfer away from them must now be flagged",
        )
    }

    // Receive-side self-promotion: a roster can legitimately make US the new
    // admin. Our own tombstone must then use SELF_ADMIN_MARKER, matching
    // createGroup, so a later re-invite by anyone but us is flagged.
    @Test
    fun handleRoster_selfPromotedToAdmin_tombstoneUsesSelfMarker() {
        val vault = InMemoryVault()
        seedPairedContact(vault, "admin-contact")
        val gm = GroupManager(vault, noTransport)
        val gid = GroupManager.newGroupId()
        val adm = gMemberId(10); val me = gMemberId(20)
        vault.insertGroup(GroupRecord(gid, "crew", epoch = 1, adminMemberId = adm, myMemberId = me, createdAt = 0L))
        vault.insertGroupMember(GroupMemberRecord(gid, adm, "admin-contact", 0L))
        vault.insertGroupMember(GroupMemberRecord(gid, me, null, 0L))
        vault.putMeta("group_admin:$gid", "admin-contact")

        // The current admin transfers authority to US.
        gm.handleControl(
            "admin-contact", gid, GroupManager.KIND_ROSTER,
            roster(me, listOf("$adm:", "$me:")),
        )
        assertEquals(me, vault.getGroup(gid)!!.adminMemberId)
        assertEquals(GroupManager.SELF_ADMIN_MARKER, vault.getMeta("group_admin:$gid"))
    }
}

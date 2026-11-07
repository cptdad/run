package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * SR Finding 4 regression guard.
 *
 * The group-table mutations that used to be sequences of autocommit writes
 * (createGroup, addMember, acceptInvite, handleLeave, handleRoster's apply block)
 * are now each wrapped in a single [VaultDatabase.withTransaction], so a crash
 * mid-sequence on the real platform SQLite can't tear the write (orphan
 * group_members after a delete, or — most dangerously — an acceptInvite that
 * committed the group but not the first-admin tombstone, letting a later re-invite
 * under a different admin slip past the adminMismatch guard).
 *
 * The platform DB layer isn't reachable from commonTest and there's no crash
 * injection, so we can't assert on-disk atomicity directly. What we CAN pin — and
 * what a future refactor is most likely to regress — is the WIRING: every
 * group-table write each operation makes happens INSIDE a withTransaction scope,
 * i.e. as one atomic unit rather than N independent commits. [TxTrackingVault]
 * fails the test the moment a wrap is dropped.
 */
internal class TxTrackingVault(private val d: InMemoryVault) : VaultDatabase by d {
    private var txDepth = 0
    /** Group-table writes (contact_groups / group_members) observed at txDepth == 0. */
    val groupWritesOutsideTx = mutableListOf<String>()
    /** One entry per admin-tombstone (group_admin:*) putMeta: true iff it was in a tx. */
    val tombstoneWriteInTx = mutableListOf<Boolean>()
    /** One entry per roster-throttle (grp_roster_rl:*) deleteMeta: true iff in a tx —
     *  the residue purge must commit atomically with the member removal. */
    val rosterRlDeleteInTx = mutableListOf<Boolean>()

    fun reset() { groupWritesOutsideTx.clear(); tombstoneWriteInTx.clear(); rosterRlDeleteInTx.clear() }

    override fun withTransaction(block: () -> Unit) {
        txDepth++
        try { block() } finally { txDepth-- }
    }

    private fun note(op: String) { if (txDepth == 0) groupWritesOutsideTx.add(op) }

    override fun insertGroup(group: GroupRecord): Long { note("insertGroup"); return d.insertGroup(group) }
    override fun insertGroupMember(member: GroupMemberRecord): Long { note("insertGroupMember"); return d.insertGroupMember(member) }
    override fun deleteGroupMember(groupId: String, memberId: String) { note("deleteGroupMember"); d.deleteGroupMember(groupId, memberId) }
    // NOTE: deleteGroup is intentionally NOT tracked — its own two deletes are made
    // atomic INSIDE the platform DB impl (a single call from GroupManager's view), so
    // a GroupManager path calling it outside a GroupManager-level tx is correct.
    override fun putMeta(key: String, value: String) {
        if (key.startsWith("group_admin:")) tombstoneWriteInTx.add(txDepth > 0)
        d.putMeta(key, value)
    }
    override fun deleteMeta(key: String) {
        if (key.startsWith("grp_roster_rl:")) rosterRlDeleteInTx.add(txDepth > 0)
        d.deleteMeta(key)
    }
}

class GroupTransactionTest {
    private val noTransport: () -> MessageManager? = { null }
    private fun memberId(seed: Int) = bytesToHex(ByteArray(8) { (seed + it).toByte() })

    /** Seed a fully-paired contact (contact row + inbound/outbound inbox caps) so
     *  createGroup/addMember accept it — mirrors GroupManagerTest.seedContactWithCaps. */
    private fun seed(d: InMemoryVault, contactId: String, secret: ByteArray) {
        d.insertContact(ContactRecord(
            contactId = contactId, sharedSecret = secret,
            trustLevel = 1, alias = "A-$contactId", aliasLastRotated = 0L,
        ))
        val base = contactId.hashCode().toUInt().toString(16).padStart(8, '0')
        d.insertInboxId(InboxIdRecord(
            inboxId = ("in$base".padEnd(32, 'A')).take(32), contactId = contactId,
            createdAt = 1L, expiresAt = Long.MAX_VALUE, direction = "inbound", cap = "A".repeat(43),
        ))
        d.insertInboxId(InboxIdRecord(
            inboxId = ("ou$base".padEnd(32, 'B')).take(32), contactId = contactId,
            createdAt = 1L, expiresAt = Long.MAX_VALUE, direction = "outbound", cap = "B".repeat(43),
        ))
    }

    @Test
    fun createGroup_wrapsAllGroupWritesInATransaction() {
        val d = InMemoryVault()
        seed(d, "c-bob", generateSecureRandom(32))
        seed(d, "c-carol", generateSecureRandom(32))
        val vault = TxTrackingVault(d)
        val gm = GroupManager(vault, noTransport)
        vault.reset()
        val gid = gm.createGroup("crew", listOf("c-bob", "c-carol"))
        assertNotNull(gid)
        assertEquals(3, d.getGroupMembers(gid).size)   // self + 2 members
        assertTrue(vault.groupWritesOutsideTx.isEmpty(),
            "createGroup group writes must all be inside a transaction, saw: ${vault.groupWritesOutsideTx}")
    }

    @Test
    fun addMember_wrapsEpochBumpAndMemberInsertInATransaction() {
        val d = InMemoryVault()
        seed(d, "c-bob", generateSecureRandom(32))
        seed(d, "c-dave", generateSecureRandom(32))
        val vault = TxTrackingVault(d)
        val gm = GroupManager(vault, noTransport)
        val gid = gm.createGroup("crew", listOf("c-bob"))!!   // creator is admin
        vault.reset()
        assertTrue(gm.addMember(gid, "c-dave"))
        assertTrue(vault.groupWritesOutsideTx.isEmpty(),
            "addMember group writes must be inside a transaction, saw: ${vault.groupWritesOutsideTx}")
    }

    @Test
    fun acceptInvite_wrapsGroupMembersAndAdminTombstoneInATransaction() {
        val d = InMemoryVault()
        seed(d, "admin-contact", generateSecureRandom(32))
        val vault = TxTrackingVault(d)
        val gm = GroupManager(vault, noTransport)
        val gid = GroupManager.newGroupId()
        val adm = memberId(10); val me = memberId(20); val bob = memberId(30)
        val invite =
            """{"n":"crew","ep":1,"adm":${jsonEscapeString(adm)},"you":${jsonEscapeString(me)},"mem":[${jsonEscapeString(adm)},${jsonEscapeString(me)},${jsonEscapeString(bob)}]}"""
        gm.handleControl("admin-contact", gid, GroupManager.KIND_INVITE, invite)   // parks the invite
        vault.reset()
        assertTrue(gm.acceptInvite(gid))
        assertTrue(vault.groupWritesOutsideTx.isEmpty(),
            "acceptInvite group writes must be inside a transaction, saw: ${vault.groupWritesOutsideTx}")
        // The first-admin tombstone was written EXACTLY once, in the SAME transaction as
        // the group+members — this is the tear the admin-eclipse guard depends on.
        assertEquals(listOf(true), vault.tombstoneWriteInTx)
        assertNotNull(d.getMeta("group_admin:$gid"))
    }

    @Test
    fun handleLeave_adminPath_wrapsRemovalAndEpochBumpInATransaction() {
        val d = InMemoryVault()
        seed(d, "c-bob", generateSecureRandom(32))
        seed(d, "c-carol", generateSecureRandom(32))
        val vault = TxTrackingVault(d)
        val gm = GroupManager(vault, noTransport)
        val gid = gm.createGroup("crew", listOf("c-bob", "c-carol"))!!   // we are admin
        vault.reset()
        // A resolved member leaves; as admin we remove it AND bump the epoch — two writes.
        gm.handleControl("c-bob", gid, GroupManager.KIND_LEAVE, "{}")
        assertEquals(2, d.getGroupMembers(gid).size)   // self + carol
        assertTrue(vault.groupWritesOutsideTx.isEmpty(),
            "handleLeave (admin) writes must be inside a transaction, saw: ${vault.groupWritesOutsideTx}")
    }

    @Test
    fun handleRoster_applyBlock_wrapsWritesInATransaction() {
        val d = InMemoryVault()
        seed(d, "admin-contact", generateSecureRandom(32))
        val vault = TxTrackingVault(d)
        val gm = GroupManager(vault, noTransport)
        val gid = GroupManager.newGroupId()
        val adm = memberId(10); val me = memberId(20); val bob = memberId(30)
        val invite =
            """{"n":"crew","ep":1,"adm":${jsonEscapeString(adm)},"you":${jsonEscapeString(me)},"mem":[${jsonEscapeString(adm)},${jsonEscapeString(me)},${jsonEscapeString(bob)}]}"""
        gm.handleControl("admin-contact", gid, GroupManager.KIND_INVITE, invite)
        assertTrue(gm.acceptInvite(gid))
        vault.reset()
        // A newer roster (ep 2) that KEEPS us but DROPS bob → the apply block runs
        // insertGroup(epoch/admin) + deleteGroupMember(bob) + re-resolutions atomically.
        val roster =
            """{"n":"crew","ep":2,"adm":${jsonEscapeString(adm)},"mem":[${jsonEscapeString("$adm:")},${jsonEscapeString("$me:")}]}"""
        gm.handleControl("admin-contact", gid, GroupManager.KIND_ROSTER, roster)
        assertTrue(d.getGroupMembers(gid).none { it.memberId == bob })
        assertTrue(vault.groupWritesOutsideTx.isEmpty(),
            "handleRoster apply writes must be inside a transaction, saw: ${vault.groupWritesOutsideTx}")
    }

    @Test
    fun removeMember_wrapsDeleteEpochBumpAndRosterRlPurgeInATransaction() {
        // The member delete, the epoch bump AND the
        // grp_roster_rl residue purge are ONE atomic batch — a tear that removed
        // the member without the bump could never be re-driven, and a purge that
        // committed outside the tx could vanish while the removal rolled back.
        val d = InMemoryVault()
        seed(d, "c-bob", generateSecureRandom(32))
        seed(d, "c-carol", generateSecureRandom(32))
        val vault = TxTrackingVault(d)
        val gm = GroupManager(vault, noTransport)
        val gid = gm.createGroup("crew", listOf("c-bob", "c-carol"))!!
        val bobMember = d.getGroupMembers(gid).first { it.contactId == "c-bob" }.memberId
        // Ordinary-participation residue the purge must lift inside the tx.
        d.putMeta("grp_roster_rl:$gid:c-bob", "1000")
        vault.reset()

        assertTrue(gm.removeMember(gid, bobMember))
        assertTrue(vault.groupWritesOutsideTx.isEmpty(),
            "removeMember group writes must be inside a transaction, saw: ${vault.groupWritesOutsideTx}")
        assertEquals(listOf(true), vault.rosterRlDeleteInTx,
            "the M19 roster-rl purge must commit in the SAME transaction as the removal")
    }

    @Test
    fun transferAdmin_wrapsGroupRowAndTombstoneInATransaction() {
        // FINDING 3B-2: the admin handoff persists the new admin AND moves our
        // group_admin tombstone as one unit — a tear between them would leave a
        // demoted admin whose eclipse detection still names the OLD admin.
        val d = InMemoryVault()
        seed(d, "c-bob", generateSecureRandom(32))
        val vault = TxTrackingVault(d)
        val gm = GroupManager(vault, noTransport)
        val gid = gm.createGroup("crew", listOf("c-bob"))!!
        markAllMembersJoined(d, gid)   // transferAdmin refuses while a join is pending
        val bobMember = d.getGroupMembers(gid).first { it.contactId == "c-bob" }.memberId
        vault.reset()

        assertTrue(gm.transferAdmin(gid, bobMember))
        assertTrue(vault.groupWritesOutsideTx.isEmpty(),
            "transferAdmin group writes must be inside a transaction, saw: ${vault.groupWritesOutsideTx}")
        assertEquals(listOf(true), vault.tombstoneWriteInTx,
            "the tombstone handoff must commit in the SAME transaction as the admin change")
        assertEquals("c-bob", d.getMeta("group_admin:$gid"))
    }

    @Test
    fun handleRoster_witnessedAdminTransfer_tombstoneUpdateIsInsideTheTransaction() {
        // Receive-side sibling of the transferAdmin case: a member witnessing a
        // legitimate transfer roster mirrors it into its OWN tombstone — that
        // write must sit inside the same atomic apply as the roster itself.
        val d = InMemoryVault()
        seed(d, "admin-contact", generateSecureRandom(32))
        seed(d, "bob-contact", generateSecureRandom(32))
        val vault = TxTrackingVault(d)
        val gm = GroupManager(vault, noTransport)
        val gid = GroupManager.newGroupId()
        val adm = memberId(10); val me = memberId(20); val bob = memberId(30)
        // Member-side state built directly (crypto-free), bob already resolved.
        d.insertGroup(GroupRecord(gid, "crew", epoch = 1, adminMemberId = adm, myMemberId = me, createdAt = 0L))
        d.insertGroupMember(GroupMemberRecord(gid, adm, "admin-contact", 0L))
        d.insertGroupMember(GroupMemberRecord(gid, me, null, 0L))
        d.insertGroupMember(GroupMemberRecord(gid, bob, "bob-contact", 0L))
        d.putMeta("group_admin:$gid", "admin-contact")
        vault.reset()

        // The CURRENT admin transfers authority to bob.
        val roster =
            """{"n":"crew","ep":2,"adm":${jsonEscapeString(bob)},"mem":[${jsonEscapeString("$adm:")},${jsonEscapeString("$me:")},${jsonEscapeString("$bob:")}]}"""
        gm.handleControl("admin-contact", gid, GroupManager.KIND_ROSTER, roster)

        assertEquals(bob, d.getGroup(gid)!!.adminMemberId)
        assertEquals("bob-contact", d.getMeta("group_admin:$gid"))
        assertTrue(vault.groupWritesOutsideTx.isEmpty(),
            "roster apply writes must be inside a transaction, saw: ${vault.groupWritesOutsideTx}")
        assertEquals(listOf(true), vault.tombstoneWriteInTx,
            "the witnessed-transfer tombstone update must commit inside the roster's transaction")
    }
}

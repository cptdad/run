package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// VaultSnapshotIo tests (docs/device-move.md, "Move to new device", area 2).
// ---------------------------------------------------------------------------

/**
 * Test double for [VaultSnapshotIo]: wraps the shared [InMemoryVault] fixture
 * (support/InMemoryVault.kt) via delegation — the same pattern [RollbackVault]
 * (PairingVaultTest.kt) already uses — and adds two things that fixture alone
 * doesn't provide:
 *
 *  - [getAllInboxIds] (the interface's default throws; every production actual
 *    overrides it, and this fixture needs a real one to exercise export).
 *  - An operation log ([ops]) so import ORDERING (IMPORTED written strictly
 *    last) is directly observable, not just inferred from end state.
 *  - Real snapshot/restore transaction semantics (the base [InMemoryVault.withTransaction]
 *    just runs the block), so a throwing upsert mid-import can be proven to
 *    leave the vault byte-for-byte unchanged — mirrors what a real SQLCipher
 *    transaction (Android) / putStringsSync journal (iOS) delivers.
 */
private class MoveTestVault(val inner: InMemoryVault = InMemoryVault()) : VaultDatabase by inner {
    val ops = mutableListOf<String>()

    /** 1-based call count at which [insertContact] throws; 0 disables. */
    var failInsertContactOnCall: Int = 0
    private var contactCalls = 0

    override fun getAllInboxIds(): List<InboxIdRecord> = inner.inboxes.toList()

    override fun insertContact(contact: ContactRecord): Long {
        contactCalls++
        if (contactCalls == failInsertContactOnCall) {
            throw RuntimeException("injected contact write failure")
        }
        ops.add("contact:${contact.contactId}")
        return inner.insertContact(contact)
    }

    override fun insertInboxId(record: InboxIdRecord): Long {
        ops.add("inbox:${record.inboxId}")
        return inner.insertInboxId(record)
    }

    override fun insertGroup(group: GroupRecord): Long {
        ops.add("group:${group.groupId}")
        return inner.insertGroup(group)
    }

    override fun insertGroupMember(member: GroupMemberRecord): Long {
        ops.add("member:${member.groupId}/${member.memberId}")
        return inner.insertGroupMember(member)
    }

    override fun putMeta(key: String, value: String) {
        ops.add("meta:$key")
        inner.putMeta(key, value)
    }

    override fun withTransaction(block: () -> Unit) {
        val c = inner.contacts.toMap()
        val i = inner.inboxes.toList()
        val g = inner.groups.toMap()
        val gm = inner.groupMembers.toList()
        val m = inner.meta.toMap()
        val opsSnapshot = ops.toList()
        try {
            block()
        } catch (e: Throwable) {
            inner.contacts.clear(); inner.contacts.putAll(c)
            inner.inboxes.clear(); inner.inboxes.addAll(i)
            inner.groups.clear(); inner.groups.putAll(g)
            inner.groupMembers.clear(); inner.groupMembers.addAll(gm)
            inner.meta.clear(); inner.meta.putAll(m)
            ops.clear(); ops.addAll(opsSnapshot)
            throw e
        }
    }
}

private fun contact(
    id: String,
    outbound: Long = 5,
    outboundCtl: Long = 7,
    outboundGrp: Long = 11,
) = ContactRecord(
    contactId = id,
    sharedSecret = ByteArray(32) { it.toByte() },
    trustLevel = 1,
    alias = "alias-$id",
    aliasLastRotated = 1000L,
    outboundCounter = outbound,
    inboundCounter = 42,
    inboundEpoch = "epoch-$id",
    outboundCtlCounter = outboundCtl,
    inboundCtlCounter = 99,
    outboundGrpCounter = outboundGrp,
    inboundGrpCounter = 77,
)

private fun inbox(id: String, contactId: String, direction: String) = InboxIdRecord(
    inboxId = id,
    contactId = contactId,
    createdAt = 1000L,
    expiresAt = 2000L,
    direction = direction,
    cap = "cap-$id",
)

class VaultSnapshotIoTest {

    // -------------------------------------------------------------------
    // export
    // -------------------------------------------------------------------

    @Test
    fun export_collectsEveryContact_allInboxRowsOfEveryDirection_groupsMembersAndOnlyAllowedMeta() {
        val vault = MoveTestVault()
        vault.insertContact(contact("c1"))
        vault.insertContact(contact("c2"))

        // Two directions for c1, PLUS a superseded row (same contact+direction,
        // older createdAt) that getInboxIdForContact would hide but export must not.
        vault.insertInboxId(inbox("in-c1-a", "c1", "inbound").copy(createdAt = 500L))
        vault.insertInboxId(inbox("in-c1-b", "c1", "inbound").copy(createdAt = 1500L))
        vault.insertInboxId(inbox("out-c1", "c1", "outbound"))
        vault.insertInboxId(inbox("in-c2", "c2", "inbound"))

        vault.insertGroup(GroupRecord("g1", "Group One", epoch = 1, adminMemberId = "adm", myMemberId = "adm", createdAt = 1L))
        vault.insertGroupMember(GroupMemberRecord("g1", "adm", contactId = null, addedAt = 1L))
        vault.insertGroupMember(GroupMemberRecord("g1", "mem2", contactId = "c2", addedAt = 2L))

        // Allowed meta.
        vault.putMeta("dr/c1/text", "ratchet-state")
        vault.putMeta("grp_roster_rl:g1:c2", "123")
        vault.putMeta("ref_p:abc", "pending-referral")
        vault.putMeta("ssn:conv1:c1:999", "notice")
        // Denied meta — must never appear in the snapshot.
        vault.putMeta("vlt_c", "wrapped-db-key")
        vault.putMeta("pin_attempts", "3")
        vault.putMeta("run.crypto.provider.key", "keyset")
        vault.putMeta("mig_frozen", "1")
        vault.putMeta("update_nudge_v1", "1.0.0|100")

        val before = vault.inner.contacts.toMap()

        val snapshot = VaultSnapshotIo.export(vault)

        assertEquals(setOf("c1", "c2"), snapshot.contacts.map { it.contactId }.toSet())
        assertEquals(4, snapshot.inboxes.size, "all four inbox rows, including the superseded one")
        assertEquals(
            setOf("in-c1-a", "in-c1-b", "out-c1", "in-c2"),
            snapshot.inboxes.map { it.inboxId }.toSet(),
        )
        assertEquals(listOf("g1"), snapshot.groups.map { it.groupId })
        assertEquals(setOf("adm", "mem2"), snapshot.members.map { it.memberId }.toSet())

        assertEquals(
            mapOf(
                "dr/c1/text" to "ratchet-state",
                "grp_roster_rl:g1:c2" to "123",
                "ref_p:abc" to "pending-referral",
                "ssn:conv1:c1:999" to "notice",
            ),
            snapshot.meta,
        )

        // Export must not mutate the vault.
        assertEquals(before, vault.inner.contacts)
    }

    @Test
    fun theGroupInboxPairAndItsCounters_surviveExport_encode_decode_import() {
        // v10 end-to-end: the THIRD pairwise pair (group text) has to reach the new
        // phone the way the v7 control pair does — the inbox rows through
        // getAllInboxIds (direction-agnostic), the counters through the bundle
        // codec. A gap anywhere in this chain is a group channel that silently
        // stops working after a move, with no error anywhere.
        val old = MoveTestVault()
        old.insertContact(contact("c1", outbound = 5, outboundCtl = 7, outboundGrp = 13))
        old.insertInboxId(inbox("in-grp", "c1", MessageManager.DIR_INBOUND_GRP))
        old.insertInboxId(inbox("out-grp", "c1", MessageManager.DIR_OUTBOUND_GRP))
        old.insertInboxId(inbox("in-text", "c1", "inbound"))

        val bundle = MigrationBundle(
            schema = MigrationBundleCodec.CURRENT_SCHEMA,
            from = MigrationBundle.FROM_ANDROID,
            createdMs = 1L,
            bundleId = migTestBundleId(3),
            snapshot = VaultSnapshotIo.export(old),
        )
        val wire = MigrationBundleCodec.decode(MigrationBundleCodec.encode(bundle))

        val fresh = MoveTestVault()
        VaultSnapshotIo.import(fresh, wire.snapshot, MoveConstants.COUNTER_JUMP, bundle.bundleId)

        val grpRows = fresh.getAllInboxIds().filter {
            it.direction == MessageManager.DIR_INBOUND_GRP || it.direction == MessageManager.DIR_OUTBOUND_GRP
        }
        assertEquals(2, grpRows.size, "both group inbox rows must travel")
        assertEquals(
            setOf("cap-in-grp", "cap-out-grp"),
            grpRows.map { it.cap }.toSet(),
            "with their capabilities — a row without its cap is an unusable inbox",
        )
        // Both group rows are OWNED-read-direction-aware: the inbound one is in
        // OWNED_READ_DIRECTIONS, so MoveManager's D4 pass rotates its read cap.
        assertTrue(MessageManager.DIR_INBOUND_GRP in MessageManager.OWNED_READ_DIRECTIONS)

        val moved = fresh.getContact("c1")!!
        assertEquals(13L + MoveConstants.COUNTER_JUMP, moved.outboundGrpCounter)
        assertEquals(77L, moved.inboundGrpCounter)
    }

    @Test
    fun deleteContact_removesTheGroupInboxRowsToo() {
        // The purge is direction-AGNOSTIC on both actuals (`DELETE FROM inbox_ids
        // WHERE contact_id = ?`), which is why the third pair costs nothing here —
        // pinned so a future "delete only these directions" refactor is caught.
        val v = InMemoryVault()
        v.insertContact(contact("c1"))
        v.insertContact(contact("c2"))
        for (d in listOf(
            "inbound", "outbound",
            MessageManager.DIR_INBOUND_CTL, MessageManager.DIR_OUTBOUND_CTL,
            MessageManager.DIR_INBOUND_GRP, MessageManager.DIR_OUTBOUND_GRP,
        )) {
            v.insertInboxId(inbox("c1-$d", "c1", d))
            v.insertInboxId(inbox("c2-$d", "c2", d))
        }
        assertEquals(12, v.inboxes.size)

        v.deleteContact("c1")

        assertTrue(v.inboxes.none { it.contactId == "c1" }, "every direction of the deleted contact must go")
        assertEquals(6, v.inboxes.size, "the other contact's rows — group pair included — must survive")
    }

    // -------------------------------------------------------------------
    // import
    // -------------------------------------------------------------------

    @Test
    fun import_appliesCounterJumpOnce_upsertsEverything_writesImportedLast() {
        val snapshot = VaultSnapshot(
            contacts = listOf(contact("c1", outbound = 5, outboundCtl = 7)),
            inboxes = listOf(inbox("in1", "c1", "inbound"), inbox("out1", "c1", "outbound")),
            groups = listOf(GroupRecord("g1", "Group One", epoch = 1, adminMemberId = "adm", myMemberId = "adm", createdAt = 1L)),
            members = listOf(GroupMemberRecord("g1", "adm", contactId = null, addedAt = 1L)),
            meta = mapOf("dr/c1/text" to "ratchet-state", "grp_roster_rl:g1:c2" to "123"),
        )

        val vault = MoveTestVault()
        VaultSnapshotIo.import(vault, snapshot, counterJump = 10_000L, bundleId = "bundle-1")

        val imported = vault.getContact("c1")!!
        assertEquals(10_005L, imported.outboundCounter, "outboundCounter + jump")
        assertEquals(10_007L, imported.outboundCtlCounter, "outboundCtlCounter + jump")
        // v10: the GROUP channel has its own counter space, and the peer enforces
        // strict-monotonic per channel — reusing a group counter the old phone
        // already spent is silent message LOSS, so it must jump too.
        assertEquals(10_011L, imported.outboundGrpCounter, "outboundGrpCounter + jump")
        // Inbound state travels UNCHANGED.
        assertEquals(42L, imported.inboundCounter)
        assertEquals("epoch-c1", imported.inboundEpoch)
        assertEquals(99L, imported.inboundCtlCounter)
        assertEquals(
            77L, imported.inboundGrpCounter,
            "the inbound group baseline is what we LEARNED from the peer — jumping it " +
                "would blind the new phone to every group message below the gap",
        )

        assertEquals(2, vault.inner.inboxes.size)
        assertEquals(listOf("g1"), vault.getAllGroups().map { it.groupId })
        assertEquals(listOf("adm"), vault.getGroupMembers("g1").map { it.memberId })
        assertEquals("ratchet-state", vault.getMeta("dr/c1/text"))
        assertEquals("123", vault.getMeta("grp_roster_rl:g1:c2"))
        assertEquals("bundle-1", vault.getMeta(MoveMetaKeys.IMPORTED))

        // Ordering: IMPORTED is the LAST op in the whole batch.
        assertEquals("meta:${MoveMetaKeys.IMPORTED}", vault.ops.last())
        val importedIndex = vault.ops.indexOf("meta:${MoveMetaKeys.IMPORTED}")
        assertTrue(importedIndex == vault.ops.size - 1)
        assertTrue(vault.ops.contains("contact:c1"))
        assertTrue(vault.ops.indexOf("contact:c1") < importedIndex)
        assertTrue(vault.ops.indexOf("inbox:in1") < importedIndex)
        assertTrue(vault.ops.indexOf("group:g1") < importedIndex)
        assertTrue(vault.ops.indexOf("member:g1/adm") < importedIndex)
        assertTrue(vault.ops.indexOf("meta:dr/c1/text") < importedIndex)
    }

    @Test
    fun import_secondRunOfSameBundle_isNoOp_notDoubleCounterJump() {
        val snapshot = VaultSnapshot(
            contacts = listOf(contact("c1", outbound = 5, outboundCtl = 7)),
            inboxes = emptyList(),
            groups = emptyList(),
            members = emptyList(),
            meta = emptyMap(),
        )
        val vault = MoveTestVault()
        VaultSnapshotIo.import(vault, snapshot, counterJump = 10_000L, bundleId = "bundle-1")
        val afterFirst = vault.getContact("c1")!!
        assertEquals(10_005L, afterFirst.outboundCounter)
        val opsAfterFirst = vault.ops.toList()

        // Re-run with the SAME (untouched) source snapshot and bundleId.
        VaultSnapshotIo.import(vault, snapshot, counterJump = 10_000L, bundleId = "bundle-1")

        val afterSecond = vault.getContact("c1")!!
        assertEquals(10_005L, afterSecond.outboundCounter, "must not double-jump")
        assertEquals(10_007L, afterSecond.outboundCtlCounter, "must not double-jump")
        assertEquals(10_011L, afterSecond.outboundGrpCounter, "must not double-jump")
        assertEquals(opsAfterFirst, vault.ops, "second call must not perform any write")
    }

    @Test
    fun import_deniedMetaKey_neverWritten_allowedKeyIs() {
        val snapshot = VaultSnapshot(
            contacts = emptyList(),
            inboxes = emptyList(),
            groups = emptyList(),
            members = emptyList(),
            meta = mapOf(
                "vlt_c" to "should-never-land",
                "dr/c1/text" to "should-land",
            ),
        )
        val vault = MoveTestVault()
        VaultSnapshotIo.import(vault, snapshot, counterJump = 0L, bundleId = "bundle-1")

        assertNull(vault.getMeta("vlt_c"))
        assertEquals("should-land", vault.getMeta("dr/c1/text"))
    }

    @Test
    fun import_throwingUpsertMidImport_leavesVaultCompletelyUnchanged() {
        val preexisting = contact("pre-existing", outbound = 1, outboundCtl = 1)
        val vault = MoveTestVault()
        // Seed directly (bypassing the counted insertContact override) so
        // failInsertContactOnCall below counts only the import's own calls.
        vault.inner.contacts[preexisting.contactId] = preexisting
        val opsBefore = vault.ops.toList()

        val snapshot = VaultSnapshot(
            contacts = listOf(contact("c1"), contact("c2")),
            inboxes = listOf(inbox("in1", "c1", "inbound")),
            groups = listOf(GroupRecord("g1", "Group One", epoch = 1, adminMemberId = "adm", myMemberId = "adm", createdAt = 1L)),
            members = emptyList(),
            meta = mapOf("dr/c1/text" to "state"),
        )
        // c2 is the 2nd insertContact call within THIS import (c1 is the 1st) —
        // throw there so contact c1, the inbox, the group and the meta row (all
        // ordered AFTER contacts) never get a chance to write either.
        vault.failInsertContactOnCall = 2

        assertFailsWith<RuntimeException> {
            VaultSnapshotIo.import(vault, snapshot, counterJump = 10_000L, bundleId = "bundle-1")
        }

        assertEquals(mapOf("pre-existing" to preexisting), vault.inner.contacts)
        assertTrue(vault.inner.inboxes.isEmpty())
        assertTrue(vault.inner.groups.isEmpty())
        assertTrue(vault.inner.meta.isEmpty())
        assertNull(vault.getMeta(MoveMetaKeys.IMPORTED))
        assertEquals(opsBefore, vault.ops, "the op log itself must roll back too")
    }
}

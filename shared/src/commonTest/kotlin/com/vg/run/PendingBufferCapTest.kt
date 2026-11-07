package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// The screen-buffer RAM caps
// (groupScreenItems/directScreenItems — the cross-conversation parking buffers
// pendingGroup/pendingDirect these caps were written for are gone since the
// 2026-10-06 NO-PARK decision; the bounds still hold for what remains).
//
// Both maps are fed via GroupManager.ingest (internal, same module — no crypto
// needed: these tests inject already-"decrypted" ReceivedMessage content
// directly). Group texts take the control sweep's `background = true` path
// (into their own group's screen buffer); 1:1 texts take a 1:1 screen's
// `bufferAll = true` hand-off.
// ---------------------------------------------------------------------------

private fun capTestMemberId(seed: Int) = bytesToHex(ByteArray(8) { (seed + it).toByte() })

private fun capTestGm(vault: InMemoryVault) = GroupManager(vault) { null }

/** One group with a single resolved member (us, admin, + one real contact). */
private fun seedGroupWithMember(vault: InMemoryVault, groupId: String, memberContactId: String) {
    val me = capTestMemberId(1)
    vault.insertContact(ContactRecord(memberContactId, ByteArray(32), 1, memberContactId, 0L))
    vault.insertGroup(GroupRecord(groupId, "g", 1, adminMemberId = me, myMemberId = me, createdAt = 0L))
    vault.insertGroupMember(GroupMemberRecord(groupId, me, contactId = null, addedAt = 0L))
    vault.insertGroupMember(GroupMemberRecord(groupId, capTestMemberId(2), contactId = memberContactId, addedAt = 0L))
}

class PendingGroupBufferCapTest {

    @Test
    fun perKeyCap_evictsOldest_keepsNewest() {
        val vault = InMemoryVault()
        seedGroupWithMember(vault, "g1", "c-bob")
        val gm = capTestGm(vault)

        val sent = GroupManager.MAX_PENDING_CONTENT_PER_KEY + 5
        for (i in 1..sent) {
            gm.ingest(
                "c-bob",
                listOf(ReceivedMessage(text = "msg-$i", timestamp = 0L, counter = i.toLong(), groupId = "g1")),
                wantGroupId = null,
                bufferAll = true,
                background = true,
            )
        }

        val drained = gm.takeGroupScreenItems("g1")
        assertEquals(
            GroupManager.MAX_PENDING_CONTENT_PER_KEY, drained.size,
            "the per-key buffer must stay pinned at the cap, not grow unbounded",
        )
        assertEquals("msg-6", drained.first().text, "the oldest 5 arrivals must have been evicted")
        assertEquals("msg-$sent", drained.last().text, "the newest arrival must always survive")
    }

    @Test
    fun globalCap_boundsTotalAcrossGroups_andNeverDropsTheNewestArrival() {
        val vault = InMemoryVault()
        val groupIds = (1..5).map { "g$it" }
        val contactIds = (1..5).map { "c-member$it" }
        groupIds.zip(contactIds).forEach { (gid, cid) -> seedGroupWithMember(vault, gid, cid) }
        val gm = capTestGm(vault)

        // 5 groups x 250 messages = 1250 sent, each group individually well under
        // the per-key cap (256) — so only the GLOBAL cap can be doing any evicting.
        val perGroup = 250
        for ((gid, cid) in groupIds.zip(contactIds)) {
            for (i in 1..perGroup) {
                gm.ingest(
                    cid,
                    listOf(ReceivedMessage(text = "$gid-$i", timestamp = 0L, counter = i.toLong(), groupId = gid)),
                    wantGroupId = null,
                    bufferAll = true,
                background = true,
                )
            }
        }

        val perGroupCounts = groupIds.associateWith { gm.takeGroupScreenItems(it).size }
        val total = perGroupCounts.values.sum()
        assertTrue(
            total <= GroupManager.MAX_PENDING_CONTENT_TOTAL,
            "global cap must bound the TOTAL across every group ($total > ${GroupManager.MAX_PENDING_CONTENT_TOTAL})",
        )
        assertTrue(
            total < groupIds.size * perGroup,
            "eviction must actually have happened (${groupIds.size * perGroup} sent, cap is ${GroupManager.MAX_PENDING_CONTENT_TOTAL})",
        )
        perGroupCounts.values.forEach { count ->
            assertTrue(count <= GroupManager.MAX_PENDING_CONTENT_PER_KEY, "no single group may exceed the per-key cap either")
        }
    }

    @Test
    fun globalCap_neverDropsTheJustArrivedMessage() {
        val vault = InMemoryVault()
        val groupIds = (1..5).map { "g$it" }
        val contactIds = (1..5).map { "c-member$it" }
        groupIds.zip(contactIds).forEach { (gid, cid) -> seedGroupWithMember(vault, gid, cid) }
        val gm = capTestGm(vault)
        for ((gid, cid) in groupIds.zip(contactIds)) {
            for (i in 1..250) {
                gm.ingest(
                    cid,
                    listOf(ReceivedMessage(text = "$gid-$i", timestamp = 0L, counter = i.toLong(), groupId = gid)),
                    wantGroupId = null,
                    bufferAll = true,
                background = true,
                )
            }
        }

        // The eviction target is whichever key currently holds the most — it must
        // never be the item that was JUST inserted (only OLDER parked entries are
        // ever dropped). Assert on the last group filled, whose last message is the
        // most recent arrival across the whole buffer.
        val lastGroup = groupIds.last()
        val drained = gm.takeGroupScreenItems(lastGroup)
        assertTrue(
            drained.any { it.text == "$lastGroup-250" },
            "the most recently arrived message must never be the one evicted",
        )
    }
}

class PendingDirectBufferCapTest {

    @Test
    fun perKeyCap_evictsOldest_keepsNewest() {
        val vault = InMemoryVault()
        vault.insertContact(ContactRecord("c-bob", ByteArray(32), 1, "Bob", 0L))
        val gm = capTestGm(vault)

        val sent = GroupManager.MAX_PENDING_CONTENT_PER_KEY + 5
        for (i in 1..sent) {
            gm.ingest(
                "c-bob",
                listOf(ReceivedMessage(text = "msg-$i", timestamp = 0L, counter = i.toLong())),
                wantGroupId = null,
                bufferAll = true,
            )
        }

        val drained = gm.takeDirectScreenItems("c-bob")
        assertEquals(GroupManager.MAX_PENDING_CONTENT_PER_KEY, drained.size)
        assertEquals("msg-6", drained.first().text, "the oldest 5 arrivals must have been evicted")
        assertEquals("msg-$sent", drained.last().text, "the newest arrival must always survive")
    }

    @Test
    fun globalCap_boundsTotalAcrossContacts() {
        val vault = InMemoryVault()
        val contactIds = (1..5).map { "c-member$it" }
        contactIds.forEach { vault.insertContact(ContactRecord(it, ByteArray(32), 1, it, 0L)) }
        val gm = capTestGm(vault)

        val perContact = 250
        for (cid in contactIds) {
            for (i in 1..perContact) {
                gm.ingest(
                    cid,
                    listOf(ReceivedMessage(text = "$cid-$i", timestamp = 0L, counter = i.toLong())),
                    wantGroupId = null,
                    bufferAll = true,
                )
            }
        }

        val perContactCounts = contactIds.associateWith { gm.takeDirectScreenItems(it).size }
        val total = perContactCounts.values.sum()
        assertTrue(
            total <= GroupManager.MAX_PENDING_CONTENT_TOTAL,
            "global cap must bound the TOTAL across every contact ($total > ${GroupManager.MAX_PENDING_CONTENT_TOTAL})",
        )
        assertTrue(
            total < contactIds.size * perContact,
            "eviction must actually have happened (${contactIds.size * perContact} sent, cap is ${GroupManager.MAX_PENDING_CONTENT_TOTAL})",
        )
        perContactCounts.values.forEach { count ->
            assertTrue(count <= GroupManager.MAX_PENDING_CONTENT_PER_KEY, "no single contact may exceed the per-key cap either")
        }
    }
}

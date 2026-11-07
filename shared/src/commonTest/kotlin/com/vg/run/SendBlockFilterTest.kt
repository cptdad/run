package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// Block is honoured on every group RECEIVE
// path (pollGroup, pollAllControls, ingest) but was missing on both SEND
// fan-outs — a blocked co-member kept silently receiving the victim's group
// texts and screenshot notices. These tests exercise the real send paths
// (real AES-GCM, like GroupFanOutTest) and assert on the actual HTTP call
// count/targets, not just the filtered member list.
// ---------------------------------------------------------------------------

private fun blockTestMemberId(seed: Int) = bytesToHex(ByteArray(8) { (seed + it).toByte() })

private fun seedResolvedMemberWithCaps(vault: InMemoryVault, contactId: String) {
    vault.insertContact(
        ContactRecord(
            contactId = contactId, sharedSecret = generateSecureRandom(32),
            trustLevel = 1, alias = "A-$contactId", aliasLastRotated = 0L,
        )
    )
    val base = contactId.hashCode().toUInt().toString(16).padStart(8, '0')
    vault.insertInboxId(InboxIdRecord(
        inboxId = ("in$base".padEnd(32, 'A')).take(32), contactId = contactId,
        createdAt = 1L, expiresAt = Long.MAX_VALUE, direction = "inbound",
        cap = "A".repeat(43),
    ))
    vault.insertInboxId(InboxIdRecord(
        inboxId = ("ou$base".padEnd(32, 'B')).take(32), contactId = contactId,
        createdAt = 1L, expiresAt = Long.MAX_VALUE, direction = "outbound",
        cap = "B".repeat(43),
    ))
}

/** A group of 2 resolved members (bob, carol) admin'd by us. */
private fun seedGroupWithTwoMembers(vault: InMemoryVault, groupId: String): String {
    val me = blockTestMemberId(1)
    seedResolvedMemberWithCaps(vault, "c-bob")
    seedResolvedMemberWithCaps(vault, "c-carol")
    vault.insertGroup(GroupRecord(groupId, "crew", 1, adminMemberId = me, myMemberId = me, createdAt = 0L))
    vault.insertGroupMember(GroupMemberRecord(groupId, me, contactId = null, addedAt = 0L))
    vault.insertGroupMember(GroupMemberRecord(groupId, blockTestMemberId(2), contactId = "c-bob", addedAt = 0L))
    vault.insertGroupMember(GroupMemberRecord(groupId, blockTestMemberId(3), contactId = "c-carol", addedAt = 0L))
    return me
}

class SendGroupMessageBlockFilterTest {

    @Test
    fun blockedMember_isExcludedFromTargets_unblockedMemberStillReceives() {
        if (!aeadUp()) return
        val vault = InMemoryVault()
        val gid = "grp-block-1"
        seedGroupWithTwoMembers(vault, gid)
        val http = RecordingRelayHttp()
        // Baseline send (both members): 1 text + 1 activity notice EACH = 4 calls.
        repeat(4) { http.script(HttpResult(202, "", true)) }
        val mgr = MessageManager(vault, "http://relay.test", http as RelayHttp)
        val gm = GroupManager(vault) { mgr }

        val baseline = gm.sendGroupMessage(gid, "hello everyone")
        assertEquals(2, baseline.total, "with nobody blocked both members are targets")
        assertEquals(2, baseline.delivered)
        assertEquals(4, http.calls.size, "2 members x (text + activity notice)")

        // Now block carol and send again — she must receive NOTHING.
        gm.blockedContacts = { setOf("c-carol") }
        http.script(HttpResult(202, "", true), HttpResult(202, "", true))  // bob's text + notice only
        val afterBlock = http.calls.size

        val result = gm.sendGroupMessage(gid, "hello again")

        assertEquals(1, result.total, "a blocked member must not even be counted as a target")
        assertEquals(1, result.delivered)
        assertEquals(2, http.calls.size - afterBlock, "only bob's text + activity notice — nothing to the blocked carol")
    }

    @Test
    fun allMembersBlocked_sendsNothing() {
        if (!aeadUp()) return
        val vault = InMemoryVault()
        val gid = "grp-block-2"
        seedGroupWithTwoMembers(vault, gid)
        val http = RecordingRelayHttp()
        val mgr = MessageManager(vault, "http://relay.test", http as RelayHttp)
        val gm = GroupManager(vault) { mgr }
        gm.blockedContacts = { setOf("c-bob", "c-carol") }

        val result = gm.sendGroupMessage(gid, "hello")

        assertEquals(0, result.total)
        assertEquals(0, result.delivered)
        assertEquals(0, http.calls.size, "no relay traffic at all when every member is blocked")
    }
}

class SendGroupScreenshotNoticeBlockFilterTest {

    @Test
    fun blockedMember_isExcludedFromTargets_unblockedMemberStillReceives() {
        if (!aeadUp()) return
        val vault = InMemoryVault()
        val gid = "grp-block-ss-1"
        seedGroupWithTwoMembers(vault, gid)
        val http = RecordingRelayHttp()
        // Baseline (both members): one notice each.
        repeat(2) { http.script(HttpResult(202, "", true)) }
        val mgr = MessageManager(vault, "http://relay.test", http as RelayHttp)
        val gm = GroupManager(vault) { mgr }

        gm.sendGroupScreenshotNotice(gid)
        assertEquals(2, http.calls.size, "with nobody blocked both members get the screenshot notice")

        // Block carol and notify again — only bob should get a copy.
        gm.blockedContacts = { setOf("c-carol") }
        http.script(HttpResult(202, "", true))
        val afterBlock = http.calls.size

        gm.sendGroupScreenshotNotice(gid)

        assertEquals(1, http.calls.size - afterBlock, "a blocked co-member must not learn about the screenshot")
    }

    @Test
    fun allMembersBlocked_sendsNoNotices() {
        if (!aeadUp()) return
        val vault = InMemoryVault()
        val gid = "grp-block-ss-2"
        seedGroupWithTwoMembers(vault, gid)
        val http = RecordingRelayHttp()
        val mgr = MessageManager(vault, "http://relay.test", http as RelayHttp)
        val gm = GroupManager(vault) { mgr }
        gm.blockedContacts = { setOf("c-bob", "c-carol") }

        gm.sendGroupScreenshotNotice(gid)

        assertTrue(http.calls.isEmpty(), "no relay traffic at all when every member is blocked")
    }
}

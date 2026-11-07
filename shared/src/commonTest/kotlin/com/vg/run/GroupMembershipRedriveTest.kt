package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// Group member removal / departure was
// fire-and-forget — the roster fan-out discarded per-target results, carried
// no relay TTL (24 h default) and woke nobody, and nothing ever re-sent it. A
// member who missed the roster (offline for a day, or a hostile relay refusing
// ONE append) kept the removed member in its fan-out indefinitely.
//
// These tests pin the fix: membership-change kinds carry a 7-day TTL, an
// undelivered roster/leave becomes a durable `_meta` obligation, and the
// control sweep redrives it — bounded by attempts and an absolute ceiling —
// until it lands, the contact is gone, or the group/admin role is gone.
// ---------------------------------------------------------------------------

private val I1_CAP = "A".repeat(43)

/** Relay double that REFUSES appends to chosen inbox ids with a real HTTP error
 *  (terminal for postWithTransientRetry — no retry), accepts everything else,
 *  and records every POST url. */
private class RefusingRelay : FakeRelayHttp(onGet = { RELAY_EMPTY_DRAIN }, onPut = { HttpResult(200, "{}", true) }) {
    val refuse = mutableSetOf<String>()
    val posts: List<String> get() = requestsOf("POST").map { it.url }
    init { onPost = { if (relayInboxIdOf(it.url) in refuse) HttpResult(503, "", false) else HttpResult(200, "{}", true) } }
}

private class I1Harness {
    val vault = InMemoryVault()
    val relay = RefusingRelay()
    val mgr = MessageManager(vault, "http://relay.test", relay)
    var transportUp = true
    val gm = GroupManager(vault) { if (transportUp) mgr else null }
    var now = 1_700_000_000_000L

    init {
        gm.clockMs = { now }
        for (c in listOf("c-bob", "c-carol", "c-dave")) seed(c)
    }

    private fun seed(contactId: String) {
        vault.insertContact(ContactRecord(contactId, generateSecureRandom(32), 1, "A-$contactId", 0L))
        val tag = contactId.removePrefix("c-").padEnd(6, 'x')
        vault.insertInboxId(InboxIdRecord(("in$tag").padEnd(32, 'A'), contactId, 1L, Long.MAX_VALUE, "inbound", I1_CAP))
        vault.insertInboxId(InboxIdRecord(("ou$tag").padEnd(32, 'B'), contactId, 1L, Long.MAX_VALUE, "outbound", I1_CAP))
        vault.insertInboxId(InboxIdRecord(("ic$tag").padEnd(32, 'C'), contactId, 1L, Long.MAX_VALUE, MessageManager.DIR_INBOUND_CTL, I1_CAP))
        vault.insertInboxId(InboxIdRecord(("oc$tag").padEnd(32, 'D'), contactId, 1L, Long.MAX_VALUE, MessageManager.DIR_OUTBOUND_CTL, I1_CAP))
    }

    /** The inbox id a control send to [contactId] lands on (its outbound-ctl row). */
    fun ctlInboxOf(contactId: String) = vault.getInboxIdForContact(contactId, MessageManager.DIR_OUTBOUND_CTL)!!.inboxId
    fun pendKey(groupId: String, contactId: String) = GroupMetaKeys.CTL_PEND_PREFIX + groupId + ":" + contactId
    fun pending(groupId: String, contactId: String) = vault.getMeta(pendKey(groupId, contactId))
    fun memberIdOf(groupId: String, contactId: String) = vault.getGroupMembers(groupId).first { it.contactId == contactId }.memberId
    fun postsTo(inboxId: String) = relay.posts.count { it.contains("/inbox/$inboxId") }
    /** The obligation's state field — `a` = delivered-but-unacknowledged. */
    fun awaitingAck(groupId: String, contactId: String): Boolean =
        pending(groupId, contactId)?.split('|')?.getOrNull(5) == "a"
    fun undelivered(groupId: String, contactId: String): Boolean =
        pending(groupId, contactId)?.split('|')?.getOrNull(5) == "u"
    /** The membership hash THIS device would stamp on its own traffic right now. */
    fun myHash(groupId: String): String {
        val g = vault.getGroup(groupId)!!
        return GroupManager.membershipHash(groupId, g.epoch, vault.getGroupMembers(groupId).map { it.memberId })
    }
    /** Simulate [contactId] speaking, carrying [hash] as their membership view. */
    fun hears(contactId: String, groupId: String, hash: String) {
        gm.ingest(
            contactId,
            listOf(ReceivedMessage("hi", 0L, counter = 1, groupId = groupId, membershipHash = hash)),
            wantGroupId = groupId,
        )
    }
    fun group(): String = gm.createGroup("crew", listOf("c-bob", "c-carol", "c-dave"))!!
}

class GroupMembershipRedriveTest {

    @Test
    fun membershipControl_carriesSevenDayRelayTtl() {
        if (!aeadUp()) return
        val h = I1Harness()
        val gid = h.group()   // createGroup fans out INVITEs
        assertTrue(h.relay.posts.isNotEmpty())
        assertTrue(h.relay.posts.all { it.contains("?ttl=${GroupManager.MEMBERSHIP_CONTROL_TTL_SECONDS}") },
            "invites must carry the 7-day TTL: ${h.relay.posts}")
        h.relay.clearRequests()
        assertTrue(h.gm.removeMember(gid, h.memberIdOf(gid, "c-dave")))
        assertTrue(h.relay.posts.isNotEmpty())
        assertTrue(h.relay.posts.all { it.contains("?ttl=604800") }, "rosters must carry the 7-day TTL")
    }

    @Test
    fun removeMember_relayRefusesOneMember_recordsObligation_redriveClearsIt() {
        if (!aeadUp()) return
        val h = I1Harness()
        val gid = h.group()
        h.relay.refuse += h.ctlInboxOf("c-carol")   // hostile relay: refuse exactly one append
        h.relay.clearRequests()

        assertTrue(h.gm.removeMember(gid, h.memberIdOf(gid, "c-dave")), "local removal still succeeds")
        assertTrue(h.undelivered(gid, "c-carol"), "the refused member becomes a durable UNDELIVERED obligation")
        // a 2xx is proof the RELAY took the blob, never proof the member got
        // it — a delivered target is held AWAITING-ACK instead of being cleared.
        assertTrue(h.awaitingAck(gid, "c-bob"), "a delivered member is held awaiting its acknowledgement")
        assertTrue(h.awaitingAck(gid, "c-dave"), "so is the removed member's own final copy")

        // Relay recovers; the next control sweep redrives the roster to carol.
        h.relay.refuse.clear()
        h.relay.clearRequests()
        h.gm.redriveUndeliveredMembershipControl()
        assertEquals(1, h.postsTo(h.ctlInboxOf("c-carol")), "redrive re-sends the roster to the refused member")
        assertTrue(h.awaitingAck(gid, "c-carol"), "accepted on the redrive ⇒ now awaiting the member's ack")
        assertTrue(h.relay.posts.all { it.contains("?ttl=604800") })

        // Carol speaks carrying OUR hash: end-to-end proof. Obligation gone.
        h.hears("c-carol", gid, h.myHash(gid))
        assertNull(h.pending(gid, "c-carol"), "a matching membership hash is the acknowledgement")

        // The slow ack cadence: nothing is re-sent on the very next sweep.
        h.relay.clearRequests()
        h.gm.redriveUndeliveredMembershipControl()
        assertTrue(h.relay.posts.isEmpty(), "an awaiting-ack obligation must not re-send every sweep")
    }

    @Test
    fun removeMember_whileTorIsDown_recordsEveryTarget_includingTheRemovedMember() {
        if (!aeadUp()) return
        val h = I1Harness()
        val gid = h.group()
        h.transportUp = false
        assertTrue(h.gm.removeMember(gid, h.memberIdOf(gid, "c-dave")))
        for (c in listOf("c-bob", "c-carol", "c-dave")) assertTrue(h.undelivered(gid, c), "$c must be an obligation")

        h.transportUp = true
        h.relay.clearRequests()
        h.gm.redriveUndeliveredMembershipControl()
        for (c in listOf("c-bob", "c-carol", "c-dave")) {
            assertEquals(1, h.postsTo(h.ctlInboxOf(c)), "$c gets the roster on the redrive")
            assertTrue(h.awaitingAck(gid, c), "$c is now awaiting acknowledgement, not cleared by the 2xx")
        }
    }

    @Test
    fun leaveGroup_relayRefuses_recordsLeaveObligation_redriveResendsLeave() {
        if (!aeadUp()) return
        val h = I1Harness()
        val gid = h.group()
        h.relay.refuse += h.ctlInboxOf("c-bob")
        h.gm.leaveGroup(gid, null)
        assertNull(h.vault.getGroup(gid), "group is gone locally")
        val ob = h.pending(gid, "c-bob")
        assertNotNull(ob, "the refused LEAVE is a durable obligation")
        assertTrue(ob.startsWith(GroupManager.KIND_LEAVE + "|"), "obligation records the kind: $ob")
        // A delivered LEAVE leaves NO record: nothing can acknowledge a group that
        // is gone locally, so an awaiting-ack row would only be roster residue.
        assertNull(h.pending(gid, "c-carol"), "a delivered LEAVE copy is not held awaiting-ack")
        assertNull(h.pending(gid, "c-dave"), "a delivered LEAVE copy is not held awaiting-ack")

        h.relay.refuse.clear()
        h.relay.clearRequests()
        h.gm.redriveUndeliveredMembershipControl()
        assertEquals(1, h.postsTo(h.ctlInboxOf("c-bob")), "leave re-sent even though the group is gone locally")
        assertNull(h.pending(gid, "c-bob"), "a LEAVE the relay took on a redrive is closed, not held awaiting-ack")
    }

    @Test
    fun leaveGroup_fullyDelivered_leavesNoMembershipResidueForTheLeftGroup() {
        if (!aeadUp()) return
        val h = I1Harness()
        val gid = h.group()
        h.gm.leaveGroup(gid, null)
        assertNull(h.vault.getGroup(gid))
        val residue = h.vault.meta.keys.filter { it.startsWith(GroupMetaKeys.CTL_PEND_PREFIX + gid + ":") }
        assertTrue(residue.isEmpty(), "no obligation may outlive a delivered leave: $residue")
        h.relay.clearRequests()
        h.gm.redriveUndeliveredMembershipControl()
        assertTrue(h.relay.posts.isEmpty(), "nothing to redrive: ${h.relay.posts}")
    }

    @Test
    fun staleInviteRateWindows_arePrunedOnTheSweep_liveOnesAreUntouched() {
        val vault = InMemoryVault()
        val gm = GroupManager(vault) { null }
        val now = 1_700_000_000_000L
        gm.clockMs = { now }
        val stale = "grp_inv_rl:c-old"
        val live = "grp_inv_rl:c-live"
        val liveValue = "${now - GroupManager.INVITE_RATE_WINDOW_MS - 5},${now - 1000}"
        vault.putMeta(stale, "${now - GroupManager.INVITE_RATE_WINDOW_MS - 1},${now - 2 * GroupManager.INVITE_RATE_WINDOW_MS}")
        vault.putMeta(live, liveValue)
        vault.putMeta("grp_other:x", "1")

        gm.pruneStaleInviteRateWindows()

        assertNull(vault.getMeta(stale), "a row whose stamps all aged out is deleted")
        assertEquals(liveValue, vault.getMeta(live), "a live row keeps its exact bytes")
        assertEquals("1", vault.getMeta("grp_other:x"), "only the rate-window prefix is touched")
    }

    @Test
    fun obligation_isBounded_byAttempts_andAbsoluteCeiling() {
        if (!aeadUp()) return
        val h = I1Harness()
        val gid = h.group()
        h.relay.refuse += h.ctlInboxOf("c-carol")
        assertTrue(h.gm.removeMember(gid, h.memberIdOf(gid, "c-dave")))
        assertNotNull(h.pending(gid, "c-carol"))

        // Keeps failing: attempts climb, then the obligation is dropped.
        repeat(12) { h.gm.redriveUndeliveredMembershipControl() }
        assertNull(h.pending(gid, "c-carol"), "exhausted after the attempt cap")

        // Absolute ceiling: an obligation older than 7 days is dropped without a send.
        h.relay.refuse.clear()
        h.relay.refuse += h.ctlInboxOf("c-bob")
        assertTrue(h.gm.addMember(gid, "c-dave"))          // new roster; bob refused
        assertNotNull(h.pending(gid, "c-bob"))
        h.relay.refuse.clear()
        h.now += 8L * 24 * 60 * 60 * 1000
        h.relay.clearRequests()
        h.gm.redriveUndeliveredMembershipControl()
        assertTrue(h.relay.posts.isEmpty(), "no send for an expired obligation")
        assertNull(h.pending(gid, "c-bob"))
    }

    @Test
    fun obligation_isDropped_whenTheContactIsGone_orTheGroupIsGone() {
        if (!aeadUp()) return
        val h = I1Harness()
        val gid = h.group()
        h.relay.refuse += h.ctlInboxOf("c-carol")
        h.relay.refuse += h.ctlInboxOf("c-bob")
        assertTrue(h.gm.removeMember(gid, h.memberIdOf(gid, "c-dave")))
        assertNotNull(h.pending(gid, "c-carol")); assertNotNull(h.pending(gid, "c-bob"))

        // Contact deleted → its obligation is purged by the shared residue classifier.
        assertTrue(isGroupMetaResidueForContact(h.pendKey(gid, "c-carol"), "c-carol"))
        h.vault.deleteContact("c-carol")
        assertNull(h.pending(gid, "c-carol"))

        // Group residue classifier covers the roster obligation too.
        assertTrue(isGroupMetaResidueForGroup(h.pendKey(gid, "c-bob"), gid))
        assertFalse(isGroupMetaResidueForGroup(h.pendKey(gid, "c-bob"), "other-group"))
        assertFalse(isGroupMetaResidueForContact(h.pendKey(gid, "c-bob"), "c-carol"))
    }

    @Test
    fun aDeliveredRoster_supersedesAnOlderMiss() {
        if (!aeadUp()) return
        val h = I1Harness()
        val gid = h.group()
        h.relay.refuse += h.ctlInboxOf("c-bob")
        assertTrue(h.gm.removeMember(gid, h.memberIdOf(gid, "c-dave")))
        assertTrue(h.undelivered(gid, "c-bob"))
        // A later membership change whose roster DOES reach bob supersedes the miss —
        // the record moves to AWAITING-ACK (the 2xx alone no longer clears it)
        // and keeps its ORIGINAL first-seen stamp so churn cannot re-arm the ceiling.
        val firstSeen = h.pending(gid, "c-bob")!!.split('|')[4]
        h.relay.refuse.clear()
        assertTrue(h.gm.addMember(gid, "c-dave"))
        assertTrue(h.awaitingAck(gid, "c-bob"), "the newer roster is full state and supersedes the miss")
        assertEquals(firstSeen, h.pending(gid, "c-bob")!!.split('|')[4],
            "the 7-day ceiling runs from the FIRST miss, not the latest roster")
        // And bob's own traffic, once it carries our hash, finally clears it.
        h.hears("c-bob", gid, h.myHash(gid))
        assertNull(h.pending(gid, "c-bob"))
    }
}

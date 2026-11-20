package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// createGroup / addMember ignored the targets fanOutControl reported as NOT
// reached, so a member whose invitation did not land (a Tor drop at that moment, a
// relay refusal, no transport at all) never got it, never joined, and nothing
// showed it. An invite that did not leave is now an UNDELIVERED obligation in the
// existing membership redrive (`grp_ctl_pend:`), re-derived from current state on
// each re-send, bounded like a roster, and ended early once the member's inbox is
// proven gone on the relay (PeerInboxGone.kt). A transport failure keeps retrying.
// ---------------------------------------------------------------------------

private val GI_CAP = "A".repeat(43)
private const val GI_HOUR = 60L * 60 * 1000

/** Per-inbox answers: a transport failure for [dropped], 404 for [gone], 202 otherwise. */
private class InviteRelay : FakeRelayHttp(onGet = { RELAY_EMPTY_DRAIN }, onPut = { HttpResult(200, "{}", true) }) {
    val dropped = mutableSetOf<String>()
    val gone = mutableSetOf<String>()
    init {
        onPost = {
            when (relayInboxIdOf(it.url)) {
                in dropped -> RELAY_DEAD
                in gone -> HttpResult(404, """{"error":"request rejected"}""", false)
                else -> RELAY_OK_202
            }
        }
    }
    fun postsTo(inboxId: String) = requestsOf("POST").filter { relayInboxIdOf(it.url) == inboxId }
}

private class InviteHarness {
    val vault = InMemoryVault()
    val relay = InviteRelay()
    val mgr = MessageManager(vault, "http://relay.test", relay)
    val gm = GroupManager(vault) { mgr }
    var now = 1_700_000_000_000L

    init {
        gm.clockMs = { now }
        mgr.peerInboxEvidenceClockMs = { now }
        mgr.sendRetrySleep = { }
        for (c in listOf("c-bob", "c-carol", "c-dave")) seed(c)
    }

    private fun seed(contactId: String) {
        vault.insertContact(ContactRecord(contactId, generateSecureRandom(32), 1, "A-$contactId", 0L))
        val tag = contactId.removePrefix("c-").padEnd(6, 'x')
        vault.insertInboxId(InboxIdRecord(("in$tag").padEnd(32, 'A'), contactId, 1L, Long.MAX_VALUE, "inbound", GI_CAP))
        vault.insertInboxId(InboxIdRecord(("ou$tag").padEnd(32, 'B'), contactId, 1L, Long.MAX_VALUE, "outbound", GI_CAP))
        vault.insertInboxId(InboxIdRecord(("ic$tag").padEnd(32, 'C'), contactId, 1L, Long.MAX_VALUE, MessageManager.DIR_INBOUND_CTL, GI_CAP))
        vault.insertInboxId(InboxIdRecord(("oc$tag").padEnd(32, 'D'), contactId, 1L, Long.MAX_VALUE, MessageManager.DIR_OUTBOUND_CTL, GI_CAP))
    }

    fun ctl(contactId: String) = vault.getInboxIdForContact(contactId, MessageManager.DIR_OUTBOUND_CTL)!!.inboxId
    fun pending(groupId: String, contactId: String) = vault.getMeta(GroupMetaKeys.CTL_PEND_PREFIX + groupId + ":" + contactId)
    fun memberIdOf(groupId: String, contactId: String) = vault.getGroupMembers(groupId).first { it.contactId == contactId }.memberId
    /** The control sweep's own drain: the relay proves it holds our state. */
    fun sweepDrain() { mgr.pollControlMessages("c-bob") }
    /** The envelope JSON of the last control append to [contactId] (legacy contacts). */
    fun lastEnvelopeTo(contactId: String): String =
        openLegacyEnvelope(vault.getContact(contactId)!!.sharedSecret, relay.postsTo(ctl(contactId)).last().body)
    /** Recorded POSTs to [contactId]'s control inbox that carry a KIND_INVITE. */
    fun invitePostsTo(contactId: String): Int {
        val secret = vault.getContact(contactId)!!.sharedSecret
        return relay.postsTo(ctl(contactId)).count { openLegacyEnvelope(secret, it.body).contains(""""k":"invite"""") }
    }
}

class GroupInviteRedriveTest {

    /** THE defect: an invite createGroup could not deliver was lost. Fails pre-fix
     *  (no obligation, no re-send). */
    @Test
    fun createGroup_anUndeliveredInvite_isReSent_withThatMembersSlot() {
        if (!aeadUp()) return
        val h = InviteHarness()
        h.relay.dropped += h.ctl("c-carol")
        val gid = assertNotNull(h.gm.createGroup("crew", listOf("c-bob", "c-carol", "c-dave")))
        val ob = assertNotNull(h.pending(gid, "c-carol"), "the undelivered invite is a durable obligation")
        assertTrue(ob.startsWith(GroupManager.KIND_INVITE + "|"), ob)
        assertNull(h.pending(gid, "c-bob"), "a delivered invite records nothing")

        h.relay.dropped.clear()
        h.relay.clearRequests()
        h.gm.redriveUndeliveredMembershipControl()
        assertEquals(1, h.relay.postsTo(h.ctl("c-carol")).size, "the sweep re-sends the invite")
        assertTrue(h.relay.postsTo(h.ctl("c-carol")).single().url.contains("?ttl=${GroupManager.MEMBERSHIP_CONTROL_TTL_SECONDS}"))
        if (legacyEnvelopeCryptoUp()) {
            val env = h.lastEnvelopeTo("c-carol")
            assertTrue(env.contains(""""k":"invite""""), env)
            assertTrue(env.contains(h.memberIdOf(gid, "c-carol")), "the invite names carol's own slot")
        }
        assertNull(h.pending(gid, "c-carol"), "an invite the relay took closes its obligation")
        h.relay.clearRequests()
        h.gm.redriveUndeliveredMembershipControl()
        assertTrue(h.relay.requestsOf("POST").isEmpty(), "nothing more to send")
    }

    /** addMember fans the invite, THEN the roster to everyone (newcomer included): the
     *  roster's obligation must not replace the invite's, or the redrive would send
     *  the newcomer a roster for a group it was never invited to. Fails pre-fix. */
    @Test
    fun addMember_anUndeliveredInvite_isNotReplacedByTheRoster_andItsJoinClearsIt() {
        if (!aeadUp()) return
        val h = InviteHarness()
        val gid = assertNotNull(h.gm.createGroup("crew", listOf("c-bob", "c-carol")))
        h.relay.dropped += h.ctl("c-dave")
        assertTrue(h.gm.addMember(gid, "c-dave"))
        val ob = assertNotNull(h.pending(gid, "c-dave"))
        assertTrue(ob.startsWith(GroupManager.KIND_INVITE + "|"), "still the INVITE obligation: $ob")

        h.relay.dropped.clear()
        h.relay.clearRequests()
        h.gm.redriveUndeliveredMembershipControl()
        val toDave = h.relay.postsTo(h.ctl("c-dave"))
        assertEquals(1, toDave.size)
        if (legacyEnvelopeCryptoUp()) {
            val env = h.lastEnvelopeTo("c-dave")
            assertTrue(env.contains(""""k":"invite""""), env)
            assertTrue(env.contains(h.memberIdOf(gid, "c-dave")))
            assertTrue(env.contains("\\\"ep\\\":${h.vault.getGroup(gid)!!.epoch}"), "current epoch: $env")
        }
        assertNull(h.pending(gid, "c-dave"))

        // Dave joins: the join clears any invite obligation, and the roster that
        // answers it gets its normal (awaiting-ack) obligation.
        h.relay.dropped += h.ctl("c-dave")
        h.vault.putMeta(GroupMetaKeys.CTL_PEND_PREFIX + gid + ":c-dave",
            "${GroupManager.KIND_INVITE}|2|abcd|0|${h.now}|u|${h.now}|")
        h.relay.dropped.clear()
        val tags = (0 until 4).joinToString(",") {
            jsonEscapeString(bytesToHex(generateSecureRandom(8)) + ":" + bytesToHex(generateSecureRandom(8)))
        }
        h.gm.handleControl("c-dave", gid, GroupManager.KIND_JOIN,
            """{"you":${jsonEscapeString(h.memberIdOf(gid, "c-dave"))},"tags":[$tags]}""")
        val after = assertNotNull(h.pending(gid, "c-dave"), "the join's roster is recorded")
        assertTrue(after.startsWith(GroupManager.KIND_ROSTER + "|"), "the invite obligation is gone: $after")
    }

    /** An invite to an inbox the relay keeps answering 404 for stops after the
     *  evidence bound (three counted 404s an hour apart), without spending the
     *  12-attempt budget on it. */
    @Test
    fun anInviteToAGoneInbox_stops_afterTheEvidenceBound() {
        if (!aeadUp()) return
        val h = InviteHarness()
        h.relay.gone += h.ctl("c-dave")
        h.sweepDrain()
        val gid = assertNotNull(h.gm.createGroup("crew", listOf("c-bob", "c-carol", "c-dave")))
        assertNotNull(h.pending(gid, "c-dave"))
        repeat(4) {
            h.sweepDrain()
            h.gm.redriveUndeliveredMembershipControl()
            h.gm.redriveUndeliveredMembershipControl()   // inside the hour: held, nothing sent
            h.now += GI_HOUR + 1
        }
        assertNull(h.pending(gid, "c-dave"), "the obligation ends on the GONE verdict")
        assertEquals(3, h.relay.postsTo(h.ctl("c-dave")).size, "createGroup + two hourly probes, then nothing")
        assertNotNull(h.vault.getContact("c-dave"), "nothing irreversible: the contact stays")
        assertTrue(h.vault.getGroupMembers(gid).any { it.contactId == "c-dave" }, "and so does the member row")
    }

    /** A transport failure is not evidence: the invite keeps being re-sent (at its
     *  growing spacing), still bounded by the 12-attempt budget. */
    @Test
    fun anInviteDroppedByTheTransport_keepsRetrying_withinTheAttemptBudget() {
        if (!aeadUp()) return
        val h = InviteHarness()
        h.relay.dropped += h.ctl("c-dave")
        val gid = assertNotNull(h.gm.createGroup("crew", listOf("c-bob", "c-dave")))
        h.relay.clearRequests()
        repeat(3) { h.sweepDrain(); h.gm.redriveUndeliveredMembershipControl(); h.now += GI_HOUR }
        // Each sweep's re-send is itself up to SEND_TRANSIENT_ATTEMPTS POSTs of the same bytes.
        assertTrue(h.relay.postsTo(h.ctl("c-dave")).size >= 3, "every due sweep retries a transport failure")
        assertNotNull(h.pending(gid, "c-dave"))
        assertNull(h.vault.getMeta(PeerInboxGonePolicy.keyFor("c-dave")), "no 404 evidence from a transport failure")
        repeat(20) { h.gm.redriveUndeliveredMembershipControl(); h.now += 7 * GI_HOUR }
        assertNull(h.pending(gid, "c-dave"), "still bounded by the 12-attempt budget")
    }

    /** The redrive rides the control sweep, which runs every ~2.5 s in the fast
     *  cadence. A transport outage longer than 12 such sweeps used to spend the whole
     *  12-attempt budget in ~30 s and drop the invite — exactly the network drop at
     *  invitation time the redrive is for. Fails before the spacing. */
    @Test
    fun anOutageLongerThanTwelveFastSweeps_doesNotSpendTheInvite_andItIsDeliveredAfter() {
        if (!aeadUp()) return
        val h = InviteHarness()
        h.relay.dropped += h.ctl("c-dave")
        val gid = assertNotNull(h.gm.createGroup("crew", listOf("c-bob", "c-dave")))
        val firstSeen = h.now
        repeat(40) {   // 40 fast sweeps ≈ 100 s of outage
            h.gm.redriveUndeliveredMembershipControl()
            h.now += 2_500
        }
        val ob = assertNotNull(h.pending(gid, "c-dave"), "the invite outlives a 100 s outage")
        assertTrue(ob.split('|')[3].toInt() < 12, "and has budget left: $ob")
        assertTrue(h.now - firstSeen < GI_HOUR)

        h.relay.dropped.clear()   // the transport returns
        h.relay.clearRequests()
        var sweeps = 0
        while (h.pending(gid, "c-dave") != null && sweeps < 2_000) {   // keep sweeping at the fast cadence
            h.gm.redriveUndeliveredMembershipControl()
            h.now += 2_500
            sweeps++
        }
        assertNull(h.pending(gid, "c-dave"), "the invitation is delivered once the transport is back")
        assertEquals(1, h.relay.postsTo(h.ctl("c-dave")).size, "exactly one delivered re-send")
        if (legacyEnvelopeCryptoUp()) assertTrue(h.lastEnvelopeTo("c-dave").contains(""""k":"invite""""))
    }

    /** No invite is re-sent once it is moot: the member was removed, or the group is gone. */
    @Test
    fun anInviteObligation_isDropped_whenTheMemberOrGroupIsGone() {
        if (!aeadUp()) return
        val h = InviteHarness()
        h.relay.dropped += h.ctl("c-dave")
        val gid = assertNotNull(h.gm.createGroup("crew", listOf("c-bob", "c-dave")))
        // The invite record is classified by the existing residue predicates.
        assertTrue(isGroupMetaResidueForGroup(GroupMetaKeys.CTL_PEND_PREFIX + gid + ":c-dave", gid))
        assertTrue(isGroupMetaResidueForContact(GroupMetaKeys.CTL_PEND_PREFIX + gid + ":c-dave", "c-dave"))
        assertTrue(h.gm.removeMember(gid, h.memberIdOf(gid, "c-dave")))
        assertTrue(h.pending(gid, "c-dave")?.startsWith(GroupManager.KIND_INVITE + "|") != true,
            "removeMember deletes the pending invite at once")
        h.relay.dropped.clear()
        h.relay.clearRequests()
        h.gm.redriveUndeliveredMembershipControl()
        assertEquals(0, h.invitePostsTo("c-dave"), "no invite for a removed member")
    }

    /** remove → re-add with a DELIVERED invite must not leave the old entry re-sending
     *  an invitation for the new slot. Fails before removeMember cleared the entry. */
    @Test
    fun removeThenReAdd_withADeliveredInvite_leavesNoInviteEntry_andSendsNoFurtherInvite() {
        if (!aeadUp() || !legacyEnvelopeCryptoUp()) return
        val h = InviteHarness()
        h.relay.dropped += h.ctl("c-dave")
        val gid = assertNotNull(h.gm.createGroup("crew", listOf("c-bob", "c-dave")))
        assertTrue(h.pending(gid, "c-dave")!!.startsWith(GroupManager.KIND_INVITE + "|"))
        h.relay.dropped.clear()
        assertTrue(h.gm.removeMember(gid, h.memberIdOf(gid, "c-dave")))
        h.relay.clearRequests()
        assertTrue(h.gm.addMember(gid, "c-dave"))
        assertEquals(1, h.invitePostsTo("c-dave"), "the re-add's invite is delivered")
        assertTrue(h.pending(gid, "c-dave")?.startsWith(GroupManager.KIND_INVITE + "|") != true,
            "no invite entry is pending: ${h.pending(gid, "c-dave")}")
        repeat(5) { h.gm.redriveUndeliveredMembershipControl(); h.now += 5 * 60 * 1000L }
        assertEquals(1, h.invitePostsTo("c-dave"), "and no further invitation is sent")
    }
}

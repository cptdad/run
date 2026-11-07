package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// Ack-gated redrive obligations, uniform ttl, stale-LEAVE handling.
//
// The redrive treated an HTTP 2xx on the APPEND as proof of DELIVERY.
// A relay that answers 201 and DISCARDS therefore suppressed a roster/leave
// permanently, recorded no obligation and was never retried: the removed member
// kept reading group plaintext from every member whose own copy was dropped the
// same way, while `removeMember` reported success throughout. That is strictly
// cheaper and quieter than the 4xx/5xx veto the member-removal redrive closed.
//
// The fix is application-layer acknowledgement, in two independent mechanisms:
//   1. an obligation is written on SUCCESS too, in AWAITING-ACK, and cleared only
//      when that member's own traffic carries OUR membership hash;
//   2. a message whose membershipHash is NOT ours is positive evidence of
//      divergence, and the admin re-sends the current roster to that member
//      alone — bounded per member and per sweep.
//
// The `?ttl` is metadata on the request line, so a per-kind value labelled
// roster/leave appends for a relay that decrypts nothing (the selector that made
// the ack-gating surgical). Every control append now carries the SAME ttl.
//
// a stale KIND_LEAVE obligation must not survive a re-join of the same
// groupId, and a leave that names a memberId the slot no longer holds is stale.
// ---------------------------------------------------------------------------

private val CV_CAP = "A".repeat(43)

/** Accepts every append with a 2xx — and delivers nothing. The adversary. */
private class AckingRelay : FakeRelayHttp(
    onPost = { HttpResult(201, "{}", true) },
    onGet = { RELAY_EMPTY_DRAIN },
    onPut = { HttpResult(200, "{}", true) },
    onDelete = { HttpResult(200, "{}", true) },
) {
    val posts: List<String> get() = requestsOf("POST").map { it.url }
}

private class CvHarness(members: List<String> = listOf("c-bob", "c-carol")) {
    val vault = InMemoryVault()
    val relay = AckingRelay()
    val mgr = MessageManager(vault, "http://relay.test", relay)
    val gm = GroupManager(vault) { mgr }
    var now = 1_700_000_000_000L
    val seeded = members

    init {
        gm.clockMs = { now }
        for (c in members) seed(c)
    }

    fun seed(contactId: String) {
        vault.insertContact(ContactRecord(contactId, generateSecureRandom(32), 1, "A-$contactId", 0L))
        val tag = contactId.removePrefix("c-").padEnd(6, 'x')
        vault.insertInboxId(InboxIdRecord(("in$tag").padEnd(32, 'A'), contactId, 1L, Long.MAX_VALUE, "inbound", CV_CAP))
        vault.insertInboxId(InboxIdRecord(("ou$tag").padEnd(32, 'B'), contactId, 1L, Long.MAX_VALUE, "outbound", CV_CAP))
        vault.insertInboxId(InboxIdRecord(("ic$tag").padEnd(32, 'C'), contactId, 1L, Long.MAX_VALUE, MessageManager.DIR_INBOUND_CTL, CV_CAP))
        vault.insertInboxId(InboxIdRecord(("oc$tag").padEnd(32, 'D'), contactId, 1L, Long.MAX_VALUE, MessageManager.DIR_OUTBOUND_CTL, CV_CAP))
    }

    fun group(): String = gm.createGroup("crew", seeded)!!
    fun ctlInboxOf(contactId: String) = vault.getInboxIdForContact(contactId, MessageManager.DIR_OUTBOUND_CTL)!!.inboxId
    fun textInboxOf(contactId: String) = vault.getInboxIdForContact(contactId, "outbound")!!.inboxId
    fun pendKey(groupId: String, contactId: String) = GroupMetaKeys.CTL_PEND_PREFIX + groupId + ":" + contactId
    fun pending(groupId: String, contactId: String) = vault.getMeta(pendKey(groupId, contactId))
    fun memberIdOf(groupId: String, contactId: String) =
        vault.getGroupMembers(groupId).first { it.contactId == contactId }.memberId
    fun postsTo(inboxId: String) = relay.posts.count { it.substringBefore("?").endsWith("/inbox/$inboxId") }
    fun myHash(groupId: String): String {
        val g = vault.getGroup(groupId)!!
        return GroupManager.membershipHash(groupId, g.epoch, vault.getGroupMembers(groupId).map { it.memberId })
    }
    /** [contactId] speaks, carrying [hash] as their view of the member list. */
    fun hears(contactId: String, groupId: String, hash: String) {
        gm.ingest(
            contactId,
            listOf(ReceivedMessage("hi", 0L, counter = 1, groupId = groupId, membershipHash = hash)),
            wantGroupId = groupId,
        )
    }
    /** Advance past the slow ack cadence and run one control sweep's redrives. */
    fun sweep(advanceMs: Long = 31L * 60 * 1000) {
        now += advanceMs
        gm.redriveUndeliveredMembershipControl()
    }
}

// ===========================================================================
// Mechanism 1: ack-gated obligations survive a 201-and-discard relay
// ===========================================================================

class GroupMembershipAckTest {

    @Test
    fun a2xxThatWasDiscarded_keepsTheObligation_andIsRedrivenUntilTheMemberActuallyAcks() {
        if (!aeadUp()) return
        val h = CvHarness(listOf("c-bob"))
        val gid = h.group()
        h.relay.clearRequests()

        // The relay ACCEPTS the removal roster (and drops it on the floor).
        assertTrue(h.gm.removeMember(gid, h.memberIdOf(gid, "c-bob")))
        assertEquals(1, h.postsTo(h.ctlInboxOf("c-bob")), "the removed member got its one final roster… allegedly")
        assertNotNull(
            h.pending(gid, "c-bob"),
            "R2-1: a 2xx is not delivery — the obligation must survive it",
        )

        // Every sweep past the slow cadence re-sends it, bounded.
        var sends = 0
        repeat(8) {
            h.relay.clearRequests()
            h.sweep()
            sends += h.postsTo(h.ctlInboxOf("c-bob"))
        }
        assertTrue(sends in 1..6, "the redrive must keep trying, and must be BOUNDED: $sends")
        assertNull(h.pending(gid, "c-bob"), "…and must eventually stop rather than beacon forever")
    }

    @Test
    fun aMatchingMembershipHash_isTheAcknowledgement_andStopsTheRedrive() {
        if (!aeadUp()) return
        val h = CvHarness(listOf("c-bob", "c-carol"))
        val gid = h.group()
        // Remove carol; bob stays and is the member that has to converge.
        assertTrue(h.gm.removeMember(gid, h.memberIdOf(gid, "c-carol")))
        assertNotNull(h.pending(gid, "c-bob"), "bob's copy is awaiting acknowledgement")

        // Bob speaks carrying the POST-change hash: end-to-end proof he converged.
        h.hears("c-bob", gid, h.myHash(gid))
        assertNull(h.pending(gid, "c-bob"), "a matching membership hash clears the obligation")

        h.relay.clearRequests()
        h.sweep()
        assertEquals(0, h.postsTo(h.ctlInboxOf("c-bob")), "an acknowledged member is never redriven again")
    }

    @Test
    fun aLegacyFiveFieldObligation_stillReadsAndIsRedriven_thenMigratesOnWrite() {
        // Migration: every obligation written by the build carries FIVE fields.
        // It must keep working (state = undelivered) and be rewritten in the new
        // 8-field shape — never dropped, which would silently lose the redrive.
        if (!aeadUp()) return
        val h = CvHarness(listOf("c-bob"))
        val gid = h.group()
        val hash = h.myHash(gid)
        h.vault.putMeta(h.pendKey(gid, "c-bob"), "${GroupManager.KIND_ROSTER}|1|$hash|0|${h.now}")
        h.relay.clearRequests()

        h.gm.redriveUndeliveredMembershipControl()
        assertEquals(1, h.postsTo(h.ctlInboxOf("c-bob")), "a legacy record must still drive a re-send")
        val migrated = h.pending(gid, "c-bob")
        assertNotNull(migrated)
        assertEquals(8, migrated.split('|').size, "…and must be rewritten in the current shape")
        assertEquals("a", migrated.split('|')[5], "the accepted append moves it to AWAITING-ACK")
    }

    @Test
    fun aGarbageObligation_isDroppedRatherThanRedriven() {
        if (!aeadUp()) return
        val h = CvHarness(listOf("c-bob"))
        val gid = h.group()
        h.vault.putMeta(h.pendKey(gid, "c-bob"), "roster|1|hash|0|${h.now}|z|${h.now}|")
        h.relay.clearRequests()
        h.gm.redriveUndeliveredMembershipControl()
        assertEquals(0, h.relay.posts.size, "an undecodable record must send nothing")
        assertNull(h.pending(gid, "c-bob"), "…and must be dropped, never retried forever")
    }
}

// ===========================================================================
// Mechanism 2: the hash-mismatch re-roster
// ===========================================================================

class GroupHashMismatchRerosterTest {

    @Test
    fun aMemberWhoseHashDiffers_getsTheCurrentRosterResent_onceAndOnlyToThem() {
        if (!aeadUp()) return
        val h = CvHarness(listOf("c-bob", "c-carol"))
        val gid = h.group()
        h.relay.clearRequests()

        // Bob's traffic carries a membership view that is NOT ours: whatever the
        // relay told us about our appends, bob has positively not converged.
        h.hears("c-bob", gid, "0".repeat(32))
        h.gm.rerosterUnconvergedMembers()

        assertEquals(1, h.postsTo(h.ctlInboxOf("c-bob")), "the diverged member gets the current roster")
        assertEquals(0, h.postsTo(h.ctlInboxOf("c-carol")), "…and nobody else does — this is never a fan-out")
        assertTrue(h.relay.posts.all { it.contains("?ttl=604800") })
    }

    @Test
    fun theReRosterIsThrottledPerMember() {
        if (!aeadUp()) return
        val h = CvHarness(listOf("c-bob"))
        val gid = h.group()
        h.relay.clearRequests()

        h.hears("c-bob", gid, "0".repeat(32))
        h.gm.rerosterUnconvergedMembers()
        assertEquals(1, h.postsTo(h.ctlInboxOf("c-bob")))

        // Keeps shouting a junk hash: no amplification, one roster per interval.
        repeat(10) {
            h.now += 1_000
            h.hears("c-bob", gid, "0".repeat(32))
            h.gm.rerosterUnconvergedMembers()
        }
        assertEquals(1, h.postsTo(h.ctlInboxOf("c-bob")), "at most one re-roster per member per interval")

        h.now += GroupManager.REROSTER_MIN_INTERVAL_MS + 1
        h.hears("c-bob", gid, "0".repeat(32))
        h.gm.rerosterUnconvergedMembers()
        assertEquals(2, h.postsTo(h.ctlInboxOf("c-bob")), "…and one more once the interval has passed")
    }

    @Test
    fun aMatchingHash_neverTriggersAReRoster() {
        if (!aeadUp()) return
        val h = CvHarness(listOf("c-bob"))
        val gid = h.group()
        h.relay.clearRequests()
        h.hears("c-bob", gid, h.myHash(gid))
        h.gm.rerosterUnconvergedMembers()
        assertEquals(0, h.relay.posts.size, "a converged member costs no traffic at all")
    }

    @Test
    fun onlyTheAdminReRosters() {
        // Receivers only honour a roster from the admin's channel, so a non-admin
        // re-send would be pure wasted traffic (and a way for a peer to make a
        // victim emit on demand).
        if (!aeadUp()) return
        val vault = InMemoryVault()
        val relay = AckingRelay()
        val mgr = MessageManager(vault, "http://relay.test", relay)
        val gm = GroupManager(vault) { mgr }
        val gid = GroupManager.newGroupId()
        val adm = bytesToHex(ByteArray(8) { 9 })
        val me = bytesToHex(ByteArray(8) { 8 })
        vault.insertContact(ContactRecord("c-adm", generateSecureRandom(32), 1, "Adm", 0L))
        vault.insertInboxId(InboxIdRecord("ocadmAAAAAAAAAAAAAAAAAAAAAAAAAAA", "c-adm", 1L, Long.MAX_VALUE, MessageManager.DIR_OUTBOUND_CTL, CV_CAP))
        vault.insertGroup(GroupRecord(gid, "crew", 1, adminMemberId = adm, myMemberId = me, createdAt = 0L))
        vault.insertGroupMember(GroupMemberRecord(gid, me, null, 0L))
        vault.insertGroupMember(GroupMemberRecord(gid, adm, "c-adm", 0L))

        gm.ingest(
            "c-adm",
            listOf(ReceivedMessage("hi", 0L, counter = 1, groupId = gid, membershipHash = "0".repeat(32))),
            wantGroupId = gid,
        )
        gm.rerosterUnconvergedMembers()
        assertEquals(0, relay.posts.size, "a non-admin must never re-broadcast a roster")
    }

    @Test
    fun reRostersAreBoundedPerSweep() {
        if (!aeadUp()) return
        val members = (1..8).map { "c-m$it" }
        val h = CvHarness(members)
        val gid = h.group()
        h.relay.clearRequests()
        for (c in members) h.hears(c, gid, "0".repeat(32))

        h.gm.rerosterUnconvergedMembers()
        assertEquals(4, h.relay.posts.size, "one sweep must not turn into a full fan-out")
    }
}

// ===========================================================================
// The ttl is UNIFORM, so it no longer classifies the kind
// ===========================================================================

class ControlAppendTtlUniformityTest {

    private fun ttls(relay: AckingRelay): List<String> =
        relay.posts.map { if (it.contains("?")) it.substringAfter("?") else "" }

    @Test
    fun everyGroupControlKind_carriesTheSameTtl() {
        if (!aeadUp()) return
        val h = CvHarness(listOf("c-bob"))

        // invite (createGroup) …
        val gid = h.group()
        // … act (the group send's activity notice) + a TEXT copy …
        h.gm.sendGroupMessage(gid, "hello")
        // … screenshot (group) …
        h.gm.sendGroupScreenshotNotice(gid)
        // … roster (a membership change) …
        h.gm.addMember(gid, "c-bob")   // already a member → no-op; use a removal instead
        assertTrue(h.gm.removeMember(gid, h.memberIdOf(gid, "c-bob")))

        val ctl = h.ctlInboxOf("c-bob")
        val controlPosts = h.relay.posts.filter { it.substringBefore("?").endsWith("/inbox/$ctl") }
        assertTrue(controlPosts.size >= 4, "invite + act + screenshot + roster: ${h.relay.posts}")
        assertTrue(
            controlPosts.all { it.endsWith("?ttl=${MessageManager.CONTROL_APPEND_TTL_SECONDS}") },
            "every control append must carry the SAME ttl: $controlPosts",
        )
    }

    @Test
    fun theLeaveAndJoinKinds_carryItToo() {
        if (!aeadUp()) return
        val h = CvHarness(listOf("c-bob"))
        val gid = h.group()
        h.relay.clearRequests()
        h.gm.leaveGroup(gid, null)
        assertTrue(h.relay.posts.isNotEmpty())
        assertTrue(
            h.relay.posts.all { it.endsWith("?ttl=${MessageManager.CONTROL_APPEND_TTL_SECONDS}") },
            "leave: ${h.relay.posts}",
        )

        // join — accept an invite from a peer.
        val h2 = CvHarness(listOf("c-bob"))
        val gid2 = GroupManager.newGroupId()
        val adm = bytesToHex(ByteArray(8) { 4 })
        val me = bytesToHex(ByteArray(8) { 5 })
        h2.gm.handleControl(
            "c-bob", gid2, GroupManager.KIND_INVITE,
            """{"n":"crew","ep":1,"adm":${jsonEscapeString(adm)},"you":${jsonEscapeString(me)},"mem":[${jsonEscapeString(adm)},${jsonEscapeString(me)}]}""",
        )
        h2.relay.clearRequests()
        assertTrue(h2.gm.acceptInvite(gid2))
        assertTrue(h2.relay.posts.isNotEmpty(), "accepting an invite fans out our KIND_JOIN")
        assertTrue(
            h2.relay.posts.all { it.endsWith("?ttl=${MessageManager.CONTROL_APPEND_TTL_SECONDS}") },
            "join: ${h2.relay.posts}",
        )
    }

    @Test
    fun theDirectControlKinds_carryItToo_andATextAppendStillCarriesNone() {
        if (!aeadUp()) return
        val h = CvHarness(listOf("c-bob"))
        h.relay.clearRequests()

        // inbox announce
        assertTrue(h.mgr.sendInboxAnnounce("c-bob", "ANNC".padEnd(32, 'y'), "C".repeat(43)))
        // 1:1 screenshot notice
        assertTrue(h.mgr.sendScreenshotNotice("c-bob"))
        val ctl = h.ctlInboxOf("c-bob")
        val controlPosts = h.relay.posts.filter { it.substringBefore("?").endsWith("/inbox/$ctl") }
        assertEquals(2, controlPosts.size)
        assertTrue(
            controlPosts.all { it.endsWith("?ttl=${MessageManager.CONTROL_APPEND_TTL_SECONDS}") },
            "announce + 1:1 screenshot must carry the uniform ttl: $controlPosts",
        )

        // A TEXT append is NOT a control append and must stay byte-identical.
        h.relay.clearRequests()
        assertTrue(h.mgr.sendMessage("c-bob", "hi"))
        assertEquals(listOf(""), ttls(h.relay), "a text append must carry no ttl at all: ${h.relay.posts}")
        assertTrue(h.relay.posts.single().endsWith("/inbox/${h.textInboxOf("c-bob")}"))
    }
}

// ===========================================================================
// a stale LEAVE must not evict a re-joined member
// ===========================================================================

class StaleLeaveGuardTest {

    @Test
    fun acceptInvite_purgesEveryStaleObligationForThatGroup() {
        if (!aeadUp()) return
        val h = CvHarness(listOf("c-bob"))
        val gid = h.group()
        // Leave while the relay is unreachable ⇒ durable LEAVE obligations.
        val gmNoTransport = GroupManager(h.vault) { null }
        gmNoTransport.clockMs = { h.now }
        gmNoTransport.leaveGroup(gid, null)
        assertNotNull(h.pending(gid, "c-bob"), "precondition: a LEAVE obligation is outstanding")

        // The admin re-invites us to the SAME groupId and we accept.
        val adm = bytesToHex(ByteArray(8) { 4 })
        val me = bytesToHex(ByteArray(8) { 5 })
        h.gm.handleControl(
            "c-bob", gid, GroupManager.KIND_INVITE,
            """{"n":"crew","ep":9,"adm":${jsonEscapeString(adm)},"you":${jsonEscapeString(me)},"mem":[${jsonEscapeString(adm)},${jsonEscapeString(me)}]}""",
        )
        assertTrue(h.gm.acceptInvite(gid))
        assertNull(
            h.pending(gid, "c-bob"),
            "re-joining a groupId must purge the previous incarnation's obligations",
        )
    }

    @Test
    fun theLeaveRedriveRefuses_whileWeAreAMemberOfThatGroupAgain() {
        if (!aeadUp()) return
        val h = CvHarness(listOf("c-bob"))
        val gid = h.group()
        // Plant the obligation directly, then re-create the group locally: the
        // redrive must refuse it even if nothing purged it (belt to acceptInvite's
        // braces — the re-join can arrive by another route).
        h.vault.putMeta(
            h.pendKey(gid, "c-bob"),
            "${GroupManager.KIND_LEAVE}|1|${"d".repeat(32)}|0|${h.now}|u|${h.now}|${h.memberIdOf(gid, "c-bob")}",
        )
        h.relay.clearRequests()
        h.gm.redriveUndeliveredMembershipControl()
        assertEquals(0, h.relay.posts.size, "a LEAVE must never be redriven while the group exists locally")
        assertNull(h.pending(gid, "c-bob"), "…and the stale obligation is dropped")
    }

    @Test
    fun aLeaveNamingAMemberIdTheSlotNoLongerHolds_isIgnored() {
        if (!aeadUp()) return
        val h = CvHarness(listOf("c-bob"))
        val gid = h.group()
        val bobMember = h.memberIdOf(gid, "c-bob")
        val stale = bytesToHex(ByteArray(8) { 7 })
        assertTrue(stale != bobMember)

        // A leave from bob's PREVIOUS membership instance (a re-join minted a new
        // memberId) must not evict the bob who is in the group now.
        h.gm.handleControl("c-bob", gid, GroupManager.KIND_LEAVE, h.gm.leaveBody(1L, stale))
        assertTrue(
            h.vault.getGroupMembers(gid).any { it.contactId == "c-bob" },
            "a stale leave must not remove the current membership",
        )

        // The leave for the CURRENT instance still applies.
        h.gm.handleControl("c-bob", gid, GroupManager.KIND_LEAVE, h.gm.leaveBody(1L, bobMember))
        assertFalse(h.vault.getGroupMembers(gid).any { it.contactId == "c-bob" })
    }

    @Test
    fun aLegacyBodylessLeave_isStillAccepted() {
        // Backward compatibility: a peer that predates the epoch/memberId fields
        // sends `{}` and must be honoured exactly as before.
        if (!aeadUp()) return
        val h = CvHarness(listOf("c-bob"))
        val gid = h.group()
        h.gm.handleControl("c-bob", gid, GroupManager.KIND_LEAVE, "{}")
        assertFalse(
            h.vault.getGroupMembers(gid).any { it.contactId == "c-bob" },
            "a legacy bare-{} leave must still remove the sender",
        )
    }

    @Test
    fun concurrentLeaves_areNotDroppedByAnEpochRace() {
        // The reason the epoch is NOT applied on its own: the epoch advances only at
        // the ADMIN, so a second leaver's copy legitimately arrives epoch-stale once
        // the first leave bumped us. Dropping it would strand that member in the
        // roster — and therefore in every later roster — forever.
        if (!aeadUp()) return
        val h = CvHarness(listOf("c-bob", "c-carol"))
        val gid = h.group()
        val carolMember = h.memberIdOf(gid, "c-carol")
        val epochWhenBothLeft = h.vault.getGroup(gid)!!.epoch

        h.gm.handleControl("c-bob", gid, GroupManager.KIND_LEAVE, h.gm.leaveBody(epochWhenBothLeft, h.memberIdOf(gid, "c-bob")))
        assertTrue(h.vault.getGroup(gid)!!.epoch > epochWhenBothLeft, "the admin bumped the epoch")

        h.gm.handleControl("c-carol", gid, GroupManager.KIND_LEAVE, h.gm.leaveBody(epochWhenBothLeft, carolMember))
        assertFalse(
            h.vault.getGroupMembers(gid).any { it.contactId == "c-carol" },
            "an honest concurrent leave must still be applied",
        )
    }

    @Test
    fun theLeaveWireCarriesTheEpochAndMemberId_butBothAreOptionalOnReceive() {
        val body = GroupManager(InMemoryVault()) { null }.leaveBody(7L, bytesToHex(ByteArray(8) { 3 }))
        assertTrue(body.contains("\"ep\":7"), body)
        assertTrue(body.contains("\"you\""), body)
    }
}

package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// GroupManager ingest guards, unread/buffer bounds, and fan-out TARGETING.
//
// Complements GroupManagerTest.kt / GroupManagerGuardsTest.kt /
// GroupMembershipEdgeCaseTest.kt. This file pins:
//
//   • The block-set BACKSTOP inside [GroupManager.ingest]: a BLOCKED
//     contact's traffic must be inert on EVERY path that reaches ingest —
//     not just the poll loops that skip blocked inboxes (those are covered
//     in ControlChannelTest). And a THROWING block-set provider fails toward
//     "nothing blocked" (delivery), never a crash or a mass-block.
//   • ingest's bufferAll (background-sweep) mode.
//   • dedupeId propagation into GroupMessage (and its absence on system
//     notices).
//   • The activity-notice ceiling (MAX_PENDING_ACTIVITY_PER_MEMBER).
//   • FIX B bounds: the global MAX_PENDING_UNRESOLVED_GROUP_TEXTS cap, the
//     flush-on-group-OPEN path (pollGroup, not just roster apply), the
//     scrubInMemory coverage of that buffer, and the no-resurrection rule
//     for a deleted group's buffered texts.
//   • on PARTIAL delivery the KIND_ACTIVITY notice
//     fans out ONLY to members whose text copy actually sent.
//   • removeMember's final roster reaching the REMOVED member (alsoTo).
//   • GROUP-2: a duplicate (unchanged-tags) join triggers NO roster fan-out,
//     and a changed-tags join inside MIN_ROSTER_INTERVAL_MS stores the tags
//     but stays throttled.
//
// Tests that must observe an actual SEND go through real AES-GCM and are
// bridge-guarded exactly like the sibling files (skipped on the iOS unit-test
// target where the Swift crypto bridge isn't installed). Everything else uses
// a null transport.
// ---------------------------------------------------------------------------

private fun seedIgContact(vault: InMemoryVault, contactId: String, secret: ByteArray = generateSecureRandom(32)) {
    vault.insertContact(
        ContactRecord(
            contactId = contactId, sharedSecret = secret,
            trustLevel = 1, alias = "A-$contactId", aliasLastRotated = 0L,
        )
    )
    val base = contactId.encodeToByteArray().fold(0) { a, b -> a * 31 + b }.toUInt().toString(16).padStart(8, '0')
    vault.insertInboxId(InboxIdRecord(
        inboxId = ("in$base".padEnd(32, 'A')).take(32), contactId = contactId,
        createdAt = 1L, expiresAt = Long.MAX_VALUE, direction = "inbound", cap = "A".repeat(43),
    ))
    vault.insertInboxId(InboxIdRecord(
        inboxId = ("ou$base".padEnd(32, 'B')).take(32), contactId = contactId,
        createdAt = 1L, expiresAt = Long.MAX_VALUE, direction = "outbound", cap = "B".repeat(43),
    ))
}

/** Member-side fixture joined via a real invite, with bob RESOLVED via roster. */
private class IgFixture(
    val vault: InMemoryVault, val gm: GroupManager, val gid: String,
    val adm: String, val me: String, val bob: String,
) {
    fun goodHash(): String {
        val g = vault.getGroup(gid)!!
        return GroupManager.membershipHash(gid, g.epoch, vault.getGroupMembers(gid).map { it.memberId })
    }
}

private fun igJoinedFixture(resolveBob: Boolean = true, vault: InMemoryVault = InMemoryVault()): IgFixture {
    seedIgContact(vault, "admin-contact")
    val gm = GroupManager(vault) { null }
    val gid = GroupManager.newGroupId()
    val adm = groupMemberId(10); val me = groupMemberId(20); val bob = groupMemberId(30)
    gm.handleControl(
        "admin-contact", gid, GroupManager.KIND_INVITE,
        """{"n":"crew","ep":1,"adm":${jsonEscapeString(adm)},"you":${jsonEscapeString(me)},"mem":[${jsonEscapeString(adm)},${jsonEscapeString(me)},${jsonEscapeString(bob)}]}""",
    )
    gm.acceptInvite(gid)
    val bobSecret = generateSecureRandom(32)
    seedIgContact(vault, "bob-contact", bobSecret)
    if (resolveBob) {
        val tag = GroupManager.boundTag(bobSecret, gid, bob)
        gm.handleControl(
            "admin-contact", gid, GroupManager.KIND_ROSTER,
            """{"n":"crew","ep":2,"adm":${jsonEscapeString(adm)},"mem":[${jsonEscapeString("$adm:")},${jsonEscapeString("$me:")},${jsonEscapeString("$bob:$tag")}]}""",
        )
    }
    return IgFixture(vault, gm, gid, adm, me, bob)
}

// ===========================================================================
// Block-set backstop in ingest + blocked-provider failure mode
// ===========================================================================

class GroupIngestBlockBackstopTest {

    @Test
    fun blockedSender_groupText_isNeitherSurfacedNorBuffered() {
        val f = igJoinedFixture()
        // Baseline: unblocked, the text surfaces.
        val before = f.gm.ingest(
            "bob-contact",
            listOf(ReceivedMessage("ok", 0L, counter = 1, groupId = f.gid, membershipHash = f.goodHash())),
            wantGroupId = f.gid,
        )
        assertEquals(1, before.group.size, "baseline: unblocked text surfaces")

        f.gm.blockedContacts = { setOf("bob-contact") }
        val after = f.gm.ingest(
            "bob-contact",
            listOf(ReceivedMessage("blocked", 0L, counter = 2, groupId = f.gid, membershipHash = f.goodHash())),
            wantGroupId = f.gid,
        )
        assertEquals(0, after.group.size, "a blocked sender's group text must not surface")
        assertEquals(0, after.direct.size)
        assertEquals(0, f.gm.takeGroupScreenItems(f.gid).size, "…and must not be buffered either")
    }

    @Test
    fun blockedSender_controls_mutateNothing() {
        val f = igJoinedFixture()
        f.gm.blockedContacts = { setOf("bob-contact") }

        // A blocked member's LEAVE must not remove their row (vault mutation).
        f.gm.ingest(
            "bob-contact",
            listOf(ReceivedMessage("", 0L, counter = 3, groupId = f.gid,
                membershipHash = f.goodHash(), controlKind = GroupManager.KIND_LEAVE, controlBody = "{}")),
            wantGroupId = null,
        )
        assertTrue(f.vault.getGroupMembers(f.gid).any { it.contactId == "bob-contact" },
            "a blocked contact's LEAVE must not mutate the roster")

        // A blocked contact's ACTIVITY must not light the group dot.
        f.gm.ingest(
            "bob-contact",
            listOf(ReceivedMessage("", 0L, counter = 4, groupId = f.gid,
                membershipHash = f.goodHash(), controlKind = GroupManager.KIND_ACTIVITY, controlBody = "{}")),
            wantGroupId = null,
        )
        assertTrue(f.gm.groupUnreadCounts().isEmpty(), "a blocked contact's activity must not count")

        // A blocked contact's INVITE must not park a consent prompt.
        val gid2 = GroupManager.newGroupId()
        val adm2 = groupMemberId(50); val me2 = groupMemberId(60)
        f.gm.ingest(
            "bob-contact",
            listOf(ReceivedMessage("", 0L, counter = 5, groupId = gid2,
                membershipHash = "0".repeat(32), controlKind = GroupManager.KIND_INVITE,
                controlBody = """{"n":"lure","ep":1,"adm":${jsonEscapeString(adm2)},"you":${jsonEscapeString(me2)},"mem":[${jsonEscapeString(adm2)},${jsonEscapeString(me2)}]}""")),
            wantGroupId = null,
        )
        assertTrue(f.gm.pendingInvites().isEmpty(), "a blocked contact's invite must not park")
    }

    @Test
    fun blockedSender_directText_isNotBufferedEither() {
        val f = igJoinedFixture()
        f.gm.blockedContacts = { setOf("bob-contact") }
        val res = f.gm.ingest("bob-contact", listOf(ReceivedMessage("psst", 0L, counter = 1)), wantGroupId = null)
        assertEquals(0, res.direct.size)
        assertEquals(0, f.gm.takeDirectScreenItems("bob-contact").size,
            "a blocked contact's direct text must not park")
    }

    @Test
    fun throwingBlockProvider_failsTowardDelivery() {
        // The provider contract: a transient Keychain failure means "nothing
        // blocked" — traffic still flows, nothing crashes, nothing is mass-blocked.
        val f = igJoinedFixture()
        f.gm.blockedContacts = { throw IllegalStateException("keychain hiccup") }
        val res = f.gm.ingest(
            "bob-contact",
            listOf(ReceivedMessage("still delivered", 0L, counter = 1, groupId = f.gid, membershipHash = f.goodHash())),
            wantGroupId = f.gid,
        )
        assertEquals(1, res.group.size, "a throwing block provider must not drop traffic")
    }
}

// ===========================================================================
// ingest routing edges — bufferAll mode + dedupeId propagation
// ===========================================================================

class GroupIngestRoutingEdgeTest {

    @Test
    fun ingest_bufferAllMode_handsDirectMessagesToTheScreenBuffer_insteadOfReturningThem() {
        // POLL-HANDOFF-1: a 1:1 screen's poll (bufferAll = true) hands its direct
        // texts to that screen's buffer, never through the return value.
        val f = igJoinedFixture()
        val res = f.gm.ingest(
            "bob-contact",
            listOf(ReceivedMessage("background direct", 0L, counter = 1)),
            wantGroupId = null,
            bufferAll = true,
        )
        assertEquals(0, res.direct.size, "bufferAll must never return a direct message")
        assertEquals(listOf("background direct"), f.gm.takeDirectScreenItems("bob-contact").map { it.text })
    }

    @Test
    fun groupMessage_preservesTheWireDedupeId() {
        // The channel-namespaced dedupe id must survive the
        // ReceivedMessage → GroupMessage conversion or the UI de-dup breaks on
        // the ratchet/legacy transition.
        val f = igJoinedFixture()
        val res = f.gm.ingest(
            "bob-contact",
            listOf(ReceivedMessage("hi", 0L, counter = 7, groupId = f.gid,
                membershipHash = f.goodHash(), dedupeId = "dr-7")),
            wantGroupId = f.gid,
        )
        assertEquals("dr-7", res.group.single().dedupeId)
    }

    @Test
    fun departureNotice_hasAnEmptyDedupeId_andIsSystem() {
        // System notices are keyed by timestamp in the UI — their dedupeId stays
        // empty by contract (see GroupMessage.dedupeId).
        val f = igJoinedFixture()
        f.gm.handleControl("bob-contact", f.gid, GroupManager.KIND_LEAVE, "{}")
        val notice = f.gm.takeGroupScreenItems(f.gid).single()
        assertTrue(notice.isSystem)
        assertEquals("", notice.dedupeId)
    }
}

// ===========================================================================
// The per-member activity-notice ceiling
// ===========================================================================

class GroupActivityCeilingTest {

    @Test
    fun activityNotices_fromOneMember_capAtTheCeiling() {
        val f = igJoinedFixture()
        repeat(GroupManager.MAX_PENDING_ACTIVITY_PER_MEMBER + 5) {
            f.gm.handleControl("bob-contact", f.gid, GroupManager.KIND_ACTIVITY, "{}")
        }
        assertEquals(GroupManager.MAX_PENDING_ACTIVITY_PER_MEMBER, f.gm.groupUnreadCounts()[f.gid],
            "one member must not push the group dot past the outstanding ceiling")
    }

    @Test
    fun drainingAGroupText_reopensTheActivityWindow() {
        // The ceiling is on OUTSTANDING pending notices, not a rate: consuming a
        // group text decrements the same counter, so the next honest notice
        // counts again.
        val f = igJoinedFixture()
        repeat(GroupManager.MAX_PENDING_ACTIVITY_PER_MEMBER + 5) {
            f.gm.handleControl("bob-contact", f.gid, GroupManager.KIND_ACTIVITY, "{}")
        }
        assertEquals(GroupManager.MAX_PENDING_ACTIVITY_PER_MEMBER, f.gm.groupUnreadCounts()[f.gid])
        // One group text drains → pending drops below the ceiling…
        f.gm.ingest(
            "bob-contact",
            listOf(ReceivedMessage("g", 0L, counter = 1, groupId = f.gid, membershipHash = f.goodHash())),
            wantGroupId = f.gid,
        )
        // …so one more notice is admitted (the dot counter itself is only
        // cleared by markGroupRead, so it moves past the old ceiling value).
        f.gm.handleControl("bob-contact", f.gid, GroupManager.KIND_ACTIVITY, "{}")
        assertEquals(GroupManager.MAX_PENDING_ACTIVITY_PER_MEMBER + 1, f.gm.groupUnreadCounts()[f.gid],
            "the ceiling gates OUTSTANDING notices — a drain reopens the window")
    }
}

// ===========================================================================
// FIX B bounds — cap, flush-on-open, scrub, no-resurrection
// ===========================================================================

class GroupUnresolvedBufferBoundsTest {

    /** Resolve bob by writing the member row directly (the roster path is
     *  already covered by GroupUnresolvedTextBufferTest — here we isolate the
     *  buffer mechanics from roster handling). */
    private fun resolveBobDirectly(f: IgFixture) {
        f.vault.insertGroupMember(GroupMemberRecord(f.gid, f.bob, "bob-contact", addedAt = 0L))
    }

    /**
     * ONE sender is bounded by the PER-SENDER sub-cap, far
     * below the global one — and the overflow evicts that sender's OLDEST parked
     * text rather than rejecting the arrival. (Before this the only bound was the
     * global 64 and the INCOMING message was dropped, which is what made cross-sender
     * starvation possible; the log line already claimed the behaviour the code now
     * actually has.)
     */
    @Test
    fun unresolvedTexts_fromOneSender_capAtThePerSenderBound_evictingTheOldest() {
        val f = igJoinedFixture(resolveBob = false)
        val over = GroupManager.MAX_PENDING_UNRESOLVED_PER_SENDER + 3
        val hash = f.goodHash()
        f.gm.ingest(
            "bob-contact",
            (1..over).map { ReceivedMessage("t$it", 0L, counter = it.toLong(), groupId = f.gid, membershipHash = hash) },
            wantGroupId = f.gid,
        )
        resolveBobDirectly(f)
        val delivered = f.gm.pollGroup(f.gid)
        assertEquals(GroupManager.MAX_PENDING_UNRESOLVED_PER_SENDER, delivered.size,
            "one sender must not hold more than its per-sender share")
        assertEquals("t4", delivered.first().text, "the OLDEST of that sender's texts are the ones evicted")
        assertEquals("t$over", delivered.last().text, "the NEWEST arrival is always admitted")
    }

    /**
     * a flooding (removed / never-resolvable) member must
     * not be able to destroy a GENUINE not-yet-resolved member's group text. The
     * feeding poll is a destructive relay drain, so a rejected arrival is a
     * permanently lost message — which is the exact loss FIX B exists to prevent.
     */
    @Test
    fun aFloodingSender_cannotStarveAnHonestUnresolvedSender() {
        val f = igJoinedFixture(resolveBob = false)
        val hash = f.goodHash()
        seedIgContact(f.vault, "flood-contact")
        // The flooder pushes far past both bounds, repeatedly.
        repeat(20) { round ->
            f.gm.ingest(
                "flood-contact",
                (1..16).map { ReceivedMessage("junk-$round-$it", 0L, counter = (round * 16 + it).toLong(), groupId = f.gid, membershipHash = hash) },
                wantGroupId = f.gid,
            )
        }
        // …and only THEN does the honest member's text arrive.
        f.gm.ingest(
            "bob-contact",
            listOf(ReceivedMessage("honest", 0L, counter = 1, groupId = f.gid, membershipHash = hash)),
            wantGroupId = f.gid,
        )
        resolveBobDirectly(f)
        val delivered = f.gm.pollGroup(f.gid)
        assertTrue(
            delivered.any { it.text == "honest" && it.senderContactId == "bob-contact" },
            "a flooding sender must never displace an honest unresolved sender's text: $delivered",
        )
    }

    /** FIX-B TTL: an unresolved text older than PENDING_UNRESOLVED_GROUP_TEXT_TTL_MS is
     *  DROPPED by the flush, not delivered when the sender later resolves. Driven via
     *  the GroupManager.clockMs seam (both the buffer stamp and the flush's `now` route
     *  through it), which is the only reason this path is now hermetically testable. */
    @Test
    fun unresolvedText_olderThanTtl_isDropped_notDelivered() {
        val f = igJoinedFixture(resolveBob = false)
        f.gm.clockMs = { 1_000L }                       // buffered-at stamp
        f.gm.ingest(
            "bob-contact",
            listOf(ReceivedMessage("late", 0L, counter = 1, groupId = f.gid, membershipHash = f.goodHash())),
            wantGroupId = f.gid,
        )
        resolveBobDirectly(f)
        // now - bufferedAt > TTL → expired: the flush drops it even though bob resolved.
        f.gm.clockMs = { 1_000L + GroupManager.PENDING_UNRESOLVED_GROUP_TEXT_TTL_MS + 1 }
        assertEquals(0, f.gm.pollGroup(f.gid).size,
            "an unresolved text past the FIX-B TTL is dropped, not delivered on resolve")
    }

    /** Boundary companion: at EXACTLY the TTL (now - bufferedAt == TTL) the entry is
     *  still live — the sweep uses a strict `>` — so it is delivered on resolve. */
    @Test
    fun unresolvedText_atExactTtlBoundary_isStillDelivered() {
        val f = igJoinedFixture(resolveBob = false)
        f.gm.clockMs = { 1_000L }
        f.gm.ingest(
            "bob-contact",
            listOf(ReceivedMessage("intime", 0L, counter = 1, groupId = f.gid, membershipHash = f.goodHash())),
            wantGroupId = f.gid,
        )
        resolveBobDirectly(f)
        f.gm.clockMs = { 1_000L + GroupManager.PENDING_UNRESOLVED_GROUP_TEXT_TTL_MS }   // == TTL, not > TTL
        val delivered = f.gm.pollGroup(f.gid)
        assertEquals(1, delivered.size, "at exactly the TTL boundary the text is still live")
        assertEquals("intime", delivered.first().text)
    }

    @Test
    fun unresolvedTexts_flushOnGroupOpen_notJustOnRosterApply() {
        // pollGroup (= opening the conversation) must also re-attempt
        // attribution — resolution can converge through any vault write.
        val f = igJoinedFixture(resolveBob = false)
        f.gm.ingest(
            "bob-contact",
            listOf(ReceivedMessage("early", 0L, counter = 1, groupId = f.gid, membershipHash = f.goodHash())),
            wantGroupId = f.gid,
        )
        assertEquals(0, f.gm.pollGroup(f.gid).size, "still unresolved — nothing delivered yet")
        resolveBobDirectly(f)
        val delivered = f.gm.pollGroup(f.gid)
        assertEquals(1, delivered.size, "opening the group must flush a now-resolved sender's texts")
        assertEquals("early", delivered.single().text)
        assertEquals("bob-contact", delivered.single().senderContactId)
    }

    @Test
    fun scrubInMemory_dropsBufferedUnresolvedPlaintext() {
        // The FIX-B buffer holds decrypted message TEXT and must be part
        // of the lock/panic-wipe RAM scrub like every other content buffer.
        val f = igJoinedFixture(resolveBob = false)
        f.gm.ingest(
            "bob-contact",
            listOf(ReceivedMessage("sensitive", 0L, counter = 1, groupId = f.gid, membershipHash = f.goodHash())),
            wantGroupId = f.gid,
        )
        f.gm.scrubInMemory()
        resolveBobDirectly(f)
        assertEquals(0, f.gm.pollGroup(f.gid).size,
            "scrubbed unresolved plaintext must be gone — resolving later delivers nothing")
    }

    // The flush resolves parked texts against the vault OUTSIDE the ConversationBuffers lock (the
    // UI thread's take lock). A scrub that lands while it is reading the vault
    // must win: nothing it dropped may be delivered or re-parked afterwards.
    @Test
    fun aScrubBetweenSnapshotAndApply_resurrectsNothing() {
        var hook: (() -> Unit)? = null
        val vault = object : InMemoryVault() {
            override fun getGroupMembers(groupId: String): List<GroupMemberRecord> {
                val h = hook
                hook = null
                h?.invoke()
                return super.getGroupMembers(groupId)
            }
        }
        val f = igJoinedFixture(resolveBob = false, vault = vault)
        f.gm.ingest(
            "bob-contact",
            listOf(ReceivedMessage("parked", 0L, counter = 1, groupId = f.gid, membershipHash = f.goodHash())),
            wantGroupId = f.gid,
        )
        resolveBobDirectly(f)
        hook = { f.gm.scrubInMemory() }   // fires inside the flush's vault read

        assertTrue(
            f.gm.pollGroup(f.gid).none { it.text == "parked" },
            "a text the scrub dropped must not be delivered by the flush that raced it",
        )
        assertEquals(0, f.gm.pollGroup(f.gid).size, "…nor re-parked for a later flush")
    }

    @Test
    fun unresolvedTexts_forADeletedGroup_arePruned_neverResurrected() {
        val f = igJoinedFixture(resolveBob = false)
        f.gm.ingest(
            "bob-contact",
            listOf(ReceivedMessage("stale", 0L, counter = 1, groupId = f.gid, membershipHash = f.goodHash())),
            wantGroupId = f.gid,
        )
        // The group goes away (leave / removal) while the text is still parked.
        f.vault.deleteGroup(f.gid)
        assertEquals(0, f.gm.pollGroup(f.gid).size, "no group — nothing delivered, entry pruned")

        // The group later comes back (re-invite) WITH bob resolved: the old
        // pre-departure text must not resurface in the new incarnation.
        f.vault.insertGroup(GroupRecord(f.gid, "crew", epoch = 1, adminMemberId = f.adm, myMemberId = f.me, createdAt = 0L))
        f.vault.insertGroupMember(GroupMemberRecord(f.gid, f.adm, "admin-contact", 0L))
        f.vault.insertGroupMember(GroupMemberRecord(f.gid, f.me, null, 0L))
        f.vault.insertGroupMember(GroupMemberRecord(f.gid, f.bob, "bob-contact", 0L))
        assertEquals(0, f.gm.pollGroup(f.gid).size,
            "a deleted group's buffered texts must never resurrect on re-join")
    }
}

// ===========================================================================
// Fan-out TARGETING — partial delivery, removeMember's alsoTo, and the
// GROUP-2 join-dedup/throttle at the send level.
// ===========================================================================

class GroupFanOutTargetingTest {

    /** Admin-side fixture with EXPLICIT, recognizable inbox ids so each call's
     *  target inbox can be attributed to a member and a channel. */
    private class FanOut(
        val vault: InMemoryVault, val http: RecordingRelayHttp,
        val gm: GroupManager, val gid: String,
        val bobMain: String, val bobCtl: String,
        val carolMain: String, val carolCtl: String,
        val bobMemberId: String,
    )

    private fun fanOutFixture(): FanOut {
        val vault = InMemoryVault()
        fun seed(contactId: String, tag: String): Pair<String, String> {
            vault.insertContact(ContactRecord(contactId, generateSecureRandom(32), 1, "A-$contactId", 0L))
            val main = "O$tag".padEnd(32, 'A')
            val ctl = "C$tag".padEnd(32, 'A')
            vault.insertInboxId(InboxIdRecord("I$tag".padEnd(32, 'A'), contactId, 1L, Long.MAX_VALUE, "inbound", "A".repeat(43)))
            vault.insertInboxId(InboxIdRecord(main, contactId, 1L, Long.MAX_VALUE, "outbound", "B".repeat(43)))
            vault.insertInboxId(InboxIdRecord(ctl, contactId, 1L, Long.MAX_VALUE, MessageManager.DIR_OUTBOUND_CTL, "C".repeat(43)))
            return main to ctl
        }
        val (bobMain, bobCtl) = seed("c-bob", "BOB")
        val (carolMain, carolCtl) = seed("c-carol", "CAR")
        val http = RecordingRelayHttp()
        val mgr = MessageManager(vault, "http://relay.test", http as RelayHttp)
        val gm = GroupManager(vault) { mgr }
        // Insert the group DIRECTLY (not via createGroup) so the only http
        // calls are the ones each test scripts — mirrors GroupUnreadAttributionTest.
        val gid = GroupManager.newGroupId()
        val me = groupMemberId(1); val bobM = groupMemberId(2); val carolM = groupMemberId(3)
        vault.insertGroup(GroupRecord(gid, "crew", epoch = 1, adminMemberId = me, myMemberId = me, createdAt = 0L))
        vault.insertGroupMember(GroupMemberRecord(gid, me, null, 0L))
        vault.insertGroupMember(GroupMemberRecord(gid, bobM, "c-bob", 0L))
        vault.insertGroupMember(GroupMemberRecord(gid, carolM, "c-carol", 0L))
        return FanOut(vault, http, gm, gid, bobMain, bobCtl, carolMain, carolCtl, bobM)
    }

    @Test
    fun sendGroupMessage_partialDelivery_activityNoticeGoesOnlyToDeliveredMembers() {
        // a notice to a member who never received the
        // text plants a PHANTOM pending count that later hides that contact's
        // real 1:1 badge. On partial delivery the activity fan-out must target
        // exactly the delivered set.
        if (!aeadUp()) return
        val f = fanOutFixture()
        // First text copy REFUSED by the relay (a definitive 4xx — no transient
        // retry), second accepted, then ONE activity notice (to the delivered
        // member only).
        f.http.script(
            HttpResult(code = 400, body = "", isSuccess = false),
            HttpResult(code = 202, body = "", isSuccess = true),
            HttpResult(code = 202, body = "", isSuccess = true),
        )
        val result = f.gm.sendGroupMessage(f.gid, "partial")
        assertEquals(2, result.total)
        assertEquals(1, result.delivered)
        assertFalse(result.allDelivered)
        assertEquals(3, f.http.calls.size, "2 text attempts + exactly ONE activity notice")

        // The delivered member is whichever TEXT inbox got the scripted 202
        // (targets are shuffled, so read it off the recorded call order).
        val deliveredIsBob = f.http.calls[1].url.contains(f.bobMain)
        val expectedCtl = if (deliveredIsBob) f.bobCtl else f.carolCtl
        val failedCtl = if (deliveredIsBob) f.carolCtl else f.bobCtl
        assertTrue(f.http.calls[2].url.contains(expectedCtl),
            "the activity notice must go to the DELIVERED member's control inbox")
        assertTrue(f.http.calls.none { it.url.contains(failedCtl) },
            "the failed member must receive NO activity notice (phantom pending)")
    }

    @Test
    fun removeMember_sendsTheFinalRoster_toTheRemovedMemberToo() {
        // The roster excluding the removed member is also sent TO them (one
        // final message) so their client deletes the group locally instead of
        // lingering forever.
        if (!aeadUp()) return
        val f = fanOutFixture()
        f.http.script(
            HttpResult(code = 202, body = "", isSuccess = true),
            HttpResult(code = 202, body = "", isSuccess = true),
        )
        assertTrue(f.gm.removeMember(f.gid, f.bobMemberId))
        assertEquals(2, f.http.calls.size, "one roster to the survivor + one to the removed member")
        val urls = f.http.calls.map { it.url }
        assertTrue(urls.any { it.contains(f.carolCtl) }, "the surviving member gets the roster")
        assertTrue(urls.any { it.contains(f.bobCtl) }, "the REMOVED member gets the final roster")
    }

    @Test
    fun duplicateJoin_unchangedTags_skipsTheRosterFanOut_andAThrottledChangeStoresWithoutFanOut() {
        // An identical re-join must not re-fan the
        // roster (amplification), and a changed-tags join inside
        // MIN_ROSTER_INTERVAL_MS stores the tags but stays throttled.
        if (!aeadUp()) return
        val f = fanOutFixture()
        repeat(4) { f.http.script(HttpResult(code = 202, body = "", isSuccess = true)) }
        val pairA = "${groupMemberId(40)}:${groupMemberId(41)}"
        val pairB = "${groupMemberId(50)}:${groupMemberId(51)}"
        fun joinBody(tags: List<String>) =
            """{"you":${jsonEscapeString(f.bobMemberId)},"tags":[${tags.joinToString(",") { jsonEscapeString(it) }}]}"""

        // First join: tags stored, roster fans to both resolved members.
        f.gm.handleControl("c-bob", f.gid, GroupManager.KIND_JOIN, joinBody(listOf(pairA)))
        assertEquals(2, f.http.calls.size, "the first join re-rosters every resolved member")

        // Identical re-join: content dedup — zero new sends.
        f.gm.handleControl("c-bob", f.gid, GroupManager.KIND_JOIN, joinBody(listOf(pairA)))
        assertEquals(2, f.http.calls.size, "an unchanged-tags join must not re-fan the roster")

        // Changed tags inside the throttle window: STORED but not fanned.
        f.gm.handleControl("c-bob", f.gid, GroupManager.KIND_JOIN, joinBody(listOf(pairB)))
        assertEquals(2, f.http.calls.size, "a changed-tags join inside the interval stays throttled")
        assertEquals(pairB, f.vault.getGroupMembers(f.gid).first { it.memberId == f.bobMemberId }.tags,
            "the throttled join's tags must still be persisted for the next allowed roster")
    }

    @Test
    fun sendGroupMessage_forAnUnknownGroup_sendsNothing() {
        // Transport present, group absent → (0, 0) and zero network calls.
        val f = fanOutFixture()
        val result = f.gm.sendGroupMessage(GroupManager.newGroupId(), "into the void")
        assertEquals(0, result.total)
        assertEquals(0, result.delivered)
        assertFalse(result.allDelivered)
        assertEquals(0, f.http.calls.size)
    }
}

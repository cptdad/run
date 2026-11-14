package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

// ---------------------------------------------------------------------------
// The DURABLE group unread attribution (GroupUnreadMarkerStore, owner decision
// 2026-11-12 "store in vault").
//
// The prod bug: a `gi` KIND_ACTIVITY notice is the only thing that names WHICH group
// a group-inbox text belongs to; it is consumed off the relay when the control
// inbox drains, and its effect lived only in RAM. After a session teardown the next
// session saw only the group-inbox /peek depth, so `unattributed = depth − noticed`
// was > 0 and the presence bump lit EVERY group shared with that sender.
//
// "A session" here is what it is in production: a GroupManager instance. A teardown
// is `scrubInMemory()` followed by a NEW GroupManager over the SAME vault (the
// platform layer nulls its reference on background/lock and builds a new one on the
// next unlock). Every dot is produced by the production paths (the control sweep,
// the unread sweep, the group/1:1 polls) against a relay double that really queues,
// peeks and drains blobs.
// ---------------------------------------------------------------------------

private fun umInbox(tag: String) = ("um$tag".padEnd(32, 'A')).take(32)
private const val UM_CAP = "QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ"
private const val HOUR_MS = 60L * 60 * 1000

/** Strict queueing relay with single-inbox peeks; the batch `/peek` and the mint are 404 (old relay). */
private class UmRelay : InboxQueueRelay(
    strict = true,
    peek = true,
    postReply = HttpResult(202, "", true),
    putReply = HttpResult(202, "", true),
) {
    override fun nonInboxRoute(method: String, url: String, body: ByteArray, headers: Map<String, String>): HttpResult =
        HttpResult(404, """{"error":"no"}""", false)
}

/**
 * Sender A and receiver B, both upgraded (all three inbox pairs), B holding
 * `1 + extraGroups` groups in each of which A is a RESOLVED member.
 */
private class UmHarness(extraGroups: Int = 0, vaultWrap: (InMemoryVault) -> VaultDatabase = { it }) {
    val shared = generateSecureRandom(32)
    val txtToB = umInbox("btxt")
    val ctlToB = umInbox("bctl")
    val grpToB = umInbox("bgrp")
    val txtToA = umInbox("atxt")
    val ctlToA = umInbox("actl")
    val grpToA = umInbox("agrp")

    val relay = UmRelay()
    val aVault = InMemoryVault()
    val aMgr = MessageManager(aVault, "http://relay.test", relay)
    val bRaw = InMemoryVault()
    val bVault: VaultDatabase = vaultWrap(bRaw)
    val bMgr = MessageManager(bVault, "http://relay.test", relay)
    /** B's monotonic clock for the presence bump's notice grace (advanced by hand). */
    var monoMs = 1_000_000L
    var gm = GroupManager(bVault) { bMgr }.also { it.noticeGraceClockMs = { monoMs } }

    val myMemberId = bytesToHex(ByteArray(8) { 1 })
    val peerMemberId = bytesToHex(ByteArray(8) { 2 })
    val gid = GroupManager.newGroupId()
    val otherGids = mutableListOf<String>()

    init {
        relay.declare(txtToB, ctlToB, grpToB, txtToA, ctlToA, grpToA)
        aVault.insertContact(ContactRecord("b", shared, 0, "B", 0L))
        aVault.insertInboxId(InboxIdRecord(txtToB, "b", 1L, Long.MAX_VALUE, "outbound", UM_CAP))
        aVault.insertInboxId(InboxIdRecord(ctlToB, "b", 1L, Long.MAX_VALUE, MessageManager.DIR_OUTBOUND_CTL, UM_CAP))
        aVault.insertInboxId(InboxIdRecord(grpToB, "b", 1L, Long.MAX_VALUE, MessageManager.DIR_OUTBOUND_GRP, UM_CAP))
        aVault.insertInboxId(InboxIdRecord(txtToA, "b", 1L, Long.MAX_VALUE, "inbound", UM_CAP))
        aVault.insertInboxId(InboxIdRecord(ctlToA, "b", 1L, Long.MAX_VALUE, MessageManager.DIR_INBOUND_CTL, UM_CAP))
        aVault.insertInboxId(InboxIdRecord(grpToA, "b", 1L, Long.MAX_VALUE, MessageManager.DIR_INBOUND_GRP, UM_CAP))

        bRaw.insertContact(ContactRecord("a", shared, 0, "A", 0L))
        bRaw.insertInboxId(InboxIdRecord(txtToB, "a", 1L, Long.MAX_VALUE, "inbound", UM_CAP))
        bRaw.insertInboxId(InboxIdRecord(ctlToB, "a", 1L, Long.MAX_VALUE, MessageManager.DIR_INBOUND_CTL, UM_CAP))
        bRaw.insertInboxId(InboxIdRecord(grpToB, "a", 1L, Long.MAX_VALUE, MessageManager.DIR_INBOUND_GRP, UM_CAP))
        bRaw.insertInboxId(InboxIdRecord(txtToA, "a", 1L, Long.MAX_VALUE, "outbound", UM_CAP))
        bRaw.insertInboxId(InboxIdRecord(ctlToA, "a", 1L, Long.MAX_VALUE, MessageManager.DIR_OUTBOUND_CTL, UM_CAP))
        bRaw.insertInboxId(InboxIdRecord(grpToA, "a", 1L, Long.MAX_VALUE, MessageManager.DIR_OUTBOUND_GRP, UM_CAP))

        seedGroup(gid)
        repeat(extraGroups) {
            val g = GroupManager.newGroupId()
            otherGids.add(g)
            seedGroup(g)
        }
    }

    private fun seedGroup(groupId: String) {
        bRaw.insertGroup(GroupRecord(groupId, "crew", 1, adminMemberId = myMemberId, myMemberId = myMemberId, createdAt = 0L))
        bRaw.insertGroupMember(GroupMemberRecord(groupId, myMemberId, contactId = null, addedAt = 0L))
        bRaw.insertGroupMember(GroupMemberRecord(groupId, peerMemberId, contactId = "a", addedAt = 0L))
    }

    fun hash(groupId: String) = GroupManager.membershipHash(groupId, 1, listOf(myMemberId, peerMemberId))

    /** A sends one group text into [groupId] (its group inbox at B) plus its `gi` notice. */
    fun sendGroupMessage(groupId: String = gid) {
        assertEquals(MessageManager.GroupTextRoute.GRP, aMgr.sendGroupTextRouted("b", groupId, hash(groupId), "hi"))
        assertTrue(
            aMgr.sendGroupControl("b", groupId, GroupManager.KIND_ACTIVITY, GroupManager.ACTIVITY_BODY_GRP, hash(groupId), noPush = true),
        )
    }

    /** The teardown → next unlock: scrub the session, build a NEW manager over the SAME vault. */
    fun newSession() {
        gm.scrubInMemory()
        gm = GroupManager(bVault) { bMgr }.also { it.noticeGraceClockMs = { monoMs } }
    }

    /** One production control cycle on B: the control drain, then the unread sweep. */
    fun cycle(advanceMs: Long = 0L) {
        monoMs += advanceMs
        gm.pollAllControls()
        gm.contactUnreadCounts()
    }

    /** See GtHarness.waitOutNoticeGrace. */
    fun waitOutNoticeGrace() = cycle(GroupUnreadTally.NOTICE_LANDING_GRACE_MS)

    fun marker(): String? = bRaw.getMeta(GroupUnreadMarkerStore.keyFor("a"))
    fun units(): List<GroupUnreadMarkerStore.MarkerUnit>? = marker()?.let { GroupUnreadMarkerStore.decode(it) }

    /** A `gi` notice applied straight through the control handler, at the session's clock. */
    fun giNotice(groupId: String = gid) =
        gm.handleControl("a", groupId, GroupManager.KIND_ACTIVITY, GroupManager.ACTIVITY_BODY_GRP, 0L)
}

class GroupUnreadMarkerTest {

    // --- the prod bug -----------------------------------------------------------

    @Test
    fun prodBug_noticeInSessionOne_survivesTheTeardown_andLightsONLYTheNamedGroup() {
        if (!aeadUp()) return
        val h = UmHarness(extraGroups = 1)   // A shares TWO groups with B
        h.sendGroupMessage(h.gid)
        h.gm.pollAllControls()   // session 1 drains the notice off the relay
        assertNotNull(h.marker(), "the counted `gi` notice is persisted")

        h.newSession()
        assertEquals(1, h.relay.pending(h.grpToB), "precondition: the text is still on the group inbox")
        assertEquals(0, h.relay.pending(h.ctlToB), "precondition: the notice is GONE from the relay")
        assertEquals(emptyMap(), h.gm.contactUnreadCounts(), "the contact row never lights (and the depth is published)")
        assertEquals(mapOf(h.gid to 1), h.gm.groupUnreadCounts(), "only the named group, never the other shared one")
    }

    /** Oracle: the same session-2 state WITHOUT the marker is exactly the prod bug. */
    @Test
    fun prodBug_oracle_withoutTheMarker_everySharedGroupLights() {
        if (!aeadUp()) return
        val h = UmHarness(extraGroups = 1)
        h.sendGroupMessage(h.gid)
        h.gm.pollAllControls()
        h.bRaw.deleteMeta(GroupUnreadMarkerStore.keyFor("a"))
        h.newSession()
        h.gm.contactUnreadCounts()
        h.waitOutNoticeGrace()   // the fallback's notice grace (2026-11-13) runs out
        assertEquals(setOf(h.gid) + h.otherGids, h.gm.groupUnreadCounts().keys, "the pre-fix behaviour, reproduced")
    }

    @Test
    fun twoGroupsFromTheSameSender_areBothRestored_andTheThirdStaysDark() {
        if (!aeadUp()) return
        val h = UmHarness(extraGroups = 2)
        h.sendGroupMessage(h.gid)
        h.sendGroupMessage(h.otherGids[0])
        h.gm.pollAllControls()

        h.newSession()
        h.gm.contactUnreadCounts()
        assertEquals(mapOf(h.gid to 1, h.otherGids[0] to 1), h.gm.groupUnreadCounts())
    }

    // --- clear / shrink in lockstep ---------------------------------------------

    @Test
    fun openingTheGroup_drainsAndClearsTheMarker() {
        if (!aeadUp()) return
        val h = UmHarness(extraGroups = 1)
        h.sendGroupMessage(h.gid)
        h.gm.pollAllControls()
        assertNotNull(h.marker())

        h.gm.pollGroup(h.gid)
        assertNull(h.marker(), "the group poll drained A's group inbox — the mirror goes with it")
        h.newSession()
        h.gm.contactUnreadCounts()
        assertTrue(h.gm.groupUnreadCounts().isEmpty(), "nothing relights after the teardown")
    }

    @Test
    fun openingTheGroupWithoutTransport_detachesIt_soTheNextSessionLightsNothing() {
        if (!aeadUp()) return
        val h = UmHarness(extraGroups = 1)
        h.sendGroupMessage(h.gid)
        h.gm.pollAllControls()
        // The group screen opens while Tor is down: no drain, the dot is cleared.
        val offline = GroupManager(h.bVault) { null }
        offline.markGroupRead(h.gid)
        offline.pollGroupIntoBuffer(h.gid)
        assertEquals(listOf<String?>(null), h.units()!!.map { it.groupId },
            "the unit is DETACHED — it still accounts for the blob, it lights no group")

        h.newSession()
        h.gm.contactUnreadCounts()
        assertTrue(h.gm.groupUnreadCounts().isEmpty(), "no dot on the opened group AND no presence bump on the other")
    }

    @Test
    fun theOneToOnePoll_drainsTheGroupInbox_andClearsTheMarker() {
        if (!aeadUp()) return
        val h = UmHarness()
        h.sendGroupMessage(h.gid)
        h.gm.pollAllControls()
        h.gm.pollDirect("a")
        assertNull(h.marker(), "GRP-DRAIN-1 drained A's group inbox (a GROUP_ECHO) — authoritative")
    }

    @Test
    fun leavingAGroup_detachesItsUnits_andKeepsTheOtherSharedGroupDark() {
        if (!aeadUp()) return
        val h = UmHarness(extraGroups = 1)
        h.sendGroupMessage(h.otherGids[0])
        h.gm.pollAllControls()
        h.gm.leaveGroup(h.otherGids[0])
        assertEquals(listOf<String?>(null), h.units()!!.map { it.groupId }, "no groupId of a left group survives")

        h.newSession()
        h.gm.contactUnreadCounts()
        assertTrue(h.gm.groupUnreadCounts().isEmpty(), "the left group's text must not bump the group we still share")
    }

    // --- TTL + heal --------------------------------------------------------------

    @Test
    fun aUnitOlderThanTheTextRetention_isDroppedAtRestore() {
        if (!aeadUp()) return
        val h = UmHarness()
        h.gm.clockMs = { currentTimeMillis() - 25 * HOUR_MS }
        h.giNotice()
        assertEquals(1, h.units()?.size, "live when written")

        h.newSession()
        assertNull(h.marker(), "a 25 h old unit outlived its text — deleted at restore")
        assertTrue(h.gm.groupUnreadCounts().isEmpty())
    }

    @Test
    fun aUnitInsideTheRetention_isRestored() {
        if (!aeadUp()) return
        val h = UmHarness()
        h.gm.clockMs = { currentTimeMillis() - 23 * HOUR_MS }
        h.giNotice()
        h.newSession()
        assertEquals(mapOf(h.gid to 1), h.gm.groupUnreadCounts(), "restored before any peek is published")
    }

    @Test
    fun aDefiniteZeroPeek_healsTheRestoredDot_andTheMarker() {
        if (!aeadUp()) return
        val h = UmHarness()
        h.giNotice()   // a notice whose text is NOT on the relay (expired / never landed)
        h.newSession()
        assertEquals(mapOf(h.gid to 1), h.gm.groupUnreadCounts())

        h.gm.contactUnreadCounts()   // the group-inbox peek answers a definite 0
        assertTrue(h.gm.groupUnreadCounts().isEmpty(), "no stale dot that never clears")
        assertNull(h.marker(), "…and the mirror healed with it")
    }

    @Test
    fun aDefinitePartialPeek_keepsOnlyTheNewestUnits() {
        if (!aeadUp()) return
        val h = UmHarness(extraGroups = 1)
        h.gm.clockMs = { currentTimeMillis() - 2 * HOUR_MS }
        h.giNotice(h.otherGids[0])                      // older, its text is gone
        h.gm.clockMs = { currentTimeMillis() }
        h.sendGroupMessage(h.gid)                       // newer, its text is queued
        h.gm.pollAllControls()
        assertEquals(2, h.units()?.size)

        h.newSession()
        h.gm.contactUnreadCounts()                      // depth 1
        assertEquals(mapOf(h.gid to 1), h.gm.groupUnreadCounts(), "the oldest restored unit is the one retracted")
        assertEquals(listOf<String?>(h.gid), h.units()!!.map { it.groupId })
    }

    @Test
    fun anUnansweredPeek_changesNothing() {
        if (!aeadUp()) return
        val h = UmHarness()
        h.giNotice()
        h.newSession()
        h.relay.throwOnGet.add(h.grpToB)   // unknown ≠ empty
        h.gm.contactUnreadCounts()
        assertEquals(mapOf(h.gid to 1), h.gm.groupUnreadCounts())
        assertEquals(1, h.units()?.size, "the mirror is untouched by an unknown depth")
    }

    // --- purge, corruption, ceiling, fail-soft ----------------------------------

    @Test
    fun deletingTheContact_purgesTheMarker_throughTheSharedPurgeList() {
        if (!aeadUp()) return
        val h = UmHarness()
        h.giNotice()
        val other = GroupUnreadMarkerStore.keyFor("someone-else")
        h.bRaw.putMeta(other, "v1;g=1")
        assertTrue(GroupUnreadMarkerStore.keyFor("a") in ratchetMetaKeysForContact("a"))
        assertFalse(GroupUnreadMarkerStore.keyFor("a") in ratchetMetaKeysForContact("someone-else"))

        h.bRaw.deleteContact("a")
        assertNull(h.marker(), "the marker dies with its contact")
        assertNotNull(h.bRaw.getMeta(other), "…and only with ITS contact")
    }

    @Test
    fun aCorruptMarker_isIgnoredAndDeleted() {
        if (!aeadUp()) return
        val h = UmHarness(extraGroups = 1)
        h.bRaw.putMeta(GroupUnreadMarkerStore.keyFor("a"), "v1;not a marker")
        h.newSession()
        assertNull(h.marker(), "deleted as residue")
        assertTrue(h.gm.groupUnreadCounts().isEmpty())
        // With a text queued the dot falls back to today's presence bump — never worse.
        assertEquals(MessageManager.GroupTextRoute.GRP, h.aMgr.sendGroupTextRouted("b", h.gid, h.hash(h.gid), "x"))
        h.gm.contactUnreadCounts()
        h.waitOutNoticeGrace()
        assertEquals(setOf(h.gid) + h.otherGids, h.gm.groupUnreadCounts().keys)
    }

    @Test
    fun aMarkerForAContactThatNoLongerExists_isDeletedAtRestore() {
        if (!aeadUp()) return
        val h = UmHarness()
        val ghost = GroupUnreadMarkerStore.keyFor("ghost")
        h.bRaw.putMeta(ghost, "v1;${h.gid}=${currentTimeMillis()}")
        h.newSession()
        assertNull(h.bRaw.getMeta(ghost))
        assertTrue(h.gm.groupUnreadCounts().isEmpty())
    }

    @Test
    fun aNoticeTheCeilingIgnored_isNotPersisted() {
        if (!aeadUp()) return
        val h = UmHarness()
        // Fill A's per-member budget with LEGACY notices (RAM-only by design)…
        repeat(GroupManager.MAX_PENDING_ACTIVITY_PER_MEMBER) {
            h.gm.handleControl("a", h.gid, GroupManager.KIND_ACTIVITY, "{}", 0L)
        }
        assertNull(h.marker(), "legacy notices are never persisted")
        // …so the next `gi` notice is ignored by the ceiling, and must not reach the vault.
        h.giNotice()
        assertNull(h.marker(), "a notice the tally did not count is not persisted")
    }

    @Test
    fun aLegacyNotice_staysRamOnly() {
        if (!aeadUp()) return
        val h = UmHarness()
        h.gm.handleControl("a", h.gid, GroupManager.KIND_ACTIVITY, "{}", 0L)
        assertNull(h.marker())
        assertEquals(mapOf(h.gid to 1), h.gm.groupUnreadCounts(), "the RAM behaviour is unchanged")
    }

    @Test
    fun aFailingVaultWrite_neverThrowsIntoTheControlPath_andTheRamDotStillLights() {
        if (!aeadUp()) return
        var faults: FaultyMarkerVault? = null
        val h = UmHarness(vaultWrap = { inner -> FaultyMarkerVault(inner).also { faults = it } })
        faults!!.failWrites = true
        h.giNotice()   // must not throw
        assertNull(h.marker())
        assertEquals(mapOf(h.gid to 1), h.gm.groupUnreadCounts(), "in-session behaviour is untouched")
    }

    @Test
    fun aFailingVaultRead_atRestore_startsEmpty_andNeverFailsConstruction() {
        if (!aeadUp()) return
        var faults: FaultyMarkerVault? = null
        val h = UmHarness(vaultWrap = { inner -> FaultyMarkerVault(inner).also { faults = it } })
        h.giNotice()
        faults!!.failReads = true
        h.newSession()   // must not throw
        assertTrue(h.gm.groupUnreadCounts().isEmpty(), "today's behaviour: nothing restored")
        faults!!.failReads = false
        assertNotNull(h.marker(), "an unreadable row is left untouched, never deleted")
    }
}

// ---------------------------------------------------------------------------
// The presence bump's NOTICE GRACE (2026-11-13). Device: cross:multi3 step 16,
// receiver and sender share `crew` + `crewb`, one text into `crewb`, and within
// one session the receiver showed a dot on BOTH. The sender ships the text, then
// the `gi` notice one jitter gap later; a control cycle whose drain ran before the
// notice landed and whose peek then saw the text read `unattributed > 0` and lit
// every shared group until the next cycle drained the notice. The fallback now
// waits for the notice it stands in for.
// ---------------------------------------------------------------------------

class GroupPresenceBumpGraceTest {

    private fun UmHarness.sendTextOnly(groupId: String = gid) =
        assertEquals(MessageManager.GroupTextRoute.GRP, aMgr.sendGroupTextRouted("b", groupId, hash(groupId), "hi"))

    private fun UmHarness.sendNoticeOnly(groupId: String = gid) = assertTrue(
        aMgr.sendGroupControl("b", groupId, GroupManager.KIND_ACTIVITY, GroupManager.ACTIVITY_BODY_GRP, hash(groupId), noPush = true),
    )

    @Test
    fun deviceRegression_textPeekedBeforeItsNotice_lightsNoGroup_thenOnlyTheNamedOne() {
        if (!aeadUp()) return
        val h = UmHarness(extraGroups = 1)   // `crew` (gid) + `crewb` (otherGids[0])
        val crewb = h.otherGids[0]
        val other = h.gid
        val seen = mutableListOf<Map<String, Int>>()
        fun publish() = h.gm.groupUnreadCounts().also { seen.add(it) }

        h.sendTextOnly(crewb)
        h.cycle()   // the control drain finds no notice yet, then the peek sees depth 1
        assertEquals(1, h.relay.pending(h.grpToB), "precondition: the text is on the group inbox")
        assertTrue(publish().isEmpty(), "NO group may light while the notice can still be in flight")

        h.cycle(3_000)   // the next FAST cycle, notice still in flight
        assertTrue(publish().isEmpty(), "a control check that started inside the grace proves nothing")

        h.sendNoticeOnly(crewb)   // the notice lands…
        h.cycle(3_000)            // …and the next cycle drains it
        assertEquals(mapOf(crewb to 1), publish(), "only the group the text was for")

        h.cycle(GroupUnreadTally.FALLBACK_CEILING_MS * 2)
        assertEquals(mapOf(crewb to 1), publish(), "and nothing else lights later either")
        assertTrue(seen.none { other in it }, "the other shared group was never lit at any point: $seen")
    }

    @Test
    fun aNoticeCarriedByTheVeryCycleThatWouldQualify_stillAttributesFirst() {
        if (!aeadUp()) return
        // The credit is given AFTER that drain's ingest: a notice in the batch resets
        // the grace before the "came back without it" check can be recorded.
        val h = UmHarness(extraGroups = 1)
        h.sendTextOnly(h.gid)
        h.cycle()
        h.sendNoticeOnly(h.gid)
        h.cycle(GroupUnreadTally.NOTICE_LANDING_GRACE_MS + 5_000)
        assertEquals(mapOf(h.gid to 1), h.gm.groupUnreadCounts())
    }

    @Test
    fun aLostNotice_endsInTheFallback_onEverySharedGroup_afterTheGraceAndAControlCheck() {
        if (!aeadUp()) return
        val h = UmHarness(extraGroups = 1)
        h.sendTextOnly(h.gid)
        h.cycle()
        assertTrue(h.gm.groupUnreadCounts().isEmpty())

        h.monoMs += GroupUnreadTally.NOTICE_LANDING_GRACE_MS * 2
        assertTrue(h.gm.groupUnreadCounts().isEmpty(), "time alone (under the ceiling) does not decide — a control check does")

        h.cycle()   // the check starts ≥ grace after first sight, and finds no notice
        assertEquals(mapOf(h.gid to 1, h.otherGids[0] to 1), h.gm.groupUnreadCounts(), "+1 on every shared group, as before")
        assertEquals(emptyMap(), h.gm.contactUnreadCounts(), "never a contact row")
    }

    @Test
    fun aLostNotice_withABrokenControlInbox_stillLights_atTheCeiling() {
        if (!aeadUp()) return
        val h = UmHarness(extraGroups = 1)
        h.sendTextOnly(h.gid)
        h.cycle()
        h.relay.throwOnGet.add(h.ctlToB)   // every control peek/drain of A now fails
        h.cycle(GroupUnreadTally.NOTICE_LANDING_GRACE_MS)
        assertTrue(h.gm.groupUnreadCounts().isEmpty(), "a FAILED check is not evidence")
        h.monoMs += GroupUnreadTally.FALLBACK_CEILING_MS
        assertEquals(setOf(h.gid) + h.otherGids, h.gm.groupUnreadCounts().keys, "the backstop fires with no further cycle")
    }

    @Test
    fun depthBackToZeroDuringTheWait_lightsNothing_andTheNextTextWaitsAfresh() {
        if (!aeadUp()) return
        val h = UmHarness(extraGroups = 1)
        h.sendTextOnly(h.gid)
        h.cycle()
        h.relay.withholdLast(h.grpToB)   // the text is gone from the relay (expired)
        h.cycle(5_000)                   // a definite 0 is published
        h.cycle(GroupUnreadTally.FALLBACK_CEILING_MS)
        assertTrue(h.gm.groupUnreadCounts().isEmpty(), "nothing lights for a depth that went away")

        // The grace was RESET, not left running: a new text much later waits its own.
        h.sendTextOnly(h.gid)
        h.cycle()
        assertTrue(h.gm.groupUnreadCounts().isEmpty(), "a fresh unattributed depth starts a fresh grace")
        h.waitOutNoticeGrace()
        assertEquals(setOf(h.gid) + h.otherGids, h.gm.groupUnreadCounts().keys)
    }

    @Test
    fun drainingTheGroupInboxDuringTheWait_resetsIt() {
        if (!aeadUp()) return
        val h = UmHarness(extraGroups = 1)
        h.sendTextOnly(h.gid)
        h.cycle()
        h.gm.pollDirect("a")   // GRP-DRAIN-1 drains A's group inbox: authoritative
        h.waitOutNoticeGrace()
        h.cycle(GroupUnreadTally.FALLBACK_CEILING_MS)
        assertTrue(h.gm.groupUnreadCounts().isEmpty())
    }

    @Test
    fun theScrubClearsAWaitingGrace() {
        if (!aeadUp()) return
        val h = UmHarness(extraGroups = 1)
        h.sendTextOnly(h.gid)
        h.cycle()
        h.gm.scrubInMemory()
        h.monoMs += GroupUnreadTally.FALLBACK_CEILING_MS * 2
        assertTrue(h.gm.groupUnreadCounts().isEmpty(), "no depth, no grace survives the scrub")
        // A new sweep after the scrub starts a brand-new grace (not the pre-scrub one).
        h.gm.contactUnreadCounts()
        assertTrue(h.gm.groupUnreadCounts().isEmpty())
    }

    @Test
    fun aRestoredMarkerSession_attributesOnTheFirstFrame_withNoWait() {
        if (!aeadUp()) return
        val h = UmHarness(extraGroups = 1)
        h.sendGroupMessage(h.gid)
        h.gm.pollAllControls()
        h.newSession()
        h.gm.contactUnreadCounts()   // first peek of the new session, no clock advance
        assertEquals(mapOf(h.gid to 1), h.gm.groupUnreadCounts(), "the restored unit lights its group at once")
        h.waitOutNoticeGrace()
        assertEquals(mapOf(h.gid to 1), h.gm.groupUnreadCounts(), "and the grace never adds the other group")
    }

    @Test
    fun connectPrime_attributedText_isLitTheFrameThePrimeEnds() = runTest {
        if (!aeadUp()) return@runTest
        val h = UmHarness(extraGroups = 1)
        h.sendGroupMessage(h.gid)   // text + notice, both still on the relay
        h.newSession()
        h.gm.primeUnreadCounts(emptySet()) { _, _ -> }
        assertEquals(mapOf(h.gid to 1), h.gm.groupUnreadCounts(), "the pre-drained notice attributes at reveal")
    }

    @Test
    fun connectPrime_genuinelyLostNotice_showsNothingAtReveal_thenTheFallbackAfterOneQualifyingCycle() = runTest {
        if (!aeadUp()) return@runTest
        val h = UmHarness(extraGroups = 1)
        h.sendTextOnly(h.gid)   // the notice was lost, and no marker exists
        h.newSession()
        h.gm.primeUnreadCounts(emptySet()) { _, _ -> }
        assertTrue(h.gm.groupUnreadCounts().isEmpty(), "the prime's own pre-drain ran BEFORE its peek — no credit")
        h.cycle(3_000)   // the loop's first cycle, still inside the grace
        assertTrue(h.gm.groupUnreadCounts().isEmpty())
        h.cycle(GroupUnreadTally.NOTICE_LANDING_GRACE_MS)
        assertEquals(setOf(h.gid) + h.otherGids, h.gm.groupUnreadCounts().keys)
    }
}

/** The grace state machine on its own, with an injected clock (no relay, no vault). */
class GroupUnreadTallyGraceTest {
    private var now = 10_000L
    private val t = GroupUnreadTally(nowMs = { now })
    private val grace = GroupUnreadTally.NOTICE_LANDING_GRACE_MS

    @Test
    fun aCheckStartedInsideTheGraceIsIgnored_oneStartedAfterItQualifies() {
        t.notePeekedGroupInboxDepths(mapOf("c" to 1))
        val since = now
        assertTrue(t.unattributedContacts().isEmpty())
        t.controlInboxChecked("c", since + grace - 1)
        now += grace * 3
        assertTrue(t.unattributedContacts().isEmpty(), "too early a check, and under the ceiling")
        t.controlInboxChecked("c", since + grace)
        assertEquals(setOf("c"), t.unattributedContacts())
    }

    @Test
    fun aGrowingDepthDoesNotRestartTheClock_butCatchingUpResetsIt() {
        t.notePeekedGroupInboxDepths(mapOf("c" to 1))
        val since = now
        now += 5_000
        t.notePeekedGroupInboxDepths(mapOf("c" to 2))
        t.controlInboxChecked("c", since + grace)
        assertEquals(setOf("c"), t.unattributedContacts(), "still timed from FIRST sight")

        t.noteActivity("c", "G", onGroupInbox = true)
        t.noteActivity("c", "G", onGroupInbox = true)
        assertTrue(t.unattributedContacts().isEmpty(), "attribution caught up")
        t.notePeekedGroupInboxDepths(mapOf("c" to 3))   // one more, unattributed again
        assertTrue(t.unattributedContacts().isEmpty(), "the old credit did not survive the reset")
    }

    @Test
    fun theCeilingAloneLights_andZeroDepthOrDrainOrScrubResets() {
        t.notePeekedGroupInboxDepths(mapOf("c" to 1, "d" to 1, "e" to 1))
        now += GroupUnreadTally.FALLBACK_CEILING_MS
        assertEquals(setOf("c", "d", "e"), t.unattributedContacts())
        t.notePeekedGroupInboxDepths(mapOf("c" to 0))
        t.groupInboxDrained("d")
        t.notePeekedGroupInboxDepths(mapOf("c" to 1, "d" to 1))
        assertEquals(setOf("e"), t.unattributedContacts(), "c and d start over")
        t.scrub()
        t.notePeekedGroupInboxDepths(mapOf("e" to 1))
        assertTrue(t.unattributedContacts().isEmpty(), "the scrub took e's start time with it")
    }

    @Test
    fun aCheckForAnAttributedContact_isANoOp() {
        t.noteActivity("c", "G", onGroupInbox = true)
        t.notePeekedGroupInboxDepths(mapOf("c" to 1))
        t.controlInboxChecked("c", now + grace)
        t.notePeekedGroupInboxDepths(mapOf("c" to 2))
        assertTrue(t.unattributedContacts().isEmpty(), "no credit carried in from before it was unattributed")
    }
}

/** Decorator whose `_meta` access to marker keys can be made to throw (iOS locked keybag). */
private class FaultyMarkerVault(private val inner: InMemoryVault) : VaultDatabase by inner {
    var failWrites = false
    var failReads = false
    private fun isMarker(k: String) = k.startsWith(GroupUnreadMarkerStore.PREFIX)

    override fun getMeta(key: String): String? {
        if (failReads && isMarker(key)) throw IllegalStateException("keybag locked")
        return inner.getMeta(key)
    }
    override fun putMeta(key: String, value: String) {
        if (failWrites && isMarker(key)) throw IllegalStateException("keybag locked")
        inner.putMeta(key, value)
    }
    override fun deleteMeta(key: String) {
        if (failWrites && isMarker(key)) throw IllegalStateException("keybag locked")
        inner.deleteMeta(key)
    }
}

// ---------------------------------------------------------------------------
// The store on its own: codec, stamp, bounds, heal, fail-soft.
// ---------------------------------------------------------------------------

class GroupUnreadMarkerStoreTest {
    private val now = 1_800_000_000_000L

    @Test
    fun codec_roundTripsOldestFirst_withDetachedUnits() {
        val units = listOf(
            GroupUnreadMarkerStore.MarkerUnit("G2", now - 3_000),
            GroupUnreadMarkerStore.MarkerUnit(null, now - 2_000),
            GroupUnreadMarkerStore.MarkerUnit("G1", now - 1_000),
            GroupUnreadMarkerStore.MarkerUnit("G2", now),
        )
        val enc = GroupUnreadMarkerStore.encode(units)
        assertEquals("v1;G2=${now - 3_000},$now;*=${now - 2_000};G1=${now - 1_000}", enc)
        assertEquals(units, GroupUnreadMarkerStore.decode(enc))
    }

    @Test
    fun decode_isStrict() {
        for (bad in listOf(
            "", "v1", "v2;G=1", "v1;G=", "v1;=1", "v1;G=1;G=2", "v1;G=-1", "v1;G=0", "v1;G=1x",
            "v1;G:1=1", "v1;G=1,,2", "garbage", "v1;G=" + (1..100).joinToString(","),
        )) assertNull(GroupUnreadMarkerStore.decode(bad), "must reject: $bad")
    }

    @Test
    fun stamp_prefersAPlausibleClaim_andIsMinuteRounded() {
        assertEquals(now - (now % 60_000), GroupUnreadMarkerStore.stampFor(0L, now))
        assertEquals(now - (now % 60_000), GroupUnreadMarkerStore.stampFor(now + 10 * HOUR_MS, now), "a future claim is ignored")
        val claimed = now - 3 * HOUR_MS + 1234
        assertEquals(claimed - (claimed % 60_000), GroupUnreadMarkerStore.stampFor(claimed, now))
    }

    @Test
    fun record_isBoundedToTheNewestUnits_andPrunesExpiredOnes() {
        val v = InMemoryVault()
        val s = GroupUnreadMarkerStore(v) { now }
        s.record("c", "G", now - 30 * HOUR_MS)   // already expired: never written
        assertNull(v.getMeta(GroupUnreadMarkerStore.keyFor("c")))
        repeat(GroupUnreadMarkerStore.MAX_UNITS + 5) { s.record("c", "G", now - 1_000_000 + it) }
        val units = GroupUnreadMarkerStore.decode(v.getMeta(GroupUnreadMarkerStore.keyFor("c"))!!)!!
        assertEquals(GroupUnreadMarkerStore.MAX_UNITS, units.size)
        assertEquals(now - 1_000_000 + 5, units.first().atMs, "the oldest are the ones evicted")
    }

    @Test
    fun healTo_keepsTheNewest_andZeroDeletes() {
        val v = InMemoryVault()
        val s = GroupUnreadMarkerStore(v) { now }
        s.record("c", "A", now - 3_000); s.record("c", "B", now - 2_000); s.record("c", "C", now - 1_000)
        s.healTo("c", 2)
        assertEquals(listOf("B", "C"), GroupUnreadMarkerStore.decode(v.getMeta(GroupUnreadMarkerStore.keyFor("c"))!!)!!.map { it.groupId })
        s.healTo("c", 5)
        assertEquals(2, GroupUnreadMarkerStore.decode(v.getMeta(GroupUnreadMarkerStore.keyFor("c"))!!)!!.size, "never heals UP")
        s.healTo("c", 0)
        assertNull(v.getMeta(GroupUnreadMarkerStore.keyFor("c")))
    }

    @Test
    fun restore_detachesUnitsOfGoneGroups_andDropsFutureOnes() {
        val v = InMemoryVault()
        v.putMeta(GroupUnreadMarkerStore.keyFor("c"), "v1;KEEP=${now - 1_000};GONE=${now - 900};FUT=${now + HOUR_MS}")
        val s = GroupUnreadMarkerStore(v) { now }
        val out = s.restore(contactExists = { true }, isMember = { _, g -> g == "KEEP" })
        assertEquals(listOf("KEEP", null), out["c"]!!.map { it.groupId })
        assertEquals("v1;KEEP=${now - 1_000};*=${now - 900}", v.getMeta(GroupUnreadMarkerStore.keyFor("c")), "rewritten without the groupId")
    }

    @Test
    fun aFieldWithADelimiter_isNeverStored() {
        val v = InMemoryVault()
        val s = GroupUnreadMarkerStore(v) { now }
        s.record("c;x", "G", now)
        s.record("c", "G=1", now)
        assertTrue(v.metaKeys().none { it.startsWith(GroupUnreadMarkerStore.PREFIX) })
    }
}

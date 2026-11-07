package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// Handoff guard (physical cross:multi3, 2026-09-17 18:24 UTC) — an admin must not hand
// the role on while a member it just added has not yet been INGESTED.
//
// What the relay journal proved for that red (dev relay, UTC):
//   16:49:50  admin D appends the INVITE to the new member M
//   16:49:51/52 D fans the companion roster to A and M
//   16:50:52  D's ~7 s control drains stop dead — exactly 60 s after its last
//             control SEND, i.e. CONTROL_CONVERGENCE_WINDOW_MS expiring — and D
//             drops to the 60–90 s idle cadence, because hasUnresolvedMembers()
//             tests `contactId == null` and M's row HAS a contactId (addMember
//             inserts it), so "I am the admin and I am waiting for a join" was
//             invisible to it.
//   16:51:12  M's KIND_JOIN lands on D's control inbox … and sits there
//   16:51:31/34 D broadcasts the HANDOFF roster (still without M's tags)
//   16:51:57  D leaves
//   16:52:10  D finally drains the join — 38 s too late, group already gone,
//             handleJoin returns at `vault.getGroup(groupId) ?: return`
// Result: the handoff roster carried an EMPTY tag list for A's slot (nothing is
// mutual with a member whose tags we never received), the promoted member could
// not resolve A, and — because resolution lives only in handleRoster and an
// admin receives no rosters — it never could. Observed as `members=2/2,
// unresolved=1` on the promoted seat.
//
// The two halves pinned here:
//   a. GroupManager.joinPending → hasUnresolvedMembers: the admin awaiting a
//      join keeps the FAST control cadence, bounded by the same 10-minute join window.
//   b. transferAdmin REFUSES while any other member's join is pending — the one
//      roster caller whose incompleteness is irreversible.
// ---------------------------------------------------------------------------

private fun jpMemberId(seed: Int) = bytesToHex(ByteArray(8) { (seed + it).toByte() })

/**
 * Stamps a placeholder tag list on every resolved, non-self member row so
 * `GroupManager.joinPending` stops seeing the group as "the admin is still waiting
 * for a join". Shared by the pre-existing `transferAdmin` tests, whose fixtures go
 * straight from `createGroup` to `transferAdmin` — a sequence the join-pending guard now
 * (correctly) refuses, because at that instant NO member has joined and any roster
 * the successor could build would be entirely tagless.
 *
 * The stamps are per-member and deliberately never MUTUAL, so `buildRosterBody`
 * still redistributes nothing: the call counts and roster shapes those tests assert
 * are unchanged, only the guard's precondition is satisfied.
 */
internal fun markAllMembersJoined(vault: VaultDatabase, groupId: String) {
    val g = vault.getGroup(groupId) ?: return
    for (m in vault.getGroupMembers(groupId)) {
        if (m.memberId == g.myMemberId || m.contactId == null || m.tags.isNotEmpty()) continue
        val half = m.memberId.take(8)
        vault.insertGroupMember(m.copy(tags = "$half:$half"))
    }
}

private fun jpSeedContact(vault: InMemoryVault, contactId: String, secret: ByteArray) {
    vault.insertContact(
        ContactRecord(
            contactId = contactId, sharedSecret = secret,
            trustLevel = 1, alias = "A-$contactId", aliasLastRotated = 0L,
        )
    )
    // Well-formed inbox ids per contact, so the (transport-less) control fan-outs
    // these tests trigger take their ordinary path rather than an early-out.
    val base = contactId.hashCode().toUInt().toString(16).padStart(8, '0')
    vault.insertInboxId(InboxIdRecord(
        inboxId = ("in$base".padEnd(32, 'A')).take(32), contactId = contactId,
        createdAt = 1L, expiresAt = Long.MAX_VALUE, direction = "inbound",
        cap = "A".repeat(43),
    ))
    vault.insertInboxId(InboxIdRecord(
        inboxId = ("out$base".padEnd(32, 'B')).take(32), contactId = contactId,
        createdAt = 1L, expiresAt = Long.MAX_VALUE, direction = "outbound",
        cap = "B".repeat(43),
    ))
}

class GroupJoinPendingHandoffTest {

    private val noTransport: () -> MessageManager? = { null }
    private val gid = GroupManager.newGroupId()
    private val dId = jpMemberId(1)   // D — the current admin (the Android seat)
    private val aId = jpMemberId(2)   // A — the co-member (the iOS admin seat)
    private val mId = jpMemberId(3)   // M — the member D just re-added (iosMember)

    // Symmetric pairwise secrets: both ends hold identical bytes.
    private val sDA = generateSecureRandom(32)
    private val sDM = generateSecureRandom(32)
    private val sAM = generateSecureRandom(32)

    /** Admin device D: admin of {D, A, M}. A is resolved; M was just added by
     *  contact, so its row carries a contactId and NO tags — the exact state
     *  `addMember` leaves behind until the join arrives. */
    private fun adminDevice(): Pair<InMemoryVault, GroupManager> {
        val v = InMemoryVault()
        jpSeedContact(v, "A", sDA)
        jpSeedContact(v, "M", sDM)
        val gm = GroupManager(v, noTransport)
        gm.clockMs = { FIXED_NOW }
        v.insertGroup(GroupRecord(gid, "crew", epoch = 5L, adminMemberId = dId, myMemberId = dId, createdAt = 0L))
        v.insertGroupMember(GroupMemberRecord(gid, dId, contactId = null, addedAt = 0L))            // self
        v.insertGroupMember(GroupMemberRecord(gid, aId, contactId = "A", addedAt = 0L))            // co-member
        v.insertGroupMember(GroupMemberRecord(gid, mId, contactId = "M", addedAt = 0L, tags = "")) // JOIN PENDING
        return v to gm
    }

    /** Co-member device A (paired with D and M); M unresolved here. */
    private fun coMemberDevice(): Pair<InMemoryVault, GroupManager> {
        val v = InMemoryVault()
        jpSeedContact(v, "D", sDA)
        jpSeedContact(v, "M", sAM)
        val gm = GroupManager(v, noTransport)
        v.insertGroup(GroupRecord(gid, "crew", epoch = 4L, adminMemberId = dId, myMemberId = aId, createdAt = 0L))
        v.insertGroupMember(GroupMemberRecord(gid, aId, contactId = null, addedAt = 0L))   // self
        v.insertGroupMember(GroupMemberRecord(gid, dId, contactId = "D", addedAt = 0L))   // admin
        v.insertGroupMember(GroupMemberRecord(gid, mId, contactId = null, addedAt = 0L))  // M unresolved
        return v to gm
    }

    /** Re-added member device M (paired with D and A); A unresolved here — the
     *  slot that must resolve, and the slot that stayed stuck on the device. */
    private fun newMemberDevice(): Pair<InMemoryVault, GroupManager> {
        val v = InMemoryVault()
        jpSeedContact(v, "D", sDM)
        jpSeedContact(v, "A", sAM)
        val gm = GroupManager(v, noTransport)
        v.insertGroup(GroupRecord(gid, "crew", epoch = 4L, adminMemberId = dId, myMemberId = mId, createdAt = 0L))
        v.insertGroupMember(GroupMemberRecord(gid, mId, contactId = null, addedAt = 0L))   // self
        v.insertGroupMember(GroupMemberRecord(gid, dId, contactId = "D", addedAt = 0L))   // admin (our inviter)
        v.insertGroupMember(GroupMemberRecord(gid, aId, contactId = null, addedAt = 0L))  // A unresolved
        return v to gm
    }

    // ---------------------------------------------------------------------
    // 1. REGRESSION ORACLE: the handoff before the join is ingested.
    // ---------------------------------------------------------------------

    @Test
    fun handoffBeforeTheJoinIsIngested_isRefused_andTheRosterItWouldHaveShippedIsTagless() {
        val (dv, dGm) = adminDevice()
        val (_, aGm) = coMemberDevice()
        val (mv, mGm) = newMemberDevice()

        // A's own join reaches D (the FIX-A self-join planted at the previous
        // handoff), so A's tags are present; M's join is still in flight.
        dGm.handleControl("A", gid, GroupManager.KIND_JOIN, aGm.buildJoinBody(gid, aId))
        assertTrue(dv.getGroupMembers(gid).first { it.memberId == aId }.tags.isNotEmpty(),
            "fixture precondition: the admin holds A's tags")
        assertEquals("", dv.getGroupMembers(gid).first { it.memberId == mId }.tags,
            "fixture precondition: M's join has NOT been applied")

        // THE OLD BEHAVIOUR, kept as a live oracle: the roster a pre-fix handoff
        // would have broadcast. Nothing is mutual with a member we have not heard
        // from, so A's entry ships with an EMPTY tag list…
        val prematureRoster = dGm.buildRosterBody(gid)
        assertNotNull(prematureRoster)
        assertTrue(prematureRoster.contains(jsonEscapeString("$aId:")),
            "A's entry must be present but carry no tags at all: $prematureRoster")

        // …and a peer applying it therefore stays unresolved — permanently, once
        // the sender has handed the role on and left.
        mGm.handleControl("D", gid, GroupManager.KIND_ROSTER, prematureRoster)
        assertNull(mv.getGroupMembers(gid).first { it.memberId == aId }.contactId,
            "the premature roster cannot resolve A — this is the stranding the guard prevents")

        // THE FIX: the handoff is refused, and nothing is persisted.
        assertFalse(dGm.transferAdmin(gid, mId),
            "transferAdmin must refuse while a member's join is still pending")
        val g = dv.getGroup(gid)!!
        assertEquals(dId, g.adminMemberId, "a refused transfer must not move the admin role")
        assertEquals(5L, g.epoch, "a refused transfer must not bump the epoch")
    }

    // ---------------------------------------------------------------------
    // 2. The joined flow: the transfer proceeds and the roster resolves.
    // ---------------------------------------------------------------------

    @Test
    fun handoffAfterTheJoinIsIngested_isAllowed_andItsRosterResolvesTheCoMember() {
        val (dv, dGm) = adminDevice()
        val (_, aGm) = coMemberDevice()
        val (mv, mGm) = newMemberDevice()

        dGm.handleControl("A", gid, GroupManager.KIND_JOIN, aGm.buildJoinBody(gid, aId))
        dGm.handleControl("M", gid, GroupManager.KIND_JOIN, mGm.buildJoinBody(gid, mId))
        assertTrue(dv.getGroupMembers(gid).first { it.memberId == mId }.tags.isNotEmpty(),
            "precondition: M's join was applied")

        // The roster this admin now advertises carries A's bound tag (the D<->A and
        // A<->M syms are both mutual), so the new member resolves A.
        val roster = dGm.buildRosterBody(gid)!!
        mGm.handleControl("D", gid, GroupManager.KIND_ROSTER, roster)
        assertEquals("A", mv.getGroupMembers(gid).first { it.memberId == aId }.contactId,
            "once the join is applied, the admin's roster must resolve the co-member")

        // And the handoff is no longer refused.
        assertTrue(dGm.transferAdmin(gid, mId),
            "with every join applied the transfer must proceed")
        assertEquals(mId, dv.getGroup(gid)!!.adminMemberId)
    }

    // ---------------------------------------------------------------------
    // 3. The predicate itself: FAST at t0, IDLE at t0 + 11 min (join-window bound).
    // ---------------------------------------------------------------------

    @Test
    fun adminAwaitingAJoin_isConvergingAtT0_andNotAfterTheScTwoWindow() {
        val (_, dGm) = adminDevice()
        // No unresolved (contactId == null) slot exists on this device: the ONLY
        // reason to report converging is the pending join.
        dGm.clockMs = { FIXED_NOW }
        assertTrue(dGm.hasUnresolvedMembers(),
            "an admin awaiting a join it solicited must keep the FAST control cadence")

        dGm.clockMs = { FIXED_NOW + 11L * 60 * 1000 }
        assertFalse(dGm.hasUnresolvedMembers(),
            "join bound: a join that never arrives must not pin fast-poll forever")
    }

    @Test
    fun aPlainMemberWithEmptyTags_neverReportsConverging() {
        // Non-admin devices store no tags at all (GroupMemberRecord.tags kdoc), so
        // the new clause MUST be admin-gated or every member would pin fast-poll.
        val (_, mGm) = newMemberDevice()
        mGm.clockMs = { FIXED_NOW }
        val g = GroupRecord(gid, "crew", epoch = 4L, adminMemberId = dId, myMemberId = mId, createdAt = 0L)
        val dRow = GroupMemberRecord(gid, dId, contactId = "D", addedAt = 0L, tags = "")
        assertFalse(mGm.joinPending(g, dRow, FIXED_NOW, anchor = 0L),
            "a non-admin device must never treat its own tagless rows as a pending join")
    }

    private companion object {
        /** Fixed, well inside UNRESOLVED_MEMBER_FAST_WINDOW_MS of the rows' addedAt = 0. */
        const val FIXED_NOW = 1_000L
    }
}

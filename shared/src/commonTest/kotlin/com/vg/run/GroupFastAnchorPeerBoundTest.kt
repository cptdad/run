package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// "Any paired co-member can keep a device on the fast
// control cadence / block transferAdmin".
//
// `GroupManager.ingest` used to call `noteUnresolvedFastAnchor(gid)` after ANY
// roster / leave / invite / join for a group this device holds — regardless of
// the handler's outcome or the sender — and `hasUnresolvedMembers()` measured
// its 10-minute join window from `max(anchor, addedAt)` with no age cap. A co-member
// pinging a no-op membership kind every few minutes therefore (a) kept
// `convergingNow` → FAST in `controlPollDelayMs` for the whole session, with no
// episode bound (CONTROL_FAST_EPISODE_MAX_MS applies only to the persistent
// window), and (b) held an admin's `joinPending` open so `transferAdmin` stayed
// refused for as long as the pings continued — breaking the join-window kdoc invariant
// "a chatty peer must not be able to hold the device on the 2.5–5 s cadence".
//
// The fix: re-anchor ONLY when the applied control CHANGED the convergence
// fingerprint (epoch / admin / member count / resolved count), and — defence in
// depth — cap anchor-driven fast time per group per episode at
// UNRESOLVED_FAST_EPISODE_MAX_MS from the first anchor of the episode, a new
// episode only after a whole quiet window. What this file pins:
//   • repeated NO-OP invite / roster / leave / join pings from a peer for a held
//     group do not move the anchor and do not keep hasUnresolvedMembers() true
//     past the window;
//   • an APPLIED change does re-anchor; the same roster re-applied unchanged
//     does not;
//   • a stream of applied changes cannot exceed the episode cap of fast time,
//     and a new episode needs a genuinely quiet window;
//   • transferAdmin's joinPending lapses once pings stop pulling the anchor
//     (and a live oracle shows the anchor IS the lever the pings used to pull);
//   • the existing join-window and handoff-guard pins (ControlConvergenceArmingTest,
//     GroupJoinPendingHandoffTest) stay green alongside.
// ---------------------------------------------------------------------------

private fun fbSeedContact(vault: InMemoryVault, contactId: String) {
    vault.insertContact(
        ContactRecord(
            contactId = contactId, sharedSecret = generateSecureRandom(32),
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

private fun fbControl(gid: String, kind: String, body: String, counter: Long) = ReceivedMessage(
    text = "", timestamp = 0L, counter = counter, groupId = gid, membershipHash = null,
    controlKind = kind, controlBody = body,
)

/** A full roster from the admin with the given epoch: APPLIED iff `ep >= epoch`. */
private fun fbRoster(adm: String, members: List<String>, ep: Long): String {
    val mem = members.joinToString(",") { jsonEscapeString("$it:") }
    return """{"n":"crew","ep":$ep,"adm":${jsonEscapeString(adm)},"mem":[$mem]}"""
}

private const val MIN = 60_000L

/**
 * Member-side device: joined via a real invite from `admin-contact`; `bob`'s slot
 * is UNRESOLVED (contactId == null). The clock is injected BEFORE the join so the
 * acceptInvite anchor and every later event sit on the same drivable clock; it
 * starts at the wall clock because acceptInvite stamps `addedAt` from it.
 */
private class FbMember(val vault: InMemoryVault, val gm: GroupManager, val gid: String,
                       val adm: String, val me: String, val bob: String) {
    var clock: Long = 0L
    private var counter = 0L
    fun ingestFrom(contactId: String, kind: String, body: String) {
        gm.ingest(contactId, listOf(fbControl(gid, kind, body, ++counter)), wantGroupId = null, bufferAll = true)
    }
    fun roster(ep: Long) = fbRoster(adm, listOf(adm, me, bob), ep)
}

private fun fbMember(): FbMember {
    val vault = InMemoryVault()
    fbSeedContact(vault, "admin-contact")
    fbSeedContact(vault, "bob-contact")
    fbSeedContact(vault, "stranger")
    val gm = GroupManager(vault) { null }
    val gid = GroupManager.newGroupId()
    val adm = groupMemberId(10); val me = groupMemberId(20); val bob = groupMemberId(30)
    val f = FbMember(vault, gm, gid, adm, me, bob)
    f.clock = currentTimeMillis()
    gm.clockMs = { f.clock }
    gm.handleControl(
        "admin-contact", gid, GroupManager.KIND_INVITE,
        """{"n":"crew","ep":1,"adm":${jsonEscapeString(adm)},"you":${jsonEscapeString(me)},""" +
            """"mem":[${jsonEscapeString(adm)},${jsonEscapeString(me)},${jsonEscapeString(bob)}]}""",
    )
    gm.acceptInvite(gid)
    assertTrue(gm.hasUnresolvedMembers(), "fixture precondition: bob's slot is unresolved and in-window")
    return f
}

// ===========================================================================

class GroupFastAnchorPeerBoundTest {

    // -----------------------------------------------------------------------
    // 1. No-op pings never move the anchor.
    // -----------------------------------------------------------------------

    @Test
    fun repeatedNoOpMembershipPings_doNotKeepTheFastWindowOpen() {
        val f = fbMember()
        f.clock += GroupManager.UNRESOLVED_MEMBER_FAST_WINDOW_MS + 1_000L
        assertFalse(f.gm.hasUnresolvedMembers(), "precondition: the join's own window has lapsed")

        // Every membership KIND, each one a no-op for this device, from a paired
        // co-member — the pre-fix code re-anchored on the mere arrival of each.
        val pings: List<Pair<String, Pair<String, String>>> = listOf(
            "admin-contact" to (GroupManager.KIND_ROSTER to "{}"),                       // malformed → dropped at "n"
            "admin-contact" to (GroupManager.KIND_ROSTER to f.roster(ep = 0)),           // stale epoch → dropped
            "bob-contact" to (GroupManager.KIND_ROSTER to f.roster(ep = 2)),             // non-admin channel → dropped
            "admin-contact" to (GroupManager.KIND_INVITE to """{"n":"crew","ep":1}"""),  // already a member → ignored
            "bob-contact" to (GroupManager.KIND_JOIN to """{"you":"x","tags":[]}"""),    // we are not admin → ignored
            "stranger" to (GroupManager.KIND_LEAVE to "{}"),                             // not a member → ignored
        )
        val fingerprintBefore = f.vault.getGroup(f.gid)!!.epoch to f.vault.getGroupMembers(f.gid).size
        // One ping a minute for a quarter of an hour (any of the six, round-robin).
        repeat(15) { n ->
            f.clock += MIN
            val (from, kb) = pings[n % pings.size]
            f.ingestFrom(from, kb.first, kb.second)
            assertFalse(
                f.gm.hasUnresolvedMembers(),
                "ping #$n (${kb.first} from $from) converges nothing and must not re-open the fast window",
            )
        }
        assertEquals(
            fingerprintBefore,
            f.vault.getGroup(f.gid)!!.epoch to f.vault.getGroupMembers(f.gid).size,
            "sanity: none of the pings changed group state",
        )
    }

    // -----------------------------------------------------------------------
    // 2. An applied change does re-anchor; an unchanged re-apply does not.
    // -----------------------------------------------------------------------

    @Test
    fun anAppliedChange_reAnchors_butTheSameRosterReAppliedUnchanged_doesNot() {
        val f = fbMember()
        f.clock += GroupManager.UNRESOLVED_MEMBER_FAST_WINDOW_MS + 1_000L
        assertFalse(f.gm.hasUnresolvedMembers())

        // epoch 1 → 2 from the admin's channel: APPLIED, fingerprint moves.
        f.ingestFrom("admin-contact", GroupManager.KIND_ROSTER, f.roster(ep = 2))
        assertEquals(2L, f.vault.getGroup(f.gid)!!.epoch, "precondition: the roster applied")
        assertTrue(f.gm.hasUnresolvedMembers(), "an applied change must re-anchor the join window")

        // Just inside the re-anchored window the SAME roster lands again. handleRoster
        // applies it (ep == epoch is not stale) but nothing changes — a replay from
        // the relay, or an admin re-sending — so it must NOT buy another window.
        f.clock += GroupManager.UNRESOLVED_MEMBER_FAST_WINDOW_MS - 1_000L
        assertTrue(f.gm.hasUnresolvedMembers(), "still inside the window the applied change opened")
        f.ingestFrom("admin-contact", GroupManager.KIND_ROSTER, f.roster(ep = 2))
        f.clock += 2_000L
        assertFalse(
            f.gm.hasUnresolvedMembers(),
            "an unchanged re-apply converges nothing and must not extend the window",
        )
    }

    // -----------------------------------------------------------------------
    // 3. The episode cap bounds even a stream of APPLIED changes.
    // -----------------------------------------------------------------------

    @Test
    fun aStreamOfAppliedChanges_cannotExceedTheEpisodeCap_andNeedsAQuietWindowToRestart() {
        val f = fbMember()
        val t0 = f.clock   // the join's own anchor opened the episode
        val cap = GroupManager.UNRESOLVED_FAST_EPISODE_MAX_MS
        assertEquals(MessageManager.CONTROL_FAST_EPISODE_MAX_MS, cap, "mirrors the peer-noise episode bound")

        // An admin flapping the epoch: one APPLIED roster every 3 minutes. Each one
        // moves the fingerprint, so each one used to re-anchor — an unbounded fast
        // cadence for as long as the admin kept flapping.
        var ep = 1L
        for (minute in listOf(3L, 6L, 9L)) {
            f.clock = t0 + minute * MIN
            f.ingestFrom("admin-contact", GroupManager.KIND_ROSTER, f.roster(ep = ++ep))
            assertTrue(f.gm.hasUnresolvedMembers(), "inside the episode at +$minute min")
        }
        f.clock = t0 + cap - 1_000L
        assertTrue(f.gm.hasUnresolvedMembers(), "one second before the cap")
        // Without the cap the +9 min roster would have held FAST until +19 min.
        f.clock = t0 + cap + 1_000L
        assertFalse(f.gm.hasUnresolvedMembers(), "the episode cap ends anchor-driven fast time regardless of re-anchors")

        // A further applied change INSIDE the (now spent) episode restarts nothing:
        // the previous anchor (+9 min) is less than a window old, so this is not a
        // quiet gap — it is the same stream continuing.
        f.clock = t0 + 12 * MIN
        f.ingestFrom("admin-contact", GroupManager.KIND_ROSTER, f.roster(ep = ++ep))
        assertEquals(ep, f.vault.getGroup(f.gid)!!.epoch, "the roster still APPLIES — only the cadence is bounded")
        f.clock = t0 + 12 * MIN + 30_000L
        assertFalse(f.gm.hasUnresolvedMembers(), "an applied change inside a spent episode buys no fast time")

        // A genuinely quiet gap — a whole window with no anchor — then a new applied
        // change opens a fresh, equally bounded episode.
        f.clock = t0 + 12 * MIN + GroupManager.UNRESOLVED_MEMBER_FAST_WINDOW_MS
        f.ingestFrom("admin-contact", GroupManager.KIND_ROSTER, f.roster(ep = ++ep))
        val t1 = f.clock
        f.clock = t1 + 30_000L
        assertTrue(f.gm.hasUnresolvedMembers(), "after a quiet window a real change opens a new episode")
        f.clock = t1 + cap + 1_000L
        assertFalse(f.gm.hasUnresolvedMembers(), "…which is bounded exactly like the first")
    }

    @Test
    fun theEpisodeStart_isRamOnly_scrubbedWithTheAnchor() {
        val f = fbMember()
        f.clock += 5 * MIN
        f.ingestFrom("admin-contact", GroupManager.KIND_ROSTER, f.roster(ep = 2))
        f.gm.scrubInMemory()
        // A fresh session starts from the persisted addedAt alone: still inside
        // addedAt's own window here, and nothing anchor-related survived.
        assertTrue(f.gm.hasUnresolvedMembers(), "addedAt alone still answers inside its window")
        f.clock += GroupManager.UNRESOLVED_MEMBER_FAST_WINDOW_MS
        assertFalse(f.gm.hasUnresolvedMembers(), "no anchor or episode survived the scrub")
    }

    // -----------------------------------------------------------------------
    // 4. transferAdmin (handoff guard): joinPending lapses once pings stop pulling the
    //    anchor — a co-member can no longer veto the handoff by pinging.
    // -----------------------------------------------------------------------

    private val gid = GroupManager.newGroupId()
    private val dId = groupMemberId(1)   // D — the admin under test
    private val aId = groupMemberId(2)   // A — a joined co-member
    private val mId = groupMemberId(3)   // M — added by contact, join NOT yet ingested

    /** Admin device D of {D, A, M}: A's join landed (tags present); M's is pending. */
    private fun adminDevice(): Pair<InMemoryVault, GroupManager> {
        val v = InMemoryVault()
        fbSeedContact(v, "A")
        fbSeedContact(v, "M")
        val gm = GroupManager(v) { null }
        v.insertGroup(GroupRecord(gid, "crew", epoch = 5L, adminMemberId = dId, myMemberId = dId, createdAt = 0L))
        v.insertGroupMember(GroupMemberRecord(gid, dId, contactId = null, addedAt = 0L))
        v.insertGroupMember(GroupMemberRecord(gid, aId, contactId = "A", addedAt = 0L, tags = "deadbeef:cafebabe"))
        v.insertGroupMember(GroupMemberRecord(gid, mId, contactId = "M", addedAt = 0L, tags = ""))
        return v to gm
    }

    @Test
    fun transferAdmin_joinPendingLapses_despiteACoMemberPingingNoOpMembershipKinds() {
        val (v, gm) = adminDevice()
        var clock = 1_000L
        gm.clockMs = { clock }
        assertFalse(gm.transferAdmin(gid, aId), "precondition: refused while M's join is pending")

        // A pings a roster every minute. On an ADMIN a peer's roster is always
        // dropped ("roster from non-admin channel") — a pure no-op — yet before
        // the fix each arrival re-anchored the group and kept joinPending alive.
        var counter = 0L
        repeat(12) {
            clock += MIN
            gm.ingest(
                "A", listOf(fbControl(gid, GroupManager.KIND_ROSTER, fbRoster(aId, listOf(dId, aId, mId), ep = 6), ++counter)),
                wantGroupId = null, bufferAll = true,
            )
        }
        assertEquals(5L, v.getGroup(gid)!!.epoch, "sanity: no ping was applied")
        assertEquals(dId, v.getGroup(gid)!!.adminMemberId)

        // 12 min after M was added, with nothing applied since: the window lapsed.
        assertFalse(gm.hasUnresolvedMembers(), "the pings must not have kept joinPending alive")
        assertTrue(gm.transferAdmin(gid, aId), "the handoff proceeds once the join window has genuinely lapsed")
        assertEquals(aId, v.getGroup(gid)!!.adminMemberId)
    }

    @Test
    fun oracle_theAnchorIsTheLeverThePingsUsedToPull() {
        // Same device, same clock — but this time the anchor IS moved (the exact
        // effect every ping used to have). The handoff is then refused again,
        // proving the fix above is doing the work, not the fixture.
        var clock = 1_000L + 12 * MIN
        val (_, gm2) = adminDevice()
        gm2.clockMs = { clock }
        assertTrue(gm2.transferAdmin(gid, aId), "control: with the window lapsed and no anchor the handoff proceeds")
        // Fresh device in the same state, now WITH the anchor pulled.
        val (_, gm3) = adminDevice()
        gm3.clockMs = { clock }
        gm3.noteUnresolvedFastAnchor(gid)   // what ingest did unconditionally pre-fix
        assertTrue(gm3.hasUnresolvedMembers(), "a moved anchor re-opens joinPending")
        assertFalse(gm3.transferAdmin(gid, aId), "…and blocks the handoff — the lever the pings no longer reach")
        // And even that lever is now episode-bounded: pulled again at +9 min, it
        // still runs out at the cap and the handoff proceeds.
        clock += 9 * MIN; gm3.noteUnresolvedFastAnchor(gid)
        clock += GroupManager.UNRESOLVED_FAST_EPISODE_MAX_MS - 9 * MIN + 1_000L
        assertFalse(gm3.hasUnresolvedMembers(), "anchor-driven joinPending ends at the episode cap")
        assertTrue(gm3.transferAdmin(gid, aId))
    }
}

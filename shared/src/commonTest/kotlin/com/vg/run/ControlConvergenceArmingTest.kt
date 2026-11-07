package com.vg.run

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// The 2026-09-17 convergence fixes (physical cross:multi3 triage).
//
// Fix 3b (IDLE 25–45 s → 60–90 s) is correct and its constants are untouched.
// What it exposed is that TWO predicates both answer "not converging" in
// exactly the state where convergence is pending, so a group chain that fell
// out of the fast window then paid the new idle interval at every remaining
// hop:
//
//   1. GroupManager.noteControlConvergence gated on isKnownGroupMember alone,
//      which tests `member.contactId == contactId` — FALSE for the very peer
//      whose member slot is UNRESOLVED (that slot's contactId IS null) and
//      false for a first group INVITE (parked for consent, no member row yet).
//   2. The 10-minute join window was measured from `member.addedAt` alone, which
//      handleRoster deliberately PRESERVES across every later roster and which
//      is persisted — so it meant "how long ago this SLOT was created", not
//      "how long this chain has been converging". Observed on-device: the
//      cadence dropped from ~11 s to a single 95 s gap at exactly
//      `addedAt + UNRESOLVED_MEMBER_FAST_WINDOW_MS`.
//
// What this file pins, and the episode-ceiling / join-window anti-pins that must survive both:
//   • a membership kind from an UNRESOLVED co-member arms the window;
//   • a membership kind while an invite from that contact is parked arms it;
//   • a NON-membership kind never arms it;
//   • a contact in no group, with no unresolved member and no parked invite,
//     never arms it (this was THE pin);
//   • an applied membership control re-anchors the 10-minute join window;
//   • with NO membership event the window still expires on `addedAt`
//     (a never-IRL-paired member must not pin fast-poll forever);
//   • the anchor is RAM-only and session-scoped (scrubInMemory drops it);
//   • controlPollDelayMs stays inside its documented FAST / IDLE bounds.
// ---------------------------------------------------------------------------

private fun seedCvContact(vault: InMemoryVault, contactId: String) {
    vault.insertContact(
        ContactRecord(
            contactId = contactId, sharedSecret = generateSecureRandom(32),
            trustLevel = 1, alias = "A-$contactId", aliasLastRotated = 0L,
        )
    )
}

/** A transport double that answers nothing — arming never needs the network. */
private fun cvRelay() = FakeRelayHttp(
    onPut = { HttpResult(code = 200, body = "", isSuccess = true) },
    onDelete = { HttpResult(code = 200, body = "", isSuccess = true) },
    onGet = { RELAY_EMPTY_DRAIN },
)

/** Member-side group whose co-member `bob` is deliberately left UNRESOLVED. */
private class CvFixture(
    val vault: InMemoryVault, val gm: GroupManager, val mgr: MessageManager,
    val gid: String, val adm: String, val me: String, val bob: String,
)

private fun cvUnresolvedFixture(): CvFixture {
    val vault = InMemoryVault()
    seedCvContact(vault, "admin-contact")
    seedCvContact(vault, "bob-contact")
    val mgr = MessageManager(vault, "http://relay.test", cvRelay())
    // The transport is attached only AFTER the fixture is built: acceptInvite fans out
    // a KIND_JOIN, and a successful control SEND legitimately arms the window
    // (sendEnvelopeSerialized). Every assertion below must observe arming caused by the
    // RECEIVE path alone.
    var transport: MessageManager? = null
    val gm = GroupManager(vault) { transport }
    val gid = GroupManager.newGroupId()
    val adm = groupMemberId(10); val me = groupMemberId(20); val bob = groupMemberId(30)
    gm.handleControl(
        "admin-contact", gid, GroupManager.KIND_INVITE,
        """{"n":"crew","ep":1,"adm":${jsonEscapeString(adm)},"you":${jsonEscapeString(me)},""" +
            """"mem":[${jsonEscapeString(adm)},${jsonEscapeString(me)},${jsonEscapeString(bob)}]}""",
    )
    gm.acceptInvite(gid)
    transport = mgr
    // bob's slot exists with contactId == null: the admin has not redistributed a
    // tag that resolves him yet. This is the state the arming predicate was blind to.
    return CvFixture(vault, gm, mgr, gid, adm, me, bob)
}

private fun rosterFrom(gid: String, hash: String?, counter: Long) = ReceivedMessage(
    text = "", timestamp = 0L, counter = counter, groupId = gid, membershipHash = hash,
    controlKind = GroupManager.KIND_ROSTER, controlBody = "{}",
)

// ===========================================================================

class ControlConvergenceArmingTest {

    @Test
    fun membershipKindFromAnUnresolvedCoMember_armsTheWindow() {
        val f = cvUnresolvedFixture()
        assertTrue(f.gm.hasUnresolvedMembers(), "fixture precondition: bob's slot is unresolved")
        assertFalse(f.mgr.isControlConverging(), "a fresh manager must not claim to be converging")

        // bob is a MEMBER but an UNRESOLVED one, so `member.contactId == "bob-contact"`
        // is false for every row — the exact case isKnownGroupMember could not see.
        f.gm.ingest("bob-contact", listOf(rosterFrom(f.gid, null, 1)), wantGroupId = null, bufferAll = true)
        assertTrue(
            f.mgr.isControlConverging(),
            "a roster from the peer we are still trying to resolve must arm the fast window",
        )
    }

    @Test
    fun membershipKindWhileAnInviteFromThatContactIsParked_armsTheWindow() {
        val vault = InMemoryVault()
        seedCvContact(vault, "inviter")
        val mgr = MessageManager(vault, "http://relay.test", cvRelay())
        val gm = GroupManager(vault) { mgr }
        val gid = GroupManager.newGroupId()
        val adm = groupMemberId(40); val me = groupMemberId(50)
        assertFalse(mgr.isControlConverging())

        // The invite is PARKED for consent, so no member row exists at all — the second
        // case isKnownGroupMember could not see. The first hop of every group join.
        gm.ingest(
            "inviter",
            listOf(
                ReceivedMessage(
                    "", 0L, counter = 1, groupId = gid,
                    controlKind = GroupManager.KIND_INVITE,
                    controlBody = """{"n":"crew","ep":1,"adm":${jsonEscapeString(adm)},""" +
                        """"you":${jsonEscapeString(me)},"mem":[${jsonEscapeString(adm)},${jsonEscapeString(me)}]}""",
                )
            ),
            wantGroupId = null, bufferAll = true,
        )
        assertTrue(gm.pendingInvites().any { it.groupId == gid }, "precondition: the invite parked")
        assertTrue(mgr.isControlConverging(), "the invite that starts the chain must arm the fast window")
    }

    @Test
    fun nonMembershipKindFromTheSameContact_neverArms_p2m2Pin() {
        val f = cvUnresolvedFixture()
        assertTrue(f.gm.hasUnresolvedMembers())
        // An activity notice is the frequent kind this guard exists to keep OUT of the
        // arming path; it must stay out even though this device has unresolved members.
        f.gm.ingest(
            "bob-contact",
            listOf(
                ReceivedMessage(
                    "", 0L, counter = 1, groupId = f.gid,
                    controlKind = GroupManager.KIND_ACTIVITY, controlBody = "{}",
                )
            ),
            wantGroupId = null, bufferAll = true,
        )
        assertFalse(f.mgr.isControlConverging(), "only a MEMBERSHIP kind may arm the window")
    }

    @Test
    fun strangerWithNoGroupNoUnresolvedMemberNoParkedInvite_neverArms_p2m2Pin() {
        val vault = InMemoryVault()
        seedCvContact(vault, "stranger")
        val mgr = MessageManager(vault, "http://relay.test", cvRelay())
        val gm = GroupManager(vault) { mgr }
        assertFalse(gm.hasUnresolvedMembers(), "precondition: nothing is converging")

        // A membership kind for a groupId we do not know, from a contact that is in no
        // group with us and has no invite awaiting consent. THIS is the pin: the old
        // the old code let one such blob a minute hold the device on 2.5–5 s sweeps.
        repeat(5) { n ->
            gm.ingest(
                "stranger",
                listOf(rosterFrom(GroupManager.newGroupId(), null, (n + 1).toLong())),
                wantGroupId = null, bufferAll = true,
            )
        }
        assertFalse(mgr.isControlConverging(), "a stranger's control traffic must arm nothing")
    }
}

// ===========================================================================

class GroupUnresolvedFastWindowTest {

    @Test
    fun withNoMembershipEvent_theWindowStillExpiresOnAddedAt_sc2Pin() {
        val f = cvUnresolvedFixture()
        var clock = currentTimeMillis()
        f.gm.clockMs = { clock }
        assertTrue(f.gm.hasUnresolvedMembers(), "inside the window")

        // A member you never IRL-paired with is NEVER resolvable, and nothing about it
        // moves. It must stop pinning fast-poll, or the device becomes a permanent
        // ~2.5–5 s Tor beacon.
        clock += GroupManager.UNRESOLVED_MEMBER_FAST_WINDOW_MS + 1_000L
        assertFalse(
            f.gm.hasUnresolvedMembers(),
            "an inert unresolved member must not pin the fast cadence forever",
        )
    }

    @Test
    fun anAppliedMembershipControl_reAnchorsTheWindow() {
        val f = cvUnresolvedFixture()
        var clock = currentTimeMillis()
        f.gm.clockMs = { clock }

        // Run the slot past its addedAt-based expiry: this is the state the Android
        // seat was in when its cadence fell to the 60–90 s idle mid-convergence.
        clock += GroupManager.UNRESOLVED_MEMBER_FAST_WINDOW_MS + 1_000L
        assertFalse(f.gm.hasUnresolvedMembers())

        // A membership control lands and is APPLIED — the chain is demonstrably still
        // moving, so the 10-minute window re-opens from HERE. It has
        // to be a roster that actually CHANGES group state (here: epoch 1 → 2 from
        // the admin's channel) — a `{}` roster is dropped by handleRoster and, since
        // the fix, re-anchors nothing (see GroupFastAnchorPeerBoundTest).
        val applied = ReceivedMessage(
            text = "", timestamp = 0L, counter = 1, groupId = f.gid, membershipHash = null,
            controlKind = GroupManager.KIND_ROSTER,
            controlBody = """{"n":"crew","ep":2,"adm":${jsonEscapeString(f.adm)},"mem":[""" +
                """${jsonEscapeString("${f.adm}:")},${jsonEscapeString("${f.me}:")},${jsonEscapeString("${f.bob}:")}]}""",
        )
        f.gm.ingest("admin-contact", listOf(applied), wantGroupId = null, bufferAll = true)
        assertTrue(f.gm.hasUnresolvedMembers(), "an applied membership control must re-anchor the join window")

        // …and the re-anchor is itself bounded by exactly one window, not open-ended.
        clock += GroupManager.UNRESOLVED_MEMBER_FAST_WINDOW_MS - 1_000L
        assertTrue(f.gm.hasUnresolvedMembers(), "still inside the re-anchored window")
        clock += 2_000L
        assertFalse(f.gm.hasUnresolvedMembers(), "one event buys ONE window, never a standing one")
    }

    @Test
    fun theAnchorIsRamOnlyAndSessionScoped() {
        val f = cvUnresolvedFixture()
        var clock = currentTimeMillis()
        f.gm.clockMs = { clock }
        clock += GroupManager.UNRESOLVED_MEMBER_FAST_WINDOW_MS + 1_000L
        f.gm.noteUnresolvedFastAnchor(f.gid)
        assertTrue(f.gm.hasUnresolvedMembers())

        // scrubInMemory runs on every lock / background teardown. A fresh session must
        // start from the PERSISTED addedAt alone — a durable anchor could be re-armed
        // by a peer forever, which is precisely what the join-window bound forbids.
        f.gm.scrubInMemory()
        assertFalse(f.gm.hasUnresolvedMembers(), "the anchor must not survive a session teardown")
    }

    @Test
    fun controlPollDelayMs_staysInsideItsDocumentedBounds() {
        val mgr = MessageManager(InMemoryVault(), "http://relay.test", cvRelay())
        // FIX 3b's constants are NOT moved by either fix above.
        repeat(40) {
            val idle = mgr.controlPollDelayMs(convergingNow = false)
            assertTrue(
                idle >= MessageManager.CONTROL_POLL_IDLE_BASE_MS &&
                    idle < MessageManager.CONTROL_POLL_IDLE_BASE_MS + MessageManager.CONTROL_POLL_IDLE_JITTER_MS,
                "idle cadence out of the 60–90 s band: $idle",
            )
            val fast = mgr.controlPollDelayMs(convergingNow = true)
            assertTrue(
                fast >= MessageManager.CONTROL_POLL_FAST_BASE_MS &&
                    fast < MessageManager.CONTROL_POLL_FAST_BASE_MS + MessageManager.CONTROL_POLL_FAST_JITTER_MS,
                "fast cadence out of the 2.5–5 s band: $fast",
            )
        }
        // convergingNow is a PER-CYCLE answer and must still not arm the persistent
        // window — that is what keeps hasUnresolvedMembers from disabling the
        // peek-before-drain for every contact.
        assertFalse(mgr.isControlConverging())
    }
}

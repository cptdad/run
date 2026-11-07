package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// GroupManager membership / protocol EDGE cases.
//
// Complements GroupManagerTest.kt (receive-side happy paths + crypto helpers)
// and GroupManagerGuardsTest.kt (admin-op guards + the main validation
// branches). This file pins the branches neither covers:
//
//   • handleRoster epoch edges — same-epoch redelivery, the exact
//     MAX_GROUP_EPOCH_ADVANCE boundary, and the ABSOLUTE MAX_GROUP_EPOCH cap
//     re-enforced on the roster path, not just at invite.
//   • handleRoster content edges — rename propagation + truncation, the
//     entries-size cap, a roster that INTRODUCES a new member slot, the
//     one-contact-backs-one-member dedup, and the parked-buffer scrub when a
//     roster removes US.
//   • handleInvite edges — missing/malformed fields, an unknown sender,
//     re-send dedup (and that a dedup consumes no rate budget), and the
//     clock-rollback (future-stamp) behaviour of the invite rate window.
//   • Persist-FAILURE paths (createGroup / acceptInvite / addMember /
//     removeMember with a throwing vault) — fail closed, stay retryable.
//   • buildJoinBody's TAG_PAD_MULTIPLE padding privacy property and the
//     GROUP-3 tag-pair shape validation.
//
// Everything here drives the protocol with a NULL transport (fan-out is a
// logged no-op; persistence and guard outcomes stay observable), exactly like
// the sibling files. No AES-GCM is involved, so no bridge guard is needed.
// ---------------------------------------------------------------------------

private fun seedEcPaired(vault: InMemoryVault, contactId: String, secret: ByteArray = generateSecureRandom(32)) {
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

private fun ecInvite(adm: String, you: String, mem: List<String>, ep: Long = 1, name: String = "crew"): String {
    val memJson = mem.joinToString(",") { jsonEscapeString(it) }
    return """{"n":${jsonEscapeString(name)},"ep":$ep,"adm":${jsonEscapeString(adm)},"you":${jsonEscapeString(you)},"mem":[$memJson]}"""
}

private fun ecRoster(adm: String, entries: List<String>, ep: Long = 2, name: String = "crew"): String {
    val mem = entries.joinToString(",") { jsonEscapeString(it) }
    return """{"n":${jsonEscapeString(name)},"ep":$ep,"adm":${jsonEscapeString(adm)},"mem":[$mem]}"""
}

/** Member-side fixture joined via a real invite (admin + me + bob, bob unresolved). */
private class EcJoined(
    val vault: InMemoryVault, val gm: GroupManager, val gid: String,
    val adm: String, val me: String, val bob: String,
)

private fun ecJoinedFixture(): EcJoined {
    val vault = InMemoryVault()
    seedEcPaired(vault, "admin-contact")
    val gm = GroupManager(vault) { null }
    val gid = GroupManager.newGroupId()
    val adm = groupMemberId(10); val me = groupMemberId(20); val bob = groupMemberId(30)
    gm.handleControl(
        "admin-contact", gid, GroupManager.KIND_INVITE,
        ecInvite(adm, me, listOf(adm, me, bob)),
    )
    gm.acceptInvite(gid)   // GROUP-1 consent gate
    return EcJoined(vault, gm, gid, adm, me, bob)
}

// ===========================================================================
// handleRoster — epoch edges
// ===========================================================================

class GroupRosterEpochEdgeTest {

    @Test
    fun roster_sameEpoch_isAccepted_forIdempotentRedelivery() {
        // ep == g.epoch is NOT stale (only ep < g.epoch is): the admin's roster
        // may be redelivered/reapplied at the same epoch, and the envelope-level
        // counter+epoch anti-replay already stops third-party replays. Pin the
        // >= semantics so a refactor to a strict > doesn't silently break
        // redelivery convergence.
        val f = ecJoinedFixture()   // epoch 1
        f.gm.handleControl("admin-contact", f.gid, GroupManager.KIND_ROSTER,
            ecRoster(f.adm, listOf("${f.adm}:", "${f.me}:"), ep = 1))
        assertEquals(1L, f.vault.getGroup(f.gid)!!.epoch, "same-epoch roster applies without bumping")
        assertTrue(f.vault.getGroupMembers(f.gid).none { it.memberId == f.bob },
            "the same-epoch roster's membership change must apply")
    }

    @Test
    fun roster_epochAdvance_exactCapAccepted_justPastCapDropped() {
        // Epoch-advance boundary: a jump of exactly MAX_GROUP_EPOCH_ADVANCE is legal;
        // one more is dropped.
        val ok = ecJoinedFixture()   // epoch 1
        val atCap = 1L + GroupManager.MAX_GROUP_EPOCH_ADVANCE
        ok.gm.handleControl("admin-contact", ok.gid, GroupManager.KIND_ROSTER,
            ecRoster(ok.adm, listOf("${ok.adm}:", "${ok.me}:", "${ok.bob}:"), ep = atCap))
        assertEquals(atCap, ok.vault.getGroup(ok.gid)!!.epoch, "advance of exactly the cap must apply")

        val bad = ecJoinedFixture()   // epoch 1
        bad.gm.handleControl("admin-contact", bad.gid, GroupManager.KIND_ROSTER,
            ecRoster(bad.adm, listOf("${bad.adm}:", "${bad.me}:", "${bad.bob}:"), ep = atCap + 1))
        assertEquals(1L, bad.vault.getGroup(bad.gid)!!.epoch, "advance of cap+1 must be dropped")
    }

    @Test
    fun roster_aboveAbsoluteEpochCap_isDropped_evenWithATinyJump() {
        // The ABSOLUTE MAX_GROUP_EPOCH cap holds on the
        // roster path too — a group already sitting at the cap must reject a
        // +1 roster (which sails through the ADVANCE check) or the invariant
        // documented at MAX_GROUP_EPOCH stops holding everywhere.
        val vault = InMemoryVault()
        seedEcPaired(vault, "admin-contact")
        val gm = GroupManager(vault) { null }
        val gid = GroupManager.newGroupId()
        val adm = groupMemberId(10); val me = groupMemberId(20)
        vault.insertGroup(GroupRecord(gid, "crew", GroupManager.MAX_GROUP_EPOCH, adminMemberId = adm, myMemberId = me, createdAt = 0L))
        vault.insertGroupMember(GroupMemberRecord(gid, adm, "admin-contact", 0L))
        vault.insertGroupMember(GroupMemberRecord(gid, me, null, 0L))

        // AT the cap: a same-epoch roster still applies (rename observable).
        gm.handleControl("admin-contact", gid, GroupManager.KIND_ROSTER,
            ecRoster(adm, listOf("$adm:", "$me:"), ep = GroupManager.MAX_GROUP_EPOCH, name = "still-fine"))
        assertEquals("still-fine", vault.getGroup(gid)!!.name)

        // ONE past the cap: dropped, state untouched.
        gm.handleControl("admin-contact", gid, GroupManager.KIND_ROSTER,
            ecRoster(adm, listOf("$adm:", "$me:"), ep = GroupManager.MAX_GROUP_EPOCH + 1, name = "poisoned"))
        assertEquals(GroupManager.MAX_GROUP_EPOCH, vault.getGroup(gid)!!.epoch)
        assertEquals("still-fine", vault.getGroup(gid)!!.name, "an above-cap roster must not apply anything")
    }
}

// ===========================================================================
// handleRoster — content edges
// ===========================================================================

class GroupRosterContentEdgeTest {

    @Test
    fun roster_renamesTheGroup_andTruncatesAnOverlongName() {
        val f = ecJoinedFixture()
        f.gm.handleControl("admin-contact", f.gid, GroupManager.KIND_ROSTER,
            ecRoster(f.adm, listOf("${f.adm}:", "${f.me}:", "${f.bob}:"), ep = 2, name = "renamed-crew"))
        assertEquals("renamed-crew", f.vault.getGroup(f.gid)!!.name, "a valid roster renames the group")

        val long = "y".repeat(GroupManager.MAX_GROUP_NAME_CHARS + 30)
        f.gm.handleControl("admin-contact", f.gid, GroupManager.KIND_ROSTER,
            ecRoster(f.adm, listOf("${f.adm}:", "${f.me}:", "${f.bob}:"), ep = 3, name = long))
        assertEquals(GroupManager.MAX_GROUP_NAME_CHARS, f.vault.getGroup(f.gid)!!.name.length,
            "a peer-supplied roster name is capped for display sanity")
    }

    @Test
    fun roster_blankName_keepsTheExistingName() {
        // Blank-name invariant: a roster whose "n" is blank/whitespace-only must
        // KEEP the group's current name — a rename to blank on every device on every
        // roster is the bug — while STILL applying its membership + epoch change. The
        // blank name must NOT drop the whole roster (that would silently freeze
        // membership). Sibling of roster_renamesTheGroup_andTruncatesAnOverlongName.
        for (blank in listOf("", "   ", "\t\n ")) {
            val f = ecJoinedFixture()   // name "crew", epoch 1, members: adm + me + bob
            assertEquals("crew", f.vault.getGroup(f.gid)!!.name, "fixture starts named 'crew'")
            // A blank-name roster at ep 2 that ALSO drops bob (a real membership change).
            f.gm.handleControl("admin-contact", f.gid, GroupManager.KIND_ROSTER,
                ecRoster(f.adm, listOf("${f.adm}:", "${f.me}:"), ep = 2, name = blank))
            val g = f.vault.getGroup(f.gid)!!
            assertEquals("crew", g.name, "a blank roster name must keep the existing group name")
            assertEquals(2L, g.epoch, "the roster's epoch bump must still apply on a blank name")
            assertTrue(f.vault.getGroupMembers(f.gid).none { it.memberId == f.bob },
                "the roster's membership change (bob removed) must still apply on a blank name")
        }
    }

    @Test
    fun roster_tooManyEntries_isRejected() {
        val f = ecJoinedFixture()
        // MAX_GROUP_MEMBERS + 1 entries (adm + me + 63 fillers) → whole roster dropped.
        val fillers = (0 until GroupManager.MAX_GROUP_MEMBERS - 1).map { "${groupMemberId(100 + it * 9)}:" }
        val entries = listOf("${f.adm}:", "${f.me}:") + fillers
        assertTrue(entries.size > GroupManager.MAX_GROUP_MEMBERS)
        f.gm.handleControl("admin-contact", f.gid, GroupManager.KIND_ROSTER, ecRoster(f.adm, entries, ep = 2))
        assertEquals(1L, f.vault.getGroup(f.gid)!!.epoch, "an over-cap roster must be dropped whole")
        assertEquals(3, f.vault.getGroupMembers(f.gid).size)
    }

    @Test
    fun roster_introducesANewMemberSlot_andResolvesItViaBoundTag() {
        // A member added by the admin AFTER our invite arrives as a brand-new
        // roster slot (no local row). It must be INSERTED — and resolved right
        // away when we hold the pairing that recomputes its bound tag.
        val f = ecJoinedFixture()
        val daveSecret = generateSecureRandom(32)
        seedEcPaired(f.vault, "dave-contact", daveSecret)
        val dave = groupMemberId(40)
        val daveTag = GroupManager.boundTag(daveSecret, f.gid, dave)
        f.gm.handleControl("admin-contact", f.gid, GroupManager.KIND_ROSTER,
            ecRoster(f.adm, listOf("${f.adm}:", "${f.me}:", "${f.bob}:", "$dave:$daveTag"), ep = 2))
        val members = f.vault.getGroupMembers(f.gid)
        assertEquals(4, members.size, "the roster must insert the new member slot")
        assertEquals("dave-contact", members.first { it.memberId == dave }.contactId,
            "the new slot must resolve via its bound tag")
    }

    @Test
    fun roster_duplicateContactClaim_resolvesOnlyTheFirstSlot() {
        // One contact backs at most ONE member. A roster carrying two slots that
        // both resolve to the same contact (each tag correctly bound to its own
        // slot — only reachable when the contact colludes or the admin misbehaves)
        // must resolve exactly one slot and leave the other unresolved.
        val f = ecJoinedFixture()
        val bobSecret = generateSecureRandom(32)
        seedEcPaired(f.vault, "bob-contact", bobSecret)
        val ghost = groupMemberId(77)
        val tagBob = GroupManager.boundTag(bobSecret, f.gid, f.bob)
        val tagGhost = GroupManager.boundTag(bobSecret, f.gid, ghost)
        f.gm.handleControl("admin-contact", f.gid, GroupManager.KIND_ROSTER,
            ecRoster(f.adm, listOf("${f.adm}:", "${f.me}:", "${f.bob}:$tagBob", "$ghost:$tagGhost"), ep = 2))
        val members = f.vault.getGroupMembers(f.gid)
        assertEquals(1, members.count { it.contactId == "bob-contact" },
            "one contact must never back two member slots")
        assertEquals("bob-contact", members.first { it.memberId == f.bob }.contactId)
        assertNull(members.first { it.memberId == ghost }.contactId, "the duplicate claim stays unresolved")
    }

    @Test
    fun roster_removingUs_alsoDropsParkedGroupMessages() {
        // RAM hygiene sibling of roster_omittingUs_deletesGroupLocally: the
        // parked pendingGroup plaintext for that group must go with it.
        val f = ecJoinedFixture()
        // Baseline: an ingested text from the (resolved) admin parks for the group.
        f.gm.ingest(
            "admin-contact",
            listOf(ReceivedMessage("parked-1", 0L, counter = 1, groupId = f.gid, membershipHash = "0".repeat(32))),
            wantGroupId = f.gid, bufferAll = true,
        )
        assertEquals(1, f.gm.takeGroupScreenItems(f.gid).size, "baseline: the text parks")
        // Park another, then get removed by roster.
        f.gm.ingest(
            "admin-contact",
            listOf(ReceivedMessage("parked-2", 0L, counter = 2, groupId = f.gid, membershipHash = "0".repeat(32))),
            wantGroupId = f.gid, bufferAll = true,
        )
        f.gm.handleControl("admin-contact", f.gid, GroupManager.KIND_ROSTER,
            ecRoster(f.adm, listOf("${f.adm}:", "${f.bob}:"), ep = 2))
        assertNull(f.vault.getGroup(f.gid))
        assertEquals(0, f.gm.takeGroupScreenItems(f.gid).size,
            "removal via roster must drop the group's parked plaintext")
    }
}

// ===========================================================================
// handleInvite — field/sender edges + rate-window clock behaviour
// ===========================================================================

class GroupInviteFieldEdgeTest {
    private val noTransport: () -> MessageManager? = { null }

    private fun freshGm(vault: InMemoryVault): GroupManager {
        seedEcPaired(vault, "friend")
        return GroupManager(vault, noTransport)
    }

    @Test
    fun invite_missingAnyRequiredField_isRejected() {
        val vault = InMemoryVault()
        val g = freshGm(vault)
        val adm = groupMemberId(1); val me = groupMemberId(2)
        val admJ = jsonEscapeString(adm); val meJ = jsonEscapeString(me)
        val bodies = listOf(
            // no "n"
            """{"ep":1,"adm":$admJ,"you":$meJ,"mem":[$admJ,$meJ]}""",
            // no "ep"
            """{"n":"crew","adm":$admJ,"you":$meJ,"mem":[$admJ,$meJ]}""",
            // non-numeric "ep"
            """{"n":"crew","ep":"abc","adm":$admJ,"you":$meJ,"mem":[$admJ,$meJ]}""",
            // no "adm"
            """{"n":"crew","ep":1,"you":$meJ,"mem":[$admJ,$meJ]}""",
            // no "you"
            """{"n":"crew","ep":1,"adm":$admJ,"mem":[$admJ,$meJ]}""",
            // no "mem"
            """{"n":"crew","ep":1,"adm":$admJ,"you":$meJ}""",
            // not even JSON
            """not json at all""",
        )
        for (body in bodies) {
            g.handleControl("friend", GroupManager.newGroupId(), GroupManager.KIND_INVITE, body)
        }
        assertTrue(g.pendingInvites().isEmpty(), "no malformed invite may park")
        assertEquals(0, vault.groups.size)
    }

    @Test
    fun invite_blankName_isRejected() {
        // Product decision 2026-08-30: an otherwise well-formed invite whose "n" is
        // blank/whitespace-only is refused at the name check (handleInvite), mirroring
        // createGroup. freshGm SEEDS the sender "friend", and that seeding is REQUIRED
        // for this to be a real tripwire: the blank-name check sits BEFORE the
        // sender-alias lookup, so if the check were reverted a blank-name invite from a
        // SEEDED sender would fall through and PARK (failing the assertion below). An
        // UNSEEDED sender is dropped at the alias lookup regardless of the name (see
        // invite_fromAnUnknownSenderContact_isDropped), which would make this assertion
        // pass even with the blank-name check gone — masking the regression. So the
        // seeding is what makes this exercise the blank-name rejection, not the sender
        // gate. See createGroup_blankName_isRejected.
        val vault = InMemoryVault()
        val g = freshGm(vault)
        val adm = groupMemberId(1); val me = groupMemberId(2)
        val admJ = jsonEscapeString(adm); val meJ = jsonEscapeString(me)
        for (nm in listOf("", "   ", "\t", "\n")) {
            val body = """{"n":${jsonEscapeString(nm)},"ep":1,"adm":$admJ,"you":$meJ,"mem":[$admJ,$meJ]}"""
            g.handleControl("friend", GroupManager.newGroupId(), GroupManager.KIND_INVITE, body)
        }
        assertTrue(g.pendingInvites().isEmpty(), "a blank group name must not park an invite")
        assertEquals(0, vault.groups.size)
    }

    @Test
    fun invite_fromAnUnknownSenderContact_isDropped() {
        // An invite can only be labeled by a known contact's alias; a sender with
        // no vault row (deleted between drain and handling) must be dropped, not
        // parked with a broken prompt.
        val vault = InMemoryVault()
        val g = freshGm(vault)   // seeds "friend" only
        val adm = groupMemberId(1); val me = groupMemberId(2)
        g.handleControl("stranger-not-in-vault", GroupManager.newGroupId(), GroupManager.KIND_INVITE,
            ecInvite(adm, me, listOf(adm, me)))
        assertTrue(g.pendingInvites().isEmpty())
    }

    @Test
    fun invite_resendWhileParked_isDeduped_andConsumesNoRateBudget() {
        val vault = InMemoryVault()
        val g = freshGm(vault)
        val adm = groupMemberId(1); val me = groupMemberId(2)
        val gid = GroupManager.newGroupId()
        g.handleControl("friend", gid, GroupManager.KIND_INVITE, ecInvite(adm, me, listOf(adm, me)))
        // The inviter re-sends the SAME invite (retry over Tor) — still one prompt.
        g.handleControl("friend", gid, GroupManager.KIND_INVITE, ecInvite(adm, me, listOf(adm, me)))
        assertEquals(1, g.pendingInvites().size, "a re-sent parked invite must dedup to one prompt")

        // And the dedup consumed no rate-window budget: MAX_INVITES_PER_WINDOW - 1
        // MORE distinct invites must all still park (total = the full window).
        repeat(GroupManager.MAX_INVITES_PER_WINDOW - 1) {
            g.handleControl("friend", GroupManager.newGroupId(), GroupManager.KIND_INVITE,
                ecInvite(adm, me, listOf(adm, me)))
        }
        assertEquals(GroupManager.MAX_INVITES_PER_WINDOW, g.pendingInvites().size,
            "the dedup path must not stamp the rate window")
    }

    @Test
    fun invite_rateWindow_discardsFutureStamps_afterAClockRollback() {
        // inviteAllowed prunes stamps OUTSIDE (now - window)..now — including
        // stamps in the FUTURE (device clock rolled back). A window "full" of
        // future stamps must not wedge invites closed.
        val vault = InMemoryVault()
        val g = freshGm(vault)
        val now = currentTimeMillis()
        val futureStamps = (1..GroupManager.MAX_INVITES_PER_WINDOW)
            .joinToString(",") { (now + 3_600_000L * it).toString() }
        vault.putMeta("grp_inv_rl:friend", futureStamps)

        val adm = groupMemberId(1); val me = groupMemberId(2)
        val gid = GroupManager.newGroupId()
        g.handleControl("friend", gid, GroupManager.KIND_INVITE, ecInvite(adm, me, listOf(adm, me)))
        assertTrue(g.pendingInvites().any { it.groupId == gid },
            "future (rolled-back-clock) stamps must be discarded, not counted against the window")
    }

    @Test
    fun acceptInvite_whenAlreadyJoined_clearsThePrompt_andTouchesNothing() {
        val vault = InMemoryVault()
        val g = freshGm(vault)
        val adm = groupMemberId(1); val me = groupMemberId(2)
        val gid = GroupManager.newGroupId()
        g.handleControl("friend", gid, GroupManager.KIND_INVITE, ecInvite(adm, me, listOf(adm, me)))
        // The group materialises through another path before the user accepts
        // (e.g. a racing control poll already joined it).
        vault.insertGroup(GroupRecord(gid, "existing", epoch = 5, adminMemberId = adm, myMemberId = me, createdAt = 0L))

        assertTrue(g.acceptInvite(gid), "accepting an already-joined invite reports success")
        assertTrue(g.pendingInvites().isEmpty(), "the stale prompt is cleared")
        val kept = vault.getGroup(gid)!!
        assertEquals("existing", kept.name, "the existing group must not be overwritten")
        assertEquals(5L, kept.epoch)
    }
}

// ===========================================================================
// createGroup — remaining input edges
// ===========================================================================

class GroupCreateInputEdgeTest {
    private val noTransport: () -> MessageManager? = { null }

    @Test
    fun createGroup_duplicateMemberContactIds_collapseToOneRow() {
        val vault = InMemoryVault()
        seedEcPaired(vault, "c-bob")
        val gm = GroupManager(vault, noTransport)
        val gid = gm.createGroup("crew", listOf("c-bob", "c-bob"))
        assertNotNull(gid)
        val members = vault.getGroupMembers(gid)
        assertEquals(2, members.size, "self + ONE bob — duplicates collapse")
        assertEquals(1, members.count { it.contactId == "c-bob" })
    }

    @Test
    fun createGroup_blankName_isRejected() {
        // Product decision 2026-08-30: a blank/whitespace-only group name is refused
        // at creation (a nameless group is a confusing consent prompt). The invite
        // path (handleInvite) rejects a blank "n" the same way — see
        // GroupInviteFieldEdgeTest.invite_blankName_isRejected.
        val vault = InMemoryVault()
        seedEcPaired(vault, "c-bob")
        val gm = GroupManager(vault, noTransport)
        assertNull(gm.createGroup("", listOf("c-bob")), "empty name is refused")
        assertNull(gm.createGroup("   ", listOf("c-bob")), "whitespace-only name is refused")
        assertNull(gm.createGroup("\t\n ", listOf("c-bob")), "tabs/newlines-only name is refused")
        // A real name still works, and nothing was persisted for the refused ones.
        assertTrue(vault.groups.isEmpty(), "no group row was written for a refused blank name")
        assertNotNull(gm.createGroup("crew", listOf("c-bob")), "a non-blank name is accepted")
    }
}

// ===========================================================================
// Persist-failure paths — fail closed, stay retryable
// ===========================================================================

/** Throws on the group_admin tombstone write — the LAST write inside
 *  createGroup's / acceptInvite's transaction — so the catch + safety-net
 *  cleanup paths are exercised with everything before it already applied
 *  (InMemoryVault has no rollback, mirroring the worst tear). */
private class EcTombstoneThrowingVault : InMemoryVault() {
    var armed = true
    override fun putMeta(key: String, value: String) {
        if (armed && key.startsWith("group_admin:")) throw IllegalStateException("simulated vault failure")
        super.putMeta(key, value)
    }
}

/** Throws on any group-row write while armed — the FIRST write inside
 *  addMember's transaction, so nothing is mutated before the failure. */
private class EcGroupRowThrowingVault : InMemoryVault() {
    var armed = false
    override fun insertGroup(group: GroupRecord): Long {
        if (armed) throw IllegalStateException("simulated vault failure")
        return super.insertGroup(group)
    }
}

/** Throws on member deletion while armed — the FIRST write inside
 *  removeMember's transaction (the member must survive a failed removal
 *  so a RETRY can re-drive it). */
private class EcMemberDeleteThrowingVault : InMemoryVault() {
    var armed = false
    override fun deleteGroupMember(groupId: String, memberId: String) {
        if (armed) throw IllegalStateException("simulated vault failure")
        super.deleteGroupMember(groupId, memberId)
    }
}

class GroupPersistFailureTest {
    private val noTransport: () -> MessageManager? = { null }

    @Test
    fun createGroup_persistFailure_leavesNoHalfBuiltGroup() {
        val vault = EcTombstoneThrowingVault()
        seedEcPaired(vault, "c-bob")
        val gm = GroupManager(vault, noTransport)
        assertNull(gm.createGroup("crew", listOf("c-bob")), "a failed persist must return null")
        // Fail closed: the catch's deleteGroup safety net cleaned up the rows the
        // torn (rollback-less) fake had already applied.
        assertEquals(0, vault.groups.size, "no half-built group may survive")
        assertEquals(0, vault.groupMembers.size, "no orphan member rows may survive")
        assertTrue(vault.meta.keys.none { it.startsWith("group_admin:") }, "no tombstone for a failed create")
    }

    @Test
    fun acceptInvite_persistFailure_keepsTheInviteParked_andIsRetryable() {
        val vault = EcTombstoneThrowingVault()
        seedEcPaired(vault, "admin-contact")
        val gm = GroupManager(vault, noTransport)
        val gid = GroupManager.newGroupId()
        val adm = groupMemberId(10); val me = groupMemberId(20)
        gm.handleControl("admin-contact", gid, GroupManager.KIND_INVITE, ecInvite(adm, me, listOf(adm, me)))

        assertFalse(gm.acceptInvite(gid), "a failed persist must report failure")
        assertNull(vault.getGroup(gid), "the safety net must remove the torn group")
        assertTrue(gm.pendingInvites().any { it.groupId == gid },
            "the invite must STAY parked on failure so the user can retry")

        // The transient failure clears → the same accept now succeeds.
        vault.armed = false
        assertTrue(gm.acceptInvite(gid), "the retry must succeed once the vault recovers")
        assertNotNull(vault.getGroup(gid))
        assertEquals("admin-contact", vault.getMeta("group_admin:$gid"), "the tombstone lands on the retry")
        assertTrue(gm.pendingInvites().isEmpty())
    }

    @Test
    fun addMember_persistFailure_returnsFalse_andIsRetryable() {
        val vault = EcGroupRowThrowingVault()
        seedEcPaired(vault, "c-bob")
        seedEcPaired(vault, "c-dave")
        val gm = GroupManager(vault, noTransport)
        val gid = gm.createGroup("crew", listOf("c-bob"))!!

        vault.armed = true
        assertFalse(gm.addMember(gid, "c-dave"))
        assertEquals(1L, vault.getGroup(gid)!!.epoch, "epoch untouched by a failed add")
        assertTrue(vault.getGroupMembers(gid).none { it.contactId == "c-dave" })

        vault.armed = false
        assertTrue(gm.addMember(gid, "c-dave"), "the retry must succeed")
        assertEquals(2L, vault.getGroup(gid)!!.epoch)
    }

    @Test
    fun removeMember_persistFailure_keepsTheMember_andIsRetryable() {
        // a failed removal must leave the member PRESENT so
        // the retry doesn't early-return false while peers keep delivering to
        // the supposedly-removed member.
        val vault = EcMemberDeleteThrowingVault()
        seedEcPaired(vault, "c-bob")
        val gm = GroupManager(vault, noTransport)
        val gid = gm.createGroup("crew", listOf("c-bob"))!!
        val bobMember = vault.getGroupMembers(gid).first { it.contactId == "c-bob" }.memberId

        vault.armed = true
        assertFalse(gm.removeMember(gid, bobMember))
        assertTrue(vault.getGroupMembers(gid).any { it.memberId == bobMember },
            "the member must survive a failed removal (retryability)")
        assertEquals(1L, vault.getGroup(gid)!!.epoch)

        vault.armed = false
        assertTrue(gm.removeMember(gid, bobMember), "the retry must re-drive the removal")
        assertTrue(vault.getGroupMembers(gid).none { it.memberId == bobMember })
        assertEquals(2L, vault.getGroup(gid)!!.epoch)
    }
}

// ===========================================================================
// buildJoinBody padding + GROUP-3 tag-pair shape + join list cap
// ===========================================================================

class GroupJoinBodyTest {
    private val noTransport: () -> MessageManager? = { null }

    @Test
    fun joinBody_padsToTheMultiple_andCarriesEveryRealPair() {
        // The tag list must land on a TAG_PAD_MULTIPLE boundary (the admin
        // learns only a coarse contact-count bucket), every entry must be
        // pair-shaped (dummies indistinguishable from real entries), and each
        // real contact's "sym:bound" pair must be present.
        val vault = InMemoryVault()
        val secrets = mutableMapOf<String, ByteArray>()
        for (c in listOf("c-a", "c-b", "c-c")) {
            val s = generateSecureRandom(32)
            secrets[c] = s
            seedEcPaired(vault, c, s)
        }
        val gm = GroupManager(vault, noTransport)
        val gid = GroupManager.newGroupId()
        val myId = groupMemberId(1)

        val body = gm.buildJoinBody(gid, myId)
        assertEquals(myId, firstStringFieldAnywhere(body, "you"))
        val tags = parseStringArrayField(body, "tags")
        assertNotNull(tags)
        assertEquals(0, tags.size % GroupManager.TAG_PAD_MULTIPLE, "tag list must land on the pad multiple")
        assertTrue(tags.size >= 3, "all real tags must be present")
        assertTrue(tags.all { GroupManager.isValidTagPair(it) }, "dummies must be pair-shaped like real entries")
        for ((_, s) in secrets) {
            val expected = GroupManager.pairTag(s, gid) + ":" + GroupManager.boundTag(s, gid, myId)
            assertTrue(expected in tags, "each real contact's sym:bound pair must be advertised")
        }
    }

    @Test
    fun joinBody_withNoContacts_isStillAFullPadBucket_ofDummies() {
        val vault = InMemoryVault()
        val gm = GroupManager(vault, noTransport)
        val tags = parseStringArrayField(gm.buildJoinBody(GroupManager.newGroupId(), groupMemberId(1)), "tags")
        assertNotNull(tags)
        assertEquals(GroupManager.TAG_PAD_MULTIPLE, tags.size, "empty contact list still discloses one full bucket")
        assertTrue(tags.all { GroupManager.isValidTagPair(it) })
    }

    @Test
    fun joinBody_atAnExactPadMultiple_addsNoDummies() {
        // Bucket boundary: exactly TAG_PAD_MULTIPLE contacts → no padding at all
        // (the size already reveals only "one bucket").
        val vault = InMemoryVault()
        repeat(GroupManager.TAG_PAD_MULTIPLE) { seedEcPaired(vault, "c-$it") }
        val gm = GroupManager(vault, noTransport)
        val tags = parseStringArrayField(gm.buildJoinBody(GroupManager.newGroupId(), groupMemberId(1)), "tags")
        assertNotNull(tags)
        assertEquals(GroupManager.TAG_PAD_MULTIPLE, tags.size, "an exact multiple gains no dummy entries")
    }

    @Test
    fun tagPairValidation_pinsTheExactShape() {
        val hex16 = "0123456789abcdef"
        assertTrue(GroupManager.isValidTagPair("$hex16:$hex16"))
        assertFalse(GroupManager.isValidTagPair(""))
        assertFalse(GroupManager.isValidTagPair(hex16), "a bare sym half is not a pair")
        assertFalse(GroupManager.isValidTagPair("$hex16$hex16:"), "colon must sit at offset 16")
        assertFalse(GroupManager.isValidTagPair("${hex16.dropLast(1)}:$hex16" + "0"), "halves must be exactly 16 chars")
        assertFalse(GroupManager.isValidTagPair("$hex16:${hex16.uppercase()}"), "hex is lowercase-only")
        assertFalse(GroupManager.isValidTagPair("$hex16;$hex16"), "separator must be ':'")
    }

    @Test
    fun join_oversizedTagList_isDropped() {
        // Defense-in-depth MAX_TAGS_PER_MEMBER cap on the admin's join parser.
        val vault = InMemoryVault()
        seedEcPaired(vault, "c-bob")
        val gm = GroupManager(vault, noTransport)
        val gid = gm.createGroup("crew", listOf("c-bob"))!!
        val bobMember = vault.getGroupMembers(gid).first { it.contactId == "c-bob" }.memberId
        val pair = { i: Int -> i.toString(16).padStart(16, '0') + ":" + i.toString(16).padStart(16, '0') }
        val tooMany = (0..GroupManager.MAX_TAGS_PER_MEMBER).joinToString(",") { jsonEscapeString(pair(it)) }
        gm.handleControl("c-bob", gid, GroupManager.KIND_JOIN,
            """{"you":${jsonEscapeString(bobMember)},"tags":[$tooMany]}""")
        assertTrue(vault.getGroupMembers(gid).first { it.memberId == bobMember }.tags.isEmpty(),
            "an over-cap tag list must be dropped whole")
    }

    @Test
    fun join_forAnUnknownGroup_isANoop() {
        val vault = InMemoryVault()
        seedEcPaired(vault, "c-bob")
        val gm = GroupManager(vault, noTransport)
        gm.handleControl("c-bob", GroupManager.newGroupId(), GroupManager.KIND_JOIN,
            """{"you":${jsonEscapeString(groupMemberId(1))},"tags":[]}""")
        assertEquals(0, vault.groupMembers.size)
    }
}

// ===========================================================================
// Leave — epoch + parked-buffer edges not pinned elsewhere
// ===========================================================================

class GroupLeaveEdgeTest {

    @Test
    fun handleLeave_onANonAdminDevice_doesNotBumpTheEpoch() {
        // Only the admin owns the epoch. A member witnessing a peer's leave
        // removes the row but must NOT bump — the admin's re-roster does that.
        val f = ecJoinedFixture()
        val bobSecret = generateSecureRandom(32)
        seedEcPaired(f.vault, "bob-contact", bobSecret)
        val tag = GroupManager.boundTag(bobSecret, f.gid, f.bob)
        f.gm.handleControl("admin-contact", f.gid, GroupManager.KIND_ROSTER,
            ecRoster(f.adm, listOf("${f.adm}:", "${f.me}:", "${f.bob}:$tag"), ep = 2))
        assertEquals(2L, f.vault.getGroup(f.gid)!!.epoch)

        f.gm.handleControl("bob-contact", f.gid, GroupManager.KIND_LEAVE, "{}")
        assertEquals(2L, f.vault.getGroup(f.gid)!!.epoch, "a non-admin device must not bump the epoch on a leave")
        assertTrue(f.vault.getGroupMembers(f.gid).none { it.memberId == f.bob })
    }

    @Test
    fun leaveGroup_dropsParkedGroupMessages() {
        // RAM hygiene: leaving must drop the group's parked plaintext, not just
        // the vault rows.
        val f = ecJoinedFixture()
        f.gm.ingest(
            "admin-contact",
            listOf(ReceivedMessage("baseline", 0L, counter = 1, groupId = f.gid, membershipHash = "0".repeat(32))),
            wantGroupId = f.gid, bufferAll = true,
        )
        assertEquals(1, f.gm.takeGroupScreenItems(f.gid).size, "baseline: the text parks")
        f.gm.ingest(
            "admin-contact",
            listOf(ReceivedMessage("doomed", 0L, counter = 2, groupId = f.gid, membershipHash = "0".repeat(32))),
            wantGroupId = f.gid, bufferAll = true,
        )
        // …and an ECHO of the group sitting in the admin's 1:1 screen buffer.
        f.gm.ingest(
            "admin-contact",
            listOf(ReceivedMessage("echoed", 0L, counter = 3, groupId = f.gid, membershipHash = "0".repeat(32))),
            wantGroupId = null, bufferAll = true,
        )
        f.gm.leaveGroup(f.gid)
        assertNull(f.vault.getGroup(f.gid))
        assertEquals(0, f.gm.takeGroupScreenItems(f.gid).size, "leaving must drop the parked plaintext")
        assertEquals(0, f.gm.takeDirectScreenItems("admin-contact").size, "…and every echo of the left group")
    }
}

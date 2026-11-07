package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// GROUP-1 per-offer "declined invite stays declined" tombstone
// (GroupManager.declinedInvites / DECLINED_INVITE_META / declineTokenFor).
//
// Product decision: a declined group invite stays declined PER OFFER — a
// re-delivery of the SAME offer must not re-prompt (or spend rate budget), while a
// genuinely NEW offer (different epoch / member set / inviter) still prompts. The
// tombstone is persisted to vault `_meta`, so it survives the session teardown that
// follows every backgrounding (a RAM-only decline would be forgotten on foreground
// return). Mirrors ReferralManager.completedIntros.
//
// Hermetic: shares the module's InMemoryVault double (support/InMemoryVault.kt); drives
// the protocol with a NULL transport (fan-out is a logged no-op; persistence and
// prompt state stay observable), exactly like the sibling group tests. No AES-GCM,
// so no bridge guard is needed.
// ---------------------------------------------------------------------------

private fun diMid(seed: Int) = bytesToHex(ByteArray(8) { (seed + it).toByte() })

private fun diPaired(vault: InMemoryVault, contactId: String) {
    vault.insertContact(
        ContactRecord(
            contactId = contactId, sharedSecret = generateSecureRandom(32),
            trustLevel = 1, alias = "A-$contactId", aliasLastRotated = 0L,
        )
    )
}

private fun diInvite(adm: String, you: String, mem: List<String>, ep: Long = 1, name: String = "crew"): String {
    val memJson = mem.joinToString(",") { jsonEscapeString(it) }
    return """{"n":${jsonEscapeString(name)},"ep":$ep,"adm":${jsonEscapeString(adm)},"you":${jsonEscapeString(you)},"mem":[$memJson]}"""
}

/** Structural token an accept/decline of this offer would produce — declineTokenFor
 *  ignores the cosmetic alias/name/mismatch fields, so blanks are fine here. */
private fun diTokenFor(gid: String, inviter: String, ep: Long, adm: String, you: String, mem: List<String>) =
    GroupManager.declineTokenFor(
        GroupInvite(
            groupId = gid, inviterContactId = inviter, inviterAlias = "", groupName = "",
            epoch = ep, adminMemberId = adm, myMemberId = you, memberIds = mem,
        )
    )

class GroupInviteDeclineTest {

    // 1. Decline then re-deliver the SAME offer → stays declined (no re-prompt) AND
    //    the suppressed re-delivery consumes NO rate-window budget.
    @Test
    fun declinedOffer_reDelivery_isSuppressed_andConsumesNoRateBudget() {
        val vault = InMemoryVault()
        diPaired(vault, "friend")
        val gm = GroupManager(vault) { null }
        val adm = diMid(1); val me = diMid(2)
        val gid = GroupManager.newGroupId()

        // Park (spends exactly one of the window's MAX stamps), then decline.
        gm.handleControl("friend", gid, GroupManager.KIND_INVITE, diInvite(adm, me, listOf(adm, me)))
        assertEquals(1, gm.pendingInvites().size, "a fresh invite parks")
        gm.declineInvite(gid)
        assertTrue(gm.pendingInvites().isEmpty(), "decline drops the prompt")

        // The SAME offer, re-delivered many times, must never re-park.
        repeat(20) {
            gm.handleControl("friend", gid, GroupManager.KIND_INVITE, diInvite(adm, me, listOf(adm, me)))
        }
        assertTrue(gm.pendingInvites().isEmpty(), "a declined offer's re-delivery must not re-park")

        // Budget proof: only the initial parking spent a stamp; the 20 suppressed
        // re-deliveries spent none — so the window still admits MAX-1 more DISTINCT
        // offers. If any suppressed re-delivery had stamped the window, fewer would fit.
        repeat(GroupManager.MAX_INVITES_PER_WINDOW - 1) {
            gm.handleControl("friend", GroupManager.newGroupId(), GroupManager.KIND_INVITE,
                diInvite(adm, me, listOf(adm, me)))
        }
        assertEquals(GroupManager.MAX_INVITES_PER_WINDOW - 1, gm.pendingInvites().size,
            "all MAX-1 remaining distinct offers park — the suppressed re-deliveries ate no budget")

        // The window is now exactly full (initial + MAX-1): the next distinct offer is
        // rate-limited, confirming the count above was the true remaining budget.
        gm.handleControl("friend", GroupManager.newGroupId(), GroupManager.KIND_INVITE,
            diInvite(adm, me, listOf(adm, me)))
        assertEquals(GroupManager.MAX_INVITES_PER_WINDOW - 1, gm.pendingInvites().size,
            "the window is full — the next distinct offer is rate-limited, not parked")
    }

    // 2a. A NEW offer for the same groupId at a DIFFERENT epoch still prompts.
    @Test
    fun newOffer_sameGroupDifferentEpoch_stillPrompts() {
        val vault = InMemoryVault()
        diPaired(vault, "friend")
        val gm = GroupManager(vault) { null }
        val adm = diMid(1); val me = diMid(2)
        val gid = GroupManager.newGroupId()

        gm.handleControl("friend", gid, GroupManager.KIND_INVITE, diInvite(adm, me, listOf(adm, me), ep = 1))
        gm.declineInvite(gid)

        gm.handleControl("friend", gid, GroupManager.KIND_INVITE, diInvite(adm, me, listOf(adm, me), ep = 2))
        val parked = gm.pendingInvites()
        assertEquals(1, parked.size, "a different-epoch offer for the same group is a NEW offer — it prompts")
        assertEquals(2L, parked.first().epoch)
    }

    // 2b. A NEW offer with a DIFFERENT member set still prompts.
    @Test
    fun newOffer_differentMemberSet_stillPrompts() {
        val vault = InMemoryVault()
        diPaired(vault, "friend")
        val gm = GroupManager(vault) { null }
        val adm = diMid(1); val me = diMid(2); val bob = diMid(3)
        val gid = GroupManager.newGroupId()

        gm.handleControl("friend", gid, GroupManager.KIND_INVITE, diInvite(adm, me, listOf(adm, me)))
        gm.declineInvite(gid)

        gm.handleControl("friend", gid, GroupManager.KIND_INVITE, diInvite(adm, me, listOf(adm, me, bob)))
        assertEquals(1, gm.pendingInvites().size, "a different member set is a NEW offer — it prompts")
        assertEquals(3, gm.pendingInvites().first().memberIds.size)
    }

    // 2c. A NEW offer from a DIFFERENT inviter still prompts (the token binds the
    //     inviterContactId), so a co-member re-invite is not silently suppressed.
    @Test
    fun newOffer_differentInviter_stillPrompts() {
        val vault = InMemoryVault()
        diPaired(vault, "friend"); diPaired(vault, "other")
        val gm = GroupManager(vault) { null }
        val adm = diMid(1); val me = diMid(2)
        val gid = GroupManager.newGroupId()

        gm.handleControl("friend", gid, GroupManager.KIND_INVITE, diInvite(adm, me, listOf(adm, me)))
        gm.declineInvite(gid)

        gm.handleControl("other", gid, GroupManager.KIND_INVITE, diInvite(adm, me, listOf(adm, me)))
        assertEquals(1, gm.pendingInvites().size, "a different inviter is a NEW offer — it prompts")
        assertEquals("other", gm.pendingInvites().first().inviterContactId)
    }

    // 3. The tombstone SURVIVES a restart: a fresh GroupManager over the same vault
    //    still suppresses the declined offer's re-delivery (proves _meta persistence).
    @Test
    fun declineTombstone_survivesRestart() {
        val vault = InMemoryVault()
        diPaired(vault, "friend")
        val adm = diMid(1); val me = diMid(2)
        val gid = GroupManager.newGroupId()

        val gm1 = GroupManager(vault) { null }
        gm1.handleControl("friend", gid, GroupManager.KIND_INVITE, diInvite(adm, me, listOf(adm, me)))
        gm1.declineInvite(gid)
        assertNotNull(vault.getMeta("grp_declined"), "the decline is persisted to _meta")

        // Session teardown + re-unlock = a brand-new GroupManager over the SAME vault.
        val gm2 = GroupManager(vault) { null }
        gm2.handleControl("friend", gid, GroupManager.KIND_INVITE, diInvite(adm, me, listOf(adm, me)))
        assertTrue(gm2.pendingInvites().isEmpty(),
            "the persisted tombstone must suppress the re-delivery after a restart")
    }

    // 4. Accept is unaffected: a normal invite still parks and acceptInvite still joins.
    @Test
    fun accept_isUnaffected_byTheTombstone() {
        val vault = InMemoryVault()
        diPaired(vault, "friend")
        val gm = GroupManager(vault) { null }
        val adm = diMid(1); val me = diMid(2)

        // A decline of ONE offer must not block a DIFFERENT offer's accept.
        val declinedGid = GroupManager.newGroupId()
        gm.handleControl("friend", declinedGid, GroupManager.KIND_INVITE, diInvite(adm, me, listOf(adm, me)))
        gm.declineInvite(declinedGid)

        val gid = GroupManager.newGroupId()
        gm.handleControl("friend", gid, GroupManager.KIND_INVITE, diInvite(adm, me, listOf(adm, me)))
        assertEquals(1, gm.pendingInvites().size, "a normal, never-declined invite parks")
        assertTrue(gm.acceptInvite(gid), "acceptInvite joins")
        assertNotNull(vault.getGroup(gid), "the group is persisted")
        assertTrue(gm.pendingInvites().isEmpty(), "the prompt is cleared after accept")
    }

    // 5. Cap eviction: past MAX_DECLINED_INVITES the OLDEST tombstone is evicted, so a
    //    very old declined offer can re-prompt while the newest stays suppressed.
    @Test
    fun tombstone_evictsOldestPastTheCap() {
        val vault = InMemoryVault()
        diPaired(vault, "friend")
        // Pre-seed the tombstone at capacity with MAX distinct valid tokens, oldest first.
        val seeded = (0 until GroupManager.MAX_DECLINED_INVITES)
            .map { "aaaa" + it.toString().padStart(20, '0') }   // 24-char, shape-valid
        vault.putMeta("grp_declined", seeded.joinToString("\n"))

        val gm = GroupManager(vault) { null }
        val adm = diMid(1); val me = diMid(2)
        val gid = GroupManager.newGroupId()

        // Park + decline one REAL offer → its token is appended, tipping the set to
        // MAX+1 and evicting the oldest seeded token.
        gm.handleControl("friend", gid, GroupManager.KIND_INVITE, diInvite(adm, me, listOf(adm, me)))
        gm.declineInvite(gid)

        val persisted = vault.getMeta("grp_declined")!!.split("\n")
        assertEquals(GroupManager.MAX_DECLINED_INVITES, persisted.size, "the set stays capped at MAX")
        assertFalse(seeded.first() in persisted, "the OLDEST tombstone was evicted past the cap")
        assertTrue(seeded.last() in persisted, "a recent seeded tombstone is retained")
        val realToken = diTokenFor(gid, "friend", 1, adm, me, listOf(adm, me))
        assertTrue(realToken in persisted, "the newly declined offer's token is retained")
    }

    // 6. Purge coupling pin: `grp_declined` is a vault SINGLETON of one-way hashes —
    //    named by no residue predicate and purged by NO contact/group delete (that
    //    persistence is the whole point). It dies only with a full-vault wipe. Mirrors
    //    the update_nudge_v1 / ref_done2 precedent (MetaResiduePurgeTest).
    @Test
    fun declineTombstone_survivesContactAndGroupDelete_diesOnlyOnWipe() {
        val k = "grp_declined"
        assertFalse(isGroupMetaResidueForGroup(k, "G1"))
        assertFalse(isGroupMetaResidueForGroup(k, ""))
        assertFalse(isGroupMetaResidueForContact(k, "friend"))
        assertFalse(isGroupMetaResidueForContact(k, ""))
        assertFalse(isReferralMetaKey(k))
        assertFalse(k in ratchetMetaKeysForContact("friend"))

        val vault = InMemoryVault()
        diPaired(vault, "friend")
        val gm = GroupManager(vault) { null }
        val adm = diMid(1); val me = diMid(2)
        val gid = GroupManager.newGroupId()
        gm.handleControl("friend", gid, GroupManager.KIND_INVITE, diInvite(adm, me, listOf(adm, me)))
        gm.acceptInvite(gid)                       // materialise a group to delete
        val declinedGid = GroupManager.newGroupId()
        gm.handleControl("friend", declinedGid, GroupManager.KIND_INVITE, diInvite(adm, me, listOf(adm, me)))
        gm.declineInvite(declinedGid)
        assertNotNull(vault.getMeta(k))

        vault.deleteContact("friend")
        assertNotNull(vault.getMeta(k), "the tombstone singleton must survive a contact delete")
        vault.deleteGroup(gid)
        assertNotNull(vault.getMeta(k), "…and a group delete")

        vault.wipeAllTables()
        assertNull(vault.getMeta(k), "a full-vault wipe erases it with every other row")
    }

    // 7. Fail-soft persist (persistDeclinedInvites' NEVER-throws rule): a putMeta that
    //    throws for the decline blob must NOT break the decline (the parked prompt is
    //    still dropped, RAM-only for the session) NOR a later accept of a DIFFERENT
    //    parked offer. A throw here only costs durability.
    @Test
    fun persistFailure_stillDeclines_andLaterAcceptStillSucceeds() {
        val vault = object : InMemoryVault() {
            override fun putMeta(key: String, value: String) {
                // Only the decline tombstone write throws; the group_admin tombstone
                // acceptInvite writes (a different key) must still land.
                if (key == "grp_declined") throw IllegalStateException("simulated _meta write failure")
                super.putMeta(key, value)
            }
        }
        diPaired(vault, "friend")
        val gm = GroupManager(vault) { null }
        val adm = diMid(1); val me = diMid(2)

        // Park + decline an offer. persistDeclinedInvites throws internally, but the
        // decline itself must complete — the parked prompt is dropped RAM-only.
        val declinedGid = GroupManager.newGroupId()
        gm.handleControl("friend", declinedGid, GroupManager.KIND_INVITE, diInvite(adm, me, listOf(adm, me)))
        assertEquals(1, gm.pendingInvites().size, "the offer parks")
        gm.declineInvite(declinedGid)   // putMeta("grp_declined") throws inside — must not propagate
        assertTrue(gm.pendingInvites().none { it.groupId == declinedGid },
            "decline drops the prompt even when the tombstone persist throws")
        assertNull(vault.getMeta("grp_declined"),
            "the refused write left nothing on disk (RAM-only degrade), not a partial blob")

        // A DIFFERENT parked offer's accept still succeeds — the throw broke nothing.
        val acceptGid = GroupManager.newGroupId()
        gm.handleControl("friend", acceptGid, GroupManager.KIND_INVITE, diInvite(adm, me, listOf(adm, me)))
        assertTrue(gm.acceptInvite(acceptGid), "a later accept of a different offer still succeeds")
        assertNotNull(vault.getGroup(acceptGid), "the accepted group is persisted")
    }

    // 8. Garbage-blob init: a corrupt/hand-tampered DECLINED_INVITE_META must not fail
    //    construction and must not seed junk into the suppression set — a genuine invite
    //    still PARKS. decodeDeclinedInvites drops non-token lines (fail toward "don't
    //    suppress"), and the init try/catch never throws out of the constructor.
    @Test
    fun garbageTombstoneBlob_constructsCleanly_andStillParksAGenuineInvite() {
        val vault = InMemoryVault()
        diPaired(vault, "friend")
        vault.putMeta("grp_declined", "!!!\n<junk>\nnot a token\n")

        val gm = GroupManager(vault) { null }   // must not throw on the junk blob

        val adm = diMid(1); val me = diMid(2)
        val gid = GroupManager.newGroupId()
        gm.handleControl("friend", gid, GroupManager.KIND_INVITE, diInvite(adm, me, listOf(adm, me)))
        assertEquals(1, gm.pendingInvites().size,
            "junk in the tombstone blob must be dropped, never treated as a suppression token")
        assertTrue(gm.pendingInvites().any { it.groupId == gid })
    }

    // 9. Codec round-trip: the top-level encodeDeclinedInvites / decodeDeclinedInvites
    //    directly. Empty ↔ ""; over-cap capped to the NEWEST max on BOTH sides;
    //    invalid/garbage lines dropped; a valid set round-trips identically.
    @Test
    fun codec_roundTrips_capsToNewest_andDropsGarbage() {
        // empty set → "" → empty
        assertEquals("", encodeDeclinedInvites(emptyList(), GroupManager.MAX_DECLINED_INVITES))
        assertTrue(decodeDeclinedInvites("", GroupManager.MAX_DECLINED_INVITES).isEmpty())

        // a valid set round-trips identically, order preserved
        val valid = listOf("aaaa" + "0".repeat(20), "bbbb" + "1".repeat(20), "cccc" + "2".repeat(20))
        val encoded = encodeDeclinedInvites(valid, GroupManager.MAX_DECLINED_INVITES)
        assertEquals(valid, decodeDeclinedInvites(encoded, GroupManager.MAX_DECLINED_INVITES),
            "a valid token set round-trips identically")

        // an over-cap collection is capped to the NEWEST `max` on BOTH encode and decode
        val cap = 4
        val many = (0 until 10).map { "zzzz" + it.toString().padStart(20, '0') }   // 24-char, shape-valid
        assertEquals(many.takeLast(cap), encodeDeclinedInvites(many, cap).split("\n"),
            "encode caps to the newest max")
        assertEquals(many.takeLast(cap), decodeDeclinedInvites(many.joinToString("\n"), cap),
            "decode caps to the newest max")

        // invalid/garbage lines are dropped, the valid ones survive (decode)
        val mixed = "!!!\n${valid[0]}\nnot a token\n${valid[1]}\n<junk>"
        assertEquals(listOf(valid[0], valid[1]), decodeDeclinedInvites(mixed, GroupManager.MAX_DECLINED_INVITES),
            "decode drops garbage lines, valid tokens survive")
        // …and encode filters invalid members before joining
        assertEquals(listOf(valid[0], valid[1]),
            encodeDeclinedInvites(listOf("!!!", valid[0], "not a token", valid[1]), GroupManager.MAX_DECLINED_INVITES).split("\n"),
            "encode filters invalid tokens before joining")
    }
}

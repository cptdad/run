package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// GROUP-1 parked-invite PERSISTENCE (GroupInviteStore / `grp_pinv:` rows).
//
// Product gap this closes: the invite blob is drained DESTRUCTIVELY from the
// relay, and Rún tears the whole session down on background (Android
// MainActivity.onStop -> finishAndRemoveTask; iOS .background -> lock ->
// GroupManager.scrubInMemory). A user who SAW the invite prompt and backgrounded
// before tapping Join lost it forever. The park is now mirrored into the
// encrypted vault's `_meta` table and rehydrated on the next vault open.
//
// The rules pinned here:
//   • persist -> reload -> accept works (and the display fields are re-derived);
//   • decline / accept / expiry / contact-delete / group-delete (leave) drop the row;
//   • scrubInMemory (ordinary lock) does NOT drop the row — that IS the fix;
//   • establish-on-read: a missing/corrupt/tampered/expired row is "no invite",
//     never a throw and never a state handleInvite itself would have refused;
//   • bounded: past MAX_PARKED_INVITES the OLDEST rows go;
//   • fail-soft: a refused `_meta` write degrades to the old RAM-only behaviour.
//
// Hermetic: shares the module's InMemoryVault double (support/InMemoryVault.kt) and
// drives the protocol with a NULL transport, exactly like the sibling group
// tests. No AES-GCM, so no bridge guard is needed.
// ---------------------------------------------------------------------------

private fun piMid(seed: Int) = bytesToHex(ByteArray(8) { (seed + it).toByte() })

private fun piPaired(vault: InMemoryVault, contactId: String, alias: String = "A-$contactId") {
    vault.insertContact(
        ContactRecord(
            contactId = contactId, sharedSecret = generateSecureRandom(32),
            trustLevel = 1, alias = alias, aliasLastRotated = 0L,
        )
    )
}

private fun piInvite(adm: String, you: String, mem: List<String>, ep: Long = 1, name: String = "crew"): String {
    val memJson = mem.joinToString(",") { jsonEscapeString(it) }
    return """{"n":${jsonEscapeString(name)},"ep":$ep,"adm":${jsonEscapeString(adm)},"you":${jsonEscapeString(you)},"mem":[$memJson]}"""
}

/** The durable row key a park writes. */
private fun piKey(gid: String, inviter: String) = GroupInviteStore.keyFor(gid, inviter)

private fun piStoredInvite(gid: String, inviter: String, adm: String, you: String, mem: List<String>, ep: Long = 1, name: String = "crew") =
    GroupInvite(
        groupId = gid, inviterContactId = inviter, inviterAlias = "", groupName = name,
        epoch = ep, adminMemberId = adm, myMemberId = you, memberIds = mem,
    )

class GroupInvitePersistenceTest {

    // 1. PERSIST -> RELOAD -> ACCEPT. The core product fix: the invite parks, the
    //    session ends, and a fresh GroupManager over the same vault re-parks it with
    //    every display field resolved — then accepting it joins for real.
    @Test
    fun parkedInvite_survivesSessionTeardown_andCanStillBeAccepted() {
        val vault = InMemoryVault()
        piPaired(vault, "friend", alias = "Birch")
        val adm = piMid(1); val me = piMid(2); val bob = piMid(3)
        val gid = GroupManager.newGroupId()

        val gm1 = GroupManager(vault) { null }
        gm1.handleControl("friend", gid, GroupManager.KIND_INVITE, piInvite(adm, me, listOf(adm, me, bob), name = "Ash"))
        assertEquals(1, gm1.pendingInvites().size, "a fresh invite parks")
        assertNotNull(vault.getMeta(piKey(gid, "friend")), "…and is mirrored into _meta")

        // Ordinary background: the RAM buffers are scrubbed, the durable row is NOT.
        gm1.scrubInMemory()
        assertTrue(gm1.pendingInvites().isEmpty(), "scrubInMemory clears the RAM copy")
        assertNotNull(vault.getMeta(piKey(gid, "friend")),
            "scrubInMemory must NOT delete the durable row — that is the whole fix")

        // Re-unlock = a brand-new GroupManager over the same vault.
        val gm2 = GroupManager(vault) { null }
        val restored = gm2.pendingInvites()
        assertEquals(1, restored.size, "the parked invite is restored on vault open")
        val inv = restored.first()
        assertEquals(gid, inv.groupId)
        assertEquals("friend", inv.inviterContactId)
        assertEquals("Ash", inv.groupName)
        assertEquals(1L, inv.epoch)
        assertEquals(adm, inv.adminMemberId)
        assertEquals(me, inv.myMemberId)
        assertEquals(listOf(adm, me, bob), inv.memberIds)
        assertEquals("Birch", inv.inviterAlias, "the alias is re-derived from the contacts table, not stored")

        assertTrue(gm2.acceptInvite(gid), "the restored invite can still be accepted")
        assertNotNull(vault.getGroup(gid), "the group is persisted")
        assertEquals(3, vault.getGroupMembers(gid).size)
        assertNull(vault.getMeta(piKey(gid, "friend")), "accept drops the durable row")
        assertTrue(gm2.pendingInvites().isEmpty(), "…and the prompt")
    }

    // 2. DECLINE removes the persisted entry (and the tombstone keeps it from
    //    re-prompting even if the row somehow survived — see test 9).
    @Test
    fun decline_removesThePersistedRow() {
        val vault = InMemoryVault()
        piPaired(vault, "friend")
        val adm = piMid(1); val me = piMid(2)
        val gid = GroupManager.newGroupId()

        val gm = GroupManager(vault) { null }
        gm.handleControl("friend", gid, GroupManager.KIND_INVITE, piInvite(adm, me, listOf(adm, me)))
        assertNotNull(vault.getMeta(piKey(gid, "friend")))

        gm.declineInvite(gid)
        assertNull(vault.getMeta(piKey(gid, "friend")), "decline drops the durable row")
        assertTrue(GroupManager(vault) { null }.pendingInvites().isEmpty(),
            "a declined invite does not come back on the next unlock")
    }

    // 3. A CONTACT DELETE purges the inviter's parked invites — the row names a
    //    group the user is not in, and acceptInvite could never fan our KIND_JOIN at
    //    a contact that no longer exists.
    @Test
    fun contactDelete_purgesThatInvitersParkedInvites() {
        val vault = InMemoryVault()
        piPaired(vault, "friend"); piPaired(vault, "other")
        val adm = piMid(1); val me = piMid(2)
        val mine = GroupManager.newGroupId(); val theirs = GroupManager.newGroupId()

        val gm = GroupManager(vault) { null }
        gm.handleControl("friend", mine, GroupManager.KIND_INVITE, piInvite(adm, me, listOf(adm, me)))
        gm.handleControl("other", theirs, GroupManager.KIND_INVITE, piInvite(adm, me, listOf(adm, me)))
        assertEquals(2, gm.pendingInvites().size)

        vault.deleteContact("friend")
        assertNull(vault.getMeta(piKey(mine, "friend")), "the deleted contact's parked invite is purged")
        assertNotNull(vault.getMeta(piKey(theirs, "other")), "…and only theirs")

        val gm2 = GroupManager(vault) { null }
        assertEquals(listOf(theirs), gm2.pendingInvites().map { it.groupId },
            "only the surviving contact's invite re-parks")
    }

    // 3b. Belt and braces: even if the purge classifier had missed the row, an invite
    //     whose inviter is gone is unusable — the LOAD path drops it and deletes it.
    @Test
    fun parkedInvite_withNoInviterContact_isDroppedAndDeletedOnLoad() {
        val vault = InMemoryVault()
        val adm = piMid(1); val me = piMid(2)
        val gid = GroupManager.newGroupId()
        // Seed the row directly — no contact row exists for "ghost".
        vault.putMeta(
            piKey(gid, "ghost"),
            GroupInviteStore.encode(piStoredInvite(gid, "ghost", adm, me, listOf(adm, me)), currentTimeMillis()),
        )

        val gm = GroupManager(vault) { null }
        assertTrue(gm.pendingInvites().isEmpty(), "an invite from an unknown contact never parks")
        assertNull(vault.getMeta(piKey(gid, "ghost")), "…and its row is deleted, not left as residue")
    }

    // 4. A GROUP DELETE purges the row. Every leave / removal path bottoms out in
    //    vault.deleteGroup, so this is what drops a parked invite for a group the
    //    user left.
    @Test
    fun groupDelete_purgesTheParkedInviteRow() {
        val vault = InMemoryVault()
        piPaired(vault, "friend")
        val adm = piMid(1); val me = piMid(2)
        val gid = GroupManager.newGroupId(); val otherGid = GroupManager.newGroupId()

        val gm = GroupManager(vault) { null }
        gm.handleControl("friend", gid, GroupManager.KIND_INVITE, piInvite(adm, me, listOf(adm, me)))
        gm.handleControl("friend", otherGid, GroupManager.KIND_INVITE, piInvite(adm, me, listOf(adm, me)))

        vault.deleteGroup(gid)
        assertNull(vault.getMeta(piKey(gid, "friend")), "the group's parked invite row is purged")
        assertNotNull(vault.getMeta(piKey(otherGid, "friend")), "…and only that group's")
    }

    // 5. EXPIRY: a row older than PARKED_INVITE_TTL_MS never parks and is deleted on
    //    load. A FUTURE-dated stamp is deliberately NOT treated as expired (a clock
    //    that jumped must never silently eat a live invite).
    @Test
    fun expiredRow_isDroppedOnLoad_futureStampIsKept() {
        val vault = InMemoryVault()
        piPaired(vault, "friend")
        val adm = piMid(1); val me = piMid(2)
        val now = currentTimeMillis()
        val oldGid = GroupManager.newGroupId(); val futureGid = GroupManager.newGroupId()

        vault.putMeta(
            piKey(oldGid, "friend"),
            GroupInviteStore.encode(piStoredInvite(oldGid, "friend", adm, me, listOf(adm, me)),
                now - PARKED_INVITE_TTL_MS - 1),
        )
        vault.putMeta(
            piKey(futureGid, "friend"),
            GroupInviteStore.encode(piStoredInvite(futureGid, "friend", adm, me, listOf(adm, me)),
                now + 60L * 60 * 1000),
        )

        val gm = GroupManager(vault) { null }
        assertEquals(listOf(futureGid), gm.pendingInvites().map { it.groupId },
            "the expired row is gone; a future-stamped one is kept")
        assertNull(vault.getMeta(piKey(oldGid, "friend")), "the expired row is deleted, not left behind")
        assertNotNull(vault.getMeta(piKey(futureGid, "friend")))
    }

    // 6. ESTABLISH-ON-READ. A corrupt row, and a row TAMPERED into a state
    //    handleInvite itself would have refused, must both degrade to "no invite" —
    //    never a throw out of the constructor, never a parked invite.
    @Test
    fun corruptOrTamperedRows_neverPark_andNeverThrow() {
        val adm = piMid(1); val me = piMid(2); val bob = piMid(3)
        // A LIVE stamp everywhere, so each row is rejected by decode's validation
        // rather than incidentally by the TTL.
        val ts = currentTimeMillis()
        val bad = listOf(
            "not json at all",
            "",
            // epoch 0 / over the cap
            """{"n":"x","ep":"0","adm":"$adm","you":"$me","mem":"$adm,$me","ts":"$ts"}""",
            """{"n":"x","ep":"${GroupManager.MAX_GROUP_EPOCH + 1}","adm":"$adm","you":"$me","mem":"$adm,$me","ts":"$ts"}""",
            // admin == self
            """{"n":"x","ep":"1","adm":"$adm","you":"$adm","mem":"$adm","ts":"$ts"}""",
            // admin not in the member set
            """{"n":"x","ep":"1","adm":"$adm","you":"$me","mem":"$me,$bob","ts":"$ts"}""",
            // self not in the member set
            """{"n":"x","ep":"1","adm":"$adm","you":"$me","mem":"$adm,$bob","ts":"$ts"}""",
            // malformed memberId
            """{"n":"x","ep":"1","adm":"$adm","you":"$me","mem":"$adm,$me,NOTHEX","ts":"$ts"}""",
            // blank name
            """{"n":"   ","ep":"1","adm":"$adm","you":"$me","mem":"$adm,$me","ts":"$ts"}""",
            // non-numeric / absent stamp
            """{"n":"x","ep":"1","adm":"$adm","you":"$me","mem":"$adm,$me","ts":"soon"}""",
            """{"n":"x","ep":"1","adm":"$adm","you":"$me","mem":"$adm,$me"}""",
        )
        for (value in bad) {
            val vault = InMemoryVault()
            piPaired(vault, "friend")
            val gid = GroupManager.newGroupId()
            vault.putMeta(piKey(gid, "friend"), value)

            val gm = GroupManager(vault) { null }   // must not throw
            assertTrue(gm.pendingInvites().isEmpty(), "an unreadable/tampered row must never park: $value")
            assertNull(vault.getMeta(piKey(gid, "friend")), "…and is deleted as residue: $value")
        }
    }

    // 6b. A row whose stamp is fine but whose KEY shape is wrong (an extra segment)
    //     is not ours to act on — it decodes to null and is dropped.
    @Test
    fun rowWithMalformedKey_isNotParked() {
        val vault = InMemoryVault()
        piPaired(vault, "friend")
        val adm = piMid(1); val me = piMid(2)
        val gid = GroupManager.newGroupId()
        vault.putMeta(
            GroupInviteMetaKeys.PREFIX + gid + ":friend:extra",
            GroupInviteStore.encode(piStoredInvite(gid, "friend", adm, me, listOf(adm, me)), currentTimeMillis()),
        )
        assertTrue(GroupManager(vault) { null }.pendingInvites().isEmpty(),
            "a key with the wrong segment count decodes to nothing")
    }

    // 7. A row for a group we are ALREADY IN (an accept whose row delete did not
    //    land) self-heals: no duplicate consent prompt, and the row is dropped.
    @Test
    fun rowForAnAlreadyJoinedGroup_selfHeals() {
        val vault = InMemoryVault()
        piPaired(vault, "friend")
        val adm = piMid(1); val me = piMid(2)
        val gid = GroupManager.newGroupId()

        val gm1 = GroupManager(vault) { null }
        gm1.handleControl("friend", gid, GroupManager.KIND_INVITE, piInvite(adm, me, listOf(adm, me)))
        assertTrue(gm1.acceptInvite(gid))
        // Simulate a torn accept: the group committed, the row delete did not.
        vault.putMeta(
            piKey(gid, "friend"),
            GroupInviteStore.encode(piStoredInvite(gid, "friend", adm, me, listOf(adm, me)), currentTimeMillis()),
        )

        val gm2 = GroupManager(vault) { null }
        assertTrue(gm2.pendingInvites().isEmpty(), "no consent prompt for a group already joined")
        assertNull(vault.getMeta(piKey(gid, "friend")), "the stale row is dropped")
    }

    // 8. BOUNDED: past MAX_PARKED_INVITES the OLDEST rows are evicted on load, the
    //    newest survive. (The per-contact cap still gates PARKING; this is the
    //    global backstop on vault growth across sessions.)
    @Test
    fun parkedInvites_areCappedToTheNewest() {
        val vault = InMemoryVault()
        piPaired(vault, "friend")
        val adm = piMid(1); val me = piMid(2)
        val base = currentTimeMillis()
        val extra = 5
        val gids = (0 until GroupInviteStore.MAX_PARKED_INVITES + extra).map { GroupManager.newGroupId() }
        gids.forEachIndexed { i, gid ->
            vault.putMeta(
                piKey(gid, "friend"),
                GroupInviteStore.encode(piStoredInvite(gid, "friend", adm, me, listOf(adm, me)), base + i),
            )
        }

        val gm = GroupManager(vault) { null }
        assertEquals(GroupInviteStore.MAX_PARKED_INVITES, gm.pendingInvites().size, "the set is capped")
        val parked = gm.pendingInvites().map { it.groupId }.toSet()
        for (i in 0 until extra) {
            assertFalse(gids[i] in parked, "the oldest rows are evicted")
            assertNull(vault.getMeta(piKey(gids[i], "friend")), "…and deleted from the vault")
        }
        assertTrue(gids.last() in parked, "the newest row survives")
    }

    // 9. The DECLINE TOMBSTONE outranks a surviving row: if the decline landed but
    //    its row delete did not, the rehydrate must NOT re-prompt — and must finish
    //    the delete.
    @Test
    fun declinedOffer_withSurvivingRow_doesNotRePrompt() {
        val vault = InMemoryVault()
        piPaired(vault, "friend")
        val adm = piMid(1); val me = piMid(2)
        val gid = GroupManager.newGroupId()

        val gm1 = GroupManager(vault) { null }
        gm1.handleControl("friend", gid, GroupManager.KIND_INVITE, piInvite(adm, me, listOf(adm, me)))
        gm1.declineInvite(gid)
        // Re-plant the row exactly as a torn decline would have left it.
        vault.putMeta(
            piKey(gid, "friend"),
            GroupInviteStore.encode(piStoredInvite(gid, "friend", adm, me, listOf(adm, me)), currentTimeMillis()),
        )

        val gm2 = GroupManager(vault) { null }
        assertTrue(gm2.pendingInvites().isEmpty(), "a declined offer must never re-prompt from a stale row")
        assertNull(vault.getMeta(piKey(gid, "friend")), "…and the rehydrate finishes the delete")
    }

    // 10. FAIL-SOFT: a `_meta` write that refuses the mirror must not break the
    //     consent gate. The invite still parks in RAM and still accepts; it is simply
    //     not durable (the pre-existing behaviour).
    @Test
    fun persistFailure_stillParks_andStillAccepts() {
        val vault = object : InMemoryVault() {
            override fun putMeta(key: String, value: String) {
                if (key.startsWith(GroupInviteMetaKeys.PREFIX)) {
                    throw IllegalStateException("simulated _meta write failure")
                }
                super.putMeta(key, value)
            }
        }
        piPaired(vault, "friend")
        val adm = piMid(1); val me = piMid(2)
        val gid = GroupManager.newGroupId()

        val gm = GroupManager(vault) { null }
        gm.handleControl("friend", gid, GroupManager.KIND_INVITE, piInvite(adm, me, listOf(adm, me)))
        assertEquals(1, gm.pendingInvites().size, "the invite still parks in RAM")
        assertNull(vault.getMeta(piKey(gid, "friend")), "the refused write left nothing on disk")
        assertTrue(gm.acceptInvite(gid), "the accept is unaffected")
        assertNotNull(vault.getGroup(gid))
    }

    // 11. A FAILED accept leaves the invite re-acceptable after a relaunch: the
    //     rollback's deleteGroup legitimately purges the row, so accept must put it
    //     back.
    @Test
    fun failedAccept_leavesTheInviteReAcceptableAfterReload() {
        val vault = object : InMemoryVault() {
            var failInserts = true
            override fun insertGroup(group: GroupRecord): Long {
                if (failInserts) throw IllegalStateException("simulated group insert failure")
                return super.insertGroup(group)
            }
        }
        piPaired(vault, "friend")
        val adm = piMid(1); val me = piMid(2)
        val gid = GroupManager.newGroupId()

        val gm1 = GroupManager(vault) { null }
        gm1.handleControl("friend", gid, GroupManager.KIND_INVITE, piInvite(adm, me, listOf(adm, me)))
        assertFalse(gm1.acceptInvite(gid), "the accept fails")
        assertNull(vault.getGroup(gid), "nothing was joined")
        assertNotNull(vault.getMeta(piKey(gid, "friend")),
            "a FAILED accept must not consume the durable invite")

        vault.failInserts = false
        val gm2 = GroupManager(vault) { null }
        assertEquals(1, gm2.pendingInvites().size, "the invite is back after a relaunch")
        assertTrue(gm2.acceptInvite(gid), "and can be accepted")
    }

    // 12. The rehydrate must NOT re-spend the per-contact invite rate budget — an
    //     invite parked in a previous session already paid for its stamp.
    @Test
    fun rehydrate_consumesNoRateBudget() {
        val vault = InMemoryVault()
        piPaired(vault, "friend")
        val adm = piMid(1); val me = piMid(2)

        val gm1 = GroupManager(vault) { null }
        gm1.handleControl("friend", GroupManager.newGroupId(), GroupManager.KIND_INVITE,
            piInvite(adm, me, listOf(adm, me)))
        assertEquals(1, gm1.pendingInvites().size)

        // New session: the one parked invite reloads without touching the window.
        val gm2 = GroupManager(vault) { null }
        assertEquals(1, gm2.pendingInvites().size)
        repeat(GroupManager.MAX_INVITES_PER_WINDOW - 1) {
            gm2.handleControl("friend", GroupManager.newGroupId(), GroupManager.KIND_INVITE,
                piInvite(adm, me, listOf(adm, me)))
        }
        assertEquals(GroupManager.MAX_INVITES_PER_WINDOW, gm2.pendingInvites().size,
            "all MAX-1 remaining distinct offers still park — the reload ate no budget")
    }

    // 13. PURGE-CLASSIFIER pin. `grp_pinv:` must be matched by its OWN two
    //     classifiers on both id segments, must respect the `:` boundary (AB vs ABC),
    //     and must not be confused with any sibling namespace.
    @Test
    fun residueClassifiers_matchBothSegments_andNothingElse() {
        val k = GroupInviteStore.keyFor("G1", "C1")
        assertTrue(isGroupInviteResidueForGroup(k, "G1"))
        assertTrue(isGroupInviteResidueForContact(k, "C1"))
        assertFalse(isGroupInviteResidueForGroup(k, "G2"))
        assertFalse(isGroupInviteResidueForContact(k, "C2"))
        // Empty ids never match anything (they would otherwise match every key).
        assertFalse(isGroupInviteResidueForGroup(k, ""))
        assertFalse(isGroupInviteResidueForContact(k, ""))
        // Prefix-sharing ids must not straddle the `:` boundary, in BOTH positions.
        assertFalse(isGroupInviteResidueForGroup(GroupInviteStore.keyFor("ABC", "C1"), "AB"))
        assertTrue(isGroupInviteResidueForGroup(GroupInviteStore.keyFor("AB", "C1"), "AB"))
        assertFalse(isGroupInviteResidueForContact(GroupInviteStore.keyFor("G1", "ABC"), "AB"))
        assertTrue(isGroupInviteResidueForContact(GroupInviteStore.keyFor("G1", "AB"), "AB"))

        // No cross-matching with the sibling namespaces, in either direction.
        assertFalse(isGroupMetaResidueForGroup(k, "G1"))
        assertFalse(isGroupMetaResidueForContact(k, "C1"))
        assertFalse(isScreenshotNoticeResidueForGroup(k, "G1"))
        assertFalse(isScreenshotNoticeResidueForContact(k, "C1"))
        assertFalse(isReferralMetaKey(k))
        assertFalse(k in ratchetMetaKeysForContact("C1"))
        for (other in listOf("grp_inv_rl:C1", "grp_roster_rl:G1:C1", "grp_ctl_pend:G1:C1",
                "grp_declined", "group_admin:G1", "ssn:G1:C1:5")) {
            assertFalse(isGroupInviteResidueForGroup(other, "G1"), "must not claim $other")
            assertFalse(isGroupInviteResidueForContact(other, "C1"), "must not claim $other")
        }
    }

    // 14. CODEC round-trip: what a park writes is exactly what a load reads back,
    //     and nothing beyond the invite's own wire fields plus our stamp is stored.
    @Test
    fun codec_roundTripsTheInviteFields_andStoresNothingElse() {
        val adm = piMid(1); val me = piMid(2); val bob = piMid(7)
        val gid = GroupManager.newGroupId()
        val invite = GroupInvite(
            groupId = gid, inviterContactId = "friend", inviterAlias = "SECRET-ALIAS",
            groupName = "Hazel \"crew\"", epoch = 42, adminMemberId = adm, myMemberId = me,
            memberIds = listOf(adm, me, bob), adminMismatch = true, priorAdminAlias = "SECRET-PRIOR",
        )
        val encoded = GroupInviteStore.encode(invite, 1_700_000_000_000L)
        // The display-only fields are re-derived at load, never persisted.
        assertFalse("SECRET-ALIAS" in encoded, "the inviter alias is never stored")
        assertFalse("SECRET-PRIOR" in encoded, "the prior-admin alias is never stored")

        val decoded = assertNotNull(GroupInviteStore.decode(piKey(gid, "friend"), encoded))
        assertEquals(gid, decoded.groupId)
        assertEquals("friend", decoded.inviterContactId)
        assertEquals("Hazel \"crew\"", decoded.groupName)
        assertEquals(42L, decoded.epoch)
        assertEquals(adm, decoded.adminMemberId)
        assertEquals(me, decoded.myMemberId)
        assertEquals(listOf(adm, me, bob), decoded.memberIds)
        assertEquals(1_700_000_000_000L, decoded.receivedAt)
        assertEquals(1_700_000_000_000L + PARKED_INVITE_TTL_MS, decoded.expiresAt)

        // A key from another namespace is never decoded as ours.
        assertNull(GroupInviteStore.decode("ssn:$gid:friend:5", encoded))
        // An unstorable id shape is refused outright.
        assertFalse(GroupInviteStore.isStorableId(""))
        assertFalse(GroupInviteStore.isStorableId("a:b"))
        assertFalse(GroupInviteStore.isStorableId("a|b"))
        assertTrue(GroupInviteStore.isStorableId(gid))
    }

    // 15. A FULL-VAULT WIPE takes the rows with everything else — no wipe path needs
    //     to enumerate this namespace.
    @Test
    fun parkedInviteRows_dieWithAFullVaultWipe() {
        val vault = InMemoryVault()
        piPaired(vault, "friend")
        val adm = piMid(1); val me = piMid(2)
        val gid = GroupManager.newGroupId()
        val gm = GroupManager(vault) { null }
        gm.handleControl("friend", gid, GroupManager.KIND_INVITE, piInvite(adm, me, listOf(adm, me)))
        assertNotNull(vault.getMeta(piKey(gid, "friend")))

        vault.wipeAllTables()
        assertNull(vault.getMeta(piKey(gid, "friend")))
        assertTrue(GroupManager(vault) { null }.pendingInvites().isEmpty())
    }

    // ------------------------------------------------------------------------
    // The durable mirror write moved OUTSIDE
    // [GroupManager.pendingInviteLock] (that lock is a blocking main-thread lock
    // taken every 4 s by pendingInvites(), and record() does a full `_meta` key
    // scan + per-row reads + a transaction — it must never run while the lock is
    // held), and handleInvite gained a second `vault.getGroup` re-check
    // immediately before the park to close the TOCTOU window against a
    // concurrent acceptInvite.
    // ------------------------------------------------------------------------

    // 16. A park still lands EXACTLY ONE durable row (no double-write from
    //     splitting the RAM mutation and the persist across the lock boundary),
    //     and the RAM entry is visible via pendingInvites() synchronously —
    //     handleControl is blocking, so there is no window where the caller has
    //     returned but pendingInvites() has not yet caught up.
    @Test
    fun park_persistsExactlyOneRow_andRamIsImmediatelyVisible() {
        val vault = InMemoryVault()
        piPaired(vault, "friend")
        val adm = piMid(1); val me = piMid(2)
        val gid = GroupManager.newGroupId()

        val gm = GroupManager(vault) { null }
        gm.handleControl("friend", gid, GroupManager.KIND_INVITE, piInvite(adm, me, listOf(adm, me)))

        assertEquals(1, vault.metaKeys().count { it == piKey(gid, "friend") },
            "exactly one durable row for this (group, inviter)")
        assertNotNull(vault.getMeta(piKey(gid, "friend")))
        val ram = gm.pendingInvites()
        assertEquals(1, ram.size, "the RAM park is visible immediately, synchronously")
        assertEquals(gid, ram.first().groupId)
    }

    // 17. TOCTOU close: a group that becomes joined AFTER handleInvite's
    //     top-of-function guard but BEFORE the re-check taken immediately before
    //     the park must still be caught by that re-check — no park, no durable
    //     row. Modelled with a vault double whose getGroup() answers "not joined"
    //     on the FIRST call (the top-of-function guard) and "joined" from the
    //     SECOND call onward (the re-check under the lock) for this groupId —
    //     standing in for a concurrent acceptInvite landing mid-handleInvite.
    @Test
    fun handleInvite_reCheckCatchesAGroupThatBecameJoinedMidCall() {
        val gid = GroupManager.newGroupId()
        val adm = piMid(1); val me = piMid(2)
        var getGroupCalls = 0
        val vault = object : InMemoryVault() {
            override fun getGroup(groupId: String): GroupRecord? {
                if (groupId != gid) return super.getGroup(groupId)
                getGroupCalls++
                return if (getGroupCalls >= 2) {
                    GroupRecord(
                        groupId = gid, name = "x", epoch = 1,
                        adminMemberId = adm, myMemberId = me, createdAt = 0L,
                    )
                } else null
            }
        }
        piPaired(vault, "friend")

        val gm = GroupManager(vault) { null }
        gm.handleControl("friend", gid, GroupManager.KIND_INVITE, piInvite(adm, me, listOf(adm, me)))

        assertTrue(getGroupCalls >= 2, "the re-check must actually run for this to be a real test")
        assertTrue(gm.pendingInvites().isEmpty(), "no park once the group is joined mid-call")
        assertNull(vault.getMeta(piKey(gid, "friend")), "…and no durable row is written")
    }

    // 18. record() itself catches every Throwable internally (see
    //     GroupInviteStore.record), so it structurally cannot propagate an
    //     exception to handleInvite — there is no way to drive "record() throws
    //     while the lock is held" from outside the store. What IS reachable, and
    //     what this pins instead: a vault that throws INSIDE record()'s
    //     transaction must not leave handleInvite's caller-visible state broken —
    //     no exception escapes handleControl, the RAM park still stands
    //     (fail-soft), and [pendingInviteLock] — taken again by pendingInvites()
    //     right after — is still usable (not stuck held from the failed attempt).
    @Test
    fun recordFailureInsideTransaction_leavesTheLockUsableAndRamIntact() {
        val vault = object : InMemoryVault() {
            override fun putMeta(key: String, value: String) {
                if (key.startsWith(GroupInviteMetaKeys.PREFIX)) {
                    throw IllegalStateException("simulated failure inside record()'s transaction")
                }
                super.putMeta(key, value)
            }
        }
        piPaired(vault, "friend")
        val adm = piMid(1); val me = piMid(2)
        val gid = GroupManager.newGroupId()

        val gm = GroupManager(vault) { null }
        // Must not throw out of handleControl even though the durable write fails.
        gm.handleControl("friend", gid, GroupManager.KIND_INVITE, piInvite(adm, me, listOf(adm, me)))

        assertEquals(1, gm.pendingInvites().size,
            "RAM park survives a durable-write failure, and the lock is still usable")
        assertNull(vault.getMeta(piKey(gid, "friend")), "nothing durable was written")
    }
}

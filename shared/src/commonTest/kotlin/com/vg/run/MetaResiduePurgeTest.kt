package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * After a user-initiated delete, no
 * group-scoped `_meta` residue for the deleted contact/group may survive in the
 * vault. The purge is driven by the shared classifiers
 * [isGroupMetaResidueForGroup] / [isGroupMetaResidueForContact] — and, since the
 * screenshot notices became durable,
 * [isScreenshotNoticeResidueForGroup] / [isScreenshotNoticeResidueForContact] —
 * which BOTH VaultDatabase actuals (Android [DatabaseManager], iOS
 * `IosVaultDatabase`) and the [InMemoryVault] test double route through, in the
 * same loop. Pinning the classifiers here pins the IDENTICAL purge set on every
 * platform (the bug was precisely a one-sided/incomplete purge list).
 */
class MetaResiduePurgeTest {

    private val G1 = "grpABC_def"   // Base64Url groupId — underscore included on purpose
    private val G2 = "grpZZZ999"
    private val C1 = "11111111-1111-1111-1111-111111111111"
    private val C2 = "22222222-2222-2222-2222-222222222222"

    private fun rosterKey(g: String, c: String) = "grp_roster_rl:$g:$c"
    private fun inviteKey(c: String) = "grp_inv_rl:$c"
    private fun adminKey(g: String) = "group_admin:$g"
    /** `ssn:<conversationId>:<senderContactId>:<receivedAtMs>` — one per notice. */
    private fun ssnKey(conv: String, sender: String, ms: Long = 1_700_000_000_000L) =
        "ssn:$conv:$sender:$ms"

    // ---- classifier: GROUP scope (drives deleteGroup) --------------------

    @Test
    fun groupClassifier_matchesRosterThrottle_forThatGroupOnly() {
        assertTrue(isGroupMetaResidueForGroup(rosterKey(G1, C1), G1))
        assertTrue(isGroupMetaResidueForGroup(rosterKey(G1, C2), G1))
        assertFalse(isGroupMetaResidueForGroup(rosterKey(G2, C1), G1),
            "another group's roster key must not be classified as G1 residue")
    }

    @Test
    fun groupClassifier_retainsAdminTombstone() {
        // The anti-eclipse tombstone must SURVIVE deleteGroup.
        assertFalse(isGroupMetaResidueForGroup(adminKey(G1), G1))
    }

    @Test
    fun groupClassifier_ignoresContactAndRatchetKeys() {
        assertFalse(isGroupMetaResidueForGroup(inviteKey(C1), G1))
        for (k in ratchetMetaKeysForContact(C1)) assertFalse(isGroupMetaResidueForGroup(k, G1))
        assertFalse(isGroupMetaResidueForGroup("seeded", G1))
    }

    @Test
    fun groupClassifier_prefixSiblingGroupDoesNotStraddleBoundary() {
        // "AB" must not swallow "ABC"'s roster keys — the trailing ':' is the guard.
        assertFalse(isGroupMetaResidueForGroup(rosterKey("ABC", C1), "AB"))
        assertTrue(isGroupMetaResidueForGroup(rosterKey("AB", C1), "AB"))
    }

    // ---- classifier: CONTACT scope (drives deleteContact) ----------------

    @Test
    fun contactClassifier_matchesInviteThrottleAndRosterAcrossAllGroups() {
        assertTrue(isGroupMetaResidueForContact(inviteKey(C1), C1))
        assertTrue(isGroupMetaResidueForContact(rosterKey(G1, C1), C1))
        assertTrue(isGroupMetaResidueForContact(rosterKey(G2, C1), C1),
            "roster residue must be purged in EVERY group, not just the current ones")
    }

    @Test
    fun contactClassifier_ignoresOtherContactsAndTombstone() {
        assertFalse(isGroupMetaResidueForContact(inviteKey(C2), C1))
        assertFalse(isGroupMetaResidueForContact(rosterKey(G1, C2), C1))
        // group_admin's VALUE is a contactId but it is a group-scoped tombstone.
        assertFalse(isGroupMetaResidueForContact(adminKey(G1), C1))
        for (k in ratchetMetaKeysForContact(C1)) assertFalse(isGroupMetaResidueForContact(k, C1))
    }

    // ---- the exact purge SET both platforms delete -----------------------

    @Test
    fun deleteGroup_purgeSet_isExactlyThatGroupsRosterKeys() {
        val universe = listOf(
            rosterKey(G1, C1), rosterKey(G1, C2), adminKey(G1),
            rosterKey(G2, C1), inviteKey(C1), "seeded",
        ) + ratchetMetaKeysForContact(C1)
        val purged = universe.filter { isGroupMetaResidueForGroup(it, G1) }.toSet()
        assertEquals(setOf(rosterKey(G1, C1), rosterKey(G1, C2)), purged)
    }

    @Test
    fun deleteContact_purgeSet_isInviteAndRosterKeysAcrossGroups() {
        val universe = listOf(
            inviteKey(C1), inviteKey(C2), adminKey(G1),
            rosterKey(G1, C1), rosterKey(G2, C1), rosterKey(G1, C2),
        )
        val purged = universe.filter { isGroupMetaResidueForContact(it, C1) }.toSet()
        assertEquals(setOf(inviteKey(C1), rosterKey(G1, C1), rosterKey(G2, C1)), purged)
    }

    // ---- behavioural, through VaultDatabase (InMemoryVault mirrors actuals) ----

    @Test
    fun deleteGroup_removesRosterResidue_keepsTombstoneAndOtherGroups() {
        val v = InMemoryVault()
        v.putMeta(rosterKey(G1, C1), "1000")
        v.putMeta(rosterKey(G1, C2), "2000")
        v.putMeta(adminKey(G1), C1)
        v.putMeta(rosterKey(G2, C1), "3000")
        v.putMeta(inviteKey(C1), "10,20")

        v.deleteGroup(G1)

        assertNull(v.getMeta(rosterKey(G1, C1)), "left/deleted group's per-member roster residue must be gone")
        assertNull(v.getMeta(rosterKey(G1, C2)))
        assertNotNull(v.getMeta(adminKey(G1)), "admin tombstone must survive (M2 anti-eclipse)")
        assertNotNull(v.getMeta(rosterKey(G2, C1)), "another group's residue must be untouched")
        assertNotNull(v.getMeta(inviteKey(C1)), "a contact-scoped invite throttle is not group residue")
    }

    @Test
    fun deleteContact_removesInviteAndRosterResidue_keepsOtherContacts() {
        val v = InMemoryVault()
        v.insertContact(ContactRecord(
            contactId = C1, sharedSecret = ByteArray(32) { 7 },
            trustLevel = 1, alias = "A", aliasLastRotated = 0L,
        ))
        v.putMeta(inviteKey(C1), "10,20")
        v.putMeta(rosterKey(G1, C1), "1000")
        v.putMeta(rosterKey(G2, C1), "2000")
        v.putMeta(inviteKey(C2), "30")
        v.putMeta(rosterKey(G1, C2), "4000")
        v.putMeta(adminKey(G1), C1)   // valued by C1, but a group-scoped tombstone

        v.deleteContact(C1)

        assertNull(v.getMeta(inviteKey(C1)), "deleted contact's invite timeline must be gone")
        assertNull(v.getMeta(rosterKey(G1, C1)), "deleted contact's roster residue must be gone in every group")
        assertNull(v.getMeta(rosterKey(G2, C1)))
        assertNotNull(v.getMeta(inviteKey(C2)), "another contact's throttle must be untouched")
        assertNotNull(v.getMeta(rosterKey(G1, C2)))
        assertNotNull(v.getMeta(adminKey(G1)), "group_admin tombstone is group-scoped — kept on contact delete")
        assertNull(v.getContact(C1))
    }

    // ---- The pending read-cap rotation markers -----------------------

    @Test
    fun deleteContact_purgesPendingCapRotationMarkers_forBothDirections() {
        // `cap-pend/{contactId}/{direction}` holds a LIVE relay capability candidate
        // (the inbox OWNER capability), so leaving one behind on delete would be a
        // new capability leak in the vault — exactly the residue class this purge
        // list exists for. Both inbound directions must go; another contact's must
        // survive.
        val v = InMemoryVault()
        v.insertContact(ContactRecord(
            contactId = C1, sharedSecret = ByteArray(32) { 7 },
            trustLevel = 1, alias = "A", aliasLastRotated = 0L,
        ))
        val mainKey = MessageManager.capPendingKey(C1, "inbound")
        val ctlKey = MessageManager.capPendingKey(C1, MessageManager.DIR_INBOUND_CTL)
        val otherKey = MessageManager.capPendingKey(C2, "inbound")
        v.putMeta(mainKey, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        v.putMeta(ctlKey, "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
        v.putMeta(otherKey, "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC")

        v.deleteContact(C1)

        assertNull(v.getMeta(mainKey), "the text inbox's pending cap marker must be purged")
        assertNull(v.getMeta(ctlKey), "the control inbox's pending cap marker must be purged too")
        assertNotNull(v.getMeta(otherKey), "another contact's marker must survive")
    }

    @Test
    fun pendingCapMarkerKeys_areInThePurgeList_forEveryOwnedDirection() {
        // Pin the coupling: any new owned inbound direction must appear in BOTH
        // OWNED_READ_DIRECTIONS and the shared purge list both actuals iterate.
        val keys = ratchetMetaKeysForContact(C1).toSet()
        for (direction in MessageManager.OWNED_READ_DIRECTIONS) {
            assertTrue(
                MessageManager.capPendingKey(C1, direction) in keys,
                "cap-pend/$C1/$direction must be purged by deleteContact",
            )
        }
    }

    // ---- The group-inbox backfill throttle ------------------------

    @Test
    fun deleteContact_purgesTheGroupInboxBackfillThrottle() {
        // `grp-ann/{contactId}` records how much of a per-contact budget of PoW
        // mints + inbox announces has been spent, and a RE-PAIR is one of only two
        // things that re-arm it. A record that outlived its contact would leave the
        // re-paired peer permanently on the legacy group route — the backfill would
        // read an exhausted budget for a pairing that never had one.
        val v = InMemoryVault()
        v.insertContact(ContactRecord(
            contactId = C1, sharedSecret = ByteArray(32) { 7 },
            trustLevel = 1, alias = "A", aliasLastRotated = 0L,
        ))
        val mine = MessageManager.groupBackfillKey(C1)
        val other = MessageManager.groupBackfillKey(C2)
        v.putMeta(mine, "4|1700000000000")
        v.putMeta(other, "1|1700000000000")

        v.deleteContact(C1)

        assertNull(v.getMeta(mine), "a spent backfill budget must never outlive its contact")
        assertNotNull(v.getMeta(other), "another contact's budget must survive")
    }

    @Test
    fun groupBackfillThrottleKey_isInTheExactPurgeList_andMatchedByNoOtherClassifier() {
        // The HYPHEN is load-bearing: `grp_` is the GROUP-manager namespace and must
        // not swallow a per-CONTACT key (the near-miss that hid `group_admin:` from
        // the move allowlist). So it belongs to the exact-key list and to nothing else.
        val k = MessageManager.groupBackfillKey(C1)
        assertEquals("grp-ann/$C1", k)
        assertTrue(k in ratchetMetaKeysForContact(C1), "grp-ann must be purged by deleteContact")
        assertFalse(k in ratchetMetaKeysForContact(C2), "…and only for ITS contact")
        assertFalse(isGroupMetaResidueForContact(k, C1), "not a group-manager key despite the prefix")
        assertFalse(isGroupMetaResidueForGroup(k, G1))
        assertFalse(isScreenshotNoticeResidueForContact(k, C1))
        assertFalse(isScreenshotNoticeResidueForGroup(k, G1))
        assertFalse(isReferralMetaKey(k))
    }

    @Test
    fun ratchetFallbackCounter_isInThePurgeList_andIsMatchedByNoOtherClassifier() {
        // `dr-legacyfb/{id}` counts consecutive
        // legacy fallbacks on a dr-on contact. It is per-contact, so it belongs to the
        // EXACT-key list — a re-pair must not inherit the old pairing's "forward
        // secrecy stalled" verdict — and to no other classifier.
        val k = MessageManager.drLegacyFallbackKey(C1)
        assertTrue(k in ratchetMetaKeysForContact(C1), "dr-legacyfb must be purged by deleteContact")
        assertFalse(k in ratchetMetaKeysForContact(C2), "…and only for ITS contact")
        assertFalse(isGroupMetaResidueForContact(k, C1))
        assertFalse(isGroupMetaResidueForGroup(k, G1))
        assertFalse(isScreenshotNoticeResidueForContact(k, C1))
        assertFalse(isScreenshotNoticeResidueForGroup(k, G1))
        assertFalse(isReferralMetaKey(k))

        val v = InMemoryVault()
        v.insertContact(ContactRecord(
            contactId = C1, sharedSecret = ByteArray(32) { 7 },
            trustLevel = 1, alias = "A", aliasLastRotated = 0L,
        ))
        v.putMeta(k, "9")
        v.putMeta(MessageManager.drLegacyFallbackKey(C2), "9")
        v.deleteContact(C1)
        assertNull(v.getMeta(k))
        assertNotNull(v.getMeta(MessageManager.drLegacyFallbackKey(C2)), "another contact's count survives")
    }

    @Test
    fun roleCollisionCountersAndRefusal_areInThePurgeList_andMatchedByNoOtherClassifier() {
        // `dr-rat-unacked/{id}` counts consecutive
        // inbound drains with no decryptable ratchet blob and `dr-refused/{id}` latches
        // the resulting refusal. A RE-PAIR is the documented way out of a refusal, so
        // both MUST be in the exact-key list both actuals iterate — a new pairing that
        // inherited the old one's verdict would refuse to send from its first message,
        // with no way to clear it.
        for (k in listOf(MessageManager.drRatUnackedKey(C1), MessageManager.drRefusedKey(C1))) {
            assertTrue(k in ratchetMetaKeysForContact(C1), "$k must be purged by deleteContact")
            assertFalse(k in ratchetMetaKeysForContact(C2), "…and only for ITS contact")
            assertFalse(isGroupMetaResidueForContact(k, C1))
            assertFalse(isGroupMetaResidueForGroup(k, G1))
            assertFalse(isScreenshotNoticeResidueForContact(k, C1))
            assertFalse(isScreenshotNoticeResidueForGroup(k, G1))
            assertFalse(isGroupInviteResidueForContact(k, C1))
            assertFalse(isGroupInviteResidueForGroup(k, G1))
            assertFalse(isReferralMetaKey(k))
        }

        val v = InMemoryVault()
        v.insertContact(ContactRecord(
            contactId = C1, sharedSecret = ByteArray(32) { 7 },
            trustLevel = 1, alias = "A", aliasLastRotated = 0L,
        ))
        v.putMeta(MessageManager.drRatUnackedKey(C1), "8")
        v.putMeta(MessageManager.drRefusedKey(C1), "1")
        v.putMeta(MessageManager.drRatUnackedKey(C2), "8")
        v.putMeta(MessageManager.drRefusedKey(C2), "1")

        v.deleteContact(C1)

        assertNull(v.getMeta(MessageManager.drRatUnackedKey(C1)), "the re-paired contact's evidence must be gone")
        assertNull(v.getMeta(MessageManager.drRefusedKey(C1)), "…and so must its refusal")
        assertNotNull(v.getMeta(MessageManager.drRatUnackedKey(C2)), "another contact's evidence survives")
        assertNotNull(v.getMeta(MessageManager.drRefusedKey(C2)), "…and its refusal")
    }

    @Test
    fun roleRuleInputs_areInThePurgeList_andMatchedByNoOtherClassifier() {
        // `dr-roleord/{id}` (our immutable ordering against the peer's
        // pairing contribution) and `dr-rolerv2/{id}` (the peer proved it runs rule
        // v2). A re-pair mints BRAND-NEW pairing secrets, so an inherited ordering bit
        // would be computed against the wrong pair — and combined with the new
        // pairing's own parity it could hand BOTH devices the same role, which is
        // precisely the collision the role-binding removes. They must die with the contact.
        for (k in listOf(MessageManager.drRoleOrderKey(C1), MessageManager.drPeerRoleRuleV2Key(C1))) {
            assertTrue(k in ratchetMetaKeysForContact(C1), "$k must be purged by deleteContact")
            assertFalse(k in ratchetMetaKeysForContact(C2), "…and only for ITS contact")
            assertFalse(isGroupMetaResidueForContact(k, C1))
            assertFalse(isGroupMetaResidueForGroup(k, G1))
            assertFalse(isScreenshotNoticeResidueForContact(k, C1))
            assertFalse(isScreenshotNoticeResidueForGroup(k, G1))
            assertFalse(isGroupInviteResidueForContact(k, C1))
            assertFalse(isGroupInviteResidueForGroup(k, G1))
            assertFalse(isReferralMetaKey(k))
        }

        val v = InMemoryVault()
        v.insertContact(ContactRecord(
            contactId = C1, sharedSecret = ByteArray(32) { 7 },
            trustLevel = 1, alias = "A", aliasLastRotated = 0L,
        ))
        v.putMeta(MessageManager.drRoleOrderKey(C1), "1")
        v.putMeta(MessageManager.drPeerRoleRuleV2Key(C1), "1")
        v.putMeta(MessageManager.drRoleOrderKey(C2), "0")
        v.putMeta(MessageManager.drPeerRoleRuleV2Key(C2), "1")

        v.deleteContact(C1)

        assertNull(v.getMeta(MessageManager.drRoleOrderKey(C1)), "the re-paired contact's role order must be gone")
        assertNull(v.getMeta(MessageManager.drPeerRoleRuleV2Key(C1)), "…and so must its v2 evidence")
        assertEquals("0", v.getMeta(MessageManager.drRoleOrderKey(C2)), "another contact's role order survives")
        assertEquals("1", v.getMeta(MessageManager.drPeerRoleRuleV2Key(C2)), "…and its v2 evidence")
    }

    // ---- classifier: persisted SCREENSHOT NOTICES (`ssn:`) ----------------
    // A predicate, not an exact-key list, because the key carries a variable
    // receivedAt suffix — which is also exactly why these keys must NOT be added to
    // ratchetMetaKeysForContact (that list can only name fixed keys).

    @Test
    fun screenshotClassifier_group_matchesThatGroupsNoticesOnly() {
        assertTrue(isScreenshotNoticeResidueForGroup(ssnKey(G1, C1), G1))
        assertTrue(isScreenshotNoticeResidueForGroup(ssnKey(G1, C2), G1))
        assertFalse(isScreenshotNoticeResidueForGroup(ssnKey(G2, C1), G1),
            "another group's notices must not be classified as G1 residue")
        // A 1:1 notice is keyed by contactId in the conversation slot — not group residue.
        assertFalse(isScreenshotNoticeResidueForGroup(ssnKey(C1, C1), G1))
    }

    @Test
    fun screenshotClassifier_group_prefixSiblingDoesNotStraddleBoundary() {
        // Same guard, same reason as the roster classifier: the trailing ':'.
        assertFalse(isScreenshotNoticeResidueForGroup(ssnKey("ABC", C1), "AB"))
        assertTrue(isScreenshotNoticeResidueForGroup(ssnKey("AB", C1), "AB"))
        assertFalse(isScreenshotNoticeResidueForGroup(ssnKey(G1, C1), ""))
    }

    @Test
    fun screenshotClassifier_contact_matchesBothIdPositions() {
        // The deleted contact as the CONVERSATION (their own 1:1 notices)…
        assertTrue(isScreenshotNoticeResidueForContact(ssnKey(C1, C1), C1))
        // …and as the SENDER inside a group the user is still in. Without this the
        // vault would keep naming a deleted contact as the screenshotter.
        assertTrue(isScreenshotNoticeResidueForContact(ssnKey(G1, C1), C1))
        assertTrue(isScreenshotNoticeResidueForContact(ssnKey(G2, C1), C1),
            "notice residue must be purged in EVERY group, not just the current ones")
    }

    @Test
    fun screenshotClassifier_contact_ignoresOtherContactsAndOtherNamespaces() {
        assertFalse(isScreenshotNoticeResidueForContact(ssnKey(C2, C2), C1))
        assertFalse(isScreenshotNoticeResidueForContact(ssnKey(G1, C2), C1))
        assertFalse(isScreenshotNoticeResidueForContact(ssnKey(C1, C1), ""))
        // Prefix siblings and foreign namespaces are never touched.
        assertFalse(isScreenshotNoticeResidueForContact("ssnx:$C1:$C1:1", C1))
        assertFalse(isScreenshotNoticeResidueForContact("ssn:$C1:$C1", C1),
            "a key that is not the 4-segment shape this namespace writes is left alone")
        assertFalse(isScreenshotNoticeResidueForContact("ssn:$C1:$C1:1:2", C1))
        assertFalse(isScreenshotNoticeResidueForContact(inviteKey(C1), C1))
        assertFalse(isScreenshotNoticeResidueForContact(rosterKey(G1, C1), C1))
        assertFalse(isScreenshotNoticeResidueForContact(adminKey(G1), C1))
        for (k in ratchetMetaKeysForContact(C1)) assertFalse(isScreenshotNoticeResidueForContact(k, C1))
        assertFalse(isScreenshotNoticeResidueForGroup(adminKey(G1), G1))
        for (k in ratchetMetaKeysForContact(C1)) assertFalse(isScreenshotNoticeResidueForGroup(k, G1))
    }

    @Test
    fun screenshotNoticeKeys_areDeliberatelyNotInTheExactKeyList() {
        // They cannot be: the receivedAt suffix is unbounded. Pinning it here stops a
        // future change from "tidying" them into ratchetMetaKeysForContact and
        // silently purging nothing.
        val exact = ratchetMetaKeysForContact(C1)
        assertTrue(exact.none { it.startsWith(ScreenshotNoticeMetaKeys.PREFIX) })
    }

    // ---- the exact purge SET both platforms delete (screenshot notices) ----

    @Test
    fun deleteGroup_purgeSet_includesThatGroupsNotices() {
        val universe = listOf(
            ssnKey(G1, C1), ssnKey(G1, C2, 2L), ssnKey(G2, C1), ssnKey(C1, C1),
            rosterKey(G1, C1), adminKey(G1), "seeded",
        )
        val purged = universe.filter {
            isGroupMetaResidueForGroup(it, G1) || isScreenshotNoticeResidueForGroup(it, G1)
        }.toSet()
        assertEquals(setOf(ssnKey(G1, C1), ssnKey(G1, C2, 2L), rosterKey(G1, C1)), purged)
    }

    @Test
    fun deleteContact_purgeSet_includesNoticesInBothIdPositions() {
        val universe = listOf(
            ssnKey(C1, C1), ssnKey(G1, C1), ssnKey(G2, C1, 5L),
            ssnKey(C2, C2), ssnKey(G1, C2), adminKey(G1), inviteKey(C1),
        )
        val purged = universe.filter {
            isGroupMetaResidueForContact(it, C1) || isScreenshotNoticeResidueForContact(it, C1)
        }.toSet()
        assertEquals(
            setOf(ssnKey(C1, C1), ssnKey(G1, C1), ssnKey(G2, C1, 5L), inviteKey(C1)),
            purged,
        )
    }

    // ---- behavioural, through VaultDatabase --------------------------------

    @Test
    fun deleteGroup_removesThatGroupsScreenshotNotices() {
        val v = InMemoryVault()
        v.putMeta(ssnKey(G1, C1), "1|1|0")
        v.putMeta(ssnKey(G1, C2, 2L), "1|1|0")
        v.putMeta(ssnKey(G2, C1), "1|1|0")
        v.putMeta(ssnKey(C1, C1), "1|0|0")
        v.putMeta(adminKey(G1), C1)

        v.deleteGroup(G1)

        assertNull(v.getMeta(ssnKey(G1, C1)), "the left/deleted group's notices must be gone")
        assertNull(v.getMeta(ssnKey(G1, C2, 2L)))
        assertNotNull(v.getMeta(ssnKey(G2, C1)), "another group's notices must be untouched")
        assertNotNull(v.getMeta(ssnKey(C1, C1)), "a 1:1 notice is not group residue")
        assertNotNull(v.getMeta(adminKey(G1)), "admin tombstone must still survive (M2 anti-eclipse)")
    }

    @Test
    fun deleteContact_removesTheirNoticesEverywhere_includingInsideGroups() {
        val v = InMemoryVault()
        v.insertContact(ContactRecord(
            contactId = C1, sharedSecret = ByteArray(32) { 7 },
            trustLevel = 1, alias = "A", aliasLastRotated = 0L,
        ))
        v.putMeta(ssnKey(C1, C1), "1|0|0")          // their own 1:1 notice
        v.putMeta(ssnKey(G1, C1), "1|1|0")          // them, screenshotting a group
        v.putMeta(ssnKey(G2, C1, 5L), "1|1|0")      // …and another group
        v.putMeta(ssnKey(C2, C2), "1|0|0")          // another contact's 1:1 notice
        v.putMeta(ssnKey(G1, C2), "1|1|0")          // another member's group notice

        v.deleteContact(C1)

        assertNull(v.getMeta(ssnKey(C1, C1)), "the deleted contact's 1:1 notices must be gone")
        assertNull(v.getMeta(ssnKey(G1, C1)), "…and every notice naming them as the screenshotter")
        assertNull(v.getMeta(ssnKey(G2, C1, 5L)))
        assertNotNull(v.getMeta(ssnKey(C2, C2)), "another contact's notices must survive")
        assertNotNull(v.getMeta(ssnKey(G1, C2)), "a surviving member's group notice must survive")
        assertNull(v.getContact(C1))
    }

    // ---- vault SINGLETONS: named by no classifier, purged by no delete ------

    @Test
    fun updateNudgeThrottle_isUnmatchedByEveryResiduePredicate() {
        // `update_nudge_v1` names no contact and no group, so every classifier
        // must miss it — including with an EMPTY id, the shape a caller with an
        // unresolved contact/group would pass.
        val k = UPDATE_NUDGE_META_KEY
        assertFalse(isGroupMetaResidueForGroup(k, G1))
        assertFalse(isGroupMetaResidueForGroup(k, ""))
        assertFalse(isGroupMetaResidueForContact(k, C1))
        assertFalse(isGroupMetaResidueForContact(k, ""))
        assertFalse(isScreenshotNoticeResidueForGroup(k, G1))
        assertFalse(isScreenshotNoticeResidueForGroup(k, ""))
        assertFalse(isScreenshotNoticeResidueForContact(k, C1))
        assertFalse(isScreenshotNoticeResidueForContact(k, ""))
        assertFalse(isReferralMetaKey(k))
        assertFalse(k in ratchetMetaKeysForContact(C1))
        assertFalse(k in ratchetMetaKeysForContact(""))
    }

    @Test
    fun updateNudgeThrottle_survivesDeleteContactAndDeleteGroup() {
        val v = InMemoryVault()
        v.insertContact(ContactRecord(
            contactId = C1, sharedSecret = ByteArray(32) { 7 },
            trustLevel = 1, alias = "A", aliasLastRotated = 0L,
        ))
        v.putMeta(UPDATE_NUDGE_META_KEY, "9.9.9|20000")
        v.putMeta(inviteKey(C1), "10,20")
        v.putMeta(rosterKey(G1, C1), "1000")

        v.deleteContact(C1)
        assertEquals("9.9.9|20000", v.getMeta(UPDATE_NUDGE_META_KEY),
            "a vault singleton must survive a contact delete — it is not per-contact state")

        v.deleteGroup(G1)
        assertEquals("9.9.9|20000", v.getMeta(UPDATE_NUDGE_META_KEY),
            "…and a group delete")

        // The wipe is what erases it, with every other row.
        v.wipeAllTables()
        assertNull(v.getMeta(UPDATE_NUDGE_META_KEY))
    }

    @Test
    fun reviewPromptCounters_isUnmatchedByEveryResiduePredicate() {
        // `review_prompt_v1` names no
        // contact and no group, so every classifier must miss it — including
        // with an EMPTY id, the shape a caller with an unresolved contact/group
        // would pass. Same pin as updateNudgeThrottle above.
        val k = REVIEW_PROMPT_META_KEY
        assertFalse(isGroupMetaResidueForGroup(k, G1))
        assertFalse(isGroupMetaResidueForGroup(k, ""))
        assertFalse(isGroupMetaResidueForContact(k, C1))
        assertFalse(isGroupMetaResidueForContact(k, ""))
        assertFalse(isScreenshotNoticeResidueForGroup(k, G1))
        assertFalse(isScreenshotNoticeResidueForGroup(k, ""))
        assertFalse(isScreenshotNoticeResidueForContact(k, C1))
        assertFalse(isScreenshotNoticeResidueForContact(k, ""))
        assertFalse(isReferralMetaKey(k))
        assertFalse(k in ratchetMetaKeysForContact(C1))
        assertFalse(k in ratchetMetaKeysForContact(""))
    }

    @Test
    fun reviewPromptCounters_survivesDeleteContactAndDeleteGroup() {
        val v = InMemoryVault()
        v.insertContact(ContactRecord(
            contactId = C1, sharedSecret = ByteArray(32) { 7 },
            trustLevel = 1, alias = "A", aliasLastRotated = 0L,
        ))
        v.putMeta(REVIEW_PROMPT_META_KEY, "1700000000000|7|0")
        v.putMeta(inviteKey(C1), "10,20")
        v.putMeta(rosterKey(G1, C1), "1000")

        v.deleteContact(C1)
        assertEquals("1700000000000|7|0", v.getMeta(REVIEW_PROMPT_META_KEY),
            "a vault singleton must survive a contact delete — it is not per-contact state")

        v.deleteGroup(G1)
        assertEquals("1700000000000|7|0", v.getMeta(REVIEW_PROMPT_META_KEY),
            "…and a group delete")

        // The wipe is what erases it, with every other row.
        v.wipeAllTables()
        assertNull(v.getMeta(REVIEW_PROMPT_META_KEY))
    }

    // ---- classifier: PARKED GROUP INVITES (`grp_pinv:`) --------------------
    // Key `grp_pinv:<groupId>:<inviterContactId>` — the only `_meta` namespace whose
    // key carries BOTH ids, so it needs its own pair of classifiers and BOTH deletes
    // must purge it from their own segment. Full behavioural coverage lives in
    // GroupInvitePersistenceTest; this pins the cross-platform purge set.

    private fun pinvKey(g: String, c: String) = GroupInviteStore.keyFor(g, c)

    @Test
    fun parkedInviteClassifiers_matchBothSegments_andNoOtherNamespace() {
        assertTrue(isGroupInviteResidueForGroup(pinvKey(G1, C1), G1))
        assertTrue(isGroupInviteResidueForContact(pinvKey(G1, C1), C1))
        assertFalse(isGroupInviteResidueForGroup(pinvKey(G2, C1), G1))
        assertFalse(isGroupInviteResidueForContact(pinvKey(G1, C2), C1))
        // Empty ids never match (the shape a caller with an unresolved id would pass).
        assertFalse(isGroupInviteResidueForGroup(pinvKey(G1, C1), ""))
        assertFalse(isGroupInviteResidueForContact(pinvKey(G1, C1), ""))
        // `grp_pinv:` must not be claimed by — or claim — any sibling namespace.
        assertFalse(isGroupMetaResidueForGroup(pinvKey(G1, C1), G1))
        assertFalse(isGroupMetaResidueForContact(pinvKey(G1, C1), C1))
        assertFalse(isScreenshotNoticeResidueForGroup(pinvKey(G1, C1), G1))
        assertFalse(isScreenshotNoticeResidueForContact(pinvKey(G1, C1), C1))
        assertFalse(isReferralMetaKey(pinvKey(G1, C1)))
        assertFalse(pinvKey(G1, C1) in ratchetMetaKeysForContact(C1))
        for (k in listOf(inviteKey(C1), rosterKey(G1, C1), adminKey(G1), ssnKey(G1, C1), "grp_declined")) {
            assertFalse(isGroupInviteResidueForGroup(k, G1), "must not claim $k")
            assertFalse(isGroupInviteResidueForContact(k, C1), "must not claim $k")
        }
    }

    @Test
    fun deleteGroupAndDeleteContact_bothPurgeTheParkedInviteRow() {
        val v = InMemoryVault()
        v.insertContact(ContactRecord(
            contactId = C1, sharedSecret = ByteArray(32) { 7 },
            trustLevel = 1, alias = "A", aliasLastRotated = 0L,
        ))
        v.putMeta(pinvKey(G1, C1), "{}")
        v.putMeta(pinvKey(G2, C1), "{}")
        v.putMeta(pinvKey(G1, C2), "{}")

        // Leaving / being removed from a group reaches deleteGroup.
        v.deleteGroup(G1)
        assertNull(v.getMeta(pinvKey(G1, C1)), "the group's parked invite row must be purged")
        assertNull(v.getMeta(pinvKey(G1, C2)), "…for every inviter of that group")
        assertNotNull(v.getMeta(pinvKey(G2, C1)), "another group's row must be untouched")

        v.deleteContact(C1)
        assertNull(v.getMeta(pinvKey(G2, C1)), "the deleted inviter's parked invites must be purged")
    }

    @Test
    fun purgeLoops_leaveEveryOtherNamespaceIntact() {
        // The purge is scoped: a delete must never take out the ratchet/referral/
        // capability state of an unrelated contact, and must never widen beyond its
        // own namespaces.
        val v = InMemoryVault()
        v.putMeta("dr/$C2/text", "state")
        v.putMeta("ref_done", "abc")
        v.putMeta("seeded", "x")
        v.putMeta(ssnKey(C1, C1), "1|0|0")

        v.deleteContact(C1)

        assertNull(v.getMeta(ssnKey(C1, C1)))
        assertNotNull(v.getMeta("dr/$C2/text"))
        assertNotNull(v.getMeta("ref_done"))
        assertNotNull(v.getMeta("seeded"))
    }
}

package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// RÚN-06 — what a deleted group leaves behind, and what still works because of it.
//
// The owner kept the admin-of-record record (`group_admin:<groupId>`): it is the
// only thing that lets the changed-administrator warning fire for a group the user
// already left. What changed around it:
//  - deleting a CONTACT rewrites every record naming that contact to the "gone"
//    marker, atomically with the delete, on both actuals and the InMemoryVault;
//  - records an older build left naming an already-deleted contact are rewritten
//    the same way at session start (GroupManager init), on positive evidence only;
//  - persisted screenshot notices no longer travel with a device move, and expired
//    ones are pruned at session start, with no transport;
//  - unread markers never travelled; now pinned through the whole move pipeline.
//
// Every outcome of the warning must be unchanged: contact ids are never reused, so
// a deleted admin can never invite again, and "gone" warns exactly as the raw
// deleted id did (mismatch, no alias).
// ---------------------------------------------------------------------------

/** UUID-shaped ids, the form direct pairing mints (36 chars). */
private const val RR_ADMIN = "aaaaaaaa-0000-4000-8000-000000000001"
private const val RR_OTHER = "bbbbbbbb-0000-4000-8000-000000000002"
private const val RR_NEW = "cccccccc-0000-4000-8000-000000000003"

private fun rrMemberId(seed: Int) = bytesToHex(ByteArray(8) { (seed + it).toByte() })

private fun rrSeedPairedContact(vault: VaultDatabase, contactId: String) {
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
    vault.insertInboxId(InboxIdRecord(
        inboxId = ("oc$base".padEnd(32, 'C')).take(32), contactId = contactId,
        createdAt = 1L, expiresAt = Long.MAX_VALUE, direction = MessageManager.DIR_OUTBOUND_CTL, cap = "C".repeat(43),
    ))
}

private fun rrInvite(adm: String, you: String, mem: List<String>, ep: Long = 1, name: String = "crew"): String {
    val memJson = mem.joinToString(",") { jsonEscapeString(it) }
    return """{"n":${jsonEscapeString(name)},"ep":$ep,"adm":${jsonEscapeString(adm)},"you":${jsonEscapeString(you)},"mem":[$memJson]}"""
}

/** A (re-)invite for [gid] from [from], naming [from] as admin; returns what the consent prompt gets. */
private fun rrReinvite(g: GroupManager, from: String, gid: String, seed: Int = 40): GroupInvite {
    val adm = rrMemberId(seed); val me = rrMemberId(seed + 1)
    g.handleControl(from, gid, GroupManager.KIND_INVITE, rrInvite(adm, me, listOf(adm, me)))
    return g.pendingInvites().single { it.groupId == gid }
}

private fun rrAdminKey(gid: String) = "group_admin:$gid"

private const val GONE = "gone"

// ===========================================================================
// T1 — outcomes after GROUP deletion and after CONTACT deletion
// ===========================================================================

class GroupAdminRetentionTest {
    private val noTransport: () -> MessageManager? = { null }

    @Test
    fun selfCreatedGroup_afterLeave_reinviteByExMember_warnsWithoutAlias() {
        val vault = InMemoryVault()
        rrSeedPairedContact(vault, RR_OTHER)
        val g = GroupManager(vault, noTransport)
        val gid = g.createGroup("crew", listOf(RR_OTHER))!!
        g.leaveGroup(gid)
        assertNull(vault.getGroup(gid))

        val re = rrReinvite(g, RR_OTHER, gid)
        assertTrue(re.adminMismatch, "a group this device ran, re-offered by someone else, must warn")
        assertNull(re.priorAdminAlias)
    }

    @Test
    fun acceptedGroup_afterLeave_sameAdminIsQuiet_differentAdminWarnsWithAlias() {
        if (!aeadUp()) return
        // The two outcomes must stay DISTINCT: same admin quiet, other admin warns.
        for (reinviter in listOf(RR_ADMIN, RR_OTHER)) {
            val vault = InMemoryVault()
            rrSeedPairedContact(vault, RR_ADMIN)
            rrSeedPairedContact(vault, RR_OTHER)
            val g = GroupManager(vault, noTransport)
            val gid = GroupManager.newGroupId()
            val adm = rrMemberId(1); val me = rrMemberId(2)
            g.handleControl(RR_ADMIN, gid, GroupManager.KIND_INVITE, rrInvite(adm, me, listOf(adm, me)))
            assertTrue(g.acceptInvite(gid))
            g.leaveGroup(gid)
            assertNull(vault.getGroup(gid))

            val re = rrReinvite(g, reinviter, gid)
            if (reinviter == RR_ADMIN) {
                assertFalse(re.adminMismatch, "the legitimate returning admin must not warn")
                assertNull(re.priorAdminAlias)
            } else {
                assertTrue(re.adminMismatch, "an unexpected admin must warn")
                assertEquals("A-$RR_ADMIN", re.priorAdminAlias, "the recorded admin is still a contact, so it is named")
            }
        }
    }

    /**
     * Owner decision 2: deleting the admin's CONTACT rewrites the record to "gone"
     * (no deleted contact id stays in the vault), and the warning behaves exactly as
     * it did with the raw deleted id: someone else inviting warns, with no alias.
     */
    @Test
    fun afterContactDeletion_theRecordSaysGone_andTheOutcomeIsUnchanged() {
        if (!aeadUp()) return
        val vault = InMemoryVault()
        rrSeedPairedContact(vault, RR_ADMIN)
        rrSeedPairedContact(vault, RR_OTHER)
        val g = GroupManager(vault, noTransport)
        val gid = GroupManager.newGroupId()
        val adm = rrMemberId(1); val me = rrMemberId(2)
        g.handleControl(RR_ADMIN, gid, GroupManager.KIND_INVITE, rrInvite(adm, me, listOf(adm, me)))
        assertTrue(g.acceptInvite(gid))
        // A second group this device created, and a third run by the contact that stays.
        val selfGid = g.createGroup("mine", listOf(RR_OTHER))!!
        val otherGid = GroupManager.newGroupId()
        vault.putMeta(rrAdminKey(otherGid), RR_OTHER)
        g.leaveGroup(gid)

        vault.deleteContact(RR_ADMIN)

        assertEquals(GONE, vault.getMeta(rrAdminKey(gid)), "a record naming the deleted contact must say gone")
        assertTrue(
            vault.meta.values.none { it == RR_ADMIN },
            "no _meta value may still carry the deleted contact's id",
        )
        assertEquals(GroupManager.SELF_ADMIN_MARKER, vault.getMeta(rrAdminKey(selfGid)), "self is untouched")
        assertEquals(RR_OTHER, vault.getMeta(rrAdminKey(otherGid)), "another contact's record is untouched")

        // The person re-pairs (a new id) or someone else invites: warns, no alias —
        // byte-identical to what the raw deleted id produced.
        rrSeedPairedContact(vault, RR_NEW)
        val re = rrReinvite(g, RR_NEW, gid)
        assertTrue(re.adminMismatch)
        assertNull(re.priorAdminAlias)
        // The surviving contact's group keeps its quiet outcome.
        assertFalse(rrReinvite(g, RR_OTHER, otherGid, seed = 60).adminMismatch)
    }

    /** The same rewrite while the group is still LIVE (the admin's 1:1 contact deleted, membership kept). */
    @Test
    fun contactDeletion_whileGroupLive_rewritesToo_andLaterLeaveKeepsIt() {
        if (!aeadUp()) return
        val vault = InMemoryVault()
        rrSeedPairedContact(vault, RR_ADMIN)
        rrSeedPairedContact(vault, RR_OTHER)
        val g = GroupManager(vault, noTransport)
        val gid = GroupManager.newGroupId()
        val adm = rrMemberId(1); val me = rrMemberId(2)
        g.handleControl(RR_ADMIN, gid, GroupManager.KIND_INVITE, rrInvite(adm, me, listOf(adm, me)))
        assertTrue(g.acceptInvite(gid))

        vault.deleteContact(RR_ADMIN)
        assertEquals(GONE, vault.getMeta(rrAdminKey(gid)))
        g.leaveGroup(gid)
        assertEquals(GONE, vault.getMeta(rrAdminKey(gid)), "the record survives the leave as before")
        val re = rrReinvite(g, RR_OTHER, gid)
        assertTrue(re.adminMismatch)
        assertNull(re.priorAdminAlias)
    }

    /** The predicate itself: only an exact match on a `group_admin:` key, never a marker. */
    @Test
    fun theTombstonePredicateMatchesOnlyTheNamedContact() {
        val k = rrAdminKey("grpABC_def")
        assertTrue(groupAdminTombstoneNamesContact(k, RR_ADMIN, RR_ADMIN))
        assertFalse(groupAdminTombstoneNamesContact(k, RR_OTHER, RR_ADMIN))
        assertFalse(groupAdminTombstoneNamesContact(k, null, RR_ADMIN), "an unreadable value rewrites nothing")
        assertFalse(groupAdminTombstoneNamesContact(k, GroupManager.SELF_ADMIN_MARKER, GroupManager.SELF_ADMIN_MARKER))
        assertFalse(groupAdminTombstoneNamesContact(k, GONE, GONE))
        assertFalse(groupAdminTombstoneNamesContact(k, "", ""))
        assertFalse(groupAdminTombstoneNamesContact("grp_ctl_pend:g:$RR_ADMIN", RR_ADMIN, RR_ADMIN))
        assertFalse(groupAdminTombstoneNamesContact("xgroup_admin:g", RR_ADMIN, RR_ADMIN))
        assertEquals("group_admin:", GroupAdminTombstone.PREFIX)
        assertEquals(GONE, GroupAdminTombstone.DELETED_ADMIN)
    }
}

// ===========================================================================
// T2 — upgrade: records in the old form
// ===========================================================================

class GroupAdminTombstoneUpgradeTest {
    private val noTransport: () -> MessageManager? = { null }

    /**
     * A vault from 1.6.75 or older: raw contact ids and `self`, one of them naming a
     * contact deleted back then. The first session on this build rewrites the
     * dangling one to "gone", leaves everything else byte-identical, and every
     * warning outcome is the same as it was.
     */
    @Test
    fun oldRecords_danglingOneIsRewrittenAtSessionStart_outcomesUnchanged() {
        val vault = InMemoryVault()
        rrSeedPairedContact(vault, RR_OTHER)
        val gDangling = "grpDangling_1"; val gLive = "grpLive_2"; val gSelf = "grpSelf_3"; val gGone = "grpGone_4"
        vault.putMeta(rrAdminKey(gDangling), RR_ADMIN)        // contact deleted under an old build
        vault.putMeta(rrAdminKey(gLive), RR_OTHER)
        vault.putMeta(rrAdminKey(gSelf), GroupManager.SELF_ADMIN_MARKER)
        vault.putMeta(rrAdminKey(gGone), GONE)
        val gLive2 = "grpLive_5"                                // same live admin, offered by someone else
        vault.putMeta(rrAdminKey(gLive2), RR_OTHER)

        val g = GroupManager(vault, noTransport)

        assertEquals(GONE, vault.getMeta(rrAdminKey(gDangling)), "the dangling id is rewritten at session start")
        assertEquals(RR_OTHER, vault.getMeta(rrAdminKey(gLive)), "a live contact's record is never touched")
        assertEquals(GroupManager.SELF_ADMIN_MARKER, vault.getMeta(rrAdminKey(gSelf)))
        assertEquals(GONE, vault.getMeta(rrAdminKey(gGone)))

        val dangling = rrReinvite(g, RR_OTHER, gDangling, seed = 10)
        assertTrue(dangling.adminMismatch); assertNull(dangling.priorAdminAlias)
        assertFalse(rrReinvite(g, RR_OTHER, gLive, seed = 20).adminMismatch, "the returning admin stays quiet")
        val self = rrReinvite(g, RR_OTHER, gSelf, seed = 30)
        assertTrue(self.adminMismatch); assertNull(self.priorAdminAlias)
        rrSeedPairedContact(vault, RR_NEW)
        assertEquals(RR_OTHER, vault.getMeta(rrAdminKey(gLive2)))
        val other = rrReinvite(g, RR_NEW, gLive2, seed = 50)
        assertTrue(other.adminMismatch, "an unexpected admin still warns")
        assertEquals("A-$RR_OTHER", other.priorAdminAlias)
    }

    /** Idempotent: a second session writes nothing. */
    @Test
    fun theSessionStartRewrite_isIdempotent() {
        val writes = mutableListOf<String>()
        val vault = object : InMemoryVault() {
            override fun putMeta(key: String, value: String) { writes.add(key); super.putMeta(key, value) }
        }
        rrSeedPairedContact(vault, RR_OTHER)
        vault.putMeta(rrAdminKey("g1"), RR_ADMIN)
        GroupManager(vault, noTransport)
        assertEquals(GONE, vault.getMeta(rrAdminKey("g1")))
        writes.clear()
        GroupManager(vault, noTransport)
        assertTrue(writes.none { it.startsWith("group_admin:") }, "nothing to rewrite the second time")
    }

    /**
     * Positive evidence only. An EMPTY contact list is also what a closed vault or
     * an iOS query error answers, so it proves nothing: the record stays as it is
     * (the outcome is the same either way — the id can never invite again).
     */
    @Test
    fun anEmptyContactList_rewritesNothing() {
        val vault = InMemoryVault()
        vault.putMeta(rrAdminKey("g1"), RR_ADMIN)
        GroupManager(vault, noTransport)
        assertEquals(RR_ADMIN, vault.getMeta(rrAdminKey("g1")))
    }

    /** Two different queries must agree that the contact is gone. */
    @Test
    fun aSingleQueryClaimingAbsence_rewritesNothing() {
        // getContact answers null for everything (the iOS bridge's error shape), but
        // the full list still names the contact: no rewrite.
        val vault = object : InMemoryVault() {
            override fun getContact(contactId: String): ContactRecord? = null
        }
        rrSeedPairedContact(vault, RR_ADMIN)
        vault.putMeta(rrAdminKey("g1"), RR_ADMIN)
        GroupManager(vault, noTransport)
        assertEquals(RR_ADMIN, vault.getMeta(rrAdminKey("g1")))

        // …and the per-row lookup still sees the contact although the list omits it.
        val v2 = object : InMemoryVault() {
            override fun getAllContacts(): List<ContactRecord> =
                super.getAllContacts().filter { it.contactId != RR_ADMIN }
        }
        rrSeedPairedContact(v2, RR_ADMIN)
        rrSeedPairedContact(v2, RR_OTHER)
        v2.putMeta(rrAdminKey("g1"), RR_ADMIN)
        GroupManager(v2, noTransport)
        assertEquals(RR_ADMIN, v2.getMeta(rrAdminKey("g1")))
    }

    /** A throwing vault never takes the session down, and writes nothing. */
    @Test
    fun aFailingRead_isSwallowed_andConstructionSucceeds() {
        val vault = object : InMemoryVault() {
            override fun getAllContacts(): List<ContactRecord> = throw RuntimeException("transient")
        }
        vault.putMeta(rrAdminKey("g1"), RR_ADMIN)
        GroupManager(vault, noTransport)
        assertEquals(RR_ADMIN, vault.getMeta(rrAdminKey("g1")))
    }
}

// ===========================================================================
// T3 — after a device MOVE
// ===========================================================================

class GroupAdminTombstoneMoveTest {
    private val noTransport: () -> MessageManager? = { null }

    @Test
    fun theRecordsTravel_andBothOutcomesSurviveTheMove() {
        val old = InMemoryVault()
        rrSeedPairedContact(old, RR_ADMIN)
        rrSeedPairedContact(old, RR_OTHER)
        val gAdmin = "grpAdmin_1"; val gSelf = "grpSelf_2"; val gGone = "grpGone_3"
        old.putMeta(rrAdminKey(gAdmin), RR_ADMIN)
        old.putMeta(rrAdminKey(gSelf), GroupManager.SELF_ADMIN_MARKER)
        old.putMeta(rrAdminKey(gGone), GONE)

        val fresh = rrMoveThroughTheWholePipeline(old)

        assertEquals(RR_ADMIN, fresh.getMeta(rrAdminKey(gAdmin)))
        assertEquals(GroupManager.SELF_ADMIN_MARKER, fresh.getMeta(rrAdminKey(gSelf)))
        assertEquals(GONE, fresh.getMeta(rrAdminKey(gGone)))

        val g = GroupManager(fresh, noTransport)
        assertFalse(rrReinvite(g, RR_ADMIN, gAdmin, seed = 10).adminMismatch, "the returning admin stays quiet")
        val selfRe = rrReinvite(g, RR_OTHER, gSelf, seed = 20)
        assertTrue(selfRe.adminMismatch); assertNull(selfRe.priorAdminAlias)
        val goneRe = rrReinvite(g, RR_OTHER, gGone, seed = 30)
        assertTrue(goneRe.adminMismatch); assertNull(goneRe.priorAdminAlias)
    }

    @Test
    fun anUnexpectedAdminStillWarns_withTheAlias_afterTheMove() {
        val old = InMemoryVault()
        rrSeedPairedContact(old, RR_ADMIN)
        rrSeedPairedContact(old, RR_OTHER)
        old.putMeta(rrAdminKey("grpAdmin_1"), RR_ADMIN)
        val g = GroupManager(rrMoveThroughTheWholePipeline(old), noTransport)
        val re = rrReinvite(g, RR_OTHER, "grpAdmin_1")
        assertTrue(re.adminMismatch)
        assertEquals("A-$RR_ADMIN", re.priorAdminAlias)
    }
}

// ===========================================================================
// T4 — expired screenshot notices are pruned at session start, no transport
// ===========================================================================

class ScreenshotNoticeSessionStartPruneTest {
    @Test
    fun expiredNotices_areGoneAfterSessionStart_withNoTransport_liveOnesStay() {
        val vault = InMemoryVault()
        val now = currentTimeMillis()
        val expired = ScreenshotNoticeStore.keyFor("grpABC_def", RR_OTHER, now - SCREENSHOT_NOTICE_TTL_MS - 60_000L)
        val expiredDm = ScreenshotNoticeStore.keyFor(RR_OTHER, RR_OTHER, now - 2 * SCREENSHOT_NOTICE_TTL_MS)
        val live = ScreenshotNoticeStore.keyFor("grpABC_def", RR_OTHER, now - 60L * 60 * 1000)
        val corrupt = "ssn:grpABC_def:$RR_OTHER:notanumber"
        vault.putMeta(expired, ScreenshotNoticeStore.encode(now - SCREENSHOT_NOTICE_TTL_MS, true, false))
        vault.putMeta(expiredDm, ScreenshotNoticeStore.encode(1L, false, true))
        vault.putMeta(live, ScreenshotNoticeStore.encode(now - 60L * 60 * 1000, true, false))
        vault.putMeta(corrupt, "x")

        // The session layer builds the GroupManager before Tor is up: no transport.
        GroupManager(vault) { null }

        assertNull(vault.getMeta(expired), "an expired group notice must be pruned at session start")
        assertNull(vault.getMeta(expiredDm), "an expired 1:1 notice must be pruned at session start")
        assertNull(vault.getMeta(corrupt), "an undecodable row is pruned too")
        assertNotNull(vault.getMeta(live), "a live notice stays until its 24 h are up")
    }

    @Test
    fun aFailingScan_neverTakesTheSessionDown() {
        val vault = object : InMemoryVault() {
            override fun metaKeys(): List<String> = throw RuntimeException("transient")
        }
        GroupManager(vault) { null }   // must not throw
    }
}

// ===========================================================================
// T5 / T6 — neither screenshot notices nor unread markers ever arrive on the new phone
// ===========================================================================

class MoveExcludesDisplayHintsTest {

    private val ssn = "ssn:grpABC_def:$RR_OTHER:1700000000000"
    private val ssnDm = "ssn:$RR_OTHER:$RR_OTHER:1700000000001"
    private val marker = GroupUnreadMarkerStore.keyFor(RR_OTHER)

    private fun oldPhone(): InMemoryVault {
        val old = InMemoryVault()
        rrSeedPairedContact(old, RR_OTHER)
        old.putMeta(ssn, "1700000000000|1|0")
        old.putMeta(ssnDm, "1700000000001|0|1")
        old.putMeta(marker, "v1;grpABC_def=1700000000000")
        old.putMeta("dr/$RR_OTHER/text", "ratchet")   // something that DOES travel
        return old
    }

    @Test
    fun theExportFilter_dropsBoth() {
        val snap = VaultSnapshotIo.export(rrMoveVault(oldPhone()))
        assertFalse(ssn in snap.meta, "a screenshot notice must not be exported")
        assertFalse(ssnDm in snap.meta)
        assertFalse(marker in snap.meta, "an unread marker must not be exported")
        assertTrue("dr/$RR_OTHER/text" in snap.meta, "the rest of the meta still travels")
    }

    @Test
    fun theEncoder_dropsBoth_evenFromAHandBuiltSnapshot() {
        val snap = VaultSnapshotIo.export(rrMoveVault(oldPhone()))
            .let { it.copy(meta = it.meta + mapOf(ssn to "1|1|0", ssnDm to "1|0|0", marker to "v1;*=1")) }
        val text = MigrationBundleCodec.encode(rrBundle(snap)).decodeToString()
        assertFalse(text.contains("ssn:"), "the encoder must not write a screenshot notice")
        assertFalse(text.contains(GroupUnreadMarkerStore.PREFIX), "the encoder must not write an unread marker")
    }

    /** A bundle from an OLDER build carries `ssn:` rows (it allowed them): the decoder drops them. */
    @Test
    fun theDecoder_dropsBoth_fromAnOlderBuildsBundle() {
        val snap = VaultSnapshotIo.export(rrMoveVault(oldPhone()))
            .let { it.copy(meta = it.meta + mapOf("ref_placeholder_s" to "1|1|0", "ref_placeholder_u" to "v1;*=1")) }
        val wire = MigrationBundleCodec.encode(rrBundle(snap)).decodeToString()
            .replace("\"ref_placeholder_s\"", jsonEscapeString(ssn))
            .replace("\"ref_placeholder_u\"", jsonEscapeString(marker))
        assertTrue(wire.contains(ssn) && wire.contains(marker), "the crafted wire must carry both rows")
        val decoded = MigrationBundleCodec.decode(wire.encodeToByteArray())
        assertFalse(ssn in decoded.snapshot.meta, "the decoder must drop a screenshot notice")
        assertFalse(marker in decoded.snapshot.meta, "the decoder must drop an unread marker")
        assertTrue("dr/$RR_OTHER/text" in decoded.snapshot.meta)
    }

    @Test
    fun theImporter_dropsBoth_fromAHandBuiltSnapshot() {
        val snap = VaultSnapshotIo.export(rrMoveVault(oldPhone()))
            .let { it.copy(meta = it.meta + mapOf(ssn to "1|1|0", marker to "v1;*=1")) }
        val fresh = InMemoryVault()
        VaultSnapshotIo.import(fresh, snap, MoveConstants.COUNTER_JUMP, migTestBundleId(7))
        assertNull(fresh.getMeta(ssn), "the importer must not write a screenshot notice")
        assertNull(fresh.getMeta(marker), "the importer must not write an unread marker")
        assertNotNull(fresh.getMeta("dr/$RR_OTHER/text"))
    }

    /** The whole pipeline, export → bundle bytes → import, for both kinds. */
    @Test
    fun throughTheWholePipeline_neitherArrives() {
        val fresh = rrMoveThroughTheWholePipeline(oldPhone())
        assertTrue(fresh.meta.keys.none { it.startsWith("ssn:") }, "no screenshot notice may arrive")
        assertTrue(fresh.meta.keys.none { it.startsWith(GroupUnreadMarkerStore.PREFIX) }, "no unread marker may arrive")
        assertNotNull(fresh.getMeta("dr/$RR_OTHER/text"))
        assertNotNull(fresh.getContact(RR_OTHER))
    }

    @Test
    fun thePolicyDeniesBothPrefixesExplicitly() {
        assertTrue(ScreenshotNoticeMetaKeys.PREFIX in MoveMetaPolicy.deniedPrefixes)
        assertTrue(GroupUnreadMarkerStore.PREFIX in MoveMetaPolicy.deniedPrefixes)
        assertFalse(MoveMetaPolicy.allowedPrefixes.any { ssn.startsWith(it) }, "no allow prefix may cover ssn:")
    }
}

// ===========================================================================
// T7 — the retention table, row by row
// ===========================================================================

class GroupRetentionTablePinTest {
    private val g1 = "grpABC_def"
    private val g2 = "grpZZZ999"
    private val c1 = RR_ADMIN
    private val c2 = RR_OTHER

    private fun seeded(): InMemoryVault {
        val v = InMemoryVault()
        rrSeedPairedContact(v, c1)
        rrSeedPairedContact(v, c2)
        v.putMeta(rrAdminKey(g1), c1)
        v.putMeta(rrAdminKey(g2), GroupManager.SELF_ADMIN_MARKER)
        v.putMeta("ssn:$g1:$c2:1700000000000", "1|1|0")
        v.putMeta("ssn:$c1:$c1:1700000000001", "1|0|0")
        v.putMeta(GroupUnreadMarkerStore.keyFor(c1), "v1;$g1=1700000000000")
        v.putMeta("grp_ctl_pend:$g1:$c2", "leave|2|h|0|1")
        v.putMeta("grp_declined", "tok1")
        return v
    }

    @Test
    fun groupDeletion() {
        val v = seeded()
        v.deleteGroup(g1)
        assertEquals(c1, v.getMeta(rrAdminKey(g1)), "admin record: retained")
        assertNull(v.getMeta("ssn:$g1:$c2:1700000000000"), "the group's screenshot notices: purged")
        assertNotNull(v.getMeta(GroupUnreadMarkerStore.keyFor(c1)), "unread marker row: kept (GroupManager detaches the units)")
        assertNull(v.getMeta("grp_ctl_pend:$g1:$c2"), "obligations existing at delete time: purged (a leave writes its own after)")
        assertNotNull(v.getMeta("grp_declined"), "decline tokens: retained")
    }

    @Test
    fun contactDeletion() {
        val v = seeded()
        v.deleteContact(c1)
        assertEquals(GONE, v.getMeta(rrAdminKey(g1)), "admin record naming the contact: rewritten to gone")
        assertEquals(GroupManager.SELF_ADMIN_MARKER, v.getMeta(rrAdminKey(g2)))
        assertNull(v.getMeta("ssn:$c1:$c1:1700000000001"), "the contact's screenshot notices: purged")
        assertNotNull(v.getMeta("ssn:$g1:$c2:1700000000000"), "another sender's notice stays")
        assertNull(v.getMeta(GroupUnreadMarkerStore.keyFor(c1)), "the contact's unread marker: purged")
        assertNotNull(v.getMeta("grp_declined"), "decline tokens: retained")
        v.deleteContact(c2)
        assertNull(v.getMeta("grp_ctl_pend:$g1:$c2"), "an obligation naming the deleted contact: purged")
    }

    @Test
    fun move() {
        val p = MoveMetaPolicy
        assertTrue(p.isAllowedKey(rrAdminKey(g1)), "admin record: transferred")
        assertFalse(p.isAllowedKey("ssn:$g1:$c2:1700000000000"), "screenshot notices: not transferred")
        assertFalse(p.isAllowedKey(GroupUnreadMarkerStore.keyFor(c1)), "unread markers: not transferred")
        assertTrue(p.isAllowedKey("grp_ctl_pend:$g1:$c2"), "leave obligations: transferred")
        assertTrue(p.isAllowedKey("grp_declined"), "decline tokens: transferred")
    }

    @Test
    fun fullWipe() {
        val v = seeded()
        v.wipeAllTables()
        assertTrue(v.meta.isEmpty(), "a wipe leaves nothing")
    }
}

// ===========================================================================
// helpers
// ===========================================================================

/** InMemoryVault + the getAllInboxIds the move exporter needs. */
private class RrMoveVault(val inner: InMemoryVault) : VaultDatabase by inner {
    override fun getAllInboxIds(): List<InboxIdRecord> = inner.inboxes.toList()
}

private fun rrMoveVault(v: InMemoryVault): VaultDatabase = RrMoveVault(v)

private fun rrBundle(snapshot: VaultSnapshot) = MigrationBundle(
    schema = MigrationBundleCodec.CURRENT_SCHEMA,
    from = MigrationBundle.FROM_ANDROID,
    createdMs = 1L,
    bundleId = migTestBundleId(5),
    snapshot = snapshot,
)

/** export → encode → decode → import into a fresh vault: the move's four filter sites. */
private fun rrMoveThroughTheWholePipeline(old: InMemoryVault): InMemoryVault {
    val bundle = rrBundle(VaultSnapshotIo.export(rrMoveVault(old)))
    val wire = MigrationBundleCodec.decode(MigrationBundleCodec.encode(bundle))
    val fresh = InMemoryVault()
    VaultSnapshotIo.import(fresh, wire.snapshot, MoveConstants.COUNTER_JUMP, bundle.bundleId)
    return fresh
}

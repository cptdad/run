package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.AfterTest
import kotlin.test.BeforeTest

// ---------------------------------------------------------------------------
// GroupManager protocol tests.
//
// Most tests drive handleControl/ingest directly with constructed bodies and
// a null transport (messageManager provider returns null), so they exercise
// pure protocol logic with no crypto dependency and run on every KMP target.
// The fan-out test goes through real AES-GCM and is guarded with the same
// bridge-availability check the other crypto tests use (skipped on the iOS
// test target where the Swift crypto bridge isn't installed).
// ---------------------------------------------------------------------------

private fun memberId(seed: Int) = bytesToHex(ByteArray(8) { (seed + it).toByte() })

private fun seedContactWithCaps(vault: InMemoryVault, contactId: String, secret: ByteArray) {
    vault.insertContact(
        ContactRecord(
            contactId = contactId, sharedSecret = secret,
            trustLevel = 1, alias = "A-$contactId", aliasLastRotated = 0L,
        )
    )
    // Unique well-formed inbox ids per contact (32 chars of base64url alphabet).
    val base = contactId.hashCode().toUInt().toString(16).padStart(8, '0')
    vault.insertInboxId(InboxIdRecord(
        inboxId = ("in$base".padEnd(32, 'A')).take(32), contactId = contactId,
        createdAt = 1L, expiresAt = Long.MAX_VALUE, direction = "inbound",
        cap = "A".repeat(43),
    ))
    vault.insertInboxId(InboxIdRecord(
        inboxId = ("ou$base".padEnd(32, 'B')).take(32), contactId = contactId,
        createdAt = 1L, expiresAt = Long.MAX_VALUE, direction = "outbound",
        cap = "B".repeat(43),
    ))
}

/**
 * The control poll runs FAST while a member's resolution is in
 * flight (hasUnresolvedMembers). A never-IRL-paired member stays unresolved forever, so
 * the fast window must be bounded by how recently the member was added — otherwise it
 * pins the poll to FAST indefinitely (a permanent Tor traffic beacon + battery drain).
 */
class UnresolvedMemberFastPollTest {
    private fun gm(vault: InMemoryVault) = GroupManager(vault) { null }

    private fun seedGroupWithUnresolved(vault: InMemoryVault, addedAt: Long) {
        vault.insertGroup(GroupRecord(
            groupId = "g1", name = "G", epoch = 1L,
            adminMemberId = "admin0", myMemberId = "self0", createdAt = 0L,
        ))
        // Our own row (excluded by the memberId != myMemberId filter regardless).
        vault.insertGroupMember(GroupMemberRecord("g1", "self0", contactId = null, addedAt = addedAt))
        // The unresolved member under test.
        vault.insertGroupMember(GroupMemberRecord("g1", "peer00", contactId = null, addedAt = addedAt))
    }

    @Test
    fun recentlyAddedUnresolvedMember_keepsFastPoll() {
        val vault = InMemoryVault()
        seedGroupWithUnresolved(vault, addedAt = currentTimeMillis())
        assertTrue(gm(vault).hasUnresolvedMembers(), "a just-added unresolved member is in flight → fast poll")
    }

    @Test
    fun staleUnresolvedMember_stopsFastPoll() {
        val vault = InMemoryVault()
        // Added well beyond the fast window and still unresolved → permanently
        // unresolvable → must NOT keep pinning the poll fast.
        val stale = currentTimeMillis() - GroupManager.UNRESOLVED_MEMBER_FAST_WINDOW_MS - 60_000L
        seedGroupWithUnresolved(vault, addedAt = stale)
        assertEquals(false, gm(vault).hasUnresolvedMembers(), "a long-stuck unresolved member must not beacon forever")
    }
}

class GroupCryptoHelpersTest {

    @Test
    fun membershipHash_isOrderIndependent() {
        val gid = GroupManager.newGroupId()
        val ids = listOf(memberId(1), memberId(2), memberId(3))
        assertEquals(
            GroupManager.membershipHash(gid, 1, ids),
            GroupManager.membershipHash(gid, 1, ids.reversed()),
        )
    }

    @Test
    fun membershipHash_changesWithEpochAndMembership() {
        val gid = GroupManager.newGroupId()
        val ids = listOf(memberId(1), memberId(2))
        val base = GroupManager.membershipHash(gid, 1, ids)
        assertNotEquals(base, GroupManager.membershipHash(gid, 2, ids))
        assertNotEquals(base, GroupManager.membershipHash(gid, 1, ids + memberId(3)))
        assertNotEquals(base, GroupManager.membershipHash(GroupManager.newGroupId(), 1, ids))
        // 16 bytes hex = 32 chars (128-bit; widened from 48-bit).
        assertEquals(32, base.length)
    }

    @Test
    fun pairTag_isSymmetric_acrossTheTwoPeers() {
        // deriveSharedSecret sorts its inputs, so both ends of a pairing hold
        // the identical secret — the tag each computes must match, otherwise
        // tag-based member resolution can never converge.
        val a = generateSecureRandom(32)
        val b = generateSecureRandom(32)
        val gid = GroupManager.newGroupId()
        val tagFromA = GroupManager.pairTag(deriveSharedSecret(a, b), gid)
        val tagFromB = GroupManager.pairTag(deriveSharedSecret(b, a), gid)
        assertEquals(tagFromA, tagFromB)
        assertEquals(16, tagFromA.length)
        // And it must be group-scoped: same pairing, different group → different tag.
        assertNotEquals(tagFromA, GroupManager.pairTag(deriveSharedSecret(a, b), GroupManager.newGroupId()))
    }

    @Test
    fun boundTag_isSymmetric_butDistinctPerMemberId() {
        // The resolution tag stays symmetric in the pairwise secret (so
        // both peers converge) BUT is distinct per memberId (so a tag only
        // resolves under the slot the advertiser committed to — the admin can't
        // move it). Also group-scoped, like pairTag.
        val a = generateSecureRandom(32)
        val b = generateSecureRandom(32)
        val gid = GroupManager.newGroupId()
        val idM = GroupManager.newMemberId()
        val idN = GroupManager.newMemberId()
        // Symmetric in the secret for a fixed memberId.
        assertEquals(
            GroupManager.boundTag(deriveSharedSecret(a, b), gid, idM),
            GroupManager.boundTag(deriveSharedSecret(b, a), gid, idM),
        )
        // Bound to the memberId: same pairing + group, different member → different tag.
        assertNotEquals(
            GroupManager.boundTag(deriveSharedSecret(a, b), gid, idM),
            GroupManager.boundTag(deriveSharedSecret(a, b), gid, idN),
        )
        // Group-scoped.
        assertNotEquals(
            GroupManager.boundTag(deriveSharedSecret(a, b), gid, idM),
            GroupManager.boundTag(deriveSharedSecret(a, b), GroupManager.newGroupId(), idM),
        )
        // Distinct from the (memberId-independent) symmetric tag.
        assertNotEquals(
            GroupManager.pairTag(deriveSharedSecret(a, b), gid),
            GroupManager.boundTag(deriveSharedSecret(a, b), gid, idM),
        )
    }

    @Test
    fun envelope_roundTrips_groupFields() {
        val mm = MessageManager(InMemoryVault(), "http://x.onion", RecordingRelayHttp())
        val gid = GroupManager.newGroupId()
        val raw = """{"e":"abc","c":7,"t":60000,"g":${jsonEscapeString(gid)},"h":"00ff00ff00ff","k":"roster","b":${jsonEscapeString("""{"n":"crew","ep":2}""")},"m":""}"""
        val env = mm.parseEnvelope(raw)
        assertNotNull(env)
        assertEquals(gid, env.groupId)
        assertEquals("00ff00ff00ff", env.membershipHash)
        assertEquals("roster", env.controlKind)
        assertEquals("""{"n":"crew","ep":2}""", env.controlBody)
        // And a plain 1:1 envelope has no group fields.
        val plain = mm.parseEnvelope("""{"e":"abc","c":7,"t":0,"m":"hi"}""")
        assertNotNull(plain)
        assertNull(plain.groupId)
        assertNull(plain.controlKind)
    }
}

class GroupControlProtocolTest {

    private val noTransport: () -> MessageManager? = { null }

    /** Builds a member-device fixture: vault with an admin contact, a manager,
     *  and the group joined via a real invite control message. */
    private fun joinedFixture(): Fixture {
        val vault = InMemoryVault()
        val adminSecret = generateSecureRandom(32)
        seedContactWithCaps(vault, "admin-contact", adminSecret)
        val gm = GroupManager(vault, noTransport)
        val gid = GroupManager.newGroupId()
        val adm = memberId(10)
        val me = memberId(20)
        val bob = memberId(30)
        val invite =
            """{"n":"crew","ep":1,"adm":${jsonEscapeString(adm)},"you":${jsonEscapeString(me)},"mem":[${jsonEscapeString(adm)},${jsonEscapeString(me)},${jsonEscapeString(bob)}]}"""
        gm.handleControl("admin-contact", gid, GroupManager.KIND_INVITE, invite)
        // GROUP-1 consent gate: the invite is parked, not auto-joined — accept it
        // so this fixture represents a genuinely joined member.
        gm.acceptInvite(gid)
        return Fixture(vault, gm, gid, adm, me, bob)
    }

    private class Fixture(
        val vault: InMemoryVault,
        val gm: GroupManager,
        val gid: String,
        val adm: String,
        val me: String,
        val bob: String,
    )

    @Test
    fun invite_createsGroup_andResolvesAdminFromChannel() {
        val f = joinedFixture()
        val g = f.vault.getGroup(f.gid)
        assertNotNull(g)
        assertEquals("crew", g.name)
        assertEquals(1L, g.epoch)
        assertEquals(f.adm, g.adminMemberId)
        assertEquals(f.me, g.myMemberId)
        assertEquals(false, g.isAdmin)
        val members = f.vault.getGroupMembers(f.gid)
        assertEquals(3, members.size)
        // The inviter's pairwise channel IS the admin binding.
        assertEquals("admin-contact", members.first { it.memberId == f.adm }.contactId)
        // Bob is unresolved until tags arrive.
        assertNull(members.first { it.memberId == f.bob }.contactId)
    }

    @Test
    fun invite_withMalformedMemberIds_isRejected() {
        val vault = InMemoryVault()
        seedContactWithCaps(vault, "admin-contact", generateSecureRandom(32))
        val gm = GroupManager(vault, noTransport)
        val gid = GroupManager.newGroupId()
        val bad =
            """{"n":"crew","ep":1,"adm":"NOT-HEX","you":${jsonEscapeString(memberId(1))},"mem":["NOT-HEX",${jsonEscapeString(memberId(1))}]}"""
        gm.handleControl("admin-contact", gid, GroupManager.KIND_INVITE, bad)
        assertNull(vault.getGroup(gid))
    }

    /** a peer-supplied group name can carry a newline, a bidi
     *  override, and zero-width runs that would otherwise survive verbatim
     *  into the eclipse-warning consent dialog. handleInvite must sanitise
     *  before persisting/parking, not just truncate. */
    @Test
    fun invite_sanitizesControlBidiAndZeroWidthFromGroupName() {
        val vault = InMemoryVault()
        seedContactWithCaps(vault, "admin-contact", generateSecureRandom(32))
        val gm = GroupManager(vault, noTransport)
        val gid = GroupManager.newGroupId()
        val adm = memberId(10); val me = memberId(20)
        val hostileName = "Team\nEvil\u202E\u200Bmoc.rekcatta"   // \n, RLO, ZWSP
        val invite =
            """{"n":${jsonEscapeString(hostileName)},"ep":1,"adm":${jsonEscapeString(adm)},"you":${jsonEscapeString(me)},"mem":[${jsonEscapeString(adm)},${jsonEscapeString(me)}]}"""
        gm.handleControl("admin-contact", gid, GroupManager.KIND_INVITE, invite)
        gm.acceptInvite(gid)
        val persisted = vault.getGroup(gid)!!.name
        for (dangerous in listOf('\n', '\u202E', '\u200B')) {
            assertTrue(dangerous !in persisted, "dangerous code point survived sanitisation: <$persisted>")
        }
        assertEquals("Team Evilmoc.rekcatta", persisted)
    }

    /** Ordinary non-Latin group names (Arabic/Persian letters — no bidi
     *  CONTROL characters involved) must render through completely unchanged;
     *  the sanitiser is not a script filter. */
    @Test
    fun invite_preservesOrdinaryUnicodeGroupName() {
        val vault = InMemoryVault()
        seedContactWithCaps(vault, "admin-contact", generateSecureRandom(32))
        val gm = GroupManager(vault, noTransport)
        val gid = GroupManager.newGroupId()
        val adm = memberId(10); val me = memberId(20)
        val arabicName = "مجموعة الأصدقاء"
        val invite =
            """{"n":${jsonEscapeString(arabicName)},"ep":1,"adm":${jsonEscapeString(adm)},"you":${jsonEscapeString(me)},"mem":[${jsonEscapeString(adm)},${jsonEscapeString(me)}]}"""
        gm.handleControl("admin-contact", gid, GroupManager.KIND_INVITE, invite)
        gm.acceptInvite(gid)
        assertEquals(arabicName, vault.getGroup(gid)!!.name)
    }

    @Test
    fun roster_fromNonAdminChannel_isDropped() {
        val f = joinedFixture()
        seedContactWithCaps(f.vault, "mallory-contact", generateSecureRandom(32))
        val hostile =
            """{"n":"crew","ep":9,"adm":${jsonEscapeString(f.adm)},"mem":[${jsonEscapeString("${f.adm}:")},${jsonEscapeString("${f.me}:")}]}"""
        f.gm.handleControl("mallory-contact", f.gid, GroupManager.KIND_ROSTER, hostile)
        // Unchanged: epoch still 1, bob still a member.
        assertEquals(1L, f.vault.getGroup(f.gid)!!.epoch)
        assertEquals(3, f.vault.getGroupMembers(f.gid).size)
    }

    @Test
    fun roster_withStaleEpoch_isDropped() {
        val f = joinedFixture()
        // First a valid epoch-3 roster from the admin.
        val ep3 =
            """{"n":"crew","ep":3,"adm":${jsonEscapeString(f.adm)},"mem":[${jsonEscapeString("${f.adm}:")},${jsonEscapeString("${f.me}:")},${jsonEscapeString("${f.bob}:")}]}"""
        f.gm.handleControl("admin-contact", f.gid, GroupManager.KIND_ROSTER, ep3)
        assertEquals(3L, f.vault.getGroup(f.gid)!!.epoch)
        // Now a replayed epoch-2 roster that drops bob — must be ignored.
        val stale =
            """{"n":"crew","ep":2,"adm":${jsonEscapeString(f.adm)},"mem":[${jsonEscapeString("${f.adm}:")},${jsonEscapeString("${f.me}:")}]}"""
        f.gm.handleControl("admin-contact", f.gid, GroupManager.KIND_ROSTER, stale)
        assertEquals(3L, f.vault.getGroup(f.gid)!!.epoch)
        assertEquals(3, f.vault.getGroupMembers(f.gid).size)
    }

    @Test
    fun roster_withEpochJumpTooLarge_isDropped() {
        val f = joinedFixture()   // starts at epoch 1
        // a malicious admin jumps the epoch to Long.MAX_VALUE to freeze
        // membership (every later lower-epoch roster would then look stale). The
        // MAX_GROUP_EPOCH_ADVANCE clamp rejects the implausible jump.
        val huge =
            """{"n":"crew","ep":${Long.MAX_VALUE},"adm":${jsonEscapeString(f.adm)},"mem":[${jsonEscapeString("${f.adm}:")},${jsonEscapeString("${f.me}:")},${jsonEscapeString("${f.bob}:")}]}"""
        f.gm.handleControl("admin-contact", f.gid, GroupManager.KIND_ROSTER, huge)
        assertEquals(1L, f.vault.getGroup(f.gid)!!.epoch, "epoch jump beyond the clamp must be dropped")
    }

    /** a roster-driven rename is peer-controlled exactly like an
     *  invite's name and must go through the same sanitiser. */
    @Test
    fun roster_sanitizesControlBidiAndZeroWidthFromRenamedGroupName() {
        val f = joinedFixture()
        val hostileName = "New\nName\u202E\u200Bmoc.rekcatta"
        val renamed =
            """{"n":${jsonEscapeString(hostileName)},"ep":2,"adm":${jsonEscapeString(f.adm)},"mem":[${jsonEscapeString("${f.adm}:")},${jsonEscapeString("${f.me}:")},${jsonEscapeString("${f.bob}:")}]}"""
        f.gm.handleControl("admin-contact", f.gid, GroupManager.KIND_ROSTER, renamed)
        val persisted = f.vault.getGroup(f.gid)!!.name
        for (dangerous in listOf('\n', '\u202E', '\u200B')) {
            assertTrue(dangerous !in persisted, "dangerous code point survived roster-rename sanitisation: <$persisted>")
        }
        assertEquals("New Namemoc.rekcatta", persisted)
    }

    @Test
    fun roster_resolvesMemberViaPairwiseTag() {
        val f = joinedFixture()
        // Bob is also our paired contact; the tag both we and bob can compute
        // arrives in the admin's roster under bob's entry.
        val bobPairSecret = generateSecureRandom(32)
        seedContactWithCaps(f.vault, "bob-contact", bobPairSecret)
        val tag = GroupManager.boundTag(bobPairSecret, f.gid, f.bob)
        val roster =
            """{"n":"crew","ep":2,"adm":${jsonEscapeString(f.adm)},"mem":[${jsonEscapeString("${f.adm}:")},${jsonEscapeString("${f.me}:")},${jsonEscapeString("${f.bob}:$tag")}]}"""
        f.gm.handleControl("admin-contact", f.gid, GroupManager.KIND_ROSTER, roster)
        val bobRow = f.vault.getGroupMembers(f.gid).first { it.memberId == f.bob }
        assertEquals("bob-contact", bobRow.contactId)
    }

    @Test
    fun roster_omittingUs_deletesGroupLocally() {
        val f = joinedFixture()
        val roster =
            """{"n":"crew","ep":2,"adm":${jsonEscapeString(f.adm)},"mem":[${jsonEscapeString("${f.adm}:")},${jsonEscapeString("${f.bob}:")}]}"""
        f.gm.handleControl("admin-contact", f.gid, GroupManager.KIND_ROSTER, roster)
        assertNull(f.vault.getGroup(f.gid))
        assertEquals(0, f.vault.getGroupMembers(f.gid).size)
    }

    @Test
    fun leave_removesOnlyTheSendersMembership() {
        val f = joinedFixture()
        // Resolve bob first so his leave can be channel-attributed.
        val bobPairSecret = generateSecureRandom(32)
        seedContactWithCaps(f.vault, "bob-contact", bobPairSecret)
        val tag = GroupManager.boundTag(bobPairSecret, f.gid, f.bob)
        val roster =
            """{"n":"crew","ep":2,"adm":${jsonEscapeString(f.adm)},"mem":[${jsonEscapeString("${f.adm}:")},${jsonEscapeString("${f.me}:")},${jsonEscapeString("${f.bob}:$tag")}]}"""
        f.gm.handleControl("admin-contact", f.gid, GroupManager.KIND_ROSTER, roster)

        f.gm.handleControl("bob-contact", f.gid, GroupManager.KIND_LEAVE, "{}")
        val members = f.vault.getGroupMembers(f.gid)
        assertEquals(2, members.size)
        assertTrue(members.none { it.memberId == f.bob })
        // A leave from a non-member channel is a no-op.
        seedContactWithCaps(f.vault, "mallory-contact", generateSecureRandom(32))
        f.gm.handleControl("mallory-contact", f.gid, GroupManager.KIND_LEAVE, "{}")
        assertEquals(2, f.vault.getGroupMembers(f.gid).size)
    }

    @Test
    fun ingest_routesAndFlags() {
        val f = joinedFixture()
        // Resolve bob.
        val bobPairSecret = generateSecureRandom(32)
        seedContactWithCaps(f.vault, "bob-contact", bobPairSecret)
        val tag = GroupManager.boundTag(bobPairSecret, f.gid, f.bob)
        f.gm.handleControl(
            "admin-contact", f.gid, GroupManager.KIND_ROSTER,
            """{"n":"crew","ep":2,"adm":${jsonEscapeString(f.adm)},"mem":[${jsonEscapeString("${f.adm}:")},${jsonEscapeString("${f.me}:")},${jsonEscapeString("${f.bob}:$tag")}]}""",
        )
        val g = f.vault.getGroup(f.gid)!!
        val goodHash = GroupManager.membershipHash(f.gid, g.epoch, f.vault.getGroupMembers(f.gid).map { it.memberId })

        // 1) Group text from a member with the right hash → delivered, membershipOk.
        val ok = f.gm.ingest(
            "bob-contact",
            listOf(ReceivedMessage("hi", 0L, counter = 1, groupId = f.gid, membershipHash = goodHash)),
            wantGroupId = f.gid,
        )
        assertEquals(1, ok.group.size)
        assertTrue(ok.group[0].membershipOk)
        assertEquals("bob-contact", ok.group[0].senderContactId)

        // 2) Wrong hash → delivered but flagged (splitting detection).
        val flagged = f.gm.ingest(
            "bob-contact",
            listOf(ReceivedMessage("hi2", 0L, counter = 2, groupId = f.gid, membershipHash = "000000000000")),
            wantGroupId = f.gid,
        )
        assertEquals(false, flagged.group[0].membershipOk)

        // 3) Group text from a NON-member contact → dropped.
        seedContactWithCaps(f.vault, "mallory-contact", generateSecureRandom(32))
        val dropped = f.gm.ingest(
            "mallory-contact",
            listOf(ReceivedMessage("intrude", 0L, counter = 1, groupId = f.gid, membershipHash = goodHash)),
            wantGroupId = f.gid,
        )
        assertEquals(0, dropped.group.size)

        // 4) NO-PARK: a 1:1 message drained during a group poll is surfaced IN the
        //    group screen as PRIVATE — never parked for the 1:1, never a group text.
        val priv = f.gm.ingest(
            "bob-contact",
            listOf(ReceivedMessage("direct!", 0L, counter = 3)),
            wantGroupId = f.gid,
        )
        assertEquals(0, priv.direct.size)
        assertEquals(listOf("direct!"), priv.group.map { it.text })
        assertEquals(ReceivedItemKind.PRIVATE, priv.group.single().kind)
        assertEquals("bob-contact", priv.group.single().senderContactId)
        assertEquals(0, f.gm.takeDirectScreenItems("bob-contact").size, "nothing parked for the 1:1")

        // 5) NO-PARK: a group message drained during a 1:1 poll is surfaced IN the
        //    1:1 screen as GROUP_ECHO, naming its group — not parked for the group.
        val echo = f.gm.ingest(
            "bob-contact",
            listOf(ReceivedMessage("grp", 0L, counter = 4, groupId = f.gid, membershipHash = goodHash)),
            wantGroupId = null,
        )
        assertEquals(listOf("grp"), echo.direct.map { it.text })
        assertEquals(ReceivedItemKind.GROUP_ECHO, echo.direct.single().kind)
        assertEquals(f.gid, echo.direct.single().groupId)
        assertEquals("crew", echo.direct.single().groupName)
        assertEquals(0, f.gm.takeGroupScreenItems(f.gid).size, "nothing parked for the group")
    }
}

// ---------------------------------------------------------------------------
// FIX A (cross:multi3 post-handoff resolution): after an admin hands off, the
// successor admin must still be able to redistribute resolution tags for the
// DEMOTED (ex-)admin. The creator never sends a normal KIND_JOIN, so no successor
// holds its join-syms — and members resolve each other ONLY through the current
// admin's mutual-sym redistribution. transferAdmin now plants the demoted admin's
// tags on the successor via a SELF-JOIN. These tests simulate three devices at the
// handleControl level (delivering the ex-admin's join to the successor is exactly
// what sendSelfJoinToNewAdmin does) and assert BOTH resolution directions.
// ---------------------------------------------------------------------------
class GroupHandoffResolutionTest {

    private val noTransport: () -> MessageManager? = { null }
    private val gid = GroupManager.newGroupId()
    private val xId = memberId(1)   // ex-admin (creator, just demoted)
    private val sId = memberId(2)   // successor admin
    private val rId = memberId(3)   // member the successor re-adds AFTER the handoff

    // One symmetric secret per pairing — both ends hold identical bytes, exactly as
    // deriveSharedSecret guarantees, so both compute the same pair/bound tags.
    private val sXS = generateSecureRandom(32)   // X <-> S
    private val sXR = generateSecureRandom(32)   // X <-> R
    private val sSR = generateSecureRandom(32)   // S <-> R

    /** Successor-admin device S: admin of {S, X, R}; X and R RESOLVED locally (S added
     *  them) but with FROZEN empty tags — X via the original invite-shortcut, R just
     *  re-added — i.e. the post-handoff state before any join has reached S. */
    private fun successorAdmin(): Pair<InMemoryVault, GroupManager> {
        val v = InMemoryVault()
        seedContactWithCaps(v, "X", sXS)
        seedContactWithCaps(v, "R", sSR)
        val gm = GroupManager(v, noTransport)
        v.insertGroup(GroupRecord(gid, "crew", epoch = 5L, adminMemberId = sId, myMemberId = sId, createdAt = 0L))
        v.insertGroupMember(GroupMemberRecord(gid, sId, contactId = null, addedAt = 0L))            // self
        v.insertGroupMember(GroupMemberRecord(gid, xId, contactId = "X", addedAt = 0L, tags = "")) // ex-admin, frozen empty
        v.insertGroupMember(GroupMemberRecord(gid, rId, contactId = "R", addedAt = 0L, tags = "")) // re-added member
        return v to gm
    }

    /** Ex-admin device X (paired with S and R); knows S is now admin; R unresolved here. */
    private fun exAdmin(): Pair<InMemoryVault, GroupManager> {
        val v = InMemoryVault()
        seedContactWithCaps(v, "S", sXS)
        seedContactWithCaps(v, "R", sXR)
        val gm = GroupManager(v, noTransport)
        v.insertGroup(GroupRecord(gid, "crew", epoch = 4L, adminMemberId = sId, myMemberId = xId, createdAt = 0L))
        v.insertGroupMember(GroupMemberRecord(gid, xId, contactId = null, addedAt = 0L))   // self
        v.insertGroupMember(GroupMemberRecord(gid, sId, contactId = "S", addedAt = 0L))   // successor admin
        v.insertGroupMember(GroupMemberRecord(gid, rId, contactId = null, addedAt = 0L))  // R unresolved
        return v to gm
    }

    /** Re-added member device R (paired with X and S); knows S is admin; X unresolved here. */
    private fun rejoinMember(): Pair<InMemoryVault, GroupManager> {
        val v = InMemoryVault()
        seedContactWithCaps(v, "X", sXR)
        seedContactWithCaps(v, "S", sSR)
        val gm = GroupManager(v, noTransport)
        v.insertGroup(GroupRecord(gid, "crew", epoch = 4L, adminMemberId = sId, myMemberId = rId, createdAt = 0L))
        v.insertGroupMember(GroupMemberRecord(gid, rId, contactId = null, addedAt = 0L))   // self
        v.insertGroupMember(GroupMemberRecord(gid, sId, contactId = "S", addedAt = 0L))   // successor admin
        v.insertGroupMember(GroupMemberRecord(gid, xId, contactId = null, addedAt = 0L))  // X unresolved
        return v to gm
    }

    @Test
    fun successorRedistributesExAdminTags_afterSelfJoin_bothDirectionsResolve() {
        val (_, sGm) = successorAdmin()
        val (xv, xgm) = exAdmin()
        val (rv, rgm) = rejoinMember()

        // 1) transferAdmin plants the demoted admin's join on the successor (self-join).
        sGm.handleControl("X", gid, GroupManager.KIND_JOIN, xgm.buildJoinBody(gid, xId))
        // 2) the re-added member joins the successor normally.
        sGm.handleControl("R", gid, GroupManager.KIND_JOIN, rgm.buildJoinBody(gid, rId))

        // 3) the successor's authoritative roster now carries BOTH X's and R's
        //    resolution tags (mutual X<->R detected via the self-join's syms).
        val roster = sGm.buildRosterBody(gid)
        assertNotNull(roster)

        // 4) DIRECTION 1 — the re-added member resolves the ex-admin.
        rgm.handleControl("S", gid, GroupManager.KIND_ROSTER, roster)
        assertEquals("X", rv.getGroupMembers(gid).first { it.memberId == xId }.contactId,
            "re-added member must resolve the ex-admin via the successor's roster")

        // 5) DIRECTION 2 — the ex-admin resolves the successor-added member.
        xgm.handleControl("S", gid, GroupManager.KIND_ROSTER, roster)
        assertEquals("R", xv.getGroupMembers(gid).first { it.memberId == rId }.contactId,
            "ex-admin must resolve the successor-added member")
    }

    @Test
    fun withoutSelfJoin_successorCannotRedistributeExAdmin_bothDirectionsStayUnresolved() {
        val (_, sGm) = successorAdmin()
        val (xv, xgm) = exAdmin()
        val (rv, rgm) = rejoinMember()

        // The re-added member still joins, but the ex-admin's self-join is NEVER
        // delivered — the pre-fix behaviour. The successor cannot detect the X<->R
        // pairing (it lacks X's sym), so both slots stay empty.
        sGm.handleControl("R", gid, GroupManager.KIND_JOIN, rgm.buildJoinBody(gid, rId))
        val roster = sGm.buildRosterBody(gid)!!

        rgm.handleControl("S", gid, GroupManager.KIND_ROSTER, roster)
        xgm.handleControl("S", gid, GroupManager.KIND_ROSTER, roster)
        assertNull(rv.getGroupMembers(gid).first { it.memberId == xId }.contactId,
            "without the self-join the re-added member cannot resolve the ex-admin")
        assertNull(xv.getGroupMembers(gid).first { it.memberId == rId }.contactId,
            "without the self-join the ex-admin cannot resolve the re-added member")
    }
}

// ---------------------------------------------------------------------------
// FIX B (cross:multi3 message loss): a decryptable group text from a member whose
// member↔member resolution hasn't converged on THIS device is BUFFERED (bounded +
// TTL) and re-attributed on the next roster / group open, instead of being dropped
// (the feeding poll is a destructive relay drain).
// ---------------------------------------------------------------------------
class GroupUnresolvedTextBufferTest {

    private val noTransport: () -> MessageManager? = { null }

    @Test
    fun groupText_fromUnresolvedMember_isBuffered_thenDeliveredOnResolve() {
        val vault = InMemoryVault()
        seedContactWithCaps(vault, "admin-contact", generateSecureRandom(32))
        val gm = GroupManager(vault, noTransport)
        val gid = GroupManager.newGroupId()
        val adm = memberId(10); val me = memberId(20); val bob = memberId(30)
        gm.handleControl(
            "admin-contact", gid, GroupManager.KIND_INVITE,
            """{"n":"crew","ep":1,"adm":${jsonEscapeString(adm)},"you":${jsonEscapeString(me)},"mem":[${jsonEscapeString(adm)},${jsonEscapeString(me)},${jsonEscapeString(bob)}]}""",
        )
        gm.acceptInvite(gid)
        // Bob IS our paired contact, but resolution (his roster tag) hasn't arrived —
        // his member row is still unresolved (contactId == null).
        val bobSecret = generateSecureRandom(32)
        seedContactWithCaps(vault, "bob-contact", bobSecret)

        val hash = GroupManager.membershipHash(gid, vault.getGroup(gid)!!.epoch, vault.getGroupMembers(gid).map { it.memberId })
        val res = gm.ingest(
            "bob-contact",
            listOf(ReceivedMessage("early group text", 0L, counter = 1, groupId = gid, membershipHash = hash)),
            wantGroupId = gid,
        )
        assertEquals(0, res.group.size, "not surfaced yet — sender unresolved")
        // It is NOT in the group buffer yet (it is parked in the unresolved buffer).
        assertEquals(0, gm.takeGroupScreenItems(gid).size)

        // The admin's roster resolves bob → the buffered text becomes attributable
        // and is flushed into the group buffer.
        val bobTag = GroupManager.boundTag(bobSecret, gid, bob)
        gm.handleControl(
            "admin-contact", gid, GroupManager.KIND_ROSTER,
            """{"n":"crew","ep":2,"adm":${jsonEscapeString(adm)},"mem":[${jsonEscapeString("$adm:")},${jsonEscapeString("$me:")},${jsonEscapeString("$bob:$bobTag")}]}""",
        )
        val delivered = gm.takeGroupScreenItems(gid)
        assertEquals(1, delivered.size, "the buffered text must be delivered once its sender resolves")
        assertEquals("early group text", delivered[0].text)
        assertEquals("bob-contact", delivered[0].senderContactId)
    }

    @Test
    fun groupText_fromStranger_whenFullyResolved_isDropped_notBuffered() {
        // Admin side: the group is fully resolved (no unresolved non-self members), so
        // a text from a genuine non-member is DROPPED (the removed/stranger-dropped
        // property must survive the FIX B buffering).
        val vault = InMemoryVault()
        seedContactWithCaps(vault, "c-bob", generateSecureRandom(32))
        val gm = GroupManager(vault) { null }
        val gid = gm.createGroup("crew", listOf("c-bob"))!!
        seedContactWithCaps(vault, "c-mallory", generateSecureRandom(32))
        val hash = GroupManager.membershipHash(gid, vault.getGroup(gid)!!.epoch, vault.getGroupMembers(gid).map { it.memberId })

        val res = gm.ingest(
            "c-mallory",
            listOf(ReceivedMessage("intrude", 0L, counter = 1, groupId = gid, membershipHash = hash)),
            wantGroupId = gid,
        )
        assertEquals(0, res.group.size)
        // Nothing buffered — pollGroup's flush surfaces nothing for the stranger.
        assertEquals(0, gm.takeGroupScreenItems(gid).size)
    }
}

class GroupFanOutTest {

    @Test
    fun createGroup_persists_andSendGroupMessage_fansOutPerMember() {
        // Goes through real AES-GCM — skip where the platform crypto bridge
        // isn't installed (iOS unit tests), like CryptoConsistencyTest.
        val bridgeAvailable = try {
            aesGcmEncrypt(ByteArray(1), generateSecureRandom(32), ByteArray(0)); true
        } catch (_: Exception) { false }
        if (!bridgeAvailable) return

        val vault = InMemoryVault()
        seedContactWithCaps(vault, "c-bob",   generateSecureRandom(32))
        seedContactWithCaps(vault, "c-carol", generateSecureRandom(32))
        val http = RecordingRelayHttp()
        // 2 invites + 2 text copies + 2 activity notices, all accepted.
        repeat(6) { http.script(HttpResult(code = 202, body = "", isSuccess = true)) }
        val mgr = MessageManager(vault, "http://relay.test", http as RelayHttp)
        val gm = GroupManager(vault) { mgr }

        val gid = gm.createGroup("crew", listOf("c-bob", "c-carol"))
        assertNotNull(gid)
        val g = vault.getGroup(gid)!!
        assertTrue(g.isAdmin)
        assertEquals(3, vault.getGroupMembers(gid).size)  // self + 2
        assertEquals(2, http.calls.size, "one invite per member")

        val result = gm.sendGroupMessage(gid, "hello group")
        assertEquals(2, result.total)
        assertEquals(2, result.delivered)
        assertTrue(result.allDelivered)
        // 4 new sends: one text copy + one activity notice per member.
        assertEquals(6, http.calls.size, "one text + one activity notice per member")
        // INTERLEAVED per member since 2026-09-05 (the notice must be on the relay
        // when the text's push wake lands, not 2·(k−1) jitter gaps later), so the
        // shape is text(X), notice(X), text(Y), notice(Y). These contacts have no
        // outbound-ctl row, so a control send falls back to the SAME main outbound
        // inbox as the text — which is exactly what makes the pairing visible here:
        // the two sends of one member share a url, and the two members differ.
        // The notice is a CONTROL append and now carries the uniform `?ttl`
        // while the text copy carries none — compare the inbox PATHS.
        val sendUrls = http.calls.drop(2).map { it.url.substringBefore("?") }
        assertEquals(sendUrls[0], sendUrls[1], "a member's notice follows that member's text")
        assertEquals(sendUrls[2], sendUrls[3], "…and likewise for the next member")
        assertEquals(2, sendUrls.toSet().size, "the two members' copies went to DIFFERENT outbound inboxes")
    }

    @Test
    fun sendGroupMessage_withUnresolvedMembersOnly_sendsNothing() {
        val vault = InMemoryVault()
        val gm = GroupManager(vault) { null }
        val gid = GroupManager.newGroupId()
        val me = memberId(1)
        vault.insertGroup(GroupRecord(gid, "g", 1, adminMemberId = me, myMemberId = me, createdAt = 0L))
        vault.insertGroupMember(GroupMemberRecord(gid, me, null, 0L))
        vault.insertGroupMember(GroupMemberRecord(gid, memberId(2), null, 0L))  // unresolved
        val result = gm.sendGroupMessage(gid, "hello")
        assertEquals(0, result.total)
        assertEquals(false, result.allDelivered)
        // The unresolved member is REPORTED, not silently left out of the total:
        // the sender's mark reads "not delivered to 1", never "✓" or "0/0".
        assertEquals(1, result.unreachable)
        assertEquals(1, result.undelivered)
    }

    @Test
    fun sendGroupMessage_withAnUnresolvedMember_deliversToTheResolvedOne_andReportsTheOther() {
        val bridgeAvailable = try {
            aesGcmEncrypt(ByteArray(1), generateSecureRandom(32), ByteArray(0)); true
        } catch (_: Exception) { false }
        if (!bridgeAvailable) return
        val vault = InMemoryVault()
        seedContactWithCaps(vault, "c-bob", generateSecureRandom(32))
        val http = RecordingRelayHttp()
        // 1 invite + 1 text copy + 1 activity notice, all accepted.
        repeat(3) { http.script(HttpResult(code = 202, body = "", isSuccess = true)) }
        val mgr = MessageManager(vault, "http://relay.test", http as RelayHttp)
        val gm = GroupManager(vault) { mgr }
        val gid = gm.createGroup("crew", listOf("c-bob"))!!
        // A member the admin's roster names but this phone has no contact for yet
        // (a fresh group whose admin is offline leaves joiners in this state).
        vault.insertGroupMember(GroupMemberRecord(gid, memberId(7), null, 0L))

        val result = gm.sendGroupMessage(gid, "hello group")
        assertEquals(1, result.delivered)
        assertEquals(1, result.total)
        assertEquals(1, result.unreachable)
        assertEquals(1, result.undelivered)
        assertEquals(false, result.allDelivered, "one member got nothing — never a ✓")
        assertEquals(3, http.calls.size, "the unreachable member costs no POST")
    }

    @Test
    fun groupSendResult_undelivered_countsRefusedAndUnreachable() {
        assertEquals(0, GroupSendResult(2, 2).undelivered)
        assertTrue(GroupSendResult(2, 2).allDelivered)
        assertEquals(1, GroupSendResult(1, 2).undelivered)
        assertEquals(2, GroupSendResult(1, 2, unreachable = 1).undelivered)
        assertEquals(false, GroupSendResult(2, 2, unreachable = 1).allDelivered)
        assertEquals(3, GroupSendResult(0, 0, unreachable = 3).undelivered)
    }

    @Test
    fun sendGroupMessage_alsoFansOutAnActivityNotice_perMember() {
        // Real AES-GCM — skip where the platform crypto bridge isn't installed.
        val bridgeAvailable = try {
            aesGcmEncrypt(ByteArray(1), generateSecureRandom(32), ByteArray(0)); true
        } catch (_: Exception) { false }
        if (!bridgeAvailable) return
        val vault = InMemoryVault()
        seedContactWithCaps(vault, "c-bob",   generateSecureRandom(32))
        seedContactWithCaps(vault, "c-carol", generateSecureRandom(32))
        val http = RecordingRelayHttp()
        // 2 invites (createGroup) + 2 text copies + 2 activity notices.
        repeat(6) { http.script(HttpResult(code = 202, body = "", isSuccess = true)) }
        val mgr = MessageManager(vault, "http://relay.test", http as RelayHttp)
        val gm = GroupManager(vault) { mgr }
        val gid = gm.createGroup("crew", listOf("c-bob", "c-carol"))!!
        val afterCreate = http.calls.size   // 2 invites

        gm.sendGroupMessage(gid, "hello group")
        // 2 text copies + 2 activity control notices = 4 sends.
        assertEquals(4, http.calls.size - afterCreate, "one text + one activity notice per member")
    }
}

// ---------------------------------------------------------------------------
// Group unread attribution. Group texts share the members' 1:1 inboxes, so the
// background /peek sweep can't decrypt them — the KIND_ACTIVITY control notice
// is what drives the GROUP dot and lets us subtract those texts from the
// CONTACT dot. These tests drive that bookkeeping directly.
// ---------------------------------------------------------------------------

class GroupUnreadAttributionTest {

    /** Builds a group (admin = us) with [bob] a resolved member, wired to a
     *  RecordingRelayHttp so peek/poll can be scripted. Group is inserted
     *  directly (not via createGroup) so the ONLY http calls are the ones the
     *  test scripts. */
    private fun fixture(): Triple<GroupManager, RecordingRelayHttp, String> {
        val vault = InMemoryVault()
        seedContactWithCaps(vault, "c-bob", generateSecureRandom(32))
        val http = RecordingRelayHttp()
        val mgr = MessageManager(vault, "http://relay.test", http as RelayHttp)
        val gm = GroupManager(vault) { mgr }
        val gid = GroupManager.newGroupId()
        val me = memberId(1)
        vault.insertGroup(GroupRecord(gid, "crew", 1, adminMemberId = me, myMemberId = me, createdAt = 0L))
        vault.insertGroupMember(GroupMemberRecord(gid, me, null, 0L))
        vault.insertGroupMember(GroupMemberRecord(gid, memberId(2), "c-bob", 0L))
        return Triple(gm, http, gid)
    }

    @Test
    fun activityNotice_bumpsGroupUnread_andMarkReadClearsIt() {
        val (gm, _, gid) = fixture()
        assertNull(gm.groupUnreadCounts()[gid])
        gm.handleControl("c-bob", gid, GroupManager.KIND_ACTIVITY, "{}")
        gm.handleControl("c-bob", gid, GroupManager.KIND_ACTIVITY, "{}")
        assertEquals(2, gm.groupUnreadCounts()[gid])
        gm.markGroupRead(gid)
        assertNull(gm.groupUnreadCounts()[gid])
    }

    @Test
    fun activityNotice_fromNonMemberOrUnknownGroup_isIgnored() {
        val (gm, _, gid) = fixture()
        // Unknown group id.
        gm.handleControl("c-bob", GroupManager.newGroupId(), GroupManager.KIND_ACTIVITY, "{}")
        // Known group, but sender is not a member.
        gm.handleControl("c-mallory", gid, GroupManager.KIND_ACTIVITY, "{}")
        assertTrue(gm.groupUnreadCounts().isEmpty())
    }

    @Test
    fun contactUnread_subtractsGroupPending_fromThePeekTotal() {
        val (gm, http, gid) = fixture()
        // Two group texts pending from bob (announced via activity notices).
        repeat(2) { gm.handleControl("c-bob", gid, GroupManager.KIND_ACTIVITY, "{}") }
        // Relay says bob has 3 blobs waiting → 3 total − 2 group = 1 direct.
        http.script(HttpResult(code = 200, body = """{"pending":3}""", isSuccess = true))
        assertEquals(1, gm.contactUnreadCounts()["c-bob"])
    }

    @Test
    fun contactUnread_clampsGroupPending_toThePeekTotal() {
        val (gm, http, gid) = fixture()
        // Three notices, but the relay only shows two blobs (one already expired
        // / drained elsewhere) → group-pending is clamped to 2, direct = 0.
        repeat(3) { gm.handleControl("c-bob", gid, GroupManager.KIND_ACTIVITY, "{}") }
        http.script(HttpResult(code = 200, body = """{"pending":2}""", isSuccess = true))
        assertNull(gm.contactUnreadCounts()["c-bob"])  // no contact dot (all group)
    }

    @Test
    fun draining_aGroupText_decrementsContactGroupPending() {
        val (gm, http, gid) = fixture()
        repeat(2) { gm.handleControl("c-bob", gid, GroupManager.KIND_ACTIVITY, "{}") }
        // One group text actually drained (buffered for the group conversation).
        gm.ingest(
            "c-bob",
            listOf(ReceivedMessage("g", 0L, counter = 1, groupId = gid, membershipHash = "000000000000")),
            wantGroupId = null,
        )
        // group-pending now 1 → 3 total − 1 = 2 direct.
        http.script(HttpResult(code = 200, body = """{"pending":3}""", isSuccess = true))
        assertEquals(2, gm.contactUnreadCounts()["c-bob"])
    }

    @Test
    fun openingThe1on1_zeroesGroupPending_forThatContact() {
        val (gm, http, gid) = fixture()
        repeat(2) { gm.handleControl("c-bob", gid, GroupManager.KIND_ACTIVITY, "{}") }
        // pollDirect drains bob's inbox fully → group-pending reset to 0.
        http.script(HttpResult(code = 200, body = """{"blobs":[]}""", isSuccess = true))  // the poll
        gm.pollDirect("c-bob")
        http.script(HttpResult(code = 200, body = """{"pending":3}""", isSuccess = true)) // the peek
        assertEquals(3, gm.contactUnreadCounts()["c-bob"])  // nothing subtracted now
    }
}

// ---------------------------------------------------------------------------
// "Member left" system notice (handleLeave buffers a GroupMessage isSystem).
// ---------------------------------------------------------------------------

class GroupLeaveNoticeTest {

    // The departure notices resolve through platformString (strings_shared.xml
    // keys); commonTest has no platform resolver, so install the English copy
    // the way the app's resources render it.
    @BeforeTest
    fun installEnglishNotices() {
        platformStringOverride = { key, args ->
            when (key) {
                GroupManager.NOTICE_LEFT_KEY -> "${args[0]} left the group"
                GroupManager.NOTICE_REMOVED_KEY -> "${args[0]} was removed from the group"
                GroupManager.NOTICE_MEMBER_FALLBACK_KEY -> "A member"
                else -> key
            }
        }
    }

    @AfterTest
    fun clearOverride() { platformStringOverride = null }

    @Test
    fun handleLeave_postsASystemMessage_namingTheLeaver() {
        val vault = InMemoryVault()
        seedContactWithCaps(vault, "c-bob",   generateSecureRandom(32))
        seedContactWithCaps(vault, "c-carol", generateSecureRandom(32))
        val gm = GroupManager(vault, { null })          // fan-out is a no-op
        val gid = gm.createGroup("crew", listOf("c-bob", "c-carol"))!!

        gm.handleControl("c-bob", gid, GroupManager.KIND_LEAVE, "{}")

        val buffered = gm.takeGroupScreenItems(gid)
        assertEquals(1, buffered.size)
        val sys = buffered.first()
        assertTrue(sys.isSystem)
        assertEquals("c-bob", sys.senderContactId)
        assertEquals("A-c-bob", sys.senderAlias)           // seedContactWithCaps alias
        assertTrue(sys.text.contains("left the group"), "got: ${sys.text}")
        // And bob is actually gone from the roster.
        assertTrue(vault.getGroupMembers(gid).none { it.contactId == "c-bob" })
    }

    @Test
    fun handleLeave_fromNonMember_postsNoSystemMessage() {
        val vault = InMemoryVault()
        seedContactWithCaps(vault, "c-bob", generateSecureRandom(32))
        seedContactWithCaps(vault, "c-mallory", generateSecureRandom(32))
        val gm = GroupManager(vault, { null })
        val gid = gm.createGroup("crew", listOf("c-bob"))!!

        // Mallory is not a member — her leave is a no-op, no notice.
        gm.handleControl("c-mallory", gid, GroupManager.KIND_LEAVE, "{}")
        assertEquals(0, gm.takeGroupScreenItems(gid).size)
    }

    /** Member-side fixture: we joined an admin's group via invite, with [bob]
     *  resolved to a contact through the admin's roster. Returns (gm, gid, bobMemberId). */
    private fun memberSideWithResolvedBob(): Triple<GroupManager, String, String> {
        val vault = InMemoryVault()
        seedContactWithCaps(vault, "admin-contact", generateSecureRandom(32))
        val gm = GroupManager(vault) { null }
        val gid = GroupManager.newGroupId()
        val adm = memberId(10); val me = memberId(20); val bob = memberId(30)
        gm.handleControl(
            "admin-contact", gid, GroupManager.KIND_INVITE,
            """{"n":"crew","ep":1,"adm":${jsonEscapeString(adm)},"you":${jsonEscapeString(me)},"mem":[${jsonEscapeString(adm)},${jsonEscapeString(me)},${jsonEscapeString(bob)}]}""",
        )
        gm.acceptInvite(gid)   // GROUP-1 consent gate: accept the parked invite to join
        val bobSecret = generateSecureRandom(32)
        seedContactWithCaps(vault, "bob-contact", bobSecret)
        val bobTag = GroupManager.boundTag(bobSecret, gid, bob)
        gm.handleControl(
            "admin-contact", gid, GroupManager.KIND_ROSTER,
            """{"n":"crew","ep":2,"adm":${jsonEscapeString(adm)},"mem":[${jsonEscapeString("$adm:")},${jsonEscapeString("$me:")},${jsonEscapeString("$bob:$bobTag")}]}""",
        )
        gm.takeGroupScreenItems(gid)   // clear any incidental buffer
        return Triple(gm, gid, bob)
    }

    @Test
    fun handleRoster_removingAResolvedMember_postsRemovedNotice() {
        val (gm, gid, bob) = memberSideWithResolvedBob()
        val adm = memberId(10); val me = memberId(20)
        // Admin re-rosters at a higher epoch WITHOUT bob → he was removed.
        gm.handleControl(
            "admin-contact", gid, GroupManager.KIND_ROSTER,
            """{"n":"crew","ep":3,"adm":${jsonEscapeString(adm)},"mem":[${jsonEscapeString("$adm:")},${jsonEscapeString("$me:")}]}""",
        )
        val notices = gm.takeGroupScreenItems(gid)
        assertEquals(1, notices.size)
        assertTrue(notices[0].isSystem)
        assertEquals("bob-contact", notices[0].senderContactId)
        assertTrue(notices[0].text.contains("was removed"), "got: ${notices[0].text}")
    }

    @Test
    fun voluntaryLeave_announcesLeftOnce_evenIfAdminReRosters() {
        val (gm, gid, _) = memberSideWithResolvedBob()
        val adm = memberId(10); val me = memberId(20)
        // Bob leaves voluntarily (his own channel) → "left".
        gm.handleControl("bob-contact", gid, GroupManager.KIND_LEAVE, "{}")
        // The admin's follow-up roster also drops bob — must NOT add a 2nd notice.
        gm.handleControl(
            "admin-contact", gid, GroupManager.KIND_ROSTER,
            """{"n":"crew","ep":3,"adm":${jsonEscapeString(adm)},"mem":[${jsonEscapeString("$adm:")},${jsonEscapeString("$me:")}]}""",
        )
        val notices = gm.takeGroupScreenItems(gid)
        assertEquals(1, notices.size)
        assertTrue(notices[0].text.contains("left the group"), "got: ${notices[0].text}")
    }
}

// ---------------------------------------------------------------------------
// Roster-rate-limit _meta purge on
// member removal, and the in-memory buffer scrub on lock/panic-wipe.
// ---------------------------------------------------------------------------

class GroupMetaPurgeAndScrubTest {

    private fun rosterKey(gid: String, contactId: String) = "grp_roster_rl:$gid:$contactId"

    /** (a) removeMember purges the removed member's grp_roster_rl:<gid>:<contactId>
     *  residue while leaving the group_admin tombstone AND other members intact. */
    @Test
    fun removeMember_purgesRemovedMembersRosterMeta_keepsAdminTombstoneAndOthers() {
        val vault = InMemoryVault()
        seedContactWithCaps(vault, "c-bob", generateSecureRandom(32))
        seedContactWithCaps(vault, "c-carol", generateSecureRandom(32))
        val gm = GroupManager(vault) { null }   // fan-out is a no-op (null transport)
        val gid = gm.createGroup("crew", listOf("c-bob", "c-carol"))!!
        val bobMemberId = vault.getGroupMembers(gid).first { it.contactId == "c-bob" }.memberId

        // Ordinary-participation residue: a per-member roster throttle key for each
        // member (written by rosterBroadcastAllowed on every KIND_JOIN), plus the
        // admin tombstone (must SURVIVE — it is deliberate anti-eclipse residue).
        vault.putMeta(rosterKey(gid, "c-bob"), "1000")
        vault.putMeta(rosterKey(gid, "c-carol"), "2000")
        vault.putMeta("group_admin:$gid", "some-admin-contact")

        assertTrue(gm.removeMember(gid, bobMemberId), "admin removal must succeed")

        // Removed member's roster residue is gone...
        assertNull(vault.getMeta(rosterKey(gid, "c-bob")), "removed member's roster-rl residue must be purged")
        // ...but the surviving member's key and the admin tombstone are untouched.
        assertNotNull(vault.getMeta(rosterKey(gid, "c-carol")), "a surviving member's roster residue must be untouched")
        assertNotNull(vault.getMeta("group_admin:$gid"), "group_admin tombstone must survive member removal")
        // And the group itself stays ALIVE with its remaining members (deleteGroup never ran).
        assertNotNull(vault.getGroup(gid), "group must stay alive")
        assertTrue(vault.getGroupMembers(gid).none { it.memberId == bobMemberId }, "removed member row gone")
        assertTrue(vault.getGroupMembers(gid).any { it.contactId == "c-carol" }, "other member remains")
    }

    /** Sibling path: a member's voluntary LEAVE applied on the admin device must
     *  purge the same roster-rl residue (handleLeave, not just removeMember). */
    @Test
    fun handleLeave_onAdmin_purgesLeaversRosterMeta() {
        val vault = InMemoryVault()
        seedContactWithCaps(vault, "c-bob", generateSecureRandom(32))
        seedContactWithCaps(vault, "c-carol", generateSecureRandom(32))
        val gm = GroupManager(vault) { null }
        val gid = gm.createGroup("crew", listOf("c-bob", "c-carol"))!!
        vault.putMeta(rosterKey(gid, "c-bob"), "1000")

        gm.handleControl("c-bob", gid, GroupManager.KIND_LEAVE, "{}")

        assertNull(vault.getMeta(rosterKey(gid, "c-bob")), "leaver's roster-rl residue must be purged on the admin device")
        assertTrue(vault.getGroupMembers(gid).none { it.contactId == "c-bob" }, "leaver row gone")
    }

    /** (b) scrubInMemory empties every in-memory group buffer (parked group text,
     *  parked direct text, group-unread dot, and parked invites — group name +
     *  inviter alias). Nulling the reference (what the platform does) does NOT do this. */
    @Test
    fun scrubInMemory_emptiesAllGroupBuffers() {
        val vault = InMemoryVault()
        seedContactWithCaps(vault, "admin-contact", generateSecureRandom(32))
        val gm = GroupManager(vault) { null }
        val gid = GroupManager.newGroupId()
        val adm = memberId(10); val me = memberId(20); val bob = memberId(30)
        gm.handleControl(
            "admin-contact", gid, GroupManager.KIND_INVITE,
            """{"n":"crew","ep":1,"adm":${jsonEscapeString(adm)},"you":${jsonEscapeString(me)},"mem":[${jsonEscapeString(adm)},${jsonEscapeString(me)},${jsonEscapeString(bob)}]}""",
        )
        gm.acceptInvite(gid)

        // A decrypted GROUP text drained by the 1:1 screen → a GROUP_ECHO in that screen's buffer.
        val goodHash = GroupManager.membershipHash(gid, vault.getGroup(gid)!!.epoch, vault.getGroupMembers(gid).map { it.memberId })
        gm.ingest(
            "admin-contact",
            listOf(ReceivedMessage("secret group text", 0L, counter = 1, groupId = gid, membershipHash = goodHash)),
            wantGroupId = null, bufferAll = true,
        )
        // A DIRECT text drained by the group screen → a PRIVATE item in that screen's buffer.
        gm.ingest("admin-contact", listOf(ReceivedMessage("secret direct text", 0L, counter = 2)), wantGroupId = gid, bufferAll = true)
        // Light the GROUP unread dot.
        gm.handleControl("admin-contact", gid, GroupManager.KIND_ACTIVITY, "{}")
        // Park a SECOND invite awaiting consent (holds group name + inviter alias + memberIds).
        val gid2 = GroupManager.newGroupId(); val me2 = memberId(40)
        gm.handleControl(
            "admin-contact", gid2, GroupManager.KIND_INVITE,
            """{"n":"secret-crew-2","ep":1,"adm":${jsonEscapeString(adm)},"you":${jsonEscapeString(me2)},"mem":[${jsonEscapeString(adm)},${jsonEscapeString(me2)}]}""",
        )

        // Precondition: the observable buffers ARE populated.
        assertTrue(gm.groupUnreadCounts().isNotEmpty(), "precondition: group unread populated")
        assertTrue(gm.pendingInvites().isNotEmpty(), "precondition: a parked invite exists")

        gm.scrubInMemory()

        // Every buffer emptied.
        assertTrue(gm.takeGroupScreenItems(gid).isEmpty(), "the group screen buffer must be scrubbed")
        assertTrue(gm.takeDirectScreenItems("admin-contact").isEmpty(), "the 1:1 screen buffer must be scrubbed")
        assertTrue(gm.groupUnreadCounts().isEmpty(), "groupUnread must be scrubbed")
        assertTrue(gm.pendingInvites().isEmpty(), "pendingInvites must be scrubbed")
    }
}

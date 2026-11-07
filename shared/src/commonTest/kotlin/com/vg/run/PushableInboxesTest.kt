package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// Inbound CONTROL inboxes joined the push-registration surface, and the
// wake decision moved to the SENDER, per control kind.
//
// Both halves are load-bearing and are pinned together here, because either one
// alone is a defect: registering the control inbox without the per-kind
// suppression banners every device for roster bookkeeping (the relay's APNs wake
// is an ALERT push with a body and a sound, not a silent content-available one),
// while suppressing without registering leaves referral offers/accepts and group
// invites unable to wake a sleeping device at all — which is the delivery half of
// the same half-pair defect the 7-day TTL attacks from the storage side.
// ---------------------------------------------------------------------------

private const val PB_RELAY = "http://relay.test"
private val PB_IN     = "pbin" + "A".repeat(28)
private val PB_IN_CTL = "pbct" + "B".repeat(28)
private val PB_OUT    = "pbou" + "C".repeat(28)
private val PB_CAP_R = "R".repeat(43)
private val PB_CAP_S = "S".repeat(43)
private val PB_CAP_W = "W".repeat(43)

private fun pbSeed(vault: InMemoryVault, id: String, alias: String) {
    vault.insertContact(
        ContactRecord(contactId = id, sharedSecret = generateSecureRandom(32), trustLevel = 0, alias = alias, aliasLastRotated = 0L)
    )
}

class AllPushableInboxesTest {

    @Test
    fun coversBothInboundDirections_andNeverAnOutboundRow() {
        val vault = InMemoryVault()
        pbSeed(vault, "carol", "Carol")
        vault.insertInboxId(InboxIdRecord(PB_IN, "carol", 1L, Long.MAX_VALUE, "inbound", PB_CAP_R))
        vault.insertInboxId(InboxIdRecord(PB_IN_CTL, "carol", 1L, Long.MAX_VALUE, MessageManager.DIR_INBOUND_CTL, PB_CAP_S))
        // An OUTBOUND row carries the PEER's write cap, never a read cap — it must
        // never reach a push registration, which authenticates with the read cap.
        vault.insertInboxId(InboxIdRecord(PB_OUT, "carol", 1L, Long.MAX_VALUE, "outbound", PB_CAP_W))

        val refs = allPushableInboxes(vault)
        assertEquals(setOf(PB_IN, PB_IN_CTL), refs.map { it.inboxId }.toSet(), "the control inbox must be pushable now")
        assertEquals(PB_CAP_S, refs.single { it.inboxId == PB_IN_CTL }.readCap, "each ref carries THAT inbox's own cap")
        assertTrue(refs.none { it.inboxId == PB_OUT })
        // The text-only surface is unchanged — it is still the right answer for
        // "where do user-visible messages arrive".
        assertEquals(listOf(PB_IN), allInboundTextInboxes(vault).map { it.inboxId })
    }

    @Test
    fun aContactWithOnlyAControlInbox_isStillPushable() {
        val vault = InMemoryVault()
        pbSeed(vault, "carol", "Carol")
        vault.insertInboxId(InboxIdRecord(PB_IN_CTL, "carol", 1L, Long.MAX_VALUE, MessageManager.DIR_INBOUND_CTL, PB_CAP_S))
        assertEquals(listOf(PB_IN_CTL), allPushableInboxes(vault).map { it.inboxId })
        assertTrue(allInboundTextInboxes(vault).isEmpty())
    }

    @Test
    fun malformedRowsAreSkipped_notSurfacedAsUnusableRefs() {
        val vault = InMemoryVault()
        pbSeed(vault, "carol", "Carol")
        // Empty cap (a pre-v7 / stale row) and a cap that fails the shape gate.
        vault.insertInboxId(InboxIdRecord(PB_IN, "carol", 1L, Long.MAX_VALUE, "inbound", null))
        vault.insertInboxId(InboxIdRecord(PB_IN_CTL, "carol", 1L, Long.MAX_VALUE, MessageManager.DIR_INBOUND_CTL, "short"))
        assertTrue(allPushableInboxes(vault).isEmpty())
    }

    @Test
    fun everyContactContributes() {
        val vault = InMemoryVault()
        pbSeed(vault, "carol", "Carol")
        pbSeed(vault, "dave", "Dave")
        val d = "pbdv" + "D".repeat(28)
        vault.insertInboxId(InboxIdRecord(PB_IN_CTL, "carol", 1L, Long.MAX_VALUE, MessageManager.DIR_INBOUND_CTL, PB_CAP_S))
        vault.insertInboxId(InboxIdRecord(d, "dave", 1L, Long.MAX_VALUE, "inbound", PB_CAP_R))
        assertEquals(setOf(PB_IN_CTL, d), allPushableInboxes(vault).map { it.inboxId }.toSet())
    }

    /** A ref must never print a live capability, whichever surface produced it. */
    @Test
    fun refsRedactTheCapabilityInToString() {
        val vault = InMemoryVault()
        pbSeed(vault, "carol", "Carol")
        vault.insertInboxId(InboxIdRecord(PB_IN_CTL, "carol", 1L, Long.MAX_VALUE, MessageManager.DIR_INBOUND_CTL, PB_CAP_S))
        val rendered = allPushableInboxes(vault).single().toString()
        assertTrue(!rendered.contains(PB_CAP_S), "a capability must never reach a log line")
    }
}

// ---------------------------------------------------------------------------
// The per-kind wake decision, asserted at the wire: `X-No-Push: 1` present or
// absent on the control POST each sender produces.
// ---------------------------------------------------------------------------

private class PbCtlFixture {
    val vault = InMemoryVault()
    val http = RecordingRelayHttp()
    val mgr = MessageManager(vault, PB_RELAY, http as RelayHttp)

    /** A peer with BOTH a text and a control outbound row, so control traffic
     *  takes the v7 control channel (not the pre-v7 main-inbox fallback). */
    fun peer(id: String): PbCtlFixture {
        val base = id.hashCode().toUInt().toString(16).padStart(8, '0')
        vault.insertContact(ContactRecord(id, generateSecureRandom(32), 0, "A-$id", 0L))
        vault.insertInboxId(InboxIdRecord(("in$base".padEnd(32, 'A')).take(32), id, 1L, Long.MAX_VALUE, "inbound", PB_CAP_R))
        vault.insertInboxId(InboxIdRecord(("ou$base".padEnd(32, 'B')).take(32), id, 1L, Long.MAX_VALUE, "outbound", PB_CAP_W))
        vault.insertInboxId(InboxIdRecord(("oc$base".padEnd(32, 'C')).take(32), id, 1L, Long.MAX_VALUE, MessageManager.DIR_OUTBOUND_CTL, PB_CAP_W))
        return this
    }

    fun ok(n: Int = 1) = repeat(n) { http.script(HttpResult(202, "", true)) }
    fun posts() = http.calls.filter { it.method == "POST" }
    fun lastNoPush() = posts().last().headers["X-No-Push"]
    fun allNoPush() = posts().map { it.headers["X-No-Push"] }
}

class ControlKindNoPushMatrixTest {

    // -- must WAKE (no suppression header at all) ------------------------------

    @Test
    fun referralOfferAndAccept_wakeTheDevice() {
        if (!aeadUp()) return
        val f = PbCtlFixture().peer("bb").peer("cc")
        f.ok(2)
        val rm = ReferralManager(f.vault) { f.mgr }
        val introId = assertNotNull(rm.startReferral("bb", "cc"))
        assertEquals(listOf(null, null), f.allNoPush(), "a referral offer raises a consent prompt — it must wake")

        f.ok(1)
        rm.handleControl(
            "bb", MessageManager.CONTROL_KIND_REFERRAL_ACCEPT,
            """{"ii":${jsonEscapeString(introId)},"pk":"AAAA","ib":"x","wc":"y","cib":"z","cwc":"w"}""",
        )
        assertNull(f.lastNoPush(), "a relayed accept completes an introduction the user is waiting on — it must wake")
    }

    @Test
    fun groupInvite_wakesTheDevice() {
        if (!aeadUp()) return
        val f = PbCtlFixture().peer("bb")
        f.ok(1)
        val gm = GroupManager(f.vault) { f.mgr }
        assertNotNull(gm.createGroup("crew", listOf("bb")))
        assertEquals(listOf(null), f.allNoPush(), "an invite either prompts or makes a group appear — it must wake")
    }

    // -- must NOT wake ---------------------------------------------------------

    @Test
    fun inboxAnnounce_isAlwaysSuppressed() {
        if (!aeadUp()) return
        val f = PbCtlFixture().peer("bb")
        f.ok(1)
        // sendInboxAnnounce has no noPush parameter at all (removed: the one
        // shipped Swift call site no longer passes one) — suppression is
        // unconditional, forced inside the function, not merely a default a
        // caller could override.
        assertTrue(f.mgr.sendInboxAnnounce("bb", PB_IN, PB_CAP_W, PB_IN_CTL, PB_CAP_W))
        assertEquals("1", f.lastNoPush(), "pairing maintenance must never banner a device")
    }

    @Test
    fun directScreenshotNotice_isSuppressed() {
        if (!aeadUp()) return
        val f = PbCtlFixture().peer("bb")
        f.ok(1)
        assertTrue(f.mgr.sendScreenshotNotice("bb"))
        assertEquals("1", f.lastNoPush())
    }

    @Test
    fun groupScreenshotNotice_isSuppressed() {
        if (!aeadUp()) return
        val f = PbCtlFixture().peer("bb")
        f.ok(1)
        val gm = GroupManager(f.vault) { f.mgr }
        val gid = assertNotNull(gm.createGroup("crew", listOf("bb")))
        f.ok(1)
        gm.sendGroupScreenshotNotice(gid)
        assertEquals("1", f.lastNoPush())
    }

    @Test
    fun groupActivityNotice_isSuppressed_becauseTheTextCopyAlreadyWoke() {
        if (!aeadUp()) return
        val f = PbCtlFixture().peer("bb")
        f.ok(1)
        val gm = GroupManager(f.vault) { f.mgr }
        val gid = assertNotNull(gm.createGroup("crew", listOf("bb")))
        f.ok(2)          // the text copy, then the activity notice
        gm.sendGroupMessage(gid, "hello")
        val tail = f.allNoPush().takeLast(2)
        assertEquals(null, tail[0], "the group TEXT keeps waking — it is a user-visible message")
        assertEquals("1", tail[1], "the activity notice must not double-banner the same message")
    }

    @Test
    fun groupLeave_isSuppressed() {
        if (!aeadUp()) return
        val f = PbCtlFixture().peer("bb")
        f.ok(1)
        val gm = GroupManager(f.vault) { f.mgr }
        val gid = assertNotNull(gm.createGroup("crew", listOf("bb")))
        f.ok(1)
        gm.leaveGroup(gid)
        assertEquals("1", f.lastNoPush(), "a departure is roster bookkeeping")
    }

    @Test
    fun groupJoin_isSuppressed() {
        if (!aeadUp()) return
        val f = PbCtlFixture().peer("admin")
        val gm = GroupManager(f.vault) { f.mgr }
        val gid = GroupManager.newGroupId()
        val adm = bytesToHex(ByteArray(8) { 10 })
        val me = bytesToHex(ByteArray(8) { 20 })
        gm.handleControl(
            "admin", gid, GroupManager.KIND_INVITE,
            """{"n":"crew","ep":1,"adm":${jsonEscapeString(adm)},"you":${jsonEscapeString(me)},""" +
                """"mem":[${jsonEscapeString(adm)},${jsonEscapeString(me)}]}""",
        )
        f.ok(1)
        assertTrue(gm.acceptInvite(gid))
        assertEquals("1", f.lastNoPush(), "our join is protocol bookkeeping for the admin's roster")
    }

    @Test
    fun groupRoster_isSuppressed() {
        if (!aeadUp()) return
        val f = PbCtlFixture().peer("bb").peer("cc")
        f.ok(1)
        val gm = GroupManager(f.vault) { f.mgr }
        val gid = assertNotNull(gm.createGroup("crew", listOf("bb")))
        val invitesSoFar = f.posts().size
        // addMember = one INVITE to the newcomer, then a roster to everyone.
        f.ok(4)
        assertTrue(gm.addMember(gid, "cc"))
        val after = f.allNoPush().drop(invitesSoFar)
        assertEquals(null, after.first(), "the newcomer's invite still wakes")
        assertTrue(
            after.drop(1).all { it == "1" } && after.size > 1,
            "every roster copy must be silent — it fans to EVERY member on every epoch change, saw $after",
        )
    }
}

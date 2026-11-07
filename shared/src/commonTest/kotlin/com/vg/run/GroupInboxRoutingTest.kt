package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// The THIRD pairwise inbox — GROUP text (wire + protocol core).
//
// A group text used to ride the sender's 1:1 TEXT inbox, and `/peek` returns a
// bare count with every routing field sealed inside the AEAD — so "is this queued
// blob a group text?" was knowable only after a decrypt the unread sweep
// deliberately never performs, and the contact dot lit for group messages. With
// group text on its OWN relay inbox the answer is structural.
//
// What is pinned here: the Chan derivations (row, counter space, sealed "ch"),
// the receive guards on the new inbox, the announce/QR/referral carriers, the
// owned-read-direction coupling, the 404 rules, and — the cell that must never
// regress — a peer with no group inbox still exchanging group text over the text
// inbox exactly as before.
// ---------------------------------------------------------------------------

private val GI_MAIN = ("gimain".padEnd(32, 'A')).take(32)
private val GI_CTL  = ("gictl".padEnd(32, 'B')).take(32)
private val GI_GRP  = ("gigrp".padEnd(32, 'C')).take(32)
private val GI_A_IN_MAIN = ("giamain".padEnd(32, 'D')).take(32)
private val GI_A_IN_CTL  = ("giactl".padEnd(32, 'E')).take(32)
private val GI_A_IN_GRP  = ("giagrp".padEnd(32, 'F')).take(32)
private val GI_CAP  = "G".repeat(43)
private val GI_CAP2 = "H".repeat(43)
private val GI_GROUP_ID = ("gigroup".padEnd(32, 'I')).take(32)

/** Seals an envelope exactly as the production sender does. */
private fun giSeal(sharedSecret: ByteArray, envelopeJson: String): String {
    val key = sha256(sharedSecret)
    val ctx = sha256(key + "message-aead".encodeToByteArray())
    return encodeBase64(aesGcmEncrypt(padMessage(envelopeJson.encodeToByteArray()), key, ctx))
}

private fun giEpoch(sharedSecret: ByteArray): String =
    bytesToHex(sha256(sharedSecret + "msg-epoch".encodeToByteArray()).copyOfRange(0, 6))

/** Opens a blob A produced, so the sealed `ch` can be asserted directly. */
private fun giOpen(mgr: MessageManager, sharedSecret: ByteArray, blobB64: String): MessageManager.Envelope? {
    val key = sha256(sharedSecret)
    val ctx = sha256(key + "message-aead".encodeToByteArray())
    val padded = aesGcmDecrypt(decodeBase64(blobB64), key, ctx)
    return mgr.parseEnvelope(unpadMessage(padded).decodeToString())
}

/**
 * Sender A and receiver B over one shared secret. A holds the three OUTBOUND
 * rows, B the three INBOUND rows for the same relay inboxes — so a blob A posts
 * to an inbox is the blob B drains from it.
 *
 * [aHasGrp] / [bHasGrp] are independent on purpose: the rollout matrix's whole
 * point is that the two sides upgrade at different times.
 */
private class GrpHarness(aHasGrp: Boolean = true, bHasGrp: Boolean = true) {
    val shared = generateSecureRandom(32)
    val epoch = giEpoch(shared)
    val aVault = InMemoryVault()
    val aHttp = RecordingRelayHttp()
    val aMgr = MessageManager(aVault, "http://relay.test", aHttp as RelayHttp)
    val bVault = InMemoryVault()
    val bHttp = RecordingRelayHttp()
    val bMgr = MessageManager(bVault, "http://relay.test", bHttp as RelayHttp)

    init {
        aVault.insertContact(ContactRecord("b", shared, 0, "B", 0L))
        aVault.insertInboxId(InboxIdRecord(GI_MAIN, "b", 1L, Long.MAX_VALUE, "outbound", GI_CAP))
        aVault.insertInboxId(InboxIdRecord(GI_CTL, "b", 1L, Long.MAX_VALUE, MessageManager.DIR_OUTBOUND_CTL, GI_CAP))
        if (aHasGrp) {
            aVault.insertInboxId(InboxIdRecord(GI_GRP, "b", 1L, Long.MAX_VALUE, MessageManager.DIR_OUTBOUND_GRP, GI_CAP))
        }
        // A's own inbound rows, so an announce it sends declares real ids.
        aVault.insertInboxId(InboxIdRecord(GI_A_IN_MAIN, "b", 1L, Long.MAX_VALUE, "inbound", GI_CAP2))
        aVault.insertInboxId(InboxIdRecord(GI_A_IN_CTL, "b", 1L, Long.MAX_VALUE, MessageManager.DIR_INBOUND_CTL, GI_CAP2))
        if (aHasGrp) {
            aVault.insertInboxId(InboxIdRecord(GI_A_IN_GRP, "b", 1L, Long.MAX_VALUE, MessageManager.DIR_INBOUND_GRP, GI_CAP2))
        }

        bVault.insertContact(ContactRecord("a", shared, 0, "A", 0L))
        bVault.insertInboxId(InboxIdRecord(GI_MAIN, "a", 1L, Long.MAX_VALUE, "inbound", GI_CAP))
        bVault.insertInboxId(InboxIdRecord(GI_CTL, "a", 1L, Long.MAX_VALUE, MessageManager.DIR_INBOUND_CTL, GI_CAP))
        if (bHasGrp) {
            bVault.insertInboxId(InboxIdRecord(GI_GRP, "a", 1L, Long.MAX_VALUE, MessageManager.DIR_INBOUND_GRP, GI_CAP))
        }
    }

    fun ok(n: Int = 1) = repeat(n) { aHttp.script(HttpResult(202, "", true)) }
    fun lastPostUrl(): String = aHttp.calls.last { it.method == "POST" }.url
    fun lastBlobB64(): String = encodeBase64(aHttp.calls.last { it.method == "POST" }.body)
    /** Script ONE drain response for B carrying [blobs]. */
    fun serveB(vararg blobs: String) {
        bHttp.script(HttpResult(200, """{"blobs":[${blobs.joinToString(",") { "\"$it\"" }}]}""", true))
    }
    fun aContact() = aVault.getContact("b")!!
    fun bContact() = bVault.getContact("a")!!
}

class GroupInboxRoutingTest {

    // --- Chan: one value, five coupled derivations --------------------------

    @Test
    fun groupText_landsOnTheGroupInbox_withTheGroupCounterAndTheGroupTag() {
        if (!aeadUp()) return
        val h = GrpHarness()
        h.ok()

        assertTrue(h.aMgr.sendGroupText("b", GI_GROUP_ID, "hash", "hello group"))

        // The ROW: the peer's group inbox, and no `?ttl` — a group TEXT append must
        // stay byte-identical in shape to a 1:1 text (no plaintext classifier).
        assertEquals("http://relay.test/inbox/$GI_GRP", h.lastPostUrl())
        // The COUNTER SPACE: the group counter only.
        assertEquals(1L, h.aContact().outboundGrpCounter)
        assertEquals(0L, h.aContact().outboundCounter, "the 1:1 text counter must not move")
        assertEquals(0L, h.aContact().outboundCtlCounter, "the control counter must not move")
        // The SEALED TAG + the destination binding.
        val env = giOpen(h.aMgr, h.shared, h.lastBlobB64())
        assertNotNull(env)
        assertEquals(MessageManager.CHANNEL_TAG_GRP, env.channel)
        assertEquals(GI_GRP, env.destInbox)
        assertEquals(GI_GROUP_ID, env.groupId)
    }

    @Test
    fun allThreeChannels_keepIndependentCounterSpaces() {
        if (!aeadUp()) return
        val h = GrpHarness()
        h.ok(3)

        assertTrue(h.aMgr.sendMessage("b", "one-to-one"))
        assertTrue(h.aMgr.sendGroupText("b", GI_GROUP_ID, "hash", "group"))
        assertTrue(h.aMgr.sendInboxAnnounce("b", GI_A_IN_MAIN, GI_CAP2))

        val c = h.aContact()
        assertEquals(1L, c.outboundCounter)
        assertEquals(1L, c.outboundGrpCounter)
        assertEquals(1L, c.outboundCtlCounter)
    }

    @Test
    fun groupTextOnTheGroupInbox_isAcceptedAndAdvancesOnlyTheGroupBaseline() {
        if (!aeadUp()) return
        val h = GrpHarness()
        h.ok()
        assertTrue(h.aMgr.sendGroupText("b", GI_GROUP_ID, "hash", "hello group"))
        h.serveB(h.lastBlobB64())

        val received = h.bMgr.pollGroupInbox("a")

        assertEquals(1, received.size)
        assertEquals("hello group", received[0].text)
        assertEquals(GI_GROUP_ID, received[0].groupId)
        assertEquals(1L, h.bContact().inboundGrpCounter)
        assertEquals(0L, h.bContact().inboundCounter, "the 1:1 baseline must not move")
        assertEquals(0L, h.bContact().inboundCtlCounter, "the control baseline must not move")
    }

    // --- Receive-side channel enforcement -----------------------------------

    @Test
    fun groupTaggedBlobSplicedOntoTheTextInbox_isDropped() {
        if (!aeadUp()) return
        // The exact move that would light a CONTACT unread dot for a group message.
        // `di` deliberately names the TEXT inbox so the destination binding PASSES
        // and this isolates the "ch" check.
        val h = GrpHarness()
        val blob = giSeal(
            h.shared,
            """{"e":"${h.epoch}","c":1,"t":0,"ch":"${MessageManager.CHANNEL_TAG_GRP}","di":"$GI_MAIN","g":"$GI_GROUP_ID","h":"x","m":"spliced"}""",
        )
        h.serveB(blob)

        assertEquals(0, h.bMgr.pollMessages("a").size, "a group-tagged blob must not be accepted on the text inbox")
        assertEquals(0L, h.bContact().inboundCounter, "a dropped splice must not advance the text baseline")
    }

    @Test
    fun textTaggedBlobSplicedOntoTheGroupInbox_isDropped() {
        if (!aeadUp()) return
        val h = GrpHarness()
        val blob = giSeal(
            h.shared,
            """{"e":"${h.epoch}","c":1,"t":0,"ch":"${MessageManager.CHANNEL_TAG_MAIN}","di":"$GI_GRP","g":"$GI_GROUP_ID","h":"x","m":"spliced"}""",
        )
        h.serveB(blob)

        assertEquals(0, h.bMgr.pollGroupInbox("a").size)
        assertEquals(0L, h.bContact().inboundGrpCounter)
    }

    @Test
    fun blobWithoutAGroupId_onTheGroupInbox_isDropped() {
        if (!aeadUp()) return
        // Nothing legitimate produces one: sendGroupText is the ONLY sender that
        // selects Chan.GRP and it always writes "g".
        val h = GrpHarness()
        val blob = giSeal(
            h.shared,
            """{"e":"${h.epoch}","c":1,"t":0,"ch":"${MessageManager.CHANNEL_TAG_GRP}","di":"$GI_GRP","m":"bare text"}""",
        )
        h.serveB(blob)

        assertEquals(0, h.bMgr.pollGroupInbox("a").size, "a bare text on the group inbox must be dropped")
        assertEquals(0L, h.bContact().inboundGrpCounter)
    }

    @Test
    fun controlKindOnTheGroupInbox_isDropped() {
        if (!aeadUp()) return
        // The buffer-flood vector, mirrored: group CONTROL stays on the
        // control inbox, and an ANNOUNCE especially must never be applied from here.
        val h = GrpHarness()
        val body = """{"gib":"$GI_A_IN_GRP","gwc":"$GI_CAP2"}"""
        val blob = giSeal(
            h.shared,
            """{"e":"${h.epoch}","c":1,"t":0,"ch":"${MessageManager.CHANNEL_TAG_GRP}","di":"$GI_GRP","g":"$GI_GROUP_ID","k":"${MessageManager.CONTROL_KIND_INBOX}","b":${jsonEscapeString(body)},"m":""}""",
        )
        h.serveB(blob)

        assertEquals(0, h.bMgr.pollGroupInbox("a").size)
        assertEquals(0L, h.bContact().inboundGrpCounter)
        assertNull(
            h.bVault.getInboxIdForContact("a", MessageManager.DIR_OUTBOUND_GRP),
            "an announce must never be applied off the group inbox",
        )
    }

    @Test
    fun groupTaggedBlobOnTheTEXTinbox_fromALegacyPeer_isStillAccepted() {
        if (!aeadUp()) return
        // Rollout cells 2/3/4 and the whole backfill window depend on this: dropping
        // it would lose every group message from a peer that has no group inbox.
        val h = GrpHarness()
        val blob = giSeal(
            h.shared,
            """{"e":"${h.epoch}","c":1,"t":0,"ch":"${MessageManager.CHANNEL_TAG_MAIN}","di":"$GI_MAIN","g":"$GI_GROUP_ID","h":"x","m":"legacy group text"}""",
        )
        h.serveB(blob)

        val received = h.bMgr.pollMessages("a")
        assertEquals(1, received.size)
        assertEquals(GI_GROUP_ID, received[0].groupId)
        assertEquals(1L, h.bContact().inboundCounter)
    }

    // --- Rollout: the capability signal is a vault ROW, not a version -------

    @Test
    fun senderWithoutThePeersGroupRow_fallsBackToTheTextInbox_andTheReceiverStillRoutesIt() {
        if (!aeadUp()) return
        // Cell 4: A has not learned B's group inbox (backfill window / announce
        // lost), while B is fully upgraded. Nothing may be lost.
        val h = GrpHarness(aHasGrp = false, bHasGrp = true)
        h.ok()

        assertTrue(h.aMgr.sendGroupText("b", GI_GROUP_ID, "hash", "fallback text"))

        assertEquals("http://relay.test/inbox/$GI_MAIN", h.lastPostUrl())
        assertEquals(1L, h.aContact().outboundCounter, "the fallback consumes the TEXT counter space")
        assertEquals(0L, h.aContact().outboundGrpCounter)
        val env = giOpen(h.aMgr, h.shared, h.lastBlobB64())
        assertNotNull(env)
        assertEquals(MessageManager.CHANNEL_TAG_MAIN, env.channel, "the tag follows the inbox ACTUALLY used")

        h.serveB(h.lastBlobB64())
        val received = h.bMgr.pollMessages("a")
        assertEquals(1, received.size)
        assertEquals(GI_GROUP_ID, received[0].groupId, "the receiver still routes it to the group layer")
    }

    @Test
    fun aContactWithNoGroupRow_pollingTheGroupInbox_isANetworklessNoop() {
        val vault = InMemoryVault()
        val http = RecordingRelayHttp()
        val mgr = MessageManager(vault, "http://relay.test", http as RelayHttp)
        vault.insertContact(ContactRecord("c", generateSecureRandom(32), 0, "C", 0L))
        vault.insertInboxId(InboxIdRecord(GI_MAIN, "c", 1L, Long.MAX_VALUE, "inbound", GI_CAP))

        assertEquals(0, mgr.pollGroupInbox("c").size)
        assertEquals(0, http.calls.size, "no group row: the group poll must not touch the network")
        assertFalse(mgr.groupInboxSelfHealDue("c"), "…so it can never record a group-channel 404")
    }

    // --- 404 rules ----------------------------------------------------------

    @Test
    fun groupInbox404Streak_doesNotRaiseTheRePairBadge_butMarksTheSelfHealDue() {
        val vault = InMemoryVault()
        vault.insertContact(ContactRecord("c1", generateSecureRandom(32), 1, "A", 0L))
        vault.insertInboxId(
            InboxIdRecord(GI_GRP, "c1", 1L, Long.MAX_VALUE, MessageManager.DIR_INBOUND_GRP, GI_CAP)
        )
        val relay = FakeRelayHttp(
            onPost = { HttpResult(202, "", true) },
            onPut = { HttpResult(202, "", true) },
            onGet = { HttpResult(404, """{"error":"request rejected"}""", false) },
        )
        val mgr = MessageManager(vault, "http://relay.test", relay)
        var clock = 0L
        mgr.relayLostClockMs = { clock }

        repeat(mgr.RELAY_LOST_404_STREAK) { mgr.pollGroupInbox("c1") }
        assertFalse(mgr.groupInboxSelfHealDue("c1"), "the count alone must not be due inside the window")

        clock = mgr.RELAY_LOST_MIN_WINDOW_MS
        mgr.pollGroupInbox("c1")

        assertTrue(mgr.groupInboxSelfHealDue("c1"), "a persistent group-inbox 404 must arm the in-band self-heal")
        assertFalse(
            "c1" in mgr.relayLostContacts(),
            "…and must NOT demand a re-pair: we own that inbox and can replace it in band",
        )
    }

    @Test
    fun outboundGroupInbox404OnASend_retriesThatOneSendOnTheTextInbox() {
        if (!aeadUp()) return
        val h = GrpHarness()
        h.aHttp.script(
            HttpResult(404, """{"error":"request rejected"}""", false),   // the group inbox is gone
            HttpResult(202, "", true),                                   // the text inbox takes it
        )

        assertTrue(h.aMgr.sendGroupText("b", GI_GROUP_ID, "hash", "retried"))

        val posts = h.aHttp.calls.filter { it.method == "POST" }
        assertEquals(2, posts.size, "one attempt per inbox — never a retry loop")
        assertEquals("http://relay.test/inbox/$GI_GRP", posts[0].url)
        assertEquals("http://relay.test/inbox/$GI_MAIN", posts[1].url)
        // MUTATE NOTHING: the row survives a relay answer we do not trust.
        assertNotNull(
            h.aVault.getInboxIdForContact("b", MessageManager.DIR_OUTBOUND_GRP),
            "a 404 must never delete the group row",
        )
    }

    @Test
    fun outboundGroupInboxTransportFailure_isNotTreatedAsInboxGone() {
        if (!aeadUp()) return
        // "Unreachable" is not evidence that an inbox is gone, so there must be no
        // text-inbox retry — only the ordinary transient retries on the SAME inbox.
        val h = GrpHarness()
        repeat(MessageManager.SEND_TRANSIENT_ATTEMPTS) {
            h.aHttp.script(HttpResult(-1, null, false))
        }

        assertFalse(h.aMgr.sendGroupText("b", GI_GROUP_ID, "hash", "dropped"))

        val posts = h.aHttp.calls.filter { it.method == "POST" }
        assertTrue(posts.all { it.url.endsWith("/inbox/$GI_GRP") }, "a transport drop must not fall back to the text inbox")
    }

    // --- The owned-read-direction coupling ----------------------------------

    @Test
    fun ownedReadDirections_carryTheGroupInbox_andSoDoEverythingDrivenByIt() {
        assertTrue(
            MessageManager.DIR_INBOUND_GRP in MessageManager.OWNED_READ_DIRECTIONS,
            "omitting it is the single worst mistake available here: the group inbox would be " +
                "the one drain/delete/rotate capability an imaged vault yields forever",
        )
        // The cap-pending marker holds a LIVE capability candidate and rides the
        // trailing map in the shared purge list both actuals iterate.
        assertTrue(
            MessageManager.capPendingKey("abc", MessageManager.DIR_INBOUND_GRP)
                in ratchetMetaKeysForContact("abc"),
        )
    }

    @Test
    fun deleteContact_purgesTheGroupInboxRow_andItsPendingCapMarker() {
        val vault = InMemoryVault()
        vault.insertContact(ContactRecord("gone", generateSecureRandom(32), 1, "T", 0L))
        vault.insertInboxId(
            InboxIdRecord(GI_GRP, "gone", 1L, Long.MAX_VALUE, MessageManager.DIR_INBOUND_GRP, GI_CAP)
        )
        val pend = MessageManager.capPendingKey("gone", MessageManager.DIR_INBOUND_GRP)
        vault.putMeta(pend, GI_CAP2)

        vault.deleteContact("gone")

        assertNull(vault.getInboxIdForContact("gone", MessageManager.DIR_INBOUND_GRP))
        assertNull(vault.getMeta(pend), "a live capability candidate must never outlive the contact")
    }

    @Test
    fun theGroupInbox_isOnThePushWakeSurface() {
        // A group text used to wake the device through the sender's TEXT inbox and
        // now arrives here instead; leaving it off would silently make every group
        // message unable to wake a sleeping device.
        val vault = InMemoryVault()
        vault.insertContact(ContactRecord("carol", generateSecureRandom(32), 0, "Carol", 0L))
        vault.insertInboxId(InboxIdRecord(GI_MAIN, "carol", 1L, Long.MAX_VALUE, "inbound", GI_CAP))
        vault.insertInboxId(InboxIdRecord(GI_CTL, "carol", 1L, Long.MAX_VALUE, MessageManager.DIR_INBOUND_CTL, GI_CAP))
        vault.insertInboxId(InboxIdRecord(GI_GRP, "carol", 1L, Long.MAX_VALUE, MessageManager.DIR_INBOUND_GRP, GI_CAP2))

        val refs = allPushableInboxes(vault)
        assertEquals(setOf(GI_MAIN, GI_CTL, GI_GRP), refs.map { it.inboxId }.toSet())
        assertEquals(GI_CAP2, refs.single { it.inboxId == GI_GRP }.readCap, "each ref carries THAT inbox's own cap")
        // The text-only surface is unchanged — it still means "where 1:1 messages arrive".
        assertEquals(listOf(GI_MAIN), allInboundTextInboxes(vault).map { it.inboxId })
    }
}

// ---------------------------------------------------------------------------
// The carriers: the in-band announce, the QR/paste payload, the referral accept.
// ---------------------------------------------------------------------------

class GroupInboxAnnounceTest {

    /** A announces to B, B drains its control inbox. */
    private fun announceAndApply(h: GrpHarness, send: () -> Boolean): Boolean {
        h.ok()
        val sent = send()
        if (!sent) return false
        h.serveB(h.lastBlobB64())
        h.bMgr.pollControlMessages("a")
        return true
    }

    @Test
    fun fullAnnounce_appliesAllThreePairs() {
        if (!aeadUp()) return
        val h = GrpHarness()
        assertTrue(
            announceAndApply(h) {
                h.aMgr.sendInboxAnnounce("b", GI_A_IN_MAIN, GI_CAP2, GI_A_IN_CTL, GI_CAP2, GI_A_IN_GRP, GI_CAP2)
            }
        )

        assertEquals(GI_A_IN_MAIN, h.bVault.getInboxIdForContact("a", "outbound")?.inboxId)
        assertEquals(GI_A_IN_CTL, h.bVault.getInboxIdForContact("a", MessageManager.DIR_OUTBOUND_CTL)?.inboxId)
        val grp = h.bVault.getInboxIdForContact("a", MessageManager.DIR_OUTBOUND_GRP)
        assertEquals(GI_A_IN_GRP, grp?.inboxId)
        assertEquals(GI_CAP2, grp?.cap)
    }

    @Test
    fun groupOnlyAnnounce_applies() {
        if (!aeadUp()) return
        // THE mandatory relaxation: our own inbound WRITE cap is never persisted, so
        // a later announce (the backfill, the 404 re-mint) physically cannot re-state
        // `wc` — it can only state `gwc`.
        val h = GrpHarness()
        assertTrue(
            announceAndApply(h) {
                h.aMgr.sendInboxAnnounce("b", null, null, null, null, GI_A_IN_GRP, GI_CAP2)
            }
        )

        assertEquals(GI_A_IN_GRP, h.bVault.getInboxIdForContact("a", MessageManager.DIR_OUTBOUND_GRP)?.inboxId)
        assertNull(h.bVault.getInboxIdForContact("a", "outbound"), "a group-only announce writes ONLY the group row")
        assertNull(h.bVault.getInboxIdForContact("a", MessageManager.DIR_OUTBOUND_CTL))
    }

    @Test
    fun legacyTextOnlyAnnounce_stillApplies_andLeavesTheGroupRowAbsent() {
        if (!aeadUp()) return
        val h = GrpHarness()
        assertTrue(announceAndApply(h) { h.aMgr.sendInboxAnnounce("b", GI_A_IN_MAIN, GI_CAP2) })

        assertEquals(GI_A_IN_MAIN, h.bVault.getInboxIdForContact("a", "outbound")?.inboxId)
        assertNull(
            h.bVault.getInboxIdForContact("a", MessageManager.DIR_OUTBOUND_GRP),
            "an old build's announce leaves the group row absent — the fallback, never a refusal",
        )
    }

    @Test
    fun announceWithNoCompletePair_isRefusedBeforeItTouchesTheRelay() {
        if (!aeadUp()) return
        val h = GrpHarness()
        assertFalse(h.aMgr.sendInboxAnnounce("b", null, null))
        assertTrue(h.aHttp.calls.isEmpty())
        // A half-present pair is refused too.
        assertFalse(h.aMgr.sendInboxAnnounce("b", GI_A_IN_MAIN, null))
        assertFalse(h.aMgr.sendInboxAnnounce("b", null, null, null, null, GI_A_IN_GRP, null))
        assertTrue(h.aHttp.calls.isEmpty())
    }

    @Test
    fun announceNamingOneIdTwice_isRejectedAsOneBatch_withNothingWritten() {
        if (!aeadUp()) return
        // `gib == ib` would have the two inserts collide on one primary key. The
        // claims are checked as ONE batch, so the WHOLE announce is dropped.
        val h = GrpHarness()
        assertTrue(
            announceAndApply(h) {
                h.aMgr.sendInboxAnnounce("b", GI_A_IN_MAIN, GI_CAP2, GI_A_IN_CTL, GI_CAP2, GI_A_IN_MAIN, GI_CAP2)
            }
        )

        assertNull(h.bVault.getInboxIdForContact("a", "outbound"), "nothing may be written")
        assertNull(h.bVault.getInboxIdForContact("a", MessageManager.DIR_OUTBOUND_CTL))
        assertNull(h.bVault.getInboxIdForContact("a", MessageManager.DIR_OUTBOUND_GRP))
    }

    @Test
    fun announceNamingOneOfOurOwnInboundInboxes_asTheGroupInbox_isRejected() {
        if (!aeadUp()) return
        // A relay reflecting our own announce back at us, or a peer eclipsing one of
        // our rows: the ownership gate covers the third id exactly as the first two.
        val h = GrpHarness()
        assertTrue(
            announceAndApply(h) {
                h.aMgr.sendInboxAnnounce("b", GI_A_IN_MAIN, GI_CAP2, GI_A_IN_CTL, GI_CAP2, GI_GRP, GI_CAP2)
            }
        )

        assertNull(h.bVault.getInboxIdForContact("a", MessageManager.DIR_OUTBOUND_GRP))
        assertNull(h.bVault.getInboxIdForContact("a", "outbound"), "rejected as ONE batch")
        assertEquals(
            MessageManager.DIR_INBOUND_GRP,
            h.bVault.getInboxId(GI_GRP)?.direction,
            "our own inbound group row must be untouched",
        )
    }

    @Test
    fun malformedGroupPair_dropsTheWholeAnnounce() {
        if (!aeadUp()) return
        val h = GrpHarness()
        h.ok()
        // Hand-built body: a `gib` of the wrong shape alongside a valid text pair.
        val body = """{"ib":"$GI_A_IN_MAIN","wc":"$GI_CAP2","gib":"too-short","gwc":"$GI_CAP2"}"""
        val blob = giSeal(
            h.shared,
            """{"e":"${h.epoch}","c":1,"t":0,"ch":"${MessageManager.CHANNEL_TAG_CTL}","di":"$GI_CTL","k":"${MessageManager.CONTROL_KIND_INBOX}","b":${jsonEscapeString(body)},"m":""}""",
        )
        h.serveB(blob)
        h.bMgr.pollControlMessages("a")

        assertNull(h.bVault.getInboxIdForContact("a", "outbound"), "a malformed pair drops the announce WHOLE")
        assertNull(h.bVault.getInboxIdForContact("a", MessageManager.DIR_OUTBOUND_GRP))
    }
}

class GroupInboxPairingPayloadTest {

    private val secret = encodeBase64(ByteArray(32) { it.toByte() })

    @Test
    fun fullCode_withTheGroupPair_roundTrips() {
        val raw = PairingPayload.buildFull(
            inboxId = GI_MAIN, writeCap = GI_CAP, ctlInboxId = GI_CTL, ctlWriteCap = GI_CAP,
            secretB64 = secret, grpInboxId = GI_GRP, grpWriteCap = GI_CAP2,
        )
        val scan = PairingPayload.parse(raw, myInboxId = null, mySecretB64 = null, requireFull = true)
        assertNotNull(scan)
        assertEquals(GI_MAIN, scan.inboxId)
        assertEquals(GI_CTL, scan.ctlInboxId)
        assertEquals(GI_GRP, scan.grpInboxId)
        assertEquals(GI_CAP2, scan.grpWriteCap)
        assertTrue(scan.roleRuleV2, "rv must stay LAST and keep parsing")
    }

    @Test
    fun legacyCode_withoutTheGroupPair_parsesToNull_notAFailure() {
        val raw = PairingPayload.buildFull(
            inboxId = GI_MAIN, writeCap = GI_CAP, ctlInboxId = GI_CTL, ctlWriteCap = GI_CAP,
            secretB64 = secret,
        )
        assertFalse(raw.contains("gib"), "an un-wired build must emit the byte-identical old code")
        val scan = PairingPayload.parse(raw, myInboxId = null, mySecretB64 = null, requireFull = true)
        assertNotNull(scan)
        assertNull(scan.grpInboxId)
        assertNull(scan.grpWriteCap)
    }

    @Test
    fun groupPair_mustBeBothOrNeither_wellShaped_andDistinct() {
        fun parse(json: String) = PairingPayload.parse(json, null, null, requireFull = true)
        val head = """{"inbox":"$GI_MAIN","wcap":"$GI_CAP","cib":"$GI_CTL","cwcap":"$GI_CAP","""
        assertNull(parse(head + """"gib":"$GI_GRP","secret":"$secret"}"""), "half-present")
        assertNull(parse(head + """"gwcap":"$GI_CAP2","secret":"$secret"}"""), "half-present")
        assertNull(parse(head + """"gib":"nope","gwcap":"$GI_CAP2","secret":"$secret"}"""), "malformed id")
        assertNull(parse(head + """"gib":"$GI_GRP","gwcap":"short","secret":"$secret"}"""), "malformed cap")
        assertNull(parse(head + """"gib":"$GI_MAIN","gwcap":"$GI_CAP2","secret":"$secret"}"""), "gib == inbox")
        assertNull(parse(head + """"gib":"$GI_CTL","gwcap":"$GI_CAP2","secret":"$secret"}"""), "gib == cib")
        assertNotNull(parse(head + """"gib":"$GI_GRP","gwcap":"$GI_CAP2","secret":"$secret"}"""))
    }

    @Test
    fun groupPairOnASecretOnlyCode_isMalformed() {
        assertNull(
            PairingPayload.parse(
                """{"gib":"$GI_GRP","gwcap":"$GI_CAP2","secret":"$secret"}""",
                null, null, requireFull = false,
            ),
            "a group pair with no message inbox is malformed, exactly like a ctl pair",
        )
    }
}

class GroupInboxPairingVaultTest {

    @Test
    fun savePairedContact_writesBothGroupRows_whenTheyArePresent() {
        val vault = InMemoryVault()
        PairingVault.savePairedContact(
            vault = vault, contactId = "c", sharedSecret = ByteArray(32) { 1 },
            peerInboxId = GI_MAIN, peerWriteCap = GI_CAP,
            peerCtlInboxId = GI_CTL, peerCtlWriteCap = GI_CAP,
            myInboxId = GI_A_IN_MAIN, myReadCap = GI_CAP2,
            myCtlInboxId = GI_A_IN_CTL, myCtlReadCap = GI_CAP2,
            alias = "A",
            peerGrpInboxId = GI_GRP, peerGrpWriteCap = GI_CAP,
            myGrpInboxId = GI_A_IN_GRP, myGrpReadCap = GI_CAP2,
        )

        val out = vault.getInboxIdForContact("c", MessageManager.DIR_OUTBOUND_GRP)
        assertEquals(GI_GRP, out?.inboxId); assertEquals(GI_CAP, out?.cap)
        val inb = vault.getInboxIdForContact("c", MessageManager.DIR_INBOUND_GRP)
        assertEquals(GI_A_IN_GRP, inb?.inboxId); assertEquals(GI_CAP2, inb?.cap)
    }

    @Test
    fun savePairedContact_withoutTheGroupPair_writesNoGroupRow_andStillPairs() {
        val vault = InMemoryVault()
        PairingVault.savePairedContact(
            vault = vault, contactId = "c", sharedSecret = ByteArray(32) { 1 },
            peerInboxId = GI_MAIN, peerWriteCap = GI_CAP,
            peerCtlInboxId = GI_CTL, peerCtlWriteCap = GI_CAP,
            myInboxId = GI_A_IN_MAIN, myReadCap = GI_CAP2,
            myCtlInboxId = GI_A_IN_CTL, myCtlReadCap = GI_CAP2,
            alias = "A",
        )

        assertNotNull(vault.getContact("c"))
        assertNull(vault.getInboxIdForContact("c", MessageManager.DIR_OUTBOUND_GRP))
        assertNull(vault.getInboxIdForContact("c", MessageManager.DIR_INBOUND_GRP))
    }
}

class GroupInboxReferralCarrierTest {

    private fun minted(withGrp: Boolean) = MintedInboxPair(
        MintedInbox(GI_MAIN, GI_CAP, GI_CAP2, 1L),
        MintedInbox(GI_CTL, GI_CAP, GI_CAP2, 1L),
        if (withGrp) MintedInbox(GI_GRP, GI_CAP, GI_CAP2, 1L) else null,
    )

    /** The PRODUCTION builder, so the emitted bytes are what is pinned. */
    private fun body(withGrp: Boolean): String =
        ReferralManager(InMemoryVault()) { null }
            .acceptBody("intro-1", ByteArray(32) { 2 }, minted(withGrp))

    @Test
    fun acceptBody_carriesTheGroupPair_whenOneWasMinted() {
        val b = body(withGrp = true)
        assertEquals(GI_GRP, firstStringFieldAnywhere(b, "gib"))
        assertEquals(GI_CAP2, firstStringFieldAnywhere(b, "gwc"))
        assertTrue(b.endsWith(""""$ROLE_RULE_FIELD":"$ROLE_RULE_V2"}"""), "rv stays LAST")
    }

    @Test
    fun acceptBody_omitsItEntirely_forAStoredAcceptMintedBeforeTheGroupInbox() {
        val b = body(withGrp = false)
        assertNull(firstStringFieldAnywhere(b, "gib"))
        assertNull(firstStringFieldAnywhere(b, "gwc"))
        assertEquals(GI_MAIN, firstStringFieldAnywhere(b, "ib"), "the rest of the body is unchanged")
    }

    @Test
    fun storedAccept_roundTripsTheGroupInbox_andALegacyRecordStillDecodes() {
        val rec = StoredAccept(
            introducerContactId = "intro", peerAlias = "P",
            privateKey = ByteArray(32) { 3 }, publicKey = ByteArray(32) { 4 },
            minted = minted(withGrp = true), sent = true, attempts = 1, createdAt = 5L,
        )
        val decoded = decodeStoredAccept(encodeStoredAccept(rec))
        assertNotNull(decoded)
        assertEquals(GI_GRP, decoded.minted.grp?.inboxId)
        assertEquals(GI_CAP, decoded.minted.grp?.readCapability)

        // A record written before the group inbox existed is a LIVE handshake and
        // must migrate on read, never be GC'd.
        val legacy = encodeStoredAccept(rec.let {
            StoredAccept(
                it.introducerContactId, it.peerAlias, it.privateKey, it.publicKey,
                minted(withGrp = false), it.sent, it.attempts, it.createdAt,
            )
        })
        assertFalse(legacy.contains("\"gi\""))
        val legacyDecoded = decodeStoredAccept(legacy)
        assertNotNull(legacyDecoded)
        assertNull(legacyDecoded.minted.grp)
        assertEquals(GI_MAIN, legacyDecoded.minted.main.inboxId)
    }
}

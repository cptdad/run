package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// Characterisation of the drain (`finishDrainCoreHoldingSecret`): what each phase
// does TODAY, pinned through the one observable a split can silently break — the
// per-blob outcome as it reaches `POST /ack` (acked = ACCEPTED / REJECTED /
// DEFERRED; absent = NOT_PROCESSED, re-delivered after the lease) — plus the
// counters, latches and the deferral store the phase writes.
//
// Every crypto test opens with `if (!legacyEnvelopeCryptoUp()) return` (the iOS
// simulator test run has no AES bridge).
// ---------------------------------------------------------------------------

private val DC_MAIN = "DCmainIN".padEnd(32, 'n')
private val DC_CTL = "DCctlIN".padEnd(32, 'n')
private val DC_GRP = "DCgrpIN".padEnd(32, 'n')
private val DC_OUT = "DCmainOUT".padEnd(32, 't')
private val DC_CAP = "C".repeat(43)
private val DC_GID = "Q".repeat(32)

private var dcSeq = 0

// Receiver of one pairing over a [LeasingRelay]: inbound MAIN + CTL + GRP rows, and
// (unless [withOutbound] is false) our outbound TEXT row. A fresh contact id per
// instance, because the uncommitted-legacy registry is process-wide.
private class Rx(ctlInboxId: String = DC_CTL, withOutbound: Boolean = true) {
    val cid = "dc-${++dcSeq}"
    val secret = generateSecureRandom(32)
    val vault = InMemoryVault()
    val relay = LeasingRelay()
    val mgr = MessageManager(vault, "http://relay.test", relay).syncAcks()
    val epoch = legacyEpochFor(secret)

    init {
        vault.insertContact(ContactRecord(cid, secret, 0, "A", 0L))
        vault.insertInboxId(InboxIdRecord(DC_MAIN, cid, 1L, Long.MAX_VALUE, "inbound", DC_CAP))
        vault.insertInboxId(InboxIdRecord(ctlInboxId, cid, 1L, Long.MAX_VALUE, MessageManager.DIR_INBOUND_CTL, DC_CAP))
        vault.insertInboxId(InboxIdRecord(DC_GRP, cid, 1L, Long.MAX_VALUE, MessageManager.DIR_INBOUND_GRP, DC_CAP))
        if (withOutbound) vault.insertInboxId(InboxIdRecord(DC_OUT, cid, 1L, Long.MAX_VALUE, "outbound", DC_CAP))
    }

    // A legacy envelope; [ch] / [di] null = the field is absent.
    fun env(
        c: Long,
        text: String = "x",
        ch: String? = MessageManager.CHANNEL_TAG_MAIN,
        di: String? = DC_MAIN,
        extra: String = "",
        epochTag: String = epoch,
    ): String {
        val chField = ch?.let { ""","ch":"$it"""" } ?: ""
        val diField = di?.let { ""","di":"$it"""" } ?: ""
        return """{"e":"$epochTag","c":$c,"t":0$chField$diField$extra,"m":"$text"}"""
    }

    fun deliver(inboxId: String, envelopeJson: String): String =
        relay.deliver(inboxId, sealLegacyEnvelopeBytes(secret, envelopeJson))

    fun contact(): ContactRecord = vault.getContact(cid)!!
}

// The delete ids of every `POST /ack` a [FakeRelayHttp] saw, in order.
private fun FakeRelayHttp.ackDeletes(): List<String> =
    requestsOf("POST").filter { it.url.endsWith("/ack") }.flatMap { r ->
        parseObjectArrayField(r.body.decodeToString(), "items", 64)!!.flatMap { parseStringArrayField(it, "delete")!! }
    }

private fun FakeRelayHttp.ackPostCount(): Int = requestsOf("POST").count { it.url.endsWith("/ack") }

// A receiver over a plain [FakeRelayHttp] (scripted answers), MAIN inbound only.
private class ScriptedRx(onGet: (FakeRelayHttp.Request) -> HttpResult) {
    val cid = "dcs-${++dcSeq}"
    val secret = generateSecureRandom(32)
    val vault = InMemoryVault()
    val relay = FakeRelayHttp(onGet = onGet, onPost = { HttpResult(200, """{"v":1,"results":[]}""", true) })
    val mgr = MessageManager(vault, "http://relay.test", relay).syncAcks()

    init {
        vault.insertContact(ContactRecord(cid, secret, 0, "A", 0L))
        vault.insertInboxId(InboxIdRecord(DC_MAIN, cid, 1L, Long.MAX_VALUE, "inbound", DC_CAP))
    }
}

class DrainCharacterisationTest {

    // --- Phase A: status and parse ------------------------------------------

    // A1: a non-2xx (or a 2xx with no body / an unparseable one) yields nothing, acks
    // nothing and writes no baseline.
    @Test
    fun nonSuccessAnswers_returnEmpty_ackNothing_andWriteNoBaseline() {
        val answers = listOf(
            HttpResult(404, """{"error":"request rejected"}""", false),
            HttpResult(429, "", false),
            HttpResult(500, "", false),
            HttpResult(200, null, true),
            HttpResult(200, """{"blobs":"x"}""", true),
        )
        for (answer in answers) {
            val rx = ScriptedRx { answer }
            assertTrue(rx.mgr.pollMessages(rx.cid).isEmpty(), "code ${answer.code}")
            assertEquals(0, rx.relay.ackPostCount(), "code ${answer.code}: nothing to ack")
            assertEquals(0L, rx.vault.getContact(rx.cid)!!.inboundCounter, "code ${answer.code}")
        }
    }

    // A1: 429, 500 and a body-less 200 neither break nor extend the 404 streak — they
    // return before the health bookkeeping.
    @Test
    fun transientAnswers_doNotResetThe404Streak() {
        var answer = HttpResult(404, "", false)
        val rx = ScriptedRx { answer }
        var clock = 0L
        rx.mgr.relayLostClockMs = { clock }
        repeat(rx.mgr.RELAY_LOST_404_STREAK - 1) { rx.mgr.pollMessages(rx.cid) }
        for (a in listOf(HttpResult(429, "", false), HttpResult(500, "", false), HttpResult(200, null, true))) {
            answer = a
            rx.mgr.pollMessages(rx.cid)
        }
        answer = HttpResult(404, "", false)
        clock = rx.mgr.RELAY_LOST_MIN_WINDOW_MS
        rx.mgr.pollMessages(rx.cid)
        assertTrue(rx.cid in rx.mgr.relayLostContacts(), "the streak survived the transient answers")
    }

    // A1b: an UNPARSEABLE 2xx still proves the inbox alive — the health bookkeeping
    // runs before the parse — so it clears the 404 streak and re-stamps the row.
    @Test
    fun unparseable2xx_clearsThe404Streak_andRestampsTheInboxLease() {
        var answer = HttpResult(404, "", false)
        val rx = ScriptedRx { answer }
        rx.vault.insertInboxId(InboxIdRecord(DC_MAIN, rx.cid, 1L, 1L, "inbound", DC_CAP))
        var clock = 0L
        rx.mgr.relayLostClockMs = { clock }
        repeat(rx.mgr.RELAY_LOST_404_STREAK - 1) { rx.mgr.pollMessages(rx.cid) }
        assertEquals(1L, rx.vault.getInboxIdForContact(rx.cid, "inbound")!!.expiresAt, "a 404 never re-stamps")
        answer = HttpResult(200, """{"blobs":"x"}""", true)
        assertTrue(rx.mgr.pollMessages(rx.cid).isEmpty())
        assertTrue(rx.vault.getInboxIdForContact(rx.cid, "inbound")!!.expiresAt > 1L, "the 2xx re-stamped the lease")
        answer = HttpResult(404, "", false)
        clock = rx.mgr.RELAY_LOST_MIN_WINDOW_MS
        repeat(rx.mgr.RELAY_LOST_404_STREAK - 1) { rx.mgr.pollMessages(rx.cid) }
        assertFalse(rx.cid in rx.mgr.relayLostContacts(), "the unparseable 2xx restarted the streak")
    }

    // --- Phase B: split + receive lock + legacy hold ------------------------

    // B1: a blob that is not base64 is REJECTED (acked) and the poll goes on.
    @Test
    fun malformedBase64Blob_isRejectedAndAcked_theNextBlobStillLands() {
        if (!legacyEnvelopeCryptoUp()) return
        val idBad = "i1".padEnd(22, 'q')
        val idGood = "i2".padEnd(22, 'q')
        val token = "t".repeat(22)
        var body = ""
        val rx = ScriptedRx { HttpResult(200, body, true) }
        val good = sealLegacyEnvelope(
            rx.secret,
            """{"e":"${legacyEpochFor(rx.secret)}","c":1,"t":0,"ch":"m","di":"$DC_MAIN","m":"ok"}""",
        )
        body = """{"blobs":["!!notb64!!","$good"],"ids":["$idBad","$idGood"],"token":"$token"}"""
        assertEquals(listOf("ok"), rx.mgr.pollMessages(rx.cid).map { it.text })
        assertEquals(setOf(idBad, idGood), rx.relay.ackDeletes().toSet())
        assertEquals(1L, rx.vault.getContact(rx.cid)!!.inboundCounter)
    }

    // B2: once the text lock is armed (no grace owed), a static-key text is REJECTED —
    // acked, nothing surfaced, the baseline untouched.
    @Test
    fun recvLocked_legacyText_isRejectedAcked_andTheCounterUntouched() {
        if (!legacyEnvelopeCryptoUp()) return
        val h = LaHarness(ratchet = true)
        val base = h.textBaseline()
        val forged = sealLegacyEnvelopeBytes(
            h.secret,
            """{"e":"${legacyEpochFor(h.secret)}","c":${base + 1},"t":0,"ch":"m","di":"$LA_IN_A","m":"forged"}""",
        )
        val id = h.relay.deliver(LA_IN_A, forged)
        assertTrue(h.aliceMgr.pollMessages(LA).isEmpty())
        assertTrue(id in h.relay.ackedIds(LA_IN_A), "a receive-lock drop is a final refusal: acked")
        assertEquals(base, h.textBaseline())
    }

    // B3: a PERSISTING drain over a channel whose legacy advance a screen holds
    // uncommitted leaves its own legacy blobs NOT_PROCESSED (released at once by the
    // empty ack, never deleted); they land after the screen commits.
    @Test
    fun legacyHeldByAnUncommittedScreenDrain_isNotProcessedByAPersistingDrain() {
        if (!legacyEnvelopeCryptoUp()) return
        val h = LaHarness(ratchet = false)
        assertTrue(h.bobMgr.sendMessage(LA, "L1"))
        val pd = h.aliceMgr.pollMessagesPending(LA)
        assertEquals(listOf("L1"), pd.messages.map { it.text })
        assertTrue(h.bobMgr.sendMessage(LA, "L2"))
        val l2 = h.relay.idsOf(LA_IN_A).last()
        assertTrue(h.aliceMgr.pollMessages(LA).isEmpty(), "held behind the uncommitted screen drain")
        assertFalse(l2 in h.relay.ackedIds(LA_IN_A), "a held legacy blob is never deleted")
        pd.commit()
        assertEquals(listOf("L2"), h.aliceMgr.pollMessages(LA).map { it.text })
        assertEquals(0, h.relay.total(LA_IN_A))
    }

    // --- Phase C + the missing-text-row rule (B1 of the review) ---------------

    // The contact is there but its outbound TEXT row is not: the ratchet has no role
    // inputs, so every fresh ratchet wire is NOT_PROCESSED — not acked, released at
    // once — and it decrypts on the first drain after the row is back.
    @Test
    fun ratchetWires_withTheTextRowMissing_areNotAcked_andLandOnceTheRowIsBack() {
        if (!legacyEnvelopeCryptoUp()) return
        val h = LaHarness(ratchet = true)
        h.alice.inboxes.removeAll { it.contactId == LA && it.direction == "outbound" }
        assertTrue(h.bobMgr.sendMessage(LA, "kept"))
        val id = h.relay.idsOf(LA_IN_A).single()
        val unackedBefore = h.aliceMgr.ratchetUnackedCount(LA)
        assertTrue(h.aliceMgr.pollMessages(LA).isEmpty())
        assertFalse(id in h.relay.ackedIds(LA_IN_A), "a wire nobody could decrypt is not deleted")
        assertEquals(1, h.relay.visible(LA_IN_A), "released by the ack, not held for the lease")
        assertEquals(unackedBefore, h.aliceMgr.ratchetUnackedCount(LA), "a drain that looked at nothing is no evidence")
        h.alice.insertInboxId(InboxIdRecord(LA_IN_B, LA, 0L, Long.MAX_VALUE, "outbound", LA_WCAP_B))
        assertEquals(listOf("kept"), h.aliceMgr.pollMessages(LA).map { it.text })
        assertTrue(id in h.relay.ackedIds(LA_IN_A))
        assertEquals(0, h.relay.total(LA_IN_A))
    }

    // The contact was DELETED while the drain was in flight: its ratchet wires are
    // REJECTED and acked (nothing will ever drain this inbox again), and nothing about
    // the contact is resurrected — no row, no dr-rxseen.
    @Test
    fun ratchetWires_ofAContactDeletedMidDrain_areAcked_andNothingIsResurrected() {
        if (!legacyEnvelopeCryptoUp()) return
        val h = LaHarness(ratchet = true)
        assertTrue(h.bobMgr.sendMessage(LA, "too late"))
        val id = h.relay.idsOf(LA_IN_A).single()
        h.relay.beforeGet = { url -> if ("/inbox/$LA_IN_A?" in url) h.alice.deleteContact(LA) }
        assertTrue(h.aliceMgr.pollMessages(LA).isEmpty())
        h.relay.beforeGet = null
        assertTrue(id in h.relay.ackedIds(LA_IN_A), "a deleted contact's wires are acked")
        assertNull(h.alice.getContact(LA), "the contact row is not resurrected")
        assertNull(h.alice.getMeta(MessageManager.drRxSeenKey(LA)), "no dr-rxseen for a deleted contact")
    }

    // C1: stored deferrals the batch did not process are RE-STORED with their original
    // stamps and hold ages (here: none can be processed, the text row is missing), so
    // the store reads back byte-identical.
    @Test
    fun storedDeferrals_notProcessed_areReStoredWithTheirOriginalStamps() {
        val rx = Rx(withOutbound = false)
        val now = currentTimeMillis()
        val raw = (0 until 9).joinToString(",") { i ->
            "${now - 1000 + i}:${MessageManager.CTL_DEFER_SHORT_AGE_MS}:${encodeBase64(generateSecureRandom(80))}"
        }
        rx.vault.putMeta(MessageManager.drCtlDeferredKey(rx.cid), raw)
        assertTrue(rx.mgr.pollControlMessages(rx.cid).isEmpty())
        assertEquals(raw, rx.vault.getMeta(MessageManager.drCtlDeferredKey(rx.cid)), "kept as stored, stamps included")
    }

    // C2 (BACKLOG): a sealed control wire drained ahead of a > 128-text backlog is
    // DEFERRED — acked (the vault copy is the one retried) and stored with the 24 h
    // hold, because unread texts are positively waiting.
    @Test
    fun backlogDeferral_isAcked_andStoredWithTheLongHold() {
        if (!legacyEnvelopeCryptoUp()) return
        val h = LaHarness(ratchet = true)
        repeat(DoubleRatchet.MAX_SKIPPED_STORE + 2) { assertTrue(h.bobMgr.sendMessage(LA, "u$it")) }
        assertTrue(h.bobMgr.sendGroupControl(LA, LA_GID, GroupManager.KIND_ROSTER, LA_ROSTER, LA_HASH, noPush = true))
        val rosterId = h.relay.idsOf(LA_CTL_A).single()
        assertTrue(MessageManager.isRatchetWire(h.relay.blobsOf(LA_CTL_A).single()), "precondition: the roster is sealed")
        assertTrue(h.aliceMgr.pollControlMessages(LA).isEmpty(), "deferred, not decrypted")
        assertTrue(rosterId in h.relay.ackedIds(LA_CTL_A), "a DEFERRED wire is acked")
        assertEquals(0, h.relay.total(LA_CTL_A))
        val stored = assertNotNull(h.alice.getMeta(MessageManager.drCtlDeferredKey(LA)))
        assertEquals(MessageManager.CTL_DEFER_MAX_AGE_MS.toString(), stored.split(':')[1])
    }

    // C2 (OLD_CHAIN): a control-only hop that would DH-step past the chain holding two
    // unread texts is DEFERRED with the SHORT hold, and acked.
    @Test
    fun oldChainDeferral_isAcked_andStoredWithTheShortHold() {
        if (!legacyEnvelopeCryptoUp()) return
        val h = LaHarness(ratchet = true)
        assertTrue(h.bobMgr.sendMessage(LA, "unread-1"))
        assertTrue(h.bobMgr.sendMessage(LA, "unread-2"))
        assertTrue(h.bobMgr.sendGroupControl(LA, LA_GID, GroupManager.KIND_INVITE, """{"n":"crew"}""", LA_HASH, noPush = true))
        assertEquals(listOf(GroupManager.KIND_INVITE), h.aliceMgr.pollControlMessages(LA).map { it.controlKind })
        assertTrue(h.aliceMgr.sendGroupControl(LA, LA_GID, GroupManager.KIND_JOIN, """{"tags":""}""", LA_HASH, noPush = true))
        assertEquals(listOf(GroupManager.KIND_JOIN), h.bobMgr.pollControlMessages(LA).map { it.controlKind })
        assertTrue(h.bobMgr.sendGroupControl(LA, LA_GID, GroupManager.KIND_ROSTER, LA_ROSTER, LA_HASH, noPush = true))
        assertEquals(listOf(GroupManager.KIND_ROSTER), h.aliceMgr.pollControlMessages(LA).map { it.controlKind })
        assertTrue(h.aliceMgr.sendGroupControl(LA, LA_GID, GroupManager.KIND_LEAVE, "{}", LA_HASH, noPush = true))
        assertEquals(listOf(GroupManager.KIND_LEAVE), h.bobMgr.pollControlMessages(LA).map { it.controlKind })
        val roster2 = """{"n":"crew","ep":3,"adm":"m1","mem":[]}"""
        assertTrue(h.bobMgr.sendGroupControl(LA, LA_GID, GroupManager.KIND_ROSTER, roster2, LA_HASH, noPush = true))
        val roster2Id = h.relay.idsOf(LA_CTL_A).last()
        assertTrue(h.aliceMgr.pollControlMessages(LA).isEmpty(), "the second receiving step is deferred")
        assertTrue(roster2Id in h.relay.ackedIds(LA_CTL_A), "a DEFERRED wire is acked")
        assertEquals(
            MessageManager.CTL_DEFER_SHORT_AGE_MS.toString(),
            h.alice.getMeta(MessageManager.drCtlDeferredKey(LA))!!.split(':')[1],
        )
        assertEquals(listOf("unread-1", "unread-2"), h.aliceMgr.pollMessages(LA).map { it.text })
    }

    // C3: with both text-bearing inboxes peeking EMPTY the skipped key is dead, so the
    // would-be deferral is decrypted at once (the late decrypt): surfaced, ACCEPTED,
    // acked, and nothing is stored.
    @Test
    fun deadSkippedKeys_lateDecrypt_isAcceptedAndAcked_andNothingIsStored() {
        if (!legacyEnvelopeCryptoUp()) return
        val h = LaHarness(ratchet = true)
        assertTrue(h.bobMgr.sendMessage(LA, "lost"))
        h.relay.withhold(LA_IN_A, h.relay.idsOf(LA_IN_A).single())
        assertTrue(h.bobMgr.sendGroupControl(LA, LA_GID, GroupManager.KIND_INVITE, """{"n":"crew"}""", LA_HASH, noPush = true))
        assertEquals(listOf(GroupManager.KIND_INVITE), h.aliceMgr.pollControlMessages(LA).map { it.controlKind })
        assertTrue(h.aliceMgr.sendGroupControl(LA, LA_GID, GroupManager.KIND_JOIN, """{"tags":""}""", LA_HASH, noPush = true))
        h.bobMgr.pollControlMessages(LA)
        assertTrue(h.bobMgr.sendGroupControl(LA, LA_GID, GroupManager.KIND_ROSTER, LA_ROSTER, LA_HASH, noPush = true))
        assertEquals(listOf(GroupManager.KIND_ROSTER), h.aliceMgr.pollControlMessages(LA).map { it.controlKind })
        assertTrue(h.aliceMgr.sendGroupControl(LA, LA_GID, GroupManager.KIND_LEAVE, "{}", LA_HASH, noPush = true))
        h.bobMgr.pollControlMessages(LA)
        val roster2 = """{"n":"crew","ep":3,"adm":"m1","mem":[]}"""
        assertTrue(h.bobMgr.sendGroupControl(LA, LA_GID, GroupManager.KIND_ROSTER, roster2, LA_HASH, noPush = true))
        val roster2Id = h.relay.idsOf(LA_CTL_A).last()
        assertEquals(listOf(roster2), h.aliceMgr.pollControlMessages(LA).map { it.controlBody })
        assertTrue(roster2Id in h.relay.ackedIds(LA_CTL_A), "the late-decrypted wire is ACCEPTED: acked")
        assertNull(h.alice.getMeta(MessageManager.drCtlDeferredKey(LA)))
    }

    // C4 (rule 3): while a screen holds an uncommitted advance of the text ratchet, a
    // control drain neither loads nor rewrites the deferral store — byte-identical —
    // and leaves the text path's retry request in place; its fresh ratchet wire is
    // NOT_PROCESSED (not acked).
    @Test
    fun rule3ControlDrain_leavesTheDeferralStoreByteIdentical_andTheRetryRequestPending() {
        if (!legacyEnvelopeCryptoUp()) return
        val h = LaHarness(ratchet = true)
        val raw = "${currentTimeMillis()}:${MessageManager.CTL_DEFER_SHORT_AGE_MS}:${encodeBase64(generateSecureRandom(80))}"
        h.alice.putMeta(MessageManager.drCtlDeferredKey(LA), raw)
        assertTrue(h.bobMgr.sendMessage(LA, "t1"))
        val pd = h.aliceMgr.pollMessagesPending(LA)
        assertEquals(listOf("t1"), pd.messages.map { it.text })
        assertTrue(h.aliceMgr.sealedControlDrainDue(LA), "precondition: the text drain asked for a retry")
        assertTrue(h.bobMgr.sendDirectControl(LA, MessageManager.CONTROL_KIND_REFERRAL_ACCEPT, "{}"))
        val ctlId = h.relay.idsOf(LA_CTL_A).single()
        assertTrue(h.aliceMgr.pollControlMessages(LA).isEmpty())
        assertEquals(raw, h.alice.getMeta(MessageManager.drCtlDeferredKey(LA)), "not even loaded")
        assertTrue(h.aliceMgr.sealedControlDrainDue(LA), "the retry request is not consumed")
        assertFalse(ctlId in h.relay.ackedIds(LA_CTL_A), "the fresh wire is NOT_PROCESSED")
        pd.commit()
    }

    // --- Phase D: after the ratchet half ----------------------------------------

    // D1: a drain whose every blob was held (NOT_PROCESSED behind an uncommitted screen
    // advance) is not both-Alice evidence; the same drain with one blob it DID look
    // at (a junk blob, rejected) is.
    @Test
    fun aDrainWhoseEveryBlobWasHeld_isNotBothAliceEvidence() {
        if (!legacyEnvelopeCryptoUp()) return
        val h = LaHarness(ratchet = true)
        repeat(MessageManager.RATCHET_SENDS_BEFORE_UNACKED_EVIDENCE) { assertTrue(h.aliceMgr.sendMessage(LA, "q$it")) }
        assertTrue(h.bobMgr.sendMessage(LA, "t1"))
        val pd = h.aliceMgr.pollMessagesPending(LA)
        assertEquals(listOf("t1"), pd.messages.map { it.text })
        assertTrue(h.bobMgr.sendMessage(LA, "t2"))
        assertEquals(0, h.aliceMgr.ratchetUnackedCount(LA))
        assertTrue(h.aliceMgr.pollMessages(LA).isEmpty(), "held behind the uncommitted advance")
        assertEquals(0, h.aliceMgr.ratchetUnackedCount(LA), "a drain that looked at nothing is no evidence")
        h.relay.deliver(LA_IN_A, ByteArray(10))
        assertTrue(h.aliceMgr.pollMessages(LA).isEmpty())
        assertEquals(1, h.aliceMgr.ratchetUnackedCount(LA), "a looked-at blob with no decrypt is one piece of evidence")
        pd.abandon()
    }

    // D5: a PENDING drain consumes the control-armed text grace at COMMIT, not at
    // decrypt; an abandoned drain leaves it owed, and the re-delivery is accepted.
    @Test
    fun pendingDrain_consumesTheTextGraceAtCommit_notAtDecrypt() {
        if (!legacyEnvelopeCryptoUp()) return
        for (commit in listOf(true, false)) {
            val h = LaHarness(ratchet = false)
            MessageManager.markRatchetCapable(h.alice, LA)
            MessageManager.markRatchetCapable(h.bob, LA)
            assertTrue(h.aliceMgr.sendMessage(LA, "a0"))
            assertEquals(listOf("a0"), h.bobMgr.pollMessages(LA).map { it.text })
            assertTrue(h.bobMgr.sendMessage(LA, "b0"))
            assertEquals(listOf("b0"), h.aliceMgr.pollMessages(LA).map { it.text })
            assertTrue(h.aliceMgr.sendMessage(LA, "a1"))
            assertEquals(listOf("a1"), h.bobMgr.pollMessages(LA).map { it.text })
            h.relay.deliver(
                LA_IN_A,
                sealLegacyEnvelopeBytes(
                    h.secret,
                    """{"e":"${legacyEpochFor(h.secret)}","c":${h.textBaseline() + 1},"t":0,"ch":"m","di":"$LA_IN_A","m":"queued-legacy"}""",
                ),
            )
            assertTrue(h.bobMgr.sendGroupControl(LA, LA_GID, GroupManager.KIND_ROSTER, LA_ROSTER, LA_HASH, noPush = true))
            assertEquals(listOf(GroupManager.KIND_ROSTER), h.aliceMgr.pollControlMessages(LA).map { it.controlKind })
            assertEquals("1", h.alice.getMeta(MessageManager.drRecvLockKey(LA)), "precondition: armed from a control drain")
            val graceKey = MessageManager.drRecvLockGraceKey(LA)
            assertEquals("m,g", h.alice.getMeta(graceKey))
            val pd = h.aliceMgr.pollMessagesPending(LA)
            assertEquals(listOf("queued-legacy"), pd.messages.map { it.text })
            assertEquals("m,g", h.alice.getMeta(graceKey), "not consumed at decrypt")
            if (commit) {
                pd.commit()
                assertEquals("g", h.alice.getMeta(graceKey), "consumed at commit")
            } else {
                pd.abandon()
                assertEquals("m,g", h.alice.getMeta(graceKey), "an abandoned drain leaves it owed")
                assertEquals(listOf("queued-legacy"), h.aliceMgr.pollMessages(LA).map { it.text }, "the re-delivery is accepted")
                assertEquals("g", h.alice.getMeta(graceKey))
            }
        }
    }

    // --- Phase F: the sorted apply ------------------------------------------------

    // F2: a legacy inbox announce and a 1:1 screenshot notice on the TEXT inbox are
    // applied (row upserted / notice parked), never surfaced, and advance the counter
    // like the text behind them; all three are acked.
    @Test
    fun legacyAnnounce_andScreenshotNotice_advanceTheCounter_andAreAcked() {
        if (!legacyEnvelopeCryptoUp()) return
        val rx = Rx()
        val newOut = "DCannIB".padEnd(32, 'n')
        val ann = """{"ib":"$newOut","wc":"$DC_CAP"}"""
        val ids = listOf(
            rx.deliver(DC_MAIN, rx.env(1, extra = ""","k":"${MessageManager.CONTROL_KIND_INBOX}","b":${jsonEscapeString(ann)}""")),
            rx.deliver(DC_MAIN, rx.env(2, extra = ""","k":"${MessageManager.CONTROL_KIND_SCREENSHOT}","b":"{}"""")),
            rx.deliver(DC_MAIN, rx.env(3, text = "hello")),
        )
        assertEquals(listOf("hello"), rx.mgr.pollMessages(rx.cid).map { it.text })
        assertEquals(newOut, rx.vault.getInboxIdForContact(rx.cid, "outbound")!!.inboxId, "the announce was applied")
        assertEquals(1, rx.mgr.drainDirectScreenshotNotices().size, "the notice was parked")
        assertEquals(3L, rx.contact().inboundCounter)
        assertEquals(ids.toSet(), rx.relay.ackedIds(DC_MAIN).toSet())
    }

    // F3: on the control inbox of a mature peer that committed watermark W, a legacy
    // sealed kind above W is dropped WITHOUT advancing, and the chatty `act` behind it
    // lands and advances; both are acked.
    @Test
    fun watermarkDrop_doesNotAdvance_andTheGenuineBlobBehindItLands() {
        if (!legacyEnvelopeCryptoUp()) return
        val rx = Rx()
        val w = 3L
        rx.vault.putMeta(MessageManager.drRecvLockKey(rx.cid), "1")
        rx.vault.putMeta(MessageManager.drCtlWatermarkKey(rx.cid), w.toString())
        val sealedId = rx.deliver(DC_CTL, rx.env(w + 1, ch = "c", di = DC_CTL,
            extra = ""","k":"${MessageManager.CONTROL_KIND_REFERRAL_OFFER}","b":"{}""""))
        val actId = rx.deliver(DC_CTL, rx.env(w + 2, ch = "c", di = DC_CTL,
            extra = ""","g":"$DC_GID","h":"h","k":"${GroupManager.KIND_ACTIVITY}","b":"{}""""))
        assertEquals(listOf(GroupManager.KIND_ACTIVITY), rx.mgr.pollControlMessages(rx.cid).map { it.controlKind })
        assertEquals(w + 2, rx.contact().inboundCtlCounter)
        assertEquals(setOf(sealedId, actId), rx.relay.ackedIds(DC_CTL).toSet())
    }

    // --- Phase E: the legacy first pass ---------------------------------------

    private enum class Ch { MAIN, CTL, GRP }

    private class DropRow(
        val name: String,
        val ch: Ch,
        val ctlInboxId: String = DC_CTL,
        val setup: (Rx) -> Unit = {},
        val blob: (Rx) -> ByteArray,
    )

    private fun counterOf(rx: Rx, ch: Ch): Long = rx.contact().let {
        when (ch) { Ch.MAIN -> it.inboundCounter; Ch.CTL -> it.inboundCtlCounter; Ch.GRP -> it.inboundGrpCounter }
    }

    private fun inboxOf(ch: Ch, ctlInboxId: String) = when (ch) { Ch.MAIN -> DC_MAIN; Ch.CTL -> ctlInboxId; Ch.GRP -> DC_GRP }

    private fun poll(rx: Rx, ch: Ch): List<ReceivedMessage> = when (ch) {
        Ch.MAIN -> rx.mgr.pollMessages(rx.cid)
        Ch.CTL -> rx.mgr.pollControlMessages(rx.cid)
        Ch.GRP -> rx.mgr.pollGroupInbox(rx.cid)
    }

    private fun sealUnpadded(secret: ByteArray, json: String): ByteArray {
        val key = sha256(secret)
        return aesGcmEncrypt(json.encodeToByteArray(), key, sha256(key + "message-aead".encodeToByteArray()))
    }

    // E1: every drop class of the first pass is a final refusal — acked, nothing
    // surfaced, the channel's counter untouched.
    @Test
    fun legacyFirstPass_everyDropClass_isRejectedAcked_andAdvancesNothing() {
        if (!legacyEnvelopeCryptoUp()) return
        val ref = ""","k":"ref-offer","b":"{}""""
        val rows = listOf(
            DropRow("too short", Ch.MAIN) { generateSecureRandom(27) },
            DropRow("other secret", Ch.MAIN) { sealLegacyEnvelopeBytes(generateSecureRandom(32), it.env(1)) },
            DropRow("not padded", Ch.MAIN) { sealUnpadded(it.secret, it.env(1)) },
            DropRow("no counter / epoch", Ch.MAIN) { sealLegacyEnvelopeBytes(it.secret, """{"t":0,"m":"x"}""") },
            DropRow("stale epoch", Ch.MAIN) { sealLegacyEnvelopeBytes(it.secret, it.env(1, epochTag = "000000000000")) },
            DropRow("main-tagged on the control inbox", Ch.CTL, ctlInboxId = DC_MAIN) {
                sealLegacyEnvelopeBytes(it.secret, it.env(1, ch = "m", di = DC_MAIN, extra = ref))
            },
            DropRow("untagged from a tagging peer", Ch.MAIN,
                setup = { it.vault.putMeta(MessageManager.channelTagSeenKey(it.cid), "1") }) {
                sealLegacyEnvelopeBytes(it.secret, it.env(1, ch = null))
            },
            DropRow("di is our outbound", Ch.MAIN) { sealLegacyEnvelopeBytes(it.secret, it.env(1, di = DC_OUT)) },
            DropRow("di-less from a binding peer", Ch.MAIN,
                setup = { it.vault.putMeta(MessageManager.inboxBoundSeenKey(it.cid), "1") }) {
                sealLegacyEnvelopeBytes(it.secret, it.env(1, di = null))
            },
            DropRow("malformed group id", Ch.MAIN) {
                sealLegacyEnvelopeBytes(it.secret, it.env(1, extra = ""","g":"bad id","h":"h""""))
            },
            DropRow("17-char control kind", Ch.CTL) {
                sealLegacyEnvelopeBytes(it.secret, it.env(1, ch = "c", di = DC_CTL,
                    extra = ""","g":"$DC_GID","h":"h","k":"abcdefghijklmnopq","b":"{}""""))
            },
            DropRow("unknown direct control", Ch.MAIN) {
                sealLegacyEnvelopeBytes(it.secret, it.env(1, extra = ""","k":"zzz","b":"{}""""))
            },
            DropRow("bare text on the control inbox", Ch.CTL) {
                sealLegacyEnvelopeBytes(it.secret, it.env(1, ch = "c", di = DC_CTL))
            },
            DropRow("group-tagged bare text on the control inbox", Ch.CTL) {
                sealLegacyEnvelopeBytes(it.secret, it.env(1, ch = "c", di = DC_CTL, extra = ""","g":"$DC_GID","h":"h""""))
            },
            DropRow("no g on the group inbox", Ch.GRP) {
                sealLegacyEnvelopeBytes(it.secret, it.env(1, ch = "g", di = DC_GRP))
            },
            DropRow("control kind on the group inbox", Ch.GRP) {
                sealLegacyEnvelopeBytes(it.secret, it.env(1, ch = "g", di = DC_GRP,
                    extra = ""","g":"$DC_GID","h":"h","k":"roster","b":"{}""""))
            },
        )
        for (row in rows) {
            val rx = Rx(ctlInboxId = row.ctlInboxId)
            row.setup(rx)
            val inbox = inboxOf(row.ch, row.ctlInboxId)
            val id = rx.relay.deliver(inbox, row.blob(rx))
            assertTrue(poll(rx, row.ch).isEmpty(), "${row.name}: nothing surfaced")
            assertTrue(id in rx.relay.ackedIds(inbox), "${row.name}: a drop is acked")
            assertEquals(0L, counterOf(rx, row.ch), "${row.name}: the counter does not move")
        }
    }

    // E1 boundary: a 16-char kind passes the length check (here as a group-scoped
    // kind, which this layer hands on unvalidated).
    @Test
    fun sixteenCharControlKind_passesTheLengthCheck() {
        if (!legacyEnvelopeCryptoUp()) return
        val rx = Rx()
        val id = rx.deliver(DC_CTL, rx.env(1, ch = "c", di = DC_CTL,
            extra = ""","g":"$DC_GID","h":"h","k":"abcdefghijklmnop","b":"{}""""))
        assertEquals(listOf("abcdefghijklmnop"), rx.mgr.pollControlMessages(rx.cid).map { it.controlKind })
        assertTrue(id in rx.relay.ackedIds(DC_CTL))
        assertEquals(1L, rx.contact().inboundCtlCounter)
    }

    // E2 (the `di` half of the same-drain upgrade order): a bound blob served AHEAD
    // of a genuinely older di-less one does not get it dropped — the binding marker
    // is decided for the whole drain from persisted state and written after it — and
    // the NEXT drain enforces it.
    @Test
    fun upgradeDrain_boundBlobFirst_thenDiLessLegacy_bothAccepted_andTheNextDrainEnforces() {
        if (!legacyEnvelopeCryptoUp()) return
        val rx = Rx()
        rx.deliver(DC_MAIN, rx.env(2, text = "m2"))
        rx.deliver(DC_MAIN, rx.env(1, text = "m1", di = null))
        assertNull(rx.vault.getMeta(MessageManager.inboxBoundSeenKey(rx.cid)))
        assertEquals(listOf("m1", "m2"), rx.mgr.pollMessages(rx.cid).map { it.text }, "sorted, both kept")
        assertEquals("1", rx.vault.getMeta(MessageManager.inboxBoundSeenKey(rx.cid)))
        val id3 = rx.deliver(DC_MAIN, rx.env(3, text = "m3", di = null))
        assertTrue(rx.mgr.pollMessages(rx.cid).isEmpty(), "from now on a di-less blob is a downgrade")
        assertTrue(id3 in rx.relay.ackedIds(DC_MAIN))
        assertEquals(2L, rx.contact().inboundCounter)
    }

    // E3: the first pass latches the peer's upgrade flags and its `cr` advert BEFORE
    // the strict-monotonic check, so even a replayed blob sets them.
    @Test
    fun aReplayedLegacyBlob_stillLatchesItsAdvertsAndUpgradeFlags() {
        if (!legacyEnvelopeCryptoUp()) return
        val rx = Rx()
        rx.vault.insertContact(rx.contact().copy(inboundCounter = 5, inboundEpoch = rx.epoch))
        val id = rx.deliver(DC_MAIN, rx.env(5, extra = ""","cr":"1""""))
        assertTrue(rx.mgr.pollMessages(rx.cid).isEmpty(), "counter 5 <= baseline 5: a replay")
        assertTrue(id in rx.relay.ackedIds(DC_MAIN))
        assertEquals("1", rx.vault.getMeta(MessageManager.channelTagSeenKey(rx.cid)))
        assertEquals("1", rx.vault.getMeta(MessageManager.inboxBoundSeenKey(rx.cid)))
        assertEquals("1", rx.vault.getMeta(MessageManager.drCtlCapKey(rx.cid)))
        assertEquals(5L, rx.contact().inboundCounter)
    }

    // --- Phase G: persist + outcome ---------------------------------------------

    // G1 (text): a baseline persist that fails drops the LEGACY batch as NOT_PROCESSED
    // — not acked, released — and the next drain, with the vault writable, lands it.
    @Test
    fun baselinePersistFailure_leavesTheLegacyBlobUnacked_andTheRedeliveryLands() {
        if (!legacyEnvelopeCryptoUp()) return
        val vault = FailingInsertVault()
        val h = LaHarness(ratchet = false, alice = vault)
        assertTrue(h.bobMgr.sendMessage(LA, "x"))
        val id = h.relay.idsOf(LA_IN_A).single()
        val base = h.textBaseline()
        vault.failInsertContact = true
        assertTrue(h.aliceMgr.pollMessages(LA).isEmpty(), "an unprotectable legacy batch is not delivered")
        vault.failInsertContact = false
        assertFalse(id in h.relay.ackedIds(LA_IN_A))
        assertEquals(1, h.relay.visible(LA_IN_A))
        assertEquals(base, h.textBaseline())
        assertEquals(listOf("x"), h.aliceMgr.pollMessages(LA).map { it.text })
        assertTrue(id in h.relay.ackedIds(LA_IN_A))
        assertTrue(h.textBaseline() > base)
    }

    // G1 (control, both halves in one drain): the ratchet message is kept and acked,
    // the legacy one is left for re-delivery, the control baseline does not move.
    @Test
    fun baselinePersistFailure_keepsTheRatchetMessage_andLeavesTheLegacyOneForRedelivery() {
        if (!legacyEnvelopeCryptoUp()) return
        val vault = FailingInsertVault()
        val h = LaHarness(ratchet = true, alice = vault)
        assertTrue(h.bobMgr.sendDirectControl(LA, MessageManager.CONTROL_KIND_REFERRAL_ACCEPT, "{}"))
        assertTrue(h.bobMgr.sendGroupControl(LA, LA_GID, GroupManager.KIND_ACTIVITY, "{}", LA_HASH, noPush = true))
        val (ratchetId, legacyId) = h.relay.idsOf(LA_CTL_A)
        val wires = h.relay.blobsOf(LA_CTL_A)
        assertTrue(MessageManager.isRatchetWire(wires[0]), "precondition: the referral accept rides the ratchet")
        assertFalse(MessageManager.isRatchetWire(wires[1]), "precondition: the activity notice is legacy")
        val base = h.ctlBaseline()
        vault.failInsertContact = true
        assertEquals(listOf(MessageManager.CONTROL_KIND_REFERRAL_ACCEPT), h.aliceMgr.pollControlMessages(LA).map { it.controlKind })
        vault.failInsertContact = false
        assertTrue(ratchetId in h.relay.ackedIds(LA_CTL_A), "the ratchet message is durable: acked")
        assertFalse(legacyId in h.relay.ackedIds(LA_CTL_A), "the legacy one is left for re-delivery")
        assertEquals(base, h.ctlBaseline())
        assertEquals(listOf(GroupManager.KIND_ACTIVITY), h.aliceMgr.pollControlMessages(LA).map { it.controlKind })
        assertTrue(legacyId in h.relay.ackedIds(LA_CTL_A))
        assertTrue(h.ctlBaseline() > base)
    }

    // G4: the persist-mode ack lists the ids with no ack dependency first, then the
    // ratchet ones, then the accepted legacy ones — each group in blob order.
    @Test
    fun persistModeAck_listsFreeThenRatchetThenLegacyIds() {
        if (!legacyEnvelopeCryptoUp()) return
        val h = LaHarness(ratchet = true)
        assertTrue(h.bobMgr.sendGroupControl(LA, LA_GID, GroupManager.KIND_ACTIVITY, "{}", LA_HASH, noPush = true))
        h.relay.deliver(LA_CTL_A, ByteArray(10))
        assertTrue(h.bobMgr.sendDirectControl(LA, MessageManager.CONTROL_KIND_REFERRAL_ACCEPT, "{}"))
        val (legacyId, junkId, ratchetId) = h.relay.idsOf(LA_CTL_A)
        h.aliceMgr.pollControlMessages(LA)
        assertEquals(listOf(junkId, ratchetId, legacyId), h.relay.acksFor(LA_CTL_A).single().delete)
    }
}

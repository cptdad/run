package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

// ---------------------------------------------------------------------------
// MoveFreezeGateTest — the "move to new device" FREEZE GATE that lives inside
// MessageManager (docs/device-move.md D2).
//
// THE BUG THESE PIN (adversarial verifier, 2026-09-09). `createSessionManagers`
// gates the MessageManager PROVIDER it hands GroupManager/ReferralManager, so
// every group/referral relay op stopped at the freeze — but the plain 1:1 paths
// hold the MessageManager DIRECTLY (RunViewModel.sendMessageInBackground,
// AppState.sendMessage, the iOS unread sweep's peekInbox, the push-wake peek),
// and MoveSessionControl.quiesce deliberately KEEPS that object alive because the
// transfer inbox still needs Tor and the HTTP client. So an open conversation
// screen could still send after `mig_frozen` was written and advance the SENDING
// ratchet chain the new phone is about to inherit — two live copies of one chain,
// which is precisely the fork the freeze exists to prevent (fact 5).
//
// What is asserted, and why each one earns a test:
//
//  * ZERO HTTP. A frozen send/poll/peek must not merely fail — it must not reach
//    the relay at all, and must not bump the outbound anti-replay counter (a
//    bumped-but-unsent counter is a gap the peer would have to tolerate).
//  * THE FAILURE SHAPE IS THE EXISTING ONE. `false` / `emptyList()` / `null` —
//    what every caller already handles as "the relay refused it". Nothing throws;
//    a crash on the conversation screen would be a worse bug than the finding.
//  * THE MOVE'S OWN PRIMITIVES STILL WORK. `mig_frozen` is written BEFORE the
//    mint + upload, so gating those would make the export impossible.
//  * THE RELAUNCH CASE. A MessageManager built over an already-frozen vault is
//    frozen with no MoveManager anywhere in the picture — the vault row, not the
//    in-RAM flip, is the durable authority.
//  * CANCEL RESTORES. A proven cancel unfreezes the LIVE instance, not just the
//    vault, or the phone stays mute for the rest of the session.
// ---------------------------------------------------------------------------

private fun id32(seed: String) = (seed + "0".repeat(32)).take(32)
private fun cap43(seed: String) = (seed + "a".repeat(43)).take(43)

private const val FZ_CONTACT = "contact-freeze-1"
private val FZ_INBOUND = id32("FzInbound")
private val FZ_INBOUND_CTL = id32("FzInboundCtl")
private val FZ_OUTBOUND = id32("FzOutbound")
private val FZ_OUTBOUND_CTL = id32("FzOutboundCtl")
private val FZ_TRANSFER = id32("FzTransfer")
private val FZ_CAP_IN = cap43("Rin")
private val FZ_CAP_IN_CTL = cap43("Rinc")
private val FZ_CAP_OUT = cap43("Wout")
private val FZ_CAP_OUT_CTL = cap43("Woutc")
private val FZ_TRANSFER_RCAP = cap43("Trc")
private val FZ_TRANSFER_WCAP = cap43("Twc")

private const val FZ_RELAY = "http://relay.test"
private const val FZ_GROUP = "FzGroupIdentifier00000000000000x"

/**
 * Real AES-GCM is only reachable where the platform crypto actual is wired (the
 * iOS-simulator test target has pre-existing bridge-dependency failures). The
 * gate itself needs no crypto — it returns before any of it — so only the
 * "…and it still works when NOT frozen" controls are guarded by this.
 */

/**
 * Answers by ROUTE rather than by a scripted queue, so a test cannot silently
 * pass by consuming a reply meant for an earlier call — which matters here,
 * where the whole assertion is about calls that must NOT happen.
 */
private class RouteRelayHttp : FakeRelayHttp() {
    var peekPending = 0
    var mintBody =
        """{"inboxId":"$FZ_TRANSFER","readCapability":"$FZ_TRANSFER_RCAP","writeCapability":"$FZ_TRANSFER_WCAP","expiresAt":0}"""

    /** Every request as "VERB url", in order. */
    val calls: List<String> get() = requests.map { "${it.method} ${it.url}" }

    private fun ok(body: String) = HttpResult(code = 200, body = body, isSuccess = true)

    init {
        // `POST /inbox` (no id) is the mint handshake; a relay with PoW disabled
        // answers 201 straight away, which is the branch this exercises.
        onPost = { if (it.url.endsWith("/inbox")) HttpResult(code = 201, body = mintBody, isSuccess = true) else ok("{}") }
        onPut = { ok("{}") }
        onGet = {
            when {
                it.url.contains("/peek") -> ok("""{"pending":$peekPending}""")
                it.url.contains("/inbox/") -> ok("""{"blobs":[]}""")
                else -> ok("{}")
            }
        }
        onDelete = { ok("{}") }
    }
}

/** Minimal [MoveSessionControl] over a fixed transport. */
private class FreezeFakeSession(private val transport: MoveTransport?) : MoveSessionControl {
    var quiesced = false
    var resumed = false
    override suspend fun unregisterPushBestEffort() {}
    override suspend fun quiesce() { quiesced = true }
    override suspend fun resume() { resumed = true }
    override fun transport(): MoveTransport? = transport
}

/** One fully paired contact (all four inbox directions), optionally frozen. */
private fun freezeVault(frozen: Boolean): MoveFakeVault {
    val v = MoveFakeVault()
    v.insertContact(ContactRecord(FZ_CONTACT, ByteArray(32) { 7 }, 2, "Frozen Peer", 0L))
    v.insertInboxId(InboxIdRecord(FZ_INBOUND, FZ_CONTACT, 1L, Long.MAX_VALUE, "inbound", FZ_CAP_IN))
    v.insertInboxId(
        InboxIdRecord(FZ_INBOUND_CTL, FZ_CONTACT, 1L, Long.MAX_VALUE, MessageManager.DIR_INBOUND_CTL, FZ_CAP_IN_CTL)
    )
    v.insertInboxId(InboxIdRecord(FZ_OUTBOUND, FZ_CONTACT, 1L, Long.MAX_VALUE, "outbound", FZ_CAP_OUT))
    v.insertInboxId(
        InboxIdRecord(FZ_OUTBOUND_CTL, FZ_CONTACT, 1L, Long.MAX_VALUE, MessageManager.DIR_OUTBOUND_CTL, FZ_CAP_OUT_CTL)
    )
    if (frozen) v.putMeta(MoveMetaKeys.FROZEN, "1")
    return v
}

class MoveFreezeGateTest {

    // -----------------------------------------------------------------------
    // Sends
    // -----------------------------------------------------------------------

    @Test
    fun frozenVault_sendMessage_touchesNoRelay_returnsFalse_andLeavesTheCounterAlone() {
        val vault = freezeVault(frozen = true)
        val relay = RouteRelayHttp()
        val mm = MessageManager(vault, FZ_RELAY, relay)

        assertFalse(mm.sendMessage(FZ_CONTACT, "this must never reach the relay"))

        assertEquals(0, relay.calls.size, "a frozen send must make ZERO HTTP calls: ${relay.calls}")
        // The outbound anti-replay counter must not advance either: a bumped but
        // unsent counter is a gap the peer has to absorb, and on the new phone the
        // +10 000 jump is sized for the snapshot window, not for our own churn.
        assertEquals(0L, vault.getContact(FZ_CONTACT)!!.outboundCounter)
        assertEquals(0L, vault.getContact(FZ_CONTACT)!!.outboundCtlCounter)
    }

    @Test
    fun frozenVault_everySendKind_isRefusedWithoutTouchingTheRelay() {
        val vault = freezeVault(frozen = true)
        val relay = RouteRelayHttp()
        val mm = MessageManager(vault, FZ_RELAY, relay)

        // Every contact-facing send funnels through sendEnvelope; each of these is a
        // separate PUBLIC/INTERNAL door onto it, and each one advances (or, on the
        // control channel, consumes counter space against) a chain the new phone
        // inherits.
        assertFalse(mm.sendMessage(FZ_CONTACT, "text"), "1:1 text")
        assertFalse(mm.sendGroupText(FZ_CONTACT, FZ_GROUP, "hash", "group text"), "group text")
        assertFalse(
            mm.sendGroupControl(FZ_CONTACT, FZ_GROUP, "roster", "{}", "hash"),
            "group control (incl. the membership redrive)",
        )
        assertFalse(mm.sendDirectControl(FZ_CONTACT, "ref-offer", "{}"), "referral handshake")
        assertFalse(mm.sendScreenshotNotice(FZ_CONTACT), "screenshot notice")
        assertFalse(
            mm.sendInboxAnnounce(FZ_CONTACT, FZ_INBOUND, FZ_CAP_OUT, FZ_INBOUND_CTL, FZ_CAP_OUT_CTL),
            "inbox announce",
        )

        assertEquals(0, relay.calls.size, "no send kind may reach the relay while frozen: ${relay.calls}")
    }

    // -----------------------------------------------------------------------
    // Polls / peeks — receiving advances the ratchet too (fact 5)
    // -----------------------------------------------------------------------

    @Test
    fun frozenVault_everyPollAndPeek_returnsEmptyWithoutTouchingTheRelay() {
        val vault = freezeVault(frozen = true)
        val relay = RouteRelayHttp()
        relay.peekPending = 9
        val mm = MessageManager(vault, FZ_RELAY, relay)

        assertTrue(mm.pollMessages(FZ_CONTACT).isEmpty(), "text drain")
        assertTrue(mm.pollControlMessages(FZ_CONTACT).isEmpty(), "control drain")
        // The THIRD inbox is a text-carrying channel like the other two — a
        // drain there advances the SAME ratchet chain (docs/device-move.md fact 5),
        // so it must be just as frozen.
        assertTrue(mm.pollGroupInbox(FZ_CONTACT).isEmpty(), "group-text drain")
        assertNull(mm.peekGroupInboxPending(FZ_CONTACT), "group unread peek")
        assertTrue(mm.inboundGroupPeekTargets(listOf(FZ_CONTACT)).isEmpty(), "group peek snapshot")
        assertNull(mm.peekInbox(FZ_CONTACT), "unread peek (the iOS sweep calls this directly)")
        assertNull(mm.peekControlPending(FZ_CONTACT), "control peek (bridged straight to Swift)")
        assertTrue(mm.peekUnreadCounts().isEmpty(), "unread sweep")
        assertTrue(
            mm.peekUnreadCountsWithGroup(emptySet(), setOf(FZ_CONTACT)).group.isEmpty(),
            "unread sweep, group half",
        )
        assertTrue(mm.inboundTextPeekTargets().isEmpty(), "connect-time unread prime snapshot")
        assertNull(mm.peekInboxRef(FZ_INBOUND, FZ_CAP_IN), "unread prime worker peek")
        // The BATCH peek answers FAILED (= unknown for every ref), never UNSUPPORTED:
        // the relay said nothing, so nothing may be latched about what it supports.
        assertTrue(
            mm.peekInboxesBatch(listOf(MessageManager.PeekRef(FZ_INBOUND, FZ_CAP_IN)))
                is MessageManager.BatchPeekOutcome.Failed,
            "connect-time batch peek",
        )
        assertFalse(mm.isBatchPeekUnsupported(), "a freeze must not latch the batch route as missing")

        assertEquals(0, relay.calls.size, "a frozen poll/peek must make ZERO HTTP calls: ${relay.calls}")
    }

    @Test
    fun frozenVault_pairingMintAndCapRotations_areRefused() = runTest {
        val vault = freezeVault(frozen = true)
        val relay = RouteRelayHttp()
        val mm = MessageManager(vault, FZ_RELAY, relay)

        // A pairing mint would create inbox rows the already-built bundle cannot
        // contain — a contact that exists on the old phone and nowhere else.
        assertNull(mm.mintInboxPair(), "pairing mint")
        // docs/device-move.md §1.6: `mintInbox` is deliberately NOT freeze-gated (it is the move's own
        // transfer-inbox primitive), so the group-inbox backfill MUST carry its own
        // gate or a frozen old phone would mint inboxes the exported bundle does not
        // contain — live capabilities on a relay that no device will ever own.
        assertEquals(
            MessageManager.GroupBackfillOutcome.SKIPPED,
            mm.maybeBackfillGroupInbox(FZ_CONTACT),
            "group-inbox backfill mint",
        )
        // Rotating a CONTACT inbox's read cap after the snapshot leaves the new phone
        // importing a cap the relay no longer accepts.
        assertFalse(mm.resetRelayAccess(FZ_CONTACT), "reset relay access")
        @Suppress("DEPRECATION")
        assertFalse(mm.rotateWriteCapabilityNonDurable(FZ_CONTACT, cap43("New")), "write-cap rotate")

        assertEquals(0, relay.calls.size, "no rotation or pairing mint may reach the relay: ${relay.calls}")
    }

    // -----------------------------------------------------------------------
    // The move's own transfer-inbox primitives must stay open
    // -----------------------------------------------------------------------

    @Test
    fun frozenVault_transferInboxPrimitives_stillReachTheRelay() {
        val vault = freezeVault(frozen = true)
        val relay = RouteRelayHttp()
        relay.peekPending = 2
        val mm = MessageManager(vault, FZ_RELAY, relay)

        // `mig_frozen` is written BEFORE the mint + upload, so if any of these were
        // gated the export could never happen at all. A transfer inbox belongs to no
        // contact: no counter, no epoch, no ratchet chain.
        assertNotNull(mm.mintInbox(), "the transfer inbox mint must still work")
        assertEquals(
            200,
            mm.postMoveChunk(FZ_TRANSFER, FZ_TRANSFER_WCAP, ByteArray(64) { 1 }, MoveConstants.TRANSFER_TTL_SECONDS),
            "chunk upload",
        )
        assertEquals(2, mm.peekMoveInbox(FZ_TRANSFER, FZ_TRANSFER_RCAP).pending, "transfer peek")
        assertEquals(200, mm.drainMoveInbox(FZ_TRANSFER, FZ_TRANSFER_RCAP).code, "transfer drain")
        assertTrue(mm.deleteInbox(FZ_TRANSFER, FZ_TRANSFER_RCAP), "transfer inbox delete")

        assertEquals(5, relay.calls.size, "every transfer primitive must reach the relay: ${relay.calls}")
    }

    // -----------------------------------------------------------------------
    // The relaunch case, and the fail direction of an unreadable vault
    // -----------------------------------------------------------------------

    @Test
    fun messageManagerBuiltOverAnAlreadyFrozenVault_isFrozen_withNoMoveManagerInvolved() {
        // The relaunch: the process died with `mig_frozen` set, a new MessageManager
        // is built when Tor reconnects, and nothing calls setMoveFrozen. The vault row
        // is the durable authority and must be enough on its own.
        val vault = freezeVault(frozen = true)
        val relay = RouteRelayHttp()
        val mm = MessageManager(vault, FZ_RELAY, relay)

        assertTrue(mm.refreshMoveFrozen(), "a fresh instance must read mig_frozen from the vault")
        assertFalse(mm.sendMessage(FZ_CONTACT, "after a relaunch"))
        assertTrue(mm.pollMessages(FZ_CONTACT).isEmpty())
        assertEquals(0, relay.calls.size)
    }

    @Test
    fun anUnreadableVault_refusesTheCall_butDoesNotLatchTheSessionFrozen() {
        // isMoveFrozen fails toward FROZEN, which is right for ONE call and wrong as a
        // latch: a single transient vault error must not wedge the whole session mute
        // with nothing left to re-read it.
        var throwOnMetaRead = true
        val vault = object : MoveFakeVault() {
            override fun getMeta(key: String): String? {
                if (throwOnMetaRead && key == MoveMetaKeys.FROZEN) error("transient vault failure")
                return super.getMeta(key)
            }
        }
        vault.insertContact(ContactRecord(FZ_CONTACT, ByteArray(32) { 7 }, 2, "Peer", 0L))
        vault.insertInboxId(InboxIdRecord(FZ_OUTBOUND, FZ_CONTACT, 1L, Long.MAX_VALUE, "outbound", FZ_CAP_OUT))
        val relay = RouteRelayHttp()
        val mm = MessageManager(vault, FZ_RELAY, relay)

        assertFalse(mm.sendMessage(FZ_CONTACT, "while the vault is unreadable"), "must fail toward frozen")
        assertEquals(0, relay.calls.size)

        throwOnMetaRead = false
        if (aeadUp()) {
            assertTrue(mm.sendMessage(FZ_CONTACT, "after the vault recovers"), "the refusal must not have latched")
            assertEquals(1, relay.calls.size)
        } else {
            // Without a crypto actual the send cannot complete, but the GATE must still
            // let it through — which is observable as the read no longer being refused.
            assertFalse(mm.refreshMoveFrozen(), "the gate must re-read, not stay latched")
        }
    }

    // -----------------------------------------------------------------------
    // Not frozen ⇒ nothing changed
    // -----------------------------------------------------------------------

    @Test
    fun unfrozenVault_pollAndPeek_reachTheRelayExactlyAsBefore() {
        val vault = freezeVault(frozen = false)
        val relay = RouteRelayHttp()
        relay.peekPending = 4
        val mm = MessageManager(vault, FZ_RELAY, relay)

        assertTrue(mm.pollMessages(FZ_CONTACT).isEmpty())      // 200 with an empty blob array
        assertEquals(4, mm.peekInbox(FZ_CONTACT))
        assertEquals(4, mm.peekInboxRef(FZ_INBOUND, FZ_CAP_IN))
        assertEquals(1, mm.inboundTextPeekTargets().size)

        assertTrue(relay.calls.size >= 3, "an unfrozen device must still poll and peek: ${relay.calls}")
    }

    @Test
    fun unfrozenVault_sendStillReachesTheRelay() {
        if (!aeadUp()) return
        val vault = freezeVault(frozen = false)
        val relay = RouteRelayHttp()
        val mm = MessageManager(vault, FZ_RELAY, relay)

        assertTrue(mm.sendMessage(FZ_CONTACT, "ordinary message"))
        assertEquals(1, relay.calls.size)
        assertEquals(1L, vault.getContact(FZ_CONTACT)!!.outboundCounter)
    }

    // -----------------------------------------------------------------------
    // setMoveFrozen — the flip MoveManager drives
    // -----------------------------------------------------------------------

    @Test
    fun setMoveFrozen_gatesAndUngatesTheLiveInstance() {
        if (!aeadUp()) return
        val vault = freezeVault(frozen = false)
        val relay = RouteRelayHttp()
        val mm = MessageManager(vault, FZ_RELAY, relay)

        // Warm the cache the way a live session does, then freeze mid-session — the
        // exact sequence beginExport drives on an instance that has been sending.
        assertTrue(mm.sendMessage(FZ_CONTACT, "before the freeze"))
        vault.putMeta(MoveMetaKeys.FROZEN, "1")
        mm.setMoveFrozen(true)

        assertFalse(mm.sendMessage(FZ_CONTACT, "after the freeze"))
        assertEquals(1, relay.calls.size, "the freeze must take effect on the LIVE instance")

        // …and a proven cancel restores it, or the phone stays mute for the session.
        vault.deleteMeta(MoveMetaKeys.FROZEN)
        mm.setMoveFrozen(false)
        assertTrue(mm.sendMessage(FZ_CONTACT, "after the cancel"))
        assertEquals(2, relay.calls.size)
    }

    // -----------------------------------------------------------------------
    // Push registration surface
    // -----------------------------------------------------------------------

    @Test
    fun allPushableInboxes_isEmptyWhileFrozen_soAFrozenPhoneCannotStealTheNewPhonesWakes() {
        // PUT /inbox/{id}/push is an UPSERT keyed by inbox, so an old phone that
        // re-registered would silently replace the new phone's token. This is the one
        // place BOTH platforms resolve the push surface from.
        assertEquals(2, allPushableInboxes(freezeVault(frozen = false)).size)
        assertTrue(allPushableInboxes(freezeVault(frozen = true)).isEmpty())
    }

    // -----------------------------------------------------------------------
    // End to end through MoveManager + RelayMoveTransport
    // -----------------------------------------------------------------------

    @Test
    fun beginExport_freezesTheLiveMessageManager_andCancelRestoresIt() = runTest {
        if (!aeadUp()) return@runTest
        val vault = freezeVault(frozen = false)
        val relay = RouteRelayHttp()
        val mm = MessageManager(vault, FZ_RELAY, relay)
        val session = FreezeFakeSession(RelayMoveTransport(mm))
        val mgr = MoveManager({ vault }, session, MigrationBundle.FROM_ANDROID, exportAuthGate = TestGrantedGate())

        mgr.beginExport()

        val ready = assertNotNull(
            mgr.exportStateNow() as? MoveExportState.Ready,
            "export must reach Ready, got ${mgr.exportStateNow()}",
        )
        assertEquals("1", vault.getMeta(MoveMetaKeys.FROZEN))
        assertTrue(session.quiesced)
        val callsAfterExport = relay.calls.size

        // THE FINDING: the conversation screen still holds `mm` and quiesce keeps it
        // alive on purpose. It must now refuse.
        assertFalse(mm.sendMessage(FZ_CONTACT, "sent from a screen that outlived the freeze"))
        assertTrue(mm.pollMessages(FZ_CONTACT).isEmpty())
        assertEquals(callsAfterExport, relay.calls.size, "nothing contact-facing may reach the relay: ${relay.calls}")

        // A cancel with POSITIVE proof the bundle is undrained (peek >= chunkCount)
        // unfreezes the live instance, not just the vault row.
        relay.peekPending = ready.chunkCount
        assertTrue(mgr.cancelExport())
        assertNull(vault.getMeta(MoveMetaKeys.FROZEN))
        assertTrue(session.resumed)
        assertTrue(mm.sendMessage(FZ_CONTACT, "after the cancel"), "the live instance must send again")
    }

    @Test
    fun aFailedExportLeavesTheLiveMessageManagerFrozen() = runTest {
        // "A failure NEVER unfreezes" (MoveManager's header) has to hold for the
        // in-RAM gate too, or a failed export would leave a frozen vault beside a
        // still-sending relay client.
        val vault = freezeVault(frozen = false)
        val relay = RouteRelayHttp()
        // A mint that answers 500 is terminal (not a transient retry), so the export
        // fails AFTER the freeze has landed — the state this test is about.
        val failing = object : RelayHttp by relay {
            override fun post(
                url: String, body: ByteArray, contentType: String,
                headers: Map<String, String>, timeoutSeconds: Int,
            ): HttpResult {
                relay.post(url, body, contentType, headers, timeoutSeconds)   // recorded as "POST url"
                return HttpResult(code = 500, body = "boom", isSuccess = false)
            }
        }
        val mm = MessageManager(vault, FZ_RELAY, failing)
        val mgr = MoveManager({ vault }, FreezeFakeSession(RelayMoveTransport(mm)), MigrationBundle.FROM_ANDROID, exportAuthGate = TestGrantedGate())

        mgr.beginExport()

        assertTrue(mgr.exportStateNow() is MoveExportState.Failed, "the mint must fail: ${mgr.exportStateNow()}")
        assertEquals("1", vault.getMeta(MoveMetaKeys.FROZEN), "a failure must never unfreeze")
        val callsAfterExport = relay.calls.size
        assertFalse(mm.sendMessage(FZ_CONTACT, "after a failed export"))
        assertEquals(callsAfterExport, relay.calls.size)
    }
}

package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// The integrity-critical CONTROL kinds — the referral
// handshake (offer / accept / the introducer-relayed accept) and group
// membership control (invite / join / roster / leave) — ride the text ratchet
// once both sides advertise it, and a static-envelope copy above the peer's
// ratchet-proven commitment is dropped. Same shape as ForgedAnnounceRedirectTest:
// two live MessageManagers over a storing relay double, and an attacker
// who acts ONLY from fields a vault image of the peer contains (sharedSecret,
// the outbound-ctl row + its write cap, the persisted outbound-ctl counter).
//
// What this file pins:
//   • capability + watermark are exchanged by ordinary traffic, no new message;
//   • honest integrity kinds are RATCHET wire on the control inbox and still land;
//   • a forged legacy ref-offer / ref-accept / roster / invite / join / leave is
//     dropped once the lock is armed, WITHOUT burning the control counter;
//   • chatty kinds (`act`) stay legacy and keep landing;
//   • an UN-UPGRADED peer (no advert) is never dropped, and is never sent sealed
//     control; a watermark in a LEGACY envelope can never arm the lock; neither
//     can one seen before the ratchet is past its bootstrap window;
//   • a genuine pre-commit legacy blob still queued on the relay still lands;
//   • the control-counter forward-jump cap, and that a device move (+10 000)
//     still passes it;
//   • the sealed-control catch-up drain: without it a lively chat flushes a
//     sealed blob's skipped key (oracle), with it the blob lands;
//   • the new `_meta` keys are in the shared purge list and travel with a move.
// ---------------------------------------------------------------------------

private const val SC = "c1"
private val SC_IN_A = "A".repeat(32)    // Alice inbound  / Bob outbound   (text)
private val SC_IN_B = "B".repeat(32)    // Bob inbound    / Alice outbound (text)
private val SC_CTL_A = "a".repeat(32)   // Alice inbound-ctl / Bob outbound-ctl
private val SC_CTL_B = "b".repeat(32)   // Bob inbound-ctl   / Alice outbound-ctl
private val SC_RCAP = "R".repeat(43)
private val SC_WCAP_A = "W".repeat(43)
private val SC_WCAP_B = "X".repeat(43)
private val SC_GID = "G".repeat(32)
private const val SC_HASH = "hash-1"

private fun scCryptoUp(): Boolean = try {
    aesGcmEncrypt(ByteArray(1), generateSecureRandom(32), ByteArray(0)); true
} catch (_: Exception) { false }

/** Seals exactly as the production legacy sender does (mirrors ForgedAnnounceRedirectTest). */
private fun scSeal(sharedSecret: ByteArray, envelopeJson: String): ByteArray {
    val key = sha256(sharedSecret)
    val ctx = sha256(key + "message-aead".encodeToByteArray())
    return aesGcmEncrypt(padMessage(envelopeJson.encodeToByteArray()), key, ctx)
}

private fun scEpoch(sharedSecret: ByteArray): String =
    bytesToHex(sha256(sharedSecret + "msg-epoch".encodeToByteArray()).copyOfRange(0, 6))

/** Storing relay double: POST appends, GET drains, GET …/peek counts without draining. */
private class ScRelay : InboxQueueRelay(peek = true)

/** A vault whose read of the capability marker can be made to THROW. */
private class CapThrowingVault : InMemoryVault() {
    var throwCapRead = false
    override fun getMeta(key: String): String? {
        if (throwCapRead && key == MessageManager.drCtlCapKey(SC)) throw IllegalStateException("simulated keybag-locked read")
        return super.getMeta(key)
    }
}

private class ScHarness(
    /** false = a pairing with NO control inbox pair (pre-v7 shape). */
    private val withCtl: Boolean = true,
) {
    val relay = ScRelay()
    val secret = generateSecureRandom(32)
    val alice = InMemoryVault()   // the VICTIM
    val bob = CapThrowingVault()  // the SEIZED device (vault-image source)
    val aliceMgr: MessageManager
    val bobMgr: MessageManager

    init {
        provision(alice, inText = SC_IN_A, outText = SC_IN_B, inCtl = SC_CTL_A, outCtl = SC_CTL_B, peerWcap = SC_WCAP_B)
        provision(bob, inText = SC_IN_B, outText = SC_IN_A, inCtl = SC_CTL_B, outCtl = SC_CTL_A, peerWcap = SC_WCAP_A)
        aliceMgr = MessageManager(alice, "http://relay.test", relay)
        bobMgr = MessageManager(bob, "http://relay.test", relay)
        MessageManager.markRatchetCapable(alice, SC)
        MessageManager.markRatchetCapable(bob, SC)
    }

    private fun provision(v: InMemoryVault, inText: String, outText: String, inCtl: String, outCtl: String, peerWcap: String) {
        v.insertContact(ContactRecord(contactId = SC, sharedSecret = secret, trustLevel = 0, alias = "p", aliasLastRotated = 0))
        v.insertInboxId(InboxIdRecord(inText, SC, 0L, Long.MAX_VALUE, "inbound", SC_RCAP))
        v.insertInboxId(InboxIdRecord(outText, SC, 0L, Long.MAX_VALUE, "outbound", peerWcap))
        if (!withCtl) return
        v.insertInboxId(InboxIdRecord(inCtl, SC, 0L, Long.MAX_VALUE, MessageManager.DIR_INBOUND_CTL, SC_RCAP))
        v.insertInboxId(InboxIdRecord(outCtl, SC, 0L, Long.MAX_VALUE, MessageManager.DIR_OUTBOUND_CTL, peerWcap))
    }

    /** One text each way, polled at once: one DH round trip once the ratchet is live. */
    fun roundTrip(i: Int) {
        assertTrue(aliceMgr.sendMessage(SC, "a$i"))
        assertEquals(listOf("a$i"), bobMgr.pollMessages(SC).map { it.text })
        assertTrue(bobMgr.sendMessage(SC, "b$i"))
        assertEquals(listOf("b$i"), aliceMgr.pollMessages(SC).map { it.text })
    }

    /** Drive the pairing until both sides' ratchets are past bootstrap AND have
     *  recorded each other's control commitment (four round trips — see the trace in
     *  docs/vault-relay-internals.md: dr-rxlock arms after the 2nd receiving DH
     *  step, and the NEXT ratchet blob carries the watermark that is then honoured). */
    fun engage() {
        repeat(4) { roundTrip(it) }
        assertEquals("1", alice.getMeta("dr-on/$SC"), "precondition: ratchet on (Alice)")
        assertEquals("1", bob.getMeta("dr-on/$SC"), "precondition: ratchet on (Bob)")
        assertEquals("1", alice.getMeta(MessageManager.drRecvLockKey(SC)), "precondition: Alice's lock armed")
        assertEquals("1", bob.getMeta(MessageManager.drRecvLockKey(SC)), "precondition: Bob's lock armed")
    }

    /** A legacy control blob built from BOB's vault (what a vault image yields). */
    fun forgeFromBobsVault(
        counter: Long,
        kind: String,
        body: String,
        groupId: String? = null,
        extraFields: String = "",
    ): ByteArray {
        val snap = bob.getContact(SC)!!
        val peerCtl = bob.getInboxIdForContact(SC, MessageManager.DIR_OUTBOUND_CTL)!!
        val group = if (groupId != null) ""","g":"$groupId","h":"$SC_HASH"""" else ""
        val env = """{"e":"${scEpoch(snap.sharedSecret)}","c":$counter,"t":0,"ch":"${MessageManager.CHANNEL_TAG_CTL}","di":"${peerCtl.inboxId}"$extraFields$group,"k":"$kind","b":${jsonEscapeString(body)},"m":""}"""
        return scSeal(snap.sharedSecret, env)
    }

    /** A legacy (static-key) TEXT from Bob, as an older/pre-flip Bob would have sent it. */
    fun legacyTextFromBob(counter: Long, text: String): ByteArray {
        val snap = bob.getContact(SC)!!
        val env = """{"e":"${scEpoch(snap.sharedSecret)}","c":$counter,"t":0,"ch":"${MessageManager.CHANNEL_TAG_MAIN}","di":"$SC_IN_A","m":"$text"}"""
        return scSeal(snap.sharedSecret, env)
    }

    fun postToAliceText(blob: ByteArray) {
        relay.post("http://relay.test/inbox/$SC_IN_A", blob, "application/octet-stream", mapOf("X-Write-Capability" to SC_WCAP_A), 30)
    }

    /** Post onto Alice's control inbox with the write cap stolen from Bob's vault. */
    fun postAsAttacker(blob: ByteArray) {
        val stolenCap = bob.getInboxIdForContact(SC, MessageManager.DIR_OUTBOUND_CTL)!!.cap!!
        relay.post("http://relay.test/inbox/$SC_CTL_A", blob, "application/octet-stream", mapOf("X-Write-Capability" to stolenCap), 30)
    }

    fun bobCtlCounter(): Long = bob.getContact(SC)!!.outboundCtlCounter
    fun aliceCtlBaseline(): Long = alice.getContact(SC)!!.inboundCtlCounter
}

private val REF_ACCEPT_BODY = """{"ii":"intro-1","pk":"attacker"}"""
private val REF_OFFER_BODY = """{"ii":"intro-2","pa":"Brave Otter"}"""
private val ROSTER_BODY = """{"n":"crew","ep":2,"adm":"m1","mem":[]}"""

class SealedControlRatchetTest {

    // -- pure helpers ----------------------------------------------------------

    @Test
    fun sealedKindSet_isExactlyTheIntegrityCriticalKinds() {
        for (k in listOf(GroupManager.KIND_INVITE, GroupManager.KIND_JOIN, GroupManager.KIND_ROSTER, GroupManager.KIND_LEAVE)) {
            assertTrue(MessageManager.isRatchetSealedControlKind(k, groupScoped = true), "$k (group) must be sealed")
        }
        for (k in MessageManager.DIRECT_REFERRAL_KINDS) {
            assertTrue(MessageManager.isRatchetSealedControlKind(k, groupScoped = false), "$k (direct) must be sealed")
        }
        // Chatty kinds stay legacy — the MAX_SKIP / skipped-key reasoning in the doc.
        assertFalse(MessageManager.isRatchetSealedControlKind(GroupManager.KIND_ACTIVITY, groupScoped = true))
        assertFalse(MessageManager.isRatchetSealedControlKind(GroupManager.KIND_SCREENSHOT, groupScoped = true))
        assertFalse(MessageManager.isRatchetSealedControlKind(MessageManager.CONTROL_KIND_SCREENSHOT, groupScoped = false))
        // The announce has its own (older, unconditional) rule.
        assertFalse(MessageManager.isRatchetSealedControlKind(MessageManager.CONTROL_KIND_INBOX, groupScoped = false))
        // A namespace mismatch is not a sealed kind (a referral kind inside a group
        // envelope, a membership kind without a group) — and neither is no kind.
        assertFalse(MessageManager.isRatchetSealedControlKind(MessageManager.CONTROL_KIND_REFERRAL_OFFER, groupScoped = true))
        assertFalse(MessageManager.isRatchetSealedControlKind(GroupManager.KIND_ROSTER, groupScoped = false))
        assertFalse(MessageManager.isRatchetSealedControlKind(null, groupScoped = true))
    }

    @Test
    fun watermarkParse_isStrictAsciiDecimal_andFailsOpen() {
        assertEquals(0L, MessageManager.parseCtlWatermark("0"))
        assertEquals(10_042L, MessageManager.parseCtlWatermark("10042"))
        for (bad in listOf(null, "", "-1", "+5", " 5", "5 ", "1e3", "١٢", "9".repeat(19), "0x10")) {
            assertNull(MessageManager.parseCtlWatermark(bad), "'$bad' must read as no watermark")
        }
    }

    @Test
    fun counterCap_coversManyDeviceMoves_andSaturatesInsteadOfOverflowing() {
        assertTrue(
            MessageManager.CTL_COUNTER_MAX_FORWARD_JUMP >= 10 * MoveConstants.COUNTER_JUMP,
            "the cap must leave room for several back-to-back device moves",
        )
        assertEquals(MessageManager.CTL_COUNTER_MAX_FORWARD_JUMP, MessageManager.ctlCounterCeiling(0L))
        assertEquals(Long.MAX_VALUE, MessageManager.ctlCounterCeiling(Long.MAX_VALUE - 5))
        assertEquals(Long.MAX_VALUE, MessageManager.ctlCounterCeiling(Long.MAX_VALUE))
    }

    // -- capability exchange ---------------------------------------------------

    @Test
    fun capabilityAndCommitment_areLearntFromOrdinaryTraffic() {
        if (!scCryptoUp()) return
        val h = ScHarness()
        h.engage()
        assertEquals("1", h.alice.getMeta(MessageManager.drCtlCapKey(SC)), "Alice must have learnt Bob seals control")
        assertEquals("1", h.bob.getMeta(MessageManager.drCtlCapKey(SC)), "Bob must have learnt Alice seals control")
        assertEquals("0", h.alice.getMeta(MessageManager.drCtlWatermarkKey(SC)), "Bob committed at control counter 0")
        assertEquals("0", h.bob.getMeta(MessageManager.drCtlWatermarkKey(SC)), "Alice committed at control counter 0")
    }

    @Test
    fun aWatermarkSeenBeforeTheRatchetMatures_isNotHonoured() {
        if (!scCryptoUp()) return
        val h = ScHarness()
        h.roundTrip(0)   // Bob's b0 is already ratchet wire carrying a watermark…
        assertNull(h.alice.getMeta(MessageManager.drRecvLockKey(SC)), "precondition: Alice is still in the bootstrap window")
        assertNull(
            h.alice.getMeta(MessageManager.drCtlWatermarkKey(SC)),
            "…but a bootstrap-window ratchet blob is forgeable from sharedSecret (M4-2) and must not arm anything",
        )
        // So a legacy roster from Bob is still accepted in that window (the documented
        // bootstrap-window limitation), never dropped.
        h.postAsAttacker(h.forgeFromBobsVault(h.bobCtlCounter() + 1, GroupManager.KIND_ROSTER, ROSTER_BODY, SC_GID))
        assertEquals(listOf(GroupManager.KIND_ROSTER), h.aliceMgr.pollControlMessages(SC).map { it.controlKind })
    }

    // -- honest traffic -----------------------------------------------------------

    @Test
    fun honestRoster_ridesTheRatchet_onTheControlInbox_andLands() {
        if (!scCryptoUp()) return
        val h = ScHarness()
        h.engage()
        assertTrue(h.bobMgr.sendGroupControl(SC, SC_GID, GroupManager.KIND_ROSTER, ROSTER_BODY, SC_HASH, noPush = true))
        val posted = h.relay.blobsIn(SC_CTL_A)
        assertEquals(1, posted.size, "the roster must be posted to the CONTROL inbox")
        assertTrue(MessageManager.isRatchetWire(posted.single()), "a post-commit roster must be ratchet wire")
        assertEquals(0L, h.bobCtlCounter(), "a sealed send consumes no legacy control counter")

        val got = h.aliceMgr.pollControlMessages(SC)
        assertEquals(1, got.size)
        val m = got.single()
        assertEquals(GroupManager.KIND_ROSTER, m.controlKind)
        assertEquals(SC_GID, m.groupId)
        assertEquals(SC_HASH, m.membershipHash)
        assertEquals(ROSTER_BODY, m.controlBody)
    }

    @Test
    fun honestReferralAccept_ridesTheRatchet_andLands() {
        if (!scCryptoUp()) return
        val h = ScHarness()
        h.engage()
        assertTrue(h.bobMgr.sendDirectControl(SC, MessageManager.CONTROL_KIND_REFERRAL_ACCEPT, REF_ACCEPT_BODY))
        assertTrue(MessageManager.isRatchetWire(h.relay.blobsIn(SC_CTL_A).single()))
        val m = h.aliceMgr.pollControlMessages(SC).single()
        assertEquals(MessageManager.CONTROL_KIND_REFERRAL_ACCEPT, m.controlKind)
        assertNull(m.groupId)
        assertEquals(REF_ACCEPT_BODY, m.controlBody)
    }

    @Test
    fun chattyActivityNotice_staysLegacy_andStillLandsAfterTheLock() {
        if (!scCryptoUp()) return
        val h = ScHarness()
        h.engage()
        assertTrue(h.bobMgr.sendGroupControl(SC, SC_GID, GroupManager.KIND_ACTIVITY, "{}", SC_HASH, noPush = true))
        assertFalse(MessageManager.isRatchetWire(h.relay.blobsIn(SC_CTL_A).single()), "`act` must stay on the static envelope")
        assertEquals(listOf(GroupManager.KIND_ACTIVITY), h.aliceMgr.pollControlMessages(SC).map { it.controlKind })
    }

    // -- the forgeries ------------------------------------------------------------

    @Test
    fun forgedLegacyIntegrityKinds_afterTheCommitment_areDropped_withoutBurningTheCounter() {
        if (!scCryptoUp()) return
        val forgeries = listOf(
            Triple(MessageManager.CONTROL_KIND_REFERRAL_OFFER, REF_OFFER_BODY, null),
            Triple(MessageManager.CONTROL_KIND_REFERRAL_ACCEPT, REF_ACCEPT_BODY, null),
            Triple(GroupManager.KIND_ROSTER, ROSTER_BODY, SC_GID),
            Triple(GroupManager.KIND_INVITE, """{"n":"crew"}""", SC_GID),
            Triple(GroupManager.KIND_JOIN, """{"tags":""}""", SC_GID),
            Triple(GroupManager.KIND_LEAVE, "{}", SC_GID),
        )
        for ((kind, body, gid) in forgeries) {
            val h = ScHarness()
            h.engage()
            val baseline = h.aliceCtlBaseline()
            // Minimal step AND a large one: neither may land.
            h.postAsAttacker(h.forgeFromBobsVault(h.bobCtlCounter() + 1, kind, body, gid))
            h.postAsAttacker(h.forgeFromBobsVault(h.bobCtlCounter() + 5_000, kind, body, gid))
            assertTrue(
                h.aliceMgr.pollControlMessages(SC).none { it.controlKind == kind },
                "H-1b: a forged legacy $kind built from a vault image was surfaced after the commitment",
            )
            assertEquals(baseline, h.aliceCtlBaseline(), "a dropped forgery must not advance the control baseline ($kind)")

            // …so the GENUINE stream behind it is untouched: Bob's next legacy control
            // (counter 1, the value the forger tried to burn) still lands.
            assertTrue(h.bobMgr.sendGroupControl(SC, SC_GID, GroupManager.KIND_ACTIVITY, "{}", SC_HASH, noPush = true))
            assertEquals(
                listOf(GroupManager.KIND_ACTIVITY), h.aliceMgr.pollControlMessages(SC).map { it.controlKind },
                "the genuine control stream must survive the dropped forgery ($kind)",
            )
        }
    }

    @Test
    fun genuinePreCommitRoster_stillQueuedOnTheRelay_isAccepted_butAForgeryAboveItIsNot() {
        if (!scCryptoUp()) return
        val h = ScHarness()
        // Bob sends a roster BEFORE either side has advertised anything: legacy, ctl 1.
        assertTrue(h.bobMgr.sendGroupControl(SC, SC_GID, GroupManager.KIND_ROSTER, ROSTER_BODY, SC_HASH, noPush = true))
        assertFalse(MessageManager.isRatchetWire(h.relay.blobsIn(SC_CTL_A).single()))
        // Alice does not sweep control while the pairing matures.
        h.engage()
        assertEquals("1", h.alice.getMeta(MessageManager.drCtlWatermarkKey(SC)), "Bob committed after his ctl counter 1")
        h.postAsAttacker(h.forgeFromBobsVault(2, GroupManager.KIND_ROSTER, """{"n":"evil","ep":3}""", SC_GID))

        val got = h.aliceMgr.pollControlMessages(SC).filter { it.controlKind == GroupManager.KIND_ROSTER }
        assertEquals(listOf(ROSTER_BODY), got.map { it.controlBody }, "the genuine pre-commit roster lands, the forgery above it does not")
    }

    // -- compatibility: an un-upgraded peer ----------------------------------------

    @Test
    fun unUpgradedPeer_isNeverDropped_andIsNeverSentSealedControl() {
        if (!scCryptoUp()) return
        val h = ScHarness()
        h.engage()
        // Model a peer whose build predates the sealed-control capability: it never advertised, so we hold
        // neither its capability nor a commitment (exactly what an old Bob leaves).
        h.alice.deleteMeta(MessageManager.drCtlCapKey(SC))
        h.alice.deleteMeta(MessageManager.drCtlWatermarkKey(SC))

        // Its legacy integrity control — no "cr" at all — keeps landing with the text
        // ratchet fully locked.
        h.postAsAttacker(h.forgeFromBobsVault(1, MessageManager.CONTROL_KIND_REFERRAL_ACCEPT, REF_ACCEPT_BODY))
        h.postAsAttacker(h.forgeFromBobsVault(2, GroupManager.KIND_ROSTER, ROSTER_BODY, SC_GID))
        assertEquals(
            listOf(MessageManager.CONTROL_KIND_REFERRAL_ACCEPT, GroupManager.KIND_ROSTER),
            h.aliceMgr.pollControlMessages(SC).map { it.controlKind },
            "an un-upgraded peer's legacy integrity control must never be dropped",
        )

        // And we never send it what it would drop: no advert ⇒ legacy, even dr-on.
        assertTrue(h.aliceMgr.sendGroupControl(SC, SC_GID, GroupManager.KIND_ROSTER, ROSTER_BODY, SC_HASH, noPush = true))
        assertTrue(h.aliceMgr.sendDirectControl(SC, MessageManager.CONTROL_KIND_REFERRAL_OFFER, REF_OFFER_BODY))
        val toBob = h.relay.blobsIn(SC_CTL_B)
        assertEquals(2, toBob.size)
        assertTrue(toBob.none { MessageManager.isRatchetWire(it) }, "no sealed control to a peer that never advertised")
    }

    @Test
    fun aWatermarkInALegacyEnvelope_canNeverArmTheLock() {
        if (!scCryptoUp()) return
        val h = ScHarness()
        h.engage()
        h.alice.deleteMeta(MessageManager.drCtlWatermarkKey(SC))
        // A static-key forger plants a commitment of 0…
        h.postAsAttacker(h.forgeFromBobsVault(
            1, GroupManager.KIND_ACTIVITY, "{}", SC_GID,
            extraFields = ""","${MessageManager.CTL_RATCHET_CAP_FIELD}":"1","${MessageManager.CTL_RATCHET_WATERMARK_FIELD}":"0"""",
        ))
        h.aliceMgr.pollControlMessages(SC)
        assertNull(
            h.alice.getMeta(MessageManager.drCtlWatermarkKey(SC)),
            "a watermark is honoured only off a ratchet blob — a legacy one could make us drop an old peer's control",
        )
        // …so a legacy roster above it is still accepted (no lock without ratchet proof).
        h.postAsAttacker(h.forgeFromBobsVault(2, GroupManager.KIND_ROSTER, ROSTER_BODY, SC_GID))
        assertEquals(listOf(GroupManager.KIND_ROSTER), h.aliceMgr.pollControlMessages(SC).map { it.controlKind })
    }

    // -- the control-counter forward-jump cap ---------------------------------------

    @Test
    fun aForgedFarFutureControlCounter_isDropped_andCannotBrickTheChannel() {
        if (!scCryptoUp()) return
        val h = ScHarness()
        h.engage()
        h.postAsAttacker(h.forgeFromBobsVault(Long.MAX_VALUE, GroupManager.KIND_ACTIVITY, "{}", SC_GID))
        h.postAsAttacker(h.forgeFromBobsVault(MessageManager.CTL_COUNTER_MAX_FORWARD_JUMP + 1, GroupManager.KIND_ACTIVITY, "{}", SC_GID))
        assertTrue(h.aliceMgr.pollControlMessages(SC).isEmpty(), "counters past the forward cap must be dropped")
        assertEquals(0L, h.aliceCtlBaseline(), "…without moving the baseline")

        assertTrue(h.bobMgr.sendGroupControl(SC, SC_GID, GroupManager.KIND_ACTIVITY, "{}", SC_HASH, noPush = true))
        assertEquals(
            listOf(GroupManager.KIND_ACTIVITY), h.aliceMgr.pollControlMessages(SC).map { it.controlKind },
            "the genuine control stream must still flow after a far-future forgery",
        )
    }

    @Test
    fun aDeviceMoveCounterJump_isStillAccepted_andTheMovedPeerKeepsSealing() {
        if (!scCryptoUp()) return
        val h = ScHarness()
        h.engage()
        // VaultSnapshotIo.import adds COUNTER_JUMP to every outbound counter on the new
        // phone; the ratchet state and the markers travel with the bundle.
        val c = h.bob.getContact(SC)!!
        val j = MoveConstants.COUNTER_JUMP
        h.bob.insertContact(c.copy(
            outboundCounter = c.outboundCounter + j,
            outboundCtlCounter = c.outboundCtlCounter + j,
            outboundGrpCounter = c.outboundGrpCounter + j,
        ))
        assertTrue(MoveMetaPolicy.isAllowedKey(MessageManager.drCtlCapKey(SC)), "the send gate must travel with a move")
        assertTrue(MoveMetaPolicy.isAllowedKey(MessageManager.drCtlWatermarkKey(SC)), "the receive evidence must travel with a move")

        // A chatty legacy kind from the moved phone lands at counter j + 1.
        assertTrue(h.bobMgr.sendGroupControl(SC, SC_GID, GroupManager.KIND_ACTIVITY, "{}", SC_HASH, noPush = true))
        val act = h.aliceMgr.pollControlMessages(SC).single()
        assertEquals(GroupManager.KIND_ACTIVITY, act.controlKind)
        assertEquals(j + 1, h.aliceCtlBaseline(), "a +COUNTER_JUMP move must pass the forward cap")

        // Integrity control from the moved phone still rides the ratchet and lands…
        assertTrue(h.bobMgr.sendGroupControl(SC, SC_GID, GroupManager.KIND_ROSTER, ROSTER_BODY, SC_HASH, noPush = true))
        assertTrue(MessageManager.isRatchetWire(h.relay.blobsIn(SC_CTL_A).single()))
        assertEquals(listOf(GroupManager.KIND_ROSTER), h.aliceMgr.pollControlMessages(SC).map { it.controlKind })
        // …and a legacy forgery above the (pre-move) commitment is still dropped.
        h.postAsAttacker(h.forgeFromBobsVault(h.bobCtlCounter() + 1, GroupManager.KIND_ROSTER, ROSTER_BODY, SC_GID))
        assertTrue(h.aliceMgr.pollControlMessages(SC).isEmpty())
    }

    // -- the sealed-control catch-up ---------------------------------------------------

    /**
     * ORACLE for the hazard the catch-up exists for. Bob sends a sealed referral offer
     * and keeps chatting; Alice reads the chat (her text drain skips the offer's key)
     * and two reply round trips go by before her control sweep — the second DH step
     * flushes the skipped key, and the offer is lost for good.
     */
    @Test
    fun oracle_withoutTheCatchUp_aLivelyChatFlushesTheSealedBlobsKey() {
        if (!scCryptoUp()) return
        val h = ScHarness()
        h.engage()
        assertTrue(h.bobMgr.sendDirectControl(SC, MessageManager.CONTROL_KIND_REFERRAL_OFFER, REF_OFFER_BODY))
        assertTrue(h.bobMgr.sendMessage(SC, "t1"))
        assertEquals(listOf("t1"), h.aliceMgr.pollMessages(SC).map { it.text })
        repeat(2) { i ->
            assertTrue(h.aliceMgr.sendMessage(SC, "r$i"))
            assertEquals(listOf("r$i"), h.bobMgr.pollMessages(SC).map { it.text })
            assertTrue(h.bobMgr.sendMessage(SC, "t${i + 2}"))
            assertEquals(listOf("t${i + 2}"), h.aliceMgr.pollMessages(SC).map { it.text })
        }
        assertTrue(
            h.aliceMgr.pollControlMessages(SC).isEmpty(),
            "oracle: with the bare transport the sealed offer's skipped key is flushed two DH steps later",
        )
    }

    @Test
    fun catchUp_aStrandedSealedKeyWakesTheIdleControlLoopOnce_andTheSweepDeliversIt() {
        if (!scCryptoUp()) return
        val h = ScHarness()
        h.engage()
        val gm = GroupManager(h.alice) { h.aliceMgr }
        val referrals = mutableListOf<Pair<String, String>>()
        gm.onReferralControl = { _, kind, body -> referrals += kind to body }

        assertTrue(h.bobMgr.sendDirectControl(SC, MessageManager.CONTROL_KIND_REFERRAL_OFFER, REF_OFFER_BODY))
        assertTrue(h.bobMgr.sendMessage(SC, "t1"))
        // The conversation poll itself does NO control I/O (fix 1)…
        assertEquals(listOf("t1"), gm.pollDirect(SC).map { it.text })
        assertEquals(1, h.relay.blobsIn(SC_CTL_A).size, "the UI-awaited poll must not drain the control inbox")
        // …it only marks the contact, which ends the platform loop's IDLE wait once.
        assertTrue(h.aliceMgr.hasPendingSealedControlCatchUp())
        val idle = MessageManager.CONTROL_POLL_IDLE_BASE_MS
        assertTrue(h.aliceMgr.controlPollIdleWaitShouldEnd(idle), "a stranded sealed key must cut the idle wait")
        assertFalse(h.aliceMgr.controlPollIdleWaitShouldEnd(idle), "…exactly once per mark, never a busy loop")

        // The ordinary background sweep then delivers it from the skipped key.
        gm.pollAllControls()
        assertEquals(listOf(MessageManager.CONTROL_KIND_REFERRAL_OFFER to REF_OFFER_BODY), referrals)

        // The same lively chat as the oracle now costs nothing.
        repeat(2) { i ->
            assertTrue(h.aliceMgr.sendMessage(SC, "r$i"))
            assertEquals(listOf("r$i"), h.bobMgr.pollMessages(SC).map { it.text })
            assertTrue(h.bobMgr.sendMessage(SC, "t${i + 2}"))
            assertEquals(listOf("t${i + 2}"), gm.pollDirect(SC).map { it.text })
        }
        assertEquals(1, referrals.size, "delivered exactly once")
    }

    @Test
    fun catchUp_isNotMarked_whenTheTextDrainSkippedNoKeys() {
        if (!scCryptoUp()) return
        val h = ScHarness()
        h.engage()
        repeat(3) { i ->
            assertTrue(h.bobMgr.sendMessage(SC, "in-order-$i"))
            assertEquals(listOf("in-order-$i"), h.aliceMgr.pollMessages(SC).map { it.text })
        }
        assertFalse(h.aliceMgr.hasPendingSealedControlCatchUp(), "an in-order drain strands nothing and must wake nothing")
        assertFalse(h.aliceMgr.controlPollIdleWaitShouldEnd(MessageManager.CONTROL_POLL_IDLE_BASE_MS))
    }

    @Test
    fun catchUp_isNotOwedForALegacyOnlyPairing() {
        if (!scCryptoUp()) return
        val h = ScHarness()
        // No ratchet blob is ever decrypted here, so no catch-up is ever marked.
        h.alice.deleteMeta(MessageManager.drIntentKey(SC))
        h.bob.deleteMeta(MessageManager.drIntentKey(SC))
        repeat(3) { h.roundTrip(it) }
        assertFalse(h.aliceMgr.hasPendingSealedControlCatchUp())
        assertFalse(h.bobMgr.hasPendingSealedControlCatchUp())
    }

    // -- fix 2: an unreadable capability marker fails the send ----------------------

    @Test
    fun capabilityReadThrowing_failsTheSealedSend_insteadOfSendingLegacy() {
        if (!scCryptoUp()) return
        val h = ScHarness()
        h.engage()
        h.bob.throwCapRead = true
        val counterBefore = h.bobCtlCounter()
        assertFalse(
            h.bobMgr.sendGroupControl(SC, SC_GID, GroupManager.KIND_ROSTER, ROSTER_BODY, SC_HASH, noPush = true),
            "an unreadable marker must FAIL a sealed kind (it is redriven), never fall back to legacy",
        )
        assertFalse(h.bobMgr.sendDirectControl(SC, MessageManager.CONTROL_KIND_REFERRAL_ACCEPT, REF_ACCEPT_BODY))
        assertTrue(h.relay.blobsIn(SC_CTL_A).isEmpty(), "nothing may reach the relay")
        assertEquals(counterBefore, h.bobCtlCounter(), "…and no control counter may be burned")
        // A chatty kind is unaffected: it is legacy for every peer anyway.
        assertTrue(h.bobMgr.sendGroupControl(SC, SC_GID, GroupManager.KIND_ACTIVITY, "{}", SC_HASH, noPush = true))
        assertFalse(MessageManager.isRatchetWire(h.relay.blobsIn(SC_CTL_A).single()))
    }

    // -- fix 3: the background sweep never destroys an undrained text backlog -------

    @Test
    fun sweepAheadOfMoreThan128UndrainedTexts_defers_insteadOfEvictingTheirKeys() {
        if (!scCryptoUp()) return
        val h = ScHarness()
        h.engage()
        val backlog = DoubleRatchet.MAX_SKIPPED_STORE + 2
        repeat(backlog) { assertTrue(h.bobMgr.sendMessage(SC, "u$it")) }
        assertTrue(h.bobMgr.sendGroupControl(SC, SC_GID, GroupManager.KIND_ROSTER, ROSTER_BODY, SC_HASH, noPush = true))

        assertTrue(h.aliceMgr.pollControlMessages(SC).isEmpty(), "the roster must be DEFERRED, not decrypted ahead of the backlog")
        val stored = assertNotNull(h.alice.getMeta(MessageManager.drCtlDeferredKey(SC)), "…and kept in the vault")
        assertEquals(
            MessageManager.CTL_DEFER_MAX_AGE_MS.toString(), stored.split(':')[1],
            "unread texts POSITIVELY waiting behind a backlog skip earn the 24 h deferral",
        )

        val texts = h.aliceMgr.pollMessages(SC).map { it.text }
        assertEquals(List(backlog) { "u$it" }, texts, "no undrained text may lose its key to a control sweep")
        assertTrue(h.aliceMgr.hasPendingSealedControlCatchUp(), "draining the backlog must schedule the deferred retry")

        // The background sweep retries it even though the control inbox itself is
        // now EMPTY (its peek answers 0) — a deferral is drained for, not peeked for.
        assertTrue(h.relay.blobsIn(SC_CTL_A).isEmpty())
        val gm = GroupManager(h.alice) { h.aliceMgr }
        gm.pollAllControls()
        assertNull(h.alice.getMeta(MessageManager.drCtlDeferredKey(SC)), "the deferred roster lands on the next sweep and leaves the vault")
    }

    @Test
    fun controlOnlyRoundTrips_neverFlushUndrainedTextKeys() {
        if (!scCryptoUp()) return
        val h = ScHarness()
        h.engage()
        // Two 1:1 texts Alice has not read yet.
        assertTrue(h.bobMgr.sendMessage(SC, "unread-1"))
        assertTrue(h.bobMgr.sendMessage(SC, "unread-2"))
        // invite → join → roster → (another sealed hop) → roster: two receiving DH
        // steps at Alice driven purely by her background control sweep.
        assertTrue(h.bobMgr.sendGroupControl(SC, SC_GID, GroupManager.KIND_INVITE, """{"n":"crew"}""", SC_HASH, noPush = true))
        assertEquals(listOf(GroupManager.KIND_INVITE), h.aliceMgr.pollControlMessages(SC).map { it.controlKind })
        assertTrue(h.aliceMgr.sendGroupControl(SC, SC_GID, GroupManager.KIND_JOIN, """{"tags":""}""", SC_HASH, noPush = true))
        assertEquals(listOf(GroupManager.KIND_JOIN), h.bobMgr.pollControlMessages(SC).map { it.controlKind })
        assertTrue(h.bobMgr.sendGroupControl(SC, SC_GID, GroupManager.KIND_ROSTER, ROSTER_BODY, SC_HASH, noPush = true))
        assertEquals(listOf(GroupManager.KIND_ROSTER), h.aliceMgr.pollControlMessages(SC).map { it.controlKind })
        assertTrue(h.aliceMgr.sendGroupControl(SC, SC_GID, GroupManager.KIND_LEAVE, "{}", SC_HASH, noPush = true))
        assertEquals(listOf(GroupManager.KIND_LEAVE), h.bobMgr.pollControlMessages(SC).map { it.controlKind })
        val roster2 = """{"n":"crew","ep":3,"adm":"m1","mem":[]}"""
        assertTrue(h.bobMgr.sendGroupControl(SC, SC_GID, GroupManager.KIND_ROSTER, roster2, SC_HASH, noPush = true))

        // This hop would DH-step past the chain holding the unread texts' keys.
        assertTrue(h.aliceMgr.pollControlMessages(SC).isEmpty(), "the second receiving step must be deferred")
        assertEquals(
            MessageManager.CTL_DEFER_SHORT_AGE_MS.toString(),
            h.alice.getMeta(MessageManager.drCtlDeferredKey(SC))!!.split(':')[1],
            "an old-chain deferral is held only for the SHORT age",
        )
        assertEquals(listOf("unread-1", "unread-2"), h.aliceMgr.pollMessages(SC).map { it.text }, "the unread texts must survive")
        assertEquals(listOf(roster2), h.aliceMgr.pollControlMessages(SC).map { it.controlBody }, "…and the roster lands right after")
    }

    // -- fix 4: a control-armed lock still gives the text channel its grace ---------

    @Test
    fun textLockArmedByAControlDrain_stillAcceptsTheQueuedGenuineLegacyText() {
        if (!scCryptoUp()) return
        val h = ScHarness()
        h.roundTrip(0)                                  // Alice: one receiving DH step
        assertTrue(h.aliceMgr.sendMessage(SC, "a1"))
        assertEquals(listOf("a1"), h.bobMgr.pollMessages(SC).map { it.text })   // Bob ratchets
        // A pre-flip legacy text from Bob is still queued on Alice's TEXT inbox…
        h.postToAliceText(h.legacyTextFromBob(1, "queued-legacy"))
        // …when Bob's sealed roster (new DH key) is drained by Alice's CONTROL sweep:
        // her 2nd receiving step, so the lock arms THERE.
        assertTrue(h.bobMgr.sendGroupControl(SC, SC_GID, GroupManager.KIND_ROSTER, ROSTER_BODY, SC_HASH, noPush = true))
        assertEquals(listOf(GroupManager.KIND_ROSTER), h.aliceMgr.pollControlMessages(SC).map { it.controlKind })
        assertEquals("1", h.alice.getMeta(MessageManager.drRecvLockKey(SC)), "precondition: armed from a control drain")

        assertEquals(
            listOf("queued-legacy"), h.aliceMgr.pollMessages(SC).map { it.text },
            "M1's one-drain grace must survive the lock being armed by a control drain",
        )
        // The grace is one drain: a legacy text after it is the downgrade and drops.
        h.postToAliceText(h.legacyTextFromBob(2, "late-legacy"))
        assertTrue(h.aliceMgr.pollMessages(SC).isEmpty(), "after the grace drain the M1 lock holds")
    }

    // -- dead skipped keys never park control -----------------------------

    @Test
    fun deadSkippedKeys_withEmptyTextInboxes_doNotDeferTheSealedControl() {
        if (!scCryptoUp()) return
        val h = ScHarness()
        h.engage()
        // Bob's text is LOST (a Tor-dropped send / a text that expired on the relay):
        // Alice will hold a skipped key for it that nothing will ever use.
        assertTrue(h.bobMgr.sendMessage(SC, "lost"))
        h.relay.withholdLast(SC_IN_A)
        assertTrue(h.bobMgr.sendGroupControl(SC, SC_GID, GroupManager.KIND_INVITE, """{"n":"crew"}""", SC_HASH, noPush = true))
        assertEquals(listOf(GroupManager.KIND_INVITE), h.aliceMgr.pollControlMessages(SC).map { it.controlKind })
        assertTrue(h.aliceMgr.sendGroupControl(SC, SC_GID, GroupManager.KIND_JOIN, """{"tags":""}""", SC_HASH, noPush = true))
        h.bobMgr.pollControlMessages(SC)
        assertTrue(h.bobMgr.sendGroupControl(SC, SC_GID, GroupManager.KIND_ROSTER, ROSTER_BODY, SC_HASH, noPush = true))
        assertEquals(listOf(GroupManager.KIND_ROSTER), h.aliceMgr.pollControlMessages(SC).map { it.controlKind })
        assertTrue(h.aliceMgr.sendGroupControl(SC, SC_GID, GroupManager.KIND_LEAVE, "{}", SC_HASH, noPush = true))
        h.bobMgr.pollControlMessages(SC)
        val roster2 = """{"n":"crew","ep":3,"adm":"m1","mem":[]}"""
        assertTrue(h.bobMgr.sendGroupControl(SC, SC_GID, GroupManager.KIND_ROSTER, roster2, SC_HASH, noPush = true))

        // This hop WOULD flush the lost text's key — but both of Alice's text-bearing
        // inboxes peek EMPTY, so the key is provably dead and nothing is deferred.
        assertEquals(
            listOf(roster2), h.aliceMgr.pollControlMessages(SC).map { it.controlBody },
            "a passive member must not have control parked behind a dead skipped key",
        )
        assertNull(h.alice.getMeta(MessageManager.drCtlDeferredKey(SC)))
    }

    // -- only sealed-control-sized wires are ever deferred ---------------

    @Test
    fun anOversizeWire_isNeverDeferred_soJunkCannotBloatTheStore() {
        if (!scCryptoUp()) return
        val h = ScHarness()
        h.engage()
        repeat(DoubleRatchet.MAX_SKIPPED_STORE + 2) { assertTrue(h.bobMgr.sendMessage(SC, "u$it")) }
        // Above the 32 KiB deferrable cap (lands in the 64 KiB padding bucket).
        val big = """{"n":"${"x".repeat(40_000)}","ep":2}"""
        assertTrue(h.bobMgr.sendGroupControl(SC, SC_GID, GroupManager.KIND_ROSTER, big, SC_HASH, noPush = true))
        assertTrue(h.relay.blobsIn(SC_CTL_A).single().size > MessageManager.MAX_DEFERRABLE_CTL_WIRE_BYTES)
        // Past the deferrable size it takes the ordinary decrypt-or-reject path.
        assertEquals(listOf(big), h.aliceMgr.pollControlMessages(SC).map { it.controlBody })
        assertNull(h.alice.getMeta(MessageManager.drCtlDeferredKey(SC)), "an oversize wire must never be stored")
    }

    // -- withdrawal only on a PROVABLY NEWER cap-less envelope ------------

    @Test
    fun preUpgradeCapLessTexts_drainedAfterTheLatch_neverWithdrawIt() {
        if (!scCryptoUp()) return
        val h = ScHarness()
        h.engage()
        // Bob's texts from before an upgrade: cap-less, on the chain Alice is on.
        h.bobMgr.simulatePreSealedControlBuildForTest = true
        assertTrue(h.bobMgr.sendMessage(SC, "old-1"))
        assertTrue(h.bobMgr.sendMessage(SC, "old-2"))
        h.bobMgr.simulatePreSealedControlBuildForTest = false
        // Bob (now upgraded) seals a roster AFTER them; Alice's sweep sees it first,
        // so the two old texts' keys are cached as skipped keys.
        assertTrue(h.bobMgr.sendGroupControl(SC, SC_GID, GroupManager.KIND_ROSTER, ROSTER_BODY, SC_HASH, noPush = true))
        assertEquals(listOf(GroupManager.KIND_ROSTER), h.aliceMgr.pollControlMessages(SC).map { it.controlKind })
        // Alice opens the chat: the stale cap-less texts are drained (from skipped keys).
        assertEquals(listOf("old-1", "old-2"), h.aliceMgr.pollMessages(SC).map { it.text })
        assertEquals("1", h.alice.getMeta(MessageManager.drCtlCapKey(SC)), "a stale cap-less blob must not withdraw the latch")
        assertNotNull(h.alice.getMeta(MessageManager.drCtlWatermarkKey(SC)), "…nor the commitment")

        // Same chain, in order, after the advert was already seen in order: still stale.
        h.bobMgr.simulatePreSealedControlBuildForTest = true
        assertTrue(h.bobMgr.sendMessage(SC, "old-3"))
        h.bobMgr.simulatePreSealedControlBuildForTest = false
        assertEquals(listOf("old-3"), h.aliceMgr.pollMessages(SC).map { it.text })
        assertEquals("1", h.alice.getMeta(MessageManager.drCtlCapKey(SC)), "same-chain cap-less is not provably newer")
    }

    @Test
    fun aRelayWithheldCapLessBlob_servedAloneFromASkippedKey_neverWithdraws() {
        if (!scCryptoUp()) return
        val h = ScHarness()
        h.engage()
        h.bobMgr.simulatePreSealedControlBuildForTest = true
        assertTrue(h.bobMgr.sendMessage(SC, "pre-upgrade"))
        h.bobMgr.simulatePreSealedControlBuildForTest = false
        val withheld = h.relay.withholdLast(SC_IN_A)
        assertTrue(h.bobMgr.sendMessage(SC, "post-upgrade"))
        assertEquals(listOf("post-upgrade"), h.aliceMgr.pollMessages(SC).map { it.text })
        // A full round trip moves Alice onto a NEWER receiving step first…
        assertTrue(h.aliceMgr.sendMessage(SC, "r"))
        assertEquals(listOf("r"), h.bobMgr.pollMessages(SC).map { it.text })
        assertTrue(h.bobMgr.sendMessage(SC, "newer"))
        assertEquals(listOf("newer"), h.aliceMgr.pollMessages(SC).map { it.text })
        // …then the relay serves the withheld cap-less blob alone.
        h.relay.inject(SC_IN_A, withheld)
        assertEquals(listOf("pre-upgrade"), h.aliceMgr.pollMessages(SC).map { it.text })
        assertEquals("1", h.alice.getMeta(MessageManager.drCtlCapKey(SC)), "a skipped-key blob proves nothing about the peer's build")
        assertNotNull(h.alice.getMeta(MessageManager.drCtlWatermarkKey(SC)))
    }

    @Test
    fun aGenuineMoveToAnOlderBuild_capLessOnANewChain_stillWithdraws() {
        if (!scCryptoUp()) return
        val h = ScHarness()
        h.engage()
        // Bob's vault now runs on an older install.
        h.bobMgr.simulatePreSealedControlBuildForTest = true
        assertTrue(h.aliceMgr.sendMessage(SC, "r"))
        assertEquals(listOf("r"), h.bobMgr.pollMessages(SC).map { it.text })
        assertTrue(h.bobMgr.sendMessage(SC, "from-older-build"))   // a NEW chain, no advert
        assertEquals(listOf("from-older-build"), h.aliceMgr.pollMessages(SC).map { it.text })
        assertNull(h.alice.getMeta(MessageManager.drCtlCapKey(SC)), "a cap-less envelope on a newer chain withdraws the latch")
        assertNull(h.alice.getMeta(MessageManager.drCtlWatermarkKey(SC)), "…and the commitment")
        // …so Alice's control to it goes legacy again, and its legacy control lands.
        assertTrue(h.aliceMgr.sendGroupControl(SC, SC_GID, GroupManager.KIND_ROSTER, ROSTER_BODY, SC_HASH, noPush = true))
        assertFalse(MessageManager.isRatchetWire(h.relay.blobsIn(SC_CTL_B).single()))
        h.postAsAttacker(h.forgeFromBobsVault(h.bobCtlCounter() + 1, GroupManager.KIND_ROSTER, ROSTER_BODY, SC_GID))
        assertEquals(listOf(GroupManager.KIND_ROSTER), h.aliceMgr.pollControlMessages(SC).map { it.controlKind })
    }

    // -- a pairing with no control inbox -------------------------------------------------

    @Test
    fun pairingWithoutAControlInbox_sealedControlLandsViaTheTextInbox() {
        if (!scCryptoUp()) return
        val h = ScHarness(withCtl = false)
        h.engage()
        assertTrue(h.bobMgr.sendGroupControl(SC, SC_GID, GroupManager.KIND_ROSTER, ROSTER_BODY, SC_HASH, noPush = true))
        val posted = h.relay.blobsIn(SC_IN_A)
        assertEquals(1, posted.size, "with no control row the roster rides the TEXT inbox")
        assertTrue(MessageManager.isRatchetWire(posted.single()))
        val m = h.aliceMgr.pollMessages(SC).single()
        assertEquals(GroupManager.KIND_ROSTER, m.controlKind)
        assertEquals(ROSTER_BODY, m.controlBody)
    }

    // -- purge + move coupling --------------------------------------------------------

    @Test
    fun newMetaKeys_areInTheSharedPurgeList_andDieWithTheContact() {
        val keys = ratchetMetaKeysForContact(SC)
        assertTrue(MessageManager.drCtlCapKey(SC) in keys)
        assertTrue(MessageManager.drCtlWatermarkKey(SC) in keys)
        assertFalse(MessageManager.drCtlCapKey(SC) in ratchetMetaKeysForContact("other"))

        val v = InMemoryVault()
        v.insertContact(ContactRecord(SC, generateSecureRandom(32), 0, "p", 0L))
        v.putMeta(MessageManager.drCtlCapKey(SC), "1")
        v.putMeta(MessageManager.drCtlWatermarkKey(SC), "7")
        v.deleteContact(SC)
        assertNull(v.getMeta(MessageManager.drCtlCapKey(SC)))
        assertNull(v.getMeta(MessageManager.drCtlWatermarkKey(SC)))
    }

    @Test
    fun aRatchetSealedControlBlob_isNeverMistakenForAText_onTheControlInbox() {
        if (!scCryptoUp()) return
        val h = ScHarness()
        h.engage()
        // A sealed roster surfaces as control with no UI id, and nothing persists a
        // receive count for it.
        assertTrue(h.bobMgr.sendGroupControl(SC, SC_GID, GroupManager.KIND_ROSTER, ROSTER_BODY, SC_HASH, noPush = true))
        val m = assertNotNull(h.aliceMgr.pollControlMessages(SC).singleOrNull())
        assertEquals("", m.dedupeId)
        assertNull(h.alice.getMeta(MessageManager.drRxCounterKey(SC)), "a control drain must not write dr-rxc")
    }

    // -- ratchet receive UI ids: RAM-only, still unique (S3 LOW #3) -------------------

    @Test
    fun ratchetTexts_getDistinctUiIds_andNoReceiveCountIsEverPersisted() {
        if (!scCryptoUp()) return
        val h = ScHarness()
        h.engage()
        assertTrue(h.bobMgr.sendMessage(SC, "x1"))
        assertTrue(h.bobMgr.sendMessage(SC, "x2"))
        val got = h.aliceMgr.pollMessages(SC)
        assertEquals(listOf("x1", "x2"), got.map { it.text })
        assertTrue(got.all { it.dedupeId.startsWith("dr-") }, "ratchet ids keep the dr- namespace: $got")
        assertEquals(2, got.map { it.dedupeId }.toSet().size, "two messages, two ids")
        // engage() alone drained eight ratchet/legacy texts on each side.
        assertNull(h.alice.getMeta(MessageManager.drRxCounterKey(SC)), "no lifetime receive count at rest (Alice)")
        assertNull(h.bob.getMeta(MessageManager.drRxCounterKey(SC)), "no lifetime receive count at rest (Bob)")
    }

    @Test
    fun ratchetUiIds_neverRepeat_acrossARebuiltManager_soTheUiNeverDropsANewMessage() {
        if (!scCryptoUp()) return
        val h = ScHarness()
        h.engage()
        assertTrue(h.bobMgr.sendMessage(SC, "before"))
        val first = h.aliceMgr.pollMessages(SC).single()
        // A Tor restart rebuilds MessageManager over the same vault while the screen
        // keeps its list: the next message must not reuse an id already shown.
        val rebuilt = MessageManager(h.alice, "http://relay.test", h.relay)
        assertTrue(h.bobMgr.sendMessage(SC, "after"))
        val second = rebuilt.pollMessages(SC).single()
        assertEquals("after", second.text)
        // Strictly increasing across instances: a per-instance counter would restart
        // at dr-1 here and collide with the ids the old manager already handed out.
        val n1 = first.dedupeId.removePrefix("dr-").toLong()
        val n2 = second.dedupeId.removePrefix("dr-").toLong()
        assertTrue(n2 > n1, "a rebuilt manager must continue the id sequence: ${first.dedupeId} then ${second.dedupeId}")
    }

    @Test
    fun legacyReceiveCount_isDeletedOnTheNextRatchetTextDrain() {
        if (!scCryptoUp()) return
        val h = ScHarness()
        h.engage()
        // A vault written by an older build still carries the retired count.
        h.alice.putMeta(MessageManager.drRxCounterKey(SC), "17")
        assertTrue(h.bobMgr.sendMessage(SC, "migrate"))
        assertEquals(listOf("migrate"), h.aliceMgr.pollMessages(SC).map { it.text })
        assertNull(h.alice.getMeta(MessageManager.drRxCounterKey(SC)), "migrate-on-write deletes the legacy dr-rxc")
    }

    @Test
    fun purgeList_callsTheKeyBuilders_andTheBytesAreUnchanged() {
        val keys = ratchetMetaKeysForContact(SC)
        assertTrue(VaultRatchetStore.stateKey(SC, MessageManager.RATCHET_TEXT_CHANNEL) in keys)
        assertTrue(MessageManager.drRxCounterKey(SC) in keys, "the retired key is still purged (legacy vaults)")
        // Byte-identical to the strings older builds wrote.
        assertTrue("dr/$SC/text" in keys)
        assertTrue("dr-rxc/$SC" in keys)
        val v = InMemoryVault()
        v.insertContact(ContactRecord(SC, generateSecureRandom(32), 0, "p", 0L))
        v.putMeta(MessageManager.drRxCounterKey(SC), "17")
        v.putMeta(VaultRatchetStore.stateKey(SC, MessageManager.RATCHET_TEXT_CHANNEL), "AAAA")
        v.deleteContact(SC)
        assertNull(v.getMeta(MessageManager.drRxCounterKey(SC)))
        assertNull(v.getMeta(VaultRatchetStore.stateKey(SC, MessageManager.RATCHET_TEXT_CHANNEL)))
    }
}

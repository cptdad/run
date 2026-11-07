package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// Role-collision detection:
// detect a ratchet ROLE COLLISION and refuse the downgrade it produces.
//
// The Double Ratchet's Alice/Bob role is a pure function of two inbox ids, and
// the OUTBOUND one is whatever the peer declared (QR payload or in-band inbox
// announce), so a peer running modified code can put BOTH devices in the same
// role. Two outcomes, and until this change neither was refused:
//
//   both-Bob   — neither side ever holds a sending chain, so every send on both
//                directions falls through to the static sha256(sharedSecret)
//                envelope, forever. No forward secrecy, no post-compromise
//                security: one later vault open decrypts everything an
//                archiving relay kept.
//   both-Alice — both hold sending chains, every blob fails the peer's AEAD, and
//                `dr-legacyfb` (the detector) stays 0 because `tryEncrypt`
//                never returns null. A silent, permanent, bidirectional blackout.
//
// The hostile peer here is modelled the way the original report described it — a
// MODIFIED CLIENT — by pre-seeding its persisted ratchet state with the wrong
// role (`RatchetManager.loadOrInit` loads persisted state without recomputing
// the role, which is exactly what a modified client's own code would do). Both
// managers otherwise run the shipping code over a storing relay double.
// ---------------------------------------------------------------------------

private const val RRC_CID = "c1"
private val RRC_LOW_ID = "A".repeat(32)    // sorts BEFORE the other id
private val RRC_HIGH_ID = "M".repeat(32)   // …which is what makes the role flip
private val RRC_RCAP = "R".repeat(43)
private val RRC_WCAP = "W".repeat(43)

/**
 * Relay double: stores POSTed blobs per inbox, drains on GET (the real relay's
 * `GET /inbox/{id}` semantics), and can selectively blackhole ratchet appends to
 * one inbox or inject junk blobs into it — the two primitives a hostile/failing
 * relay really has (ratchet blobs are self-identifying on the wire).
 */
private class RrcRelay : InboxQueueRelay()

/**
 * Two paired devices over one relay. [victimInbound]/[victimOutbound] decide the
 * VICTIM's role the way production does; the peer's vault is the mirror image, so
 * the honest rule would always give it the opposite role — which is precisely why
 * [armModifiedPeer] has to plant the state a modified client would hold.
 */
private class RrcPair(victimInbound: String, victimOutbound: String) {
    val relay = RrcRelay()
    val secret = generateSecureRandom(32)
    val victimVault = InMemoryVault()
    val peerVault = InMemoryVault()
    val victim: MessageManager
    val peer: MessageManager
    val victimInboxId = victimInbound
    val peerInboxId = victimOutbound

    init {
        provision(victimVault, inId = victimInbound, outId = victimOutbound)
        provision(peerVault, inId = victimOutbound, outId = victimInbound)
        victim = MessageManager(victimVault, "http://relay.test", relay)
        peer = MessageManager(peerVault, "http://relay.test", relay)
        MessageManager.markRatchetCapable(victimVault, RRC_CID)
        MessageManager.markRatchetCapable(peerVault, RRC_CID)
    }

    private fun provision(v: InMemoryVault, inId: String, outId: String) {
        v.insertContact(ContactRecord(RRC_CID, secret, 0, "p", 0L))
        v.insertInboxId(InboxIdRecord(inId, RRC_CID, 0L, Long.MAX_VALUE, "inbound", RRC_RCAP))
        v.insertInboxId(InboxIdRecord(outId, RRC_CID, 0L, Long.MAX_VALUE, "outbound", RRC_WCAP))
    }

    /**
     * The peer's ONE honest-looking bootstrap message: legacy (its own `dr-on` has not
     * flipped yet), so the victim's `dr-rxseen` + `dr-on` flip exactly as in a real
     * pairing. Call this BEFORE [armModifiedPeer] — the bootstrap exchange is legacy on
     * every real pairing, and a planted ratchet role would make it undecryptable.
     */
    fun peerBootstrapsVictim() {
        assertTrue(peer.sendMessage(RRC_CID, "hello"))
        assertEquals(listOf("hello"), victim.pollMessages(RRC_CID).map { it.text })
        assertEquals("1", victimVault.getMeta(MessageManager.drOnKey(RRC_CID)), "victim must be dr-on")
    }

    /**
     * The modified client: plant the peer's persisted ratchet state in the role it
     * WANTS (the role the honest id-order rule would never give it here — this is the
     * "a peer can simply act as the wrong role" half of the problem that no role RULE
     * can prevent), and flip its own send activation so it behaves like a fully
     * engaged peer from here on.
     */
    fun armModifiedPeer(asBob: Boolean) {
        val planted = if (asBob) DoubleRatchet.initAsBob(secret) else DoubleRatchet.initAsAlice(secret)
        val blob = planted.serialize()
        peerVault.putMeta("dr/$RRC_CID/${MessageManager.RATCHET_TEXT_CHANNEL}", encodeBase64(blob))
        planted.wipe()
        blob.secureWipe()
        peerVault.putMeta(MessageManager.drRxSeenKey(RRC_CID), "1")
        peerVault.putMeta(MessageManager.drOnKey(RRC_CID), "1")
    }

    fun ratchetStateBlob(): String? =
        victimVault.getMeta("dr/$RRC_CID/${MessageManager.RATCHET_TEXT_CHANNEL}")
}

class RatchetRoleCollisionTest {

    // -- §6.1 both-Bob: reproduced, then refused ----------------------------

    @Test
    fun bothBobCollision_isReproducedThenRefused() {
        // The victim's inbound sorts BELOW the id the peer declared, so the honest
        // rule makes the victim BOB; the modified peer holds a planted Bob state too.
        val h = RrcPair(victimInbound = RRC_LOW_ID, victimOutbound = RRC_HIGH_ID)
        h.peerBootstrapsVictim()
        h.armModifiedPeer(asBob = true)

        // Every send falls through to the static envelope (the harm), and the
        // consecutive-fallback counter climbs one per send. The sends themselves must
        // still SUCCEED up to and including the one that crosses the threshold — that
        // send IS the evidence, not yet the verdict.
        for (i in 1..MessageManager.RATCHET_FALLBACK_STALL_THRESHOLD) {
            assertTrue(h.victim.sendMessage(RRC_CID, "v$i"), "send $i must still go out")
            assertEquals(i, h.victim.ratchetFallbackCount(RRC_CID), "fallback $i must be counted")
        }
        assertFalse(h.relay.sawRatchetWire, "both-Bob: no ratchet blob can exist in either direction")
        assertEquals(
            MessageManager.RATCHET_FALLBACK_STALL_THRESHOLD, h.relay.pending(h.peerInboxId),
            "all 8 downgraded sends really were delivered (the pre-fix behaviour)",
        )
        assertTrue(h.victim.forwardSecrecyStalled(RRC_CID))
        assertTrue(h.victim.ratchetRefused(RRC_CID), "the threshold must arm the refusal")
        assertEquals("1", h.victimVault.getMeta(MessageManager.drRefusedKey(RRC_CID)), "durable latch")

        // The 9th send FAILS and nothing reaches the relay.
        val ratchetStateBefore = h.ratchetStateBlob()
        val postsBefore = h.relay.posts
        assertFalse(h.victim.sendMessage(RRC_CID, "v9"), "a refused contact must not send on the static envelope")
        assertEquals(postsBefore, h.relay.posts, "a refused send must make no HTTP request at all")
        assertEquals(
            MessageManager.RATCHET_FALLBACK_STALL_THRESHOLD, h.relay.pending(h.peerInboxId),
            "no 9th blob may reach the peer's inbox",
        )

        // …and the refusal touched NOTHING of the ratchet (design §5, last bullet).
        assertNotNull(ratchetStateBefore)
        assertEquals(ratchetStateBefore, h.ratchetStateBlob(), "a refusal must never wipe or re-init dr/<id>/text")
        assertNotNull(h.victimVault.getContact(RRC_CID), "…nor touch the contact")
    }

    @Test
    fun corruptReinit_clearsBothCountersAndTheLatch_soTheRefusalIsReEarnedNotInherited() {
        // onCorruptReinit puts the pairing back at the legacy bootstrap, so it must
        // start clean: BOTH downgrade counters and the latch. Leaving `dr-legacyfb` at
        // the threshold kept ratchetRefused()/forwardSecrecyStalled() true across the
        // re-init and re-armed the latch on the very next fallback (count 9 >= 8).
        val h = RrcPair(victimInbound = RRC_LOW_ID, victimOutbound = RRC_HIGH_ID)
        h.peerBootstrapsVictim()
        h.armModifiedPeer(asBob = true)
        repeat(MessageManager.RATCHET_FALLBACK_STALL_THRESHOLD) { h.victim.sendMessage(RRC_CID, "v$it") }
        assertTrue(h.victim.ratchetRefused(RRC_CID), "precondition: refused")
        assertTrue(h.victim.forwardSecrecyStalled(RRC_CID), "precondition: stalled")

        // A LOCAL disk anomaly: the persisted text ratchet no longer deserializes.
        h.victimVault.putMeta(
            "dr/$RRC_CID/${MessageManager.RATCHET_TEXT_CHANNEL}", encodeBase64(ByteArray(10) { 7 }),
        )
        // The next send loads it, hits onCorruptReinit, and (the fresh Bob state has
        // no sending chain) records ONE fallback against the cleared counter. The
        // send itself is still refused — the latch was read before the attempt.
        h.victim.sendMessage(RRC_CID, "after-corruption")

        assertNull(h.victimVault.getMeta(MessageManager.drRefusedKey(RRC_CID)), "the latch must not re-arm")
        assertTrue(
            h.victim.ratchetFallbackCount(RRC_CID) < MessageManager.RATCHET_FALLBACK_STALL_THRESHOLD,
            "dr-legacyfb must restart from zero, not carry the old count over the threshold",
        )
        assertFalse(h.victim.ratchetRefused(RRC_CID), "the re-created state starts NOT refused")
        assertFalse(h.victim.forwardSecrecyStalled(RRC_CID), "…and not stalled")
        assertNull(h.victimVault.getMeta(MessageManager.drOnKey(RRC_CID)), "dr-on cleared by the re-init")
        // Back at the bootstrap: text goes out again (legacy, uncounted while dr-on is off).
        assertTrue(h.victim.sendMessage(RRC_CID, "legacy-again"), "the re-inited pairing must be able to send")
        assertFalse(h.victim.ratchetRefused(RRC_CID))
    }

    @Test
    fun bothBobRefusal_doesNotBlockControlTrafficOrTheOtherDirection() {
        // Scope check: the refusal stops the TEXT downgrade only. Control traffic is
        // on the static envelope for EVERY contact by design (there is no downgrade to
        // refuse), and blocking it would break group convergence, the referral
        // handshake and the inbox announce a recovery needs.
        val h = RrcPair(victimInbound = RRC_LOW_ID, victimOutbound = RRC_HIGH_ID)
        h.peerBootstrapsVictim()
        h.armModifiedPeer(asBob = true)
        repeat(MessageManager.RATCHET_FALLBACK_STALL_THRESHOLD) { h.victim.sendMessage(RRC_CID, "v$it") }
        assertTrue(h.victim.ratchetRefused(RRC_CID))

        assertFalse(h.victim.sendMessage(RRC_CID, "blocked"), "text is refused")
        assertTrue(
            h.victim.sendInboxAnnounce(RRC_CID, RRC_LOW_ID, RRC_WCAP),
            "a control announce must still be sendable — it is how a re-pair/rotation recovers",
        )
        // Inbound is untouched: a refusal is about what WE send.
        assertTrue(h.peer.sendMessage(RRC_CID, "still-arrives"))
        assertEquals(listOf("still-arrives"), h.victim.pollMessages(RRC_CID).map { it.text })
    }

    // -- §6.2 both-Alice: detected by the NEW counter only ------------------

    @Test
    fun bothAliceCollision_isDetected() {
        // The victim's inbound sorts ABOVE the declared id, so the honest rule makes
        // the victim ALICE; the modified peer plants an Alice state too. Both hold
        // sending chains, so every blob fails the other's AEAD.
        val h = RrcPair(victimInbound = RRC_HIGH_ID, victimOutbound = RRC_LOW_ID)
        h.peerBootstrapsVictim()
        h.armModifiedPeer(asBob = false)

        // The victim's sends SUCCEED (it has a sending chain) and are real ratchet
        // wire — this is the case the detector is structurally blind to.
        repeat(MessageManager.RATCHET_SENDS_BEFORE_UNACKED_EVIDENCE) { i ->
            assertTrue(h.victim.sendMessage(RRC_CID, "v$i"))
        }
        assertTrue(h.relay.sawRatchetWire, "both-Alice: the victim really does emit ratchet blobs")
        assertEquals(0, h.victim.ratchetUnackedCount(RRC_CID), "no inbound drain yet ⇒ no evidence yet")

        // The peer answers with ratchet blobs of its own that can never decrypt here.
        for (i in 1..MessageManager.RATCHET_UNACKED_REFUSE_THRESHOLD) {
            assertTrue(h.peer.sendMessage(RRC_CID, "m$i"))
            assertEquals(
                emptyList(), h.victim.pollMessages(RRC_CID).map { it.text },
                "a both-Alice blob can never be decrypted — this is the silent blackout",
            )
            assertEquals(i, h.victim.ratchetUnackedCount(RRC_CID), "unacked receive $i must be counted")
        }

        assertTrue(h.victim.ratchetRefused(RRC_CID), "the both-Alice collision must now be refused")
        assertEquals("1", h.victimVault.getMeta(MessageManager.drRefusedKey(RRC_CID)))
        // The point of the new detector: the OLD one never moves in this case.
        assertEquals(0, h.victim.ratchetFallbackCount(RRC_CID), "dr-legacyfb is blind to both-Alice")
        assertFalse(h.victim.forwardSecrecyStalled(RRC_CID), "…so the stall signal alone would never fire")

        // A ratchet send that SUCCEEDS is never blocked — the refusal gates the
        // downgrade, not the secure path (which here is broken at the peer, not here).
        assertTrue(h.victim.sendMessage(RRC_CID, "still-ratchets"), "a working tryEncrypt must never be blocked")
        // And the refusal still never touched the ratchet state.
        assertNotNull(h.ratchetStateBlob())
    }

    @Test
    fun unackedCounter_needsOurOwnRatchetSendsFirst() {
        // Absence is never evidence: a contact with no outstanding ratchet sends can
        // receive any number of non-ratchet drains without arming anything. This is
        // what keeps the both-Bob bootstrap (0 ratchet sends, by definition) off the
        // both-Alice detector, and an ordinary legacy-only pairing off it entirely.
        val h = RrcPair(victimInbound = RRC_HIGH_ID, victimOutbound = RRC_LOW_ID)
        h.peerBootstrapsVictim()
        h.armModifiedPeer(asBob = false)

        repeat(MessageManager.RATCHET_UNACKED_REFUSE_THRESHOLD + 2) {
            h.relay.injectJunk(h.victimInboxId)
            h.victim.pollMessages(RRC_CID)
        }
        assertEquals(0, h.victim.ratchetUnackedCount(RRC_CID), "no ratchet sends outstanding ⇒ no evidence")
        assertFalse(h.victim.ratchetRefused(RRC_CID))

        // One send short of the evidence floor is still not enough.
        repeat(MessageManager.RATCHET_SENDS_BEFORE_UNACKED_EVIDENCE - 1) { h.victim.sendMessage(RRC_CID, "v$it") }
        h.relay.injectJunk(h.victimInboxId)
        h.victim.pollMessages(RRC_CID)
        assertEquals(0, h.victim.ratchetUnackedCount(RRC_CID), "below the floor ⇒ still no evidence")

        // The floor itself arms counting.
        h.victim.sendMessage(RRC_CID, "v-floor")
        h.relay.injectJunk(h.victimInboxId)
        h.victim.pollMessages(RRC_CID)
        assertEquals(1, h.victim.ratchetUnackedCount(RRC_CID), "at the floor ⇒ counted")
    }

    @Test
    fun emptyDrains_areNeverEvidence() {
        // An idle conversation polls ~1 Hz with a conversation open. An empty inbox
        // says nothing about anybody's role, so it must never move the counter —
        // otherwise every quiet contact would refuse itself within seconds.
        val h = RrcPair(victimInbound = RRC_HIGH_ID, victimOutbound = RRC_LOW_ID)
        h.peerBootstrapsVictim()
        h.armModifiedPeer(asBob = false)
        repeat(MessageManager.RATCHET_SENDS_BEFORE_UNACKED_EVIDENCE + 2) { h.victim.sendMessage(RRC_CID, "v$it") }

        repeat(50) { assertEquals(emptyList(), h.victim.pollMessages(RRC_CID).map { it.text }) }

        assertEquals(0, h.victim.ratchetUnackedCount(RRC_CID), "an empty drain is not evidence")
        assertFalse(h.victim.ratchetRefused(RRC_CID))
    }

    // -- §6.4 an inbound ratchet blob clears the refusal --------------------

    @Test
    fun inboundRatchetBlob_clearsTheRefusal() {
        // HONEST roles (the victim is the responder/Bob, the peer the initiator), but
        // the relay blackholes every ratchet append to the victim — the attack.
        // The victim is pinned on legacy, arms the refusal, and then the relay relents:
        // one decryptable ratchet blob must restore the conversation with NO user
        // action, because a refusal a relay can force must also be one it cannot hold.
        val h = RrcPair(victimInbound = RRC_LOW_ID, victimOutbound = RRC_HIGH_ID)
        h.relay.dropRatchetTo.add(h.victimInboxId)
        h.peerBootstrapsVictim()

        repeat(MessageManager.RATCHET_FALLBACK_STALL_THRESHOLD) { i ->
            assertTrue(h.victim.sendMessage(RRC_CID, "v$i"))
            assertEquals(listOf("v$i"), h.peer.pollMessages(RRC_CID).map { it.text })
            assertTrue(h.peer.sendMessage(RRC_CID, "dropped$i"))            // ratchet → blackholed
            assertEquals(emptyList(), h.victim.pollMessages(RRC_CID).map { it.text })
        }
        assertTrue(h.victim.ratchetRefused(RRC_CID), "a permanently pinned direction must be refused")
        assertFalse(h.victim.sendMessage(RRC_CID, "refused"), "…and its next legacy send must fail")

        // The relay stops dropping. One ratchet blob lands on the ordinary poll.
        h.relay.dropRatchetTo.clear()
        assertTrue(h.peer.sendMessage(RRC_CID, "recovered"))
        assertEquals(listOf("recovered"), h.victim.pollMessages(RRC_CID).map { it.text })

        assertFalse(h.victim.ratchetRefused(RRC_CID), "an inbound ratchet blob must clear the refusal at once")
        assertNull(h.victimVault.getMeta(MessageManager.drRefusedKey(RRC_CID)), "the latch is deleted, not kept at 0")
        assertEquals(0, h.victim.ratchetFallbackCount(RRC_CID))
        assertEquals(0, h.victim.ratchetUnackedCount(RRC_CID))

        // The conversation works again, forward-secret this time.
        assertTrue(h.victim.sendMessage(RRC_CID, "after"))
        assertEquals(listOf("after"), h.peer.pollMessages(RRC_CID).map { it.text })
    }

    @Test
    fun refusalIsClearedByARePair() {
        // The other documented way out. `deleteContact` purges the whole per-contact
        // set on BOTH platforms through ratchetMetaKeysForContact, so a re-pair can
        // never inherit the old pairing's verdict.
        val h = RrcPair(victimInbound = RRC_LOW_ID, victimOutbound = RRC_HIGH_ID)
        h.peerBootstrapsVictim()
        h.armModifiedPeer(asBob = true)
        repeat(MessageManager.RATCHET_FALLBACK_STALL_THRESHOLD) { h.victim.sendMessage(RRC_CID, "v$it") }
        assertTrue(h.victim.ratchetRefused(RRC_CID))

        h.victimVault.deleteContact(RRC_CID)

        assertNull(h.victimVault.getMeta(MessageManager.drRefusedKey(RRC_CID)))
        assertNull(h.victimVault.getMeta(MessageManager.drRatUnackedKey(RRC_CID)))
        assertNull(h.victimVault.getMeta(MessageManager.drLegacyFallbackKey(RRC_CID)))
        assertFalse(h.victim.ratchetRefused(RRC_CID), "a re-paired contact starts clean")
    }

    // -- §6.3 the gate: an honest pairing must NEVER refuse -----------------

    @Test
    fun honestPairing_neverRefuses() {
        // 200 messages both directions over a real bootstrap, including the
        // responder's pre-ratchet legacy fallbacks and one relay-dropped ratchet burst
        // that later recovers. Nothing here may refuse anything, and both counters
        // must come back to 0. This is the gate before any device run: a too-tight
        // threshold would show up as a mid-suite send failure on cross:multi.
        val relay = RrcRelay()
        val secret = generateSecureRandom(32)
        val vaultA = InMemoryVault(); val vaultB = InMemoryVault()
        val idA = "A".repeat(32)   // A inbound / B outbound  ⇒ A is the responder (Bob)
        val idB = "B".repeat(32)   // B inbound / A outbound  ⇒ B is the initiator (Alice)
        fun provision(v: InMemoryVault, inId: String, outId: String) {
            v.insertContact(ContactRecord(RRC_CID, secret, 0, "p", 0L))
            v.insertInboxId(InboxIdRecord(inId, RRC_CID, 0L, Long.MAX_VALUE, "inbound", RRC_RCAP))
            v.insertInboxId(InboxIdRecord(outId, RRC_CID, 0L, Long.MAX_VALUE, "outbound", RRC_WCAP))
        }
        provision(vaultA, idA, idB)
        provision(vaultB, idB, idA)
        val a = MessageManager(vaultA, "http://relay.test", relay)
        val b = MessageManager(vaultB, "http://relay.test", relay)
        MessageManager.markRatchetCapable(vaultA, RRC_CID)
        MessageManager.markRatchetCapable(vaultB, RRC_CID)

        var deliveredToA = 0
        var deliveredToB = 0
        fun assertNobodyRefuses(where: String) {
            assertFalse(a.ratchetRefused(RRC_CID), "responder refused an honest pairing at $where")
            assertFalse(b.ratchetRefused(RRC_CID), "initiator refused an honest pairing at $where")
        }

        // Bootstrap, in the order that actually produces the responder's counted
        // pre-ratchet fallback: the initiator speaks first on the legacy envelope (its
        // own dr-on has not flipped), which flips the RESPONDER's dr-on — so the
        // responder's next send takes the ratchet branch, finds no sending chain, and
        // falls back. That fallback is real and must be counted…
        assertTrue(b.sendMessage(RRC_CID, "b-boot"))
        deliveredToA += a.pollMessages(RRC_CID).size
        assertEquals("1", vaultA.getMeta(MessageManager.drOnKey(RRC_CID)))
        assertTrue(a.sendMessage(RRC_CID, "a-boot"))
        assertEquals(1, a.ratchetFallbackCount(RRC_CID), "the responder's pre-ratchet fallback must be counted")
        deliveredToB += b.pollMessages(RRC_CID).size
        // …and cleared the moment the ratchet really engages.
        assertTrue(b.sendMessage(RRC_CID, "b-boot2"))
        deliveredToA += a.pollMessages(RRC_CID).size
        assertEquals(0, a.ratchetFallbackCount(RRC_CID), "one ratchet receive clears the bootstrap fallbacks")
        assertNobodyRefuses("bootstrap")

        // 100 full rounds = 200 messages, every one of which must be delivered.
        repeat(100) { i ->
            assertTrue(a.sendMessage(RRC_CID, "a$i"), "honest send a$i must not be refused")
            val gotB = b.pollMessages(RRC_CID)
            assertEquals(listOf("a$i"), gotB.map { it.text })
            deliveredToB += gotB.size
            assertTrue(b.sendMessage(RRC_CID, "b$i"), "honest send b$i must not be refused")
            val gotA = a.pollMessages(RRC_CID)
            assertEquals(listOf("b$i"), gotA.map { it.text })
            deliveredToA += gotA.size
            if (i % 25 == 0) assertNobodyRefuses("round $i")
        }
        assertTrue(relay.sawRatchetWire, "the ratchet must really have engaged (not a legacy-only run)")
        assertEquals(102, deliveredToA, "every message sent to the responder must have arrived")
        assertEquals(101, deliveredToB, "every message sent to the initiator must have arrived")

        // A relay burst: it blackholes B's ratchet blobs to A and serves A junk in
        // their place. The counter MOVES (proving the detector is live in this test,
        // not vacuously asleep) but never reaches the threshold.
        relay.dropRatchetTo.add(idA)
        repeat(8) { i ->
            assertTrue(a.sendMessage(RRC_CID, "burst$i"))
            assertEquals(listOf("burst$i"), b.pollMessages(RRC_CID).map { it.text })
            assertTrue(b.sendMessage(RRC_CID, "lost$i"))          // blackholed
            relay.injectJunk(idA)                                  // …and replaced with junk
            assertEquals(emptyList(), a.pollMessages(RRC_CID).map { it.text })
            assertNobodyRefuses("burst round $i")
        }
        val duringBurst = a.ratchetUnackedCount(RRC_CID)
        assertTrue(duringBurst > 0, "the burst must actually produce evidence — otherwise this test proves nothing")
        assertTrue(
            duringBurst < MessageManager.RATCHET_UNACKED_REFUSE_THRESHOLD,
            "a recoverable burst of this length must stay under the threshold (got $duringBurst)",
        )

        // The relay recovers. One decryptable ratchet blob clears everything.
        relay.dropRatchetTo.clear()
        assertTrue(b.sendMessage(RRC_CID, "b-recovered"))
        assertEquals(listOf("b-recovered"), a.pollMessages(RRC_CID).map { it.text })

        assertEquals(0, a.ratchetUnackedCount(RRC_CID), "counters must return to 0 after recovery")
        assertEquals(0, a.ratchetFallbackCount(RRC_CID))
        assertEquals(0, b.ratchetUnackedCount(RRC_CID))
        assertEquals(0, b.ratchetFallbackCount(RRC_CID))
        assertNobodyRefuses("after recovery")
        assertNull(vaultA.getMeta(MessageManager.drRefusedKey(RRC_CID)))
        assertNull(vaultB.getMeta(MessageManager.drRefusedKey(RRC_CID)))

        // …and the conversation keeps working in both directions.
        assertTrue(a.sendMessage(RRC_CID, "a-final"))
        assertEquals(listOf("a-final"), b.pollMessages(RRC_CID).map { it.text })
        assertTrue(b.sendMessage(RRC_CID, "b-final"))
        assertEquals(listOf("b-final"), a.pollMessages(RRC_CID).map { it.text })
    }

    @Test
    fun legacyOnlyPairing_neverRefuses() {
        // A contact that never became ratchet-capable (paired under an older build)
        // stays on the static envelope forever BY DESIGN. It must never be refused:
        // neither counter may move for it, whatever the traffic looks like.
        val relay = RrcRelay()
        val secret = generateSecureRandom(32)
        val vaultA = InMemoryVault(); val vaultB = InMemoryVault()
        val idA = "A".repeat(32); val idB = "B".repeat(32)
        fun provision(v: InMemoryVault, inId: String, outId: String) {
            v.insertContact(ContactRecord(RRC_CID, secret, 0, "p", 0L))
            v.insertInboxId(InboxIdRecord(inId, RRC_CID, 0L, Long.MAX_VALUE, "inbound", RRC_RCAP))
            v.insertInboxId(InboxIdRecord(outId, RRC_CID, 0L, Long.MAX_VALUE, "outbound", RRC_WCAP))
        }
        provision(vaultA, idA, idB)
        provision(vaultB, idB, idA)
        val a = MessageManager(vaultA, "http://relay.test", relay)
        val b = MessageManager(vaultB, "http://relay.test", relay)
        // No markRatchetCapable on either side.

        repeat(20) { i ->
            assertTrue(a.sendMessage(RRC_CID, "a$i"))
            assertEquals(listOf("a$i"), b.pollMessages(RRC_CID).map { it.text })
            assertTrue(b.sendMessage(RRC_CID, "b$i"))
            assertEquals(listOf("b$i"), a.pollMessages(RRC_CID).map { it.text })
        }
        assertFalse(relay.sawRatchetWire, "precondition: a pure legacy pairing")
        assertFalse(a.ratchetRefused(RRC_CID))
        assertFalse(b.ratchetRefused(RRC_CID))
        assertEquals(0, a.ratchetUnackedCount(RRC_CID))
        assertEquals(0, a.ratchetFallbackCount(RRC_CID))
    }

    // -- the reads themselves ------------------------------------------------

    @Test
    fun refusalReads_failTowardNotRefused_onAnAbsentOrUnreadableVault() {
        // Brick-safety direction: absence is NOT refusal. A fresh vault, an unknown
        // contact and a vault whose `_meta` read throws must all answer false — a
        // false "refused" would stop a healthy conversation and tell the user to
        // re-pair, while a false "fine" costs at most one more legacy send at the
        // level the pairing is already running at.
        val fresh = InMemoryVault()
        val mgr = MessageManager(fresh, "http://relay.test", RrcRelay())
        assertFalse(mgr.ratchetRefused("nobody"))
        assertEquals(0, mgr.ratchetUnackedCount("nobody"))

        val throwing = object : InMemoryVault() {
            override fun getMeta(key: String): String? = throw IllegalStateException("vault unavailable")
        }
        val throwingMgr = MessageManager(throwing, "http://relay.test", RrcRelay())
        assertFalse(throwingMgr.ratchetRefused(RRC_CID), "an unreadable vault must never refuse")
        assertEquals(0, throwingMgr.ratchetUnackedCount(RRC_CID))
    }

    @Test
    fun refusalSurvivesANewManagerOverTheSameVault() {
        // The latch is vault state, not session state: the UI reads it at unlock,
        // through a MessageManager that did not observe the collision.
        val h = RrcPair(victimInbound = RRC_LOW_ID, victimOutbound = RRC_HIGH_ID)
        h.peerBootstrapsVictim()
        h.armModifiedPeer(asBob = true)
        repeat(MessageManager.RATCHET_FALLBACK_STALL_THRESHOLD) { h.victim.sendMessage(RRC_CID, "v$it") }

        val fresh = MessageManager(h.victimVault, "http://relay.test", h.relay)
        assertTrue(fresh.ratchetRefused(RRC_CID))
        assertFalse(fresh.sendMessage(RRC_CID, "still-refused"))
    }

    // A11 pin: the corrupt-state re-init clears exactly these eight latches, in this
    // order, and never `dr-intent` (deleting it would revert the pairing to the static
    // envelope until a manual re-pair).
    @Test
    fun reinitResetKeys_areExactlyTheEightLatches_andNeverTheIntent() {
        val id = "contact-x"
        val keys = MessageManager.ratchetReinitResetKeys(id)
        assertEquals(
            listOf(
                MessageManager.drRecvLockKey(id),
                MessageManager.drRecvLockGraceKey(id),
                MessageManager.drCtlCapStepKey(id),
                MessageManager.drOnKey(id),
                MessageManager.drRxSeenKey(id),
                MessageManager.drLegacyFallbackKey(id),
                MessageManager.drRatUnackedKey(id),
                MessageManager.drRefusedKey(id),
            ),
            keys,
        )
        assertFalse(MessageManager.drIntentKey(id) in keys, "dr-intent must survive a re-init")
        assertTrue(keys.all { it in ratchetMetaKeysForContact(id) }, "every reset key is also purged with the contact")
    }
}

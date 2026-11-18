package com.vg.run

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// The v3 bootstrap's forward-secrecy acceptance test at the ratchet layer
// (docs/ratchet-bootstrap-plan.md §2 G-B and §7).
//
// The attacker ([V3BootstrapOracle]) gets EVERYTHING that remains after the
// recipients have decrypted (= committed, at this layer): both serialized ratchet
// states, the stored pairing secret `ss'` from both sides, both QR codes (secret
// halves + one-time public keys) and every recorded wire with its header. It then
// runs the derivation program and AES-GCM-opens every wire with its real AAD.
//
// Expected for v3: nothing opens. The NON-VACUITY controls below prove the same
// oracle DOES open messages wherever a key is genuinely recoverable — without
// them "nothing opens" would prove nothing:
//   - the legacy bootstrap (the phase-0 control's attack, rerun through this oracle;
//     RatchetBootstrapRecoverabilityTest stays as the end-to-end control);
//   - v3, Bob snapshotted BEFORE his first receive: the documented residual window
//     (§3.2) — Alice's in-flight messages open, Bob's own pre-chain never does;
//   - v3 with one side's one-time private key left unwiped (test-only: the fixture
//     keeps a copy).
// The REFERRAL bootstrap (phase 3) has its own section at the end: after commit nothing
// opens; the `ref_p` window opens exactly what was sent to the unfinalized side; controls
// for the legacy referral and for a leaked referral one-time key.
// Not covered here (needs the pairing/vault layers, phase 2): the "§3.3 off"
// static-control case, a pending (uncommitted) drain, group fan-out, move bundles.
// ---------------------------------------------------------------------------
class RatchetBootstrapForwardSecrecyTest {

    private fun up() = aeadUp() && x25519Up()

    private fun snapshot(p: V3Pairing, wire: RecordingWire, extraLeaks: List<ByteArray> = emptyList()) =
        V3BootstrapOracle.Snapshot(
            ratchetBlobs = listOf(p.a.ratchet.serialize(), p.b.ratchet.serialize()),
            storedSecrets = listOf(p.a.ready.pairingSecret, p.b.ready.pairingSecret) + extraLeaks,
            qrHalves = p.qrHalves,
            qrPublicKeys = p.qrPublicKeys,
            bodies = wire.bodies,
        )

    /** Three each way; the initiator writes first. Returns every text sent. */
    private fun initiatorFirst(p: V3Pairing, wire: RecordingWire): List<String> {
        val sent = mutableListOf<String>()
        val a = (0 until 3).map { "alice $it" }.onEach { sent += it }.map { wire.send(p.alice.ratchet, it) }
        a.forEachIndexed { i, m -> assertEquals("alice $i", p.bob.ratchet.receive(m)) }
        val b = (0 until 3).map { "bob $it" }.onEach { sent += it }.map { wire.send(p.bob.ratchet, it) }
        b.forEachIndexed { i, m -> assertEquals("bob $i", p.alice.ratchet.receive(m)) }
        return sent
    }

    /** Three each way; the responder writes first, on the pre-chain. */
    private fun responderFirst(p: V3Pairing, wire: RecordingWire): List<String> {
        val sent = mutableListOf<String>()
        val b = (0 until 3).map { "bob $it" }.onEach { sent += it }.map { wire.send(p.bob.ratchet, it) }
        b.forEachIndexed { i, m -> assertEquals("bob $i", p.alice.ratchet.receive(m)) }
        val a = (0 until 3).map { "alice $it" }.onEach { sent += it }.map { wire.send(p.alice.ratchet, it) }
        a.forEachIndexed { i, m -> assertEquals("alice $i", p.bob.ratchet.receive(m)) }
        return sent
    }

    // --- the property ----------------------------------------------------------------

    // Both roles x both send orders, pinned (side A = the device listed first everywhere).
    private fun nothingOpens(aIsBob: Boolean, responderWritesFirst: Boolean) {
        val p = V3PairingFixture.pairWithAAs(bob = aIsBob)
        assertEquals(aIsBob, p.a.isBob)
        val wire = RecordingWire()
        if (responderWritesFirst) responderFirst(p, wire) else initiatorFirst(p, wire)
        assertEquals(emptyList(), V3BootstrapOracle.open(snapshot(p, wire)))
    }

    @Test
    fun v3_initiatorWritesFirst_afterCommit_nothingOpens() {
        if (!up()) return
        nothingOpens(aIsBob = false, responderWritesFirst = false)
    }

    @Test
    fun v3_initiatorWritesFirst_sideAIsTheResponder_afterCommit_nothingOpens() {
        if (!up()) return
        nothingOpens(aIsBob = true, responderWritesFirst = false)
    }

    @Test
    fun v3_responderWritesFirstOnThePreChain_afterCommit_nothingOpens() {
        if (!up()) return
        nothingOpens(aIsBob = true, responderWritesFirst = true)
    }

    @Test
    fun v3_responderWritesFirstOnThePreChain_sideAIsTheInitiator_afterCommit_nothingOpens() {
        if (!up()) return
        nothingOpens(aIsBob = false, responderWritesFirst = true)
    }

    /**
     * The pn-skipped pre-chain (mirrors RatchetBootstrapV3Test.preChainThenBobsFirstDhChain):
     * pre0, then Bob's first DH chain c0 caches the keys of pre1/pre2 at Alice. With those
     * skipped keys stored, exactly pre1 and pre2 open (the documented in-flight exposure);
     * once both are consumed, nothing does.
     */
    @Test
    fun v3_pnSkippedPreChain_skippedKeysOpenOnlyTheirOwnMessages_andNothingOnceConsumed() {
        if (!up()) return
        val p = V3PairingFixture.pair()
        val wire = RecordingWire()
        val pre = (0 until 3).map { wire.send(p.bob.ratchet, "bob pre $it") }
        assertEquals("bob pre 0", p.alice.ratchet.receive(pre[0]))
        assertEquals("alice 0", p.bob.ratchet.receive(wire.send(p.alice.ratchet, "alice 0")))
        val c0 = wire.send(p.bob.ratchet, "bob dh 0")
        assertEquals("bob dh 0", p.alice.ratchet.receive(c0))
        assertEquals(2, p.alice.ratchet.skippedKeyCount())
        assertEquals(listOf("bob pre 1", "bob pre 2"), V3BootstrapOracle.open(snapshot(p, wire)))

        assertEquals("bob pre 2", p.alice.ratchet.receive(pre[2]))
        assertEquals("bob pre 1", p.alice.ratchet.receive(pre[1]))
        assertEquals(0, p.alice.ratchet.skippedKeyCount())
        assertEquals(emptyList(), V3BootstrapOracle.open(snapshot(p, wire)))
    }

    /**
     * Alice keeps neither rk0 nor rB_seed (plan §3.2 "Alice wipes rk0 and rB_seed"). Two
     * angles, neither needing a production hook: (1) recompute both from a test-kept copy
     * of the one-time key and look for them anywhere in Alice's serialized state and in
     * what bootstrap returned to her; (2) the oracle given ONLY Alice's vault opens Bob's
     * pre-chain messages while they are in flight (her receiving chain — inherent) but
     * never her own sent messages, which rk0 + rB_seed would open.
     * (The in-RAM wipe of the transient copies inside bootstrap is not observable without
     * a production seam; it stays reasoned-only.)
     */
    @Test
    fun v3_aliceRetainsNeitherRk0NorRbSeed() {
        if (!up()) return
        val p = V3PairingFixture.pair(leakBoth = true)
        val s = x25519Ecdh(p.alice.leakedEphemeralPriv!!, p.bob.ephemeralPub)
        val d = V3BootstrapOracle.deriveV3(s, p.ssHalves, p.qrPublicKeys)
        val rk0 = d.getValue("root"); val seed = d.getValue("bob-key")
        fun containsWindow(hay: ByteArray, needle: ByteArray) =
            (0..hay.size - needle.size).any { o -> needle.indices.all { hay[o + it] == needle[it] } }
        fun assertAbsent(where: String, blob: ByteArray) {
            assertFalse(containsWindow(blob, rk0), "rk0 found in $where")
            assertFalse(containsWindow(blob, seed), "rB_seed found in $where")
        }
        assertAbsent("Alice's state at birth", p.alice.ratchet.serialize())
        assertAbsent("Alice's stored pairing secret", p.alice.ready.pairingSecret)
        // Control: Bob's state at birth DOES hold both (so the search is not blind).
        val bobBlob = p.bob.ratchet.serialize()
        assertTrue(containsWindow(bobBlob, rk0) && containsWindow(bobBlob, seed))

        val wire = RecordingWire()
        val bobSent = (0 until 3).map { "bob pre $it" }
        val bobWires = bobSent.map { wire.send(p.bob.ratchet, it) }
        (0 until 3).forEach { wire.send(p.alice.ratchet, "alice $it") }
        assertAbsent("Alice's state after sending", p.alice.ratchet.serialize())
        fun aliceOnly() = V3BootstrapOracle.open(
            V3BootstrapOracle.Snapshot(
                ratchetBlobs = listOf(p.alice.ratchet.serialize()),
                storedSecrets = listOf(p.alice.ready.pairingSecret),
                qrHalves = p.qrHalves,
                qrPublicKeys = p.qrPublicKeys,
                bodies = wire.bodies,
            ),
        )
        assertEquals(bobSent, aliceOnly(), "only Bob's in-flight pre-chain opens, never Alice's own first chain")
        bobWires.forEachIndexed { i, m -> assertEquals("bob pre $i", p.alice.ratchet.receive(m)) }
        assertAbsent("Alice's state after receiving", p.alice.ratchet.serialize())
        assertEquals(emptyList(), aliceOnly())
    }

    @Test
    fun v3_simultaneousFirstSends_thenThreeEachWay_afterCommit_nothingOpens() {
        if (!up()) return
        val p = V3PairingFixture.pair()
        val wire = RecordingWire()
        val a0 = wire.send(p.alice.ratchet, "alice first")
        val b0 = wire.send(p.bob.ratchet, "bob first")
        assertEquals("bob first", p.alice.ratchet.receive(b0))
        assertEquals("alice first", p.bob.ratchet.receive(a0))
        initiatorFirst(p, wire)
        assertEquals(emptyList(), V3BootstrapOracle.open(snapshot(p, wire)))
    }

    // --- non-vacuity controls ---------------------------------------------------------

    @Test
    fun control_legacyBootstrap_sameOracleOpensEverything() {
        if (!up()) return
        val halfA = generateSecureRandom(32)
        val halfB = generateSecureRandom(32)
        val ss = deriveSharedSecret(halfA, halfB)
        val alice = DoubleRatchet.initAsAlice(ss)
        val bob = DoubleRatchet.initAsBob(ss)
        val wire = RecordingWire()
        val sent = mutableListOf<String>()
        (0 until 3).map { "alice $it" }.onEach { sent += it }.map { wire.send(alice, it) }.forEach { bob.receive(it) }
        (0 until 3).map { "bob $it" }.onEach { sent += it }.map { wire.send(bob, it) }.forEach { alice.receive(it) }
        val opened = V3BootstrapOracle.open(
            V3BootstrapOracle.Snapshot(
                ratchetBlobs = listOf(alice.serialize(), bob.serialize()),
                storedSecrets = listOf(ss),
                qrHalves = listOf(halfA, halfB),
                qrPublicKeys = emptyList(),
                bodies = wire.bodies,
            ),
        )
        assertEquals(
            sent, opened,
            "the oracle must recover the legacy first epoch (and walk on to the responder's chain) — otherwise " +
                "its empty answer for v3 would prove nothing",
        )
    }

    @Test
    fun control_v3BobBeforeHisFirstReceive_opensAlicesInFlightMessages_neverHisOwnPreChain() {
        if (!up()) return
        val p = V3PairingFixture.pair()
        val wire = RecordingWire()
        val bobSent = (0 until 3).map { "bob pre $it" }.onEach { wire.send(p.bob.ratchet, it) }
        val aliceSent = (0 until 3).map { "alice $it" }
        val aliceWires = aliceSent.map { wire.send(p.alice.ratchet, it) }
        // Bob's vault only (+ both QR codes, his stored secret, every wire).
        fun bobOnly() = V3BootstrapOracle.open(
            V3BootstrapOracle.Snapshot(
                ratchetBlobs = listOf(p.bob.ratchet.serialize()),
                storedSecrets = listOf(p.bob.ready.pairingSecret),
                qrHalves = p.qrHalves,
                qrPublicKeys = p.qrPublicKeys,
                bodies = wire.bodies,
            ),
        )
        val before = bobOnly()
        assertEquals(aliceSent, before, "the §3.2 residual window: rk0 + rB_seed open Alice's not-yet-committed messages")
        assertTrue(bobSent.none { it in before }, "Bob's own pre-chain is an independent HKDF output and never opens")

        // The bootstrap window closes with Bob's first committed receive: rk0 and rB_seed
        // are gone. What still opens is only what any ratchet exposes — the not-yet-committed
        // messages of the CURRENT receiving chain (plan §2 non-goals: in-flight messages).
        assertEquals("alice 0", p.bob.ratchet.receive(aliceWires[0]))
        assertEquals(listOf("alice 1", "alice 2"), bobOnly(), "only the uncommitted rest of the live chain opens")
        assertEquals("alice 1", p.bob.ratchet.receive(aliceWires[1]))
        assertEquals("alice 2", p.bob.ratchet.receive(aliceWires[2]))
        assertEquals(emptyList(), bobOnly(), "after Bob committed them all, nothing of Alice's opens from his vault")
    }

    /**
     * One side's one-time private key left unwiped (a test-kept copy). Run for both
     * leaking roles x both send orders, so a role- or order-dependent slip in the label,
     * transcript or salt is caught. Besides "everything opens", it pins that the oracle's
     * OWN derivation is production's: its ss' equals the returned pairing secret, it is
     * distinct from rk0 / rB_seed / CK_pre, and those three really key the wires.
     */
    private fun leakControl(aIsBob: Boolean, leakTheResponder: Boolean, responderWritesFirst: Boolean) {
        val p = V3PairingFixture.pairWithAAs(bob = aIsBob, leakBoth = true)
        val leaker = if (leakTheResponder) p.bob else p.alice
        val other = if (leakTheResponder) p.alice else p.bob
        val wire = RecordingWire()
        val sent = if (responderWritesFirst) responderFirst(p, wire) else initiatorFirst(p, wire)
        val leaked = leaker.leakedEphemeralPriv!!
        // Precondition: the array bootstrap DID get was wiped — the leak is the test's copy.
        assertTrue(leaker.ephemeralPrivHandedOver.all { it.toInt() == 0 })

        val d = V3BootstrapOracle.deriveV3(x25519Ecdh(leaked, other.ephemeralPub), p.ssHalves, p.qrPublicKeys)
        val ssPrime = d.getValue("pairing-secret")
        assertContentEquals(p.a.ready.pairingSecret, ssPrime, "the \"pairing-secret\" label / ss' derivation")
        assertContentEquals(p.b.ready.pairingSecret, ssPrime)
        for (l in listOf("root", "bob-key", "pre-chain")) assertFalse(ssPrime.contentEquals(d.getValue(l)), "ss' == $l")
        val wires = wire.bodies.map { LegacyBootstrapAttacker.parseRatchetBody(it)!! }
        val aliceFirstWire = wires[if (responderWritesFirst) 3 else 0]
        val firstChain = LegacyBootstrapAttacker.kdfRk(
            d.getValue("root"), x25519Ecdh(d.getValue("bob-key"), aliceFirstWire.senderRatchetPub),
        ).second
        assertEquals("alice 0", LegacyBootstrapAttacker.openRatchetWire(LegacyBootstrapAttacker.messageKeyAt(firstChain, 0), aliceFirstWire))
        if (responderWritesFirst) {
            assertEquals("bob 0", LegacyBootstrapAttacker.openRatchetWire(LegacyBootstrapAttacker.messageKeyAt(d.getValue("pre-chain"), 0), wires[0]))
            assertContentEquals(wires[0].senderRatchetPub, x25519Ecdh(d.getValue("bob-key"), ByteArray(32).also { it[0] = 9 }))
        }

        val opened = V3BootstrapOracle.open(snapshot(p, wire, extraLeaks = listOf(leaked)))
        assertEquals(sent, opened, "S = X25519(e_priv, e_peer_pub) recovers rk0, rB_seed and CK_pre — every bootstrap message")
    }

    @Test
    fun control_v3WithTheOneTimePrivateKeyLeftUnwiped_opensTheBootstrapEpoch() {
        if (!up()) return
        leakControl(aIsBob = true, leakTheResponder = true, responderWritesFirst = true)
    }

    @Test
    fun control_v3_initiatorsOneTimeKeyLeaked_responderWritesFirst_opensTheBootstrapEpoch() {
        if (!up()) return
        leakControl(aIsBob = true, leakTheResponder = false, responderWritesFirst = true)
    }

    @Test
    fun control_v3_responderOneTimeKeyLeaked_initiatorWritesFirst_opensTheBootstrapEpoch() {
        if (!up()) return
        leakControl(aIsBob = false, leakTheResponder = true, responderWritesFirst = false)
    }

    @Test
    fun control_v3_initiatorsOneTimeKeyLeaked_initiatorWritesFirst_opensTheBootstrapEpoch() {
        if (!up()) return
        leakControl(aIsBob = false, leakTheResponder = false, responderWritesFirst = false)
    }

    // --- mutation checks: the oracle WOULD have caught these production slips --------------

    private fun mutationOpens(m: V3PairingFixture.Mutation): Pair<List<String>, List<String>> {
        val bad = V3PairingFixture.mutatedPairing(m)
        val wire = RecordingWire()
        val bobSent = (0 until 3).map { "bob $it" }.onEach { bob -> assertEquals(bob, bad.alice.receive(wire.send(bad.bob, bob))) }
        val aliceSent = (0 until 3).map { "alice $it" }.onEach { a -> assertEquals(a, bad.bob.receive(wire.send(bad.alice, a))) }
        val opened = V3BootstrapOracle.open(
            V3BootstrapOracle.Snapshot(
                ratchetBlobs = listOf(bad.alice.serialize(), bad.bob.serialize()),
                storedSecrets = listOf(bad.storedSecret),
                qrHalves = bad.qrHalves,
                qrPublicKeys = bad.qrPublicKeys,
                bodies = wire.bodies,
            ),
        )
        return (bobSent + aliceSent) to opened
    }

    @Test
    fun mutationCheck_preChainKeyedWithTheStoredSecret_isOpened() {
        if (!up()) return
        val (sent, opened) = mutationOpens(V3PairingFixture.Mutation.PRE_CHAIN_IS_STORED_SECRET)
        assertTrue(opened.containsAll(sent.take(3)), "the pre-chain = ss' slip must be caught; opened $opened")
    }

    @Test
    fun mutationCheck_rootAndBobKeyFromTheStoredSecret_isOpened() {
        if (!up()) return
        val (sent, opened) = mutationOpens(V3PairingFixture.Mutation.ROOT_AND_BOB_KEY_FROM_STORED_SECRET)
        assertTrue(opened.containsAll(sent.drop(3)), "rk0/rB_seed from ss' must be caught; opened $opened")
    }

    @Test
    fun mutationCheck_forgottenDh_isOpened() {
        if (!up()) return
        val (sent, opened) = mutationOpens(V3PairingFixture.Mutation.NO_DH)
        assertEquals(sent, opened, "keys from ss_halves alone must be caught")
    }

    @Test
    fun control_aWrongOneTimeKeyOpensNothing() {
        if (!up()) return
        val p = V3PairingFixture.pairWithAAs(bob = true)
        val wire = RecordingWire()
        responderFirst(p, wire)
        val unrelated = x25519GenerateKeypair().privateKey
        assertEquals(emptyList(), V3BootstrapOracle.open(snapshot(p, wire, extraLeaks = listOf(unrelated))))
    }

    // --- referral (plan §4.2; §7 "phase 3: ref_p") -----------------------------------------
    //
    // The two introducees finalize through the REAL ReferralManager handshake
    // (support/V3ReferralFixture); their stored ratchet states are then driven here at the
    // ratchet layer. The oracle gets, per snapshot: every serialized state, every secret at
    // rest on both introducees (contact rows — including each one's pairing with the
    // introducer, i.e. the introducer's stored secrets for those pairings — every 32-byte
    // `_meta` value, and the private + public key of any `ref_p` record that still exists),
    // both accept bodies and the offer as relayed (their `pk`s are the transcript keys),
    // every recorded wire, and the introId.
    //
    // The exact window of §4.2: a `ref_p` (lives ≤ 28 days, deleted in the commit
    // transaction) opens only what was sent to that side while it had NOT finalized — which
    // it therefore cannot have consumed. After both commits nothing opens.

    private fun referralSecretsAtRest(s: ReferralSide): List<ByteArray> =
        V3BootstrapOracle.secretsAtRest(s.inner, exclude = setOf(s.stateKey))

    private fun referralSnapshot(r: V3Referral, blobs: List<ByteArray>, stored: List<ByteArray>, wire: RecordingWire) =
        V3BootstrapOracle.Snapshot(
            ratchetBlobs = blobs,
            storedSecrets = stored,
            qrHalves = emptyList(),
            qrPublicKeys = listOf(r.b.acceptBody, r.c.acceptBody).map { decodeBase64(firstStringFieldAnywhere(it, "pk")!!) },
            bodies = wire.bodies + listOf(referralOfferJson(r.introId, "Running Fox"), r.b.acceptBody, r.c.acceptBody)
                .map { it.encodeToByteArray() },
            referralIntroId = r.introId,
        )

    private fun stateOf(s: ReferralSide): DoubleRatchet = DoubleRatchet.deserialize(s.stateBlob()!!)

    /** Three each way at the ratchet layer; [responderFirst] = Bob writes first (pre-chain). */
    private fun referralConversation(alice: DoubleRatchet, bob: DoubleRatchet, wire: RecordingWire, responderFirst: Boolean): List<String> {
        val sent = mutableListOf<String>()
        fun leg(from: DoubleRatchet, to: DoubleRatchet, who: String) {
            val ws = (0 until 3).map { "$who $it" }.onEach { sent += it }.map { wire.send(from, it) }
            ws.forEachIndexed { i, m -> assertEquals("$who $i", to.receive(m)) }
        }
        if (responderFirst) { leg(bob, alice, "bob"); leg(alice, bob, "alice") } else { leg(alice, bob, "alice"); leg(bob, alice, "bob") }
        return sent
    }

    private fun referralNothingOpens(bIsBob: Boolean, responderFirst: Boolean) {
        val r = V3Referral.pairWithBAs(bob = bIsBob)
        val alice = stateOf(r.alice); val bob = stateOf(r.bob)
        val wire = RecordingWire()
        referralConversation(alice, bob, wire, responderFirst)
        assertTrue(r.b.refP() == null && r.c.refP() == null, "precondition: both committed, no ref_p left")
        val stored = referralSecretsAtRest(r.b) + referralSecretsAtRest(r.c)
        assertEquals(emptyList(), V3BootstrapOracle.open(referralSnapshot(r, listOf(alice.serialize(), bob.serialize()), stored, wire)))
    }

    @Test
    fun referral_v3_responderWritesFirst_afterCommit_nothingOpens() {
        if (!up()) return
        referralNothingOpens(bIsBob = true, responderFirst = true)
    }

    @Test
    fun referral_v3_initiatorWritesFirst_afterCommit_nothingOpens() {
        if (!up()) return
        referralNothingOpens(bIsBob = false, responderFirst = false)
    }

    /**
     * The §4.2 window, both halves. C committed, B has not (its `ref_p` exists): C's
     * messages to B open from B's `ref_p` (must succeed — this is the documented window and
     * the control that the oracle's referral derivations are real), and from nothing else.
     * Once B commits (`ref_p` deleted in the same transaction) and consumes them, and both
     * talk on, nothing opens.
     */
    @Test
    fun referral_v3_refPWindow_opensOnlyWhatWasSentToTheUnfinalizedSide_thenNothing() {
        if (!up()) return
        val r = V3Referral.stage()
        r.deliverToC()
        assertNotNull(r.b.refP()); assertNull(r.c.refP())
        val c = stateOf(r.c)
        val wire = RecordingWire()
        val cSent = (0 until 3).map { "c pending $it" }
        val cWires = cSent.map { wire.send(c, it) }

        val withRefP = referralSecretsAtRest(r.b) + referralSecretsAtRest(r.c)
        assertEquals(cSent, V3BootstrapOracle.open(referralSnapshot(r, listOf(c.serialize()), withRefP, wire)),
            "B's ref_p opens what C sent to the not-yet-finalized B")
        val withoutRefP = r.b.inner.contacts.values.map { it.sharedSecret } + referralSecretsAtRest(r.c)
        assertEquals(emptyList(), V3BootstrapOracle.open(referralSnapshot(r, listOf(c.serialize()), withoutRefP, wire)),
            "…and nothing else at rest does")

        r.deliverToB()
        assertNull(r.b.refP(), "the commit deleted ref_p")
        val b = stateOf(r.b)
        cWires.forEachIndexed { i, m -> assertEquals("c pending $i", b.receive(m)) }
        val (alice, bob) = if (r.b.isBobAtBirth()) c to b else b to c
        referralConversation(alice, bob, wire, responderFirst = false)
        val stored = referralSecretsAtRest(r.b) + referralSecretsAtRest(r.c)
        assertEquals(emptyList(), V3BootstrapOracle.open(referralSnapshot(r, listOf(b.serialize(), c.serialize()), stored, wire)))
    }

    /**
     * Non-vacuity for the referral half of the oracle: the LEGACY referral bootstrap (both
     * introducees on a pre-v3 build). Given only B's `ref_p` key pair, the public keys of
     * the accepts and the wires — no stored contact secret, no ratchet state — the oracle
     * must derive `ss_ref` ("run-referral-v1|introId") and from it the legacy bootstrap:
     * the initiator's whole first chain opens (plan §1, T3). With both stored states added
     * it walks on to the responder's chain too, i.e. everything (the phase-0 control's
     * result). Otherwise its empty answers above would prove nothing.
     */
    @Test
    fun control_legacyReferral_refPAloneOpensTheInitiatorsFirstChain_andWithTheStatesEverything() {
        if (!up()) return
        val r = V3Referral.stage(bLegacy = true, cLegacy = true)
        val refP = assertNotNull(decodeStoredAccept(assertNotNull(r.b.refP())))
        r.deliverToB(); r.deliverToC()
        val ss = assertNotNull(r.b.contact()).sharedSecret
        assertFalse(r.b.contact()!!.ratchetBootstrapV3)
        val bIsBob = ratchetSelfIsBobFromRoleOrder(ss, assertNotNull(ratchetRoleOrderBit(r.b.publicKey, r.c.publicKey)))
        val alice = DoubleRatchet.initAsAlice(ss)
        val bob = DoubleRatchet.initAsBob(ss)
        val wire = RecordingWire()
        val sent = referralConversation(alice, bob, wire, responderFirst = false)
        val fromRefP = V3BootstrapOracle.open(
            referralSnapshot(r, emptyList(), listOf(refP.privateKey, refP.publicKey), wire),
        )
        assertEquals(sent.take(3), fromRefP, "legacy referral (B is ${if (bIsBob) "Bob" else "Alice"}): ref_p → ss_ref → the initiator's first chain")
        val withStates = V3BootstrapOracle.open(
            referralSnapshot(r, listOf(alice.serialize(), bob.serialize()), listOf(refP.privateKey, refP.publicKey), wire),
        )
        assertEquals(sent, withStates)
    }

    /** Non-vacuity for the v3 referral derivation: a referral one-time key left unwiped
     *  (a test-kept copy) after commit opens the whole bootstrap epoch — the oracle does
     *  derive S_ref ("run-referral-drboot-v3|introId") and the referral transcript. */
    @Test
    fun control_v3Referral_aOneTimeKeyLeftUnwiped_opensEverything() {
        if (!up()) return
        val r = V3Referral.pairWithBAs(bob = true)
        val alice = stateOf(r.alice); val bob = stateOf(r.bob)
        val wire = RecordingWire()
        val sent = referralConversation(alice, bob, wire, responderFirst = true)
        val stored = referralSecretsAtRest(r.b) + referralSecretsAtRest(r.c) + listOf(r.b.leakedPriv)
        assertEquals(sent, V3BootstrapOracle.open(referralSnapshot(r, listOf(alice.serialize(), bob.serialize()), stored, wire)))
    }

    /**
     * Must-fail-if-leaked control for the encoding-independent scan: `S_ref` stored HEX-encoded
     * in an arbitrary `_meta` row opens the whole bootstrap epoch. (Before the scan tried
     * every encoding, a hex value was invisible to the oracle.)
     */
    @Test
    fun control_v3Referral_SRefStoredHexEncodedInMeta_isFoundAndOpensEverything() {
        if (!up()) return
        val r = V3Referral.pairWithBAs(bob = true)
        val alice = stateOf(r.alice); val bob = stateOf(r.bob)
        val wire = RecordingWire()
        val sent = referralConversation(alice, bob, wire, responderFirst = true)
        val blobs = listOf(alice.serialize(), bob.serialize())
        assertEquals(emptyList(), V3BootstrapOracle.open(referralSnapshot(r, blobs, referralSecretsAtRest(r.b) + referralSecretsAtRest(r.c), wire)))
        val sRef = hkdfSha256(x25519Ecdh(r.b.leakedPriv, r.c.publicKey), ByteArray(0), "run-referral-drboot-v3|${r.introId}".encodeToByteArray(), 32)
        r.b.inner.meta["leak/hex"] = bytesToHex(sRef)
        assertEquals(sent, V3BootstrapOracle.open(referralSnapshot(r, blobs, referralSecretsAtRest(r.b) + referralSecretsAtRest(r.c), wire)))
    }

    /**
     * The pre-commit `ref_p` window, as a control that MUST succeed. A copy of B's `ref_p`
     * taken BEFORE B commits (the one-time private key), plus the public keys and the wires,
     * recomputes `S_ref` → `rk0`, `rB_seed`, `CK_pre`: the responder's (Bob's) pre-chain and
     * the initiator's (Alice's) FIRST sending chain open. It heals at Bob's first receiving
     * DH step: the chain Bob sends on after his first receive is keyed by a fresh ratchet
     * private key, and every chain after it (both sides) is closed. Run for C = Bob and C = Alice.
     */
    private fun preCommitCopy(cIsBob: Boolean) {
        var r: V3Referral? = null
        var copy: StoredAccept? = null
        for (i in 0 until 128) {
            val t = V3Referral.stage()
            val c = assertNotNull(decodeStoredAccept(assertNotNull(t.b.refP())))
            t.deliverToB(); t.deliverToC()
            if (t.c.isBobAtBirth() == cIsBob) { r = t; copy = c; break }
        }
        val ref = assertNotNull(r); val leaked = assertNotNull(copy)
        assertNull(ref.b.refP(), "B committed: the live ref_p is gone — the attacker holds an older copy")
        val c = stateOf(ref.c); val b = stateOf(ref.b)
        val wire = RecordingWire()
        fun leg(from: DoubleRatchet, to: DoubleRatchet, tag: String): List<String> {
            val ts = (0 until 3).map { "$tag $it" }
            ts.map { wire.send(from, it) }.forEachIndexed { i, m -> assertEquals(ts[i], to.receive(m)) }
            return ts
        }
        val c1 = leg(c, b, "c1"); val b1 = leg(b, c, "b1"); val c2 = leg(c, b, "c2"); val b2 = leg(b, c, "b2")
        val fromCopy = V3BootstrapOracle.open(referralSnapshot(ref, emptyList(), listOf(leaked.privateKey, leaked.publicKey), wire))
        // C = Bob: C's pre-chain (c1) and Alice's first chain (b1) open; C = Alice: only C's first chain.
        val expected = if (cIsBob) c1 + b1 else c1
        assertEquals(expected, fromCopy, "C is ${if (cIsBob) "Bob" else "Alice"}")
        assertTrue(fromCopy.none { it in c2 || it in b2 }, "healed: nothing after Bob's first receiving DH step")
        // Adding everything at rest at the end opens nothing more.
        val all = V3BootstrapOracle.open(referralSnapshot(
            ref, listOf(b.serialize(), c.serialize()),
            listOf(leaked.privateKey, leaked.publicKey) + referralSecretsAtRest(ref.b) + referralSecretsAtRest(ref.c), wire,
        ))
        assertEquals(expected, all)
    }

    @Test
    fun control_preCommitRefPCopy_cIsBob_opensBobsPreChainAndAlicesFirstChain_thenHeals() {
        if (!up()) return
        preCommitCopy(cIsBob = true)
    }

    @Test
    fun control_preCommitRefPCopy_cIsAlice_opensAlicesFirstChain_thenHeals() {
        if (!up()) return
        preCommitCopy(cIsBob = false)
    }
}

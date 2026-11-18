package com.vg.run

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// The v3 bootstrap's derivation and state machine (docs/ratchet-bootstrap-plan.md
// §3.2, §3.3, §7 "State machine"). Pure: no relay, no vault. The forward-secrecy
// property itself is RatchetBootstrapForwardSecrecyTest.
// ---------------------------------------------------------------------------
class RatchetBootstrapV3Test {

    private fun up() = aeadUp() && x25519Up()

    private fun msg(s: String) = s.encodeToByteArray()
    private fun DoubleRatchet.open(m: RatchetMessage) = decrypt(m.header, m.ciphertext).decodeToString()

    private fun refusal(r: RatchetBootstrapV3.Result): RatchetBootstrapV3.Refusal =
        assertIs<RatchetBootstrapV3.Result.Refused>(r).reason

    // --- derivation ---------------------------------------------------------------------

    @Test
    fun bothSidesDeriveTheSamePairingSecret_andOppositeRoles() {
        if (!up()) return
        repeat(8) {
            val p = V3PairingFixture.pair()
            assertContentEquals(p.a.ready.pairingSecret, p.b.ready.pairingSecret)
            assertNotEquals(p.a.isBob, p.b.isBob, "role rule v2 must give exactly one Bob")
            // ss' is a new secret: neither the legacy secret nor a half.
            assertFalse(p.a.ready.pairingSecret.contentEquals(p.ssHalves))
            assertFalse(p.a.ready.pairingSecret.contentEquals(p.a.half))
            assertFalse(p.a.ready.pairingSecret.contentEquals(p.b.half))
        }
    }

    @Test
    fun theRoleIsRoleRuleV2OverTheStoredPairingSecret() {
        if (!up()) return
        val p = V3PairingFixture.pair()
        val orderA = ratchetRoleOrderBit(p.a.half, p.b.half)!!
        assertEquals(ratchetSelfIsBobFromRoleOrder(p.a.ready.pairingSecret, orderA), p.a.isBob)
    }

    @Test
    fun theOneTimePrivateKeyIsWipedOnSuccess() {
        if (!up()) return
        val p = V3PairingFixture.pair()
        assertTrue(p.a.ephemeralPrivHandedOver.all { it.toInt() == 0 })
        assertTrue(p.b.ephemeralPrivHandedOver.all { it.toInt() == 0 })
    }

    @Test
    fun aDifferentSaltGivesStatesThatDoNotInteroperate() {
        if (!up()) return
        val halfA = generateSecureRandom(32); val halfB = generateSecureRandom(32)
        val eA = x25519GenerateKeypair(); val eB = x25519GenerateKeypair()
        val ss = deriveSharedSecret(halfA, halfB)
        val order = ratchetRoleOrderBit(halfA, halfB)!!
        val ra = assertIs<RatchetBootstrapV3.Result.Ready>(RatchetBootstrapV3.bootstrap(eA.privateKey, eB.publicKey, ss, order))
        val rb = assertIs<RatchetBootstrapV3.Result.Ready>(
            RatchetBootstrapV3.bootstrap(eB.privateKey, eA.publicKey, generateSecureRandom(32), !order),
        )
        assertFalse(ra.pairingSecret.contentEquals(rb.pairingSecret))
        // Whatever roles they took (both can always send), a message from one does not
        // open at the other — the bounded key-confirmation failure phase 2 builds on.
        val m = ra.ratchet.encrypt(msg("x"))
        assertFailsWith<RatchetException> { rb.ratchet.decrypt(m.header, m.ciphertext) }
    }

    // --- refusals: typed, never thrown ----------------------------------------------------

    private fun bootstrapAgainst(peerPub: ByteArray, priv: ByteArray = x25519GenerateKeypair().privateKey) =
        RatchetBootstrapV3.bootstrap(priv, peerPub, generateSecureRandom(32), mineSortsFirst = true)

    private val lowOrderHex = listOf(
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    )

    private fun hex(s: String) = ByteArray(32) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    /** Each table entry, and the same point with bit 255 set (ignored by X25519). */
    private fun lowOrderPoints(): List<ByteArray> = lowOrderHex.map { hex(it) }.flatMap { p ->
        listOf(p, p.copyOf().also { it[31] = (it[31].toInt() or 0x80).toByte() })
    }

    @Test
    fun theLowOrderTableReallyIsLowOrder_andHonestKeysAreNeverInIt() {
        if (!x25519Up()) return
        for (point in lowOrderPoints()) {
            val out = try { x25519Ecdh(x25519GenerateKeypair().privateKey, point) } catch (_: Exception) { null }
            // Tink refuses such points itself; CryptoKit returns the all-zero output.
            assertTrue(out == null || out.all { it.toInt() == 0 }, "table entry is not low order")
            assertTrue(RatchetBootstrapV3.isLowOrderPublicKey(point))
        }
        repeat(64) { assertFalse(RatchetBootstrapV3.isLowOrderPublicKey(x25519GenerateKeypair().publicKey)) }
    }

    @Test
    fun aLowOrderPeerKey_isATypedRefusal_andOurKeyIsStillWiped() {
        if (!up()) return
        for (point in lowOrderPoints()) {
            val priv = x25519GenerateKeypair().privateKey
            assertEquals(RatchetBootstrapV3.Refusal.LOW_ORDER_PEER_KEY, refusal(bootstrapAgainst(point, priv)))
            assertTrue(priv.all { it.toInt() == 0 })
        }
    }

    /**
     * The `ek` equal on both sides is REJECTED, not merely documented: two honest
     * keypairs never collide, so equality is a reflected copy of our own code (or a
     * bug); the transcript's min/max has no order; and the reflecting party learns
     * nothing it could use, so there is no legitimate pairing to keep.
     */
    @Test
    fun aReflectedOneTimeKey_isRefused() {
        if (!up()) return
        val mine = x25519GenerateKeypair()
        assertEquals(
            RatchetBootstrapV3.Refusal.REFLECTED_PEER_KEY,
            refusal(bootstrapAgainst(mine.publicKey.copyOf(), mine.privateKey)),
        )
        assertTrue(mine.privateKey.all { it.toInt() == 0 })
    }

    /** X25519 ignores bit 255 of a public key, so our own key with that bit set is
     *  the same reflection in another spelling. */
    @Test
    fun aReflectedOneTimeKey_withTheIgnoredTopBitSet_isRefused() {
        if (!up()) return
        val mine = x25519GenerateKeypair()
        val respelled = mine.publicKey.copyOf().also { it[31] = (it[31].toInt() or 0x80).toByte() }
        assertEquals(
            RatchetBootstrapV3.Refusal.REFLECTED_PEER_KEY,
            refusal(bootstrapAgainst(respelled, mine.privateKey)),
        )
    }

    @Test
    fun malformedInputs_areRefused() {
        if (!up()) return
        val peer = x25519GenerateKeypair().publicKey
        fun r(priv: ByteArray, pub: ByteArray, salt: ByteArray) = refusal(RatchetBootstrapV3.bootstrap(priv, pub, salt, true))
        val malformed = RatchetBootstrapV3.Refusal.MALFORMED_INPUT
        assertEquals(malformed, r(ByteArray(31) { 1 }, peer, generateSecureRandom(32)))
        assertEquals(malformed, r(x25519GenerateKeypair().privateKey, peer.copyOf(33), generateSecureRandom(32)))
        assertEquals(malformed, r(x25519GenerateKeypair().privateKey, peer, ByteArray(0)))
        assertEquals(malformed, r(x25519GenerateKeypair().privateKey, peer, generateSecureRandom(16)))
    }

    @Test
    fun aSpentOneTimeKey_isRefused_neverUsedAsTheZeroScalar() {
        if (!up()) return
        assertEquals(
            RatchetBootstrapV3.Refusal.SPENT_EPHEMERAL_KEY,
            refusal(bootstrapAgainst(x25519GenerateKeypair().publicKey, ByteArray(32))),
        )
        // A key bootstrap already consumed is exactly that: a second use is refused.
        val e = x25519GenerateKeypair()
        val peer = x25519GenerateKeypair().publicKey
        assertIs<RatchetBootstrapV3.Result.Ready>(bootstrapAgainst(peer, e.privateKey))
        assertEquals(RatchetBootstrapV3.Refusal.SPENT_EPHEMERAL_KEY, refusal(bootstrapAgainst(peer, e.privateKey)))
    }

    // --- state machine ---------------------------------------------------------------------

    @Test
    fun bothSidesCanSendImmediately() {
        if (!up()) return
        val p = V3PairingFixture.pair()
        assertTrue(p.alice.ratchet.canSend())
        assertTrue(p.bob.ratchet.canSend(), "Bob sends on the pre-chain from birth (plan G-C: no wait state)")
    }

    @Test
    fun bobSendsFirst_headersCarryRbPubPn0_aliceReceivesWithNoDhStep() {
        if (!up()) return
        val p = V3PairingFixture.pair()
        val bob = p.bob.ratchet; val alice = p.alice.ratchet
        val ms = (0 until 3).map { bob.encrypt(msg("b$it")) }
        val rbPub = ms[0].header.dhPub
        ms.forEachIndexed { i, m ->
            assertContentEquals(rbPub, m.header.dhPub)
            assertEquals(0, m.header.pn)
            assertEquals(i, m.header.n)
        }
        // Alice's initial remote key IS rB_pub (she DHed against it at init).
        val aliceRemote = V3BootstrapOracle.parseState(alice.serialize()).remote!!
        assertContentEquals(rbPub, aliceRemote)
        ms.forEachIndexed { i, m -> assertEquals("b$i", alice.open(m)) }
        assertEquals(0, alice.receivingStepCount(), "the pre-chain is received with no DH step")
        // Alice's own sending chain still goes on its first chain.
        val a = alice.encrypt(msg("a0"))
        assertEquals("a0", bob.open(a))
        assertEquals(1, bob.receivingStepCount())
    }

    @Test
    fun aliceSendsFirst_likeTheLegacyInitiator() {
        if (!up()) return
        val p = V3PairingFixture.pair()
        val alice = p.alice.ratchet; val bob = p.bob.ratchet
        repeat(3) { assertEquals("a$it", bob.open(alice.encrypt(msg("a$it")))) }
        repeat(3) { assertEquals("b$it", alice.open(bob.encrypt(msg("b$it")))) }
        repeat(4) { i ->
            assertEquals("a-r$i", bob.open(alice.encrypt(msg("a-r$i"))))
            assertEquals("b-r$i", alice.open(bob.encrypt(msg("b-r$i"))))
        }
    }

    @Test
    fun simultaneousFirstSends_bothDecrypt_andTheConversationContinues() {
        if (!up()) return
        val p = V3PairingFixture.pair()
        val alice = p.alice.ratchet; val bob = p.bob.ratchet
        val a = (0 until 2).map { alice.encrypt(msg("a$it")) }
        val b = (0 until 2).map { bob.encrypt(msg("b$it")) }
        a.forEachIndexed { i, m -> assertEquals("a$i", bob.open(m)) }
        b.forEachIndexed { i, m -> assertEquals("b$i", alice.open(m)) }
        // Bob's first post-receive message comes from his first DH chain and names
        // the 2 pre-chain messages in pn.
        val b1 = bob.encrypt(msg("b-dh"))
        assertEquals(2, b1.header.pn)
        assertEquals("b-dh", alice.open(b1))
        repeat(3) { i ->
            assertEquals("a-r$i", bob.open(alice.encrypt(msg("a-r$i"))))
            assertEquals("b-r$i", alice.open(bob.encrypt(msg("b-r$i"))))
        }
    }

    @Test
    fun preChainThenBobsFirstDhChain_withPn_latePreChainOpensFromSkippedKeys() {
        if (!up()) return
        val p = V3PairingFixture.pair()
        val alice = p.alice.ratchet; val bob = p.bob.ratchet
        val pre = (0 until 3).map { bob.encrypt(msg("pre$it")) }
        assertEquals("pre0", alice.open(pre[0]))
        assertEquals("a0", bob.open(alice.encrypt(msg("a0"))))      // Bob's first DH step
        val c0 = bob.encrypt(msg("c0"))
        assertEquals(3, c0.header.pn, "pn = the pre-chain length")
        assertEquals(0, c0.header.n)
        assertFalse(c0.header.dhPub.contentEquals(pre[0].header.dhPub))
        assertEquals("c0", alice.open(c0))
        assertEquals(2, alice.skippedKeyCount(), "pre1 and pre2 cached by the pn-skip")
        assertEquals("pre2", alice.open(pre[2]))
        assertEquals("pre1", alice.open(pre[1]))
        assertEquals(0, alice.skippedKeyCount())
    }

    @Test
    fun outOfOrderPreChain() {
        if (!up()) return
        val p = V3PairingFixture.pair()
        val pre = (0 until 4).map { p.bob.ratchet.encrypt(msg("pre$it")) }
        for (i in listOf(3, 0, 2, 1)) assertEquals("pre$i", p.alice.ratchet.open(pre[i]))
        assertEquals(0, p.alice.ratchet.skippedKeyCount())
        // A replay of a consumed pre-chain message does not open.
        assertFailsWith<RatchetException> { p.alice.ratchet.decrypt(pre[0].header, pre[0].ciphertext) }
    }

    /**
     * More than MAX_SKIP lost pre-chain messages strand the pre-chain exactly like any
     * chain today (plan §3.2 residual, not new): the same refusal, with the same
     * message, as a legacy pairing losing the same number on its first chain.
     */
    @Test
    fun moreThanMaxSkipLostPreChainMessages_strandLikeAnyChain() {
        if (!up()) return
        val p = V3PairingFixture.pair()
        // Same shape on both legs: one message delivered, then MAX_SKIP + 2 lost.
        assertEquals("x", p.alice.ratchet.open(p.bob.ratchet.encrypt(msg("x"))))
        val last = (0 until DoubleRatchet.MAX_SKIP + 2).map { p.bob.ratchet.encrypt(msg("lost")) }.last()
        val v3 = assertFailsWith<RatchetException> { p.alice.ratchet.decrypt(last.header, last.ciphertext) }

        val ss = generateSecureRandom(32)
        val la = DoubleRatchet.initAsAlice(ss); val lb = DoubleRatchet.initAsBob(ss)
        assertEquals("x", lb.open(la.encrypt(msg("x"))))
        val legacyLast = (0 until DoubleRatchet.MAX_SKIP + 2).map { la.encrypt(msg("lost")) }.last()
        val legacy = assertFailsWith<RatchetException> { lb.decrypt(legacyLast.header, legacyLast.ciphertext) }
        assertEquals(legacy.message, v3.message)
        // And it stays stranded: every later pre-chain message is further out still.
        val later = p.bob.ratchet.encrypt(msg("later"))
        assertFailsWith<RatchetException> { p.alice.ratchet.decrypt(later.header, later.ciphertext) }
    }

    // --- persistence (SER_VERSION 3, unchanged) -------------------------------------------------

    @Test
    fun bothInitialStatesRoundTripThroughTheExistingSerialization() {
        if (!up()) return
        val p = V3PairingFixture.pair()
        val aliceBlob = p.alice.ratchet.serialize()
        val bobBlob = p.bob.ratchet.serialize()
        assertEquals(DoubleRatchet.SER_VERSION, aliceBlob[0])
        assertEquals(0x7, aliceBlob[1].toInt(), "Alice: remote + send + receive chain")
        assertEquals(0x2, bobBlob[1].toInt(), "Bob: send chain only, no remote")
        val alice = DoubleRatchet.deserialize(aliceBlob)
        val bob = DoubleRatchet.deserialize(bobBlob)
        assertContentEquals(aliceBlob, alice.serialize())
        assertContentEquals(bobBlob, bob.serialize())
        // The restored states are the same states: both directions, pre-chain first.
        assertEquals("b0", alice.open(bob.encrypt(msg("b0"))))
        assertEquals("a0", bob.open(alice.encrypt(msg("a0"))))
        assertEquals("b1", alice.open(bob.encrypt(msg("b1"))))
    }

    @Test
    fun midConversationRoundTrip_restoresAtEveryStep() {
        if (!up()) return
        val p = V3PairingFixture.pair()
        var alice = p.alice.ratchet; var bob = p.bob.ratchet
        fun reload() {
            alice = DoubleRatchet.deserialize(alice.serialize())
            bob = DoubleRatchet.deserialize(bob.serialize())
        }
        val pre = (0 until 3).map { bob.encrypt(msg("pre$it")) }
        reload()
        assertEquals("pre0", alice.open(pre[0]))
        reload()
        val a0 = alice.encrypt(msg("a0"))
        reload()
        assertEquals("a0", bob.open(a0))
        reload()
        val c0 = bob.encrypt(msg("c0"))
        reload()
        assertEquals("c0", alice.open(c0))
        reload()
        assertEquals(2, alice.skippedKeyCount(), "skipped pre-chain keys survive persistence")
        assertEquals("pre2", alice.open(pre[2]))
        assertEquals("pre1", alice.open(pre[1]))
        reload()
        repeat(3) { i ->
            assertEquals("a-r$i", bob.open(alice.encrypt(msg("a-r$i")))); reload()
            assertEquals("b-r$i", alice.open(bob.encrypt(msg("b-r$i")))); reload()
        }
    }
}

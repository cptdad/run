package com.vg.run

/**
 * Two devices paired with the v3 bootstrap exactly as the pairing transaction will
 * call it (docs/ratchet-bootstrap-plan.md §3.2): each side has a QR secret half and a
 * one-time X25519 keypair, `ss_halves = deriveSharedSecret(halves)`, the order bit of
 * role rule v2 comes from [ratchetRoleOrderBit] over the halves, and each side runs
 * [RatchetBootstrapV3.bootstrap] with ITS private key and the PEER's public key.
 */
internal class V3Side(
    val half: ByteArray,
    val ephemeralPub: ByteArray,
    /** The private-key array handed to bootstrap (wiped by it). */
    val ephemeralPrivHandedOver: ByteArray,
    /** Test-only: an unwiped copy, non-null only when the fixture was asked to leak it. */
    val leakedEphemeralPriv: ByteArray?,
    val ready: RatchetBootstrapV3.Result.Ready,
) {
    val ratchet: DoubleRatchet get() = ready.ratchet
    val isBob: Boolean get() = ready.selfIsBob
}

internal class V3Pairing(val a: V3Side, val b: V3Side, val ssHalves: ByteArray) {
    val alice: V3Side get() = if (a.isBob) b else a
    val bob: V3Side get() = if (a.isBob) a else b
    val qrHalves: List<ByteArray> get() = listOf(a.half, b.half)
    val qrPublicKeys: List<ByteArray> get() = listOf(a.ephemeralPub, b.ephemeralPub)
}

internal object V3PairingFixture {

    /** [leakEphemeralPrivOfA] keeps an unwiped copy of A's one-time key; [leakBoth] of both. */
    fun pair(leakEphemeralPrivOfA: Boolean = false, leakBoth: Boolean = false): V3Pairing {
        val halfA = generateSecureRandom(32)
        val halfB = generateSecureRandom(32)
        val eA = x25519GenerateKeypair()
        val eB = x25519GenerateKeypair()
        val leakA = if (leakEphemeralPrivOfA || leakBoth) eA.privateKey.copyOf() else null
        val leakB = if (leakBoth) eB.privateKey.copyOf() else null
        val ss = deriveSharedSecret(halfA, halfB)
        val orderA = ratchetRoleOrderBit(halfA, halfB) ?: error("identical halves")
        val orderB = ratchetRoleOrderBit(halfB, halfA) ?: error("identical halves")
        val rA = RatchetBootstrapV3.bootstrap(eA.privateKey, eB.publicKey, ss, orderA)
        val rB = RatchetBootstrapV3.bootstrap(eB.privateKey, eA.publicKey, ss, orderB)
        check(rA is RatchetBootstrapV3.Result.Ready) { "A refused: ${(rA as RatchetBootstrapV3.Result.Refused).reason}" }
        check(rB is RatchetBootstrapV3.Result.Ready) { "B refused: ${(rB as RatchetBootstrapV3.Result.Refused).reason}" }
        return V3Pairing(
            V3Side(halfA, eA.publicKey, eA.privateKey, leakA, rA),
            V3Side(halfB, eB.publicKey, eB.privateKey, leakB, rB),
            ss,
        )
    }

    /** A pairing in which side A took the given role (the role is a coin flip per pairing). */
    fun pairWithAAs(bob: Boolean, leakEphemeralPrivOfA: Boolean = false, leakBoth: Boolean = false): V3Pairing {
        repeat(128) {
            val p = pair(leakEphemeralPrivOfA, leakBoth)
            if (p.a.isBob == bob) return p
        }
        error("no pairing with A as ${if (bob) "Bob" else "Alice"} in 128 tries")
    }

    /** Deliberately BROKEN bootstrap derivations, for the oracle's mutation checks. */
    enum class Mutation {
        /** Bob's pre-chain key is the stored pairing secret ss' (a non-labelled reuse). */
        PRE_CHAIN_IS_STORED_SECRET,
        /** rk0 and rB_seed keyed by the stored secret alone — the legacy shape. */
        ROOT_AND_BOB_KEY_FROM_STORED_SECRET,
        /** The DH is forgotten: every output keyed by ss_halves (ikm) instead of S. */
        NO_DH,
    }

    /**
     * A pairing built exactly like production EXCEPT for [mutation], straight through the
     * v3 state factories. Side A is Alice, side B is Bob. Returns (alice, bob, storedSecret,
     * halves, qrPublicKeys). The derivation here is the oracle's own ([V3BootstrapOracle.deriveV3]).
     */
    class Mutated(
        val alice: DoubleRatchet, val bob: DoubleRatchet, val storedSecret: ByteArray,
        val qrHalves: List<ByteArray>, val qrPublicKeys: List<ByteArray>,
    )

    fun mutatedPairing(mutation: Mutation): Mutated {
        val halfA = generateSecureRandom(32); val halfB = generateSecureRandom(32)
        val eA = x25519GenerateKeypair(); val eB = x25519GenerateKeypair()
        val ss = deriveSharedSecret(halfA, halfB)
        val qr = listOf(eA.publicKey, eB.publicKey)
        val s = x25519Ecdh(eA.privateKey, eB.publicKey)
        val good = V3BootstrapOracle.deriveV3(s, ss, qr)
        val d = when (mutation) {
            Mutation.PRE_CHAIN_IS_STORED_SECRET -> good + ("pre-chain" to good.getValue("pairing-secret").copyOf())
            Mutation.ROOT_AND_BOB_KEY_FROM_STORED_SECRET -> good +
                ("root" to good.getValue("pairing-secret").copyOf()) + ("bob-key" to good.getValue("pairing-secret").copyOf())
            Mutation.NO_DH -> V3BootstrapOracle.deriveV3(ss, ss, qr)
        }
        fun k(l: String) = d.getValue(l).copyOf()
        val basepoint = ByteArray(32).also { it[0] = 9 }
        val bobSeed = k("bob-key")
        val bobPub = x25519Ecdh(bobSeed, basepoint)
        val alice = DoubleRatchet.initV3AsAlice(k("root"), bobPub, k("pre-chain"))
        val bob = DoubleRatchet.initV3AsBob(k("root"), bobSeed, bobPub, k("pre-chain"))
        return Mutated(alice, bob, k("pairing-secret"), listOf(halfA, halfB), qr)
    }

    /** Padded `{"m": text}` — the shape [LegacyBootstrapAttacker.envelopeText] reads. */
    fun envelope(text: String): ByteArray = padMessage("{\"m\":\"$text\"}".encodeToByteArray())

    fun text(plain: ByteArray): String = LegacyBootstrapAttacker.envelopeText(plain) ?: error("not an envelope")

    /** What a hostile relay records for one ratchet message. */
    fun body(m: RatchetMessage): ByteArray = LegacyBootstrapAttacker.RATCHET_MAGIC + m.encodeWire()
}

/** A relay that records every ratchet body it carries. */
internal class RecordingWire {
    val bodies = mutableListOf<ByteArray>()
    fun send(from: DoubleRatchet, text: String): RatchetMessage =
        from.encrypt(V3PairingFixture.envelope(text)).also { bodies += V3PairingFixture.body(it) }
}

internal fun DoubleRatchet.receive(m: RatchetMessage): String = V3PairingFixture.text(decrypt(m.header, m.ciphertext))

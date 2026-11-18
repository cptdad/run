package com.vg.run

// ---------------------------------------------------------------------------
// RatchetBootstrapV3 — the one-time ratchet bootstrap for NEW pairings
// (docs/ratchet-bootstrap-plan.md §3.2 and §3.3).
//
// The legacy bootstrap ([DoubleRatchet.initAsAlice] / [DoubleRatchet.initAsBob])
// derives rk0 and Bob's first ratchet private key from the STORED pairing secret,
// so the first epoch of every pairing can be recreated from an opened vault or a
// photo of both QR codes. Here each side contributes a one-time X25519 keypair `e`
// and the whole bootstrap is keyed by `S = X25519(e_mine, e_peer)`, which neither
// device keeps:
//
//   S        = X25519(e_mine_priv, e_peer_pub)            (low-order / all-zero → Refused)
//   T        = "run-dr-boot-v3" ‖ min(eA_pub, eB_pub) ‖ max(eA_pub, eB_pub)
//   rk0      = HKDF(ikm = S, salt = ss_halves, info = T ‖ "root")
//   rB_seed  = HKDF(ikm = S, salt = ss_halves, info = T ‖ "bob-key")
//   CK_pre   = HKDF(ikm = S, salt = ss_halves, info = T ‖ "pre-chain")
//   ss'      = HKDF(ikm = S, salt = ss_halves, info = T ‖ "pairing-secret")
//
// The four outputs are independent HKDF expansions, so knowing any one of them
// (in particular the stored ss') reveals none of the others.
//
// This file is PURE: no I/O, no vault, no wiring. The pairing transaction
// (phase 2) calls [RatchetBootstrapV3.bootstrap] once per pairing, persists the
// returned state and stores the returned pairing secret on the contact row. The
// referral commit (phase 3, §4.2) calls [RatchetBootstrapV3.bootstrapReferral]
// with the referral's own DH-derived secrets; same derivation, no `ss'`.
// Nothing here is reachable from an existing contact: the legacy init paths and
// every persisted ratchet are untouched.
// ---------------------------------------------------------------------------

internal object RatchetBootstrapV3 {

    // Wire contract: both devices must derive byte-identical keys, so these labels
    // are never renamed. The forward-secrecy oracle test spells them out as
    // literals on purpose (a rename breaks that test instead of being followed).
    private val DOMAIN = "run-dr-boot-v3".encodeToByteArray()
    private val LABEL_ROOT = "root".encodeToByteArray()
    private val LABEL_BOB_KEY = "bob-key".encodeToByteArray()
    private val LABEL_PRE_CHAIN = "pre-chain".encodeToByteArray()
    private val LABEL_PAIRING_SECRET = "pairing-secret".encodeToByteArray()

    private const val KEY_BYTES = 32
    private val BASEPOINT = ByteArray(KEY_BYTES).also { it[0] = 9 }   // X25519 generator u = 9

    /**
     * Why a bootstrap was refused. A refusal is a VALUE, never an exception: the
     * pairing caller turns it into the existing "invalid code" / "pairing failed"
     * surface, and nothing on this path can crash the app (an uncaught Kotlin
     * exception SIGABRTs iOS).
     */
    enum class Refusal {
        /** A key or the pairing secret has the wrong length. */
        MALFORMED_INPUT,
        /** Our own one-time private key is all zero — already wiped (a holder reused
         *  after wipe). Refused rather than used: a zeroed scalar is a fixed, public one. */
        SPENT_EPHEMERAL_KEY,
        /** The peer's one-time key equals ours: a reflected copy of our own code.
         *  Two honest keypairs never collide, and with equal keys T has no order. */
        REFLECTED_PEER_KEY,
        /** The peer's one-time key is a low-order point, or the DH output is all zero
         *  (RFC 7748 §6.1) — an attacker-predictable S. */
        LOW_ORDER_PEER_KEY,
        /** The platform X25519 failed for any other reason. */
        KEY_AGREEMENT_FAILED,
    }

    sealed class Result {
        /**
         * The initial ratchet state for THIS side plus `ss'`, the secret to store on
         * the contact row (§3.3). Both are owned by the caller: persist
         * `ratchet.serialize()` (and wipe that blob), store [pairingSecret], then
         * [wipe]. [selfIsBob] is the role this side took (for the caller's own
         * bookkeeping; the state already embodies it).
         */
        class Ready(val ratchet: DoubleRatchet, val pairingSecret: ByteArray, val selfIsBob: Boolean) : Result() {
            fun wipe() {
                ratchet.wipe()
                pairingSecret.secureWipe()
            }
        }

        class Refused(val reason: Refusal) : Result()
    }

    /**
     * The X25519 points of small order, little-endian u-coordinates with bit 255
     * cleared (RFC 7748 masks it on input): 0, 1, the two order-8 points, p − 1, and
     * the non-canonical encodings p and p + 1. The same table libsodium checks.
     * Any honest key — a clamped scalar times the base point — is in the prime-order
     * subgroup and never matches. Checkable WITHOUT a private key, so phase 2 can
     * reject a scanned code at parse time; [bootstrap] re-checks as a backstop.
     */
    private val LOW_ORDER_POINTS: List<ByteArray> = listOf(
        ByteArray(KEY_BYTES),
        ByteArray(KEY_BYTES).also { it[0] = 1 },
        hex32("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
        hex32("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
        hex32("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        hex32("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        hex32("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    )

    private fun hex32(s: String): ByteArray {
        val out = ByteArray(KEY_BYTES)
        for (i in out.indices) out[i] = s.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        return out
    }

    /** True when [publicKey] is a 32-byte low-order X25519 point (see [LOW_ORDER_POINTS]). */
    fun isLowOrderPublicKey(publicKey: ByteArray): Boolean {
        if (publicKey.size != KEY_BYTES) return false
        return LOW_ORDER_POINTS.any { point ->
            var diff = (publicKey[31].toInt() and 0x7F) xor (point[31].toInt() and 0x7F)
            for (i in 0 until 31) diff = diff or (publicKey[i].toInt() xor point[i].toInt())
            (diff and 0xFF) == 0
        }
    }

    /**
     * Run the v3 bootstrap for THIS side.
     *
     * @param myEphemeralPriv our one-time X25519 private key for this pairing attempt.
     *   CONSUMED: wiped in place on every path (success and refusal). Our public key
     *   is recomputed from it, so the transcript can never disagree with the scalar.
     * @param peerEphemeralPub the peer's one-time public key from its code.
     * @param pairingSecret `ss_halves` = [deriveSharedSecret] of the two QR secret
     *   halves — the HKDF salt. Read only; the caller owns and wipes it.
     * @param mineSortsFirst the immutable order bit of the existing role rule v2
     *   ([ratchetRoleOrderBit] over the two halves). The role is
     *   [ratchetSelfIsBobFromRoleOrder] applied to `ss'` — the secret this contact
     *   row will store — so `MessageManager.ratchetSelfIsBobOverride`, which reads
     *   the role rule from the stored secret, agrees with the state built here.
     *
     * Wipes: S, our private key, the transcript-bound intermediates; Alice also
     * wipes rk0 and rB_seed (Bob keeps them as his state until his first receive).
     */
    fun bootstrap(
        myEphemeralPriv: ByteArray,
        peerEphemeralPub: ByteArray,
        pairingSecret: ByteArray,
        mineSortsFirst: Boolean,
        nowMs: () -> Long = { currentTimeMillis() },
    ): Result {
        var shared: ByteArray? = null
        try {
            if (myEphemeralPriv.size != KEY_BYTES || peerEphemeralPub.size != KEY_BYTES ||
                pairingSecret.size != KEY_BYTES
            ) return Result.Refused(Refusal.MALFORMED_INPUT)
            if (isAllZero(myEphemeralPriv)) return Result.Refused(Refusal.SPENT_EPHEMERAL_KEY)
            if (isLowOrderPublicKey(peerEphemeralPub)) return Result.Refused(Refusal.LOW_ORDER_PEER_KEY)

            val myPub = x25519Ecdh(myEphemeralPriv, BASEPOINT)
            if (samePoint(myPub, peerEphemeralPub)) return Result.Refused(Refusal.REFLECTED_PEER_KEY)

            val s = x25519Ecdh(myEphemeralPriv, peerEphemeralPub)
            shared = s
            if (isAllZero(s)) return Result.Refused(Refusal.LOW_ORDER_PEER_KEY)

            return derive(s, pairingSecret, myPub, peerEphemeralPub, storedSecretIsSalt = false, mineSortsFirst, nowMs)
        } catch (_: Exception) {
            // Never a crash path: whatever the platform X25519 threw (Tink rejects some
            // inputs itself; a missing iOS bridge throws) becomes a typed refusal.
            return Result.Refused(Refusal.KEY_AGREEMENT_FAILED)
        } finally {
            myEphemeralPriv.secureWipe()
            shared?.secureWipe()
        }
    }

    /**
     * The referral (vouched introduction) entry point — docs/ratchet-bootstrap-plan.md
     * §4.2. The referral handshake already runs its own X25519 between the two
     * introducees' one-time keys, so the caller passes the DH-derived secrets instead of
     * a private key:
     *
     *   S_ref  = HKDF(ecdh, info = "run-referral-drboot-v3|" + introId)   → [bootstrapSecret]
     *   ss_ref = HKDF(ecdh, info = "run-referral-v1|" + introId)          → [referralSecret]
     *
     * and the §3.2 derivation runs with `ikm = S_ref`, `salt = ss_ref` and `T` over the
     * two referral public keys. Differences from [bootstrap], both by the plan:
     *  - there is no `ss'`: the contact row keeps `ss_ref` (already DH-derived), so
     *    [Result.Ready.pairingSecret] is a COPY of [referralSecret] (still "the secret the
     *    contact row stores") and the role is [ratchetSelfIsBobFromRoleOrder] over
     *    `ss_ref` — exactly what `MessageManager.ratchetSelfIsBobOverride` reads from the
     *    stored row with the `dr-roleord` bit the caller records from the same two keys;
     *  - [mineSortsFirst] is [ratchetRoleOrderBit] over the two PUBLIC keys (the referral
     *    order bit, see `MessageManager.recordRatchetRoleInputs`).
     *
     * The refusals stay meaningful for the referral keys: a malformed size, an all-zero
     * secret (a wiped buffer — a fixed, public value), a low-order peer key (the caller's
     * checked X25519 already refuses an all-zero DH; this is the table check), a reflected
     * copy of our own key. Never throws. [bootstrapSecret] and [referralSecret] are READ
     * ONLY — the caller owns and wipes them.
     */
    fun bootstrapReferral(
        bootstrapSecret: ByteArray,
        referralSecret: ByteArray,
        myPub: ByteArray,
        peerPub: ByteArray,
        mineSortsFirst: Boolean,
        nowMs: () -> Long = { currentTimeMillis() },
    ): Result {
        try {
            if (bootstrapSecret.size != KEY_BYTES || referralSecret.size != KEY_BYTES ||
                myPub.size != KEY_BYTES || peerPub.size != KEY_BYTES
            ) return Result.Refused(Refusal.MALFORMED_INPUT)
            if (isAllZero(bootstrapSecret) || isAllZero(referralSecret)) return Result.Refused(Refusal.SPENT_EPHEMERAL_KEY)
            if (isLowOrderPublicKey(peerPub)) return Result.Refused(Refusal.LOW_ORDER_PEER_KEY)
            if (samePoint(myPub, peerPub)) return Result.Refused(Refusal.REFLECTED_PEER_KEY)
            return derive(bootstrapSecret, referralSecret, myPub, peerPub, storedSecretIsSalt = true, mineSortsFirst, nowMs)
        } catch (_: Exception) {
            return Result.Refused(Refusal.KEY_AGREEMENT_FAILED)
        }
    }

    /**
     * The §3.2 derivation shared by both entry points: `rk0`, `rB_seed`, `CK_pre` from
     * `HKDF(ikm = s, salt, T ‖ label)` and the initial state for this side's role. The
     * stored secret (and the role secret) is `ss'` ("pairing-secret") for a QR pairing,
     * or a copy of [salt] when [storedSecretIsSalt] (referral: the row keeps `ss_ref`).
     * Does not touch [s] / [salt] (the callers own them); wipes its own intermediates
     * exactly as before: Alice keeps neither rk0 nor rB_seed. Throws only what the
     * platform crypto throws — the callers map that to a refusal.
     */
    private fun derive(
        s: ByteArray,
        salt: ByteArray,
        myPub: ByteArray,
        peerPub: ByteArray,
        storedSecretIsSalt: Boolean,
        mineSortsFirst: Boolean,
        nowMs: () -> Long,
    ): Result {
        var rk0: ByteArray? = null
        var bobSeed: ByteArray? = null
        var preChain: ByteArray? = null
        var stored: ByteArray? = null
        // Which secrets the returned state now owns (must survive the finally).
        var stateOwnsRootAndSeed = false
        var stateOwnsPreChain = false
        var handedOutStored = false
        try {
            val transcript = transcript(myPub, peerPub)
            rk0 = expand(s, salt, transcript, LABEL_ROOT)
            bobSeed = expand(s, salt, transcript, LABEL_BOB_KEY)
            preChain = expand(s, salt, transcript, LABEL_PRE_CHAIN)
            val storedSecret = if (storedSecretIsSalt) salt.copyOf() else expand(s, salt, transcript, LABEL_PAIRING_SECRET)
            stored = storedSecret

            val bobPub = x25519Ecdh(bobSeed, BASEPOINT)
            val selfIsBob = ratchetSelfIsBobFromRoleOrder(storedSecret, mineSortsFirst)
            val ratchet = if (selfIsBob) {
                DoubleRatchet.initV3AsBob(rk0, bobSeed, bobPub, preChain, nowMs).also {
                    stateOwnsRootAndSeed = true
                    stateOwnsPreChain = true
                }
            } else {
                DoubleRatchet.initV3AsAlice(rk0, bobPub, preChain, nowMs).also {
                    stateOwnsPreChain = true
                }
            }
            handedOutStored = true
            return Result.Ready(ratchet, storedSecret, selfIsBob)
        } finally {
            if (!stateOwnsRootAndSeed) {
                rk0?.secureWipe()
                bobSeed?.secureWipe()
            }
            if (!stateOwnsPreChain) preChain?.secureWipe()
            if (!handedOutStored) stored?.secureWipe()
        }
    }

    /** `T = DOMAIN ‖ min(a, b) ‖ max(a, b)`, unsigned byte-lexicographic order. */
    private fun transcript(a: ByteArray, b: ByteArray): ByteArray {
        val (lo, hi) = if (compareUnsigned(a, b) <= 0) a to b else b to a
        return DOMAIN + lo + hi
    }

    private fun expand(shared: ByteArray, salt: ByteArray, transcript: ByteArray, label: ByteArray): ByteArray =
        hkdfSha256(ikm = shared, salt = salt, info = transcript + label, length = KEY_BYTES)

    private fun compareUnsigned(a: ByteArray, b: ByteArray): Int {
        for (i in 0 until minOf(a.size, b.size)) {
            val d = (a[i].toInt() and 0xFF) - (b[i].toInt() and 0xFF)
            if (d != 0) return d
        }
        return a.size - b.size
    }

    /** Equal as X25519 inputs: bit 255 is masked by the function (RFC 7748), so a
     *  copy of our key with that bit set is still our key. */
    private fun samePoint(a: ByteArray, b: ByteArray): Boolean {
        var diff = (a[31].toInt() and 0x7F) xor (b[31].toInt() and 0x7F)
        for (i in 0 until 31) diff = diff or (a[i].toInt() xor b[i].toInt())
        return (diff and 0xFF) == 0
    }

    private fun isAllZero(bytes: ByteArray): Boolean {
        var acc = 0
        for (b in bytes) acc = acc or b.toInt()
        return acc == 0
    }
}

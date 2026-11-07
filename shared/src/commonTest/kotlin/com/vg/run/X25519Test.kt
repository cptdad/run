package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// X25519 ECDH + HKDF tests (referral key agreement). The X25519 cases go
// through the real primitive (Tink on Android; CryptoKit bridge on iOS) and are
// bridge-guarded like the other crypto tests — skipped on the iOS unit-test
// target where the Swift bridge isn't installed. HKDF is pure commonMain over
// HMAC-SHA256, so it runs everywhere.
// ---------------------------------------------------------------------------

private fun hex(s: String): ByteArray {
    val clean = s.replace(" ", "")
    return ByteArray(clean.length / 2) { i ->
        clean.substring(i * 2, i * 2 + 2).toInt(16).toByte()
    }
}

private fun ByteArray.toHex(): String =
    joinToString("") { ((it.toInt() and 0xFF) + 0x100).toString(16).substring(1) }

class X25519Test {

    // RFC 7748 §6.1 known-answer vector.
    private val alicePriv = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    private val alicePub  = hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    private val bobPriv   = hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    private val bobPub    = hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    private val sharedK   = hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")

    @Test
    fun ecdh_matchesRfc7748_knownAnswer() {
        if (!x25519Up()) return
        // X25519(alicePriv, bobPub) == X25519(bobPriv, alicePub) == K.
        assertEquals(sharedK.toHex(), x25519Ecdh(alicePriv, bobPub).toHex())
        assertEquals(sharedK.toHex(), x25519Ecdh(bobPriv, alicePub).toHex())
    }

    @Test
    fun ecdh_twoFreshKeypairs_agreeAndAreNotTheRawScalar() {
        if (!x25519Up()) return
        val a = x25519GenerateKeypair()
        val b = x25519GenerateKeypair()
        assertEquals(32, a.privateKey.size)
        assertEquals(32, a.publicKey.size)
        // Both sides derive the identical shared point.
        val ab = x25519Ecdh(a.privateKey, b.publicKey)
        val ba = x25519Ecdh(b.privateKey, a.publicKey)
        assertEquals(ab.toHex(), ba.toHex())
        assertEquals(32, ab.size)
        // Two independent pairings must not collide.
        val c = x25519GenerateKeypair()
        assertTrue(x25519Ecdh(a.privateKey, c.publicKey).toHex() != ab.toHex())
    }

    @Test
    fun referralSharedKey_isStableAcrossSidesViaHkdf() {
        if (!x25519Up()) return
        // The actual referral derivation: HKDF over the ECDH point. Both
        // introducees must land on the same key from their own (priv, peerPub).
        val bobK   = hkdfSha256(x25519Ecdh(bobPriv, alicePub), ByteArray(0), "run-referral-v1".encodeToByteArray(), 32)
        val aliceK = hkdfSha256(x25519Ecdh(alicePriv, bobPub), ByteArray(0), "run-referral-v1".encodeToByteArray(), 32)
        assertEquals(aliceK.toHex(), bobK.toHex())
        assertEquals(32, aliceK.size)
    }

    @Test
    fun ecdhChecked_returnsSameAsRaw_forValidKeys() {
        if (!x25519Up()) return
        // The guard is transparent for legitimate keys.
        assertEquals(x25519Ecdh(alicePriv, bobPub).toHex(), x25519EcdhChecked(alicePriv, bobPub).toHex())
    }

    @Test
    fun ecdhChecked_rejectsLowOrderPoint_allZeroPeerKey() {
        if (!x25519Up()) return
        // A malicious introducer substitutes a low-order peer public key. The
        // all-zero point has order 1 → the scalar-mult collapses to an all-zero
        // "shared secret" the attacker can predict. x25519EcdhChecked must reject
        // it (RFC 7748 §6.1). On Android Tink throws inside x25519Ecdh; the shared
        // commonMain all-zero guard catches it on iOS where CryptoKit does not —
        // either way the call must fail rather than return a usable key.
        val lowOrder = ByteArray(32) // 32 zero bytes
        assertFailsWith<Exception> { x25519EcdhChecked(alicePriv, lowOrder) }
    }

    @Test
    fun hkdf_matchesRfc5869_testCase1() {
        // RFC 5869 Appendix A.1.
        val ikm  = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        val salt = hex("000102030405060708090a0b0c")
        val info = hex("f0f1f2f3f4f5f6f7f8f9")
        val okm  = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        assertEquals(okm, hkdfSha256(ikm, salt, info, 42).toHex())
    }
}

@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package com.vg.run

import platform.Foundation.NSData
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * The iOS `PlatformCrypto` actuals must
 * not leave secret material sitting in a bridge-boundary `NSData` once they have
 * copied it into the ByteArray commonMain owns and scrubs.
 *
 * Two properties per site, and the SECOND is the brick/corruption guard:
 *
 *  1. the bridge-boundary NSData is all-zero after the call (the security property:
 *     ARC frees it without zeroing, so the raw SQLCipher DB key / the full Argon2id
 *     `stretched` output / an X25519 private key would otherwise stay legible in a
 *     freed heap block on every unlock);
 *  2. the value the actual RETURNS is still correct, and the CALLER's own arrays are
 *     untouched — i.e. the memset happens strictly after the copy-out and only ever
 *     hits storage we uniquely own. A wipe-before-copy regression here would hand
 *     the vault an all-zero key, so it is worth pinning.
 *
 * Fakes stand in for the Swift bridges, so this runs without SwiftAesGcm /
 * SwiftArgon2 / SwiftX25519 (mirrors CryptoProviderKeyGuardTest's FakeKeychainBridge).
 */
class BridgeSecretWipeTest {

    @AfterTest
    fun tearDown() {
        AesGcmBridgeHolder.bridge = null
        Argon2BridgeHolder.bridge = null
        X25519BridgeHolder.bridge = null
    }

    private fun assertAllZero(data: NSData, what: String) {
        val bytes = data.toByteArray()
        assertTrue(bytes.isNotEmpty(), "$what: fake handed over no bytes — test is not proving anything")
        assertTrue(bytes.all { it == 0.toByte() }, "$what must be zeroed once the actual has copied it out")
    }

    // --- AES-GCM -----------------------------------------------------------

    private class FakeAesGcm(private val plaintextOut: ByteArray) : AesGcmBridge {
        var lastKey: NSData? = null
        var lastPlaintext: NSData? = null
        var decryptReturn: NSData? = null

        override fun encrypt(plaintext: NSData, key: NSData, aad: NSData): NSData {
            lastPlaintext = plaintext
            lastKey = key
            // Any >= IV(12)+tag(16) blob satisfies the actual's success check.
            return ByteArray(28) { 0x11 }.toNSData()
        }

        override fun decrypt(ciphertext: NSData, key: NSData, aad: NSData): NSData? {
            lastKey = key
            return plaintextOut.toNSData().also { decryptReturn = it }
        }
    }

    @Test
    fun aesGcmEncrypt_wipesBothTheKeyAndThePlaintextBridgeCopies() {
        val fake = FakeAesGcm(ByteArray(0))
        AesGcmBridgeHolder.bridge = fake
        val key = ByteArray(32) { 0x41 }
        val plaintext = ByteArray(48) { 0x42 }   // stands in for the raw DB key

        aesGcmEncrypt(plaintext, key, "ctx".encodeToByteArray())

        assertAllZero(fake.lastPlaintext!!, "plaintext bridge copy")
        assertAllZero(fake.lastKey!!, "key bridge copy")
        // The wipe must never reach the CALLER's arrays — toNSData() copies, and
        // commonMain owns the lifetime of these.
        assertTrue(plaintext.all { it == 0x42.toByte() }, "caller's plaintext must not be clobbered")
        assertTrue(key.all { it == 0x41.toByte() }, "caller's key must not be clobbered")
    }

    @Test
    fun aesGcmDecrypt_returnsThePlaintextAndThenWipesTheBridgeReturn() {
        val secret = ByteArray(32) { (it + 1).toByte() }   // stands in for the DB key
        val expected = secret.copyOf()                     // snapshot, so an aliasing
        val fake = FakeAesGcm(secret)                      // regression can't hide here
        AesGcmBridgeHolder.bridge = fake

        val out = aesGcmDecrypt(ByteArray(64) { 0x7F }, ByteArray(32) { 0x41 }, ByteArray(0))

        // Ordering guard: copy-out strictly BEFORE the memset.
        assertTrue(out.contentEquals(expected), "decrypt must return the plaintext, not the zeroed buffer")
        assertAllZero(fake.decryptReturn!!, "decrypt bridge return (the recovered plaintext)")
        assertAllZero(fake.lastKey!!, "key bridge copy")
    }

    // --- Argon2id ----------------------------------------------------------

    private class FakeArgon2(private val out: ByteArray) : Argon2Bridge {
        var lastPassword: NSData? = null
        var argonReturn: NSData? = null

        override fun argon2id(
            password: NSData,
            salt: NSData,
            memoryKiB: Int,
            iterations: Int,
            parallelism: Int,
            keyLength: Int
        ): NSData? {
            lastPassword = password
            return out.toNSData().also { argonReturn = it }
        }
    }

    @Test
    fun argon2id_returnsStretchedAndThenWipesTheBridgeReturn() {
        val stretched = ByteArray(32) { (0xA0 + it).toByte() }
        val expected = stretched.copyOf()
        val fake = FakeArgon2(stretched)
        Argon2BridgeHolder.bridge = fake

        val out = argon2id(
            password = "0000".encodeToByteArray(),
            salt = ByteArray(16) { 0x5A },
            memoryKiB = 1024, iterations = 1, parallelism = 1, keyLengthBytes = 32
        )

        assertTrue(out.contentEquals(expected), "argon2id must return the derived key, not the zeroed buffer")
        // With `stretched` an examiner skips the KDF entirely: the verifier is
        // sha256(stretched‖LABEL_CRED) and the DB-key KEK is sha256(stretched‖LABEL_KEK).
        assertAllZero(fake.argonReturn!!, "argon2id bridge return (the full KDF output)")
        assertAllZero(fake.lastPassword!!, "credential bridge copy")
    }

    // --- X25519 ------------------------------------------------------------

    private class FakeX25519(private val keypair: ByteArray, private val ecdhOut: ByteArray) : X25519Bridge {
        var keypairReturn: NSData? = null
        var lastPrivate: NSData? = null
        var ecdhReturn: NSData? = null

        override fun generateKeypair(): NSData = keypair.toNSData().also { keypairReturn = it }

        override fun ecdh(privateKey: NSData, peerPublicKey: NSData): NSData? {
            lastPrivate = privateKey
            return ecdhOut.toNSData().also { ecdhReturn = it }
        }
    }

    @Test
    fun x25519GenerateKeypair_splitsTheKeypairAndThenWipesTheBridgeReturn() {
        val combined = ByteArray(64) { (it + 1).toByte() }
        val expected = combined.copyOf()
        val fake = FakeX25519(combined, ByteArray(32))
        X25519BridgeHolder.bridge = fake

        val kp = x25519GenerateKeypair()

        assertTrue(kp.privateKey.contentEquals(expected.copyOfRange(0, 32)), "private half must survive the wipe")
        assertTrue(kp.publicKey.contentEquals(expected.copyOfRange(32, 64)), "public half must survive the wipe")
        assertAllZero(fake.keypairReturn!!, "keypair bridge return (bytes 0..31 are the private key)")
    }

    @Test
    fun x25519Ecdh_returnsTheSharedSecretAndThenWipesTheBridgeReturn() {
        val sharedSecret = ByteArray(32) { (0xC0 + it).toByte() }
        val expected = sharedSecret.copyOf()
        val fake = FakeX25519(ByteArray(64), sharedSecret)
        X25519BridgeHolder.bridge = fake

        val out = x25519Ecdh(ByteArray(32) { 0x31 }, ByteArray(32) { 0x32 })

        assertTrue(out.contentEquals(expected), "ecdh must return the shared secret, not the zeroed buffer")
        assertAllZero(fake.ecdhReturn!!, "ecdh bridge return (the raw shared secret)")
        assertAllZero(fake.lastPrivate!!, "private-key bridge copy")
    }
}

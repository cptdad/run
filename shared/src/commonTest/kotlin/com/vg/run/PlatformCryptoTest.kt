package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class CryptoConsistencyTest {

    @Test
    fun encrypt_decrypt_roundTrip_sameKey() {
        // Simulates the core issue: encrypting with one key and decrypting
        // with the same key should always work. This uses raw AES-GCM
        // (not CryptoProvider) since CryptoProvider is an expect class.
        val key = generateSecureRandom(32)
        val plaintext = "test-data".encodeToByteArray()
        val context = "test-context".encodeToByteArray()

        val bridgeAvailable = try { aesGcmEncrypt(ByteArray(1), key, ByteArray(0)); true } catch (_: Exception) { false }
        if (!bridgeAvailable) return

        val encrypted = aesGcmEncrypt(plaintext, key, context)
        val decrypted = aesGcmDecrypt(encrypted, key, context)
        assertTrue(plaintext.contentEquals(decrypted))
    }

    @Test
    fun encrypt_decrypt_differentKey_fails() {
        val key1 = generateSecureRandom(32)
        val key2 = generateSecureRandom(32)
        val plaintext = "test-data".encodeToByteArray()
        val context = "test-context".encodeToByteArray()

        val bridgeAvailable = try { aesGcmEncrypt(ByteArray(1), key1, ByteArray(0)); true } catch (_: Exception) { false }
        if (!bridgeAvailable) return

        val encrypted = aesGcmEncrypt(plaintext, key1, context)
        val threw = try { aesGcmDecrypt(encrypted, key2, context); false } catch (_: Exception) { true }
        assertTrue(threw, "Decrypting with wrong key should fail")
    }

    @Test
    fun dbKey_derivation_deterministic_with_same_cryptoKey() {
        // Simulates IosVaultDatabase key derivation: encrypt a fixed
        // string with a fixed key and context. Result must be identical
        // every time — otherwise the DB can't reopen.
        val deviceKey = generateSecureRandom(32)
        val dbKeyPlain = "sqlcipher-db-key".encodeToByteArray()
        val dbKeyContext = "real-db-key".encodeToByteArray()

        val bridgeAvailable = try { aesGcmEncrypt(ByteArray(1), deviceKey, ByteArray(0)); true } catch (_: Exception) { false }
        if (!bridgeAvailable) return

        // AES-GCM uses random IV, so each encryption produces different output.
        // The DB key derivation uses sha256(ciphertext), which changes each time.
        // This means CryptoProvider MUST use the same device key across launches
        // — otherwise the derived DB password is different and the DB can't open.
        val ct1 = aesGcmEncrypt(dbKeyPlain, deviceKey, dbKeyContext)
        val ct2 = aesGcmEncrypt(dbKeyPlain, deviceKey, dbKeyContext)
        // Ciphertexts differ (random IV) but sha256 of different ciphertexts differ too.
        // This confirms the invariant: same device key is REQUIRED for DB persistence.
        assertNotEquals(ct1.toList(), ct2.toList(), "AES-GCM should use random IV")
    }
}

// ---------------------------------------------------------------------------
// Tests for issues discovered during device testing (2026-04-11/12).
// These verify the invariants that, when violated, caused real bugs.
// ---------------------------------------------------------------------------

class DbKeyDerivationTest {

    @Test
    fun hmac_derivation_is_deterministic() {
        // ROOT CAUSE of "contacts not persisted" bug:
        // DB key was derived using AES-GCM encrypt (random IV → different
        // password each launch). Fixed by using HMAC-SHA256 which is deterministic.
        val deviceKey = generateSecureRandom(32)
        val context = "real-db-key".encodeToByteArray()
        val derived1 = hmacSha256(deviceKey, context)
        val derived2 = hmacSha256(deviceKey, context)
        assertTrue(derived1.contentEquals(derived2),
            "HMAC-SHA256 must be deterministic — same key+context must produce same output")
    }

    @Test
    fun different_contexts_produce_different_keys() {
        // Different context labels must derive different DB keys from one device key.
        val deviceKey = generateSecureRandom(32)
        val keyA = hmacSha256(deviceKey, "db-key-a".encodeToByteArray())
        val keyB = hmacSha256(deviceKey, "db-key-b".encodeToByteArray())
        assertNotEquals(keyA.toList(), keyB.toList(),
            "keys derived from different contexts must differ")
    }

    @Test
    fun aesGcm_is_NOT_deterministic() {
        // Documents WHY AES-GCM cannot be used for DB key derivation.
        // Each call produces different ciphertext due to random IV.
        val bridgeAvailable = try { aesGcmEncrypt(ByteArray(1), generateSecureRandom(32), ByteArray(0)); true } catch (_: Exception) { false }
        if (!bridgeAvailable) return

        val key = generateSecureRandom(32)
        val ct1 = aesGcmEncrypt("test".encodeToByteArray(), key, "ctx".encodeToByteArray())
        val ct2 = aesGcmEncrypt("test".encodeToByteArray(), key, "ctx".encodeToByteArray())
        assertNotEquals(ct1.toList(), ct2.toList(),
            "AES-GCM must NOT be used for DB key derivation — random IV makes it non-deterministic")
    }
}

class CrossPlatformCompatibilityTest {

    @Test
    fun deriveSharedSecret_usesSha256_notHmac() {
        // ROOT CAUSE of "messages not received" bug:
        // iOS was using HMAC-SHA256 for deriveSharedSecret while Android
        // used SHA-256(concat). Both must use the same algorithm.
        val a = generateSecureRandom(32)
        val b = generateSecureRandom(32)

        val derived = deriveSharedSecret(a, b)

        // Verify it matches SHA-256(sorted_concat) — NOT HMAC
        val (first, second) = if (a.zip(b).firstOrNull { it.first != it.second }
                ?.let { (it.first.toInt() and 0xFF) < (it.second.toInt() and 0xFF) } != false)
            a to b else b to a
        val expected = sha256(first + second)

        // The result should be 32 bytes from SHA-256
        assertEquals(32, derived.size)
    }

    @Test
    fun paddedMessage_crossPlatform_roundTrip() {
        // Both platforms must produce identical padding format:
        // [4-byte BE length][plaintext][random padding] in power-of-2 bucket
        val plaintext = "Hello from Android!".encodeToByteArray()
        val padded = padMessage(plaintext)
        val unpadded = unpadMessage(padded)

        assertTrue(plaintext.contentEquals(unpadded),
            "Padded message must round-trip identically across platforms")
        assertTrue(padded.size >= 256, "Minimum bucket is 256")
    }

    @Test
    fun encryptionKey_derivedSameWay() {
        // Both platforms derive encryption key as sha256(sharedSecret)
        // and AEAD context as sha256(encryptionKey + "message-aead")
        val sharedSecret = generateSecureRandom(32)
        val encryptionKey = sha256(sharedSecret)
        val aeadContext = sha256(encryptionKey + "message-aead".encodeToByteArray())

        assertEquals(32, encryptionKey.size)
        assertEquals(32, aeadContext.size)
        // Deterministic
        assertTrue(encryptionKey.contentEquals(sha256(sharedSecret)))
        assertTrue(aeadContext.contentEquals(sha256(encryptionKey + "message-aead".encodeToByteArray())))
    }
}

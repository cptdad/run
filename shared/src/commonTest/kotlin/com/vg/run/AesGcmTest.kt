package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.assertFailsWith

/**
 * AES-GCM tests — these execute against the Android JCE/Tink backend (available
 * directly in the JVM test runner). On the iOS Kotlin/Native test target the
 * CryptoKit bridge isn't registered, so [bridgeAvailable] is false and the
 * body-executing cases skip (the `require()`-only cases still run everywhere).
 *
 * iOS COVERAGE (SR_2 B3-1): the production iOS backends (CryptoKit AES-GCM/X25519,
 * PHC Argon2id) are covered by a dedicated XCTest suite,
 * iosApp/RunCryptoTests/RunCryptoTests.swift, which drives the real Swift bridges
 * (SwiftAesGcm/SwiftX25519/SwiftArgon2) with KAT + tamper cases and REUSES the same
 * Argon2/X25519 vectors pinned here + in VaultKdfTest/X25519Test — so an iOS↔Android
 * crypto divergence fails there. It runs as a Run-hosted unit-test target:
 * `xcodebuild test -scheme Run -only-testing:RunCryptoTests`. (The commonTest cases
 * below still execute only on the JVM/Android backend — the CryptoKit bridge isn't
 * registered on the Kotlin/Native test target, so [bridgeAvailable] is false there.)
 */
class AesGcmTest {

    @Test
    fun encrypt_rejectsNon32ByteKey() {
        // Parity across platforms: a 16/24-byte key must be
        // rejected, never silently selecting AES-128/192. The require() fires
        // before any cipher/bridge call, so this holds with or without the bridge.
        assertFailsWith<IllegalArgumentException> {
            aesGcmEncrypt("x".encodeToByteArray(), ByteArray(16), ByteArray(0))
        }
    }

    @Test
    fun decrypt_rejectsNon32ByteKey() {
        assertFailsWith<IllegalArgumentException> {
            aesGcmDecrypt(ByteArray(28), ByteArray(16), ByteArray(0))
        }
    }

    @Test
    fun encryptThenDecrypt_roundTrip() {
        if (!aeadUp()) return
        val key = generateSecureRandom(32)
        val plaintext = "Secret message".encodeToByteArray()
        val aad = "context".encodeToByteArray()
        val ciphertext = aesGcmEncrypt(plaintext, key, aad)
        val decrypted = aesGcmDecrypt(ciphertext, key, aad)
        assertTrue(plaintext.contentEquals(decrypted))
    }

    @Test
    fun ciphertext_is_longer_than_plaintext() {
        if (!aeadUp()) return
        val key = generateSecureRandom(32)
        val plaintext = "Hello".encodeToByteArray()
        val ciphertext = aesGcmEncrypt(plaintext, key, "".encodeToByteArray())
        assertTrue(ciphertext.size > plaintext.size)
        assertEquals(plaintext.size + 12 + 16, ciphertext.size)
    }

    @Test
    fun tampered_ciphertext_throws() {
        if (!aeadUp()) return
        val key = generateSecureRandom(32)
        val plaintext = "Hello".encodeToByteArray()
        val aad = "ctx".encodeToByteArray()
        val ciphertext = aesGcmEncrypt(plaintext, key, aad)
        val tampered = ciphertext.copyOf()
        tampered[ciphertext.size / 2] = (tampered[ciphertext.size / 2].toInt() xor 1).toByte()
        val threw = try { aesGcmDecrypt(tampered, key, aad); false } catch (_: Exception) { true }
        assertTrue(threw, "Tampered ciphertext should fail decryption")
    }

    @Test
    fun wrong_key_throws() {
        if (!aeadUp()) return
        val key1 = generateSecureRandom(32)
        val key2 = generateSecureRandom(32)
        val ciphertext = aesGcmEncrypt("data".encodeToByteArray(), key1, "".encodeToByteArray())
        val threw = try { aesGcmDecrypt(ciphertext, key2, "".encodeToByteArray()); false } catch (_: Exception) { true }
        assertTrue(threw, "Wrong key should fail decryption")
    }

    @Test
    fun wrong_aad_throws() {
        if (!aeadUp()) return
        val key = generateSecureRandom(32)
        val ciphertext = aesGcmEncrypt("data".encodeToByteArray(), key, "aad1".encodeToByteArray())
        val threw = try { aesGcmDecrypt(ciphertext, key, "aad2".encodeToByteArray()); false } catch (_: Exception) { true }
        assertTrue(threw, "Wrong AAD should fail decryption")
    }
}

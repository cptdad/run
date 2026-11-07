package com.vg.run

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import kotlin.experimental.xor

/**
 * Instrumented tests for CryptoManager.
 *
 * These tests must run on a real device or emulator because CryptoManager relies
 * on the Android Keystore, which is only available in an Android runtime — it
 * cannot be faked in a plain JVM (unit test) environment.
 *
 * Run with: ./gradlew connectedAndroidTest
 */
@RunWith(AndroidJUnit4::class)
class CryptoManagerTest {

    private lateinit var cryptoManager: CryptoManager

    @Before
    fun setUp() {
        // Use the instrumentation target context so the test shares the same
        // app environment (SharedPreferences, Keystore) as the real application.
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        cryptoManager = CryptoManager(context)
    }

    /**
     * Test 1 — Round-trip: encrypt then decrypt returns original plaintext.
     *
     * This is the baseline correctness test. If encrypt/decrypt aren't inverse
     * operations, none of the other security properties matter.
     */
    @Test
    fun encryptThenDecrypt_returnsOriginalPlaintext() {
        val original = "Hello, Rún!".toByteArray(Charsets.UTF_8)
        val context  = "test:round-trip".toByteArray(Charsets.UTF_8)

        val ciphertext = cryptoManager.encrypt(original, context)
        val decrypted  = cryptoManager.decrypt(ciphertext, context)

        assertArrayEquals(
            "Decrypted bytes must exactly match the original plaintext",
            original,
            decrypted
        )
    }

    /**
     * Test 2 — Tamper detection: a modified ciphertext must not decrypt.
     *
     * AES-256-GCM appends a 16-byte authentication tag to every ciphertext.
     * Flipping even a single bit anywhere in the ciphertext (payload or tag)
     * must cause decryption to fail with an exception rather than silently
     * returning garbled data. This property is called "ciphertext integrity"
     * and is essential to detect in-transit or at-rest tampering.
     */
    @Test
    fun decrypt_withTamperedCiphertext_throwsException() {
        val original   = "Sensitive data".toByteArray(Charsets.UTF_8)
        val context    = "test:tamper".toByteArray(Charsets.UTF_8)

        val ciphertext = cryptoManager.encrypt(original, context).copyOf()

        // Flip one bit in the middle of the ciphertext (past Tink's 5-byte header).
        // Any position works — AES-GCM authenticates the entire ciphertext body.
        val tamperIndex = ciphertext.size / 2
        ciphertext[tamperIndex] = ciphertext[tamperIndex].xor(0xFF.toByte())

        try {
            cryptoManager.decrypt(ciphertext, context)
            // If we reach this line the library silently accepted tampered bytes — fail loudly.
            fail("Expected an exception when decrypting a tampered ciphertext, but none was thrown")
        } catch (e: Exception) {
            // Expected: Tink throws GeneralSecurityException (or a subclass) on
            // authentication failure. We catch the broad Exception type here so the
            // test is not brittle against internal Tink exception hierarchy changes.
        }
    }

    /**
     * Test 3 — Context binding: decrypting with a different contextInfo must fail.
     *
     * The contextInfo ("associated data" in AEAD terminology) is cryptographically
     * bound to the ciphertext during encryption. Attempting to decrypt with any
     * other contextInfo value must be rejected. This prevents a valid ciphertext
     * from being replayed in a different context — for example, a message encrypted
     * for one chat thread cannot be injected into a different thread and decrypted
     * there.
     */
    @Test
    fun decrypt_withDifferentContextInfo_throwsException() {
        val original        = "Context-bound message".toByteArray(Charsets.UTF_8)
        val correctContext  = "chat:thread_1".toByteArray(Charsets.UTF_8)
        val wrongContext    = "chat:thread_2".toByteArray(Charsets.UTF_8)

        val ciphertext = cryptoManager.encrypt(original, correctContext)

        try {
            cryptoManager.decrypt(ciphertext, wrongContext)
            fail("Expected an exception when decrypting with the wrong contextInfo, but none was thrown")
        } catch (e: Exception) {
            // Expected: Tink rejects the ciphertext because the authenticated
            // associated data does not match what was bound at encryption time.
        }
    }
}

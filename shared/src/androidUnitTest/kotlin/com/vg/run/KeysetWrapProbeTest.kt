package com.vg.run

import com.google.crypto.tink.Aead
import com.google.crypto.tink.BinaryKeysetReader
import com.google.crypto.tink.BinaryKeysetWriter
import com.google.crypto.tink.InsecureSecretKeyAccess
import com.google.crypto.tink.KeyTemplates
import com.google.crypto.tink.KeysetHandle
import com.google.crypto.tink.LegacyKeysetSerialization
import com.google.crypto.tink.aead.AeadConfig
import com.google.crypto.tink.subtle.Hex
import java.io.ByteArrayOutputStream
import java.security.GeneralSecurityException
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * `CryptoManager` used to decide "is the
 * persisted Tink keyset Keystore-wrapped?" from
 * `AndroidKeysetManager.isUsingKeystore()`, which in the pinned tink-android
 * 1.21.0 is exactly `masterAead != null` — it reports that a Keystore AEAD
 * HANDLE was obtained, never whether the bytes on disk are encrypted. The
 * builder's SECOND cleartext fallback (`parseEncryptedKeyset` throws ->
 * `readKeysetInCleartext`) runs with `masterAead` ALREADY SET, so the one state
 * the repair exists for — a CLEARTEXT keyset on disk with a healthy Keystore —
 * reported `true`, `rewrapKeysetUnderKeystore` never ran, and the repair's own
 * post-write check (`verified.isUsingKeystore()`) was vacuous for the same
 * reason.
 *
 * [KeysetWrapProbe] is the replacement decider and is byte-level, so it is
 * pinnable off-device: this runs on the JVM with the real tink-android artifact
 * and no Keystore, no SharedPreferences and no emulator. It pins BOTH directions
 * (the repair fires exactly on a cleartext keyset; a wrapped keyset is left
 * alone) and the hex framing `SharedPrefKeysetWriter` actually persists.
 */
class KeysetWrapProbeTest {

    @BeforeTest
    fun setUp() {
        AeadConfig.register()   // idempotent
    }

    /**
     * Stand-in for the Android Keystore master AEAD: the test only needs a real
     * `EncryptedKeyset` proto of the shape a healthy install persists, and this
     * runs where no Keystore exists. Reversible so Tink's own serialize path
     * (which round-trips the wrapped keyset) is satisfied.
     */
    private class FakeMasterAead : Aead {
        override fun encrypt(plaintext: ByteArray, associatedData: ByteArray): ByteArray =
            ByteArray(plaintext.size + 4).also { out ->
                MARKER.copyInto(out)
                for (i in plaintext.indices) out[i + 4] = (plaintext[i].toInt() xor 0x5A).toByte()
            }

        override fun decrypt(ciphertext: ByteArray, associatedData: ByteArray): ByteArray {
            if (ciphertext.size < 4) throw GeneralSecurityException("too short")
            return ByteArray(ciphertext.size - 4) { i ->
                (ciphertext[i + 4].toInt() xor 0x5A).toByte()
            }
        }

        companion object {
            private val MARKER = byteArrayOf('F'.code.toByte(), 'A'.code.toByte(), 'K'.code.toByte(), 'E'.code.toByte())
        }
    }

    private fun newKeyset(): KeysetHandle = KeysetHandle.generateNew(KeyTemplates.get("AES256_GCM"))

    /** Exactly what Tink's `readKeysetInCleartext` path leaves on disk. */
    private fun serializeCleartext(handle: KeysetHandle): ByteArray {
        val out = ByteArrayOutputStream()
        LegacyKeysetSerialization.serializeKeyset(
            handle,
            BinaryKeysetWriter.withOutputStream(out),
            InsecureSecretKeyAccess.get(),
        )
        return out.toByteArray()
    }

    /** Exactly what a HEALTHY, master-key-wrapped install leaves on disk. */
    private fun serializeWrapped(handle: KeysetHandle): ByteArray {
        val out = ByteArrayOutputStream()
        LegacyKeysetSerialization.serializeEncryptedKeyset(
            handle,
            BinaryKeysetWriter.withOutputStream(out),
            FakeMasterAead(),
            ByteArray(0),
        )
        return out.toByteArray()
    }

    // -- the detector ---------------------------------------------------------

    @Test
    fun cleartextKeysetOnDisk_isDetected() {
        // The state: the AES-256 data key sits in the prefs in the clear, with
        // no Keystore involved. This MUST classify as cleartext — it is the sole
        // trigger for rewrapKeysetUnderKeystore now that the library flag is gone.
        assertTrue(
            KeysetWrapProbe.isCleartextKeyset(serializeCleartext(newKeyset())),
            "a cleartext keyset on disk must be detected regardless of Keystore health",
        )
    }

    @Test
    fun keystoreWrappedKeyset_isNotFlaggedCleartext() {
        // The healthy state: an EncryptedKeyset proto. Must never be classified
        // cleartext, or every launch would pointlessly rewrite the keyset.
        assertFalse(
            KeysetWrapProbe.isCleartextKeyset(serializeWrapped(newKeyset())),
            "a Keystore-wrapped keyset must not be classified as cleartext",
        )
    }

    @Test
    fun wrappedKeysets_neverFalsePositive_overManyKeys() {
        // The wrapped bytes vary with the random data key, so pin the absence of
        // false positives over many independent keysets rather than one sample.
        repeat(64) {
            assertFalse(
                KeysetWrapProbe.isCleartextKeyset(serializeWrapped(newKeyset())),
                "wrapped keyset misclassified as cleartext",
            )
        }
    }

    @Test
    fun absentOrGarbageBytes_areNotCleartext() {
        // Brick-safety / first-provision safety: "no classifiable bytes" is NOT
        // evidence of a downgrade. An absent pref is a fresh install.
        assertFalse(KeysetWrapProbe.isCleartextKeyset(null))
        assertFalse(KeysetWrapProbe.isCleartextKeyset(ByteArray(0)))
        assertFalse(KeysetWrapProbe.isCleartextKeyset(ByteArray(64) { (it * 31 + 7).toByte() }))
    }

    // -- the pref framing -----------------------------------------------------

    @Test
    fun prefHexFraming_matchesTinkWriterAndComposesWithTheDetector() {
        // SharedPrefKeysetWriter persists Hex.encode(bytes); the production
        // detector reads that string back itself instead of trusting the library.
        // Pin the whole composition against Tink's own encoder.
        val cleartext = serializeCleartext(newKeyset())
        val decoded = KeysetWrapProbe.hexToBytesOrNull(Hex.encode(cleartext))
        assertContentEquals(cleartext, decoded, "hex decode must reproduce the persisted bytes exactly")
        assertTrue(KeysetWrapProbe.isCleartextKeyset(decoded))

        val wrapped = serializeWrapped(newKeyset())
        val decodedWrapped = KeysetWrapProbe.hexToBytesOrNull(Hex.encode(wrapped))
        assertContentEquals(wrapped, decodedWrapped)
        assertFalse(KeysetWrapProbe.isCleartextKeyset(decodedWrapped))
    }

    @Test
    fun hexDecoder_acceptsBothCases_andRejectsNonHex() {
        assertContentEquals(byteArrayOf(0x0A, 0xBC.toByte(), 0x00), KeysetWrapProbe.hexToBytesOrNull("0abc00"))
        assertContentEquals(byteArrayOf(0x0A, 0xBC.toByte(), 0x00), KeysetWrapProbe.hexToBytesOrNull("0ABC00"))
        // Total, never throwing: every unusable value reads as "nothing to classify".
        assertNull(KeysetWrapProbe.hexToBytesOrNull(null), "absent pref")
        assertNull(KeysetWrapProbe.hexToBytesOrNull(""), "empty pref")
        assertNull(KeysetWrapProbe.hexToBytesOrNull("abc"), "odd length")
        assertNull(KeysetWrapProbe.hexToBytesOrNull("zz"), "non-hex")
        assertNull(KeysetWrapProbe.hexToBytesOrNull("0a 0b"), "embedded space")
    }

    @Test
    fun unparseablePref_doesNotTriggerTheRepair() {
        // Composition of the two: an unreadable/absent pref yields null bytes,
        // which classify as NOT cleartext — the repair (which rewrites the only
        // copy of the keyset) must never fire on ambiguity.
        assertFalse(KeysetWrapProbe.isCleartextKeyset(KeysetWrapProbe.hexToBytesOrNull(null)))
        assertFalse(KeysetWrapProbe.isCleartextKeyset(KeysetWrapProbe.hexToBytesOrNull("not-hex")))
    }

    // -- the repair's verification, in reverse --------------------------------

    @Test
    fun repairVerification_isTheDetectorInReverse() {
        // rewrapKeysetUnderKeystore now verifies by re-reading the bytes and
        // requiring the cleartext parse to FAIL. Pin both outcomes of that check
        // on the two possible post-write states of the pref.
        val handle = newKeyset()

        // (a) the write landed: bytes are now an EncryptedKeyset -> verification passes.
        assertFalse(KeysetWrapProbe.isCleartextKeyset(serializeWrapped(handle)))

        // (b) the write did not land: bytes are still the cleartext keyset ->
        //     verification fails and the caller throws KeyUnavailableException
        //     (deferrable), instead of the old vacuous isUsingKeystore() == true.
        assertTrue(KeysetWrapProbe.isCleartextKeyset(serializeCleartext(handle)))
    }

    @Test
    fun rewrapPreservesTheKeyset_soAnExistingVaultStillOpens() {
        // Migration safety: the repair re-wraps the SAME keyset it just read, so
        // every CryptoProvider blob stays
        // decryptable afterwards. Unwrapping the re-wrapped bytes must yield the
        // identical cleartext keyset serialization.
        val handle = newKeyset()
        val before = serializeCleartext(handle)

        val wrapped = serializeWrapped(handle)
        val reopened = LegacyKeysetSerialization.parseEncryptedKeyset(
            BinaryKeysetReader.withBytes(wrapped),
            FakeMasterAead(),
            ByteArray(0),
        )
        assertContentEquals(
            before,
            serializeCleartext(reopened),
            "the re-wrap must preserve the exact keyset — anything else is a bricked vault",
        )
    }
}

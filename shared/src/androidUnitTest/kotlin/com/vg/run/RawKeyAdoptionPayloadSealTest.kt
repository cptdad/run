package com.vg.run

import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Raw-key adoption (2026-10-07), the JVM-testable halves that need real crypto:
 *
 *  1. The payload as it is actually SEALED in `vlt_c`'s inner layer
 *     (`aesGcmEncrypt(payload, kek, VaultCryptoContexts.DBKEY_INNER)`): a LEGACY blob sealed the
 *     pre-adoption way (32 bytes of dbKey) still opens and decodes to the same key;
 *     an adopted blob round-trips R and K'; and the largest inner still fits the
 *     Lever B RSA-2048-OAEP(SHA-256) plaintext budget (190 bytes).
 *  2. `DatabaseManager.pbkdf2HmacSha512` — the derivation of K' — against the JDK's
 *     own `PBKDF2WithHmacSHA512` (ASCII passwords, where `char[]` and raw bytes
 *     coincide), and the exact 67-byte `x'<hex>'` keyspec SQLCipher requires.
 *
 * Whether SQLCipher accepts K' for a real file is proven on-device by androidTest
 * `RawKeyAdoptionTest`; this class proves the bytes we hand it are the right ones.
 */
class RawKeyAdoptionPayloadSealTest {

    private val ctx = VaultCryptoContexts.DBKEY_INNER.encodeToByteArray()
    private val kek = ByteArray(32) { (it * 11 + 5).toByte() }
    private val r = ByteArray(32) { (it * 3 + 1).toByte() }
    private val k = ByteArray(32) { (0xA0 + it).toByte() }

    @Test
    fun legacySealedBlob_stillOpens_andDecodesToTheSameKeyInPassphraseMode() {
        // Exactly what every pre-adoption provision / change-PIN / KDF migration wrote.
        val legacyInner = aesGcmEncrypt(r, kek, ctx)
        val p = assertNotNull(DbKeyPayloadCodec.decodeDbKeyPayload(aesGcmDecrypt(legacyInner, kek, ctx)))
        assertEquals(DbKeyMode.PASSPHRASE, p.mode)
        assertContentEquals(r, p.dbKey)
    }

    @Test
    fun adoptedSealedBlob_roundTripsBothKeys() {
        val inner = aesGcmEncrypt(DbKeyPayloadCodec.encodeDbKeyPayload(r, k), kek, ctx)
        val p = assertNotNull(DbKeyPayloadCodec.decodeDbKeyPayload(aesGcmDecrypt(inner, kek, ctx)))
        assertEquals(DbKeyMode.RAW, p.mode)
        assertContentEquals(r, p.dbKey)
        assertContentEquals(k, p.rawKey)
    }

    @Test
    fun theModeTagIsAuthenticated_aFlippedTagFailsTheAead() {
        val inner = aesGcmEncrypt(DbKeyPayloadCodec.encodeDbKeyPayload(r, k), kek, ctx)
        // Flip one byte of the ciphertext region covering the tag position (12-byte IV first).
        val tampered = inner.copyOf().also { it[12 + 32] = (it[12 + 32].toInt() xor 0x03).toByte() }
        assertFailsWith<Exception> { aesGcmDecrypt(tampered, kek, ctx) }
    }

    @Test
    fun largestInner_fitsTheLeverBRsaOaepSha256PlaintextBudget() {
        val inner = aesGcmEncrypt(DbKeyPayloadCodec.encodeDbKeyPayload(r, k), kek, ctx)
        // RSA-2048 OAEP(SHA-256): 256 - 2*32 - 2 = 190 bytes max (AuthBoundKeyStore.wrap).
        assertTrue(inner.size <= 190, "adopted inner is ${inner.size} B; the ab: wrap must still fit")
        assertEquals(12 + 65 + 16, inner.size)
    }

    @Test
    fun pbkdf2HmacSha512_matchesTheJdkImplementation() {
        val jdk = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512")
        for ((pw, salt, iter) in listOf(
            Triple("password", "salt", 1),
            Triple("password", "salt", 2),
            Triple("passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096),
            Triple("x".repeat(200), "0123456789abcdef", 1000),   // key longer than the HMAC block
        )) {
            val expected = jdk.generateSecret(PBEKeySpec(pw.toCharArray(), salt.encodeToByteArray(), iter, 256)).encoded
            val ours = DatabaseManager.pbkdf2HmacSha512(pw.encodeToByteArray(), salt.encodeToByteArray(), iter, 32)
            assertContentEquals(expected, ours, "PBKDF2-HMAC-SHA512($pw, $iter)")
        }
    }

    @Test
    fun rawKeySpec_isExactlyTheSqlcipherRawForm() {
        val spec = DatabaseManager.rawKeySpec(k)
        assertEquals(67, spec.size, "SQLCipher takes the raw branch only for key_sz*2+3 bytes")
        val text = spec.decodeToString()
        assertTrue(text.startsWith("x'") && text.endsWith("'"))
        assertEquals(k.joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }, text.substring(2, 66))
        assertFailsWith<IllegalArgumentException> { DatabaseManager.rawKeySpec(ByteArray(33)) }
    }
}

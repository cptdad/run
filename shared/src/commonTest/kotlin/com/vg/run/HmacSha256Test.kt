package com.vg.run

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class HmacSha256Test {

    @Test
    fun deterministic_output() {
        val key = generateSecureRandom(32)
        val data = "test message".encodeToByteArray()
        val result1 = hmacSha256(key, data)
        val result2 = hmacSha256(key, data)
        assertTrue(result1.contentEquals(result2))
    }

    @Test
    fun different_keys_produce_different_output() {
        val data = "test message".encodeToByteArray()
        val result1 = hmacSha256(generateSecureRandom(32), data)
        val result2 = hmacSha256(generateSecureRandom(32), data)
        assertNotEquals(result1.toList(), result2.toList())
    }

    @Test
    fun output_is_32_bytes() {
        val result = hmacSha256(generateSecureRandom(32), "data".encodeToByteArray())
        assertEquals(32, result.size)
    }

    // --- The Android actual now caches ONE Mac engine per
    // thread (the ratchet turned HMAC into a hot loop and `Mac.getInstance` did a JCA
    // provider lookup per call). A cached, re-keyed, re-`doFinal`'d engine is exactly
    // where a stale-key or stale-buffer bug would hide, and it would be SILENT — the
    // ratchet would simply stop decrypting. These pin the primitive against fixed
    // vectors and against key/data interleaving, on every platform.

    private fun hex(b: ByteArray) = b.joinToString("") { ((it.toInt() and 0xFF) + 0x100).toString(16).substring(1) }
    private fun unhex(s: String) = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    @Test
    fun matchesRfc4231Vectors() {
        // RFC 4231 §4.2–4.4 (HMAC-SHA-256).
        assertEquals(
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            hex(hmacSha256(unhex("0b".repeat(20)), "Hi There".encodeToByteArray())),
        )
        assertEquals(
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            hex(hmacSha256("Jefe".encodeToByteArray(), "what do ya want for nothing?".encodeToByteArray())),
        )
        assertEquals(
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
            hex(hmacSha256(unhex("aa".repeat(20)), unhex("dd".repeat(50)))),
        )
    }

    @Test
    fun interleavedKeysAndSizes_neverReuseTheEngineState() {
        // Drive the engine the way the ratchet does: alternating keys, alternating
        // data lengths, hundreds of calls in a row. Each answer must equal the one the
        // same (key, data) pair produced in isolation — a retained key or an
        // un-reset buffer breaks exactly this.
        val k1 = ByteArray(32) { it.toByte() }
        val k2 = ByteArray(32) { (255 - it).toByte() }
        val d1 = byteArrayOf(0x01)
        val d2 = ByteArray(200) { (it * 7).toByte() }
        val ref11 = hex(hmacSha256(k1, d1)); val ref12 = hex(hmacSha256(k1, d2))
        val ref21 = hex(hmacSha256(k2, d1)); val ref22 = hex(hmacSha256(k2, d2))
        assertNotEquals(ref11, ref21)
        repeat(200) {
            assertEquals(ref11, hex(hmacSha256(k1, d1)))
            assertEquals(ref22, hex(hmacSha256(k2, d2)))
            assertEquals(ref21, hex(hmacSha256(k2, d1)))
            assertEquals(ref12, hex(hmacSha256(k1, d2)))
        }
        // The caller's key array must never be mutated by the actual (the Android one
        // hands it to a SecretKeySpec, which clones; the scrub re-keys the ENGINE).
        assertContentEquals(ByteArray(32) { it.toByte() }, k1)
        assertContentEquals(ByteArray(32) { (255 - it).toByte() }, k2)
    }
}

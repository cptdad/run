package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals

// Fixed vectors pinning that the RAM-hygiene wipes inside deriveSharedSecret and
// hkdfSha256 (the 2026-11-06 RAM-hygiene change) leave the OUTPUT byte-identical. The HKDF
// cases are RFC 5869 A.2 (multi-block: exercises the block-chaining wipe) and A.3
// (empty salt + info); A.1 is pinned in X25519Test. The deriveSharedSecret vector
// was computed independently (sha256 of the two inputs, ordered by their SHA-256).
class CryptoWipeVectorsTest {

    private fun hex(s: String): ByteArray =
        ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }

    private fun ByteArray.toHex(): String =
        joinToString("") { ((it.toInt() and 0xFF) + 0x100).toString(16).substring(1) }

    private fun range(from: Int, until: Int) = ByteArray(until - from) { (from + it).toByte() }

    @Test
    fun deriveSharedSecret_fixedVector_unchanged_eitherArgumentOrder() {
        val a = range(0x00, 0x20)
        val b = range(0x20, 0x40)
        val expected = "fdeab9acf3710362bd2658cdc9a29e8f9c757fcf9811603a8c447cd1d9151108"
        assertEquals(expected, deriveSharedSecret(a, b).toHex())
        assertEquals(expected, deriveSharedSecret(b, a).toHex())
        // The inputs are the caller's and must NOT be wiped.
        assertEquals(range(0x00, 0x20).toHex(), a.toHex())
        assertEquals(range(0x20, 0x40).toHex(), b.toHex())
    }

    @Test
    fun hkdf_matchesRfc5869_testCase2_multiBlock() {
        val okm = "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c" +
            "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71" +
            "cc30c58179ec3e87c14c01d5c1f3434f1d87"
        assertEquals(okm, hkdfSha256(range(0x00, 0x50), range(0x60, 0xb0), range(0xb0, 0x100), 82).toHex())
    }

    @Test
    fun hkdf_matchesRfc5869_testCase3_emptySaltAndInfo() {
        val ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        val okm = "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
        assertEquals(okm, hkdfSha256(ikm, ByteArray(0), ByteArray(0), 42).toHex())
        // The caller's IKM is not wiped.
        assertEquals("0b".repeat(22), ikm.toHex())
    }
}

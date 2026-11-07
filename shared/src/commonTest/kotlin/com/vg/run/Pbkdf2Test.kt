package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class Pbkdf2Test {

    @Test
    fun deterministic_output() {
        val password = "password123".encodeToByteArray()
        val salt = generateSecureRandom(16)
        val result1 = pbkdf2Sha256(password, salt, 1000, 32)
        val result2 = pbkdf2Sha256(password, salt, 1000, 32)
        assertTrue(result1.contentEquals(result2))
    }

    @Test
    fun different_salts_produce_different_output() {
        val password = "password123".encodeToByteArray()
        val result1 = pbkdf2Sha256(password, generateSecureRandom(16), 1000, 32)
        val result2 = pbkdf2Sha256(password, generateSecureRandom(16), 1000, 32)
        assertNotEquals(result1.toList(), result2.toList())
    }

    @Test
    fun output_length_matches_request() {
        val result = pbkdf2Sha256("pw".encodeToByteArray(), generateSecureRandom(16), 1000, 64)
        assertEquals(64, result.size)
    }

    // Independent pure-Kotlin PBKDF2-HMAC-SHA256 (RFC 8018) built on the
    // platform HMAC, used to cross-check the native pbkdf2Sha256. A mismatch
    // catches the iOS byte-length bug: the buggy impl passed the UTF-16
    // unit count as the byte length and truncated the password at any NUL,
    // hashing the wrong bytes.
    private fun pbkdf2Reference(password: ByteArray, salt: ByteArray, iterations: Int, keyLen: Int): ByteArray {
        val hLen = 32
        val blocks = (keyLen + hLen - 1) / hLen
        val out = ByteArray(blocks * hLen)
        for (block in 1..blocks) {
            val intBE = byteArrayOf(
                (block ushr 24).toByte(), (block ushr 16).toByte(),
                (block ushr 8).toByte(), block.toByte(),
            )
            var u = platformHmacSha256(password, salt + intBE)
            val t = u.copyOf()
            for (c in 2..iterations) {
                u = platformHmacSha256(password, u)
                for (k in t.indices) t[k] = (t[k].toInt() xor u[k].toInt()).toByte()
            }
            t.copyInto(out, (block - 1) * hLen)
        }
        return out.copyOf(keyLen)
    }

    @Test
    fun matches_independent_reference_for_multibyte_password() {
        // Multibyte UTF-8: é/☃/ñ are 2-3 UTF-8 bytes each, so the UTF-8 byte
        // length differs from the UTF-16 char count the buggy iOS impl passed.
        val password = "café ☃ señor".encodeToByteArray()
        val salt = "salt-1234567890".encodeToByteArray()
        assertTrue(
            pbkdf2Reference(password, salt, 1000, 32)
                .contentEquals(pbkdf2Sha256(password, salt, 1000, 32)),
            "native PBKDF2 must match the byte-exact reference for a multibyte password",
        )
    }

    @Test
    fun matches_independent_reference_for_ascii() {
        val password = "password123".encodeToByteArray()
        val salt = "saltsaltsalt".encodeToByteArray()
        assertTrue(
            pbkdf2Reference(password, salt, 500, 32)
                .contentEquals(pbkdf2Sha256(password, salt, 500, 32)),
        )
    }

    @Test
    fun output_is_not_all_zero() {
        // Regression for the silent zero-key failure: a non-success CC
        // status used to leave the buffer all-zero; it now throws instead.
        val out = pbkdf2Sha256("pw".encodeToByteArray(), "salt".encodeToByteArray(), 1000, 32)
        assertTrue(out.any { it.toInt() != 0 }, "derived key must not be all-zero")
    }
}

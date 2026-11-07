package com.vg.run

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class DeriveSharedSecretTest {

    @Test
    fun sameResult_regardless_of_argument_order() {
        val secretA = ByteArray(32) { it.toByte() }
        val secretB = ByteArray(32) { (31 - it).toByte() }

        val resultAB = deriveSharedSecret(secretA, secretB)
        val resultBA = deriveSharedSecret(secretB, secretA)

        assertArrayEquals(
            "deriveSharedSecret must produce the same result regardless of order",
            resultAB, resultBA
        )
    }

    @Test
    fun identical_secrets_produce_consistent_result() {
        val secret = ByteArray(32) { 0x42 }
        val result1 = deriveSharedSecret(secret, secret)
        val result2 = deriveSharedSecret(secret.copyOf(), secret.copyOf())

        assertArrayEquals(result1, result2)
    }

    @Test
    fun different_secrets_produce_different_results() {
        val secretA = ByteArray(32) { 0x00 }
        val secretB = ByteArray(32) { 0x01 }
        val secretC = ByteArray(32) { 0x02 }

        val resultAB = deriveSharedSecret(secretA, secretB)
        val resultAC = deriveSharedSecret(secretA, secretC)

        assertFalse(
            "Different secret pairs must produce different results",
            resultAB.contentEquals(resultAC)
        )
    }

    @Test
    fun output_is_32_bytes() {
        val secretA = ByteArray(32) { it.toByte() }
        val secretB = ByteArray(32) { (it + 100).toByte() }

        val result = deriveSharedSecret(secretA, secretB)
        assert(result.size == 32) { "SHA-256 output must be 32 bytes" }
    }
}

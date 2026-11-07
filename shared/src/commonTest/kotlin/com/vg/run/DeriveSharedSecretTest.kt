package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class DeriveSharedSecretTest {

    @Test
    fun sameResult_regardless_of_argument_order() {
        val a = generateSecureRandom(32)
        val b = generateSecureRandom(32)
        val result1 = deriveSharedSecret(a, b)
        val result2 = deriveSharedSecret(b, a)
        assertTrue(result1.contentEquals(result2))
    }

    @Test
    fun identical_secrets_produce_consistent_result() {
        val secret = generateSecureRandom(32)
        val result1 = deriveSharedSecret(secret, secret)
        val result2 = deriveSharedSecret(secret, secret)
        assertTrue(result1.contentEquals(result2))
    }

    @Test
    fun different_secrets_produce_different_results() {
        val a = generateSecureRandom(32)
        val b = generateSecureRandom(32)
        val c = generateSecureRandom(32)
        val result1 = deriveSharedSecret(a, b)
        val result2 = deriveSharedSecret(a, c)
        assertNotEquals(result1.toList(), result2.toList())
    }

    @Test
    fun output_is_32_bytes() {
        val a = generateSecureRandom(32)
        val b = generateSecureRandom(32)
        assertEquals(32, deriveSharedSecret(a, b).size)
    }
}

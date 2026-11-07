package com.vg.run

import kotlin.test.Test
import kotlin.test.assertTrue

class ConstantTimeEqualsTest {

    @Test
    fun equal_arrays_return_true() {
        val a = generateSecureRandom(32)
        assertTrue(constantTimeEquals(a, a.copyOf()))
    }

    @Test
    fun different_arrays_return_false() {
        val a = generateSecureRandom(32)
        val b = generateSecureRandom(32)
        assertTrue(!constantTimeEquals(a, b))
    }

    @Test
    fun different_sizes_return_false() {
        val a = generateSecureRandom(32)
        val b = generateSecureRandom(16)
        assertTrue(!constantTimeEquals(a, b))
    }

    @Test
    fun empty_arrays_are_equal() {
        assertTrue(constantTimeEquals(ByteArray(0), ByteArray(0)))
    }
}

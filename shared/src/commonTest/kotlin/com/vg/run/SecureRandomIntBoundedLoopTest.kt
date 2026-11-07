package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.assertFailsWith

class SecureRandomIntBoundedLoopTest {

    @Test
    fun values_are_in_range_and_loop_terminates() {
        // Exercising it heavily also proves the bounded loop terminates.
        for (bound in listOf(1, 2, 3, 7, 11, 256, 1000, Int.MAX_VALUE)) {
            repeat(1000) {
                val v = secureRandomInt(bound)
                assertTrue(v in 0 until bound, "secureRandomInt($bound) returned out-of-range $v")
            }
        }
    }

    @Test
    fun bound_one_always_zero() {
        repeat(100) { assertEquals(0, secureRandomInt(1)) }
    }

    @Test
    fun rejects_nonpositive_bound() {
        assertFailsWith<IllegalArgumentException> { secureRandomInt(0) }
        assertFailsWith<IllegalArgumentException> { secureRandomInt(-5) }
    }
}

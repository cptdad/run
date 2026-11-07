package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class SecureRandomIntTest {

    @Test
    fun zero_inclusive_lower_bound() {
        // Over many samples, 0 should be reachable.
        var sawZero = false
        repeat(2000) { if (secureRandomInt(7) == 0) sawZero = true }
        assertTrue(sawZero, "expected to see 0 in 2000 draws of bound=7")
    }

    @Test
    fun output_strictly_below_bound() {
        repeat(5000) {
            val v = secureRandomInt(7)
            assertTrue(v in 0..6, "$v out of [0,7)")
        }
    }

    @Test
    fun rejects_zero_or_negative_bound() {
        try { secureRandomInt(0); error("expected IAE for bound=0") } catch (_: IllegalArgumentException) {}
        try { secureRandomInt(-1); error("expected IAE for bound=-1") } catch (_: IllegalArgumentException) {}
    }

    @Test
    fun bound_one_always_zero() {
        repeat(50) { assertEquals(0, secureRandomInt(1)) }
    }

    @Test
    fun distribution_is_roughly_uniform_for_bound_7() {
        // Chi-squared sanity check. With 70_000 samples and bound=7 the
        // expected count per bucket is 10_000. Critical value at p=0.0001
        // for 6 d.o.f. is ~30. A correct implementation should rarely cross
        // it. A modulo-bias regression (e.g. `bytes[0] % 7`) yields a
        // chi-squared in the hundreds.
        val n = 70_000
        val counts = IntArray(7)
        repeat(n) { counts[secureRandomInt(7)]++ }
        val expected = n.toDouble() / 7.0
        var chi2 = 0.0
        for (c in counts) {
            val diff = c - expected
            chi2 += (diff * diff) / expected
        }
        assertTrue(chi2 < 30.0, "chi^2 = $chi2, distribution looks biased")
    }
}

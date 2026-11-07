package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class RingPulseTest {
    private val eps = 1e-4f

    @Test
    fun troughAndPeakAtPhaseExtremes() {
        assertEquals(RingPulse.trough(0.4f), RingPulse.opacity(0.4f, 0f), eps)
        assertEquals(RingPulse.peak(0.4f), RingPulse.opacity(0.4f, 0.5f), eps)
        assertEquals(RingPulse.trough(0.4f), RingPulse.opacity(0.4f, 1f), eps)
    }

    @Test
    fun fullRedOnlyAtHundred() {
        assertEquals(1f, RingPulse.peak(1f), eps)
        assertTrue(RingPulse.peak(0.99f) < 1f)
        assertTrue(RingPulse.opacity(0f, 0.5f) >= 0.6f) // bright from the first breath
    }

    @Test
    fun strongerAndStronger_monotoneInProgressAtEveryPhase() {
        for (ph in listOf(0f, 0.1f, 0.25f, 0.5f, 0.75f, 0.9f)) {
            var last = -1f
            for (i in 0..100) {
                val v = RingPulse.opacity(i / 100f, ph)
                assertTrue(v >= last, "phase $ph p=$i: $v < $last")
                assertTrue(v in 0f..1f)
                last = v
            }
        }
    }

    @Test
    fun amplitudeGrowsWithProgress() {
        val a0 = RingPulse.peak(0f) - RingPulse.trough(0f)
        val a1 = RingPulse.peak(1f) - RingPulse.trough(1f)
        assertTrue(a1 > a0)
    }

    @Test
    fun phaseWrapsWithTheClock() {
        assertEquals(0f, RingPulse.phaseAt(0), eps)
        assertEquals(0.5f, RingPulse.phaseAt(RingPulse.PERIOD_MS / 2), eps)
        assertEquals(0f, RingPulse.phaseAt(RingPulse.PERIOD_MS * 7), eps)
        assertTrue(RingPulse.phaseAt(-1) in 0f..1f)
    }
}

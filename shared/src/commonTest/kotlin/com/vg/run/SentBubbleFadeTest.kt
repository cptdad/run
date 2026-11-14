package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class SentBubbleFadeTest {
    private val eps = 1e-5f

    @Test
    fun pendingStartsAtStartAlpha() {
        assertEquals(SentBubbleFade.START_ALPHA, SentBubbleFade.pendingAlpha(0), eps)
        assertEquals(SentBubbleFade.START_ALPHA, SentBubbleFade.pendingAlpha(-500), eps)
    }

    @Test
    fun pendingIsMonotoneAndNeverExceedsCap() {
        var prev = 0f
        var t = 0L
        while (t <= 60_000L) {
            val a = SentBubbleFade.pendingAlpha(t)
            assertTrue(a >= prev - eps, "monotone at $t")
            assertTrue(a <= SentBubbleFade.PENDING_CAP + eps, "cap at $t")
            prev = a
            t += 50
        }
        assertEquals(SentBubbleFade.PENDING_CAP, SentBubbleFade.pendingAlpha(SentBubbleFade.CREEP_MS), eps)
        assertEquals(SentBubbleFade.PENDING_CAP, SentBubbleFade.pendingAlpha(Long.MAX_VALUE), eps)
    }

    @Test
    fun deliveredIsExactlyOpaque() {
        for (t in listOf(0L, 1L, 5_000L, 10_000L, 1_000_000L)) {
            assertEquals(1f, SentBubbleFade.alpha(t, delivered = true))
        }
    }

    @Test
    fun failedOrPartialNeverBecomesOpaque() {
        for (t in listOf(0L, 5_000L, 10_000L, 86_400_000L)) {
            assertTrue(SentBubbleFade.alpha(t, delivered = false) <= SentBubbleFade.PENDING_CAP + eps)
        }
        assertTrue(SentBubbleFade.PENDING_CAP < 0.6f, "the cap must stay clearly translucent")
        assertEquals(SentBubbleFade.PENDING_CAP, SentBubbleFade.reducedMotionPendingAlpha())
    }

    @Test
    fun transitionRunsFromPendingToOpaque() {
        val p = 0.4f
        assertEquals(p, SentBubbleFade.transitionAlpha(p, 0f), eps)
        assertEquals(1f, SentBubbleFade.transitionAlpha(p, 1f), eps)
        assertTrue(SentBubbleFade.transitionAlpha(p, 0.5f) in p..1f)
        assertEquals(1f, SentBubbleFade.transitionAlpha(p, 7f), eps)
    }

    @Test
    fun creepingStopsAtCreepDuration() {
        assertTrue(SentBubbleFade.isCreeping(0))
        assertTrue(SentBubbleFade.isCreeping(SentBubbleFade.CREEP_MS - 1))
        assertFalse(SentBubbleFade.isCreeping(SentBubbleFade.CREEP_MS))
    }
}

package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class RunestoneGeometryTest {
    private val eps = 0.01f

    @Test
    fun fillWidthIsWidthDriven() {
        // 412 dp wide → art drawn 828 dp tall → foot at 68 %
        assertEquals(412f * 1254f / 624f * 0.68f, RunestoneGeometry.stoneBottomY(412f, 900f, fillWidth = true), eps)
    }

    @Test
    fun aspectFillOnATallPhoneIsHeightDriven() {
        // 402 × 874 pt (art aspect 0.498 > screen 0.46): the art fills the height exactly
        assertEquals(874f * 0.68f, RunestoneGeometry.stoneBottomY(402f, 874f, fillWidth = false), eps)
    }

    @Test
    fun aspectFillOnAWideViewportCentresTheOverflow() {
        val w = 1000f; val h = 1000f
        val drawnH = w * 1254f / 624f
        val expected = drawnH * 0.68f - (drawnH - h) / 2f
        assertEquals(expected, RunestoneGeometry.stoneBottomY(w, h, fillWidth = false), eps)
        assertTrue(expected < h)
    }

    @Test
    fun ringBottomIsBelowTheStoneFootOnBothFillModes() {
        // The forcefield base (78.5 %) ends under the stone's foot (68 %), so
        // a caption anchored to it clears the ring on every art tier.
        assertEquals(412f * 1254f / 624f * 0.785f, RunestoneGeometry.ringBottomY(412f, 900f, fillWidth = true), eps)
        assertEquals(874f * 0.785f, RunestoneGeometry.ringBottomY(402f, 874f, fillWidth = false), eps)
        assertTrue(RunestoneGeometry.ringBottomY(412f, 900f, true) > RunestoneGeometry.stoneBottomY(412f, 900f, true))
        assertTrue(RunestoneGeometry.ringBottomY(402f, 874f, false) > RunestoneGeometry.stoneBottomY(402f, 874f, false))
    }

    @Test
    fun captionStartsAFixedGapBelowTheRing() {
        // "Connecting to…" well below the blue ring.
        assertEquals(
            RunestoneGeometry.ringBottomY(402f, 874f, false) + RunestoneGeometry.BELOW_RING_GAP,
            RunestoneGeometry.captionTopY(402f, 874f, false), eps,
        )
        assertEquals(RunestoneGeometry.BELOW_RING_GAP, RunestoneGeometry.belowRingGap(), eps)
        assertTrue(RunestoneGeometry.captionTopY(402f, 874f, false) < 874f)
    }
}

package com.vg.run

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The triple-tap gesture that expands the live connection-log panel
 * (`Modifier.tripleTapToggle`, ConnectionLogPanel.kt). Clock-injected, so the
 * 600 ms window is pinned here instead of in a device test.
 *
 * iOS uses SwiftUI's built-in `.onTapGesture(count: 3)`, which owns its own
 * (system) window — there is no Swift sibling to test.
 */
class TripleTapDetectorTest {

    @Test
    fun firesOnTheThirdTapInsideTheWindow() {
        val d = TripleTapDetector()
        assertFalse(d.onTap(0))
        assertFalse(d.onTap(200))
        assertTrue(d.onTap(400))
    }

    @Test
    fun doesNotFireOnTwoTaps() {
        val d = TripleTapDetector()
        assertFalse(d.onTap(0))
        assertFalse(d.onTap(100))
    }

    @Test
    fun aLateThirdTapStartsAFreshRunInsteadOfFiring() {
        val d = TripleTapDetector()
        assertFalse(d.onTap(0))
        assertFalse(d.onTap(200))
        // 601 ms after the FIRST tap — outside the window.
        assertFalse(d.onTap(601))
        // …and that late tap became tap #1 of a new run, so two more fire.
        assertFalse(d.onTap(700))
        assertTrue(d.onTap(800))
    }

    @Test
    fun resetsAfterFiringSoASixthTapIsNeededForASecondToggle() {
        val d = TripleTapDetector()
        d.onTap(0); d.onTap(100)
        assertTrue(d.onTap(200))
        assertFalse(d.onTap(250))
        assertFalse(d.onTap(300))
        assertTrue(d.onTap(350))
    }

    @Test
    fun singleTapsFarApartNeverFire() {
        val d = TripleTapDetector()
        for (i in 0 until 10) assertFalse(d.onTap(i * 5_000L))
    }
}

package com.vg.run

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for the pure pieces of the update-nudge store gate:
 * [isPlayInstaller] and
 * [PLAY_STORE_MARKET_URI]. [RunViewModel.isPlayInstall] itself needs a real
 * `Application`/`PackageManager` (no Robolectric in this module — see the
 * other `*SourceTest`s), so it stays untested here; this pins the decision it
 * delegates to plus the URL it opens, both fail-closed-relevant.
 */
class UpdateNudgeInstallGateTest {

    @Test
    fun playStorePackage_isPlayInstall() {
        assertTrue(isPlayInstaller("com.android.vending"))
    }

    @Test
    fun nullInstaller_isNotPlayInstall() {
        // Sideload / `adb install` / no installer of record — fail CLOSED to
        // the info-only variant, never assume a store install.
        assertFalse(isPlayInstaller(null))
    }

    @Test
    fun emptyStringInstaller_isNotPlayInstall() {
        assertFalse(isPlayInstaller(""))
    }

    @Test
    fun otherStoreInstaller_isNotPlayInstall() {
        // A look-alike or another store's package id proves nothing — exact
        // match only, never a substring/prefix match.
        assertFalse(isPlayInstaller("com.amazon.venezia"))
        assertFalse(isPlayInstaller("com.android.vendingx"))
        assertFalse(isPlayInstaller("xcom.android.vending"))
    }

    @Test
    fun marketUri_hasNoHttpsFallback() {
        // `market://` only, and it must resolve to no store other
        // than THIS app's own listing.
        assertEquals("market://details?id=com.vg.run", PLAY_STORE_MARKET_URI)
        assertTrue(PLAY_STORE_MARKET_URI.startsWith("market://"))
        assertFalse(PLAY_STORE_MARKET_URI.contains("https://"))
    }
}

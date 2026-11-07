package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

// ProtectionLevel — the three-tier slider (Casual / Private / Maximum). Pins the
// lever mapping (credential type + Lever B) and that the per-level auto-lock /
// self-wipe thresholds tighten monotonically CASUAL → MAXIMUM, plus the persisted
// storage values (a rename would silently orphan every provisioned install's level).
class ProtectionLevelTest {

    @Test
    fun storageValuesAreStableAndRoundTrip() {
        assertEquals("casual", ProtectionLevel.CASUAL.storageValue)
        assertEquals("private", ProtectionLevel.PRIVATE.storageValue)
        assertEquals("maximum", ProtectionLevel.MAXIMUM.storageValue)
        for (l in ProtectionLevel.entries) {
            assertEquals(l, ProtectionLevel.fromStorageOrNull(l.storageValue))
        }
    }

    @Test
    fun fromStorage_unknownOrNullIsNull() {
        assertNull(ProtectionLevel.fromStorageOrNull(null))
        assertNull(ProtectionLevel.fromStorageOrNull(""))
        assertNull(ProtectionLevel.fromStorageOrNull("high-risk"))
    }

    @Test
    fun retiredHardenedMapsForwardToPrivate() {
        // "hardened" was folded into PRIVATE (identical crypto — PIN + Lever B); a
        // vault provisioned at Hardened must keep working, at Private's gentler timers.
        assertEquals(ProtectionLevel.PRIVATE, ProtectionLevel.fromStorageOrNull("hardened"))
    }

    @Test
    fun onlyMaximumUsesAPassphrase_andOnlyPrivateBindsHardware() {
        // Only MAXIMUM is passphrase; only PRIVATE binds hardware (Lever B).
        assertFalse(ProtectionLevel.CASUAL.usesPassphrase)
        assertFalse(ProtectionLevel.PRIVATE.usesPassphrase)
        assertTrue(ProtectionLevel.MAXIMUM.usesPassphrase)

        assertFalse(ProtectionLevel.CASUAL.usesLeverB)
        assertTrue(ProtectionLevel.PRIVATE.usesLeverB)
        assertFalse(ProtectionLevel.MAXIMUM.usesLeverB)
    }

    @Test
    fun strictComposerKeyboard_onlyMaximum() {
        // Keyboard privacy scales with the tier (2026-09-20, option 3): only
        // MAXIMUM keeps the password-style composer; see ComposerKeyboardPolicy
        // for how a persisted-level READ (not a bare tier) resolves this.
        assertFalse(ProtectionLevel.CASUAL.strictComposerKeyboard)
        assertFalse(ProtectionLevel.PRIVATE.strictComposerKeyboard)
        assertTrue(ProtectionLevel.MAXIMUM.strictComposerKeyboard)
    }

    @Test
    fun autoLockTightensMonotonically() {
        val c = ProtectionLevel.CASUAL.autoLockTimeoutMs
        val p = ProtectionLevel.PRIVATE.autoLockTimeoutMs
        val m = ProtectionLevel.MAXIMUM.autoLockTimeoutMs
        assertTrue(c > p && p > m, "auto-lock must tighten CASUAL→MAXIMUM ($c>$p>$m)")
        // PRIVATE keeps the current shipped default (2 min) so it's the neutral point.
        assertEquals(CredentialPolicy.AUTO_LOCK_TIMEOUT_MS, p)
    }

    @Test
    fun inactivityWipeTightensMonotonically() {
        val c = ProtectionLevel.CASUAL.inactivityWipeMs
        val p = ProtectionLevel.PRIVATE.inactivityWipeMs
        val m = ProtectionLevel.MAXIMUM.inactivityWipeMs
        assertTrue(c > p && p > m, "inactivity wipe must tighten CASUAL→MAXIMUM")
        // MAXIMUM keeps the current shipped 7-day default.
        assertEquals(InactivityPolicy.THRESHOLD_MS, m)
    }

    @Test
    fun wrongTriesTightensMonotonically() {
        val c = ProtectionLevel.CASUAL.maxConsecutiveAttempts
        val p = ProtectionLevel.PRIVATE.maxConsecutiveAttempts
        val m = ProtectionLevel.MAXIMUM.maxConsecutiveAttempts
        assertTrue(c >= p && p >= m, "wrong-tries must not loosen CASUAL→MAXIMUM")
        assertTrue(c == 10 && m == 5)
        // MAXIMUM keeps the current shipped 5-try default.
        assertEquals(CredentialPolicy.MAX_CONSECUTIVE_ATTEMPTS, m)
    }
}

package com.vg.run

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Unit tests for [honestPersistedLevel] — the pure decision that keeps the
 * PERSISTED protection tier honest about the key actually backing the vault
 * atomically. It is the single point both the onboarding
 * (PinSetupScreen) and settings (ProtectionLevelSettingsScreen) flows use to
 * decide which tier to write, so a hardened tier is never persisted over a plain
 * (non-auth-bound) DB key.
 */
class HonestPersistedLevelTest {

    @Test
    fun private_withLeverBEnabled_staysPrivate() {
        // Success path: the auth-bound key engaged, so PRIVATE is honest.
        assertEquals(
            ProtectionLevel.PRIVATE,
            honestPersistedLevel(ProtectionLevel.PRIVATE, leverBEnabled = true),
        )
    }

    @Test
    fun private_withoutLeverB_downgradesToCasual() {
        // Cancelled biometric / failed enable: the DB key is plain, so the honest
        // tier is CASUAL — never "PRIVATE persisted + plain key".
        assertEquals(
            ProtectionLevel.CASUAL,
            honestPersistedLevel(ProtectionLevel.PRIVATE, leverBEnabled = false),
        )
    }

    @Test
    fun casual_isAlwaysCasual() {
        assertEquals(
            ProtectionLevel.CASUAL,
            honestPersistedLevel(ProtectionLevel.CASUAL, leverBEnabled = false),
        )
        assertEquals(
            ProtectionLevel.CASUAL,
            honestPersistedLevel(ProtectionLevel.CASUAL, leverBEnabled = true),
        )
    }

    @Test
    fun maximum_doesNotUseLeverB_soAlwaysHonest() {
        // MAXIMUM's strength is the passphrase, not Lever B, so the Lever B outcome
        // must never demote it.
        assertEquals(
            ProtectionLevel.MAXIMUM,
            honestPersistedLevel(ProtectionLevel.MAXIMUM, leverBEnabled = false),
        )
        assertEquals(
            ProtectionLevel.MAXIMUM,
            honestPersistedLevel(ProtectionLevel.MAXIMUM, leverBEnabled = true),
        )
    }

    @Test
    fun onlyLeverBTiersAreEverDowngraded() {
        // Exhaustive guard: for every tier, a false Lever B result may only ever
        // reduce a tier that actually uses Lever B, and only to CASUAL.
        for (level in ProtectionLevel.entries) {
            val result = honestPersistedLevel(level, leverBEnabled = false)
            if (level.usesLeverB) {
                assertEquals(ProtectionLevel.CASUAL, result)
            } else {
                assertEquals(level, result)
            }
        }
    }
}

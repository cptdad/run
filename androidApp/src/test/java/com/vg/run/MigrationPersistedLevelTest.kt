package com.vg.run

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test

/**
 * Unit tests for [migrationPersistedLevel] — the pure decision
 * [ProtectionLevelMigrationScreen] uses to pick what to PERSIST for a legacy
 * vault's one-time tier choice
 * (including the MAXIMUM/passphrase dimension below).
 *
 * Migration never runs the interactive Lever B enable, or an interactive
 * credential rotation, inline (unlike onboarding / Settings), so it must
 * never persist a tier whose precondition doesn't already hold: PRIVATE
 * unless Lever B is ALREADY bound, or MAXIMUM unless the credential is
 * ALREADY a passphrase — otherwise the vault would claim a hardware-bound
 * key, or passphrase-strength protection, it doesn't actually have. This
 * also pins the "diverges from chosen" contract the migration screen relies
 * on to decide whether the follow-up trip to Settings is a real remediation
 * (see the composable's needsLever check) rather than a no-op.
 */
class MigrationPersistedLevelTest {

    @Test
    fun private_withLeverBAlreadyBound_persistsPrivate() {
        assertEquals(
            ProtectionLevel.PRIVATE,
            migrationPersistedLevel(ProtectionLevel.PRIVATE, leverBEnabled = true, passphraseAlreadySet = false),
        )
    }

    @Test
    fun private_withoutLeverB_downgradesToCasual() {
        // The over-claim this guards against: migration cannot enable
        // Lever B inline, so a plain-keyed vault must never be labelled PRIVATE.
        assertEquals(
            ProtectionLevel.CASUAL,
            migrationPersistedLevel(ProtectionLevel.PRIVATE, leverBEnabled = false, passphraseAlreadySet = false),
        )
    }

    @Test
    fun private_withoutLeverB_divergesFromChosen() {
        // The composable's "needs a follow-up note" / "Settings isn't a no-op"
        // logic depends on persisted != chosen exactly in this case.
        val chosen = ProtectionLevel.PRIVATE
        val persisted = migrationPersistedLevel(chosen, leverBEnabled = false, passphraseAlreadySet = false)
        assertNotEquals(chosen, persisted)
    }

    @Test
    fun casual_isAlwaysCasual() {
        assertEquals(
            ProtectionLevel.CASUAL,
            migrationPersistedLevel(ProtectionLevel.CASUAL, leverBEnabled = false, passphraseAlreadySet = false),
        )
        assertEquals(
            ProtectionLevel.CASUAL,
            migrationPersistedLevel(ProtectionLevel.CASUAL, leverBEnabled = true, passphraseAlreadySet = true),
        )
    }

    @Test
    fun maximum_withPassphraseAlreadySet_persistsMaximum_regardlessOfLeverB() {
        // MAXIMUM has no Lever B component (Lever A / passphrase only) — once
        // its ONE precondition (a passphrase credential) already holds, it
        // persists as chosen.
        assertEquals(
            ProtectionLevel.MAXIMUM,
            migrationPersistedLevel(ProtectionLevel.MAXIMUM, leverBEnabled = false, passphraseAlreadySet = true),
        )
        assertEquals(
            ProtectionLevel.MAXIMUM,
            migrationPersistedLevel(ProtectionLevel.MAXIMUM, leverBEnabled = true, passphraseAlreadySet = true),
        )
    }

    @Test
    fun maximum_withoutPassphrase_downgradesToCasual() {
        // The credential is still whatever PIN the legacy
        // vault already had — migration never rotates it — so persisting
        // MAXIMUM here would claim passphrase-strength protection over a PIN.
        assertEquals(
            ProtectionLevel.CASUAL,
            migrationPersistedLevel(ProtectionLevel.MAXIMUM, leverBEnabled = false, passphraseAlreadySet = false),
        )
    }

    @Test
    fun maximum_withoutPassphrase_divergesFromChosen() {
        // Same "real remediation, not a no-op" contract as the PRIVATE case:
        // Settings must see persisted != current so re-picking Maximum there
        // actually runs the credential rotation instead of short-circuiting.
        val chosen = ProtectionLevel.MAXIMUM
        val persisted = migrationPersistedLevel(chosen, leverBEnabled = false, passphraseAlreadySet = false)
        assertNotEquals(chosen, persisted)
    }

    @Test
    fun maximum_withoutPassphrase_ignoresLeverB() {
        // MAXIMUM's precondition is the passphrase, not Lever B — a bound
        // Lever B (left over from a prior PRIVATE pick) must not paper over a
        // missing passphrase.
        assertEquals(
            ProtectionLevel.CASUAL,
            migrationPersistedLevel(ProtectionLevel.MAXIMUM, leverBEnabled = true, passphraseAlreadySet = false),
        )
    }
}

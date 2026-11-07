package com.vg.run

import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

// LOCALIZATION: DeviceLockPolicy.stopReason now returns a resolved resource key
// (protection_stop_* in strings_shared.xml). Tests that assert on the ENGLISH
// wording install that text via platformStringOverride; tests that only need a
// non-null/null shape don't (fail-soft key text still satisfies those).
class DeviceLockPolicyTest {

    @AfterTest
    fun tearDown() {
        platformStringOverride = null
    }

    private val english = mapOf(
        "protection_stop_no_lock" to "Your phone has no %1\$s, only Maximum can protect Rún here.",
        "protection_stop_no_chip" to "This phone has no security chip.",
        "protection_stop_no_biometrics" to "Biometrics is missing. setup Face ID or fingerprint.",
        "protection_device_lock_term_android" to "lock screen",
        "protection_device_lock_term_ios" to "passcode",
    )

    private fun installEnglish() {
        platformStringOverride = { key, args -> formatPositional(english[key] ?: key, args) }
    }

    // -----------------------------------------------------------------------
    // The floor itself
    // -----------------------------------------------------------------------

    @Test
    fun tierOrdinalsAscendWeakToStrong() {
        // The whole policy compares ORDINALS (so does the settings screen's
        // downgrade confirm). Reordering the enum would silently invert the
        // floor — a lock-less phone could then be forced DOWN to Casual.
        assertTrue(ProtectionLevel.CASUAL.ordinal < ProtectionLevel.PRIVATE.ordinal)
        assertTrue(ProtectionLevel.PRIVATE.ordinal < ProtectionLevel.MAXIMUM.ordinal)
        assertEquals(ProtectionLevel.MAXIMUM, DeviceLockPolicy.LEVEL_WITHOUT_DEVICE_LOCK)
    }

    @Test
    fun noLockScreenForcesMaximum() {
        assertEquals(ProtectionLevel.MAXIMUM, DeviceLockPolicy.forcedLevel(DeviceLockState.Absent))
    }

    @Test
    fun aLockedDeviceIsNotForced() {
        assertNull(DeviceLockPolicy.forcedLevel(DeviceLockState.Present))
    }

    @Test
    fun anUNKNOWNProbeDoesNotForce() {
        // Fail direction (documented in DeviceLockPolicy): an ambiguous probe
        // must not drag a user through an irreversible credential migration.
        // The check re-runs every unlock, so a real no-passcode phone is caught
        // as soon as the probe answers definitely.
        assertNull(DeviceLockPolicy.forcedLevel(DeviceLockState.Unknown))
        assertTrue(DeviceLockPolicy.isSelectable(ProtectionLevel.CASUAL, DeviceLockState.Unknown, leverBSupported = true))
        assertFalse(DeviceLockPolicy.needsForcedMigration(ProtectionLevel.CASUAL, DeviceLockState.Unknown))
    }

    // -----------------------------------------------------------------------
    // Selectability — the chooser's greyed stops
    // -----------------------------------------------------------------------

    @Test
    fun withoutALockScreenOnlyMaximumIsSelectable() {
        for (level in ProtectionLevel.entries) {
            assertEquals(
                level == ProtectionLevel.MAXIMUM,
                DeviceLockPolicy.isSelectable(level, DeviceLockState.Absent, leverBSupported = true),
                "selectability of $level without a lock screen",
            )
        }
    }

    @Test
    fun maximumIsAlwaysSelectable() {
        // The forced tier can never be unreachable, whatever the hardware says
        // — otherwise a lock-less phone would have NO legal level at all.
        for (lock in DeviceLockState.entries) {
            for (hw in listOf(true, false)) {
                assertTrue(
                    DeviceLockPolicy.isSelectable(ProtectionLevel.MAXIMUM, lock, hw),
                    "MAXIMUM must stay selectable (lock=$lock, leverB=$hw)",
                )
            }
        }
    }

    @Test
    fun privateStillNeedsItsHardware() {
        // The pre-existing stop survives the new one.
        assertFalse(DeviceLockPolicy.isSelectable(ProtectionLevel.PRIVATE, DeviceLockState.Present, leverBSupported = false))
        assertTrue(DeviceLockPolicy.isSelectable(ProtectionLevel.PRIVATE, DeviceLockState.Present, leverBSupported = true))
    }

    @Test
    fun everyStopCarriesAReason_andSelectableOnesCarryNone() {
        for (level in ProtectionLevel.entries) {
            for (lock in DeviceLockState.entries) {
                for (hw in listOf(true, false)) {
                    val selectable = DeviceLockPolicy.isSelectable(level, lock, hw)
                    val reason = DeviceLockPolicy.stopReason(level, lock, hw)
                    if (selectable) assertNull(reason, "$level/$lock/$hw should have no stop reason")
                    else assertNotNull(reason, "$level/$lock/$hw must explain itself")
                }
            }
        }
    }

    @Test
    fun theNoLockStopNamesTheTierThatWorks() {
        // A stop the user can act on must never read as a dead end (the greyed
        // Private copy got this wrong once — f53aaec). The no-lock-screen stop now
        // names the ONE tier that still protects Rún here. (The device-lock term
        // itself is platform-worded via the top-level protectionDeviceLockTerm,
        // so we assert on the term-agnostic "Maximum" rather than "lock screen"/"passcode".)
        installEnglish()
        val reason = DeviceLockPolicy.stopReason(ProtectionLevel.CASUAL, DeviceLockState.Absent, leverBSupported = true)
        assertNotNull(reason)
        assertTrue(reason.contains("Maximum"), "must name the tier that works: $reason")
    }

    @Test
    fun privateStopReasonsSplitChipVsBiometrics() {
        installEnglish()
        // PRIVATE-biometric hardening: when Lever B is unavailable on a device that
        // HAS a lock screen, the reason distinguishes "no security chip" (no hardware /
        // biometric sensor) from "enroll biometrics" (sensor present, nothing enrolled).
        assertNull(
            DeviceLockPolicy.stopReason(
                ProtectionLevel.PRIVATE, DeviceLockState.Present,
                leverBSupported = true, secureElementPresent = true),
            "PRIVATE with SE + biometrics must be selectable (no stop reason)",
        )
        assertEquals(
            "This phone has no security chip.",
            DeviceLockPolicy.stopReason(
                ProtectionLevel.PRIVATE, DeviceLockState.Present,
                leverBSupported = false, secureElementPresent = false),
        )
        assertEquals(
            "Biometrics is missing. setup Face ID or fingerprint.",
            DeviceLockPolicy.stopReason(
                ProtectionLevel.PRIVATE, DeviceLockState.Present,
                leverBSupported = false, secureElementPresent = true),
        )
        // Default (no probe wired) favours the common-case "enroll biometrics" on real
        // hardware rather than the chip-less message.
        assertEquals(
            "Biometrics is missing. setup Face ID or fingerprint.",
            DeviceLockPolicy.stopReason(
                ProtectionLevel.PRIVATE, DeviceLockState.Present, leverBSupported = false),
        )
    }

    // -----------------------------------------------------------------------
    // Forced migration — the part that makes the rule real
    // -----------------------------------------------------------------------

    @Test
    fun aBelowFloorVaultOnALocklessPhoneMustMigrate() {
        // The Android hole: provisioned WITH a lock screen at Casual, then the
        // lock screen is removed. Nothing invalidates, nothing notices — except
        // this check, on every unlock.
        assertTrue(DeviceLockPolicy.needsForcedMigration(ProtectionLevel.CASUAL, DeviceLockState.Absent))
        assertTrue(DeviceLockPolicy.needsForcedMigration(ProtectionLevel.PRIVATE, DeviceLockState.Absent))
    }

    @Test
    fun anAtFloorVaultDoesNotMigrate() {
        assertFalse(DeviceLockPolicy.needsForcedMigration(ProtectionLevel.MAXIMUM, DeviceLockState.Absent))
    }

    @Test
    fun aLockedDeviceNeverMigrates() {
        for (level in ProtectionLevel.entries) {
            assertFalse(DeviceLockPolicy.needsForcedMigration(level, DeviceLockState.Present))
        }
    }

    @Test
    fun aLevellessLegacyVaultIsLeftToTheChooser() {
        // stored == null routes to the one-time chooser, which is itself gated
        // by isSelectable — routing it to the forced flow as well would fight
        // over the same screen.
        assertFalse(DeviceLockPolicy.needsForcedMigration(null, DeviceLockState.Absent))
    }

    // -----------------------------------------------------------------------
    // 2A-1 — the [stored] argument's PROVENANCE
    // -----------------------------------------------------------------------

    @Test
    fun theFloorGateMustBeFedTheProvenRead() {
        // This is a FLOOR, so the fail direction is the inverse of every
        // timer/budget read of the same slot: a tier that merely CLAIMS to be at
        // or above it must not be believed. `vlt_lvl` keeps a legacy-cleartext
        // fallback that carries no integrity, so the seven ASCII bytes `maximum`
        // — writable by anyone who can write the app's private storage — used to
        // satisfy this comparison forever on a lock-less phone.
        //
        // The coupling both consumers (MainActivity.postUnlockRoute and
        // IosAppController.needsForcedProtectionMigration) must respect:
        // VaultSelector.protectionLevelForFloorCheck, whose decision unit is
        // provenProtectionLevel, answers with the WEAKEST tier for anything it
        // cannot authenticate.
        val lenient = ProtectionLevel.MAXIMUM                       // protectionLevelOrNull (pre-fix)
        val proven = SelectorMetaPolicy.provenProtectionLevel(           // protectionLevelForFloorCheck
            storedLevel = ProtectionLevel.MAXIMUM, present = true, authenticated = false,
        )
        assertFalse(DeviceLockPolicy.needsForcedMigration(lenient, DeviceLockState.Absent))
        assertTrue(DeviceLockPolicy.needsForcedMigration(proven, DeviceLockState.Absent))
    }

    @Test
    fun anUnprovenTierNeverForcesWithoutADefiniteNoLockAnswer() {
        // Brick-safety / fail-direction: the provenance rule tightens WHAT counts
        // as being at the floor; it must not widen WHEN the floor applies. Only a
        // definite Absent still forces.
        val proven = SelectorMetaPolicy.provenProtectionLevel(
            storedLevel = ProtectionLevel.MAXIMUM, present = true, authenticated = false,
        )
        assertFalse(DeviceLockPolicy.needsForcedMigration(proven, DeviceLockState.Present))
        assertFalse(DeviceLockPolicy.needsForcedMigration(proven, DeviceLockState.Unknown))
    }
}

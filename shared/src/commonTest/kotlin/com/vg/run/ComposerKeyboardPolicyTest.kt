package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// ComposerKeyboardPolicy — "keyboard privacy scales with the protection tier"
// (2026-09-20, option 3). Pins the fail-toward-strict direction for every
// ProtectionLevelRead state — the one shared decision both RunViewModel
// (Android) and IosAppController.strictComposerKeyboard() (iOS) consume so
// the two composers can never diverge on when the password-style keyboard
// applies.
// ---------------------------------------------------------------------------

class ComposerKeyboardPolicyTest {

    @Test
    fun present_maximumIsStrict_casualAndPrivateAreNot() {
        assertTrue(ComposerKeyboardPolicy.isStrict(ProtectionLevelRead.Present(ProtectionLevel.MAXIMUM)))
        assertFalse(ComposerKeyboardPolicy.isStrict(ProtectionLevelRead.Present(ProtectionLevel.CASUAL)))
        assertFalse(ComposerKeyboardPolicy.isStrict(ProtectionLevelRead.Present(ProtectionLevel.PRIVATE)))
    }

    @Test
    fun absentDamagedUnreadable_allFailStrict() {
        // Unlike ReauthPolicy (whose Absent is false — periodic re-auth is a NEW
        // behaviour a legacy vault never had), a legacy vault's composer has
        // ALWAYS been unconditionally strict, so Absent must not be the state
        // that first loosens it. Damaged/Unreadable cost only UX here (no emoji
        // key), never data, so both stay strict too — matching
        // CredentialPolicy.autoLockTimeoutMs's "locking/hardening sooner loses
        // no data" fail direction, not ReauthPolicy's destructive-budget one.
        assertTrue(ComposerKeyboardPolicy.isStrict(ProtectionLevelRead.Absent))
        assertTrue(ComposerKeyboardPolicy.isStrict(ProtectionLevelRead.Damaged))
        assertTrue(ComposerKeyboardPolicy.isStrict(ProtectionLevelRead.Unreadable))
    }

    @Test
    fun present_delegatesToTheLevelsOwnProperty() {
        for (level in ProtectionLevel.entries) {
            assertEquals(
                level.strictComposerKeyboard,
                ComposerKeyboardPolicy.isStrict(ProtectionLevelRead.Present(level)),
            )
        }
    }
}

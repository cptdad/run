package com.vg.run

// ---------------------------------------------------------------------------
// ComposerKeyboardPolicy — "keyboard privacy scales with the protection tier"
// (decided 2026-09-20). Resolves a persisted-level READ
// ([ProtectionLevelRead], from [VaultSelector.protectionLevelForEnforcement])
// to the single Boolean both message composers gate their `KeyboardType`/
// `.textContentType` on — mirrors [ReauthPolicy.appliesTo] /
// [CredentialPolicy.autoLockTimeoutMs] so PinEntryScreen-adjacent UI never has
// to interpret [ProtectionLevelRead] itself.
//
// Fail-secure direction matches [CredentialPolicy.autoLockTimeoutMs], NOT
// [ReauthPolicy.appliesTo]: showing the stricter (password-style) composer
// costs only UX — no emoji key on Android — never data, so every state OTHER
// than a confirmed CASUAL/PRIVATE [ProtectionLevelRead.Present] stays strict,
// including [ProtectionLevelRead.Absent]. That is the opposite of
// ReauthPolicy's Absent handling: a legacy pre-slider vault never had a
// choice here — the composer has ALWAYS run in password mode unconditionally
// — so "nothing chosen yet" must not be the branch that first loosens it.
// ---------------------------------------------------------------------------

object ComposerKeyboardPolicy {
    /**
     * True = strict (password-style) composer; false = ordinary text keyboard
     * with suggestions/emoji.
     *  - Present    -> the chosen tier's [ProtectionLevel.strictComposerKeyboard].
     *  - Absent     -> true (legacy pre-slider install; matches the composer's
     *    unconditional pre-tier-split behavior, never loosened by silence).
     *  - Damaged    -> true (fail-secure: a blob that fails AEAD under
     *    a WORKING device key is positive tamper evidence).
     *  - Unreadable -> true (transient device-key outage: a healthy blob and a
     *    damaged one are indistinguishable here, and — unlike the destructive
     *    decisions in CredentialPolicy — there is no "shrinking a chosen
     *    budget" cost to weigh against, so this stays strict rather than
     *    picking the most lenient tier).
     */
    fun isStrict(read: ProtectionLevelRead): Boolean = when (read) {
        is ProtectionLevelRead.Present -> read.level.strictComposerKeyboard
        ProtectionLevelRead.Absent -> true
        ProtectionLevelRead.Damaged -> true
        ProtectionLevelRead.Unreadable -> true
    }
}

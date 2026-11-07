package com.vg.run

// ---------------------------------------------------------------------------
// ProtectionLevel — the three-tier "protection slider" that bundles the existing
// forensic-hardening levers into one intent-level choice made at onboarding (and
// changeable from Settings).
//
//   CASUAL   — PIN, no hardware binding. Smoothest; not built to survive seizure.
//   PRIVATE  — PIN + Lever B (hardware auth-bound DB key). A seized phone strongly
//              resists offline brute-forcing; moderate auto-lock / self-wipe timers.
//   MAXIMUM  — passphrase (Lever A, ≥70-bit), biometrics off, no hardware crutch.
//              Coercion-resistant; tightest auto-lock / self-wipe.
//
// The per-level numbers are the spec's recommended STARTING values (tunable).
// Levers A (passphrase) and B (auth-bound key) are applied through the existing
// VaultSelector APIs; C (auto-lock) + the two self-wipe thresholds are read at
// their enforcement sites via the accessors below. The chosen level is PERSISTED
// explicitly (vlt_lvl) so enforcement reads one source of truth for the timers.
//
// IMPORTANT (migration safety): enforcement sites read the level via a NULLABLE
// accessor and fall back to the current CredentialPolicy/InactivityPolicy
// constants when it is unset, so a legacy vault provisioned before the slider
// keeps its exact behavior — a level is only ever applied to installs that
// explicitly chose one.
// ---------------------------------------------------------------------------

enum class ProtectionLevel(val storageValue: String) {
    CASUAL("casual"),
    PRIVATE("private"),
    MAXIMUM("maximum");

    /** MAXIMUM unlocks with a passphrase (Lever A); the rest use a 6-digit PIN. */
    val usesPassphrase: Boolean get() = this == MAXIMUM

    /** PRIVATE binds the DB key to hardware (Lever B). */
    val usesLeverB: Boolean get() = this == PRIVATE

    /**
     * Keyboard privacy scales with the tier (by design):
     * MAXIMUM keeps the password-style message composer — the IME never learns
     * message words into its on-device dictionary (which lives outside the app
     * sandbox and survives a wipe) and offers no suggestions, but on Android this
     * ALSO costs the emoji key (Gboard/Samsung Keyboard both drop it in password
     * mode; iOS keeps its emoji key either way). CASUAL and PRIVATE get an
     * ordinary text keyboard — personalized-learning/suggestions are disabled
     * where the platform lets us ask without going all the way to a password
     * field (see the Android/iOS composer wiring for the exact per-platform
     * limitation). See [ComposerKeyboardPolicy] for how a persisted-level READ
     * (rather than a bare tier) resolves this, including the legacy/damaged/
     * unreadable fail-toward-strict cases.
     */
    val strictComposerKeyboard: Boolean get() = this == MAXIMUM

    /** Lever C — idle auto-lock timeout (ms). Tightens CASUAL → MAXIMUM.
     *
     *  MAXIMUM is 60 s: 30 s closed the app while people were still READING a
     *  message (the 5 s warning overlay softened that but couldn't fix it) and
     *  is a hostile floor for the test-phone automation, where a passcode-less
     *  phone is forced to this tier. 60 s is double the idle-AFU window it
     *  bounds, which stays far inside PRIVATE's 2 min
     *  and is bounded anyway by the immediate lock on background. */
    val autoLockTimeoutMs: Long get() = when (this) {
        CASUAL   -> 15L * 60 * 1000
        PRIVATE  ->  2L * 60 * 1000
        MAXIMUM  -> 60L * 1000
    }

    /** Inactivity dead-man self-wipe threshold (ms). Always on; scales gentle → aggressive. */
    val inactivityWipeMs: Long get() = when (this) {
        CASUAL   -> 180L * 24 * 60 * 60 * 1000
        PRIVATE  ->  90L * 24 * 60 * 60 * 1000
        MAXIMUM  ->   7L * 24 * 60 * 60 * 1000
    }

    /** Consecutive wrong-credential self-wipe threshold. Always on. */
    val maxConsecutiveAttempts: Int get() = when (this) {
        CASUAL   -> 10
        PRIVATE  -> 8
        MAXIMUM  -> 5
    }

    companion object {
        /**
         * Default when nothing has ever been chosen. Only used as the display
         * fallback for a legacy (pre-slider) install; enforcement uses the
         * nullable path so a legacy vault keeps the current constants, not
         * CASUAL's (gentler) numbers.
         */
        val DEFAULT = CASUAL

        /** Largest wrong-credential budget of any tier — the fail-safe for an
         *  UNREADABLE stored level (see [ProtectionLevelRead.Unreadable]): a
         *  level we cannot read must never yield a SMALLER budget than the one
         *  the user chose ("cannot decide" never wipes). */
        val MOST_LENIENT_MAX_ATTEMPTS: Int = entries.maxOf { it.maxConsecutiveAttempts }

        /** Parse the persisted [storageValue]; null when unset/unknown. The retired
         *  "hardened" tier (folded into PRIVATE — same crypto) maps forward so a vault
         *  provisioned at Hardened keeps working at Private (its gentler timers). */
        fun fromStorageOrNull(value: String?): ProtectionLevel? =
            if (value == "hardened") PRIVATE
            else entries.firstOrNull { it.storageValue == value }
    }
}

// ---------------------------------------------------------------------------
// ProtectionLevelRead — four-state result of reading the PERSISTED level for a
// DESTRUCTIVE enforcement site (inactivity self-wipe, wrong-credential budget).
//
// Absent and Unreadable must never be conflated: the stored level is a
// device-key AEAD blob, and collapsing "present but
// unreadable right now" into the legacy-absent fallback silently substitutes
// the (tighter) current constants for the user's chosen tier — e.g. a CASUAL
// vault's 180-day inactivity window becomes the 7-day default and the vault is
// crypto-erased ~173 days early. Display sites keep using
// VaultSelector.protectionLevelOrNull (null routes a broken level to the
// one-time chooser, whose write self-heals the blob).
//
// Damaged is split out of Unreadable for the opposite
// reason — see [Damaged].
// ---------------------------------------------------------------------------
sealed class ProtectionLevelRead {
    /** No level was ever chosen (legacy pre-slider install) — the current
     *  CredentialPolicy/InactivityPolicy constants apply, as always. */
    data object Absent : ProtectionLevelRead()

    /** The stored level, decrypted and parsed. */
    data class Present(val level: ProtectionLevel) : ProtectionLevelRead()

    /**
     * A level IS stored, the device key WORKS, and the
     * blob failed AEAD verification — positive evidence of tampering/corruption
     * of that one value, not an outage. Folding this into [Unreadable] made the
     * dead-man's-switch permanently disarmable: flipping one byte INSIDE the
     * base64 (rather than deleting the key, which yields [Absent] and keeps the
     * 7-day default) skipped the inactivity check on EVERY launch, so an
     * examiner could hold the device for months while working the credential,
     * and it simultaneously raised the wrong-credential budget from 5 to 10.
     *
     * So this state selects the STRICTEST tier's policy window (MAXIMUM), the
     * same fail-secure direction an unrecognized-but-authenticated token gets.
     *
     * BRICK-SAFETY: Damaged is a POLICY-WINDOW selector, never a wipe trigger.
     * It only says "enforce MAXIMUM's 7-day window / 5-attempt budget"; the
     * wipe itself still requires the ordinary positive evidence (a decryptable
     * last-active timestamp that is genuinely past the window, or the attempt
     * counter actually reaching the budget). Ambiguous ABSENCE keeps its
     * establish-on-read behaviour ([Absent]) and a transient device-key outage
     * keeps deferring ([Unreadable]) — neither may ever route here.
     */
    data object Damaged : ProtectionLevelRead()

    /** A level IS stored but cannot be read right now because the DEVICE KEY is
     *  transiently unavailable (locked keybag / Keystore hiccup) — we cannot
     *  tell a healthy blob from a damaged one, so destructive enforcement must
     *  fail SAFE: skip the check or use the most lenient tier value, never a
     *  shorter-than-chosen window. A blob that provably fails AEAD with a
     *  WORKING key is [Damaged], not this. */
    data object Unreadable : ProtectionLevelRead()
}

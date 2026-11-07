package com.vg.run

// ---------------------------------------------------------------------------
// DeviceLockPolicy — "a phone with no lock screen MUST run at MAXIMUM".
//
// WHY (the security argument, in full):
//
// CR-1 binds the vault's DB key to TWO factors: the user credential and a
// device key. On a phone with no lock screen the device-key factor is free to
// anyone holding the handset:
//   * iOS — kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly cannot be
//     satisfied, so KeychainHelper deliberately falls back to
//     AfterFirstUnlockThisDeviceOnly (it logs the downgrade). That item is
//     readable in any AFU extraction.
//   * Android — setUnlockedDeviceRequired(true) is vacuous when there is no
//     lock screen to be locked, and Lever B (auth-bound key) cannot exist at
//     all: it needs a credential to bind to.
//
// So CR-1 collapses to ONE factor: whatever the user types, stretched by
// Argon2id. CASUAL's 6-digit PIN is ~20 bits — offline brute force becomes a
// compute-budget question, not an infeasibility. PRIVATE is already
// unselectable (its hardware key needs a credential). MAXIMUM is the only tier
// left whose promise still holds once the device key is captured, because its
// passphrase clears CredentialPolicy.MIN_PASSPHRASE_BITS (70 bits).
//
// Without this rule the SAME tier label means two very different things
// depending on a device setting the app never looked at. That asymmetry — not
// the PIN itself — is the defect this closes.
//
// FAIL DIRECTION: only a DEFINITE [DeviceLockState.Absent] forces. [Unknown]
// (an ambiguous LAContext error on iOS; Android's KeyguardManager is always
// definite) leaves the user's chosen tier alone. That is the same convention
// the four existing probe sites use (KeychainHelper / UserSafety /
// SecureEnclaveHelper / ContentView all assume a passcode IS set when the
// error is ambiguous), and it is the right direction here too: forcing an
// irreversible credential migration on a transient probe failure is worse than
// missing one launch's enforcement, and the check re-runs on EVERY unlock.
// ---------------------------------------------------------------------------

/** Whether this device has a lock screen (passcode / PIN / pattern / biometric
 *  enrolment behind one). [Unknown] is reserved for a probe that FAILED — it is
 *  never "probably not". */
enum class DeviceLockState {
    Present,
    Absent,
    Unknown,
}

object DeviceLockPolicy {

    /** The floor a lock-less device is held to. */
    val LEVEL_WITHOUT_DEVICE_LOCK: ProtectionLevel = ProtectionLevel.MAXIMUM

    /**
     * The tier this device MUST run at, or null when the user chooses freely.
     * Only a definite [DeviceLockState.Absent] forces — see the fail-direction
     * note above.
     */
    fun forcedLevel(lock: DeviceLockState): ProtectionLevel? =
        if (lock == DeviceLockState.Absent) LEVEL_WITHOUT_DEVICE_LOCK else null

    /**
     * Whether [level] may be picked on this device. Two independent stops:
     *  - the forced floor (no lock screen → nothing below MAXIMUM), and
     *  - PRIVATE's hardware requirement ([leverBSupported]).
     *
     * [leverBSupported] is [VaultSelector.supportsDbKeyAuthBinding], which as of
     * the PRIVATE-biometric-hardening change means BOTH "a secure-element / hardware
     * auth-bound key is available" AND "strong biometrics are enrolled" — because
     * the auth-bound key is now biometric-only (iOS `.biometryCurrentSet` / Android
     * AUTH_BIOMETRIC_STRONG) and cannot be created or used without an enrollment.
     * So a single boolean still gates PRIVATE correctly; [stopReason] splits the two
     * sub-reasons for the user via [secureElementPresent].
     * Both stops are shown with their own reason ([stopReason]) rather than a
     * silently greyed slider stop.
     */
    fun isSelectable(
        level: ProtectionLevel,
        lock: DeviceLockState,
        leverBSupported: Boolean,
    ): Boolean {
        val floor = forcedLevel(lock)
        if (floor != null && level.ordinal < floor.ordinal) return false
        if (level.usesLeverB && !leverBSupported) return false
        return true
    }

    /**
     * Why [level] is greyed out, or null when it is selectable. Copy lives here
     * so both platforms say the same thing — a stop the user can act on must never
     * read as a dead end.
     *
     * [leverBSupported] = secure element AND biometrics enrolled (see [isSelectable]).
     * [secureElementPresent] separates the two PRIVATE sub-reasons: when Lever B is
     * unavailable, is it because there is NO hardware/biometric sensor at all
     * ("no security chip"), or because the sensor is there but nothing is enrolled
     * ("Biometrics is missing")? Defaults to `true`, so a caller that doesn't wire
     * the probe still gets the common-case "enroll biometrics" message on real
     * hardware (every real iPhone, and any Android phone with a fingerprint sensor);
     * pass the platform secure-element probe (Android
     * `AuthBoundKeyStore.isSecureElementPresent(context)`; iOS is always `true` on a
     * real device) to also get the precise "no security chip" message on chip-less /
     * old-OS devices.
     */
    // LOCALIZATION: reasons are resource keys resolved through [platformString] at
    // call time (protection_stop_* in strings_shared.xml), so a language change is
    // picked up without any caching here.
    fun stopReason(
        level: ProtectionLevel,
        lock: DeviceLockState,
        leverBSupported: Boolean,
        secureElementPresent: Boolean = true,
    ): String? = when {
        isSelectable(level, lock, leverBSupported) -> null
        // No lock screen forces MAXIMUM — greys BOTH the sub-MAXIMUM tiers (Decent
        // and Secure). Handled FIRST so the PRIVATE branches below only ever see a
        // device that HAS a lock screen. [protectionDeviceLockTerm] is the top-level
        // expect val beside ProtectionLevelContent — "lock screen" on Android /
        // "passcode" on iOS.
        forcedLevel(lock) != null && level.ordinal < LEVEL_WITHOUT_DEVICE_LOCK.ordinal ->
            platformString("protection_stop_no_lock", protectionDeviceLockTerm)
        // From here the only remaining unselectable case is PRIVATE (Lever B) on a
        // device WITH a lock screen but missing the hardware/biometric prerequisites.
        !secureElementPresent ->
            platformString("protection_stop_no_chip")
        else ->
            platformString("protection_stop_no_biometrics")
    }

    /**
     * True when an ALREADY-PROVISIONED vault is sitting below the floor and has
     * to be migrated up before the app can be used.
     *
     * This is what makes the rule real rather than cosmetic. Gating the chooser
     * only covers vaults provisioned on a lock-less phone; the undetected hole
     * is the phone that HAD a lock at provision time and lost it afterwards:
     *  - Android CASUAL is the live one — no auth-bound key to invalidate, and
     *    setUnlockedDeviceRequired just goes vacuous. Nothing notices.
     *  - iOS is partly self-solving (removing the passcode purges the
     *    WhenPasscodeSet device key, so the vault dies with it — and the
     *    recovery blob dies too).
     * So the probe belongs on every unlock, not just at onboarding.
     *
     * [stored] is the persisted level; null (never chosen — a legacy vault)
     * returns false because the one-time chooser runs first and is itself
     * gated by [isSelectable].
     *
     * [stored] MUST come from `VaultSelector.protectionLevelForFloorCheck()`, never
     * from the lenient `protectionLevelOrNull()`. This is a
     * FLOOR, so the fail direction is the inverse of every timer/budget decision:
     * `vlt_lvl` tolerates a legacy CLEARTEXT value that carries no integrity, and
     * seven planted ASCII bytes (`maximum`) reading back verbatim satisfy
     * `level.ordinal < floor.ordinal` forever — silently disarming the one control
     * written for the lock-less device class. The floor-check accessor answers with
     * the WEAKEST tier for anything it cannot authenticate, which is what makes the
     * comparison below meaningful. Both consumers — `MainActivity.postUnlockRoute`
     * and `IosAppController.needsForcedProtectionMigration` — must stay on it.
     */
    fun needsForcedMigration(stored: ProtectionLevel?, lock: DeviceLockState): Boolean {
        val floor = forcedLevel(lock) ?: return false
        val level = stored ?: return false
        return level.ordinal < floor.ordinal
    }
}

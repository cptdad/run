package com.vg.run

// ---------------------------------------------------------------------------
// ProtectionUpgradePlan — the ONE decision every tier screen on both platforms
// makes before it persists a stronger tier: does moving to this level require
// ROTATING the credential first?
//
// There used to be FOUR copies of this predicate —
// ProtectionLevelSettingsScreen.apply() and ProtectionLevelView.apply (Settings,
// both platforms) plus ProtectionLevelMigrationScreen and the one-time chooser in
// ProtectionLevelView (the post-unlock migration, both platforms) — and all four
// spelled it `level.usesPassphrase && !isPassphraseMode()`. `isPassphraseMode()`
// fails OPEN to `true` for anything it cannot authenticate (it picks the ENTRY
// WIDGET, and the digit keypad hard-locks a passphrase user out), so ≥28 bytes of
// base64 garbage planted in `vlt_m` answered "a passphrase is already set" and the
// upgrade became a pure metadata write: an AEAD-AUTHENTICATED `vlt_lvl = maximum`
// over an UNCHANGED 6-digit PIN, permanently satisfying
// DeviceLockPolicy.needsForcedMigration — the lock-less floor (a passcode-less
// phone must run at MAXIMUM) — on a vault a later, image-only attacker then grinds at ~20 bits.
//
// The rule is now PROOF-gated and lives here once, so the two platforms cannot
// drift: only an AEAD-authenticated `vlt_m` saying `phrase`
// (VaultSelector.credentialKindProven() == true) may SKIP the rotation. Every
// other state — unauthenticated cleartext, a plant, a damaged blob, a device-key
// outage, an unknown token — routes the user through the credential change, which
// is recoverable, non-destructive, and re-writes `vlt_m` as an authenticated blob
// on the way, so a genuine legacy install self-heals rather than looping.
// ---------------------------------------------------------------------------
object ProtectionUpgradePlan {

    /**
     * True when [target] cannot be honestly persisted until the credential has
     * been rotated — i.e. the tier's strength IS a passphrase (Lever A / MAXIMUM)
     * and this vault cannot PROVE it already has one.
     *
     * [credentialKindProven] is [VaultSelector.credentialKindProven]'s tri-state:
     * `true` = proven passphrase, `false` = proven PIN, `null` = unproven. Only
     * `true` skips the credential chain; `false` and `null` both require it.
     *
     * A null [target] (a storage token this build does not recognise) is treated
     * as "no passphrase implied", which is exactly what the pre-fix platform code
     * did — the tier vocabulary is closed and every caller picks from it.
     *
     * Nothing destructive rides on this: a `true` costs one pass through the
     * credential-change screen, a `false` persists a tier that is honest about
     * what backs it.
     */
    fun needsCredentialChange(target: ProtectionLevel?, credentialKindProven: Boolean?): Boolean =
        target?.usesPassphrase == true && credentialKindProven != true

    /**
     * [needsCredentialChange] over the persisted STORAGE token ("casual" /
     * "private" / "maximum"), for the Swift call sites, which carry the tier as a
     * String throughout. Unknown/absent tokens parse to null — see above.
     */
    fun needsCredentialChangeForStorage(
        targetStorageValue: String?,
        credentialKindProven: Boolean?,
    ): Boolean = needsCredentialChange(
        ProtectionLevel.fromStorageOrNull(targetStorageValue),
        credentialKindProven,
    )

    /**
     * The ONE-TIME CHOOSER's finish-note rule: did that screen leave work the
     * user must finish in Settings?
     *
     * It neither rotates the credential nor enables Lever B, so the note is owed
     * exactly when (a) the chosen tier needs a credential rotation this screen did
     * not perform, or (b) what it could honestly persist is not what was chosen
     * ([persisted] != [chosen] — the Lever-B half, via `honestPersistedLevel` /
     * `migrationPersistedLevel`). Android spells this inline in
     * `ProtectionLevelMigrationScreen` as `mustRotateCredential || persistedLevel
     * != level`; iOS calls it here.
     *
     * iOS used to additionally OR in `!usesPassphrase &&
     * isPassphraseMode()` — the fail-OPEN widget reader, which Android has never
     * consulted here. That disjunct made a passphrase vault picking a PIN tier
     * show "almost there, finish in Settings" when there is nothing to finish
     * (the credential is untouched and the persisted tier IS the chosen one), and
     * it cost a second `vlt_m` decrypt. Both platforms now answer from this rule
     * alone. Note the DOWNGRADE direction is not this function's business at all:
     * a passphrase kept under a CASUAL label under-claims, which is the safe side.
     */
    fun needsFinishInSettings(
        chosen: ProtectionLevel?,
        persisted: ProtectionLevel?,
        mustRotateCredential: Boolean,
    ): Boolean = mustRotateCredential || persisted != chosen

    /** [needsFinishInSettings] over the storage tokens, for the Swift call site. */
    fun needsFinishInSettingsForStorage(
        chosenStorageValue: String?,
        persistedStorageValue: String?,
        mustRotateCredential: Boolean,
    ): Boolean = needsFinishInSettings(
        ProtectionLevel.fromStorageOrNull(chosenStorageValue),
        ProtectionLevel.fromStorageOrNull(persistedStorageValue),
        mustRotateCredential,
    )
}

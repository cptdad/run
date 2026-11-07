package com.vg.run

// ---------------------------------------------------------------------------
// VaultStoreKeys — THE table of every vault-selector store key, and
// VaultCryptoContexts — every AEAD context / KDF label that is part of the
// on-disk format.
//
// FROZEN VALUES: a key name or context string IS the persisted format, so
// changing a VALUE (rather than a Kotlin name) orphans or bricks every existing
// vault. Kotlin names may be renamed freely.
//
// Each key's kdoc starts with one line in a fixed shape:
//   holds · sealed under · written by · store · wiped by · legacy-UD era
// "store" — Android: the `vault_selector_prefs` SharedPreferences file (via
// KeyValueStore.android.kt); iOS: the Keychain KV service (via
// KeyValueStore.ios.kt), which ALSO holds PinAttemptsStore / ChangePinAttemptStore
// / debug-consent / ext-proxy / notification-consent items (one service, so
// `kvDeleteAll` sweeps all of them). "wiped by" — Android: WipeRoutine deletes
// the whole prefs file; iOS: IosAppController.emergencyWipe's `kvDeleteAll` plus
// the NSUserDefaults sweep of [IosUserDefaultsKeys.all]. "legacy-UD era" — the
// key may have a pre-Keychain NSUserDefaults copy on iOS and is therefore in
// [IosUserDefaultsKeys.all]; that list is a SECURITY gate (it is also what lets
// KeyValueStore.ios.kt answer a read from the plist), so a Keychain-native key
// must NEVER be added to it.
//
// Deliberately NOT folded in here, because each is a POLICY over keys with its
// own membership rule: `ratchetMetaKeysForContact` / `GroupMetaKeys` (vault
// `_meta` purge lists — see VaultDatabase), `MoveMetaPolicy` (what a device move
// carries), [IosUserDefaultsKeys.all], `WipeRoutine.PREFS_FILES`, and
// [VaultWriteProofs.PROVISION_ROLLBACK_KEYS] (order-load-bearing). The inactivity
// deletion anchor `inactivity_armed_v1` is declared below as the public top-level
// [INACTIVITY_ARMED_ANCHOR_KEY] (both InactivityWipes read it; this internal object
// is invisible to androidApp and Swift).
// ---------------------------------------------------------------------------

/**
 * Storage key of the wrapped (PIN + device-key) SQLCipher DB key inside the
 * vault-selector store — [VaultStoreKeys.WRAPPED_DBKEY]. Public and top-level so
 * the app module can reference the exact key the (internal) VaultSelector writes
 * — used by the attempt-counter anchor in RunViewModel, which must fail closed
 * when this un-deletable-without-destroying-the-vault wrap is present but the
 * counter is absent.
 */
const val VAULT_DBKEY_STORAGE_KEY = "vlt_c"

/**
 * `inactivity_armed_v1` — presence flag "the inactivity timestamp was durably armed once"
 * · none (not credential material) · InactivityWipe (Android) / InactivityWipe.swift (iOS)
 * · Android: `vault_selector_prefs` (fate-shared with `vlt_c`), iOS: Keychain KV · prefs
 * delete / `kvDeleteAll` · legacy-UD: no. Public and top-level because both app modules
 * read it; the value is the persisted format and must never change.
 */
const val INACTIVITY_ARMED_ANCHOR_KEY = "inactivity_armed_v1"

internal object VaultStoreKeys {
    /**
     * `vlt_a` — KDF version ‖ salt ‖ verifier [‖ Argon2 cost] ([VaultKdf.parseCredentialBlob])
     * · device-key AEAD, ctx [VaultCryptoContexts.CREDENTIAL] · provision, change-credential,
     * KDF migration, key-name migration · both · prefs delete / `kvDeleteAll` · legacy-UD: yes
     * (as [IosUserDefaultsKeys.CREDENTIAL_VERIFIER]).
     */
    // Neutral, opaque storage-key names. (They were once "real_*"/"decoy_*",
    // which leaked vault layout as cleartext key NAMES — the AEAD only
    // protects the VALUES, never the names. Renamed to
    // opaque labels and migrated in place by VaultSelector.migrateLegacyKeyNamesIfNeeded via
    // [LEGACY_KEY_NAME_MIGRATIONS].)
    const val CREDENTIAL_VERIFIER = "vlt_a"

    /**
     * `vlt_c` — [DbKeyScheme] neutral `v:` blob → outer [DbKeyProtector] layer →
     * `aesGcmEncrypt(DbKeyPayload, kek, DBKEY_INNER)` · device key or auth-bound key, ctx
     * [VaultCryptoContexts.DBKEY_INNER] · provision, change-credential, KDF migration, the
     * Lever B toggle/enable/finalize/legacy reconcile, recovery, rotation promotion, raw-key
     * adoption · both · prefs delete / `kvDeleteAll` · legacy-UD: yes.
     */
    // Wrapped (PIN + device-key) SQLCipher passphrase. CR-1: the DB key is
    // bound to the user PIN so that device-key extraction alone cannot open
    // the vault. Value is the public [VAULT_DBKEY_STORAGE_KEY] so the app
    // module (RunViewModel's attempt-counter anchor) can name the same
    // key this internal table defines, without exposing the whole table.
    const val WRAPPED_DBKEY = VAULT_DBKEY_STORAGE_KEY

    /**
     * `vlt_cn` — rotation candidate, same form as [WRAPPED_DBKEY] · same layers · written ONLY
     * by a change-credential tier upgrade · both · prefs delete / `kvDeleteAll` · legacy-UD: NO
     * (Keychain-native).
     */
    // The PENDING SQLCipher key of an in-flight DB-key
    // rotation. Byte-identical in FORM to [WRAPPED_DBKEY] — the same
    // dbKeyProtector wrap of the same `aesGcmEncrypt(dbKey, kek, VaultCryptoContexts.DBKEY_INNER)`
    // inner — so promoting it is a pure byte COPY that needs no key material and
    // can therefore run at unlock, off the reconcile path, with nothing but the
    // store.
    //
    // THE INVARIANT, and the only thing that makes any interruption point safe:
    //   union { vlt_c, vlt_cn } ALWAYS contains the key the file is encrypted with.
    // No cross-engine atomicity is needed (the store and SQLCipher are different
    // engines and cannot commit together — that is what sank the original
    // proposal). Instead the OLD key stays in `vlt_c` until the new one is PROVEN
    // to open the file, and the new one is durable in `vlt_cn` before the re-key
    // starts. Same shape as the shipped relay capability rotation.
    //
    // It is written ONLY by a credential TIER UPGRADE (PIN → passphrase) over a
    // PLAIN, recovery-blob-free vault; see [DbKeyRotationPolicy.mayRotateDbKey] for why each of those
    // conditions is load-bearing. Its presence is NEVER evidence of tamper and
    // never gates a wipe — an unresolved record is resolved by opening the file,
    // and "we could not tell" always means CHANGE NOTHING.
    //
    // Cleared by every wipe (Android deletes the whole vault_selector_prefs file;
    // iOS's kvDeleteAll() sweeps the whole Keychain KV service), exactly like
    // [AUTHBOUND_SCHEME] and [RECOVERY_PENDING] — so, like them, it is
    // deliberately NOT added to IosUserDefaultsKeys.all: that list exists for keys
    // that may have a LEGACY NSUserDefaults copy, and a brand-new Keychain-resident
    // key never can.
    const val PENDING_DBKEY = "vlt_cn"

    /**
     * `vlt_m` — [SelectorMetaPolicy.MODE_PIN] / [SelectorMetaPolicy.MODE_PASSPHRASE],
     * NUL-padded · device-key AEAD, ctx `SELECTOR_META_PREFIX + "vlt_m"` · provision,
     * change-credential · both · prefs delete / `kvDeleteAll` · legacy-UD: yes.
     */
    // Credential-mode flag (Lever A): MODE_PIN →
    // 6-digit PIN keypad; MODE_PASSPHRASE → free-text passphrase. (Absent is only
    // a LEGACY state — installs provisioned before the always-write rule — and still reads as
    // PIN for backward compatibility.)
    // The VALUE is a device-key AEAD blob (fixed
    // per-key context — see readSelectorMeta/encryptSelectorMeta), NOT cleartext.
    // Previously plaintext, which on Android sat in the unencrypted
    // shared_prefs XML and told a forensic examiner reading the file off disk
    // whether the vault uses a PIN (brute-force worthwhile) or a ≥70-bit
    // passphrase. It is still readable BEFORE unlock — the device key is the
    // same pre-unlock layer that decrypts the credential verifier (evalCredential)
    // — so it can still pick the entry UI. Legacy plaintext values are read
    // transparently and upgraded to a blob on the next write (migrate-on-write).
    // The plaintext is NUL-padded to a fixed length before
    // AEAD so "pin" vs "phrase" no longer differ in ciphertext length, and the key
    // is ALWAYS written (MODE_PIN too) so its presence/absence can't leak the mode
    // either. The crypto below is credential-agnostic — this flag is purely a UI
    // selector. Flipped ONLY inside the atomic change-credential write so the
    // mode can never disagree with the stored credential.
    const val CREDENTIAL_MODE = "vlt_m"

    /**
     * `vlt_lvl` — [ProtectionLevel] token, NUL-padded · device-key AEAD, ctx
     * `SELECTOR_META_PREFIX + "vlt_lvl"` · provision, `setProtectionLevel`, Lever B finalize ·
     * both · prefs delete / `kvDeleteAll` · legacy-UD: yes.
     */
    // Chosen protection tier (threat-level slider). A
    // device-key AEAD blob like the mode flag (was plaintext — leaked the
    // target's paranoia tier off disk). The plaintext is
    // NUL-padded to a fixed length before AEAD (like vlt_m) so the ciphertext
    // length no longer distinguishes CASUAL ("casual", 6B) from PRIVATE/MAXIMUM
    // (7B) at rest. Still readable BEFORE unlock (device key, pre-unlock) to drive
    // the per-level auto-lock / self-wipe thresholds at their pre-unlock
    // enforcement sites; legacy plaintext is read transparently and upgraded on
    // the next write — but an UNAUTHENTICATED (legacy
    // cleartext, therefore forgeable) value is display-only. Destructive
    // enforcement fails secure to MAXIMUM on it; see protectionLevelForEnforcement.
    // (Presence still legitimately means "a tier was chosen" — the
    // padding hides WHICH tier, and absence keeps the legacy fallback.) Absent = a legacy install
    // provisioned before the slider; enforcement then falls back to the current
    // CredentialPolicy/InactivityPolicy constants (no silent weakening — see
    // ProtectionLevel + protectionLevelOrNull).
    const val PROTECTION_LEVEL = "vlt_lvl"

    /**
     * `vlt_rc` — device AEAD( AES-GCM(recovery-KEK, R) ) · ctx [VaultCryptoContexts.RECOVERY]
     * on both layers · Lever B enable (phase one), post-recovery re-establish · both · prefs
     * delete / `kvDeleteAll` · legacy-UD: yes (it had a real UserDefaults era; dropping it from
     * [IosUserDefaultsKeys.all] would strand pre-migration recovery codes). Classified, never
     * presence-checked: [RecoveryBlobPolicy.classifyRecoveryBlob].
     */
    // Recovery blob (Lever B data-recovery code). An INDEPENDENT
    // wrap of the SQLCipher passphrase (dbKey) under a KEK derived from a 160-bit
    // user-held code, then device-AEAD'd. Lets a vault whose hardware auth-bound
    // key later invalidates (biometric re-enroll / device-passcode change) be
    // recovered instead of bricked. Wraps dbKey (STABLE) not the PIN-KEK inner,
    // so it survives PIN rotation with no regeneration. Written only while Lever
    // B is enabled; removed when it is disabled. NOT a PIN-only copy (the 160-bit
    // code is the barrier), so it doesn't re-open the brute-PIN attack Lever B
    // prevents.
    const val RECOVERY_BLOB = "vlt_rc"

    /**
     * `vlt_rp` — [RecoveryBlobPolicy.RECOVERY_PENDING_ARMED], NUL-padded · device-key AEAD,
     * ctx `SELECTOR_META_PREFIX + "vlt_rp"` · armed by the Lever B enable BEFORE the `vlt_rc`
     * write, cleared by every path that claims or drops the blob · both · prefs delete /
     * `kvDeleteAll` · legacy-UD: NO (Keychain-native).
     */
    // The "a Lever B enable is IN FLIGHT" marker.
    //
    // Enabling Lever B is two-phase: phase one commits + read-back-verifies
    // [RECOVERY_BLOB] and then holds the auth-bound blob in RAM only
    // (`VaultSelector.pendingAuthBoundBlob`) until the user acknowledges the displayed code.
    // If finalize never runs — back press (that screen registers no back
    // handler), auto-lock mid-transcription, backgrounding, process death — the
    // vault stays PLAIN while `vlt_rc` lives on disk forever: a second, live,
    // independent vault-decrypt path the user believes was never created. Worse,
    // a later PIN rotation nulls the RAM blob, so the enable can never be
    // finalized while the orphan survives every future rotation.
    //
    // This marker names that state EXACTLY, so the unlock-time purge fires only
    // on positive evidence and never on the post-recovery re-establish window
    // (which deliberately re-mints `vlt_rc` under the SAME user code — see
    // `VaultSelector.tryReEstablishLeverBAfterRecovery`). Stored as a device-key selector-meta
    // blob (like vlt_m / vlt_lvl / vlt_abk) and honoured ONLY when the read is
    // AUTHENTICATED — an unauthenticated (legacy-cleartext-shaped, therefore
    // plantable) value must never be able to revoke a recovery code.
    //
    // Cleared by every wipe (Android deletes the whole vault_selector_prefs file;
    // iOS's kvDeleteAll() sweeps the whole Keychain KV service), exactly like
    // [AUTHBOUND_SCHEME] — so, like it, this key is deliberately NOT added to
    // IosUserDefaultsKeys.all: that list exists for keys that may have a LEGACY
    // NSUserDefaults copy, and a brand-new Keychain-resident key never can.
    const val RECOVERY_PENDING = "vlt_rp"

    /**
     * `vlt_abk` — [SelectorMetaPolicy.AUTHBOUND_SCHEME_STRICT], NUL-padded · device-key
     * AEAD, ctx `SELECTOR_META_PREFIX + "vlt_abk"` · every strict auth-bound key commit
     * (removed when the blob goes plain) · both · prefs delete / `kvDeleteAll` · legacy-UD:
     * NO (Keychain-native).
     */
    // Scheme marker for the auth-bound (Lever B) key (PRIVATE-biometric
    // hardening). Present + == [SelectorMetaPolicy.AUTHBOUND_SCHEME_STRICT] means the CURRENT ab:
    // DB-key blob is wrapped by the biometric-only, strict-invalidate key.
    // ABSENT while the blob is auth-bound = a LEGACY WEAK key (biometric
    // OR device-credential, survives re-enrollment) minted before the strict-scheme marker existed — a
    // cracked device passcode still opens it, so the unlock-time reconcile re-mints
    // it strict when it is SAFE (biometrics available + a recovery code to guard the
    // re-mint). Stored device-key-AEAD'd via the selector-meta machinery (value
    // hidden, like vlt_m/vlt_lvl). Written on every strict-key commit; removed when
    // the blob goes plain. Cleared by every wipe (whole prefs / kvDeleteAll).
    const val AUTHBOUND_SCHEME = "vlt_abk"

    /**
     * `vlt_txn_journal` — `k\nv\n…` of the batch being applied · none of its own (every value
     * it carries is already sealed) · iOS [KeyValueStore.putStringsSync] with 2+ entries
     * only; replayed by `recoverPendingBatch` at the next construction · iOS Keychain KV
     * only (Android has no journal, so `contains` is always false there) · `kvDeleteAll`;
     * dropped FIRST by the failed-provision rollback · legacy-UD: NO.
     *
     * Declared in commonMain because commonMain has to be able to ask "is a multi-key write
     * still pending?" — VaultSelector's orphan-recovery-code purge must not revoke a recovery
     * code while a journal replay could still commit an auth-bound DB-key blob at a LATER
     * launch. Single source of truth so the iOS actual and that reader cannot drift apart.
     */
    const val BATCH_JOURNAL = "vlt_txn_journal"

    /**
     * Pre-rename copies of `vlt_a` / `vlt_c` · same layers as their successors · written by
     * nothing any more (only READ, by the one-time key-name migration) · both · as above ·
     * legacy-UD: yes.
     */
    // Pre-migration discriminating names. Referenced only by the one-time
    // key-name migration (below) and the iOS wipe list (IosUserDefaultsKeys)
    // so a wipe that runs before migration still clears them.
    internal const val LEGACY_CREDENTIAL  = "real_credential_hash"
    internal const val LEGACY_DBKEY  = "real_db_wrapped"

    /** (legacy name → neutral name) pairs the one-time key-name migration copies. */
    internal val LEGACY_KEY_NAME_MIGRATIONS = listOf(
        LEGACY_CREDENTIAL to CREDENTIAL_VERIFIER,
        LEGACY_DBKEY to WRAPPED_DBKEY,
    )

    /**
     * The removed decoy vault's credential / DB-key blobs · — · written by nothing · both ·
     * as above, and by the one-time `purgeDecoyArtifactsIfNeeded` · legacy-UD: yes. Keep the
     * `REMOVED_` prefix: these are live cleanup for old installs, not dead code.
     */
    // Removed decoy-vault storage keys. Retained only so the one-time
    // purgeDecoyArtifactsIfNeeded() can clear them from installs provisioned
    // before the decoy feature was removed (both the neutral and the older
    // discriminating names). Not used by any live code path.
    internal const val REMOVED_DECOY_CREDENTIAL = "vlt_b"
    internal const val REMOVED_DECOY_DBKEY      = "vlt_d"
    internal const val REMOVED_LEGACY_DECOY_CREDENTIAL = "decoy_credential_hash"
    internal const val REMOVED_LEGACY_DECOY_DBKEY      = "decoy_db_wrapped"
}

/**
 * Every AEAD context and KDF domain-separation label of the vault's on-disk format.
 *
 * FROZEN: changing any VALUE here bricks every existing vault (the stored blobs were
 * sealed under these exact bytes). Rename the Kotlin names freely; never the strings.
 */
internal object VaultCryptoContexts {
    /** Device-key AEAD context of [VaultStoreKeys.CREDENTIAL_VERIFIER]. */
    const val CREDENTIAL = "vault-selector:real-credential"

    /**
     * AEAD context of the INNER DB-key layer, `aesGcmEncrypt(payload, kek, DBKEY_INNER)` —
     * and of the default [CryptoProviderDbKeyProtector]'s outer device-key layer.
     */
    const val DBKEY_INNER = "vault-dbkey:real"

    /** Context of BOTH layers of [VaultStoreKeys.RECOVERY_BLOB] (device AEAD and code-KEK AES-GCM). */
    const val RECOVERY = "vault-dbkey:recovery"

    /**
     * Per-key selector-metadata context prefix: a selector-meta value under store key `k` is
     * sealed under `SELECTOR_META_PREFIX + k`, so a blob copied from one slot to another
     * fails AEAD.
     */
    const val SELECTOR_META_PREFIX = "vault-selector-meta:"

    // Domain-separation labels: the stored credential verifier and the
    // DB-key KEK are independent one-way functions of the same stretched
    // KDF output, so leaking the (device-AEAD-wrapped) verifier never
    // yields the KEK — recovering the DB key still requires the PIN.
    const val LABEL_VERIFIER = "vault:cred-verifier"
    const val LABEL_DBKEY_KEK = "vault:dbkey-kek"

    /** KDF label for the recovery-code KEK: `sha256WithLabel(code, LABEL_RECOVERY_KEK)`. */
    const val LABEL_RECOVERY_KEK = "vault:recovery-kek"
}

/** Vault file names on both platforms. Values are the on-disk names. */
internal object VaultFiles {
    /** The single SQLCipher vault file (both platforms). */
    const val DB = "run.db"

    /** The removed decoy vault's file. Still deleted by both wipes for pre-removal installs. */
    const val REMOVED_DECOY_DB = "run_b.db"

    /**
     * Suffixes of the main file plus every SQLite sidecar either platform can leave beside
     * it: Android runs a rollback journal (`-journal`), iOS runs WAL (`-wal` / `-shm`), and
     * both lists include all three so neither platform's delete misses a file the other
     * mode could have produced.
     */
    val SIDECAR_SUFFIXES: List<String> = listOf("", "-wal", "-shm", "-journal")
}

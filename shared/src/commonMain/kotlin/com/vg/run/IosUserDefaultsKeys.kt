package com.vg.run

/**
 * The iOS UserDefaults keys that hold sensitive vault state.
 *
 * Single source of truth for what the iOS wipe paths must delete:
 *   - production [IosAppController.emergencyWipe]
 *   - DEBUG `--test-wipe-on-launch` in iosApp/iosApp/RunApp.swift
 *
 * Both iterate [all]; neither hard-codes the list. The regression
 * this prevents: in May 2026 a rename of "pin_failed_attempts" →
 * "pin_failed_attempts_v2" (in [PinAttemptsStore.STORAGE_KEY])
 * was made without updating the two wipe sites, leaving stale
 * ciphertext on disk. Combined with a rotated Keychain key, the
 * iPad app then crashed ~30 s into launch with an uncaught Kotlin
 * TamperException when PinEntryView.readAttempts() decrypted with
 * the wrong key. Locked in by [IosUserDefaultsKeysTest].
 *
 * Lives in commonMain (rather than iosMain) so commonTest can
 * enforce the invariant; the actual consumers are iOS-only.
 */
object IosUserDefaultsKeys {
    // Reuse the vault store-key table (same module) so these key names cannot
    // drift from where the credential-verifier blob is actually written/read.
    // (Was REAL_CREDENTIAL_HASH — decoy-era "real", and the slot holds a KDF
    // verifier blob, not a hash. Same value, `vlt_a`.)
    val CREDENTIAL_VERIFIER = VaultStoreKeys.CREDENTIAL_VERIFIER

    /** Pre-v2 plaintext counter. Kept in the wipe list for backward-compat. */
    const val PIN_FAILED_ATTEMPTS_LEGACY = "pin_failed_attempts"

    /**
     * The encrypted last-active timestamp Swift's `InactivityWipe` uses for the
     * 7-day dead-man's-switch (`iosApp/iosApp/InactivityWipe.swift`).
     *
     * The LIVE copy moved off this UserDefaults key and into the Keychain KV
     * service (same store as [VaultStoreKeys.WRAPPED_DBKEY]/
     * [VaultStoreKeys.CREDENTIAL_VERIFIER]) — `touch()`/`isExpired()` now read
     * and write it via `KeychainHelper.kvGet`/`kvPut` under this SAME literal
     * account name, not `UserDefaults`. Two reasons, both load-bearing:
     *  1. A UserDefaults marker/timestamp pair is deletable by exactly the
     *     adversary the anchor defends against (a bare plist an examiner can
     *     edit with the app closed), which would make the anchor decorative.
     *  2. `UserDefaults.set()`'s disk flush is asynchronous/coalesced and
     *     `.string(forKey:)` reads the same in-memory cache `.set()` just
     *     updated, so a read-back against it cannot prove the write is durable
     *     — exactly the gap that let Android's *original* patch arm a
     *     durable marker over an `apply()`'d (async) timestamp a crash then
     *     lost. `SecItemAdd`/`SecItemUpdate` commit synchronously with no such
     *     client-side cache, so only a Keychain-backed read-back is trustworthy
     *     enough to gate arming the marker on.
     *
     * This constant — and its entry in [all] — stays as a LEGACY sweep only:
     * installs that wrote the timestamp here before the migration may still
     * have a stale copy in UserDefaults, so every wipe path must still clear
     * it (mirrors the `VaultStoreKeys.LEGACY_*` entries below). New writes never
     * land here again.
     */
    const val INACTIVITY_TS_ENC = "inactivity_ts_enc"

    /**
     * The mtime-dilution probe key (mirrors Swift's
     * `InactivityWipe.probeKey`, iosApp/iosApp/InactivityWipe.swift). Its VALUE is
     * a content-free random nonce, but it is WRITTEN only on a bare launch that
     * reaches isExpired()'s "present + valid timestamp, not expired" path — a path
     * reachable ONLY when the vault was configured AND unlocked at least once and
     * then relaunched. A never-configured device never writes it, so — like
     * [EULA_ACCEPTED] — its post-wipe presence is unambiguous proof of prior setup,
     * a V-2 deniability tell. iOS deletes UserDefaults keys individually (Android's
     * WipeRoutine deletes the whole prefs file and sweeps its probe for free), so
     * this MUST be in [all] or it survives every iOS wipe path. Keep the literal in
     * sync with Swift.
     */
    const val INACTIVITY_MTIME_PROBE = "inactivity_mtime_probe"

    const val CRYPTO_PROVIDER = "run.crypto.provider.key"

    /**
     * The EULA-accepted flag (iOS-only). NOT vault state — a plaintext consent
     * flag written only after the user taps "I Agree & Continue" — but for that
     * reason it is UNAMBIGUOUS proof the app was set up and used. The V-2
     * deniability contract requires a wiped device to be indistinguishable from
     * never-configured, so every iOS wipe path must clear it. It mirrors Swift's
     * `EulaConsent.storageKey` (iosApp/iosApp/UserSafety.swift) — keep the two in
     * sync; a Swift `clearWipeResidue()` also clears it as a belt-and-suspenders.
     */
    const val EULA_ACCEPTED = "eula_accepted_version"

    /**
     * The Tier-2 push opt-in level selector. Mirrors Swift's
     * `NotifLevelPreference.storageKey` (AppState.swift) and Kotlin's own
     * `NotificationLevelStore.KEY` (NotificationLevel.kt, `private` there —
     * duplicated here as a NAMED constant rather than a bare literal so this
     * list can't silently drift; keep both in sync on any rename). NOT vault
     * key material — it's a plaintext preference readable before unlock — but
     * every writer OTHER than a wipe path requires an unlocked vault
     * (`pushEnabled`'s setter, reached only from the Settings toggle or a
     * device-token callback gated on it), so its presence on a supposedly
     * never-configured install is itself proof of prior setup. Previously every
     * iOS wipe path ended by *writing*
     * `"off"` into this key via `pushEnabled = false` in `clearWipeResidue()`
     * — a breadcrumb the wipe planted rather than removed, and one this key
     * was never in [all] to sweep. `clearWipeResidue()` now calls
     * `removeObject(forKey:)` instead.
     */
    const val NOTIF_LEVEL = NotificationLevelStore.KEY

    /**
     * The LEGACY Tier-2 push flag (`PushPreference.storageKey`, AppState.swift).
     * Superseded by [NOTIF_LEVEL], but `pushEnabled`'s getter still forward-folds
     * it: a surviving `true` here makes the getter report vendor-push ON and
     * RE-SEED [NOTIF_LEVEL] — i.e. a wiped install would silently re-acquire a
     * push preference it no longer has a vault for. It was missing from [all],
     * so `IosAppController.emergencyWipe`'s sweep never removed it; only Swift's
     * `clearWipeResidue()` did. That covered it in practice, but left the wipe's
     * completeness resting on one platform's call-ordering discipline rather than
     * on this list. Same breadcrumb class as [NOTIF_LEVEL] and [EULA_ACCEPTED].
     */
    const val PUSH_TIER2_LEGACY = "push_tier2_enabled"

    val all: List<String> = listOf(
        CREDENTIAL_VERIFIER,
        PIN_FAILED_ATTEMPTS_LEGACY,
        PinAttemptsStore.STORAGE_KEY,
        // The rolling-24h wrong-PIN window counter: a new
        // CryptoProvider-encrypted blob that must be crypto-erased by a wipe,
        // else it survives as undecryptable ciphertext after the key is gone.
        PinAttemptsStore.WINDOW_STORAGE_KEY,
        // The "counter established" marker. kvDeleteAll()
        // already clears the Keychain copy on wipe; listed here so any legacy
        // UserDefaults copy is swept too and a re-provisioned vault starts with no
        // stale marker (which would otherwise read an absent counter as tamper).
        PinAttemptsStore.ESTABLISHED_KEY,
        ChangePinAttemptStore.STORAGE_KEY,
        INACTIVITY_TS_ENC,
        // Deniability residue (V-2): the mtime-dilution probe is written
        // only on a bare launch of a previously-configured+unlocked vault, so its
        // post-wipe presence proves prior setup. Was omitted when the probe
        // was introduced — see INACTIVITY_MTIME_PROBE.
        INACTIVITY_MTIME_PROBE,
        CRYPTO_PROVIDER,
        // Deniability residue (V-2): the EULA-accepted flag is unambiguous
        // proof of prior setup, so a wipe must erase it — see EULA_ACCEPTED.
        EULA_ACCEPTED,
        // The Tier-2 push-level selector —
        // see NOTIF_LEVEL. Listed as a belt-and-suspenders sweep; the primary
        // fix is that clearWipeResidue() no longer WRITES "off" into it.
        NOTIF_LEVEL,
        // The legacy flag NOTIF_LEVEL replaced. Must be swept for the same reason
        // NOTIF_LEVEL is — and additionally because pushEnabled's forward-fold
        // getter would re-seed NOTIF_LEVEL from it after a wipe. See PUSH_TIER2_LEGACY.
        PUSH_TIER2_LEGACY,
        // The PIN-wrapped SQLCipher passphrase. Its LIVE copy is in the
        // Keychain KV service (KeyValueStore.ios.kt) and dies with kvDeleteAll;
        // a pre-Keychain install can still hold a LEGACY NSUserDefaults copy,
        // which MUST be wiped — it was previously omitted, so it survived a
        // panic wipe (and, with the PIN, allowed forensic re-derivation of the
        // DB key). Referenced from VaultStoreKeys so it can never drift from
        // where it's actually written.
        VaultStoreKeys.WRAPPED_DBKEY,
        // Threat-level slider: the Lever B recovery blob is an INDEPENDENT wrap of
        // the SQLCipher passphrase under a user-held code — it MUST be crypto-erased
        // by a wipe, or the code holder can still decrypt the (supposedly-erased) DB
        // key. The level selector is a device-key AEAD blob (was
        // a plaintext flag), cleared here for a clean slate. Both referenced
        // from VaultStoreKeys so they can't drift.
        VaultStoreKeys.RECOVERY_BLOB,
        VaultStoreKeys.PROTECTION_LEVEL,
        // The credential-MODE selector ("pin" vs
        // "phrase") is the same class of selector metadata as PROTECTION_LEVEL
        // above and had the same plaintext era, but was never added here — so a
        // legacy install could keep a plaintext UserDefaults copy through a
        // panic wipe (and into device backups), leaking whether the wiped vault was
        // PIN- or passphrase-protected. Android sweeps it already (WipeRoutine
        // deletes the whole prefs file). Enforced by IosUserDefaultsKeysTest.
        VaultStoreKeys.CREDENTIAL_MODE,
        // Legacy discriminating credential/DB-key names (pre key-name
        // migration). A wipe must clear them too, in case it runs before
        // VaultSelector's one-time rename has moved them to the neutral keys.
        VaultStoreKeys.LEGACY_CREDENTIAL,
        VaultStoreKeys.LEGACY_DBKEY,
        // Removed decoy-vault blobs. Still cleared so a wipe on an install
        // provisioned before the decoy feature was removed leaves nothing behind.
        VaultStoreKeys.REMOVED_DECOY_CREDENTIAL,
        VaultStoreKeys.REMOVED_DECOY_DBKEY,
        VaultStoreKeys.REMOVED_LEGACY_DECOY_CREDENTIAL,
        VaultStoreKeys.REMOVED_LEGACY_DECOY_DBKEY,
    )

    private val allSet: Set<String> = all.toSet()

    /**
     * True when [key] is one of the keys that genuinely HAD a pre-Keychain
     * NSUserDefaults era — i.e. the only keys for which `KeyValueStore.getString`/
     * `contains` (KeyValueStore.ios.kt) may answer from NSUserDefaults after a
     * CONFIRMED-absent Keychain read.
     *
     * Why the gate exists: that fallback used to apply to EVERY key, so a
     * Keychain-NATIVE slot — one that has only ever been written to the Keychain,
     * e.g. [VaultStoreKeys.PENDING_DBKEY] (`vlt_cn`),
     * [VaultStoreKeys.RECOVERY_PENDING] (`vlt_rp`),
     * [VaultStoreKeys.AUTHBOUND_SCHEME] (`vlt_abk`) or [VaultStoreKeys.BATCH_JOURNAL]
     * — could be ANSWERED from an ordinary, examiner-writable plist. That turns
     * "value present in the Keychain under
     * kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly" into "value present in a
     * file anyone with the container can create", downgrading the storage class
     * of every such marker to plaintext-domain. This list is exactly the
     * may-have-a-legacy-copy set (it is also the wipe sweep list, for the same
     * reason: a key is swept here iff it could have a UserDefaults copy), and it
     * is locked by [IosUserDefaultsKeysTest].
     *
     * Adding a key here is a security decision, not bookkeeping: it re-opens the
     * plist as an accepted source for that key. Only add one that provably had a
     * UserDefaults era. Note [VaultStoreKeys.RECOVERY_BLOB] (`vlt_rc`) IS in
     * the list and must stay — it had a real UserDefaults era, and dropping its
     * fallback would strand pre-migration installs' recovery codes.
     */
    fun mayHaveLegacyUserDefaultsCopy(key: String): Boolean = key in allSet
}

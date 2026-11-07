package com.vg.run

import com.vg.run.VaultKdf.SALT_LENGTH
import com.vg.run.VaultKdf.DBKEY_LENGTH
import com.vg.run.VaultKdf.CURRENT_KDF_VERSION
import com.vg.run.VaultKdf.stretch
import com.vg.run.VaultKdf.stretchCurrent
import com.vg.run.VaultKdf.needsCredentialRewrap
import com.vg.run.VaultKdf.parseCredentialBlob
import com.vg.run.SelectorMetaPolicy.MODE_PIN
import com.vg.run.SelectorMetaPolicy.MODE_PASSPHRASE
import com.vg.run.SelectorMetaPolicy.AUTHBOUND_SCHEME_STRICT
import com.vg.run.SelectorMetaPolicy.padSelectorMetaPlaintext
import com.vg.run.SelectorMetaPolicy.unpadSelectorMetaPlaintext
import com.vg.run.SelectorMetaPolicy.isSelectorMetaBlobShaped
import com.vg.run.SelectorMetaPolicy.interruptedWipeAttemptThreshold
import com.vg.run.SelectorMetaPolicy.provenProtectionLevel
import com.vg.run.SelectorMetaPolicy.passphraseModeFromRead
import com.vg.run.SelectorMetaPolicy.credentialKindProvenFromRead
import com.vg.run.SelectorMetaPolicy.resolveChangeCredentialMode
import com.vg.run.VaultWriteProofs.plainDbKeyReadBackProves
import com.vg.run.VaultWriteProofs.singleKeyDbKeyWriteAllowed
import com.vg.run.VaultWriteProofs.credentialWriteRefuted
import com.vg.run.VaultWriteProofs.storeWriteProven
import com.vg.run.VaultWriteProofs.PROVISION_ROLLBACK_KEYS
import com.vg.run.VaultWriteProofs.mayDeleteVaultFileAfterRollback
import com.vg.run.RecoveryBlobPolicy.RECOVERY_SECRET_LENGTH
import com.vg.run.RecoveryBlobPolicy.RECOVERY_PENDING_ARMED
import com.vg.run.RecoveryBlobPolicy.AbandonedEnableAction
import com.vg.run.RecoveryBlobPolicy.abandonedEnableAction
import com.vg.run.RecoveryBlobPolicy.RecoveryBlobState
import com.vg.run.RecoveryBlobPolicy.classifyRecoveryBlob
import com.vg.run.RecoveryBlobPolicy.recoveryBlobVetoesRotation
import com.vg.run.RecoveryBlobPolicy.recoveryPathOffered
import com.vg.run.RecoveryBlobPolicy.recoveryBlobUsableAsNet
import com.vg.run.DbKeyRotationPolicy.mayRotateDbKey
import com.vg.run.DbKeyRotationPolicy.RotationOutcome
import com.vg.run.DbKeyRotationPolicy.rotationOutcomeFromProbes
import com.vg.run.DbKeyRotationPolicy.rekeyOutcomeKeepsLiveHandle
import com.vg.run.DbKeyPayloadCodec.encodeDbKeyPayload
import com.vg.run.DbKeyPayloadCodec.openModeOrder
import com.vg.run.RawKeyAdoptionPolicy.rawKeyAdoptionAllowed
import com.vg.run.RawKeyAdoptionPolicy.rawKeyAdoptionMayCommit
import kotlin.time.TimeMark
import kotlin.time.TimeSource

// ---------------------------------------------------------------------------
// VaultSelector — credential gate for the (single) vault.
//
// This class lives in commonMain and uses platform-agnostic abstractions:
//   • KeyValueStore for credential persistence (SharedPreferences on Android,
//     the Keychain KV service on iOS)
//   • CryptoProvider for the device-key AEAD over the credential verifier and
//     selector metadata (Tink on Android, a Keychain-held key on iOS)
//   • DbKeyProtector for the OUTER layer of the wrapped DB key (plain device key,
//     or the hardware auth-bound key under Lever B)
//   • VaultFactory for creating the vault without referencing Android-only classes
//   • Platform.kt functions for Base64, SecureRandom, logging
//   • PlatformCrypto for SHA-256, AES-GCM, PBKDF2/Argon2id and constant-time compare
//
// The pure policy, codecs and constants live next to this file:
//   VaultStoreKeys.kt      every store key + AEAD context + file name (the table)
//   VaultKdf.kt            KDF versions, Argon2 cost + release floors, credential-blob layout
//   SelectorMetaPolicy.kt  selector-meta tokens, padding, read-policy decisions
//   VaultWriteProofs.kt    "did the write land?" predicates, provision-rollback lists
//   RecoveryBlobPolicy.kt  what `vlt_rc` proves; the abandoned-enable (`vlt_rp`) decision
//   DbKeyRotationPolicy.kt the `vlt_cn` rotation decisions
//   DbKeyPayload.kt        the inner DB-key payload codec + raw-key adoption decisions
//   VaultCryptoPrimitives.kt  selectorWriteGuard, sha256WithLabel
//   VaultBlobCodecs.kt     the seal/open of the `vlt_a` / `vlt_c` / `vlt_rc` formats
// This file keeps the runtime: every store read/write, every unwrap, the unlock
// ladder, provision, change-credential, Lever B, recovery, rotation and adoption.
//
// Platform asymmetries a reader of this class keeps rediscovering (each "on iOS"
// comment below is one of these):
//   1. Store READS can fail transiently only on iOS — KeyValueStore.ios.kt throws
//      KeyUnavailableException on any non-confirmed-absent Keychain read; Android
//      SharedPreferences reads never fail. So every "fails toward …" catch on a
//      store read here is, in practice, iOS behaviour.
//   2. Multi-key atomicity: Android = one editor commit(); iOS = a write-ahead
//      journal (VaultStoreKeys.BATCH_JOURNAL) replayed at the next construction.
//      batchJournalPending() is therefore always false on Android.
//   3. A ONE-entry putStringsSync on iOS is a bare kvPut: no journal, and it does
//      NOT displace a stale journal — the reason singleKeyDbKeyWriteAllowed exists.
//   4. Write-drop signal: iOS kvPut no-ops silently on a locked keybag, and a
//      read-back really catches it; Android putString discards commit()'s Boolean
//      and getString reads the in-memory map, so a read-back there proves only
//      "the editor accepted it" (see VaultWriteProofs.storeWriteProven).
//   5. Only iOS has the legacy NSUserDefaults read fallback, gated by
//      IosUserDefaultsKeys.mayHaveLegacyUserDefaultsCopy.
//
// Historical note: this used to route between a real and a "decoy" vault for
// plausible deniability. The decoy feature was removed; only the real vault
// remains. A one-time purge (see init) clears any leftover decoy state from
// installs that were provisioned before the removal.
// ---------------------------------------------------------------------------

class VaultSelector internal constructor(
    // The store and the device-key cipher are interface-typed so a JVM test can build
    // the REAL class (VaultSelectorGoldenTest); production always arrives through the
    // public secondary constructor below, which adapts the platform KeyValueStore /
    // CryptoProvider by pure delegation (same members, same exceptions).
    private val store: SelectorStore,
    private val crypto: DeviceKeyCipher,
    private val vaultFactory: VaultFactory,
    // Outer device-key layer for the wrapped DB key (CR-1). The production
    // constructor defaults it to the pre-Lever-B behavior (plain CryptoProvider
    // device key, no fresh-auth); Android injects an auth-bound protector so the
    // DB-key unwrap can require a fresh biometric while the screen is locked
    // (Lever B), WITHOUT prompting for the pre-PIN counter/verifier reads (those
    // keep using [crypto] directly). iOS also injects an auth-bound protector now
    // (Secure Enclave ECIES — Lever B shipped on both platforms; opt-in per install).
    private val dbKeyProtector: DbKeyProtector,
    // The LIVE vault handle, for the SQLCipher key rotation a
    // credential TIER UPGRADE performs. VaultSelector deliberately does not own the
    // open vault — RunViewModel.vault / IosAppController.vault do, and the
    // change-credential call sites are leaf UI — so the handle is injected as a
    // provider read at the moment it is needed rather than captured. Defaulted to "no
    // handle" so the many construction sites that never rotate (InactivityWipe,
    // MainActivity's orphan probe, tests) keep compiling AND keep the pre-rotation
    // behaviour exactly: no handle ⇒ the rotation is skipped silently and the
    // credential change is byte-for-byte what it was.
    private val vaultProvider: () -> VaultDatabase? = { null },
    // Invoked AFTER [rotateDbKeyAfterUpgrade] has
    // CLOSED the live vault handle because a re-key did not verifiably COMMIT (see
    // [retireRekeyedVaultHandle] — the rolled-back sqlite3_rekey_v2 leaves the
    // handle's codec WRITE context on the new key over an old-key file, so it must
    // never serve another write). The owner of the handle (RunViewModel /
    // IosAppController) must treat this as "the session is over": drop every
    // reference that routes through the handle and fall back to the LOCKED state,
    // where the next unlock's [reconcilePendingRotation] recovers on positive
    // evidence. Fires on the caller's (background) thread. Defaulted to no-op for
    // the construction sites that never rotate (no vaultProvider ⇒ no rotation ⇒
    // never fired).
    private val onRekeyHandleRetired: () -> Unit = {},
) {

    /**
     * The production constructor — every app / platform / instrumented-test call site,
     * with the exact signature, parameter names and defaults this class always had.
     */
    constructor(
        store: KeyValueStore,
        crypto: CryptoProvider,
        vaultFactory: VaultFactory,
        dbKeyProtector: DbKeyProtector =
            CryptoProviderDbKeyProtector(crypto, VaultCryptoContexts.DBKEY_INNER.encodeToByteArray()),
        vaultProvider: () -> VaultDatabase? = { null },
        onRekeyHandleRetired: () -> Unit = {},
    ) : this(
        store.asSelectorStore(),
        crypto.asDeviceKeyCipher(),
        vaultFactory,
        dbKeyProtector,
        vaultProvider,
        onRekeyHandleRetired,
    )

    // The at-rest formats of `vlt_a`, `vlt_c` / `vlt_cn` and `vlt_rc` in one place
    // (VaultBlobCodecs.kt): every seal / open below goes through it.
    private val codecs = VaultBlobCodecs(crypto, dbKeyProtector)

    /**
     * A present selector-meta blob failed AEAD verification with a WORKING
     * device key — damaged/tampered storage, not the transient outage
     * [KeyUnavailableException] signals (retrying won't help; unlock itself
     * still evaluates normally). Never escapes this class: every reader maps
     * it to its fail-safe default, so it can't cross the Swift bridge.
     */
    private class SelectorMetaDamagedException(key: String) :
        RuntimeException("selector meta '$key' present but undecryptable (damaged blob)")

    // Commit-before-display close: the strict auth-bound blob PREPARED by
    // [enableDbKeyAuthBindingWithRecovery] is held here — NOT committed to
    // VaultStoreKeys.WRAPPED_DBKEY — until the user has seen + acknowledged their recovery code and
    // the UI calls [finalizeDbKeyAuthBinding]. In-RAM only: if the process dies with a
    // code on screen, the vault is still PLAIN (PIN opens it) and the orphan recovery
    // blob + orphan strict key are harmless (rotated / overwritten on the next enable),
    // so a lost code can never brick a strict-invalidate vault.
    private var pendingAuthBoundBlob: String? = null

    // The exact PLAIN `vlt_c` string the prepared [pendingAuthBoundBlob] was wrapped
    // from. Set and cleared together with it. [finalizeDbKeyAuthBinding] refuses to
    // commit when `vlt_c` no longer equals it: on iOS this VaultSelector outlives
    // lock(), so an unlock between enable and finalize can run the KDF migration (new
    // salt ⇒ new KEK ⇒ new inner layer), and committing the held ab: blob — wrapping
    // the OLD inner — over it would leave a vault every unlock answers Error until
    // the recovery code is used.
    private var pendingAuthBoundBase: String? = null

    /**
     * True when the most recent level-aware [setRealCredential] call returned
     * `false` because [selectorWriteGuard] caught a transient device-key outage
     * (`KeyUnavailableException`) mid-provision — e.g. Android's Keystore super
     * decryption key evicted from memory ("Required super decryption key is not
     * in memory"), or a locked iOS keybag — rather than the entropy floor, the
     * provision guard ([ExistingVaultException]), or an unproven write
     * ([ProvisionNotPersistedException]). `selectorWriteGuard`'s write lambda
     * here is exactly [provisionCredentialAndVault], which never returns a
     * sentinel of its own, so a `false` out of it is ALWAYS the caught
     * `KeyUnavailableException` — this field just remembers that fact past the
     * point the guard collapses it to a Boolean.
     *
     * RAM-only, reset at the START of every [setRealCredential] attempt so a
     * stale `true` from a PRIOR call can never explain a DIFFERENT failure on
     * retry. Read-after-write only: both setup UIs check this immediately after
     * a `false` return, on the same call stack, so no synchronization beyond
     * that ordering is needed (provisioning is already single-flight per
     * vault). Exists purely so the two first-run setup screens can tell
     * "the device key is momentarily unavailable — lock/unlock and retry"
     * apart from a generic retryable failure, without widening the non-@Throws
     * Boolean bridge contract or reclassifying the exception: it stays a pure
     * DEFER here, never a tamper signal and never a wipe trigger (see
     * [selectorWriteGuard], [KeyUnavailableException]).
     */
    private var lastProvisionDeviceKeyUnavailable = false

    /**
     * True when [setRealCredential]'s level-aware overload most recently
     * returned `false` specifically because the device key was transiently
     * unavailable mid-provision, rather than a real provisioning failure. See
     * [lastProvisionDeviceKeyUnavailable]. Call immediately after a `false`
     * return; the next provision attempt overwrites it.
     */
    fun lastProvisionWasDeviceKeyUnavailable(): Boolean = lastProvisionDeviceKeyUnavailable

    init {
        // Run the one-time storage-key-name migration before any operation so
        // every entry point (isConfigured/unlock/verify/change) sees the
        // neutral key names regardless of which is called first. A transient
        // store read failure (iOS Keychain) defers the migration —
        // it is idempotent and retried on the next construction; construction
        // itself must never throw (IosAppController builds this in a field
        // initializer during AppState.init).
        try {
            migrateLegacyKeyNamesIfNeeded()
        } catch (_: KeyUnavailableException) {
            platformLogWarn("VaultSelector", "key-name migration deferred — store unavailable")
        } catch (_: Exception) {
            // The migration now issues a journalled batch write, which has more
            // failure modes than the old plain put. Construction still must never
            // throw (IosAppController builds this in a field initializer during
            // AppState.init) and the migration is idempotent — defer and retry.
            platformLogWarn("VaultSelector", "key-name migration deferred — write failed")
        }
        // Clear any decoy state left over from installs provisioned before the
        // decoy feature was removed. (The stale run_b.db is deleted by the WIPE
        // paths — WipeRoutine / IosAppController — NOT this purge, which only clears
        // leftover decoy credential/DB-key blobs, and never fires on a healthy install.)
        purgeDecoyArtifactsIfNeeded()
    }

    /**
     * One-time migration of the credential / DB-key storage keys from the old
     * discriminating names ("real_*", which leaked vault layout as cleartext
     * key names) to the neutral names. Each old entry's VALUE
     * is copied verbatim to its neutral key and the old key removed, so the
     * existing vault file (and all its contacts / inbox rows) keeps opening
     * unchanged — no data or contact loss. Idempotent.
     */
    private fun migrateLegacyKeyNamesIfNeeded() {
        // The credential verifier and the wrapped DB
        // key are a COUPLED pair — the same rule that forces change-PIN through
        // putStringsSync applies here, so both copies land in one journalled write
        // rather than two independent puts. And an old name is retired only after
        // its new copy READS BACK: on iOS kvPut fails SILENTLY on a locked keybag,
        // so the old copy-then-remove could reject the put, succeed at the remove
        // and destroy the ONLY copy of the credential / DB key — purgeHalfCredentialPairIfNeeded
        // then clears the remnant and the vault re-provisions clean (total loss).
        // Anything unverified is left alone; the migration is idempotent and
        // retried on the next construction.
        val copies = mutableMapOf<String, String>()   // newName -> value to persist
        val retire = mutableListOf<String>()          // oldName safe to remove now
        for ((oldName, newName) in VaultStoreKeys.LEGACY_KEY_NAME_MIGRATIONS) {
            if (!store.contains(oldName)) continue
            if (store.getString(newName) != null) { retire += oldName; continue }
            // A null read on a key that `contains` reports present is a transient
            // store failure — leave both copies and retry next construction.
            val value = store.getString(oldName) ?: continue
            copies[newName] = value
        }
        if (copies.isNotEmpty()) {
            store.putStringsSync(copies)
            for ((oldName, newName) in VaultStoreKeys.LEGACY_KEY_NAME_MIGRATIONS) {
                val value = copies[newName] ?: continue
                // fail-direction: proof-required (the legacy copy is retired only after a proven copy).
                if (store.getString(newName) == value) retire += oldName
                else platformLogWarn(
                    "VaultSelector", "key-name migration unverified — keeping the legacy copy"
                )
            }
        }
        retire.forEach { store.remove(it) }
    }

    /**
     * One-time removal of decoy-vault credential/DB-key blobs left behind by
     * installs provisioned before the decoy feature was removed. Removing these
     * stored blobs (plus the platform-side run_b.db file deletion) fully erases
     * the old decoy state; the real vault is untouched. Idempotent.
     */
    private fun purgeDecoyArtifactsIfNeeded() {
        store.remove(VaultStoreKeys.REMOVED_DECOY_CREDENTIAL)
        store.remove(VaultStoreKeys.REMOVED_DECOY_DBKEY)
        store.remove(VaultStoreKeys.REMOVED_LEGACY_DECOY_CREDENTIAL)
        store.remove(VaultStoreKeys.REMOVED_LEGACY_DECOY_DBKEY)
    }

    // -----------------------------------------------------------------------
    // Credential setup
    // -----------------------------------------------------------------------

    fun isConfigured(): Boolean {
        purgeHalfCredentialPairIfNeeded()
        return try {
            store.contains(VaultStoreKeys.CREDENTIAL_VERIFIER) &&
                store.contains(VaultStoreKeys.WRAPPED_DBKEY)
        } catch (_: KeyUnavailableException) {
            // Ambiguous read (transient iOS Keychain failure) — NEVER report
            // "not configured": that routes a provisioned install to first-run
            // setup, whose provision overwrites the credential blobs and
            // delete-retries the differently-keyed DB file — destroying the real
            // vault. Reporting configured is the safe
            // direction on a genuinely-fresh install too: the PIN screen's
            // unlock defers with the neutral non-counting Error until the store
            // recovers, and setup appears once reads succeed again.
            platformLogWarn("VaultSelector", "isConfigured deferred — store unavailable, assuming configured")
            true
        }
    }

    /**
     * CR-1 migration (clean re-provision, data loss accepted): an install
     * created before PIN-wrapped DB keys has a credential hash but no
     * wrapped-DB-key blob. Such a vault's DB file is keyed the old way and is
     * intentionally NOT migrated — we clear the credential state so the app
     * returns to first-run setup — but NOT to a provision over it: the provision
     * guard ([provisionCredentialAndVault] throws [ExistingVaultException] whenever
     * the vault file exists) refuses, and the routing OR-gate
     * (`isConfigured() || vaultFileExists()`) sends the user to unlock, where
     * [orphanedVaultFile] offers the explicit, confirmed "Erase and start over".
     * The stale old-key file is therefore deleted only by that confirmed erase,
     * never silently by a provision.
     *
     * Also the cleanup for a TORN provision (a `vlt_a` that landed without its
     * `vlt_c` — see [VaultWriteProofs.storeWriteProven]), which reads identically.
     *
     * Idempotent; safe to call on every isConfigured() check.
     */
    private fun purgeHalfCredentialPairIfNeeded() {
        val hasCreds: Boolean
        val hasDbKeys: Boolean
        try {
            hasCreds  = store.contains(VaultStoreKeys.CREDENTIAL_VERIFIER)
            hasDbKeys = store.contains(VaultStoreKeys.WRAPPED_DBKEY)
        } catch (_: KeyUnavailableException) {
            // Purge is destructive and irreversible — it may only run on a
            // CONFIRMED-absent DB-key read. A transient failure here (including
            // the keybag locking between the two contains calls) previously read
            // as hasDbKeys=false and removed live credentials.
            // Defer; this is re-checked on every isConfigured().
            return
        }
        if (hasCreds && !hasDbKeys) {
            platformLogWarn("VaultSelector", "legacy vault detected — clearing for clean re-provision")
            store.remove(VaultStoreKeys.CREDENTIAL_VERIFIER)
            store.remove(VaultStoreKeys.WRAPPED_DBKEY)
            store.remove(VaultStoreKeys.CREDENTIAL_MODE)
            // The pending-rotation record is a wrap of a DB key for a vault this
            // purge has just declared un-openable, so it must go with the rest. Left
            // behind, it would be adopted by the NEXT provision's unlock reconcile —
            // which would then try to open a freshly provisioned vault with a stale
            // key. (Safe here for the same reason the three removes above are: this
            // branch runs only on a CONFIRMED-absent DB-key read.)
            store.remove(VaultStoreKeys.PENDING_DBKEY)
        }
    }

    /**
     * Returns true if the stored credential verifier blob can be decrypted with the
     * current device key. False means the stored blob is orphaned
     * (e.g. Keychain reset) and the app should clear it.
     */
    fun credentialsReadable(): Boolean {
        if (!isConfigured()) return true  // Nothing stored, nothing to break
        return credentialBlobDecrypts()
    }

    private fun credentialBlobDecrypts(): Boolean {
        return try {
            // The store read sits INSIDE the try: on iOS getString itself throws
            // KeyUnavailableException on a transient Keychain failure,
            // and returning false here drives the orphan-credential wipe.
            val storedB64 = store.getString(VaultStoreKeys.CREDENTIAL_VERIFIER) ?: return false
            val credentialPlain = codecs.openCredentialVerifier(storedB64)
            credentialPlain.size >= SALT_LENGTH
        } catch (e: KeyUnavailableException) {
            // Device locked / protected data unavailable — the key may still
            // exist, so we CANNOT conclude the stored hash is orphaned. Report
            // "readable" to DEFER the orphan check rather than let a transient
            // locked read drive credentialsReadable()=false and wipe the vault.
            // A genuine orphan is still caught later at unlock. (Mirrors
            // PinAttemptsStore.read()'s locked-key handling.)
            true
        } catch (_: Exception) {
            false
        }
    }


    /**
     * Legacy (level-less) provision. THROWS — [ExistingVaultException] when the
     * provision guard refuses, [ProvisionNotPersistedException] when the credential
     * pair could not be proven to have persisted (already rolled back), plus
     * whatever the store/SQLCipher raise. Its only production caller is
     * `IosAppController.setRealCredential`, which is a non-@Throws bridge method and
     * catches every exception; new callers must do the same, or use the
     * level-aware Boolean overload below, which converts both to a retryable
     * `false`.
     */
    fun setRealCredential(credential: String) {
        provisionCredentialAndVault(credential, passphraseMode = false, level = null)
    }

    /**
     * Level-aware provision (threat-level slider). Writes the credential mode
     * (PIN vs passphrase — Lever A) and the chosen [level] in the SAME provision,
     * so the entry UI and the per-level auto-lock / self-wipe thresholds are
     * correct from the very first unlock. Lever B (PRIVATE) is applied
     * AFTER unlock via [enableDbKeyAuthBindingWithRecovery] — there is no
     * provision-time hardware path and it needs a biometric prompt + a recovery
     * code to display.
     *
     * Enforces the ≥70-bit passphrase floor at this shared boundary so a passphrase level can't be provisioned weak even by a
     * non-UI caller. Returns false (nothing provisioned) if a passphrase level is
     * below the floor — or if the device key was transiently unavailable mid-
     * provision ([selectorWriteGuard]: both UIs already treat false as a retryable
     * provision failure, and the exception must not reach the non-@Throws Swift
     * bridge or the Compose setup coroutine) — or if the provision guard refused
     * ([ExistingVaultException]) — or if the credential pair could not be proven to
     * have persisted ([ProvisionNotPersistedException]), in which case
     * [rollBackFailedProvision] has already restored a clean slate for the retry.
     */
    fun setRealCredential(credential: String, passphraseMode: Boolean, level: ProtectionLevel): Boolean {
        // Reset at the top of every attempt — see lastProvisionDeviceKeyUnavailable's
        // kdoc for why a stale `true` from a PRIOR call must never explain THIS one.
        lastProvisionDeviceKeyUnavailable = false
        if (passphraseMode && !CredentialPolicy.meetsFloor(credential)) {
            platformLogWarn("VaultSelector", "provision denied — passphrase below the entropy floor")
            return false
        }
        return try {
            val persisted = selectorWriteGuard("provision") {
                provisionCredentialAndVault(credential, passphraseMode, level)
            }
            // selectorWriteGuard's ONLY false path is a caught KeyUnavailableException
            // (its write() here is provisionCredentialAndVault, which never returns a
            // sentinel of its own) — so a false here always means the device key, never
            // a different provisioning defect. This only records that for the caller;
            // the exception's classification/handling above is unchanged.
            if (!persisted) lastProvisionDeviceKeyUnavailable = true
            persisted
        } catch (_: ExistingVaultException) {
            // The provision guard fired. Report the same retryable `false` the
            // entropy-floor and device-key-outage paths use — it must NOT throw
            // across the non-@Throws Swift bridge (SIGABRT). Nothing was written
            // and, crucially, the existing vault is intact; callers route the
            // user to unlock via [vaultFileExists].
            false
        } catch (_: ProvisionNotPersistedException) {
            // The coupled vlt_a/vlt_c batch could not be PROVEN to have
            // landed, and [rollBackFailedProvision] has already undone everything
            // this call created (both blobs, the iOS write-ahead journal, and the
            // run.db it materialised moments ago). Same retryable `false` — both
            // UIs already treat it as "provisioning failed, try again", and the
            // next attempt now meets a genuinely clean slate rather than tripping
            // the provision guard on our own leftovers.
            false
        }
    }

    /**
     * True when a vault database file exists on disk, regardless of what the
     * credential store says.
     *
     * Callers use this to decide ROUTING — never show first-run setup when a
     * vault is present — so the provision guard is a backstop rather than the
     * only line of defence. Deliberately independent of [isConfigured]: that
     * reads the KeyValueStore, whose transient failure is what misroutes a
     * provisioned install into setup to begin with.
     */
    fun vaultFileExists(): Boolean = vaultFactory.vaultFileExists()

    /**
     * True when a vault FILE exists but no credential is stored for it — a vault
     * nothing can open.
     *
     * This is the dead end the provision guard deliberately creates rather than
     * resolving destructively: before the guard, this state silently became
     * "provision over it and lose everything"; now the user lands on an unlock
     * screen no credential satisfies. So the UI must offer an explicit, clearly
     * labelled erase — and ONLY here, because offering "erase everything" to a
     * healthy vault is the very data loss we just closed.
     *
     * Fail direction is what makes that safe: [isConfigured] returns `true` on a
     * transient store failure, so this returns `false` and the erase offer stays
     * hidden whenever the store is merely unreadable. It surfaces only on a
     * CONFIRMED-absent credential. Callers must additionally require the device
     * to be unlocked before showing it — the same gate [InactivityWipe] and the
     * orphan self-heal use, so a locked-storage read can never drive it.
     */
    fun orphanedVaultFile(): Boolean = vaultFileExists() && !isConfigured()

    /**
     * True when the vault credential is a high-risk-mode passphrase rather
     * than the default 6-digit PIN. Drives which entry UI the lock screens
     * render; the underlying crypto never branches on it.
     */
    fun isPassphraseMode(): Boolean = try {
        // The RAW read, so the provenance flag survives. The
        // lenient [readSelectorMeta] discards it, which handed a 3-byte cleartext
        // plant (`pin`) the power to render the digit keypad on a passphrase vault —
        // guaranteed-wrong entries, durably counted, wipe at MAXIMUM's 5. See
        // [passphraseModeFromRead] for the full rationale and why failing OPEN is
        // safe for a genuine legacy cleartext install.
        val read = readSelectorMetaRaw(VaultStoreKeys.CREDENTIAL_MODE)
        passphraseModeFromRead(read?.value, read?.authenticated == true)
    } catch (_: KeyUnavailableException) {
        // UI selector only — on a transient store failure default to the PIN
        // keypad. A keybag-wide outage makes unlock defer with the neutral
        // Error anyway (evalCredential's read fails the same way), so a
        // passphrase-mode user can't burn the wipe budget through the
        // transiently-wrong entry UI. Called from Swift (non-@Throws) — must
        // not let the Kotlin exception cross the bridge (SIGABRT).
        false
    } catch (_: SelectorMetaDamagedException) {
        // Damaged mode blob — unlike the outage above, the device key WORKS and
        // unlock evaluates normally. Fail OPEN to the free-text passphrase UI:
        // the unlock path is input-widget-agnostic (the credential is just a
        // string to evalCredential; PinEntryScreen/PinEntryView submit either
        // widget's text identically), so a PIN user can still type 6 digits in
        // the text field — whereas the digit keypad hard-locks a passphrase
        // user out and lets their forced wrong entries burn the wipe budget.
        // The next mode/level write re-wraps a fresh blob.
        true
    }

    /**
     * TRI-STATE PROOF of the credential's kind —
     * `true` = provably a passphrase, `false` = provably a PIN, `null` = unproven.
     * See [credentialKindProvenFromRead] for the full rule.
     *
     * This is the reader every TIER-UPGRADE decision must use
     * ([ProtectionUpgradePlan.needsCredentialChange]); [isPassphraseMode] is NOT
     * one of them and keeps its documented fail-OPEN semantics, because it picks
     * the ENTRY WIDGET (and `changeCredentialInner` keeps resolving an
     * unauthenticated mode from the NEW credential's SHAPE, never from this). The
     * two readers share one slot and need OPPOSITE fail directions — exactly the
     * same shape as [protectionLevelForEnforcement] vs [protectionLevelForFloorCheck]
     * over `vlt_lvl`. Do not collapse them.
     *
     * Never throws: reached from Compose click handlers and from the non-@Throws
     * Swift bridge (`IosAppController.credentialKindProven`, `KotlinBoolean?`).
     * Both catch branches answer `null` — an unproven claim, which routes the user
     * through the credential change rather than skipping it.
     */
    fun credentialKindProven(): Boolean? = try {
        val read = readSelectorMetaRaw(VaultStoreKeys.CREDENTIAL_MODE)
        credentialKindProvenFromRead(read?.value, read?.authenticated == true)
    } catch (_: KeyUnavailableException) {
        // Transient device-key outage — proves nothing about the credential.
        null
    } catch (_: SelectorMetaDamagedException) {
        // Positive tamper evidence on this one value. The device key WORKS, so
        // this is the plant the tier-upgrade rule turns on: it must never read as "a passphrase
        // is already set".
        null
    }

    // -----------------------------------------------------------------------
    // Protection level (threat-level slider)
    // -----------------------------------------------------------------------


    /**
     * The persisted protection tier, or null for a legacy install provisioned
     * before the slider. A lenient read for display/routing only: destructive
     * enforcement (auto-lock, self-wipe thresholds) reads
     * [protectionLevelForEnforcement], which falls back to the current constants on
     * null, so a legacy vault keeps its exact behavior — a level's (possibly
     * gentler) numbers are only ever applied to an install that explicitly chose one.
     */
    fun protectionLevelOrNull(): ProtectionLevel? = try {
        ProtectionLevel.fromStorageOrNull(readSelectorMeta(VaultStoreKeys.PROTECTION_LEVEL))
    } catch (_: KeyUnavailableException) {
        // Selector read only — a transient store outage falls back to the current
        // constants (never crosses the non-@Throws Swift bridge).
        null
    } catch (_: SelectorMetaDamagedException) {
        // Damaged level blob: null here is DISPLAY/routing-safe only — it sends
        // the user to the one-time level chooser, whose setProtectionLevel write
        // self-heals the blob. DESTRUCTIVE enforcement (inactivity wipe, wrong-
        // credential budget) must NOT consume this null (it maps to the SHORTER
        // defaults); those sites read [protectionLevelForEnforcement].
        null
    }

    /**
     * The tier this vault can PROVE it is at — the read for the Lever A CREDENTIAL
     * FLOOR decision ([DeviceLockPolicy.needsForcedMigration]: "a phone with no
     * lock screen MUST run at MAXIMUM"). Never throws.
     *
     * This gate used to read [protectionLevelOrNull],
     * whose legacy-cleartext tolerance discards the provenance flag — so the
     * seven ASCII bytes `maximum`, written into `vault_selector_prefs.xml` (or the
     * iOS NSUserDefaults slot) by anyone who can write the app's private storage,
     * satisfied the floor permanently and the user was never routed to the tier
     * change that would have given them a ≥70-bit passphrase. On a lock-less phone
     * that is the whole of CR-1's second factor gone plus a ~20-bit credential.
     *
     * [protectionLevelForEnforcement] CANNOT be substituted here: its fail-secure
     * answer for an unauthenticated read is `Present(MAXIMUM)`, which is fail-OPEN
     * for this decision. The two readers share one slot and need OPPOSITE fail
     * directions — see [provenProtectionLevel] for the full rule and for why
     * "never chosen" and "authenticated but unparseable" are `null` (the gated
     * one-time chooser owns them) rather than "below the floor".
     *
     * The two non-Present reads map to `null` deliberately, i.e. to exactly the
     * routing they already had before the strict-scheme marker existed:
     *  - [SelectorMetaDamagedException] — positive tamper on the blob, but the
     *    chooser it routes to is gated by [DeviceLockPolicy.isSelectable] (nothing
     *    under MAXIMUM is selectable without a lock screen) and its write self-heals
     *    the damaged blob, so the floor is enforced there without this reader having
     *    to claim knowledge it does not have.
     *  - [KeyUnavailableException] — a transient device-key outage proves nothing at
     *    all, and forcing an irreversible credential migration on probe noise is the
     *    exact failure direction [DeviceLockPolicy] was written to avoid.
     *
     * BRICK-SAFETY: no wipe path reads this. Its consumers route to the forced
     * tier-change screen (a credential-change flow) or to the one-time chooser;
     * both are recoverable, neither destroys data, and the way out of the forced
     * screen — setting a device lock screen — retires the forcing on the next
     * unlock.
     */
    fun protectionLevelForFloorCheck(): ProtectionLevel? = try {
        val read = readSelectorMetaRaw(VaultStoreKeys.PROTECTION_LEVEL)
        provenProtectionLevel(
            storedLevel = read?.let { ProtectionLevel.fromStorageOrNull(it.value) },
            present = read != null,
            authenticated = read?.authenticated == true,
        )
    } catch (_: KeyUnavailableException) {
        null
    } catch (_: SelectorMetaDamagedException) {
        null
    }

    /**
     * Four-state level read for DESTRUCTIVE enforcement sites (the inactivity
     * self-wipe on both platforms, the wrong-credential budget). Unlike
     * [protectionLevelOrNull] it distinguishes "no level ever chosen" (legacy →
     * current constants) from "stored but the device key is out right now"
     * (defer) and from "stored but provably corrupt" (fail secure), so the shared
     * decisions ([InactivityPolicy.thresholdMsOrNull],
     * [CredentialPolicy.maxConsecutiveAttempts]) can refuse both to apply a
     * shorter-than-chosen window AND to be disarmed by a tampered blob.
     * Never throws.
     *
     * This read requires AUTHENTICATION. `vlt_lvl` is
     * device-key AEAD, but [readSelectorMetaRaw] still tolerates a LEGACY
     * cleartext value for pre-encryption installs — and that fallback accepts ANY short
     * string, so writing the six ASCII bytes `casual` into the selector store
     * (or, on iOS, into the NSUserDefaults slot KeyValueStore falls back to)
     * used to be parsed straight into Present(CASUAL). That single unsigned
     * write stretched the MAXIMUM dead-man's-switch from 7 days to 180, doubled
     * the wrong-credential budget 5 → 10 — the ONLY rate limit on unlock() —
     * and relaxed auto-lock from 60 s to 15 min. So an unauthenticated value now
     * takes the same fail-secure path as an unrecognized token below.
     */
    fun protectionLevelForEnforcement(): ProtectionLevelRead = try {
        val read = readSelectorMetaRaw(VaultStoreKeys.PROTECTION_LEVEL)
        when {
            // Genuinely never chosen (legacy pre-slider install) → current constants.
            read == null -> ProtectionLevelRead.Absent
            // Legacy cleartext (or an attacker's forgery — indistinguishable,
            // by construction, since neither carries a tag). The value is still
            // READ and still drives DISPLAY + migrate-on-write, so a genuine
            // pre-encryption vault keeps working and self-heals on its next tier write;
            // it just can no longer LOOSEN a destructive window.
            //
            // Be precise about the cost, because this comment is load-bearing:
            // the fail-secure result is STRICTER than a legitimately-cleartext
            // CASUAL install chose — 7-day dead-man's switch instead of 180,
            // 5 attempts instead of 10, 60 s auto-lock instead of 15 min. "It
            // matches what a pre-slider vault has always enforced" is true of a
            // genuine Absent read (the branch above), NOT of this one. What makes
            // it affordable is the POPULATION: a cleartext `vlt_lvl` could only
            // ever be WRITTEN in the ~66 h between the tier slider landing
            // (2026-07-10 21:12) and every selector-meta write becoming
            // AEAD (2026-07-13 15:17) — a window that opened and closed
            // before the slider reached a user (all pre-release).
            // So the install shape this would cost — a legitimately-cleartext CASUAL
            // vault idle between 7 and 180 days, wiped by the tighter switch —
            // essentially does not exist, while everything else reaching this branch
            // in the field is a forgery.
            //
            // The narrower fix — exempt ONLY the inactivity window from the
            // fail-secure, keeping the value untrusted for attempts/auto-lock —
            // was considered and REJECTED: stretching the dead-man's switch from
            // 7 days to 180 by planting the six bytes `casual` IS the primary
            // exploit, so that is the one decision the exemption must never cover.
            !read.authenticated -> ProtectionLevelRead.Present(ProtectionLevel.MAXIMUM)
            else -> when (val level = ProtectionLevel.fromStorageOrNull(read.value)) {
                // The blob decrypts fine but the token is
                // unrecognized — almost always a tier written by a NEWER binary that
                // this (older / downgraded / sideloaded) one can't parse. This is NOT
                // "never chosen" (so it must not take the Absent → current-constants
                // path) and NOT a transient/damaged read (so not Unreadable/lenient).
                // Under the forensic threat model an ambiguous-but-present level must
                // FAIL SECURE: enforce the STRICTEST tier (60s auto-lock, 7-day
                // inactivity wipe, 5-attempt budget) so a binary downgrade can never
                // LOOSEN self-wipe / lockout below what the user chose.
                null -> ProtectionLevelRead.Present(ProtectionLevel.MAXIMUM)
                else -> ProtectionLevelRead.Present(level)
            }
        }
    } catch (_: KeyUnavailableException) {
        // Transient device-key outage — a healthy blob and a damaged one are
        // indistinguishable here, so DEFER (lenient), never wipe-adjacent.
        ProtectionLevelRead.Unreadable
    } catch (_: SelectorMetaDamagedException) {
        // The device key WORKS and the blob failed AEAD —
        // positive tamper evidence, NOT an outage. Returning Unreadable here made
        // one flipped byte inside the base64 disarm the dead-man's-switch forever
        // (threshold null = "skip this launch", every launch) while also handing
        // the tamperer the most LENIENT attempt budget. Damaged selects MAXIMUM's
        // policy window instead — and only the window: it is never itself a wipe
        // trigger (see ProtectionLevelRead.Damaged).
        ProtectionLevelRead.Damaged
    }

    /**
     * Wrong-credential threshold for the LAUNCH-TIME interrupted-wipe re-trigger
     * ONLY — the composition-time `persisted >= …` check in PinEntryScreen /
     * PinEntryView and RecoveryEntryScreen. NEW attempts keep using
     * [CredentialPolicy.maxConsecutiveAttempts] over [protectionLevelForEnforcement],
     * so every tightening for unauthenticated/damaged reads stays in force; see
     * [interruptedWipeAttemptThreshold] for the rule and for why the two must
     * differ (a budget that shrinks retroactively must not fire a wipe on failures
     * that were counted under the older, larger one).
     *
     * Reads the same `vlt_lvl` slot as [protectionLevelForEnforcement] and never
     * throws — Swift calls it straight off `vaultSelector` with no @Throws bridge.
     */
    fun maxConsecutiveAttemptsForInterruptedWipe(): Int = try {
        val read = readSelectorMetaRaw(VaultStoreKeys.PROTECTION_LEVEL)
        interruptedWipeAttemptThreshold(
            storedLevel = read?.let { ProtectionLevel.fromStorageOrNull(it.value) },
            present = read != null,
            authenticated = read?.authenticated == true,
        )
    } catch (_: Exception) {
        // KeyUnavailableException (transient device-key outage) or
        // SelectorMetaDamagedException (positive tamper) — under BOTH, the budget
        // the stranded failures were counted under is unknown, and a launch-time
        // wipe may never fire on a budget that shrank after the fact. Damaged
        // still gets MAXIMUM's tight budget for NEW attempts; it just cannot
        // retroactively condemn an existing counter. Broad catch because this
        // crosses the non-@Throws Swift bridge directly.
        ProtectionLevel.MOST_LENIENT_MAX_ATTEMPTS
    }

    /**
     * The level to DISPLAY (Settings / runestone art). Stored level, else a
     * best-effort label derived from a legacy install's crypto state (passphrase →
     * MAXIMUM, auth-bound → PRIVATE, else CASUAL). Do NOT use for enforcement —
     * that must go through [protectionLevelForEnforcement]
     * so legacy vaults keep their thresholds and the timer tier is never loosened.
     *
     * PRIVATE-over-plain honesty reconcile: PRIVATE's promise IS the Lever
     * B hardware barrier, so if the persisted tier claims PRIVATE while the DB key
     * is NOT actually auth-bound (a recovery-code unlock re-wrapped it plain and
     * Lever B could not be re-established; or an onboarding/Settings Lever-B enable
     * was cancelled), the DISPLAY drops to the honest CASUAL art — prompting the
     * user to re-harden — WITHOUT touching the persisted tier. So the enforcement
     * timers stay at the user's chosen (tight) PRIVATE values, and because the
     * claim is recomputed LIVE from [isDbKeyAuthBound] on every read, an interrupted
     * post-recovery reconcile can never strand a false PRIVATE-over-plain claim
     * Display-only: a transient [isDbKeyAuthBound] outage merely under-claims
     * (CASUAL art) for one render, never over-claims.
     *
     * The persisted tier is read through
     * [protectionLevelForFloorCheck], NOT [protectionLevelOrNull], so an
     * UNAUTHENTICATED value (legacy cleartext — or a plant, indistinguishable)
     * shows as [SelectorMetaPolicy.UNPROVEN_LEVEL] instead of whatever tier it claims. Two reasons,
     * and the second is load-bearing rather than cosmetic:
     *  - honesty, the same principle as the PRIVATE-over-plain reconcile above: a
     *    claim with no integrity is not evidence, and displaying the planted tier
     *    made the UI actively CORROBORATE the forgery (Settings showed the Maximum
     *    runestone for a 6-digit-PIN vault).
     *  - the forced tier-change screen this routes to is a NO-OP when the pick
     *    equals the displayed current level (`newLevel == current → dismiss`, in
     *    both ProtectionLevelSettingsScreen and ProtectionLevelSettingsView) — and
     *    on a lock-less device MAXIMUM is the only selectable pick. So a display
     *    that still reported the planted `maximum` would put the user on a screen
     *    that writes nothing and re-presents on the next unlock forever, leaving
     *    the vault on its PIN: the problem surfaced but not fixed.
     * The direction is always UNDER-claiming (never PRIVATE/MAXIMUM art over a
     * weaker reality), and it self-heals on the first authenticated tier write.
     */
    fun currentProtectionLevel(): ProtectionLevel {
        val persisted = protectionLevelForFloorCheck()
            ?: return when {
                isPassphraseMode() -> ProtectionLevel.MAXIMUM
                isDbKeyAuthBound() -> ProtectionLevel.PRIVATE
                else -> ProtectionLevel.CASUAL
            }
        return if (persisted == ProtectionLevel.PRIVATE && !isDbKeyAuthBound()) {
            ProtectionLevel.CASUAL   // honest: the hardware barrier PRIVATE promises is gone
        } else {
            persisted
        }
    }

    /**
     * [currentProtectionLevel] for UI art (the per-level runestone tiers) —
     * identical, but never throws: the legacy-install fallback probes crypto
     * state, which can hit a transient store outage (locked keybag
     * mid-transition). Falls back to CASUAL (plain art) instead of crashing a
     * render or crossing the non-@Throws Swift bridge. UI-only.
     */
    fun displayProtectionLevel(): ProtectionLevel = try {
        currentProtectionLevel()
    } catch (_: KeyUnavailableException) {
        ProtectionLevel.CASUAL
    }

    /**
     * Persist a new protection level (Settings level change, the one-time chooser,
     * the forced-migration commit). Device-key AEAD blob, durable.
     *
     * Returns false when the device key was transiently unavailable (nothing
     * written): reached from non-@Throws Swift callers (IosAppController via
     * ProtectionLevelView) and Compose click handlers, so the encrypt's
     * KeyUnavailableException must never escape (SIGABRT / UI crash) — the
     * write-side guard every sibling selector READ already has.
     *
     * It ALSO returns false when the write cannot be
     * PROVEN to have landed. This was a silent loop, and the worst kind — one that
     * re-arms itself. `putStringSync` reaches iOS `kvPut`, which returns without
     * writing on a locked keybag; a dropped `vlt_lvl` then reads as "no tier ever
     * chosen", which is exactly the condition `needsProtectionChoice` /
     * `DeviceLockPolicy.needsForcedMigration` trip on — so the user is marched
     * through the protection chooser on EVERY unlock, and every pass reports
     * success while dropping the write again. Nothing in the app could ever notice,
     * because nothing ever read the value back.
     *
     * Fail direction is the [storeWriteProven] one — proof required, ambiguity is
     * not proof — and it is right here for the same reason it is right at
     * provision: a false FAILURE costs one retry of a tier change the user is
     * actively making, while a false SUCCESS costs them the loop. Every shipped
     * caller already treats false as "abort this apply and tell the user"
     * (ProtectionLevelSettingsScreen / ProtectionLevelMigrationScreen on Android,
     * ProtectionLevelView's `persistFailed` on iOS), so no call site changes.
     *
     * DELIBERATELY NOT A PROOF GATE. It was proposed that this
     * refuse to persist a passphrase TIER unless [credentialKindProven] is `true`,
     * as a persist-layer backstop for the tier-upgrade rule. Three objections against it, recorded so
     * the idea is not re-derived from scratch:
     *  - **It would report a change that already LANDED as a failure.**
     *    `changeCredentialInner` verifies only the credential PAIR (`vlt_a` +
     *    `vlt_c`) before returning SUCCESS — dropping the trailing `vlt_m` is an
     *    explicitly accepted torn-write outcome there, repaired by the iOS journal
     *    replay. The tier commit runs immediately after that SUCCESS, so the read
     *    this guard depends on can legitimately still say `pin`; refusing then
     *    leaves a rotated passphrase stuck under a CASUAL label and, on the forced
     *    route, the user held at the gate for the rest of the session.
     *  - **It is not the persist layer.** Two other writers put `vlt_lvl` on disk
     *    without passing through here — the provision batch and
     *    [finalizeDbKeyAuthBinding]'s atomic key+tier batch — so the backstop
     *    would cover one of three doors.
     *  - **It contradicts the migrate-on-write contract** this method IS the
     *    self-heal for: "one authenticated tier write and a genuine vault is left
     *    alone again" (pinned by the instrumented
     *    `protectionLevel_plantedCleartextMaximum_cannotSatisfyTheDeviceLockFloor`
     *    and `InterruptedWipeRetriggerTest`, both of which write MAXIMUM onto a
     *    PIN-provisioned vault and assert `true`).
     * The proof gate therefore stays at the DECISION layer, where it can route the
     * user through a credential rotation instead of dead-ending:
     * [ProtectionUpgradePlan.needsCredentialChange], consulted by all four tier
     * screens on both platforms.
     */
    fun setProtectionLevel(level: ProtectionLevel): Boolean {
        var written: String? = null
        val encrypted = selectorWriteGuard("setProtectionLevel") {
            val blob = encryptSelectorMeta(VaultStoreKeys.PROTECTION_LEVEL, level.storageValue)
            written = blob
            store.putStringSync(VaultStoreKeys.PROTECTION_LEVEL, blob)
        }
        // Compare against the exact ciphertext we wrote, never a re-encryption: the
        // AEAD carries a fresh random IV, so a second encrypt of the same tier never
        // reproduces the same bytes.
        val blob = written
        if (!encrypted || blob == null) return false
        // fail-direction: proof-required (an unproven tier write reports false).
        if (!storeWriteProven(mapOf(VaultStoreKeys.PROTECTION_LEVEL to blob)) { store.getString(it) }) {
            platformLogWarn("VaultSelector",
                "setProtectionLevel NOT persisted — the tier did not read back; reporting failure " +
                    "so the caller can retry instead of looping the chooser on every unlock")
            return false
        }
        return true
    }

    // -----------------------------------------------------------------------
    // Selector metadata (vlt_m / vlt_lvl / vlt_rp / vlt_abk) at rest
    //
    // These values must be readable BEFORE unlock (vlt_m / vlt_lvl pick the entry
    // UI and drive the per-level lock/wipe thresholds; vlt_rp / vlt_abk gate the
    // unlock-time purge and reconcile), so they cannot be wrapped under
    // the PIN. Instead they are wrapped under the DEVICE key — the same layer that
    // decrypts the credential verifier pre-unlock (evalCredential) — with a fixed
    // per-key AEAD context. That closes the Android plaintext-shared_prefs leak
    // (and hardens the already-keychain-protected iOS copy) without changing when
    // they can be read. Reads tolerate a legacy cleartext value (installs
    // provisioned before the wrapped-meta migration) and every write re-persists a wrapped blob,
    // so the migration is lazy and lossless.
    //
    // That legacy tolerance is UNAUTHENTICATED by
    // definition — the fallback accepts any short string, so it is equally a
    // forgery channel for anyone who can write the store. Reads therefore carry
    // their provenance ([SelectorMetaRead.authenticated]); UI selectors may keep
    // consuming either, destructive enforcement may not.
    // -----------------------------------------------------------------------

    /** Fixed AEAD context binding a wrapped selector value to its storage slot. */
    private fun selectorMetaContext(key: String): ByteArray =
        (VaultCryptoContexts.SELECTOR_META_PREFIX + key).encodeToByteArray()

    /**
     * Device-key-wrap a selector value into the base64 blob persisted at [key].
     * The plaintext is NUL-padded to a FIXED length first, so the AEAD
     * ciphertext is a constant length regardless of the token (no mode/tier length
     * side-channel at rest).
     */
    private fun encryptSelectorMeta(key: String, plainValue: String): String =
        encodeBase64(crypto.seal(padSelectorMetaPlaintext(plainValue), selectorMetaContext(key)))

    // `writeSelectorMeta` — the fire-and-forget
    // "encrypt then putString, verify nothing" helper — is GONE. It had exactly two
    // callers, both inside the provision, and both are now sealed into the one
    // verified batch (see provisionCredentialAndVault). The rule since then is that
    // EVERY selector write declares its fail direction instead of being silently
    // fire-and-forget:
    //   - provision (`vlt_m` + `vlt_lvl` in the batch) and [setProtectionLevel]:
    //     proof required ([storeWriteProven]);
    //   - [armRecoveryEnablePending] (`vlt_rp`): its own authenticated read-back,
    //     false ⇒ no `vlt_rc` is minted;
    //   - change-credential (`vlt_m` in the batch): only the credential PAIR is
    //     checked ([credentialWriteRefuted]) — a torn write that dropped only `vlt_m`
    //     did rotate the credential, and the journal replay repairs the marker;
    //   - [markAuthBoundKeyStrict] (`vlt_abk`): deliberately UNVERIFIED — a lost
    //     stamp only triggers one harmless re-reconcile.
    // An unverified tier/mode write is how a dropped `vlt_lvl` looped the
    // protection chooser on every unlock and a dropped `vlt_m` put the digit keypad
    // on a passphrase vault. Re-adding the fire-and-forget helper would re-open both.

    /**
     * A selector value plus its PROVENANCE.
     * [authenticated] is true ONLY when the value came out of a SUCCESSFUL
     * device-key AEAD decrypt; false marks the LEGACY cleartext fallback, which
     * carries no integrity whatsoever — anyone who can write
     * vault_selector_prefs.xml (or the iOS NSUserDefaults fallback slot) can
     * choose it. Display/UI readers may consume either; DESTRUCTIVE enforcement
     * must treat an unauthenticated value as untrusted.
     */
    private class SelectorMetaRead(val value: String, val authenticated: Boolean)

    /**
     * Read a selector value, unwrapping the device-key AEAD blob. Returns null when
     * the key is absent. Transparently returns a LEGACY cleartext value (any stored
     * string that is not one of our blobs — decrypt throws, and the legacy tokens
     * "pin"/"phrase"/level names are far too short to be a valid IV+ct+tag, so there
     * is no ambiguity), flagged `authenticated = false`; the next write upgrades it
     * to a blob. A transient device-key outage (KeyUnavailableException, from
     * getString OR decrypt) is rethrown so the caller falls back to its neutral
     * default instead of misreading the value.
     */
    private fun readSelectorMetaRaw(key: String): SelectorMetaRead? {
        val raw = store.getString(key) ?: return null
        return try {
            // Strip the fixed-length NUL padding. unpad is a no-op on a
            // legacy unpadded blob, so both formats read to the same token.
            SelectorMetaRead(
                unpadSelectorMetaPlaintext(crypto.open(decodeBase64(raw), selectorMetaContext(key))),
                authenticated = true,
            )
        } catch (e: KeyUnavailableException) {
            throw e
        } catch (_: Exception) {
            // A value SHAPED like one of our blobs (≥ IV+tag raw bytes — see
            // isSelectorMetaBlobShaped) that fails decrypt is a DAMAGED blob,
            // never legacy cleartext. It must NOT be returned as the value:
            // surfaced raw, the base64 garbage read as "not phrase" (a
            // passphrase vault rendered the digit keypad — silent lockout) and
            // as an unknown level (shorter default thresholds). Surface it as
            // its own signal so callers pick a DAMAGED-specific fail-safe,
            // distinct from the transient outage above.
            if (isSelectorMetaBlobShaped(raw)) throw SelectorMetaDamagedException(key)
            // Legacy cleartext — still READ (so a pre-encryption install keeps working and
            // is upgraded to a blob on the next write), but flagged unauthenticated
            // so enforcement can refuse to trust it.
            SelectorMetaRead(raw, authenticated = false)
        }
    }

    /**
     * LENIENT read for UI/display selectors: the token, legacy cleartext
     * included, with its provenance discarded. Enforcement sites must use
     * [readSelectorMetaRaw] and honour `authenticated`.
     */
    private fun readSelectorMeta(key: String): String? = readSelectorMetaRaw(key)?.value

    // -----------------------------------------------------------------------
    // Lever B — hardware auth-bound DB-key layer (opt-in)
    // -----------------------------------------------------------------------

    /** True when this device can hardware auth-bind the DB-key unwrap. */
    fun supportsDbKeyAuthBinding(): Boolean = dbKeyProtector.supportsAuthBinding()

    /**
     * POSITIVE proof that the PLAIN (non-auth-bound) DB-key
     * blob a caller just wrote is really in the store — the precondition for
     * deleting [VaultStoreKeys.RECOVERY_BLOB], which is irreversible and, over a silently
     * dropped write, permanent vault loss (see [plainDbKeyReadBackProves]).
     *
     * Never throws (both call sites are on a non-@Throws Swift path) and fails
     * toward `false`, i.e. toward KEEPING the recovery code: a stale recovery blob
     * is a harmless orphan the next enable/disable rotates, a missing one over a
     * dead hardware key is a brick.
     */
    // fail-direction: proof-required (ambiguity keeps `vlt_rc`).
    private fun plainDbKeyCommitted(): Boolean = try {
        plainDbKeyReadBackProves(store.getString(VaultStoreKeys.WRAPPED_DBKEY)) { dbKeyProtector.isAuthBoundBlob(it) }
    } catch (_: Exception) {
        false
    }

    /**
     * Is an iOS write-ahead batch journal pending? `null` when the store
     * could not tell (a transient `KeyUnavailableException` from `contains`, which
     * is deliberately throwing there because "false" drives destructive decisions).
     * Consumed through [singleKeyDbKeyWriteAllowed], which treats `null` as refuse.
     */
    private fun batchJournalPending(): Boolean? = try {
        store.contains(VaultStoreKeys.BATCH_JOURNAL)
    } catch (_: Exception) {
        null
    }

    /** True when the stored DB key is currently auth-bound (Lever B active). */
    fun isDbKeyAuthBound(): Boolean = try {
        store.getString(VaultStoreKeys.WRAPPED_DBKEY)?.let { dbKeyProtector.isAuthBoundBlob(it) } ?: false
    } catch (_: KeyUnavailableException) {
        // Display-only (Settings toggle state). Called from Swift (non-@Throws);
        // a transient store failure must not cross the bridge (SIGABRT).
        false
    }

    /**
     * Fresh strong-auth proof for a Lever B vault: unwraps the auth-bound DB-key
     * layer (ONE biometric prompt on Android BiometricGate / iOS Secure Enclave),
     * discards the result and writes nothing. True when the vault is not auth-bound
     * (nothing to prove) or the unwrap succeeded; false on cancel/lockout/outage.
     * Heavy + may prompt — call OFF the main thread. Used by the move-export gate.
     */
    fun verifyStrongAuth(): Boolean = try {
        val stored = store.getString(VaultStoreKeys.WRAPPED_DBKEY)
        if (stored == null || !dbKeyProtector.isAuthBoundBlob(stored)) {
            stored != null
        } else {
            val inner = dbKeyProtector.unwrap(stored)
            inner.secureWipe()
            true
        }
    } catch (_: Exception) {
        false
    }

    /**
     * Enable or disable the auth-bound DB-key layer (Lever B) on the OUTER
     * device-key wrap only — no PIN needed, since the PIN-KEK inner layer is
     * untouched. Re-wraps in place:
     *  - enable:  unwrap the current (plain) outer layer [no prompt], re-wrap
     *             under the auth-bound key [no prompt — public/encrypt op].
     *  - disable: unwrap the current AUTH-BOUND layer [ONE biometric prompt,
     *             proving the user can pass it], re-wrap plain.
     * The caller (Settings) must already be unlocked. Runs heavy crypto + a
     * possible prompt — call OFF the main thread. Returns true on success;
     * false leaves the stored blob untouched (fail-safe, never bricks).
     */
    fun setDbKeyAuthBinding(enabled: Boolean): Boolean {
        if (enabled && !dbKeyProtector.supportsAuthBinding()) return false
        // BRICK-SAFETY (biometric strict-invalidate). This raw toggle cannot MINT a
        // recovery code (it re-wraps the outer layer with no credential / dbKey in
        // hand), so it must NEVER create an auth-bound blob without an existing
        // recovery path — otherwise a later biometric re-enrollment would brick the
        // vault with no way back. Enabling from scratch MUST go through
        // enableDbKeyAuthBindingWithRecovery (which mints + verifies a code). Refuse
        // an enable unless a recovery blob is already provisioned (e.g. re-arming
        // after a transient write glitch left the DB key plain with recovery intact).
        //
        // PRESENCE is not a net. This gate used to ask
        // `store.contains`, so a planted `vlt_rc` — six bytes anyone able to write
        // the store can add — satisfied the one condition standing between this
        // toggle and an auth-bound vault with NO way back. It now requires a blob
        // that actually opens under the device key ([recoveryBlobUsableAsNet]);
        // ABSENT, FORGED and UNREADABLE all refuse, and refusing an enable is
        // never destructive.
        if (enabled && !recoveryBlobUsableAsNet(recoveryBlobState())) {
            platformLogWarn("VaultSelector",
                "setDbKeyAuthBinding(true) refused — no PROVEN recovery code; use enableDbKeyAuthBindingWithRecovery")
            return false
        }
        return try {
            // Inside the try: on iOS this read throws KeyUnavailableException on
            // a transient Keychain failure; the catch below maps it
            // to false with the stored blob untouched — and the Swift caller is
            // non-@Throws, so it must never cross the bridge.
            val stored = store.getString(VaultStoreKeys.WRAPPED_DBKEY) ?: return false
            if (dbKeyProtector.isAuthBoundBlob(stored) == enabled) return true  // already in target state
            // This toggle writes `vlt_c` with a SINGLE-KEY
            // putStringSync and, on the disable leg, deletes `vlt_rc` once that write
            // reads back. A stale iOS journal would replay the OLD `vlt_c` at the next
            // construction — restoring the ab: blob over a deleted recovery code.
            // Refuse while one is pending (or unreadable) and report failure: nothing
            // is written, so the vault stays exactly as openable as it is now, and the
            // journal clears itself on the next launch. Checked BEFORE the unwrap so a
            // refusal never costs the user a biometric prompt.
            if (!singleKeyDbKeyWriteAllowed(batchJournalPending())) {
                platformLogWarn("VaultSelector",
                    "setDbKeyAuthBinding($enabled) deferred — a pending write-ahead journal could revert the DB-key blob")
                return false
            }
            // Each leg unwraps, re-wraps, commits and finishes on its own; any exception
            // falls through to the catch below (false, stored blob untouched or proven).
            if (enabled) enableBindingInPlace(stored) else disableBindingInPlace(stored)
        } catch (e: Exception) {
            platformLogWarn("VaultSelector", "setDbKeyAuthBinding($enabled) failed: ${e::class.simpleName}")
            false
        }
    }

    // [setDbKeyAuthBinding]'s ENABLE leg over a PLAIN [stored] blob (checked by the
    // caller, together with the PROVEN recovery net and the journal gate): unwrap
    // [no prompt], delete → wrap auth-bound → round-trip verify [ONE prompt], commit,
    // stamp the strict scheme, disarm `vlt_rp`. False = round trip failed, nothing
    // written. Exceptions propagate to the caller's catch.
    private fun enableBindingInPlace(stored: String): Boolean {
        val inner = dbKeyProtector.unwrap(stored)  // plain → no prompt
        try {
            // On ENABLE the current blob is PLAIN (checked above), so mint a
            // FRESH strict key — this plain→ab: transition must not reuse a stale
            // old-params key. Safe: no ab: blob depends on the auth-bound key yet.
            // Before COMMITTING an auth-bound blob, prove it can
            // actually be UNWRAPPED on this device — one fresh biometric/
            // credential prompt. A buggy OEM Keystore/SE (or a device passcode
            // the user later removes) could make the private-key unwrap fail
            // forever, bricking every future unlock (KeyUnavailableException →
            // Error loop) with no recovery but a data-losing wipe. Verify the
            // round trip and only persist if it decrypts back to the same inner;
            // otherwise leave the old (plain, still-usable) blob untouched.
            // (delete → wrap → round-trip: [VaultBlobCodecs.wrapAuthBoundVerified].)
            val rewrapped = codecs.wrapAuthBoundVerified(inner) ?: run {
                platformLogWarn("VaultSelector", "auth-binding round-trip verify failed — NOT enabling (old blob kept)")
                return false
            }
            store.putStringSync(VaultStoreKeys.WRAPPED_DBKEY, rewrapped)
            // Stamp the fresh strict key so the unlock-time reconcile skips it.
            markAuthBoundKeyStrict()
            // Defensive only — this toggle refuses to enable without an
            // EXISTING recovery blob (above), so it never runs mid-two-phase and
            // no shipped caller passes true. If a future one does, the vault is
            // now auth-bound and nothing is in flight: disarm, so the purge can
            // never look at a live Lever B vault.
            clearRecoveryEnablePending()
            platformLog("VaultSelector", "DB-key auth-binding enabled")
            return true
        } finally {
            inner.secureWipe()
        }
    }

    // [setDbKeyAuthBinding]'s DISABLE leg over an AUTH-BOUND [stored] blob: unwrap
    // [ONE biometric prompt — proves the user can pass it], re-wrap plain, commit, and
    // only once the plain blob is PROVEN to read back drop `vlt_rc`, `vlt_rp` and
    // `vlt_abk`. False = not proven, recovery code KEPT. Exceptions propagate to the
    // caller's catch.
    private fun disableBindingInPlace(stored: String): Boolean {
        val inner = dbKeyProtector.unwrap(stored)  // disable path prompts here
        try {
            val rewrapped = dbKeyProtector.wrap(inner, authBound = false)
            store.putStringSync(VaultStoreKeys.WRAPPED_DBKEY, rewrapped)
            // Lever B off → the recovery code no longer protects anything;
            // drop it (a fresh one is minted if Lever B is re-enabled). Written
            // AFTER the plain blob commits, so a failure can't strand the ab:
            // blob without its recovery path. Also drop the scheme marker.
            //
            // "After" is not enough — the two writes fail
            // ASYMMETRICALLY. putStringSync returns Unit and iOS's actual returns
            // WITHOUT writing on a locked keybag, while remove() is a bare
            // SecItemDelete that needs no class key and still succeeds. So prove
            // the plain blob really landed before revoking the only way back into
            // an ab: blob whose hardware key may already be dead. Not proven ⇒
            // keep the recovery code and report failure: the vault is untouched
            // (biometric OR recovery code still opens it) and the user retries.
            if (!plainDbKeyCommitted()) {
                platformLogWarn("VaultSelector",
                    "disable: plain DB-key blob did not read back — KEEPING the recovery code")
                return false
            }
            store.remove(VaultStoreKeys.RECOVERY_BLOB)
            // The blob the in-flight marker could ever have referred to is gone.
            clearRecoveryEnablePending()
            clearAuthBoundKeyScheme()
            platformLog("VaultSelector", "DB-key auth-binding disabled")
            return true
        } finally {
            inner.secureWipe()
        }
    }

    // -----------------------------------------------------------------------
    // Lever B recovery code — survive hardware-key invalidation
    // -----------------------------------------------------------------------

    sealed class RecoveryEnableResult {
        /** Lever B enabled; show this one-time code to the user (raw Base32, ungrouped). */
        data class Enabled(val recoveryCode: String) : RecoveryEnableResult()
        /** This device can't hardware-bind (Lever B unsupported / Simulator). */
        data object Unsupported : RecoveryEnableResult()
        /** [credential] did not match — nothing changed. */
        data object WrongCredential : RecoveryEnableResult()
        /** Enable failed (round-trip verify / store / prompt) — nothing changed. */
        data object Failed : RecoveryEnableResult()
    }

    /**
     * What [VaultStoreKeys.RECOVERY_BLOB] actually proves right now — see
     * [classifyRecoveryBlob] for why presence alone is not an answer.
     *
     * Opens the DEVICE layer only ([VaultBlobCodecs.openRecoveryDeviceLayer]); the
     * user's 160-bit code is a second, inner layer this never touches, so this
     * costs one AES-GCM open, prompts for nothing and needs no vault. Never
     * throws — both consumers sit on non-`@Throws` Swift-reachable paths.
     */
    private fun recoveryBlobState(): RecoveryBlobState {
        val raw = try {
            store.getString(VaultStoreKeys.RECOVERY_BLOB)
        } catch (_: Exception) {
            // The STORE could not be read at all (iOS locked keybag, securityd
            // glitch). Same conclusion as a device key that cannot decrypt:
            // nothing can be concluded, so keep whatever state we are in.
            return RecoveryBlobState.UNREADABLE
        }
        return classifyRecoveryBlob(raw) { blob ->
            codecs.openRecoveryDeviceLayer(blob)
            true
        }
    }

    /**
     * True when a recovery code is provisioned for the current vault (Lever B on).
     *
     * PROVEN or UNREADABLE — never a bare `contains`.
     * A planted `vlt_rc` used to put "use your recovery code" on the unlock
     * screen of a vault that has none, and every attempt against it was a
     * counted wrong-code guess against the emergency-wipe budget. An UNREADABLE
     * slot still answers true, because hiding the escape hatch from a user whose
     * hardware key just died is the brick this whole subsystem prevents.
     */
    fun hasRecoveryCode(): Boolean = recoveryPathOffered(recoveryBlobState())

    // --- The in-flight Lever B enable marker ------------------------------------

    /**
     * Arm [VaultStoreKeys.RECOVERY_PENDING] and PROVE it is readable back before returning
     * true. Called immediately BEFORE the `vlt_rc` write, and that ordering IS the
     * invariant: the marker must be durable before the recovery blob exists, so the
     * only torn half a crash can leave is marker-WITHOUT-blob — inert (the next
     * unlock's purge removes an absent `vlt_rc`, a no-op, and clears the marker).
     * The dangerous half would be blob-without-marker: an orphan nothing can ever
     * name again, which is precisely the bug this marker exists for.
     *
     * This is DELIBERATELY the INVERSE of the inactivity / PinAttemptsStore anchor
     * ordering, where the evidence must be durable BEFORE the marker is
     * armed. Those markers authorise a WIPE, so a marker that outruns its evidence
     * destroys a legitimate vault. This one authorises only a `vlt_rc` DELETE over a
     * blob proven still plain, so the dangerous direction here is a MISSING marker,
     * not an early one. Do NOT harmonise these two orderings.
     *
     * On Android the read-back proves nothing about the DISK — `KeyValueStore`
     * discards `commit()`'s Boolean and `getString` reads the in-memory map the
     * write just updated. The ordering invariant survives anyway because the marker
     * and `vlt_rc` share ONE SharedPreferences file that every `commit()` rewrites
     * whole: no flush can carry the blob without the marker, so no checked-commit
     * API is needed for this ordering (the only commit-Boolean handling in
     * KeyValueStore.android.kt is the loud log in `putStringsSync`).
     * On iOS the read-back is a real Keychain read and does catch the silent
     * locked-keybag `kvPut` no-op.
     */
    private fun armRecoveryEnablePending(): Boolean = try {
        store.putStringSync(
            VaultStoreKeys.RECOVERY_PENDING,
            encryptSelectorMeta(VaultStoreKeys.RECOVERY_PENDING, RECOVERY_PENDING_ARMED),
        )
        // fail-direction: proof-required (unproven ⇒ no `vlt_rc` is minted).
        val read = readSelectorMetaRaw(VaultStoreKeys.RECOVERY_PENDING)
        read?.authenticated == true && read.value == RECOVERY_PENDING_ARMED
    } catch (_: Exception) {
        // Device-key outage, damaged read, store fault — all "not proven durable".
        // The caller then declines to mint `vlt_rc` at all, so nothing is orphaned.
        false
    }

    /**
     * Disarm the in-flight marker. A bare remove that never throws: every call site
     * is on a path whose real work already succeeded (or is being rolled back), and
     * a leftover marker is never destructive on its own — the purge additionally
     * requires a CONFIRMED-plain DB-key blob.
     */
    private fun clearRecoveryEnablePending() {
        try {
            store.remove(VaultStoreKeys.RECOVERY_PENDING)
        } catch (_: Exception) {
            platformLogWarn("VaultSelector", "recovery-pending marker clear deferred — store unavailable")
        }
    }

    /**
     * Revoke the orphan recovery code left by an ABANDONED Lever B enable.
     *
     * Runs on a successful unlock, where [dbKeyBlob] is the very blob the verified
     * credential just opened the vault with — so "the DB key is still plain" is a
     * fact, not a read that might be racing something. Never throws: the marker read
     * goes through [readSelectorMetaRaw], which RETHROWS [KeyUnavailableException]
     * and THROWS [SelectorMetaDamagedException] for any blob-shaped value that fails
     * AEAD. Unguarded, a planted blob-shaped `vlt_rp` (the same filesystem-write
     * adversary the selector-meta provenance rules assume) would make EVERY correct-PIN unlock throw —
     * an app crash on Android, `UNLOCK_ERROR` on iOS, and a skipped `dbKey.secureWipe()`
     * — i.e. a permanent vault DoS. So the whole body fails toward
     * [AbandonedEnableAction.NONE]: doing nothing is always safe here.
     *
     * Two skips are correctness, not caution:
     *  - [pendingAuthBoundBlob] still live, or an iOS write-ahead batch journal still
     *    pending. Both mean an ab: commit may STILL land — the journal replays on a
     *    LATER launch than the one that purged — and an auth-bound vault with no
     *    recovery path violates the invariant that plain → auth-bound happens only
     *    after a working recovery path is proven durable.
     *  - [credentialRewritten]: [migrateCredentialToCurrentKdf] just rewrote `vlt_a`
     *    AND `vlt_c`, so "the blob the credential just decrypted" stops being
     *    literally true. Defer one cycle; the next unlock proves the migrated
     *    credential still opens the vault and then decides.
     */
    private fun purgeAbandonedRecoveryEnable(dbKeyBlob: String, credentialRewritten: Boolean) {
        try {
            if (credentialRewritten) return
            if (pendingAuthBoundBlob != null) return
            if (store.contains(VaultStoreKeys.BATCH_JOURNAL)) return
            val marker = readSelectorMetaRaw(VaultStoreKeys.RECOVERY_PENDING)
            val action = abandonedEnableAction(
                markerValue = marker?.value,
                markerAuthenticated = marker?.authenticated == true,
                dbKeyBlob = dbKeyBlob,
            ) { dbKeyProtector.isAuthBoundBlob(it) }
            when (action) {
                AbandonedEnableAction.NONE -> return
                AbandonedEnableAction.CLEAR_MARKER_ONLY -> {
                    // The enable completed; only the marker is stale. `vlt_rc` is the
                    // live recovery path of an auth-bound vault — never touch it.
                    clearRecoveryEnablePending()
                }
                AbandonedEnableAction.PURGE_RECOVERY -> {
                    // Recovery blob FIRST, marker LAST: a crash between them re-runs
                    // this on the next unlock and converges. Marker-first would leave
                    // exactly the unnameable orphan this purge is about.
                    store.remove(VaultStoreKeys.RECOVERY_BLOB)
                    clearRecoveryEnablePending()
                    platformLog("VaultSelector",
                        "abandoned Lever B enable — orphan recovery code revoked (vault stays plain)")
                }
            }
        } catch (_: Exception) {
            // KeyUnavailableException / SelectorMetaDamagedException / store fault.
            // Do nothing at all; this runs on an already-successful unlock and must
            // never turn one into a crash or an Error.
            platformLogWarn("VaultSelector", "abandoned-enable check skipped — marker unreadable")
        }
    }

    // --- Auth-bound key scheme marker (legacy-weak-key detection) ---------------

    /**
     * True when the CURRENT auth-bound key is the STRICT biometric-only scheme
     * (the strict-scheme marker). A missing marker while the DB-key blob is auth-bound means a
     * LEGACY WEAK key (device-passcode-openable) → the unlock-time reconcile upgrades
     * it. Ambiguous read (outage / damaged) → true so a re-mint never fires on
     * uncertainty; genuinely-absent (key not present) → false.
     *
     * This read requires AUTHENTICATION. The lenient [readSelectorMeta]
     * discards [SelectorMetaRead.authenticated], so a planted CLEARTEXT `2` in the
     * `vlt_abk` slot (vault_selector_prefs.xml, or the iOS defaults slot) read as
     * "already strict" — which silently suppresses BOTH the unlock-time re-mint
     * ([maybeReconcileLegacyAuthBoundKey]) and the [needsLeverBReharden] UI nudge,
     * pinning a PRIVATE vault on the legacy WEAK key a cracked device passcode opens.
     * Unlike `vlt_lvl` there is no honest-cleartext population to protect here:
     * [markAuthBoundKeyStrict] has written this slot device-key-AEAD'd since the key
     * was introduced, so no legitimate cleartext value has ever existed in it and
     * every unauthenticated read of it is, by definition, forged. Hence zero brick
     * risk and zero false-reconcile risk from rejecting it.
     *
     * Failing toward strict on an UNREADABLE marker (device-key outage) stays and is
     * independently load-bearing — it stops a delete-legacy-then-mint rotation from
     * firing during a transient outage, when the read proves nothing.
     *
     * A DAMAGED marker is the opposite case and
     * must read NOT strict. `readSelectorMetaRaw` already distinguishes them — a
     * blob-SHAPED value that fails AEAD while the device key works is positive
     * tamper evidence ([SelectorMetaDamagedException]), exactly as `vlt_lvl` and
     * `vlt_m` treat it. The old blanket `catch { true }` collapsed both signals, so
     * one zero-crypto write of ≥28 base64 bytes into this slot permanently
     * suppressed [maybeReconcileLegacyAuthBoundKey] — pinning a PRIVATE vault on the
     * legacy device-credential-openable Lever B key. Returning false on damage is
     * safe in both directions: the re-mint it re-enables is separately gated on
     * [supportsAuthBinding] + a PROVEN recovery blob (opens under the device key), is best-effort and non-fatal,
     * and rewrites this slot on success, so a damaged marker self-heals instead of
     * latching. Any other unexpected failure keeps the outage direction.
     */
    private fun isAuthBoundKeyStrict(): Boolean = try {
        val read = readSelectorMetaRaw(VaultStoreKeys.AUTHBOUND_SCHEME)
        read?.authenticated == true && read.value == AUTHBOUND_SCHEME_STRICT
    } catch (_: KeyUnavailableException) {
        true    // transient outage: the read proves nothing — do not rotate
    } catch (_: SelectorMetaDamagedException) {
        false   // positive tamper evidence: a planted marker must not suppress the upgrade
    } catch (_: Exception) {
        true
    }

    /** Stamp the current auth-bound key as the strict scheme (synchronous, alongside
     *  a strict-key ab: commit). A lost stamp only triggers one harmless re-reconcile. */
    private fun markAuthBoundKeyStrict() {
        store.putStringSync(VaultStoreKeys.AUTHBOUND_SCHEME, encryptSelectorMeta(VaultStoreKeys.AUTHBOUND_SCHEME, AUTHBOUND_SCHEME_STRICT))
    }

    /** Drop the scheme marker when the DB-key blob goes plain (disable / recover). */
    // Block body, not an expression body: [KeyValueStore.remove] returns a
    // confirmation Boolean now (see its kdoc), and this helper deliberately
    // stays Unit — nothing here acts on it.
    private fun clearAuthBoundKeyScheme() { store.remove(VaultStoreKeys.AUTHBOUND_SCHEME) }

    /**
     * True when the current vault is PRIVATE-armed with a LEGACY WEAK auth-bound key
     * (device-passcode-openable) that the unlock-time reconcile could NOT auto-upgrade
     * — biometrics unavailable, or no recovery code to guard the re-mint. A UI signal:
     * the app can prompt the user to re-harden (Settings disable→enable, which mints a
     * strict key + fresh recovery code) or step down. Called post-unlock; never throws.
     */
    fun needsLeverBReharden(): Boolean = try {
        val stored = store.getString(VaultStoreKeys.WRAPPED_DBKEY) ?: return false
        dbKeyProtector.isAuthBoundBlob(stored) && !isAuthBoundKeyStrict()
    } catch (_: Exception) {
        false
    }

    /**
     * Commit-before-display close + honest-tier atomicity: commit the
     * auth-bound blob PREPARED by [enableDbKeyAuthBindingWithRecovery], AFTER the UI has
     * shown + the user has acknowledged the one-time recovery code — AND promote the
     * protection [level] (PRIVATE) in the SAME atomic store write, so the tier can never
     * be persisted PRIVATE while the DB key is still plain (the over-claim).
     *
     * The single [KeyValueStore.putStringsSync] batch lands all three — the ab: blob, the
     * strict-scheme marker, and the tier — or NONE (journalled on iOS). So the states are:
     *  - pre-ack: the UI leaves the HONEST BASE tier committed over the plain key
     *    (consistent under-claim; app death here is safe + re-doable), and
     *  - post-ack: tier == [level] ⟺ key == auth-bound (consistent honest).
     *
     * Returns false — vault stays PLAIN, tier UNCHANGED (base), pending kept for a retry —
     * when nothing was prepared or the batch did not persist (never bricks: PIN still
     * opens the vault, and the verified recovery blob is a harmless orphan). The tier is
     * ATOMIC with the key, so there is no "ab: committed but tier lagged" half-state.
     * Call OFF the main thread after the code ack.
     */
    fun finalizeDbKeyAuthBinding(level: ProtectionLevel): Boolean {
        val blob = pendingAuthBoundBlob ?: return false
        // Stale-inner gate (read only, writes nothing on a mismatch): the held blob
        // wraps the inner layer of [pendingAuthBoundBase]; if `vlt_c` moved since the
        // enable, that inner may be under a KEK the current verifier no longer
        // derives. Drop the prepared enable — the vault stays PLAIN on its current
        // (valid) blob, and the armed `vlt_rp` lets the next unlock revoke the orphan
        // `vlt_rc` (the purge skips only while a pending blob is live, which is why
        // this does NOT clear it on lock/unlock: a finalize still in flight relies on
        // that skip). An unreadable store keeps the pending blob for a retry.
        val current = try {
            store.getString(VaultStoreKeys.WRAPPED_DBKEY)
        } catch (_: Exception) {
            platformLogWarn("VaultSelector", "finalize deferred — store unavailable (prepared enable kept)")
            return false
        }
        // A RETRY after a finalize whose batch LANDED but whose read-back missed (iOS
        // locked keybag): `vlt_c` already IS the prepared ab: blob — byte-for-byte what
        // this call would write — so the enable is complete. Report success without
        // re-writing the batch (a torn remainder of it is the iOS journal's to replay),
        // and finish exactly like the success path below: disarm `vlt_rp` (the blob on
        // disk reads back auth-bound — the same proof that path requires) and drop the
        // pending state. Refusing here instead reported failure twice and invited a
        // re-run of the enable that would replace the recovery code the user saved.
        if (current != null && current == blob) {
            clearRecoveryEnablePending()
            pendingAuthBoundBlob = null
            pendingAuthBoundBase = null
            platformLog("VaultSelector", "Lever B finalize retry — the ab: blob had already landed; nothing re-written")
            return true
        }
        if (current == null || current != pendingAuthBoundBase) {
            platformLogWarn("VaultSelector",
                "finalize refused — the DB-key blob changed since the enable; vault stays plain (re-run the enable)")
            pendingAuthBoundBlob = null
            pendingAuthBoundBase = null
            return false
        }
        return try {
            store.putStringsSync(mapOf(
                VaultStoreKeys.WRAPPED_DBKEY to blob,
                VaultStoreKeys.AUTHBOUND_SCHEME to encryptSelectorMeta(VaultStoreKeys.AUTHBOUND_SCHEME, AUTHBOUND_SCHEME_STRICT),
                VaultStoreKeys.PROTECTION_LEVEL to encryptSelectorMeta(VaultStoreKeys.PROTECTION_LEVEL, level.storageValue),
            ))
            // Confirm the atomic batch landed. The code is already acknowledged, so a
            // read-back here can't lose it; if the ab: blob is absent the batch did not
            // persist (atomic → the tier didn't either) → the vault stays PLAIN + the
            // honest base tier, a safe under-claim, and pending is kept for a retry.
            // fail-direction: proof-required (finalize reports false unless `vlt_c` reads back auth-bound).
            if (store.getString(VaultStoreKeys.WRAPPED_DBKEY)?.let { dbKeyProtector.isAuthBoundBlob(it) } != true) {
                platformLogWarn("VaultSelector",
                    "finalize: atomic ab:+tier batch did not persist — vault stays plain at base (retry)")
                return false
            }
            // The enable COMPLETED — nothing is in flight, so disarm the marker.
            // Strictly after the read-back gate above: while the batch is unproven the
            // vault may still be plain, and a cleared marker there would strand the very
            // orphan this closes. Ordered before `pendingAuthBoundBlob = null` only for
            // readability — a crash between them just leaves a stale marker, which the
            // unlock purge resolves as CLEAR_MARKER_ONLY (the ab: blob is committed).
            clearRecoveryEnablePending()
            pendingAuthBoundBlob = null
            pendingAuthBoundBase = null
            platformLog("VaultSelector", "Lever B finalized — ab: key + ${level.storageValue} tier committed atomically after code ack")
            true
        } catch (e: Exception) {
            platformLogWarn("VaultSelector", "finalizeDbKeyAuthBinding failed (vault stays plain, tier unchanged): ${e::class.simpleName}")
            false
        }
    }

    /**
     * Enable Lever B and mint a data-recovery code — PHASE ONE of a two-phase
     * enable. Verifies [credential], mints a FRESH strict biometric-only key,
     * re-wraps the DB key under it (with a round-trip biometric verify), and writes +
     * read-back-verifies the recovery blob (dbKey under a fresh 160-bit code KEK). It
     * does NOT yet commit the auth-bound blob NOR promote the protection tier: the DB
     * key stays PLAIN and the strict blob is HELD in [pendingAuthBoundBlob] until the UI
     * shows the returned code and the user acknowledges it, then calls
     * [finalizeDbKeyAuthBinding], which commits the ab: key AND the PRIVATE tier in one
     * atomic write. The enable phase (UI) must therefore keep the HONEST BASE tier during
     * display — never persist PRIVATE while the key is still plain. This closes the
     * window where the app dies with the code on screen: pre-commit the vault is plain
     * (PIN opens it) so a lost code can never brick a strict-invalidate vault. The
     * vault must be unlocked. Call OFF the main thread (Argon2 + a biometric prompt).
     * On any failure nothing load-bearing is persisted (fail-safe, never bricks).
     * Returns the displayable code exactly once — it is never stored in the clear.
     */
    fun enableDbKeyAuthBindingWithRecovery(credential: String): RecoveryEnableResult {
        // Rate-limit this credential-probe channel at the
        // SHARED API boundary. evalCredential inside is a PIN oracle; without the
        // uniform floor a caller — a future or alternate one, since the shipped UIs
        // funnel through the counted+floored change-credential flow first — could
        // probe candidate PINs at raw-KDF speed with no penalty. Same
        // markNow()/enforceChangePinDelay bracket verifyCredential/changeCredential
        // use, so the delay leaks nothing about the outcome and can't be defeated by
        // an alternate caller (enforce at the boundary, not the UI).
        val start = TimeSource.Monotonic.markNow()
        try {
            return enableDbKeyAuthBindingWithRecoveryInner(credential)
        } finally {
            enforceChangePinDelay(start)
        }
    }

    private fun enableDbKeyAuthBindingWithRecoveryInner(credential: String): RecoveryEnableResult {
        if (!dbKeyProtector.supportsAuthBinding()) return RecoveryEnableResult.Unsupported
        // Never mint a recovery code over an unresolved DB-key rotation. The
        // recovery blob wraps the DB key read out of `vlt_c`, which during a pending
        // rotation may not be the key the FILE is on — the user would write down a code
        // that opens nothing. Retryable and benign (the vault stays plain at its
        // existing tier); the next unlock reconciles the record.
        if (rotationPending()) {
            platformLogWarn("VaultSelector",
                "Lever B enable deferred — a DB-key rotation is still pending (resolved on the next unlock)")
            return RecoveryEnableResult.Failed
        }
        val (matches, stretched, _) = try {
            evalCredential(credential)
        } catch (_: KeyUnavailableException) {
            return RecoveryEnableResult.Failed
        }
        if (!matches || stretched == null) {
            stretched?.secureWipe()
            return RecoveryEnableResult.WrongCredential
        }
        var kek: ByteArray? = null
        var inner: ByteArray? = null
        var dbKey: ByteArray? = null
        var secret: ByteArray? = null
        try {
            val stored = store.getString(VaultStoreKeys.WRAPPED_DBKEY) ?: return RecoveryEnableResult.Failed
            if (dbKeyProtector.isAuthBoundBlob(stored)) return RecoveryEnableResult.Failed  // already on
            kek = codecs.dbKeyKek(stretched)
            inner = dbKeyProtector.unwrap(stored)             // currently plain → no prompt
            // Raw-key adoption: the inner payload may carry the key mode (+ K'); the
            // recovery blob wraps R ONLY — the stable dbKey, which opens the vault in
            // passphrase mode whatever mode `vlt_c` is in. The ab: blob below wraps
            // [inner] verbatim, so the mode tag survives the enable unchanged.
            val payload = codecs.openDbKeyInner(inner, kek) ?: return RecoveryEnableResult.Failed
            dbKey = payload.dbKey                             // the stable dbKey (R)
            payload.rawKey?.secureWipe()

            // Enable = a genuine plain → auth-bound transition (checked above), so mint
            // a FRESH hardware key: drop any stale/invalidated one first. Without this a
            // key invalidated by a prior biometric re-enrollment would be reused and the
            // round-trip verify would fail forever, blocking re-arming Lever B.
            // Auth-bound re-wrap + round-trip verify (one biometric) before committing —
            // a buggy Keystore/SE that can't unwrap must not brick every future unlock.
            val authBoundBlob = codecs.wrapAuthBoundVerified(inner) ?: run {
                platformLogWarn("VaultSelector", "recovery-enable round-trip verify failed — NOT enabling")
                return RecoveryEnableResult.Failed
            }

            // Recovery blob over the STABLE dbKey (survives PIN rotation), so the
            // code alone recovers the data and the PIN alone still can't (Lever B's
            // guarantee is preserved — the code is a 160-bit user-held barrier).
            secret = generateSecureRandom(RECOVERY_SECRET_LENGTH)
            val recoveryBlob = codecs.sealRecoveryBlob(dbKey, secret)

            // BRICK-SAFETY (biometric strict-invalidate). The auth-bound key now
            // invalidates on ANY biometric re-enrollment, so once VaultStoreKeys.WRAPPED_DBKEY is
            // auth-bound the recovery code is the ONLY way back into the vault.
            // Therefore: commit the recovery blob and READ-BACK-VERIFY it decrypts to
            // the same dbKey BEFORE the ab: blob is persisted. Ordering matters —
            // VaultStoreKeys.WRAPPED_DBKEY only ever transitions plain → auth-bound AFTER a working
            // recovery path is proven durable:
            //   1. write recovery, verify it round-trips to dbKey. If not (silent
            //      keybag-locked put, damaged blob, device-key outage), abort with the
            //      DB key STILL PLAIN — the PIN still opens the vault (never a brick).
            //   2. only then commit the ab: blob as the final write.
            //
            // ARM the in-flight marker first, read-back-gated,
            // so the abandoned state below (this returns, the user never acknowledges
            // the code, finalize never runs) can be NAMED on the next unlock instead of
            // leaving `vlt_rc` on disk forever as an unnameable second decrypt path. See
            // [armRecoveryEnablePending] for why marker-before-blob is the right (and
            // deliberately anchor-INVERSE) ordering. Not proven durable ⇒ do not mint
            // the blob at all: an unmarked orphan is exactly what this closes.
            if (!persistRecoveryBlobArmed(recoveryBlob, secret, dbKey)) return RecoveryEnableResult.Failed
            // Commit-before-display close: DO NOT commit the auth-bound blob yet.
            // Committing it here would strict-invalidate the vault to a key the user
            // could lose access to if the app dies while the code is still on screen
            // (the code is only displayed AFTER this returns) — a later re-enrollment
            // would then permanently lose the vault. So HOLD the strict blob; the DB
            // key stays PLAIN (PIN opens it) with a harmless verified recovery orphan
            // until the UI shows + acknowledges the code and calls
            // [finalizeDbKeyAuthBinding]. Recovery-first + read-back-verify (above)
            // still runs first — an orphan plain-key recovery blob is harmless.
            pendingAuthBoundBlob = authBoundBlob
            pendingAuthBoundBase = stored
            platformLog("VaultSelector", "Lever B prepared (recovery code verified) — awaiting code ack to finalize")
            return RecoveryEnableResult.Enabled(Base32.encode(secret))
        } catch (e: Exception) {
            platformLogWarn("VaultSelector", "enableDbKeyAuthBindingWithRecovery failed: ${e::class.simpleName}")
            return RecoveryEnableResult.Failed
        } finally {
            stretched.secureWipe()
            kek?.secureWipe(); inner?.secureWipe(); dbKey?.secureWipe()
            secret?.secureWipe()
        }
    }

    // Phase one's recovery-blob commit: ARM `vlt_rp` (read-back-gated) → P(`vlt_rc`)
    // → prove the stored blob reconstructs [dbKey] under [secret]; on a miss
    // R(`vlt_rc`) + disarm. True only when the recovery path is proven durable AND
    // correct, the precondition for ever holding an ab: blob. Marker BEFORE blob is
    // the deliberate inverse of the wipe anchors (see [armRecoveryEnablePending]).
    // NOT shared with [tryReEstablishLeverBAfterRecovery], which DISARMS the marker
    // before its re-mint on purpose — do not harmonise the two. A store exception
    // propagates to the caller's catch (Failed).
    private fun persistRecoveryBlobArmed(recoveryBlob: String, secret: ByteArray, dbKey: ByteArray): Boolean {
        if (!armRecoveryEnablePending()) {
            platformLogWarn("VaultSelector",
                "recovery-pending marker not durable — NOT minting a recovery blob (vault stays plain)")
            return false
        }
        store.putStringSync(VaultStoreKeys.RECOVERY_BLOB, recoveryBlob)
        if (!recoveryBlobReconstructsDbKey(secret, dbKey)) {
            platformLogWarn("VaultSelector",
                "recovery blob read-back verify failed — NOT enabling Lever B (vault stays plain)")
            store.remove(VaultStoreKeys.RECOVERY_BLOB)
            clearRecoveryEnablePending()   // nothing in flight any more
            return false
        }
        return true
    }

    /**
     * Read the persisted recovery blob back and confirm it decrypts — device layer
     * then code-KEK layer — to [expectedDbKey]. The brick-safety gate for arming
     * Lever B: the auth-bound key strict-invalidates on biometric re-enrollment, so
     * the ab: blob must never be committed until the recovery path (the ONLY way
     * back after an invalidation) is proven both DURABLE and CORRECT. Any miss —
     * absent/damaged blob, wrong dbKey, or a transient device-key outage — returns
     * false so the caller aborts with the vault still plain (never a brick). Never
     * throws; wipes its transient key material.
     */
    private fun recoveryBlobReconstructsDbKey(secret: ByteArray, expectedDbKey: ByteArray): Boolean {
        var recoveryOuter: ByteArray? = null
        var dbKey: ByteArray? = null
        return try {
            val blobB64 = store.getString(VaultStoreKeys.RECOVERY_BLOB) ?: return false
            recoveryOuter = codecs.openRecoveryDeviceLayer(blobB64)        // device layer off
            dbKey = codecs.openRecoveryCodeLayer(recoveryOuter, secret)    // code layer off
            dbKey.contentEquals(expectedDbKey)
        } catch (_: Exception) {
            false
        } finally {
            recoveryOuter?.secureWipe(); dbKey?.secureWipe()
        }
    }

    /**
     * Close the cracked-passcode door on UPGRADED installs: when unlock finds a
     * PRIVATE vault whose auth-bound key is the LEGACY WEAK scheme (device-passcode-
     * openable, no strict marker), re-mint it to the new strict biometric-only key —
     * IN PLACE, keeping the vault's data and the existing recovery blob (which wraps
     * the UNCHANGED stable dbKey, so it stays valid across the key swap). Runs after
     * the credential verified and [inner] (the PIN-KEK-wrapped dbKey) is in hand.
     *
     * SAFETY (never brick / never lock out):
     *  - Skips unless BIOMETRICS are available ([supportsAuthBinding]) — minting a
     *    biometric-only key on a device without biometrics would lock the user out.
     *    A passcode-only-PRIVATE user keeps their working legacy key; [needsLeverBReharden]
     *    signals the UI to offer re-harden / step-down.
     *  - Skips unless a recovery blob is PROVEN (opens under the device key) (Gen-A installs enabled Lever B before the
     *    recovery code existed) — that blob is the net for the delete-legacy → mint-strict
     *    window (same alias forces delete-before-mint). Without it we do NOT strict-
     *    invalidate; the legacy key keeps working and [needsLeverBReharden] prompts re-harden.
     *  - Best-effort: on any failure the CURRENT unlock still succeeds (dbKey in hand);
     *    a rare failure in the window leaves the vault recoverable via the (present)
     *    recovery code, never data loss. No biometric prompt (silent re-mint; the strict
     *    key's usability is netted by the recovery blob, exactly like an unverified enable
     *    would be).
     */
    private fun maybeReconcileLegacyAuthBoundKey(currentBlob: String, inner: ByteArray) {
        try {
            if (!dbKeyProtector.isAuthBoundBlob(currentBlob)) return   // plain vault — nothing to do
            if (isAuthBoundKeyStrict()) return                          // already strict
            if (!dbKeyProtector.supportsAuthBinding()) {
                platformLog("VaultSelector",
                    "legacy Lever B key kept — biometrics unavailable; UI to offer re-harden / step-down")
                return
            }
            // The net for the delete-legacy → mint-strict window has to be
            // a blob that really opens, not merely a key that exists — this window
            // is the one place the vault is momentarily wrapped by nothing at all.
            if (!recoveryBlobUsableAsNet(recoveryBlobState())) {
                platformLog("VaultSelector",
                    "legacy Lever B key kept — no PROVEN recovery code to guard the re-mint; UI to offer re-harden")
                return
            }
            // The next two lines delete the legacy
            // key and then commit the strict blob with a SINGLE-KEY write. A stale
            // iOS journal replaying the OLD `vlt_c` afterwards would leave a blob
            // wrapped by a key this call just destroyed — not a brick (the PROVEN
            // recovery blob checked above is the net, and it still opens the vault)
            // but it forces the user onto their recovery code for nothing. Checked
            // BEFORE the irreversible delete; refusing just keeps the legacy key and
            // the next unlock retries.
            if (!singleKeyDbKeyWriteAllowed(batchJournalPending())) {
                platformLog("VaultSelector",
                    "legacy Lever B key kept — a pending write-ahead journal could revert the re-mint; retried next unlock")
                return
            }
            dbKeyProtector.deleteAuthBoundKeyBeforeEnable()                // delete the legacy weak key
            // [inner] is re-wrapped VERBATIM, so the raw-key adoption mode tag inside it
            // (and K', when adopted) survives the re-mint unchanged.
            val strictBlob = dbKeyProtector.wrap(inner, authBound = true)   // mint strict key + wrap
            store.putStringSync(VaultStoreKeys.WRAPPED_DBKEY, strictBlob)
            markAuthBoundKeyStrict()
            platformLog("VaultSelector", "reconciled legacy Lever B key to strict biometric-only")
        } catch (e: Exception) {
            // The legacy key may already be deleted; the recovery blob (a precondition)
            // still opens the vault, and the current unlock already succeeded. No data loss.
            platformLogWarn("VaultSelector", "legacy Lever B reconcile failed (non-fatal): ${e::class.simpleName}")
        }
    }

    /**
     * Recover a vault whose Lever B hardware key has invalidated. Needs BOTH the
     * [recoveryCode] (decrypts the stable dbKey) AND the [credential] (to rebuild
     * the PIN-KEK wrap so ordinary unlock works again). On success the DB key is
     * re-wrapped PLAIN (Lever B off — the "re-provision, don't brick" floor) and the
     * vault opens; then [reconcileTierAfterRecovery] re-arms Lever B on a PRIVATE vault
     * whose device can still hardware-bind, re-minting `vlt_rc` under the SAME code
     * (which therefore stays valid). Only when that is impossible does the vault stay
     * plain with the code consumed; a later enable mints a fresh one. [UnlockResult.Denied] = bad code or wrong credential; [UnlockResult.Error]
     * = no recovery configured / transient / open failed. Call OFF the main thread.
     */
    fun recoverWithCode(recoveryCode: String, credential: String): UnlockResult {
        // Apply the same uniform rate-limit floor the
        // change-credential flow uses. This screen is the ONE credential sink with
        // no attempt budget of its own; the floor bounds an attacker who already
        // holds the (written-down) recovery code to ~1 PIN guess per changePinMinDelayMs
        // instead of raw-KDF speed. The wrong-attempt WIPE budget is enforced by the
        // callers (RecoveryEntryScreen / iOS recovery entry) against the same 24h
        // window counter the unlock screen uses — recovery has no headless caller.
        val start = TimeSource.Monotonic.markNow()
        try {
            return recoverWithCodeInner(recoveryCode, credential)
        } finally {
            enforceChangePinDelay(start)
        }
    }

    private fun recoverWithCodeInner(recoveryCode: String, credential: String): UnlockResult {
        val secret = Base32.decode(recoveryCode.trim()) ?: return UnlockResult.Denied
        if (secret.size != RECOVERY_SECRET_LENGTH) { secret.secureWipe(); return UnlockResult.Denied }
        var dbKey: ByteArray? = null
        try {
            // Device layer fails ⇒ Error (a forged / damaged blob is never a wrong
            // code); code layer fails ⇒ Denied. See [openRecoveryBlob].
            dbKey = when (val opened = openRecoveryBlob(secret)) {
                is RecoveryOpen.Stop -> return opened.result
                is RecoveryOpen.Ok -> opened.dbKey
            }

            // Verify the credential and rebuild the PIN-KEK wrap for future unlocks.
            val (matches, stretched, _) = try {
                evalCredential(credential)
            } catch (_: KeyUnavailableException) {
                return UnlockResult.Error
            }
            if (!matches || stretched == null) {
                stretched?.secureWipe()
                return UnlockResult.Denied
            }
            // Plain blob committed + `vlt_rc` deleted BEFORE the open — the ordering
            // that makes a failed open a usable plain vault, never a brick.
            val refused = try {
                commitPlainBlobThenDropRecovery(stretched, dbKey)
            } finally {
                stretched.secureWipe()
            }
            if (refused != null) return refused

            val vault = try {
                vaultFactory.create(dbKey, isProvision = false)   // PASSPHRASE mode with R
            } catch (_: Exception) {
                platformLogWarn("VaultSelector", "recovery open failed (transient)")
                return UnlockResult.Error
            }
            // The DB key was just re-wrapped PLAIN (Lever B off)
            // and the recovery blob consumed, but the persisted tier may still claim
            // PRIVATE (hardware-bound). Now that the vault is CONFIRMED open, reconcile
            // it — re-establish Lever B when the device still supports it, else record
            // the honestly-downgraded tier. Strictly AFTER the open and best-effort: it
            // never fails the successful recovery and never touches the commit-plain-
            // THEN-open ordering above that prevents bricking.
            reconcileTierAfterRecovery(dbKey, secret)
            return UnlockResult.Opened(vault)
        } finally {
            secret.secureWipe()
            dbKey?.secureWipe()
        }
    }

    // The recovery code's half of [recoverWithCodeInner]: read `vlt_rc`, then its two
    // layers as two SEPARATE calls, because they fail for opposite reasons and only
    // one of them is a guess. [Ok] = R (the caller wipes it); [Stop] = the result.
    private sealed class RecoveryOpen {
        class Ok(val dbKey: ByteArray) : RecoveryOpen()
        class Stop(val result: UnlockResult) : RecoveryOpen()
    }

    private fun openRecoveryBlob(secret: ByteArray): RecoveryOpen {
        val blobB64 = try {
            store.getString(VaultStoreKeys.RECOVERY_BLOB)
        } catch (_: KeyUnavailableException) {
            return RecoveryOpen.Stop(UnlockResult.Error)
        } ?: return RecoveryOpen.Stop(UnlockResult.Error)   // no recovery configured
        // The two layers are unwrapped in SEPARATE
        // try blocks because they fail for opposite reasons and only ONE of
        // them is a guess. The DEVICE layer failing means the stored blob is
        // not ours at all — a plant, or damage — which the user's code can
        // never fix, so reporting Denied there turned a forged `vlt_rc` into a
        // phantom recovery screen that spent the emergency-wipe budget one
        // attempt at a time. It is the neutral Error instead (both recovery
        // screens roll that back off the budget). Only the CODE layer's tag
        // miss is a wrong code.
        val outer = try {
            codecs.openRecoveryDeviceLayer(blobB64)                     // device layer off
        } catch (_: KeyUnavailableException) {
            return RecoveryOpen.Stop(UnlockResult.Error)
        } catch (_: KeyPermanentlyInvalidException) {
            return RecoveryOpen.Stop(UnlockResult.Error)
        } catch (_: Exception) {
            platformLogWarn("VaultSelector",
                "recovery blob is not ours (planted or damaged) — not counting this as a wrong code")
            return RecoveryOpen.Stop(UnlockResult.Error)
        }
        try {
            return try {
                RecoveryOpen.Ok(codecs.openRecoveryCodeLayer(outer, secret))   // code layer off → dbKey
            } catch (_: KeyUnavailableException) {
                RecoveryOpen.Stop(UnlockResult.Error)
            } catch (_: Exception) {
                RecoveryOpen.Stop(UnlockResult.Denied)    // wrong recovery code (AEAD tag miss)
            }
        } finally {
            outer.secureWipe()
        }
    }

    // The plain-blob commit of [recoverWithCodeInner], strictly BEFORE its vault
    // open: re-wrap R plain under [stretched]'s KEK, refuse while an iOS journal is
    // pending, P(`vlt_c`), PROVE it read back, and only then R(`vlt_rc`) R(`vlt_rp`)
    // R(`vlt_abk`). Null = committed (the caller opens); non-null = the neutral Error
    // to return with the recovery code KEPT. Does not wipe [stretched] (the caller
    // does); propagates a device-key exception from the seal exactly as before.
    private fun commitPlainBlobThenDropRecovery(stretched: ByteArray, dbKey: ByteArray): UnlockResult? {
        var kek: ByteArray? = null
        var payloadPlain: ByteArray? = null
        try {
            kek = codecs.dbKeyKek(stretched)
            // Raw-key adoption: `vlt_rc` wraps R only (the code is never persisted,
            // so it can never learn K'), and this path opens in PASSPHRASE mode with
            // R — so the blob it commits is the explicitly-tagged PASSPHRASE payload.
            // The next normal unlock re-adopts from the file's salt. Ordering below
            // (plain blob committed + `vlt_rc` deleted BEFORE the open) is unchanged.
            payloadPlain = encodeDbKeyPayload(dbKey, null)
            val plainBlob = codecs.sealDbKeyBlob(payloadPlain, kek, authBound = false)  // downgrade Lever B
            // Plain (working) blob committed FIRST, then the consumed recovery
            // blob removed — a failure between them leaves a usable plain vault +
            // a harmless stale recovery blob, never a bricked ab: blob.
            //
            // The ordering alone only covers PROCESS DEATH
            // between the two calls. It does not cover a SILENT write failure:
            // putStringSync returns Unit and iOS's actual returns without writing
            // when the keybag is locked, while remove() (a bare SecItemDelete,
            // no class key required) still succeeds — leaving the ab: blob,
            // wrapped by the very hardware key that just failed, with its only
            // recovery path deleted. Permanently unopenable. So read the plain
            // blob back BEFORE revoking the recovery code. This sits strictly
            // between the put and the remove and strictly before the vault open,
            // so the documented commit-plain-THEN-open ordering is unchanged.
            // The read-back below proves the Keychain
            // item CHANGED, not that it will STAY changed — a stale iOS
            // write-ahead journal replays its own `vlt_c` at the next
            // construction, which would restore the ab: blob over the `vlt_rc`
            // this path is about to delete. Refuse while one is pending (or
            // unreadable) and answer the same neutral Error the read-back failure
            // answers: nothing is written, the recovery blob is kept, the vault
            // is still openable by the very code just entered, and the journal
            // clears itself on the next launch.
            if (!singleKeyDbKeyWriteAllowed(batchJournalPending())) {
                platformLogWarn("VaultSelector",
                    "recovery deferred — a pending write-ahead journal could revert the DB-key blob; recovery code KEPT")
                return UnlockResult.Error
            }
            store.putStringSync(VaultStoreKeys.WRAPPED_DBKEY, plainBlob)
            if (!plainDbKeyCommitted()) {
                platformLogWarn("VaultSelector",
                    "recovery: plain DB-key blob did not read back — KEEPING the recovery code, not opening")
                // Neutral Error, never Denied: the recovery code AND the credential
                // both verified. Both recovery screens roll their pre-evaluation
                // attempt increment back off the wipe budget for Error, so this
                // costs the user nothing but a retry — and the retry still has a
                // recovery blob to work with.
                return UnlockResult.Error
            }
            store.remove(VaultStoreKeys.RECOVERY_BLOB)
            // The consumed recovery blob is gone, so any in-flight marker is
            // moot. Clearing it HERE (not later) also keeps the re-establish window
            // below marker-free — see tryReEstablishLeverBAfterRecovery.
            clearRecoveryEnablePending()
            clearAuthBoundKeyScheme()   // blob is plain again — drop the strict marker
            platformLog("VaultSelector", "vault recovered via recovery code — Lever B reset to plain")
            return null
        } finally {
            kek?.secureWipe(); payloadPlain?.secureWipe()
        }
    }

    /**
     * After a recovery-code unlock the DB key is wrapped PLAIN
     * (Lever B off) and the recovery blob is consumed, so the vault no longer has
     * the Lever B hardware barrier PRIVATE promises. Called once the vault is
     * confirmed open, this tries to make the hardware barrier real again:
     *
     *  - If the persisted tier does not claim Lever B (MAXIMUM's passphrase / CASUAL
     *    / a legacy-null tier), nothing is over-claimed — return.
     *  - Else, when the device still supports auth-binding, RE-ESTABLISH Lever B
     *    (re-wrap auth-bound + re-mint the recovery blob under the SAME code the user
     *    just used) — restoring the PRIVATE guarantee.
     *  - Otherwise (no secure lock / SE/StrongBox gone, or the round-trip verify
     *    fails) it does NOT relax the persisted tier. See below.
     *
     * KEY vs TIMER split: an earlier version persisted CASUAL here, but
     * CASUAL carries the GENTLEST auto-lock / inactivity-self-wipe / wrong-PIN timers
     * of any tier, so that silently loosened the anti-forensic windows the user chose
     * at PRIVATE. The lost hardware barrier is a KEY-binding fact, not a reason to
     * relax TIMERS — so on the unrestorable branch the PRIVATE timer tier is KEPT
     * ([protectionLevelForEnforcement] stays PRIVATE) and the plain-key state is
     * surfaced SEPARATELY and LIVE by [isDbKeyAuthBound]==false, which
     * [currentProtectionLevel]/[displayProtectionLevel] reflect on every read. That
     * live derivation also means this reconcile persists NOTHING on the unrestorable
     * branch, so an interrupt during the (already-completed) recovery — even mid
     * biometric round-trip in [tryReEstablishLeverBAfterRecovery] — can never strand
     * a false PRIVATE-over-plain claim: the display claim is recomputed from
     * the actual DB-key blob every time.
     *
     * Best-effort: the vault is already open, so any failure only logs — it never
     * bricks. MAXIMUM stays MAXIMUM because its guarantee is the ≥70-bit passphrase,
     * which recovery does not touch.
     */
    private fun reconcileTierAfterRecovery(dbKey: ByteArray, secret: ByteArray) {
        // Whole body best-effort: the vault is already open and about to be handed
        // back, so reconciliation must NEVER throw across the return (it would turn a
        // successful recovery into a crash / non-@Throws Swift SIGABRT).
        try {
            val claimsLeverB = try {
                protectionLevelOrNull() == ProtectionLevel.PRIVATE
            } catch (_: Exception) {
                false   // tier unreadable → can't confirm an over-claim; leave it alone
            }
            if (!claimsLeverB) return

            if (dbKeyProtector.supportsAuthBinding() && tryReEstablishLeverBAfterRecovery(dbKey, secret)) {
                return   // Lever B restored → PRIVATE is honest again
            }
            // The hardware barrier could not be restored. Do NOT persist CASUAL —
            // that would loosen the user's chosen PRIVATE timers. Keep the
            // PRIVATE timer tier; the missing barrier is reflected live via
            // isDbKeyAuthBound()==false (the DB key is plain), so nothing is
            // persisted here and no interrupt can strand a false claim.
            platformLog("VaultSelector",
                "recovery kept PRIVATE timers; Lever B not restorable — hardware claim reconciled live via isDbKeyAuthBound()")
        } catch (e: Exception) {
            platformLogWarn("VaultSelector", "post-recovery tier reconcile failed (non-fatal): ${e::class.simpleName}")
        }
    }

    /**
     * Re-arm Lever B for the just-recovered vault: re-wrap the (plain) DB key
     * auth-bound with the same round-trip verify [setDbKeyAuthBinding] uses (one
     * biometric prompt — the user is present, having just entered the code), and
     * re-mint the recovery blob under the SAME [secret], so the code they already
     * hold keeps working (an [UnlockResult] has no channel to surface a fresh code).
     * Two separate writes, in this order: the recovery blob first (read-back
     * verified), then the auth-bound blob as the final write — so a Lever B blob is
     * never committed without its recovery path. Returns true only when both
     * persist; false leaves the plain blob untouched (caller keeps the PRIVATE timer
     * tier; the plain key is reflected live via isDbKeyAuthBound).
     */
    private fun tryReEstablishLeverBAfterRecovery(dbKey: ByteArray, secret: ByteArray): Boolean {
        var inner: ByteArray? = null
        return try {
            val stored = store.getString(VaultStoreKeys.WRAPPED_DBKEY) ?: return false
            inner = dbKeyProtector.unwrap(stored)                 // plain blob → no prompt
            // Raw-key adoption: [inner] is the PASSPHRASE-tagged payload recoverWithCode
            // just committed and it is re-wrapped VERBATIM below, so the ab: blob agrees
            // with it on the mode (PASSPHRASE until the next unlock adopts); the re-minted
            // recovery blob wraps [dbKey] = R, the same key both blobs carry.
            // Fresh key on this plain → auth-bound re-establish (recoverWithCode wrote
            // plain first), same rationale as the enable path: a key invalidated by the
            // re-enrollment that triggered recovery must be re-minted, not reused.
            // delete → wrap → unwrap (PROMPTS once, round-trip verify).
            val authBoundBlob = codecs.wrapAuthBoundVerified(inner) ?: run {
                platformLogWarn("VaultSelector", "recovery Lever B re-establish round-trip failed — staying plain")
                return false
            }
            val recoveryBlob = codecs.sealRecoveryBlob(dbKey, secret)
            // Same brick-safety ordering as enableDbKeyAuthBindingWithRecoveryInner
            // (sibling sink to the ab: blob): commit + read-back-verify the re-minted
            // recovery blob under the SAME code BEFORE re-committing the auth-bound
            // blob. If the recovery path can't be proven durable, stay plain — the
            // vault is already open and recoverWithCode kept it working; the tier
            // reconcile then keeps PRIVATE timers with an honest CASUAL display.
            //
            // ABANDONED-ENABLE PURGE FALSE-FIRE EXCLUSION — this is the path that is the
            // reason a naive "plain blob + vlt_rc present" purge is UNSAFE. This
            // re-mint deliberately rewrites `vlt_rc` under the SAME code the user just
            // used, so the code they already hold keeps working, and two of its failure
            // modes (a silent kvPut no-op on the ab: commit below, or a throw) leave a
            // PLAIN blob beside a LIVE recovery blob permanently. The marker must
            // therefore be disarmed BEFORE the re-mint, so no interruption anywhere in
            // this window can present as an abandoned enable.
            //
            // Do NOT move this after the ab: commit below: the gap between the re-mint
            // and that commit is exactly the plain-blob + live-vlt_rc state, and an
            // armed marker across it would let the next unlock revoke a code the user
            // was explicitly told still works.
            clearRecoveryEnablePending()
            store.putStringSync(VaultStoreKeys.RECOVERY_BLOB, recoveryBlob)
            if (!recoveryBlobReconstructsDbKey(secret, dbKey)) {
                platformLogWarn("VaultSelector",
                    "recovery re-mint read-back verify failed — staying plain after recovery")
                store.remove(VaultStoreKeys.RECOVERY_BLOB)
                clearRecoveryEnablePending()   // belt-and-braces, nothing in flight
                return false
            }
            // Recovery proven durable → commit the auth-bound blob last (the
            // recovery blob above is the one that was read back). A failure here leaves the vault
            // plain (recoverWithCode already made it usable) with a verified recovery
            // orphan — the tier reconcile then keeps PRIVATE timers + honest CASUAL art.
            store.putStringSync(VaultStoreKeys.WRAPPED_DBKEY, authBoundBlob)
            markAuthBoundKeyStrict()   // the re-established key is the strict scheme
            platformLog("VaultSelector", "Lever B re-established after recovery — tier stays PRIVATE")
            true
        } catch (_: Exception) {
            platformLogWarn("VaultSelector", "recovery Lever B re-establish failed — staying plain, tier timers unchanged")
            false
        } finally {
            inner?.secureWipe()
        }
    }

    // -----------------------------------------------------------------------
    // SQLCipher key rotation on a credential tier upgrade
    //
    // The union invariant ({vlt_c, vlt_cn} always contains the key the file is on)
    // is stated on [VaultStoreKeys.PENDING_DBKEY]; everything below exists to keep it true at
    // every interruption point. Three rules run through all of it:
    //   • decide from PROBES / OPENS, never from a re-key return value;
    //   • "could not tell" and "did not work" are indistinguishable, so ambiguity
    //     always means CHANGE NOTHING and keep both records;
    //   • a promotion's `remove(vlt_cn)` may only follow a PROVEN `vlt_c` write.
    // -----------------------------------------------------------------------

    /**
     * Is a DB-key rotation record present? The cheap gate that keeps the steady
     * state (no rotation ever started) at ONE store lookup and zero extra opens.
     *
     * Fails toward `false` — "no rotation pending" — on any store fault. That is the
     * right direction at every call site: they use it to REFUSE work (a credential
     * change, a KDF migration, a Lever B enable) whose only hazard is re-wrapping
     * `vlt_c` under a new KEK while `vlt_cn` still holds the old one, and a transient
     * false `false` merely lets that pre-rotation behaviour happen once — never a wipe,
     * never a delete.
     */
    private fun rotationPending(): Boolean = try {
        store.contains(VaultStoreKeys.PENDING_DBKEY)
    } catch (_: Exception) {
        false
    }

    /**
     * Is this change a credential TIER UPGRADE — a vault that unlocks with a
     * 6-digit PIN moving to a Lever A passphrase (CASUAL/PRIVATE → MAXIMUM)? That is
     * the transition the DB-key rotation is about: the user has just made the credential
     * qualitatively stronger, so the archived weak-era wrap of the SQLCipher
     * passphrase is exactly what must stop working.
     *
     * Fails toward `false` (no rotation) on EVERY ambiguity, which is why it can
     * safely reuse [passphraseModeFromRead]'s fail-OPEN: an unauthenticated or
     * damaged `vlt_m` reads as "already a passphrase vault", i.e. not an upgrade, so a
     * plantable byte can at worst SUPPRESS a rotation — never provoke one. An ABSENT
     * marker is a genuine legacy PIN install and does count as an upgrade.
     */
    private fun isCredentialTierUpgrade(newMode: String?): Boolean {
        if (newMode != MODE_PASSPHRASE) return false
        return try {
            val read = readSelectorMetaRaw(VaultStoreKeys.CREDENTIAL_MODE)
            !passphraseModeFromRead(read?.value, read?.authenticated == true)
        } catch (_: Exception) {
            false
        }
    }

    /** Drop the pending-rotation record. Never throws; a leftover record is inert
     *  (the next unlock reconciles it by opening the file). */
    private fun removePendingRotation() {
        try {
            store.remove(VaultStoreKeys.PENDING_DBKEY)
        } catch (_: Exception) {
            platformLogWarn("VaultSelector", "pending-rotation record removal deferred — store unavailable")
        }
    }

    /**
     * Promote the pending record: copy `vlt_cn`'s bytes over `vlt_c`, PROVE the copy
     * landed, and only then drop `vlt_cn`.
     *
     * The read-back gate before the remove is the single most dangerous ordering in
     * this design and is mandatory. On iOS `kvPut` no-ops SILENTLY on a locked keybag
     * while `remove` is a bare `SecItemDelete` that needs no class key and succeeds
     * unconditionally — so a dropped promotion followed by a successful delete would
     * leave `vlt_c` holding the OLD key over a file that is on the NEW one, with the
     * only record of the new key deleted: a permanent brick. Unproven ⇒ keep BOTH
     * records (the union invariant holds) and let the next unlock retry.
     *
     * A pure byte copy: [VaultStoreKeys.PENDING_DBKEY] is written in the same wrap form as
     * [VaultStoreKeys.WRAPPED_DBKEY], so no key material, no device-key call and no biometric
     * prompt is involved.
     */
    private fun promotePendingRotation(): Boolean = try {
        val pending = store.getString(VaultStoreKeys.PENDING_DBKEY)
        if (pending == null) {
            false
        } else {
            store.putStringSync(VaultStoreKeys.WRAPPED_DBKEY, pending)
            // fail-direction: proof-required (`vlt_cn` is removed only after a proven copy).
            if (store.getString(VaultStoreKeys.WRAPPED_DBKEY) == pending) {
                store.remove(VaultStoreKeys.PENDING_DBKEY)
                true
            } else {
                platformLogWarn("VaultSelector",
                    "rotation promote did not read back — KEEPING both key records (retried next unlock)")
                false
            }
        }
    } catch (_: Exception) {
        platformLogWarn("VaultSelector", "rotation promote deferred — store unavailable (both key records kept)")
        false
    }

    /** A vault handle plus the SQLCipher key mode that actually opened it. */
    private class PayloadOpen(val vault: VaultDatabase, val viaPassphrase: Boolean)

    /**
     * Open the EXISTING vault with whatever [payload] offers, in [openModeOrder]:
     * an adopted RAW payload tries K' first and falls back to passphrase mode with R;
     * a PASSPHRASE payload (tagged or legacy) opens with R exactly as every unlock
     * did before raw-key adoption. Unlock semantics only — never provisions
     * (`isProvision = false`: no delete-and-recreate branch exists on either path).
     * Throws the LAST failure when no mode opens, so callers keep their existing
     * neutral-Error mapping. A raw-mode failure is logged (no key material) and
     * never surfaces on its own: it is not evidence of anything but "use R".
     */
    private fun openWithPayload(payload: DbKeyPayload): PayloadOpen {
        var last: Exception? = null
        for (mode in openModeOrder(payload.mode)) {
            try {
                return when (mode) {
                    DbKeyMode.RAW -> PayloadOpen(
                        vaultFactory.createWithRawKey(payload.rawKey ?: continue), viaPassphrase = false,
                    )
                    DbKeyMode.PASSPHRASE -> PayloadOpen(
                        vaultFactory.create(payload.dbKey, isProvision = false), viaPassphrase = true,
                    )
                }
            } catch (e: Exception) {
                last = e
                if (mode == DbKeyMode.RAW) {
                    platformLogWarn("VaultSelector",
                        "raw-key open failed — falling back to passphrase mode (${e::class.simpleName})")
                }
            }
        }
        throw last ?: IllegalStateException("no key mode to open the vault with")
    }

    /** [openWithPayload], or null if no mode opens. Never throws, never provisions. */
    private fun tryOpenPayload(payload: DbKeyPayload): PayloadOpen? = try {
        openWithPayload(payload)
    } catch (_: Exception) {
        null
    }

    /**
     * Does [payload]'s key open the existing file? Probes the modes it offers (raw
     * first, then R), so a RAW payload whose K' went stale still answers from R —
     * the rotation outcome must come from exact probes, never from a mode mismatch.
     */
    private fun probePayload(payload: DbKeyPayload): Boolean {
        val raw = payload.rawKey
        if (raw != null && (try { vaultFactory.probeRawKey(raw) } catch (_: Exception) { false })) return true
        return try { vaultFactory.probeKey(payload.dbKey) } catch (_: Exception) { false }
    }

    /**
     * Unwrap the pending-rotation record under the SAME [kek] the current one uses.
     * Returns null when nothing is pending or the record cannot be read — both of
     * which are handled as "no candidate key" by [reconcilePendingRotation], never as
     * a reason to delete anything. Never throws: this runs inside a successful unlock.
     */
    private fun readPendingRotationKey(kek: ByteArray): DbKeyPayload? = try {
        store.getString(VaultStoreKeys.PENDING_DBKEY)?.let { blob ->
            var pendingInner: ByteArray? = null
            try {
                pendingInner = dbKeyProtector.unwrap(blob)
                // Raw-key adoption: a pending record is a payload like `vlt_c` (always
                // PASSPHRASE — a re-key target is a fresh R). Malformed ⇒ no candidate.
                codecs.openDbKeyInner(pendingInner, kek)
            } finally {
                pendingInner?.secureWipe()
            }
        }
    } catch (_: Exception) {
        null
    }

    /** Outcome of the unlock-time reconcile: the handle that actually opened (null =
     *  neither key opened) and whether the PENDING key is the one that opened it. */
    private class RotationReconcile(
        val vault: VaultDatabase?,
        val promoted: Boolean,
    )

    /**
     * DB-key rotation unlock reconcile. Runs ONLY when [VaultStoreKeys.PENDING_DBKEY] is present, and
     * strictly BEFORE [migrateCredentialToCurrentKdf] — that migration re-wraps
     * `vlt_c` under a fresh KEK, which would leave `vlt_cn` unreadable and break the
     * union invariant while it still mattered.
     *
     * The order is the safety argument. `vlt_c` is tried FIRST because it is the
     * record every other path treats as authoritative; if it opens the file, the
     * rotation simply never landed and the pending record is dead weight. Only if it
     * does NOT open do we try the pending key — and the promotion happens strictly
     * AFTER that open succeeds, because the open is the only positive evidence about
     * which key the file holds. A crash between the open and the promotion is
     * harmless: both records survive and the next unlock repeats the same decision.
     *
     * Neither key opening returns a null handle, which the caller maps to the
     * existing neutral [UnlockResult.Error] — never [UnlockResult.Denied] (the
     * credential already verified), never a wipe, and never a `vlt_cn` removal.
     */
    private fun reconcilePendingRotation(
        currentPayload: DbKeyPayload,
        pendingPayload: DbKeyPayload?,
    ): RotationReconcile {
        // Raw-key adoption: each record is opened in EVERY mode it offers (its tagged
        // mode first). Only a record that opens in NO mode counts as "does not open" —
        // a stale K' must never be mistaken for "the file is not on this key", which
        // would promote `vlt_cn` over a file that is still on `vlt_c`'s key.
        tryOpenPayload(currentPayload)?.vault?.let { opened ->
            // The file is still on `vlt_c`'s key: the re-key never landed (or rolled
            // back). Dropping the pending record is safe on POSITIVE evidence only —
            // which this open is.
            removePendingRotation()
            platformLog("VaultSelector", "pending DB-key rotation discarded — the vault is still on the stored key")
            return RotationReconcile(opened, promoted = false)
        }
        if (pendingPayload == null) return RotationReconcile(null, promoted = false)
        val opened = tryOpenPayload(pendingPayload)?.vault
            ?: return RotationReconcile(null, promoted = false)
        promotePendingRotation()
        platformLog("VaultSelector", "pending DB-key rotation adopted — vault opened with the rotated key")
        return RotationReconcile(opened, promoted = true)
    }

    /**
     * Re-key the live vault to [newDbKey] after a credential tier upgrade has already
     * committed [pendingBlob] to [VaultStoreKeys.PENDING_DBKEY].
     *
     * Never reports failure upward: the user requested a CREDENTIAL change, that
     * change has landed, and turning a rotation that may well have succeeded into a
     * reported failure is the destructive direction (the caller would tell the user to
     * re-enter a credential that no longer opens the vault). Every branch here either
     * converges immediately or leaves a state the next unlock converges.
     */
    private fun rotateDbKeyAfterUpgrade(
        pendingBlob: String,
        newDbKey: ByteArray,
        oldPayload: DbKeyPayload,
    ) {
        // Durability gate. The re-key may only start once the NEW key is provably on
        // disk, or a crash straight after it would leave a file nothing can open.
        // (Android: the batch is one prefs commit() that rewrites the file whole, so
        // the record and the credential pair are durable together — the read-back sees
        // the in-memory map and catches nothing there, which is the same known
        // limitation [credentialWriteRefuted] documents. iOS: a real Keychain read, which does catch the
        // silent locked-keybag no-op.)
        val durable = try {
            store.getString(VaultStoreKeys.PENDING_DBKEY) == pendingBlob
        } catch (_: Exception) {
            false
        }
        if (!durable) {
            platformLogWarn("VaultSelector",
                "DB-key rotation skipped — the pending record is not provably durable")
            removePendingRotation()
            return
        }
        // Re-read the handle: it is owned elsewhere and an auto-lock could have closed
        // it since the pre-flight check. No handle ⇒ nothing was re-keyed, so the
        // record is simply dropped.
        val vault = vaultProvider()
        if (vault == null) {
            platformLogWarn("VaultSelector", "DB-key rotation skipped — no live vault handle")
            removePendingRotation()
            return
        }
        // No attempt is made to quiesce anything. On Android the connection pool nulls
        // the primary connection while a statement is in flight, so a concurrent poll
        // makes changePassword throw AFTER the library restored the old password — a
        // loud, retryable, NON-destructive `false`. Skipping and retrying on a later
        // credential change is the correct response; the probes below decide either way.
        val rekeyOk = vault.rekey(newDbKey)
        // The decision comes from the PROBES, never from rekeyOk: sqlite3_rekey_v2
        // returns SQLITE_OK on both its commit and its rollback branch.
        // Modes (raw-key adoption): the re-key TARGET is always passphrase mode —
        // `rekey` hands SQLCipher the raw 32 new bytes, which it stretches with the
        // file's (unchanged) salt, whether the live handle was opened with R or with
        // an adopted K' (RawKeyAdoptionTest proves the raw-handle case) — so the new
        // key is probed in passphrase mode and its `vlt_cn` record is a PASSPHRASE
        // payload; it is re-adopted on the first unlock after the rotation resolves.
        // The OLD key is probed in every mode its payload offers ([probePayload]).
        val newOpens = try { vaultFactory.probeKey(newDbKey) } catch (_: Exception) { false }
        val oldOpens = probePayload(oldPayload)
        val outcome = rotationOutcomeFromProbes(newKeyOpens = newOpens, oldKeyOpens = oldOpens)
        when (outcome) {
            RotationOutcome.PROMOTE -> {
                promotePendingRotation()
                platformLog("VaultSelector", "vault DB key rotated on credential upgrade")
            }
            RotationOutcome.DROP_PENDING -> {
                // Deliberately NOT removePendingRotation() here, even though the probes
                // say the file is still on the old key. sqlite3_rekey_v2 returns
                // SQLITE_OK on its ROLLBACK branch too, and on that branch it has
                // already installed the new key in the codec's WRITE context of this
                // still-live handle without ever undoing it (see the comment in
                // SwiftDatabaseBridge.rekey). So a rolled-back re-key leaves a handle
                // that writes new-key pages onto an old-key file — page 1 goes on the
                // next commit — and vlt_cn is then the ONLY surviving record of the key
                // those pages are under (the local copy is secureWipe'd on the way out).
                // Dropping it here would move the file to a key that exists nowhere:
                // permanent, total data loss. Keep both records and let the unlock
                // reconcile decide on positive evidence — it drops the record when
                // vlt_c opens the file, and promotes when vlt_cn does, so the rollback
                // case still converges. The poisoned handle itself is RETIRED below
                // so no later commit can produce the mixed-key file. The kept
                // records cover a crash anywhere before the
                // close, and a rekey that silently landed whole. Costs one deferral
                // cycle, which the design already treats as benign.
                platformLogWarn("VaultSelector",
                    "DB-key rotation rolled back (rekeyOk=$rekeyOk) — both key records kept for the unlock reconcile")
            }
            RotationOutcome.LEAVE_PENDING -> {
                // Both probes agreed, so nothing is known. Keeping the old key over an
                // already-rotated file is a brick, so change NOTHING: the union
                // invariant still holds and the next unlock resolves it by opening.
                platformLogWarn("VaultSelector",
                    "DB-key rotation outcome undetermined (rekeyOk=$rekeyOk) — both key records kept for the unlock reconcile")
            }
        }
        // [VaultDatabase.rekey]'s kdoc contract, which this
        // caller previously ignored: a handle whose re-key did not verifiably commit
        // must never serve another write (see [rekeyOutcomeKeepsLiveHandle] for the
        // per-outcome argument). The record handling above is untouched by this —
        // nothing is written and nothing is removed here, so the union invariant
        // holds exactly as before.
        if (!rekeyOutcomeKeepsLiveHandle(outcome)) retireRekeyedVaultHandle(vault)
    }

    /**
     * Close a live handle whose re-key did not verifiably commit, then tell the
     * session owner to fall back to the LOCKED state ([onRekeyHandleRetired]).
     *
     * The close is SYNCHRONOUS and happens here, in commonMain, so the guarantee
     * does not depend on the injected callback being wired or scheduled: from the
     * moment this returns, no write can reach the file through the poisoned codec
     * context. Both platforms tolerate the shared handle closing under a
     * concurrent poller — Android's pool makes later statements throw an
     * `IllegalStateException` the per-cycle poll catches (the same exposure every
     * existing teardown path already has), and iOS serialises `close()` on the
     * `IosVaultDatabase` lock while a closed bridge reports reads as empty and
     * writes as a caught failure. Loud and non-destructive, never a poisoned page.
     *
     * Neither the close nor the callback may throw upward: this runs strictly
     * after the credential change LANDED, and an escaping exception would be
     * reported to the user as a failure of a change that already works (the
     * false-FAILURE hazard [credentialWriteRefuted] describes).
     */
    private fun retireRekeyedVaultHandle(vault: VaultDatabase) {
        try {
            vault.close()
        } catch (_: Exception) {
            // Best-effort by contract — both actuals already swallow close errors.
        }
        platformLogWarn("VaultSelector",
            "live vault handle retired — re-key did not verifiably commit; session must re-lock " +
                "(recovered by the next unlock's rotation reconcile)")
        try {
            onRekeyHandleRetired()
        } catch (_: Exception) {
            // The callback crosses into platform session/UI code; its failure must
            // not turn a landed credential change into a reported error.
        }
    }

    /**
     * Provision the vault: derive one Argon2id (KDF v3) [stretched] from the PIN, store
     * the (device-AEAD-wrapped) credential verifier, generate + wrap the
     * random SQLCipher passphrase, and materialize the encrypted DB file. Run
     * synchronously from credential setup — the only point the PIN is known —
     * so the vault file exists before setup completes.
     *
     * The verifier and the DB-key KEK are independent one-way functions of
     * [stretched] (distinct labels), so the stored verifier never yields the
     * KEK; recovering the DB key always requires the PIN (CR-1).
     */
    private fun provisionCredentialAndVault(
        credential: String,
        passphraseMode: Boolean,
        level: ProtectionLevel?,
    ) {
        // ---------------------------------------------------------------------
        // PROVISION GUARD — refuse to provision on top of an existing vault file.
        //
        // Everything below this line is destructive to a vault that already
        // exists: the credential + db-key blobs are overwritten with freshly
        // generated ones, and `vaultFactory.create(isProvision = true)` opens
        // run.db with the NEW key, so the OLD file reads as SQLITE_NOTADB and
        // both platforms' isProvision+NOTADB branch deletes it (DatabaseManager
        // / IosVaultDatabase). That is correct for a genuinely legacy or
        // corrupt-header file at first run, and catastrophic for a live vault —
        // and at that point the two are indistinguishable, because a live vault
        // keyed with the old key and a corrupt header BOTH surface as NOTADB.
        //
        // The missing precondition is "did we expect a vault to be here?".
        // isConfigured() cannot answer it: it reads the KeyValueStore, and a bad
        // read of that store is the thing that routes a provisioned install into
        // first-run setup in the first place (and the
        // reason isConfigured() fails toward true — see the internals doc). The
        // filesystem is an INDEPENDENT witness with a different failure mode, so
        // it is what the guard asks.
        //
        // This defends every route into setup — the transient not-configured
        // read, a wipe that half-completed, a future routing bug — not just the
        // one transient we happen to know about. A legitimate re-provision is
        // unaffected: WipeRoutine / the iOS wipe delete run.db, so after a real
        // wipe the file is gone and this passes. It trips ONLY when credential
        // state says "fresh install" while a vault file is sitting right there,
        // which is exactly the state that used to cost the user everything.
        // ---------------------------------------------------------------------
        if (vaultFactory.vaultFileExists()) {
            platformLogWarn(
                "VaultSelector",
                "provision REFUSED — a vault database already exists. Credential state read as " +
                    "unconfigured, but the vault file is present: provisioning would destroy it."
            )
            throw ExistingVaultException()
        }
        // Mode + tier blobs for THIS provision, sealed BEFORE the vault file exists so
        // a device-key outage aborts with nothing created — see [sealProvisionMeta].
        val meta = sealProvisionMeta(passphraseMode, level)
        // A null level still REMOVES the key (a removal cannot ride in a put batch,
        // and it is the legacy setRealCredential path that has no tier to claim).
        if (meta.levelBlob == null) store.remove(VaultStoreKeys.PROTECTION_LEVEL)
        val salt = generateSecureRandom(SALT_LENGTH)
        val pwBytes = credential.encodeToByteArray()
        val stretched = stretchCurrent(pwBytes, salt)   // Argon2id (v3)
        pwBytes.secureWipe()  // zero the transient PIN-bytes copy
        val dbKey = generateSecureRandom(DBKEY_LENGTH)
        // Hold kek so the finally can wipe it — with the inner ciphertext (wiped
        // inside [VaultBlobCodecs.sealDbKeyBlob]) it reconstructs dbKey without the
        // PIN or device key.
        var kek: ByteArray? = null
        var rawKey: ByteArray? = null
        var payloadPlain: ByteArray? = null
        try {
            // Materialize the DB file BEFORE persisting the credential
            // and db-key blobs, so `configured` (both blobs present) ALWAYS implies
            // the DB file exists. Previously the file was created LAST, so a process
            // death after the blobs were written but before the file was materialized
            // left configured=true + credentialsReadable=true + DB-absent — which the
            // missing-DB guard turns into a PERMANENT UnlockResult.Error
            // with no recovery (creds ARE readable, so neither the orphan self-heal
            // nor the 7-day check clears them). Creating the file first closes that
            // window without weakening that guard: an EXTERNAL later deletion of run.db still
            // hits the fail-closed guard, but a legitimate provision can no longer
            // strand itself. Constructor opens (creating if absent) the SQLCipher file
            // with this passphrase; we only need it materialized, so close immediately
            // (leaving it open leaks a SQLCipher handle and collides with the later
            // unlock-time open). isProvision=true so a pre-existing "not a database"
            // file may be recreated (no real data exists yet); unlock passes false
            // (fail closed). If this throws, NO credential blob is written below, and
            // the provision rollback removes whatever file the failed create left → the
            // next launch sees a genuinely clean slate, not a stuck Error.
            vaultFactory.create(dbKey, isProvision = true).close()
            // Raw-key adoption (2026-10-07): new Android vaults are raw-key from day
            // one. The create above IS the passphrase-mode open that proves R is the
            // file's key; K' is kept only if it then opens the file too. Null (iOS, or
            // any failure) ⇒ a PASSPHRASE payload, adopted by the first unlock.
            rawKey = adoptRawKeyAtProvision(dbKey)

            val credBlob = codecs.sealCredentialVerifier(stretched, salt)

            kek = codecs.dbKeyKek(stretched)
            payloadPlain = encodeDbKeyPayload(dbKey, rawKey)
            // First-run setup always provisions the plain (non-auth-bound) outer
            // layer — enabling Lever B is an explicit opt-in from Settings, so
            // first run never prompts for a biometric.
            val dbBlob = codecs.sealDbKeyBlob(payloadPlain, kek, authBound = false)

            // ONE journalled batch, then a READ-BACK GATE.
            //
            // `vlt_a` + `vlt_c` are a COUPLED pair — the same coupling that forces
            // change-PIN, the KDF migration, the legacy key-name migration and the
            // Lever-B finalize through [KeyValueStore.putStringsSync] — and this was
            // the last credential-path site still issuing them as two independent,
            // unverified writes. It is also the one that shipped the field bug: on
            // iOS `kvPut` returns WITHOUT writing on a locked keybag (a fail-closed
            // strict `WhenPasscodeSet` add whose `AfterFirstUnlock` fallback is
            // skipped when the passcode probe flakes), so `vlt_a` could land while
            // `vlt_c` was dropped. The next launch reads hasCreds && !hasDbKeys →
            // [purgeHalfCredentialPairIfNeeded] clears the whole credential set → isConfigured()
            // false → first-run setup AGAIN, forever, over a `run.db` this call
            // already materialised. `vlt_m` and `vlt_lvl` join them for the reasons
            // given where they were sealed above — each has its own silent-drop loop.
            //
            // Batching makes Android atomic (one editor commit instead of four) and
            // iOS journalled+replayable; the read-back is what turns a silent drop
            // into a reported, retryable failure instead of a "successful" provision
            // nobody can unlock. All-or-nothing is deliberate: a provision that
            // cannot prove every value landed is rolled back whole, because at THIS
            // moment there is nothing to lose — no contacts, no messages, no key
            // anyone else holds — and one retry is cheaper than any of the permanent
            // states a partial provision produces.
            val batch = buildMap {
                put(VaultStoreKeys.CREDENTIAL_VERIFIER, credBlob)
                put(VaultStoreKeys.WRAPPED_DBKEY, dbBlob)
                put(VaultStoreKeys.CREDENTIAL_MODE, meta.modeBlob)
                meta.levelBlob?.let { put(VaultStoreKeys.PROTECTION_LEVEL, it) }
            }
            store.putStringsSync(batch)
            // fail-direction: proof-required (an unproven provision fails and rolls back).
            if (!storeWriteProven(batch) { store.getString(it) }) {
                throw ProvisionNotPersistedException()
            }
        } catch (e: Exception) {
            // ANY failure after the guard — a dropped credential write,
            // a device-key outage inside crypto.seal, a SQLCipher fault, a partial
            // `create` — leaves this provision half-done, and half-done is the state
            // that strands the install. Undo it so the retry starts clean.
            //
            // Why this matters more than the read-back alone: the app's ROUTING is an
            // OR-gate (`isConfigured() || vaultFileExists()` — MainActivity's
            // startDestination / AppState.vaultPresent), so a leftover `run.db` with no
            // credential behind it sends the user to the UNLOCK screen on every future
            // launch — a prompt that rejects every entry, whose only way out is the
            // explicit "Erase and start over" the unlock screens offer
            // (orphanedVaultFile / erase_orphaned_vault_button). That escape hatch is
            // the right backstop for a genuinely ambiguous file, but landing an honest
            // first-run user there because OUR write failed is the bug. Rolling back
            // here is what keeps them out of it: no residue, no guard trip, just a
            // retryable "setup failed".
            rollBackFailedProvision(e)
            throw e
        } finally {
            stretched.secureWipe()
            dbKey.secureWipe()
            kek?.secureWipe()
            rawKey?.secureWipe()
            payloadPlain?.secureWipe()
        }
    }

    // The two selector-meta blobs a provision persists in its one credential batch.
    // [levelBlob] is null for the legacy level-less provision.
    private class ProvisionMeta(val modeBlob: String, val levelBlob: String?)

    // Seal the provision's `vlt_m` and (when chosen) `vlt_lvl` blobs — mode first,
    // then tier, the order they were always sealed in. Throws whatever the device
    // key throws (KeyUnavailableException ⇒ the caller's selectorWriteGuard ⇒ a
    // retryable false). Writes nothing.
    //
    // Set the credential mode + chosen level for THIS provision. A passphrase
    // level (MAXIMUM) writes MODE_PASSPHRASE so the lock screen renders the text
    // field; a PIN level writes MODE_PIN. We ALWAYS write vlt_m (never
    // remove it) so its presence/absence can't leak the mode with no device key.
    // Writing MODE_PIN also overwrites any leftover MODE_PASSPHRASE
    // from an interrupted wipe, so the entry UI can't disagree with the freshly
    // provisioned credential. The level (when chosen) drives the per-level
    // auto-lock / self-wipe thresholds; a null level (legacy setRealCredential)
    // clears it so those sites keep the current constants. Lever B stays an
    // opt-in post-unlock step (enableDbKeyAuthBindingWithRecovery) — first run
    // never prompts for a biometric here.
    //
    // SEALED HERE, PERSISTED WITH THE CREDENTIAL PAIR.
    // The blobs are computed BEFORE the vault file is created (so a device-key
    // outage still aborts with nothing created, exactly as before) but the writes now
    // join provisionCredentialAndVault's one verified batch instead of being two unverified
    // `putString`s. Both had a silent-drop failure mode of their own, and both
    // are the loop the field reports describe:
    //   • a dropped `vlt_lvl` reads as "no tier ever chosen", which is precisely
    //     what the one-time chooser and the forced-migration route trip on — so
    //     the user meets the protection chooser on EVERY unlock, forever.
    //   • a dropped `vlt_m` reads as PIN mode, which on a MAXIMUM/passphrase
    //     vault renders the 6-digit keypad: Lever A's ≥70-bit floor guarantees
    //     the real credential is not six digits, so every auto-submitted entry
    //     is durably counted and MAXIMUM's budget of 5 emergency-wipes a vault
    //     that has no recovery code (the planted-`pin` destruction path, reached by accident
    //     rather than by a plant).
    private fun sealProvisionMeta(passphraseMode: Boolean, level: ProtectionLevel?): ProvisionMeta {
        val modeBlob = encryptSelectorMeta(
            VaultStoreKeys.CREDENTIAL_MODE, if (passphraseMode) MODE_PASSPHRASE else MODE_PIN
        )
        val levelBlob = level?.let { encryptSelectorMeta(VaultStoreKeys.PROTECTION_LEVEL, it.storageValue) }
        return ProvisionMeta(modeBlob, levelBlob)
    }

    /**
     * Undo a provision that failed after the guard — the credential
     * batch could not be PROVEN to have persisted, or anything else threw — so the
     * retry the UI offers starts from a genuinely clean slate rather than tripping
     * the provision guard on the half-state this call left behind.
     *
     * **Deleting a vault database file is otherwise forbidden in this class**, and
     * the narrow reason it is correct HERE — and nowhere else — is worth stating
     * exactly, because the next reader will (rightly) flinch at it:
     *
     *  - the provision guard proved `vaultFileExists() == false` at the top of THIS
     *    invocation, moments ago and in this same call stack;
     *  - so the only thing that can be at that path is the file
     *    `vaultFactory.create(dbKey, isProvision = true)` created (or partially
     *    created) a few lines up, keyed with a passphrase that has existed only in
     *    this function's locals — and is `secureWipe`d in the `finally` that is
     *    about to run;
     *  - it therefore contains ZERO user data — no contacts, no messages, no
     *    pairings — and nothing that survives can ever open it.
     *
     * The same argument licenses the two credential removes: reaching a provision at
     * all means the UI routed to first-run setup, i.e. `isConfigured()` (both blobs
     * present) was false, so at most ONE of `vlt_a`/`vlt_c` predated this call — a
     * lone half that opens nothing and that [purgeHalfCredentialPairIfNeeded] already deletes on
     * sight.
     *
     * Every other "vault file present, credential absent" state in the app is
     * genuinely ambiguous between that and a REAL vault whose credential is
     * transiently unreadable, which is precisely why the guard leaves it alone and
     * routes to the unlock screen's explicit, user-confirmed "Erase and start
     * over" instead of resolving it destructively. Do not generalise this helper,
     * and do not call it from anywhere else.
     *
     * Removals are ISSUED best-effort — they are the direction that does not fail
     * silently on a locked iOS keybag (`kvRemove` is a bare `SecItemDelete`, which
     * needs no class key, while `kvPut` no-ops) — but the FILE DELETE is not
     * best-effort at all: it is gated on [mayDeleteVaultFileAfterRollback] PROVING
     * every [VaultWriteProofs.PROVISION_FILE_DELETE_BLOCKERS] key gone. `kvRemove` discards its
     * `OSStatus`, so "removals are reliable" is an argument, not evidence, and the
     * state a wrong bet produces here is the one dead end the app cannot escape
     * (configured-without-a-database — see that list's kdoc). Order therefore
     * matters twice over: the journal is dropped FIRST so nothing can replay the
     * pair back, and the file is unlinked LAST and only on proof.
     *
     * Every other partial outcome lands somewhere the app already handles safely —
     * see [PROVISION_ROLLBACK_KEYS] for the per-interruption-point enumeration — so
     * nothing here may throw over the [ProvisionNotPersistedException] the caller
     * is about to raise.
     */
    private fun rollBackFailedProvision(cause: Exception) {
        val reason = if (cause is ProvisionNotPersistedException)
            "the credential pair did not read back" else "failed (${cause::class.simpleName})"
        platformLogWarn(
            "VaultSelector",
            "provision $reason — rolling back (dropping both credential blobs and any pending " +
                "write-ahead journal, then the just-created vault file IF the store is proven " +
                "clean) so the retry starts clean."
        )
        for (key in PROVISION_ROLLBACK_KEYS) {
            try {
                store.remove(key)
            } catch (_: Exception) {
                platformLogWarn("VaultSelector", "provision rollback: could not remove $key")
            }
        }
        // CONDITIONAL, and the dependency runs the other way from the intuition:
        // the file may only go once the STORE is proven clean, because a surviving
        // credential record — or a surviving journal that replays one back at the
        // next KeyValueStore construction — over a DELETED run.db is
        // configured-without-a-database: permanent non-counting UnlockResult.Error
        // on every unlock, and orphanedVaultFile() (file present + creds absent) is
        // the exact inverse, so the erase hatch never appears either. Leaving the
        // file is the safe side of that bet: it holds nothing, and the state
        // degrades to a working vault (full journal replay) or to
        // orphanedVaultFile() and its confirmed "Erase and start over".
        val storeProvenClean = mayDeleteVaultFileAfterRollback { store.contains(it) }
        if (!storeProvenClean) {
            platformLogWarn(
                "VaultSelector",
                "provision rollback: a credential record or the write-ahead journal could not be " +
                    "PROVEN gone — KEEPING the fresh vault file, so the worst case is the unlock " +
                    "screen's erase offer rather than a configured vault with no database."
            )
            return
        }
        try {
            vaultFactory.deleteVaultFileAfterFailedProvision()
        } catch (_: Exception) {
            // A surviving file is NOT a data-loss state (it holds nothing) and it is
            // not a brick: the credential records are already PROVEN gone, so the next
            // launch reports orphanedVaultFile() and the unlock screen offers the
            // confirmed erase. Never let it mask the provisioning failure.
            platformLogWarn("VaultSelector", "provision rollback: could not delete the fresh vault file")
        }
    }

    // -----------------------------------------------------------------------
    // Credential change (PIN rotation)
    // -----------------------------------------------------------------------

    enum class ChangePinResult {
        /** The current PIN was accepted and the PIN was rotated. */
        SUCCESS,
        /**
         * [currentCredential] did not unlock the vault — OR the change was DEFERRED
         * with nothing changed. The name is kept (it crosses IosAppController's
         * string bridge, where anything unknown collapses to `wrongCurrent`), but
         * the code means "nothing changed, retry". Returned for exactly these causes:
         *  1. a DB-key rotation (`vlt_cn`) is still pending;
         *  2. the device key is unavailable while verifying the current credential;
         *  3. the current credential really did not match;
         *  4. the store is unreadable, or `vlt_c` is absent;
         *  5. the current DB-key blob failed to unwrap / decode;
         *  6. the credential batch's read-back REFUTED the write;
         *  7. the device key vanished during the re-wrap (nothing persisted).
         * Change-PIN never wipes, so every one of these is benign; the user retries.
         * A separate DEFERRED case is plan-only (it would cross the string bridge).
         */
        WRONG_CURRENT,
        /**
         * The new credential is a passphrase below the Lever A entropy floor
         * ([CredentialPolicy.meetsFloor]). The shipped UIs already gate the submit
         * button on the floor, so this only trips a non-UI / future caller — but
         * the ≥70-bit guarantee is enforced HERE too so it can't be
         * defeated by an alternate caller. Swift maps any non-"success" code to
         * wrongCurrent, so no Swift outcome case is required.
         */
        WEAK_CREDENTIAL
    }

    /**
     * Minimum wall-clock duration (ms) enforced on every change-PIN credential
     * operation ([verifyCredential] / [changeCredential]). Defense-in-depth: the
     * flow is intentionally exempt from the unlock-screen auto-wipe (the user is
     * already authenticated inside the vault), which would otherwise make it a
     * penalty-free channel for an attacker to probe candidate PINs. A uniform
     * floor rate-limits that probing without ever wiping legitimate data.
     * Mutable ONLY so tests can set it to 0 (the instrumented VaultSelectorTest
     * lives in the androidApp module, so it cannot reach an `internal` member of
     * :shared — hence left public, Kotlin's default visibility, here). Production
     * never reassigns it.
     */
    var changePinMinDelayMs: Long = 5_000L

    /**
     * Side-effect-free credential check: evaluates the candidate against the
     * stored credential (constant-time) and wipes the derived material. Unlike
     * [unlock] it never opens the vault. The change-PIN UI uses this to confirm
     * the current PIN before prompting for a new one, without the cost/side-
     * effects of a full unlock.
     */
    fun verifyCredential(credential: String): Boolean {
        val start = TimeSource.Monotonic.markNow()
        try {
            return verifyCredentialInner(credential)
        } finally {
            enforceChangePinDelay(start)
        }
    }

    private fun verifyCredentialInner(credential: String): Boolean {
        val (matches, stretched, _) = try {
            evalCredential(credential)
        } catch (_: KeyUnavailableException) {
            // Cannot decide during a transient key outage. Report "not verified"
            // (benign false-negative — this change-PIN gate never wipes; the user
            // retries once the key returns) rather than letting the exception
            // cross into the caller.
            platformLogWarn("VaultSelector", "verifyCredential deferred — device key unavailable")
            return false
        }
        stretched?.secureWipe()
        return matches
    }

    /**
     * Sleep until at least [changePinMinDelayMs] has elapsed since [start].
     * Applied uniformly to BOTH outcomes of every change-PIN credential op so the
     * duration leaks nothing about the result (it is not a timing oracle) while
     * still rate-limiting an attacker probing PINs through the change-PIN flow.
     * Runs on the caller's (off-main) thread.
     *
     * Measured with a MONOTONIC clock, not the wall clock. A
     * forward wall-clock jump during the op made (now - start) large → a negative
     * sleep → the floor was skipped, letting an attacker inside an unlocked vault
     * probe PINs with no rate limit. A monotonic mark can't be jumped.
     */
    private fun enforceChangePinDelay(start: TimeMark) {
        sleepMillis(changePinMinDelayMs - start.elapsedNow().inWholeMilliseconds)
    }

    /**
     * Rotate the vault PIN, keeping the vault's data. The random SQLCipher
     * passphrase is NOT regenerated: it is unwrapped with the current PIN's KEK
     * and re-wrapped under the new PIN's KEK, while a fresh credential verifier
     * (new salt) replaces the old one.
     *
     * The new verifier and the re-wrapped DB key are persisted in a SINGLE
     * atomic store write ([KeyValueStore.putStringsSync]); an interrupt mid-
     * rotation can therefore never leave a credential whose KEK no longer
     * unwraps the DB key (which would brick the vault). Heavy (two KDF derivations — Argon2id for the new credential) —
     * call off the main thread.
     */
    fun changeCredential(currentCredential: String, newCredential: String): ChangePinResult {
        val start = TimeSource.Monotonic.markNow()
        try {
            return changeCredentialInner(currentCredential, newCredential, newMode = null)
        } finally {
            enforceChangePinDelay(start)
        }
    }

    /**
     * [changeCredential] that also switches the credential MODE (PIN ↔
     * passphrase, Lever A). The mode flag is written in the
     * SAME atomic batch as the new verifier + re-wrapped DB key, so an
     * interrupt can never leave the entry UI (keypad vs text field)
     * disagreeing with the stored credential. Callers enforce the passphrase
     * entropy floor ([CredentialPolicy.meetsFloor]) and the
     * downgrade warning BEFORE calling; this only rotates.
     */
    fun changeCredentialAndMode(
        currentCredential: String,
        newCredential: String,
        newModePassphrase: Boolean,
    ): ChangePinResult {
        val start = TimeSource.Monotonic.markNow()
        try {
            return changeCredentialInner(
                currentCredential, newCredential,
                newMode = if (newModePassphrase) MODE_PASSPHRASE else MODE_PIN,
            )
        } finally {
            enforceChangePinDelay(start)
        }
    }

    private fun changeCredentialInner(
        currentCredential: String,
        newCredential: String,
        newMode: String?,
    ): ChangePinResult {
        // Refuse (benignly) while a DB-key rotation is unresolved, BEFORE
        // touching any state. A credential change re-wraps `vlt_c` under a fresh KEK;
        // `vlt_cn` is wrapped under the OLD one, so proceeding would make the pending
        // record unreadable — and if the file happens to be on THAT key, the union
        // invariant breaks and the vault is lost. WRONG_CURRENT is this flow's
        // established "nothing changed, retry" code (see the read-back refutation branch below for why
        // no new enum case is added). Self-clearing: the very next unlock reconciles
        // the record by opening the file.
        if (rotationPending()) {
            platformLogWarn("VaultSelector",
                "changeCredential deferred — a DB-key rotation is still pending (resolved on the next unlock)")
            return ChangePinResult.WRONG_CURRENT
        }
        // A PIN rotation re-wraps the inner PIN-KEK layer, so any auth-bound blob
        // PREPARED (but not yet finalized) wraps a now-stale inner. Drop it so a later
        // finalize can never commit a blob that no longer unwraps under the new PIN.
        // NOTE the ordering: this runs BEFORE the current-credential check, so a
        // WRONG-PIN change attempt also drops a prepared Lever B enable (the user
        // re-runs the enable). Harmless — the vault stays plain and openable, and an
        // armed `vlt_rp` marker still lets the next unlock purge the orphan `vlt_rc`.
        // Moving it after the match is plan-only (P-7).
        pendingAuthBoundBlob = null
        pendingAuthBoundBase = null
        val (matches, stretched, _) = try {
            evalCredential(currentCredential)
        } catch (_: KeyUnavailableException) {
            // Device key transiently unavailable — cannot verify the current PIN.
            // Report WRONG_CURRENT (benign: change-PIN never wipes, the user
            // retries once the key returns) rather than propagating.
            platformLogWarn("VaultSelector", "changeCredential deferred — device key unavailable")
            return ChangePinResult.WRONG_CURRENT
        }
        if (!matches || stretched == null) {
            stretched?.secureWipe()
            platformLogWarn("VaultSelector", "changeCredential denied — wrong current PIN")
            return ChangePinResult.WRONG_CURRENT
        }

        // Enforce the Lever A ≥70-bit passphrase floor at the
        // shared API boundary — the submit buttons gate it, but the whole point of
        // high-risk mode (a passphrase that survives device-key extraction) must
        // not be defeatable by a future UI change or an alternate caller. Only the
        // RESULTING passphrase mode is gated: newMode==MODE_PASSPHRASE, or a plain
        // change (newMode==null) while the vault is already in passphrase mode. A
        // PIN change is unaffected.
        //
        // newMode==null must NOT resolve the stored mode through
        // isPassphraseMode() — its DAMAGED-blob branch fails open to `true`
        // (correct for the ENTRY UI, where a PIN user can still type digits in
        // the text field), but here it held every new 6-digit PIN to the
        // passphrase floor (WEAK_CREDENTIAL → PIN rotation permanently blocked),
        // and a mode-preserving change wrote no vlt_m, so the damage never
        // healed. When the stored blob is provably damaged, derive the resulting
        // mode from the NEW credential's shape (the same shape the entry keypads
        // enforce — CredentialPolicy.isPinShaped) and re-write vlt_m in the
        // atomic swap below so the damage heals with the rotation. The
        // transient-outage default (PIN, matching isPassphraseMode) and the
        // unlock-time fail-open stay untouched.
        //
        // An UNAUTHENTICATED stored mode gets the
        // same shape-derived treatment as a damaged one — REQUIRED for the entry-widget fail-open
        // to stay brick-safe. With the entry UI now rendering the free-text field for
        // such an install, a legacy-cleartext (or planted) `pin` token would otherwise
        // be trusted here and re-persisted AUTHENTICATED over a credential the user
        // just set as free text, permanently pinning the keypad on a vault the keypad
        // cannot enter. See [resolveChangeCredentialMode]; the floor only ever
        // tightens, so no existing WEAK_CREDENTIAL denial is relaxed.
        val mode = resolveModeForChange(newMode, newCredential)
        if (mode.resultingPassphrase && !CredentialPolicy.meetsFloor(newCredential)) {
            stretched.secureWipe()
            platformLogWarn("VaultSelector", "changeCredential denied — new passphrase below the entropy floor")
            return ChangePinResult.WEAK_CREDENTIAL
        }

        try {
            // Unwrap the EXISTING SQLCipher passphrase with the current PIN's
            // KEK — the passphrase itself is preserved so the DB file stays
            // readable; only its wrapping changes. A transient store failure
            // (iOS Keychain) defers exactly like the evalCredential
            // outage above — WRONG_CURRENT is benign here (change-PIN never
            // wipes; the user retries) and the exception must not reach the
            // non-@Throws Swift caller (SIGABRT).
            val wrappedB64 = try {
                store.getString(VaultStoreKeys.WRAPPED_DBKEY)
            } catch (_: KeyUnavailableException) {
                platformLogWarn("VaultSelector", "changeCredential deferred — store unavailable")
                return ChangePinResult.WRONG_CURRENT
            } ?: return ChangePinResult.WRONG_CURRENT
            // Preserve the CURRENT outer-layer scheme (plain vs auth-bound)
            // across the rotation — changing the PIN must not silently drop
            // Lever B protection. An auth-bound unwrap here prompts once; the
            // user is mid-change-PIN and interacting, so that's expected.
            val wasAuthBound = dbKeyProtector.isAuthBoundBlob(wrappedB64)
            // A credential TIER UPGRADE also retires the
            // SQLCipher passphrase, so an archived copy of the OLD `vlt_c` plus the old
            // PIN plus the still-current device key can no longer open the vault the
            // user just strengthened. Decided BEFORE any new key material exists so the
            // ineligible case is byte-for-byte the pre-rotation flow. See [mayRotateDbKey].
            val rotate = mayRotateDbKey(
                tierUpgrade = isCredentialTierUpgrade(newMode),
                // Proven-absent or proven-forged releases the veto; PROVEN
                // and UNREADABLE both keep it. See [recoveryBlobVetoesRotation].
                recoveryBlobVetoes = recoveryBlobVetoesRotation(recoveryBlobState()),
                dbKeyAuthBound = wasAuthBound,
                hasVaultHandle = vaultProvider() != null,
                rotationAlreadyPending = rotationPending(),
            )
            // Raw-key adoption: the unwrapped plaintext is a PAYLOAD (R + key mode, and
            // K' when adopted). The rotation below re-seals the WHOLE payload, so a
            // credential change never drops an adopted vault back to passphrase mode;
            // a malformed payload is "current key unwrap failed" exactly like a damaged
            // blob — benign, nothing written.
            val payload = unwrapCurrentPayload(stretched, wrappedB64) ?: run {
                platformLogWarn("VaultSelector", "changeCredential denied — current key unwrap failed")
                return ChangePinResult.WRONG_CURRENT
            }
            try {
                // New verifier + re-wrapped DB key (+ the `vlt_cn` record on an eligible
                // tier upgrade, + the mode) — sealed, not yet written. Throws a
                // KeyUnavailableException out to the catch below with nothing persisted.
                val batch = buildChangeCredentialBatch(newCredential, payload, wasAuthBound, rotate, mode.modeToWrite)
                try {
                    if (!commitChangeCredentialBatch(batch)) return ChangePinResult.WRONG_CURRENT
                    platformLog("VaultSelector", "changeCredential succeeded")
                    // The credential change has LANDED. Everything from here is the
                    // best-effort DB-key rotation, whose outcome never changes the
                    // reported result — reporting a failure over a rotation that may
                    // well have succeeded would send the user back to re-enter a
                    // credential that already works, and those retries count against the
                    // daily change-PIN cap.
                    //
                    // The catch is defensive, not decorative: this call sits INSIDE the
                    // enclosing `catch (KeyUnavailableException) -> WRONG_CURRENT`, so a
                    // throw escaping the rotation would report a credential change that
                    // ALREADY LANDED as a failure — the exact false-FAILURE hazard.
                    // Nothing below throws today (every helper swallows), and this keeps
                    // that true no matter what is added later.
                    rotateAfterLandedChange(batch, payload)
                    return ChangePinResult.SUCCESS
                } finally {
                    // The candidate SQLCipher passphrase (tier upgrade only).
                    batch.wipe()
                }
            } finally {
                payload.wipe()
            }
        } catch (_: KeyUnavailableException) {
            // Device key vanished during the RE-WRAP half (crypto.seal of the
            // new verifier, the encryptSelectorMeta mode write, or the store
            // batch) — nothing was persisted (putStringsSync is the last step).
            // Defer as WRONG_CURRENT like the earlier outages in this flow: the
            // exception must not cross the non-@Throws Swift bridge (SIGABRT) or
            // the Compose change-PIN coroutine; change-PIN never wipes, the user
            // retries once the key returns.
            platformLogWarn("VaultSelector", "changeCredential deferred — device key unavailable during re-wrap")
            return ChangePinResult.WRONG_CURRENT
        } finally {
            stretched.secureWipe()
        }
    }

    // How a credential change resolves the RESULTING mode: whether the new
    // credential is held to the passphrase floor, and which `vlt_m` token (if any)
    // rides the batch.
    private class ModeForChange(val resultingPassphrase: Boolean, val modeToWrite: String?)

    // An explicit [newMode] decides alone. A mode-preserving change (null) reads the
    // stored `vlt_m` and resolves it through [resolveChangeCredentialMode] — an
    // unauthenticated or DAMAGED stored mode is resolved from the NEW credential's
    // shape, never from the stored token; a transient outage writes no mode and
    // keeps the PIN default. Never throws (both catches are inside).
    private fun resolveModeForChange(newMode: String?, newCredential: String): ModeForChange = when (newMode) {
        MODE_PASSPHRASE -> ModeForChange(resultingPassphrase = true, modeToWrite = newMode)
        MODE_PIN -> ModeForChange(resultingPassphrase = false, modeToWrite = newMode)
        else -> {
            val decision = try {
                val read = readSelectorMetaRaw(VaultStoreKeys.CREDENTIAL_MODE)
                // Re-persist the resolved mode on every rotation, so a
                // legacy ABSENT / pre-padding vlt_m migrates to the always-written,
                // fixed-length blob (closes the presence/absence + length oracle for
                // existing vaults).
                resolveChangeCredentialMode(
                    storedMode = read?.value,
                    storedAuthenticated = read?.authenticated == true,
                    storedDamaged = false,
                    newCredentialIsPinShaped = CredentialPolicy.isPinShaped(newCredential),
                )
            } catch (_: KeyUnavailableException) {
                // Transient outage — can't know the real mode, so DON'T persist a
                // guess (writing MODE_PIN over a passphrase vault would corrupt the
                // entry UI). Leave vlt_m as-is; same neutral PIN default as
                // isPassphraseMode() for the (unchanged) floor check.
                null
            } catch (_: SelectorMetaDamagedException) {
                resolveChangeCredentialMode(
                    storedMode = null,
                    storedAuthenticated = false,
                    storedDamaged = true,
                    newCredentialIsPinShaped = CredentialPolicy.isPinShaped(newCredential),
                )
            }
            ModeForChange(
                resultingPassphrase = decision?.resultingPassphrase ?: false,
                modeToWrite = decision?.modeToWrite,
            )
        }
    }

    // Unwrap the CURRENT `vlt_c` under the current credential's KEK: the outer
    // layer (an auth-bound blob prompts here) then the inner PIN layer. Null on ANY
    // failure — unwrap error, AEAD miss, malformed payload — which the caller reports
    // as "current key unwrap failed" (WRONG_CURRENT, nothing written). The KEK and
    // the inner ciphertext are wiped here.
    private fun unwrapCurrentPayload(stretched: ByteArray, wrappedB64: String): DbKeyPayload? {
        var oldKek: ByteArray? = null
        var inner: ByteArray? = null
        return try {
            oldKek = codecs.dbKeyKek(stretched)
            inner = dbKeyProtector.unwrap(wrappedB64)
            codecs.openDbKeyInner(inner, oldKek)
        } catch (_: Exception) {
            null
        } finally {
            oldKek?.secureWipe()
            inner?.secureWipe()
        }
    }

    // A change-credential batch, sealed and ready to write. [values] is the whole
    // atomic batch (insertion order `vlt_a, vlt_c, [vlt_cn], [vlt_m]`); [credentialPair]
    // is the part the refutation check reads back; [rotationKey] is the candidate
    // SQLCipher passphrase of an eligible tier upgrade (null otherwise), kept alive
    // for the re-key and wiped by [wipe].
    private class ChangeBatch(
        val values: Map<String, String>,
        val credentialPair: Map<String, String>,
        val pendingDbBlob: String?,
        val rotationKey: ByteArray?,
    ) {
        fun wipe() { rotationKey?.secureWipe() }
    }

    // Derive the new credential's verifier + re-wrap the DB key under the new PIN
    // (fresh salt → fresh stretched → fresh KEK), plus — when [rotate] — the `vlt_cn`
    // record of a fresh SQLCipher passphrase, plus the [modeToWrite] blob. Writes
    // nothing. The new stretched value, the new KEK and the payload encodings are
    // wiped here; the rotation key survives inside the result (or is wiped here if
    // sealing throws). A KeyUnavailableException from any device-key seal propagates.
    private fun buildChangeCredentialBatch(
        newCredential: String,
        payload: DbKeyPayload,
        wasAuthBound: Boolean,
        rotate: Boolean,
        modeToWrite: String?,
    ): ChangeBatch {
        val newSalt = generateSecureRandom(SALT_LENGTH)
        val newPwBytes = newCredential.encodeToByteArray()
        // New credential always uses the CURRENT (v3 / Argon2id) KDF, so
        // changing the PIN also migrates a legacy v1/v2 vault up to v3.
        val newStretched = stretchCurrent(newPwBytes, newSalt)
        newPwBytes.secureWipe()  // zero the transient PIN-bytes copy
        var newKek: ByteArray? = null
        // The candidate SQLCipher passphrase and its pending record. Both
        // null unless this change is an eligible tier upgrade.
        var rotationKey: ByteArray? = null
        var newPlain: ByteArray? = null
        var rotationPlain: ByteArray? = null
        var handedOff = false
        try {
            val newCredBlob = codecs.sealCredentialVerifier(newStretched, newSalt)

            newKek = codecs.dbKeyKek(newStretched)
            // The canonical re-encoding of the payload just unwrapped: same R,
            // same mode, same K'. (A legacy 32-byte payload is re-written in its
            // explicitly-tagged PASSPHRASE form — same meaning, migrate-on-write.)
            newPlain = encodeDbKeyPayload(payload)
            val newDbBlob = codecs.sealDbKeyBlob(newPlain, newKek, authBound = wasAuthBound)

            // `vlt_c` above still wraps the OLD DB key — that is the whole
            // point. The NEW key goes to `vlt_cn` in the SAME batch, so the
            // union of the two records covers the file whichever key it ends up
            // on, and (on iOS) a journal replay that later restores this batch
            // restores BOTH halves of that union rather than half of it.
            val pendingDbBlob: String? = if (!rotate) null else {
                rotationKey = generateSecureRandom(DBKEY_LENGTH)
                // A re-key target is always PASSPHRASE mode (see
                // [rotateDbKeyAfterUpgrade]); tagged explicitly.
                rotationPlain = encodeDbKeyPayload(rotationKey, null)
                // authBound=false is guaranteed correct: [mayRotateDbKey]
                // requires the current blob to be PLAIN, which is also what
                // keeps the unlock reconcile's second unwrap prompt-free.
                codecs.sealDbKeyBlob(rotationPlain, newKek, authBound = false)
            }

            // Atomic swap: verifier + wrapped key (+ mode flag when the
            // credential type changes) land together.
            //
            // This batch needs no journal guard, and
            // the reason is the ≥2 entries below — `putStringsSync` only takes
            // its journalled path for a multi-key map (a single-entry map
            // short-circuits to a bare `kvPut` with no journal at all) and that
            // path OVERWRITES any stale journal with this batch before applying
            // it, so nothing older can replay over the result. Never reduce this
            // map to one key; see [singleKeyDbKeyWriteAllowed].
            val values = buildMap {
                put(VaultStoreKeys.CREDENTIAL_VERIFIER, newCredBlob)
                put(VaultStoreKeys.WRAPPED_DBKEY, newDbBlob)
                pendingDbBlob?.let { put(VaultStoreKeys.PENDING_DBKEY, it) }
                // Mode value is a device-key AEAD blob, same as the
                // provision/level writes — kept in the atomic swap so it
                // still lands together with the new verifier + wrapped key.
                // modeToWrite is newMode, OR the
                // shape-derived mode when the stored blob was damaged or
                // UNAUTHENTICATED — re-writing it here self-heals both
                // atomically with the rotation.
                modeToWrite?.let { put(VaultStoreKeys.CREDENTIAL_MODE, encryptSelectorMeta(VaultStoreKeys.CREDENTIAL_MODE, it)) }
            }
            val result = ChangeBatch(
                values = values,
                credentialPair = mapOf(
                    VaultStoreKeys.CREDENTIAL_VERIFIER to newCredBlob,
                    VaultStoreKeys.WRAPPED_DBKEY to newDbBlob,
                ),
                pendingDbBlob = pendingDbBlob,
                rotationKey = rotationKey,
            )
            handedOff = true
            return result
        } finally {
            newStretched.secureWipe()
            // newKek (+ the inner ciphertext, wiped inside sealDbKeyBlob)
            // reconstructs dbKey from the NEW wrapping — wipe alongside newStretched.
            newKek?.secureWipe()
            newPlain?.secureWipe()
            rotationPlain?.secureWipe()
            // RotationKey IS a live SQLCipher passphrase: it leaves only inside the result.
            if (!handedOff) rotationKey?.secureWipe()
        }
    }

    // Write the batch, then refute it ONLY on positive evidence. False = the store
    // provably refused the credential pair (the previous credential still opens the
    // vault; any `vlt_cn` record is dropped best-effort) — the caller reports
    // WRONG_CURRENT. True = landed or ambiguous (ambiguity keeps SUCCESS).
    private fun commitChangeCredentialBatch(batch: ChangeBatch): Boolean {
        store.putStringsSync(batch.values)
        // putStringsSync returns Unit. On iOS it
        // does a per-key kvPut that fails SILENTLY on a locked keybag and
        // uses its own read-back only to decide whether to keep the
        // journal, never to report upward; on Android the commit() Boolean
        // is discarded. Reporting SUCCESS over that is the dangerous
        // direction: the app claims the PIN changed while the OLD one still
        // opens the vault, and the user's NEW PIN then comes back Denied —
        // which DOES count toward the wipe budget, so an honest user can
        // destroy their own vault entering the PIN we told them we set.
        // Refute only on positive evidence (see [credentialWriteRefuted]);
        // an ambiguous read keeps the original report, because a false
        // FAILURE is equally destructive (the user keeps using a credential
        // that no longer opens the vault).
        //
        // Deliberately only the CREDENTIAL PAIR, not the whole batch: those
        // two are what decide whether the new credential opens the vault. A
        // torn write that landed them but dropped the (last-written) mode
        // marker HAS rotated the credential, so refuting on vlt_m would send
        // a user whose PIN really did change back to a current-credential
        // prompt the old value no longer satisfies — and those retries count
        // against the daily change-PIN cap. The stale marker is repaired by
        // the iOS journal replay on the next construction.
        // fail-direction: refute-only-on-evidence (ambiguity keeps SUCCESS).
        if (credentialWriteRefuted(batch.credentialPair) { store.getString(it) }) {
            platformLogWarn("VaultSelector",
                "changeCredential NOT persisted (store refused the batch) — the previous credential still opens the vault")
            // The batch is refuted, so nothing may reference the
            // candidate key — and the vault was never re-keyed (the re-key
            // is strictly after this check). Best-effort: a surviving record
            // is inert, since the next unlock finds `vlt_c`'s key still opens
            // the file and drops it.
            if (batch.pendingDbBlob != null) removePendingRotation()
            // WRONG_CURRENT is the flow's established "nothing changed,
            // retry" code — every other deferral here returns it, both UIs
            // treat it as a restart, and Swift already maps it (a new enum
            // case would have to cross IosAppController's string bridge,
            // where anything unknown collapses to wrongCurrent anyway).
            return false
        }
        return true
    }

    // The best-effort DB-key rotation after a credential change has LANDED (see the
    // caller). Never throws: an escaping exception would report a landed change as
    // a failure.
    private fun rotateAfterLandedChange(batch: ChangeBatch, oldPayload: DbKeyPayload) {
        val pendingDbBlob = batch.pendingDbBlob ?: return
        val rotationKey = batch.rotationKey ?: return
        try {
            rotateDbKeyAfterUpgrade(pendingDbBlob, rotationKey, oldPayload)
        } catch (e: Exception) {
            platformLogWarn("VaultSelector",
                "DB-key rotation threw (credential change still SUCCEEDED): ${e::class.simpleName}")
        }
    }

    // -----------------------------------------------------------------------
    // Vault unlock
    // -----------------------------------------------------------------------

    sealed class UnlockResult {
        data class Opened(val vault: VaultDatabase) : UnlockResult()

        /**
         * The COUNTING outcome: the caller adds one attempt to the wrong-credential
         * budget (and may wipe when it is spent). Returned when the stored verifier
         * decrypts and the candidate does not match it (or no verifier is stored /
         * it decrypts to nothing parseable) — AND, from [unlock], when the verifier
         * MATCHES but `vlt_c` is CONFIRMED absent: that vault is already unopenable
         * by any credential (only the half-pair purge or the orphan erase leads out),
         * so counting there spends a budget over nothing that could still open.
         * From [recoverWithCode]: a malformed / wrong-length code, a code-layer AEAD
         * miss against a REAL recovery blob, or a wrong credential after a correct
         * code. Never returned for a transient device-key outage or a damaged
         * `vlt_c` — those are [Error] — nor for a FORGED recovery blob.
         */
        data object Denied : UnlockResult()

        /**
         * The neutral, NON-COUNTING outcome: nothing proves the credential wrong.
         * Most often the credential MATCHED but opening the vault failed transiently
         * (locked or corrupt SQLCipher file / sidecar, I/O error) — but it is also
         * returned BEFORE any match is known (the device key is unavailable while
         * reading/decrypting the verifier), for a malformed DB-key payload, for a
         * neither-key-opens rotation reconcile, and from [recoverWithCode] for a
         * FORGED recovery blob or a pending iOS write-ahead journal. Distinct from
         * [Denied] (wrong credential): the caller MUST NOT count this toward the
         * brute-force budget or wipe — it should let the user retry. The underlying SQLite
         * exception is dropped rather than propagated so a transient open failure
         * cannot crash the unlock caller or leak file internals.
         */
        data object Error : UnlockResult()

        /**
         * The credential was CORRECT, but the Lever-B hardware key that wraps
         * the DB key is permanently destroyed (lock screen / passcode removed), so
         * no retry can ever open the vault. Distinct from [Error]: the caller must
         * stop offering "try again" and route the user to their recovery code —
         * which still opens the vault, because the recovery blob wraps the same
         * SQLCipher passphrase independently of the hardware key. Like [Error] it
         * NEVER counts toward the brute-force budget: the PIN was right.
         */
        data object RecoveryRequired : UnlockResult()
    }

    /**
     * Open the vault with [credential]. Heavy (one KDF derivation; an auth-bound
     * blob also prompts once) — call OFF the main thread. Phase order, which every
     * later refactor must keep:
     *  1. evaluate the credential against `vlt_a` ([evalCredential]);
     *  2. read `vlt_c` and unwrap it (the biometric prompt point for an `ab:` blob),
     *     then — inside the same phase — the legacy weak-key re-mint
     *     ([maybeReconcileLegacyAuthBoundKey]) and the pending-rotation read;
     *  3. reconcile a pending `vlt_cn` rotation ([reconcilePendingRotation]), which
     *     is also the open when a record exists;
     *  4. the KDF / sub-floor-cost migration ([migrateCredentialToCurrentKdf]);
     *  5. the abandoned-enable purge ([purgeAbandonedRecoveryEnable]);
     *  6. open the vault in the payload's tagged mode ([openWithPayload]);
     *  7. raw-key adoption ([maybeAdoptRawKey], Android only).
     *
     * Results: [UnlockResult.Opened] with the handle; [UnlockResult.Denied] (COUNTS)
     * for a verifier mismatch or a matching verifier over a confirmed-absent `vlt_c`;
     * [UnlockResult.RecoveryRequired] (non-counting) when the auth-bound hardware key
     * is permanently invalid; [UnlockResult.Error] (non-counting, never a wipe) for
     * every transient or storage-damage case — device key unavailable, store read
     * failure, damaged / malformed `vlt_c`, neither rotation key opening, or the open
     * itself failing.
     */
    fun unlock(credential: String): UnlockResult {
        platformLog("VaultSelector", "unlock: checking credential...")
        val (matches, stretched, credVersion, credParams) = try {
            evalCredential(credential)
        } catch (_: KeyUnavailableException) {
            // Device key transiently unavailable — we could not decide if the PIN
            // is correct. NEVER treat "cannot decide" as a wrong PIN: return the
            // neutral Error, which the caller retries WITHOUT counting toward the
            // wrong-credential wipe budget. A wrong PIN can
            // still only be established by a successful decrypt + verifier miss.
            platformLogWarn("VaultSelector", "unlock deferred — device key unavailable")
            return UnlockResult.Error
        }
        platformLog("VaultSelector", "credential check complete (match found: $matches)")

        if (!matches || stretched == null) {
            stretched?.secureWipe()
            platformLogWarn("VaultSelector", "unlock denied — no credential match")
            return UnlockResult.Denied
        }

        // Reuse the stretched KDF output to derive the DB-key KEK (distinct
        // label) and unwrap the SQLCipher passphrase. A wrong PIN never reaches
        // here (credential check fails first); a missing device key fails the
        // outer AEAD — both yield denial. A TRANSIENT store failure (iOS
        // Keychain) is neither: the credential already matched, so
        // defer with the neutral, non-counting Error.
        val wrappedB64 = try {
            store.getString(VaultStoreKeys.WRAPPED_DBKEY)
        } catch (_: KeyUnavailableException) {
            stretched.secureWipe()
            platformLogWarn("VaultSelector", "unlock deferred — store unavailable reading wrapped key")
            return UnlockResult.Error
        } ?: run {
            stretched.secureWipe()
            platformLogWarn("VaultSelector", "unlock denied — no wrapped key")
            return UnlockResult.Denied
        }
        val unwrapped = try {
            unwrapForUnlock(stretched, wrappedB64)
        } finally {
            stretched.secureWipe()
        }
        val ok = when (unwrapped) {
            is UnwrapOutcome.Stop -> return unwrapped.result
            is UnwrapOutcome.Ok -> unwrapped
        }
        return openAfterUnwrap(ok, credential, credVersion, credParams, wrappedB64)
    }

    // Phase 2 of [unlock]: `vlt_c` unwrapped under the matched credential's KEK.
    // [Ok] carries the payload, the pending-rotation candidate (if a record exists)
    // and the still-live KEK, all owned by [openAfterUnwrap] from here; [Stop] is the
    // result the unlock returns at once.
    private sealed class UnwrapOutcome {
        class Ok(val payload: DbKeyPayload, val pendingPayload: DbKeyPayload?, val kek: ByteArray) : UnwrapOutcome()
        class Stop(val result: UnlockResult) : UnwrapOutcome()
    }

    // Unwrap `vlt_c` (the biometric prompt point for an ab: blob), then — inside the
    // same phase, in this order — the legacy weak-key re-mint and the pending-rotation
    // read. The catch ladder is the unlock's: a permanently invalid hardware key ⇒
    // RecoveryRequired; a transient outage ⇒ Error; anything else (damaged / malformed
    // `vlt_c` after a verifier MATCH) ⇒ Error, never Denied. Does not wipe [stretched]
    // (the caller does, right after this returns).
    private fun unwrapForUnlock(stretched: ByteArray, wrappedB64: String): UnwrapOutcome {
        // Raw-key adoption: the KEK outlives the unwrap — it leaves inside
        // [UnwrapOutcome.Ok] and is wiped by [openAfterUnwrap]'s finally, after the
        // open — because adopting raw-key mode re-seals the payload under this same
        // KEK once the vault has opened. (kek + the on-disk blob reconstruct dbKey,
        // which is itself live for exactly that span.)
        var kek: ByteArray? = null
        var inner: ByteArray? = null
        // The candidate key of an in-flight DB-key rotation, unwrapped under the
        // SAME KEK as `vlt_c` while that KEK is still live. Null in the steady state — the read is gated on one cheap
        // `contains`, so a vault that never rotated pays a single store lookup.
        var pendingPayload: DbKeyPayload? = null
        var unwrapCompleted = false
        try {
            kek = codecs.dbKeyKek(stretched)
            // Auth-bound blobs prompt for a fresh biometric HERE (after the
            // credential already matched, so only a correct PIN reaches the
            // prompt). Runs off the main thread; unwrap blocks until the
            // biometric callback returns.
            inner = dbKeyProtector.unwrap(wrappedB64)
            // Raw-key adoption: R + the SQLCipher key mode (+ K'). A legacy 32-byte
            // payload decodes as PASSPHRASE (establish-on-read). A malformed one is the
            // storage-damage case below: neutral Error, never Denied, never a wipe.
            val dk = codecs.openDbKeyInner(inner, kek)
                ?: throw IllegalStateException("malformed DB-key payload")
            // Upgrade a LEGACY weak auth-bound key to the strict biometric-only
            // scheme now — credential verified, inner in hand. Best-effort; brick-safe
            // (skips when unsafe; recovery blob nets the same-alias delete→mint window).
            //
            // WHY a `vlt_c` WRITE sits inside the unwrap phase: this is the only point
            // where the verified inner blob AND a live (just-prompted) auth-bound key
            // coexist, which the strict re-mint needs. The coupling to know: on
            // success `vlt_c` no longer equals [wrappedB64], yet the later
            // [purgeAbandonedRecoveryEnable] and [maybeAdoptRawKey] still reason about
            // [wrappedB64]. Both stay safe — the purge classifies an auth-bound blob as
            // CLEAR_MARKER_ONLY either way (the reconcile only runs on auth-bound
            // blobs), and adoption's "stored blob unchanged" gate refuses because
            // `vlt_c` moved. Folding this into credentialBlobsMoved is plan-only (P-6).
            maybeReconcileLegacyAuthBoundKey(wrappedB64, inner)
            // A rotation record is ALWAYS a plain wrap (mayRotateDbKey refuses to
            // create one over an auth-bound blob), so this second unwrap can never
            // raise a second biometric prompt. Never throws — an unreadable record is
            // simply "no candidate key".
            if (rotationPending()) pendingPayload = readPendingRotationKey(kek)
            unwrapCompleted = true
            return UnwrapOutcome.Ok(dk, pendingPayload, kek)
        } catch (_: KeyPermanentlyInvalidException) {
            // Correct credential, but the auth-bound hardware key is destroyed.
            // Retrying is futile — send the caller to the recovery-code path.
            platformLogWarn("VaultSelector", "unlock needs recovery — auth-bound key permanently invalidated")
            return UnwrapOutcome.Stop(UnlockResult.RecoveryRequired)
        } catch (_: KeyUnavailableException) {
            // Credential already matched above, so this is NOT a wrong PIN — the
            // device key (or the auth-bound biometric) was unavailable/cancelled
            // during the unwrap. Defer as a neutral Error (non-counting,
            // non-wiping) rather than Denied (biometric
            // cancel/lockout must be retryable). stretched is wiped by
            // the caller's finally.
            platformLogWarn("VaultSelector", "unlock deferred — device key/auth unavailable during key unwrap")
            return UnwrapOutcome.Stop(UnlockResult.Error)
        } catch (_: Exception) {
            // The credential VERIFIER already matched above, so
            // a failure unwrapping/decrypting the DB key here is storage damage (corrupt
            // vlt_c / AEAD tag miss), NOT a wrong PIN. Returning Denied made the lock
            // screen count it toward the wrong-credential wipe, so an honest user with the
            // CORRECT PIN and a damaged blob was emergency-wiped — needlessly destroying
            // the recovery blob that could still open a Lever B vault. Defer as a neutral
            // Error (non-counting, non-wiping), exactly like the KeyUnavailable branch.
            // Not a brute-force bypass: reaching this catch requires the verifier match,
            // i.e. the correct credential, so it gives an attacker nothing.
            platformLogWarn("VaultSelector", "unlock deferred — key unwrap failed after verifier match (damaged vlt_c?)")
            return UnwrapOutcome.Stop(UnlockResult.Error)
        } finally {
            // kek + inner together reconstruct the DB key that is
            // meticulously wiped later — don't leave THEM resident. A live-RAM capture on
            // an unlocking device could otherwise re-derive dbKey from kek + the on-disk
            // wrapped blob, undoing the dbKey wipe. kek: wiped HERE on every early
            // return above, otherwise by [openAfterUnwrap]'s finally (see its declaration).
            if (!unwrapCompleted) kek?.secureWipe()
            inner?.secureWipe()
        }

    }

    // Phases 3–7 of [unlock], after a successful unwrap: rotation reconcile → KDF
    // migration → abandoned-enable purge → open → raw-key adoption (see [unlock]'s
    // kdoc). [wrappedB64] is the blob the credential just opened; [ok]'s payloads and
    // KEK are wiped here on every path.
    private fun openAfterUnwrap(
        ok: UnwrapOutcome.Ok,
        credential: String,
        credVersion: Byte,
        credParams: VaultKdf.KdfParams?,
        wrappedB64: String,
    ): UnlockResult {
        val payload = ok.payload
        val pendingPayload = ok.pendingPayload
        val kek = ok.kek
        // Resolve an interrupted DB-key rotation FIRST — before
        // migrateCredentialToCurrentKdf, which re-wraps `vlt_c` under a fresh KEK and
        // would leave the pending record unreadable while it still mattered. It is also
        // the open: which key actually opens the file is the only positive evidence
        // about which key the file holds.
        var openedVault: VaultDatabase? = null
        var effectivePayload = payload
        var rotationReconciled = false
        try {
            if (rotationPending()) {
                val reconcile = reconcilePendingRotation(payload, pendingPayload)
                if (reconcile.vault == null) {
                    // Neither key opened. Ambiguous by construction (a wrong key and an
                    // unreadable/locked file are indistinguishable), so change NOTHING —
                    // both records stay, and the neutral Error keeps this off the
                    // brute-force budget. Never Denied, never a wipe.
                    platformLogWarn("VaultSelector",
                        "vault open failed with both the stored and the pending DB key — neutral error, records kept")
                    return UnlockResult.Error
                }
                openedVault = reconcile.vault
                if (reconcile.promoted) effectivePayload = pendingPayload ?: payload
                rotationReconciled = true
            }

            // The credential matched and the DB key unwrapped (both AEAD-
            // authenticated), so this is the genuine PIN on this device — the safe
            // point to transparently re-wrap a legacy v1/v2 credential up to the
            // current Argon2id KDF.
            val credentialRewritten =
                migrateCredentialToCurrentKdf(credential, credVersion, credParams, effectivePayload)

            // And the safe point to revoke the orphan recovery
            // code left by a Lever B enable the user abandoned before acknowledging it.
            // [wrappedB64] is the blob this very credential just opened the vault with, so
            // "still plain" is proven rather than raced. Never throws; skips itself on any
            // ambiguity (see purgeAbandonedRecoveryEnable).
            //
            // A rotation reconcile counts as "the credential blobs moved" for the
            // same reason a KDF migration does — after a promotion `vlt_c` is no longer
            // the blob [wrappedB64] names — so it defers the purge one cycle rather than
            // letting it reason about a stale blob.
            purgeAbandonedRecoveryEnable(wrappedB64, credentialRewritten || rotationReconciled)

            platformLog("VaultSelector", "opening vault")
            // Raw-key adoption: open in the payload's tagged mode, falling back to
            // passphrase mode with R (see [openWithPayload]). Assigned to openedVault so
            // the catch below closes it if anything after this line throws.
            val handle: VaultDatabase
            // "May this unlock's open count as raw-key adoption's passphrase-mode
            // evidence?" — true only for a passphrase-mode open THIS unlock performed.
            val adoptionEligibleOpen: Boolean
            val reconciledHandle = openedVault
            if (reconciledHandle != null) {
                // The rotation reconcile opened it. Adoption is deferred for this unlock
                // regardless (rotationReconciled ⇒ the credential blobs moved).
                handle = reconciledHandle
                adoptionEligibleOpen = false
            } else {
                val opened = openWithPayload(effectivePayload)
                openedVault = opened.vault
                handle = opened.vault
                adoptionEligibleOpen = opened.viaPassphrase
            }
            // Raw-key adoption (2026-10-07): only now — the vault is OPEN, i.e. the
            // credential, the payload AND the file have all been proven — may an
            // Android vault opened in passphrase mode adopt raw-key mode. Best-effort
            // and never throws: whatever happens inside, this unlock has already
            // succeeded and returns the handle it has.
            maybeAdoptRawKey(
                payload = effectivePayload,
                kek = kek,
                unwrappedBlob = wrappedB64,
                openedInPassphraseMode = adoptionEligibleOpen,
                credentialBlobsMoved = credentialRewritten || rotationReconciled,
            )
            return UnlockResult.Opened(handle)
        } catch (_: Exception) {
            // The credential matched, but the vault failed to open (transient I/O,
            // locked/corrupt SQLCipher file or sidecar). NEVER let the platform
            // exception propagate: on Android the unlock caller does not catch it,
            // so it would crash the app. Return a neutral Error the caller retries
            // without wiping or counting. The exception is dropped (not chained).
            platformLogWarn("VaultSelector", "vault open failed (transient) — neutral error")
            // A handle opened by the reconcile must not leak when a LATER step
            // throws — the caller never sees it, so nothing else can close it.
            try { openedVault?.close() } catch (_: Exception) { }
            return UnlockResult.Error
        } finally {
            payload.wipe()
            pendingPayload?.wipe()
            kek.secureWipe()
        }
    }

    /**
     * Raw-key adoption at UNLOCK (2026-10-07): the vault has just OPENED in
     * passphrase mode with R; derive K' for the file, PROVE it opens the file, and
     * only then re-seal `vlt_c` as `R ‖ RAW ‖ K'` in ONE write, read back.
     *
     * The exact promotion rule is [rawKeyAdoptionAllowed] (preconditions, all from
     * this unlock) followed by [rawKeyAdoptionMayCommit] (the probe + the
     * unchanged-blob + the round-trip gates). Every refusal leaves the vault exactly
     * as openable as it was: R stays in every payload, so passphrase mode keeps
     * working whatever happens here, and a torn or dropped write leaves either the
     * old blob or the new one — both open the vault.
     *
     * Lever B (`ab:`): the re-seal is re-wrapped under the SAME live auth-bound key
     * that unwrapped it moments ago (a public-key op — no second biometric prompt;
     * the identical re-wrap change-PIN and the KDF migration already perform), and
     * only when a PROVEN recovery blob stands behind it. That recovery blob wraps R,
     * which adoption never changes, so it stays valid. Not round-trip-verified (that
     * would prompt); a plain blob always is.
     *
     * Never throws; never touches `vlt_rc`, `vlt_cn`, `vlt_a` or the file.
     */
    private fun maybeAdoptRawKey(
        payload: DbKeyPayload,
        kek: ByteArray,
        unwrappedBlob: String,
        openedInPassphraseMode: Boolean,
        credentialBlobsMoved: Boolean,
    ) {
        if (!vaultFactory.supportsRawKeyAdoption()) return   // iOS: zero cost, zero reads
        var rawKey: ByteArray? = null
        var newPlain: ByteArray? = null
        try {
            val authBound = dbKeyProtector.isAuthBoundBlob(unwrappedBlob)
            val rotation: Boolean? = try { store.contains(VaultStoreKeys.PENDING_DBKEY) } catch (_: Exception) { null }
            val allowed = rawKeyAdoptionAllowed(
                platformAdopts = true,
                openedInPassphraseMode = openedInPassphraseMode,
                credentialBlobsMovedThisUnlock = credentialBlobsMoved,
                rotationPending = rotation,
                journalPending = batchJournalPending(),
                authBound = authBound,
                // Evaluated only for an auth-bound blob (one device-key AES-GCM open).
                recoveryNetProven = authBound && recoveryBlobUsableAsNet(recoveryBlobState()),
            )
            if (!allowed) {
                if (openedInPassphraseMode) {
                    platformLog("VaultSelector", "raw-key adoption deferred — preconditions not met this unlock")
                }
                return
            }
            rawKey = vaultFactory.deriveAdoptedRawKey(payload.dbKey) ?: run {
                platformLogWarn("VaultSelector", "raw-key adoption skipped — vault salt unreadable")
                return
            }
            val probeOpened = try { vaultFactory.probeRawKey(rawKey) } catch (_: Exception) { false }
            val ctx = VaultCryptoContexts.DBKEY_INNER.encodeToByteArray()
            newPlain = encodeDbKeyPayload(payload.dbKey, rawKey)
            val newBlob = codecs.sealDbKeyBlob(newPlain, kek, authBound = authBound)
            val roundTripOk: Boolean? = if (authBound) null else {
                var checkInner: ByteArray? = null
                var checkPlain: ByteArray? = null
                try {
                    checkInner = dbKeyProtector.unwrap(newBlob)        // plain → no prompt
                    checkPlain = aesGcmDecrypt(checkInner, kek, ctx)
                    checkPlain.contentEquals(newPlain)
                } catch (_: Exception) {
                    false
                } finally {
                    checkInner?.secureWipe(); checkPlain?.secureWipe()
                }
            }
            val unchanged = try { store.getString(VaultStoreKeys.WRAPPED_DBKEY) == unwrappedBlob } catch (_: Exception) { false }
            if (!rawKeyAdoptionMayCommit(probeOpened, unchanged, roundTripOk)) {
                platformLogWarn("VaultSelector",
                    "raw-key adoption NOT committed (probe=$probeOpened unchanged=$unchanged roundTrip=$roundTripOk) — stays in passphrase mode")
                return
            }
            store.putStringSync(VaultStoreKeys.WRAPPED_DBKEY, newBlob)
            // fail-direction: best-effort (old and new blob both carry R; a miss retries next unlock).
            val landed = try { store.getString(VaultStoreKeys.WRAPPED_DBKEY) == newBlob } catch (_: Exception) { false }
            if (landed) {
                platformLog("VaultSelector", "vault adopted SQLCipher raw-key mode (no rekey; file unchanged)")
            } else {
                // Both the old and the new blob open the vault (R is in both), so an
                // unproven write is a missed optimisation, never a lockout.
                platformLogWarn("VaultSelector", "raw-key adoption write did not read back — retried next unlock")
            }
        } catch (e: Exception) {
            platformLogWarn("VaultSelector", "raw-key adoption failed (non-fatal): ${e::class.simpleName}")
        } finally {
            rawKey?.secureWipe(); newPlain?.secureWipe()
        }
    }

    /**
     * Raw-key adoption at PROVISION: the provision open just CREATED the file in
     * passphrase mode with [dbKey] (positive evidence that R is its key), so derive
     * K' from the new file's salt and keep it only if [VaultFactory.probeRawKey]
     * opens the file. Null ⇒ the provision writes a PASSPHRASE payload and the first
     * unlock adopts instead. Never throws: an optimisation must not fail a provision.
     */
    private fun adoptRawKeyAtProvision(dbKey: ByteArray): ByteArray? {
        if (!vaultFactory.supportsRawKeyAdoption()) return null
        var rawKey: ByteArray? = null
        return try {
            rawKey = vaultFactory.deriveAdoptedRawKey(dbKey) ?: return null
            if (vaultFactory.probeRawKey(rawKey)) rawKey.also { rawKey = null } else null
        } catch (_: Exception) {
            null
        } finally {
            rawKey?.secureWipe()
        }
    }

    /**
     * Transparent KDF upgrade on successful unlock: re-wraps a credential
     * provisioned under an older KDF version (v1/v2 PBKDF2) to the current one
     * (v3 Argon2id) using the just-verified PIN and the just-unwrapped [payload].
     * Mirrors the re-wrap half of [changeCredentialInner]: fresh salt, new
     * verifier + re-wrapped DB key persisted in ONE atomic write, so an
     * interrupt can never leave a credential whose KEK no longer unwraps the
     * DB key. Best-effort by design — the vault is already open by rights, so
     * a migration failure only logs and leaves the (still valid) old blob in
     * place to be retried on the next unlock.
     *
     * Returns true when a re-wrap batch was actually ISSUED on this unlock (the abandoned-enable purge defers on it).
     * Only the caller's decision to DEFER uses it, so the fail direction is "assume
     * it changed something": an issued-but-unproven batch (see the read-back below)
     * counts as changed, because the safe response to ambiguity is to defer a cycle.
     * Control flow is otherwise untouched — this stays best-effort.
     */
    private fun migrateCredentialToCurrentKdf(
        credential: String,
        storedVersion: Byte,
        storedParams: VaultKdf.KdfParams?,
        payload: DbKeyPayload,
    ): Boolean {
        // A version check alone is not enough. A v3 blob
        // PINS its Argon2 cost and re-derives with that pinned cost forever, so a
        // credential provisioned at the DEBUG cost (1 MiB × 1 pass) and carried into a
        // release binary — iOS dev/TestFlight → App Store upgrades preserve app data —
        // stays forensically weak for the life of the install. assertKdfBuildIntegrity
        // only checks what THIS build would WRITE, so it passes and never notices.
        // Re-pin those to the release cost on the next successful unlock, which is the
        // one moment the credential and the unwrapped DB key are both in hand.
        // Never re-wrap `vlt_c` under a fresh KEK while a DB-key rotation record
        // is still unresolved — `vlt_cn` is wrapped under the CURRENT KEK, so this
        // would make it unreadable and collapse the union invariant to one record. The
        // caller reconciles first, so this only trips when the reconcile could not
        // PROVE its promotion; the migration is best-effort and retries next unlock.
        if (rotationPending()) {
            platformLogWarn("VaultSelector",
                "KDF migration deferred — a DB-key rotation record is still unresolved")
            return false
        }
        val repinSubFloorCost = storedVersion >= CURRENT_KDF_VERSION && storedCostBelowReleaseFloor(storedParams)
        if (storedVersion >= CURRENT_KDF_VERSION && !repinSubFloorCost) return false
        var rewrapIssued = false
        try {
            val newSalt = generateSecureRandom(SALT_LENGTH)
            val pwBytes = credential.encodeToByteArray()
            // Wipe the transient PIN-bytes copy even if stretchCurrent
            // throws (it was zeroed only on the success path before).
            val newStretched = try { stretchCurrent(pwBytes, newSalt) } finally { pwBytes.secureWipe() }
            var newKek: ByteArray? = null
            var newPlain: ByteArray? = null
            try {
                val newCredBlob = codecs.sealCredentialVerifier(newStretched, newSalt)

                val kek = codecs.dbKeyKek(newStretched).also { newKek = it }
                // Raw-key adoption: re-seal the WHOLE payload (R, mode, K') so the KDF
                // migration never drops an adopted vault back to passphrase mode.
                newPlain = encodeDbKeyPayload(payload)
                // Preserve the current outer-layer scheme across the KDF re-wrap.
                val authBound = store.getString(VaultStoreKeys.WRAPPED_DBKEY)?.let { dbKeyProtector.isAuthBoundBlob(it) } ?: false
                val newDbBlob = codecs.sealDbKeyBlob(newPlain, kek, authBound = authBound)

                val batch = mapOf(VaultStoreKeys.CREDENTIAL_VERIFIER to newCredBlob, VaultStoreKeys.WRAPPED_DBKEY to newDbBlob)
                store.putStringsSync(batch)
                // The batch is out — vlt_a/vlt_c may no longer be the blobs the
                // caller's in-scope copies name. Set BEFORE the read-back so an
                // unproven write still defers the abandoned-enable check by a cycle.
                rewrapIssued = true
                // Same silent-write shape as
                // changeCredentialInner, but NOTHING is claimed to the user here and
                // the vault keeps working either way — the old blob still verifies and
                // the migration retries on the next unlock. So the read-back only
                // corrects the LOG (a "migrated" line for a write that never landed is
                // exactly what makes this class of bug invisible); it must not change
                // control flow, or a best-effort optimisation would start failing
                // unlocks.
                // fail-direction: refute-only-on-evidence (ambiguity keeps the migration).
                if (credentialWriteRefuted(batch) { store.getString(it) }) {
                    platformLogWarn("VaultSelector",
                        "KDF migration did not persist — old credential blob still in force, will retry next unlock")
                } else if (repinSubFloorCost) {
                    platformLog("VaultSelector", "credential re-pinned to the release Argon2 cost")
                } else {
                    platformLog("VaultSelector", "credential KDF migrated v$storedVersion → v$CURRENT_KDF_VERSION")
                }
            } finally {
                newStretched.secureWipe()
                // The re-wrap KEK (+ the kek-encrypted DB key, wiped inside
                // sealDbKeyBlob) reconstructs dbKey — wipe it too, not just newStretched.
                newKek?.secureWipe()
                newPlain?.secureWipe()
            }
        } catch (_: Exception) {
            platformLogWarn("VaultSelector", "KDF migration failed (non-fatal) — will retry next unlock")
        }
        return rewrapIssued
    }

    /**
     * True when the stored v3 credential PINS an Argon2 cost below the release
     * floor while this is a RELEASE build — i.e. a debug-cost vault that a
     * release binary would otherwise honour forever. Debug builds legitimately run
     * the cheap cost, so they never re-pin (that would make every debug unlock pay
     * the full 64 MiB × 3 and re-break the e2e inner loop). A pre-pinning v3 blob pins
     * nothing, derives with the runtime constants, and is already at release cost.
     * Fails toward `false`: a re-pin is an optimisation of an already-valid vault,
     * never a gate, so missing params must not force one.
     */
    private fun storedCostBelowReleaseFloor(storedParams: VaultKdf.KdfParams?): Boolean {
        // [storedParams] are the ones [evalCredential] parsed out of the very `vlt_a`
        // the credential just MATCHED (carried in [CredentialMatch]) — no second read +
        // decrypt of `vlt_a`; nothing between the match and the migration writes it.
        if (isDebugBuild) return false
        val params = storedParams ?: return false
        return needsCredentialRewrap(params.version, params.memoryKiB, params.iterations, isDebugBuild)
    }

    // -----------------------------------------------------------------------
    // Credential evaluation (CR-1)
    //
    // Stored credential blob = deviceAEAD( version ‖ salt(16) ‖ verifier(32) [‖ m ‖ t ‖ p] ),
    // (48/49/58-byte layouts — see parseCredentialBlob), where
    //   stretched = KDF(pin, salt)                      ← requires the PIN
    //               (Argon2id for v3, PBKDF2 for v1/v2 — see [stretch])
    //   verifier  = sha256(stretched ‖ VaultCryptoContexts.LABEL_VERIFIER)  ← one-way
    // Stored DB-key blob     = deviceAEAD( AES-GCM(kek, payload) ), where
    //   payload = dbKey [‖ mode ‖ K'] — see decodeDbKeyPayload (raw-key adoption), and
    //   kek = sha256(stretched ‖ VaultCryptoContexts.LABEL_DBKEY_KEK)
    // Leaking the (device-AEAD-wrapped) verifier never yields kek; the DB
    // key cannot be recovered without the PIN even if the device key leaks.
    // Returns (matched, stretched, version) — stretched is non-null only on a
    // match so the caller can reuse it for the KEK without a second KDF pass;
    // version is the blob's stored KDF version, driving the on-unlock upgrade
    // ([migrateCredentialToCurrentKdf]).
    // -----------------------------------------------------------------------

    /**
     * Result of [evalCredential]: whether the candidate matched, the stretched KDF
     * output (non-null ONLY on a match — the caller owns it and must secureWipe it),
     * and the stored credential's KDF version. A data class only so the five call
     * sites keep their `val (matches, stretched, version) = …` destructuring; its
     * generated toString prints the array REFERENCE, never the bytes.
     */
    private data class CredentialMatch(
        val matched: Boolean,
        val stretched: ByteArray?,
        val kdfVersion: Byte,
        // The parsed `vlt_a` layout (salt, verifier, pinned Argon2 cost) — non-null
        // only on a match; the unlock's sub-floor re-pin decision reads it.
        val params: VaultKdf.KdfParams? = null,
    )

    private fun evalCredential(
        candidate: String
    ): CredentialMatch {
        // On iOS this read throws KeyUnavailableException on a TRANSIENT
        // Keychain failure — deliberately not caught here: every
        // caller already discriminates it (unlock → neutral Error, verify/
        // change → deferred), exactly like the crypto.open throw below.
        // Only a CONFIRMED-absent blob returns null → "no match".
        val storedB64 = store.getString(VaultStoreKeys.CREDENTIAL_VERIFIER)
            ?: return CredentialMatch(false, null, CURRENT_KDF_VERSION)

        // Decryption fails if encrypted with a different device key
        // (Keychain reset, cross-install). Treat as "no match".
        val plain = try {
            codecs.openCredentialVerifier(storedB64)
        } catch (e: KeyUnavailableException) {
            // The device key was transiently unavailable (Keystore/Keychain
            // glitch, or the device locked mid-call) — we CANNOT decide whether
            // the credential matches. Propagate so callers distinguish this from
            // a genuine wrong-PIN "no match": treating "cannot decide" as a
            // denial would consume the brute-force/wipe budget on an honest user
            // during a key outage. Every other decrypt
            // failure below is a real no-match.
            throw e
        } catch (_: Exception) {
            return CredentialMatch(false, null, CURRENT_KDF_VERSION)
        }
        // Determine salt + verifier + the KDF this credential was provisioned
        // with (v1/v2 PBKDF2 vs v3 Argon2id) from its version byte.
        val params = parseCredentialBlob(plain) ?: return CredentialMatch(false, null, CURRENT_KDF_VERSION)

        val pwBytes = candidate.encodeToByteArray()
        val stretched = stretch(pwBytes, params)
        pwBytes.secureWipe()  // zero the transient PIN-bytes copy
        val matched = constantTimeEquals(params.verifier, sha256WithLabel(stretched, VaultCryptoContexts.LABEL_VERIFIER.encodeToByteArray()))
        return if (matched) {
            CredentialMatch(true, stretched, params.version, params)
        } else {
            stretched.secureWipe()
            CredentialMatch(false, null, params.version)
        }
    }
}

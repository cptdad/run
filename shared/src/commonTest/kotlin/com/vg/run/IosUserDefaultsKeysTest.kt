package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Regression guard on the iOS wipe key list. The May-2026 iPad crash
 * happened because [PinAttemptsStore.STORAGE_KEY] was renamed from
 * "pin_failed_attempts" to "pin_failed_attempts_v2" without updating
 * the iOS wipe paths, leaving stale ciphertext that crashed the app
 * at next launch.
 */
class IosUserDefaultsKeysTest {

    @Test
    fun wipeListIncludesPinAttemptsStorageKey() {
        assertTrue(
            PinAttemptsStore.STORAGE_KEY in IosUserDefaultsKeys.all,
            "IosUserDefaultsKeys.all must include PinAttemptsStore.STORAGE_KEY " +
                "(\"${PinAttemptsStore.STORAGE_KEY}\") — without it the iOS " +
                "wipe paths skip the encrypted counter, leaving stale ciphertext " +
                "that crashes the app on next launch."
        )
    }

    @Test
    fun wipeListIncludesChangePinAttemptsStorageKey() {
        assertTrue(
            ChangePinAttemptStore.STORAGE_KEY in IosUserDefaultsKeys.all,
            "IosUserDefaultsKeys.all must include ChangePinAttemptStore.STORAGE_KEY " +
                "(\"${ChangePinAttemptStore.STORAGE_KEY}\") — otherwise the daily " +
                "change-PIN counter survives a wipe and, once the crypto key is " +
                "rotated, decrypts as a TamperException that wrongly wipes the " +
                "freshly re-provisioned vault on the next change-PIN attempt."
        )
    }

    @Test
    fun wipeListIncludesWrongPinWindowKey() {
        // The rolling-24h wrong-PIN window counter is a new
        // CryptoProvider-encrypted UserDefaults blob; if it is missing from the
        // wipe list it survives a panic wipe as undecryptable ciphertext after
        // the key is erased.
        assertTrue(
            PinAttemptsStore.WINDOW_STORAGE_KEY in IosUserDefaultsKeys.all,
            "IosUserDefaultsKeys.all must include PinAttemptsStore.WINDOW_STORAGE_KEY " +
                "(\"${PinAttemptsStore.WINDOW_STORAGE_KEY}\")."
        )
    }

    @Test
    fun wipeListIncludesEstablishedMarkerKey() {
        // The "counter established" marker must be cleared by
        // a wipe. kvDeleteAll() clears the Keychain copy, but a stale marker left in
        // any legacy UserDefaults path would make a re-provisioned vault read its
        // (absent) counter as tamper and self-wipe on the next launch — so it is
        // listed for the UserDefaults sweep too.
        assertTrue(
            PinAttemptsStore.ESTABLISHED_KEY in IosUserDefaultsKeys.all,
            "IosUserDefaultsKeys.all must include PinAttemptsStore.ESTABLISHED_KEY " +
                "(\"${PinAttemptsStore.ESTABLISHED_KEY}\")."
        )
    }

    @Test
    fun pinAttemptsStorageKeyIsV2() {
        // Locks in the current key name. If the encrypted counter format ever
        // changes again (v3, …), update this AND IosUserDefaultsKeys.all in
        // the same change set, and add the prior key as a *_LEGACY entry so
        // existing deployments wipe cleanly on upgrade.
        assertEquals("pin_failed_attempts_v2", PinAttemptsStore.STORAGE_KEY)
    }

    @Test
    fun wipeListIncludesWrappedDbKeyBlob() {
        // The PIN-wrapped SQLCipher passphrase (real_db_wrapped) lives in
        // NSUserDefaults and MUST be wiped, or it survives a panic wipe and
        // allows forensic DB-key re-derivation given the PIN.
        assertTrue(
            VaultStoreKeys.WRAPPED_DBKEY in IosUserDefaultsKeys.all,
            "wipe list must include the wrapped real DB key " +
                "(\"${VaultStoreKeys.WRAPPED_DBKEY}\").",
        )
    }

    @Test
    fun wipeListIncludesRecoveryBlob() {
        // Threat-level slider: the Lever B recovery blob is an independent wrap of
        // the SQLCipher passphrase under a user-held code. If it survives a panic
        // wipe, the code holder can still decrypt the DB key the wipe was meant to
        // destroy — so it MUST be in the wipe list.
        assertTrue(
            VaultStoreKeys.RECOVERY_BLOB in IosUserDefaultsKeys.all,
            "wipe list must include the recovery blob (\"${VaultStoreKeys.RECOVERY_BLOB}\").",
        )
    }

    @Test
    fun wipeListIncludesSelectorMetadataKeys() {
        // The protection-LEVEL and credential-MODE
        // selectors are the same class of vault metadata (both had a plaintext era);
        // the level was listed, the mode was not. A surviving plaintext mode copy
        // leaks whether the wiped vault was PIN- or passphrase-protected — exactly
        // the metadata class that was closed. Assert them together so the next
        // selector key added is noticed here.
        for (k in listOf(
            VaultStoreKeys.PROTECTION_LEVEL,
            VaultStoreKeys.CREDENTIAL_MODE,
        )) {
            assertTrue(k in IosUserDefaultsKeys.all,
                "wipe list must include vault selector metadata \"$k\".")
        }
    }

    @Test
    fun wipeListIncludesRemovedDecoyBlobs() {
        // The decoy feature was removed, but installs provisioned before the
        // removal still hold the decoy credential + wrapped DB-key blobs in
        // NSUserDefaults. They MUST stay in the wipe list so a panic wipe on
        // such an install leaves nothing behind.
        for (k in listOf(
            VaultStoreKeys.REMOVED_DECOY_CREDENTIAL,
            VaultStoreKeys.REMOVED_DECOY_DBKEY,
            VaultStoreKeys.REMOVED_LEGACY_DECOY_CREDENTIAL,
            VaultStoreKeys.REMOVED_LEGACY_DECOY_DBKEY,
        )) {
            assertTrue(k in IosUserDefaultsKeys.all,
                "wipe list must still include removed-decoy blob \"$k\".")
        }
    }

    @Test
    fun wipeListIncludesEulaAcceptedFlag() {
        // 2026-07-23: the EULA-accepted flag is a
        // plaintext consent flag written only after real user interaction, so it
        // is unambiguous proof of prior setup. The deniability contract
        // requires a wiped device to look never-configured, so every iOS wipe
        // path (all iterate IosUserDefaultsKeys.all) must clear it.
        assertTrue(
            IosUserDefaultsKeys.EULA_ACCEPTED in IosUserDefaultsKeys.all,
            "wipe list must include the EULA-accepted flag " +
                "(\"${IosUserDefaultsKeys.EULA_ACCEPTED}\") — otherwise it survives " +
                "every production wipe and proves prior setup (deniability breach)."
        )
    }

    @Test
    fun eulaAcceptedKeyMatchesSwiftStorageKey() {
        // Mirrors Swift's EulaConsent.storageKey (UserSafety.swift). Locks in the
        // literal so a rename on either side is caught here rather than silently
        // leaving the flag behind after a wipe.
        assertEquals("eula_accepted_version", IosUserDefaultsKeys.EULA_ACCEPTED)
    }

    @Test
    fun wipeListIncludesMtimeDilutionProbe() {
        // The mtime-dilution probe
        // is written only on a bare launch of a previously-configured+unlocked
        // vault, so its post-wipe presence is unambiguous proof of prior setup
        // (deniability breach). iOS deletes UserDefaults keys individually, so
        // it must be in the wipe list or it survives every iOS wipe path.
        assertTrue(
            IosUserDefaultsKeys.INACTIVITY_MTIME_PROBE in IosUserDefaultsKeys.all,
            "wipe list must include the mtime-dilution probe " +
                "(\"${IosUserDefaultsKeys.INACTIVITY_MTIME_PROBE}\") — otherwise it " +
                "survives every wipe and proves prior setup (deniability breach)."
        )
    }

    @Test
    fun mtimeProbeKeyMatchesSwiftStorageKey() {
        // Mirrors Swift's InactivityWipe.probeKey (InactivityWipe.swift). Locks in
        // the literal so a rename on either side is caught here rather than
        // silently leaving the probe behind after a wipe.
        assertEquals("inactivity_mtime_probe", IosUserDefaultsKeys.INACTIVITY_MTIME_PROBE)
    }

    @Test
    fun wipeListIncludesNotifLevelKey() {
        // Every iOS wipe path used to WRITE
        // "off" into notif_level (via pushEnabled = false in
        // clearWipeResidue()) rather than remove it — a breadcrumb the wipe
        // planted, proving prior setup on a supposedly never-configured
        // install, and the key was never in this list to sweep either.
        assertTrue(
            IosUserDefaultsKeys.NOTIF_LEVEL in IosUserDefaultsKeys.all,
            "wipe list must include the push-level selector " +
                "(\"${IosUserDefaultsKeys.NOTIF_LEVEL}\") — otherwise a wipe leaves " +
                "prior push-preference residue behind (deniability breach)."
        )
    }

    @Test
    fun notifLevelKeyMatchesSwiftStorageKey() {
        // Mirrors Swift's NotifLevelPreference.storageKey (AppState.swift) and
        // the shared NotificationLevelStore.KEY (NotificationLevel.kt,
        // private there). Locks in the literal so a rename on any side is
        // caught here rather than silently leaving the old key behind after a
        // wipe.
        assertEquals("notif_level", IosUserDefaultsKeys.NOTIF_LEVEL)
    }

    @Test
    fun keychainNativeKeysHaveNoUserDefaultsFallback() {
        // KeyValueStore.ios.kt's NSUserDefaults fallback is gated
        // to this list. These keys are Keychain-NATIVE — they were introduced after
        // the Keychain move and no honest UserDefaults copy has ever existed — so
        // they must stay OUT, or an examiner-writable plist becomes an accepted
        // source for vault control markers (a pending DB-key commit, an armed
        // recovery-enable marker, the Lever B strict-scheme claim, a batch journal
        // whose replay writes arbitrary keys).
        for (k in listOf(
            VaultStoreKeys.PENDING_DBKEY,
            VaultStoreKeys.RECOVERY_PENDING,
            VaultStoreKeys.AUTHBOUND_SCHEME,
            VaultStoreKeys.BATCH_JOURNAL,
        )) {
            assertTrue(
                !IosUserDefaultsKeys.mayHaveLegacyUserDefaultsCopy(k),
                "\"$k\" is Keychain-native — adding it to IosUserDefaultsKeys.all " +
                    "re-opens NSUserDefaults as a source for it (KeyValueStore.ios.kt).",
            )
        }
    }

    @Test
    fun legacyKeysKeepTheirUserDefaultsFallback() {
        // The other half of the gate: these DID have a pre-Keychain era, so a
        // pre-migration install must still be able to read (and migrate) them.
        // vlt_rc especially — dropping its fallback would strand the recovery
        // code of every install provisioned before the Keychain move.
        for (k in listOf(
            VaultStoreKeys.RECOVERY_BLOB,
            VaultStoreKeys.CREDENTIAL_VERIFIER,
            VaultStoreKeys.WRAPPED_DBKEY,
            VaultStoreKeys.CREDENTIAL_MODE,
            VaultStoreKeys.PROTECTION_LEVEL,
            PinAttemptsStore.STORAGE_KEY,
        )) {
            assertTrue(
                IosUserDefaultsKeys.mayHaveLegacyUserDefaultsCopy(k),
                "\"$k\" had a legacy NSUserDefaults copy — removing it from " +
                    "IosUserDefaultsKeys.all breaks migration for pre-Keychain installs.",
            )
        }
    }

    @Test
    fun legacyKeyIsStillInWipeList() {
        // The pre-v2 plaintext counter ("pin_failed_attempts") must continue
        // to be wiped so old installs upgrading through v2 don't carry
        // a stale, unencrypted value that an attacker could probe.
        assertTrue(
            IosUserDefaultsKeys.PIN_FAILED_ATTEMPTS_LEGACY in IosUserDefaultsKeys.all,
            "Legacy pre-v2 PIN-attempts key must remain in the wipe list."
        )
    }
}

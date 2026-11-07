package com.vg.run

import platform.Foundation.NSUserDefaults

// ---------------------------------------------------------------------------
// KeyValueStore — iOS actual implementation backed by the Keychain.
//
// Holds VaultSelector's credential verifier + PIN-wrapped DB key and the
// wrong-PIN counters. All values are already AES-GCM ciphertext (CryptoProvider
// device-AEAD) before they reach here. They previously lived in NSUserDefaults,
// whose plist is included in device backups and lacks a strong file-protection
// class; they now live in the Keychain (via KeychainBridge) under
// kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly — not backed up, readable only
// while the device is unlocked. Reads mostly happen during active use (unlock /
// PIN evaluation / change-PIN), when the device is unlocked — but Keychain reads
// can still fail transiently there (device locks mid-op → errSecInteractionNotAllowed,
// errSecAuthFailed / -34018-class securityd glitches), so "unlocked by definition"
// is NOT a safety argument.
//
// Tri-state reads: getString/contains throw KeyUnavailableException
// when the Keychain read fails with anything other than errSecItemNotFound.
// Collapsing a transient error to "absent" upstream reads as a wrong PIN
// (consumes the 5-attempt wipe budget), as not-configured (first-run setup
// re-provisions OVER the real vault), or as a purgeable legacy install — all
// destructive. Callers already discriminate KeyUnavailableException (defer /
// neutral UnlockResult.Error) on the device-key path; this extends the same
// discipline to the credential/counter reads.
//
// Migration: installs provisioned before this change still have the values in
// NSUserDefaults. getString/contains transparently fall back to NSUserDefaults
// ONLY on a confirmed-absent Keychain read and, on a hit, migrate the value into
// the Keychain, dropping the plaintext-domain copy only after the Keychain write
// reads back (kvPut fails silently on a locked keybag — deleting the legacy copy
// on an unverified write would lose the only remaining copy).
//
// That fallback is GATED to IosUserDefaultsKeys.mayHaveLegacyUserDefaultsCopy.
// It used to apply to EVERY key, which silently made an
// ordinary, examiner-writable plist an accepted source for keys that never had a
// UserDefaults era at all — vlt_cn (pending DB key), vlt_rp (recovery-enable
// marker), vlt_abk (auth-bound scheme) and the batch journal are Keychain-native,
// so answering them from a plist downgrades their storage class from
// kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly to "any file in the container"
// and hands an attacker a write channel into vault control markers. The gate list
// is exactly the set of keys with a real legacy copy, and it is commonTest-locked
// (IosUserDefaultsKeysTest). Every key it EXCLUDES fails toward the safe branch:
// absent vlt_cn = no pending commit, absent vlt_rp = marker not armed, absent
// vlt_abk = "not strict" (a guarded re-mint, never a wipe), absent journal = no
// replay, absent change_pin_attempts_established_v1 = establish-on-read.
// ---------------------------------------------------------------------------

actual class KeyValueStore {
    private val defaults = NSUserDefaults.standardUserDefaults

    private val keychain: KeychainBridge
        get() = KeychainBridgeHolder.bridge
            ?: error("KeychainBridge not registered — register it before using KeyValueStore")

    init {
        // Re-apply a multi-key write left half-done by a crash, before any value
        // is read (see putStringsSync). Bridge ordering guarantees it is already
        // registered (AppState.init registers it before IosAppController, which
        // constructs this); null-safe anyway so construction can never crash.
        KeychainBridgeHolder.bridge?.let { recoverPendingBatch(it) }
    }

    actual fun getString(key: String): String? {
        val res = keychain.kvGet(key)
        res.value?.let { return it }
        if (!res.itemMissing) {
            // Transient Keychain failure — the item may still exist. Returning
            // null here would read as wrong-PIN / not-configured upstream;
            // surface the same typed defer-signal the device-key
            // path uses so callers retry instead of counting/wiping.
            throw KeyUnavailableException("kv read failed for $key (status=${res.status})")
        }
        // Confirmed absent in the Keychain (errSecItemNotFound) — lazy one-time
        // migration from the legacy NSUserDefaults location, but ONLY for the
        // finite set of keys that actually had one (see the header note). A
        // Keychain-native key must never be answerable from a plist.
        if (!IosUserDefaultsKeys.mayHaveLegacyUserDefaultsCopy(key)) return null
        val legacy = defaults.stringForKey(key) ?: return null
        keychain.kvPut(key, legacy)
        // kvPut fails SILENTLY on a locked keybag; only drop the legacy copy
        // once the Keychain write reads back, or this migration would delete
        // the only remaining copy of the credential/counter blob.
        if (keychain.kvGet(key).value == legacy) {
            defaults.removeObjectForKey(key)
            defaults.synchronize()
        }
        return legacy
    }

    actual fun putString(key: String, value: String) = keychain.kvPut(key, value)

    // Same body as putString (SecItemAdd commits synchronously); the split is a
    // contract — see the expect declaration.
    actual fun putStringSync(key: String, value: String) = keychain.kvPut(key, value)

    actual fun putStringsSync(values: Map<String, String>) {
        if (values.isEmpty()) return
        if (values.size == 1) {
            // No journal for one key — and a stale journal from an earlier torn
            // batch is NOT displaced (see the expect kdoc and
            // VaultWriteProofs.singleKeyDbKeyWriteAllowed).
            val (k, v) = values.entries.first()
            keychain.kvPut(k, v)
            return
        }
        // NSUserDefaults gave atomic multi-key writes (whole-plist replace); the
        // Keychain has no multi-item transaction, so a crash between the two
        // change-PIN writes (new verifier + re-wrapped DB key) could leave a
        // verifier whose KEK no longer unwraps the DB key — a bricked vault.
        // Write-ahead journal: persist all pairs in ONE atomic Keychain item,
        // apply them, then drop the journal. recoverPendingBatch() re-applies a
        // journal left by a crash before the next read observes a torn write.
        keychain.kvPut(VaultStoreKeys.BATCH_JOURNAL, encodeBatch(values))
        for ((k, v) in values) keychain.kvPut(k, v)
        // kvPut fails SILENTLY (KeychainHelper returns Void and only
        // logs on a rejected write). Dropping the journal unconditionally after a
        // torn apply would delete the only recovery record and leave a verifier
        // whose KEK no longer unwraps the DB key — a bricked vault. So read every
        // value back and only remove the journal once ALL writes are confirmed
        // persisted; otherwise keep it and recoverPendingBatch re-applies on the
        // next read. Keychain writes are synchronous, so a matching read-back
        // proves the write landed. (Cheap: the change-PIN batch is ~2 keys.)
        val allPersisted = values.all { (k, v) -> keychain.kvGet(k).value == v }
        if (allPersisted) keychain.kvRemove(VaultStoreKeys.BATCH_JOURNAL) else {
            // PROVISION-1 (2026-08-09): this method returns Unit, and it deliberately
            // still does. Making it THROW on a torn apply is the wrong fail direction
            // for its existing callers: the journal above means the write may yet land
            // on the next construction, so a throw would report change-PIN / the KDF
            // migration / the Lever-B finalize as FAILED over a write that succeeds
            // later — the false-FAILURE hazard, which is as destructive as a false
            // success (the user keeps entering a credential that stops working, and
            // those attempts count toward the wipe budget). Each of those callers
            // already decides for itself on positive evidence
            // (credentialWriteRefuted / plainDbKeyReadBackProves / the finalize
            // read-back / storeWriteProven), each with the fail direction that is
            // right for IT.
            //
            // What was missing was that a torn apply left NO trace anywhere. Say so
            // loudly, so the pending journal is visible in a log capture rather than
            // being inferred from a user's next-launch symptoms.
            platformLogWarn(
                "KeyValueStore",
                "multi-key write did not fully persist (${values.size} keys) — journal KEPT " +
                    "for replay on the next launch; the caller decides on its own read-back"
            )
        }
    }

    actual fun contains(key: String): Boolean {
        // Single read primitive (kvGet) so contains/getString can never disagree
        // about the same item; false ONLY on a CONFIRMED-absent read — a
        // transient error throws, because "false" here drives destructive
        // decisions (isConfigured → re-provision, purgeHalfCredentialPairIfNeeded → remove).
        val res = keychain.kvGet(key)
        if (res.value != null) return true
        if (!res.itemMissing) {
            throw KeyUnavailableException("kv presence check failed for $key (status=${res.status})")
        }
        // Same legacy gate as getString: presence may only be inherited from
        // NSUserDefaults for keys that had a pre-Keychain era. Otherwise a
        // planted plist entry could assert the presence of a Keychain-native
        // marker (vlt_cn / vlt_rp / vlt_abk / the batch journal) — e.g. blocking
        // the abandoned-enable purge, or faking a pending-DB-key commit.
        return IosUserDefaultsKeys.mayHaveLegacyUserDefaultsCopy(key) &&
            defaults.objectForKey(key) != null
    }

    actual fun remove(key: String): Boolean {
        // The Keychain half decides the verdict: it is the authoritative store
        // (the NSUserDefaults line below only sweeps a pre-Keychain-era copy,
        // which cannot exist for Keychain-native keys). SecItemDelete on a
        // LOCKED KEYBAG fails, and that failure used to be discarded here — see
        // the expect's @return and DebugMode.setEnabledIn, which now acts on it.
        val removed = keychain.kvRemove(key)
        defaults.removeObjectForKey(key) // also drop any legacy plaintext-domain copy
        defaults.synchronize()
        return removed
    }

    private fun recoverPendingBatch(kc: KeychainBridge) {
        // .value collapses a transient read error to "no journal" — construction
        // must never throw; an unread journal simply defers recovery to the next
        // launch (the journal item itself is untouched).
        val journal = kc.kvGet(VaultStoreKeys.BATCH_JOURNAL).value ?: return
        val entries = decodeBatch(journal)
        entries.forEach { (k, v) -> kc.kvPut(k, v) }
        // Same persist-verify guard as putStringsSync. kvPut fails
        // SILENTLY on a locked keybag, so drop the journal ONLY once every value reads
        // back. A torn recovery would otherwise delete the only recovery record and
        // strand a mismatched verifier vs re-wrapped DB key — an unrecoverable vault.
        val allPersisted = entries.all { (k, v) -> kc.kvGet(k).value == v }
        if (allPersisted) kc.kvRemove(VaultStoreKeys.BATCH_JOURNAL) else platformLogWarn(
            "KeyValueStore",
            "journal replay did not fully persist (${entries.size} keys) — journal KEPT for the next launch"
        )
    }

    private companion object {
        // Flat key\nvalue\nkey\nvalue… — vault keys are bare identifiers and
        // values are base64 (iOS encodes with no line breaks), so neither field
        // can contain the '\n' separator.
        fun encodeBatch(values: Map<String, String>): String =
            values.entries.joinToString("\n") { "${it.key}\n${it.value}" }

        fun decodeBatch(s: String): List<Pair<String, String>> =
            s.split("\n").chunked(2).mapNotNull { if (it.size == 2) it[0] to it[1] else null }
    }
}

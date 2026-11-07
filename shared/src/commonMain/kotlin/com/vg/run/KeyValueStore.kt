package com.vg.run

// ---------------------------------------------------------------------------
// KeyValueStore — platform-agnostic key-value persistence.
//
// On Android: backed by SharedPreferences (reads never fail transiently).
// On iOS: backed by the Keychain (KeychainBridge), which CAN fail transiently
// (locked keybag, securityd glitches). getString/contains there throw
// KeyUnavailableException when a read fails with anything other than
// confirmed-absent — callers on destructive paths (unlock denial counting,
// isConfigured-driven re-provision, legacy purges) MUST catch it and defer,
// never treat it as absent/false.
// ---------------------------------------------------------------------------

// The iOS write-ahead batch journal's key is [VaultStoreKeys.BATCH_JOURNAL]
// (`vlt_txn_journal`), declared in the vault store-key table with the others.

expect class KeyValueStore {
    fun getString(key: String): String?

    /**
     * Persist a value. Both actuals write DURABLY before returning — iOS by
     * construction (SecItemAdd commits synchronously), Android since
     * 2026-07-31: the SharedPreferences `apply()` this used to be snapshots the
     * whole map and flushes it later, so a write issued just before a wipe could
     * land AFTER `deleteSharedPreferences` and re-create the file — vlt_a/vlt_c/
     * vlt_rc restored, dated after the erasure. See the Android actual for the
     * mechanism and for why [ProcessWipeLatch] is deliberately NOT used there.
     *
     * Callers that DEPEND on durability must still say so with [putStringSync] —
     * that is the contract; this is a platform property.
     */
    fun putString(key: String, value: String)

    /**
     * Like [putString] but the CALLER states that it depends on durability.
     * Used for the wrong-PIN counter: the increment must survive
     * a force-quit that happens during the (slow) PIN evaluation, so it
     * cannot be discarded by an async flush.
     *
     * Today both actuals implement [putString] and this identically (Android: one
     * `commit()`; iOS: a synchronous `kvPut`). The split is kept as a CONTRACT, so a
     * future change to [putString] cannot silently weaken a caller that needs this.
     * Neither actual reports a dropped write: Android discards `commit()`'s Boolean,
     * and iOS `kvPut` no-ops silently on a locked keybag — a caller that must KNOW
     * reads the value back (VaultWriteProofs).
     */
    fun putStringSync(key: String, value: String)

    /**
     * Atomically and durably persist several key/value pairs in one shot:
     * either all of them land or none do. Used by every coupled credential-path
     * write in VaultSelector — provision (verifier + wrapped DB key + mode + tier),
     * change-credential (including the `vlt_cn` rotation's batch), the KDF
     * migration, the Lever B finalize and the legacy key-name migration — because a partial write
     * (new verifier, old wrapped key) would leave a credential whose KEK no longer
     * unwraps the SQLCipher passphrase, bricking the vault.
     * On Android this is a single SharedPreferences editor commit(); on iOS the
     * values live in the KEYCHAIN (not NSUserDefaults) and are written under a
     * write-ahead journal ([VaultStoreKeys.BATCH_JOURNAL]) for atomicity — not
     * synchronize()d.
     *
     * iOS: a ONE-entry map short-circuits to a bare `kvPut` — no journal is
     * written, and a STALE journal left by an earlier torn batch is NOT displaced,
     * so that journal's replay at the next construction can still revert this
     * write. That is why a single-key `vlt_c` write gates on
     * [VaultWriteProofs.singleKeyDbKeyWriteAllowed], and why a coupled pair must
     * never be built so that it can shrink to one entry.
     *
     * Returns `Unit` even on a torn iOS apply (the journal is kept for replay, so
     * the write may yet land); each caller proves or refutes the outcome itself.
     */
    fun putStringsSync(values: Map<String, String>)

    fun contains(key: String): Boolean

    /**
     * Delete a value; a no-op when the key is absent, on both platforms. Durable
     * for the same reason [putString] is — a removal here is a security-state
     * transition (dropping `vlt_rc` revokes the second, independent
     * vault-decrypt path), not a hint.
     *
     * @return true when the key is CONFIRMED gone (including "was never
     * there"), false when the platform reported the delete failed — iOS
     * `SecItemDelete` on a locked keybag, an Android `commit()` that returned
     * false. Most callers ignore it; [DebugMode.setEnabledIn] does not, because
     * a silently-refused delete there leaves consent armed for the next launch.
     * A false NEVER means "definitely still there" — it means "not confirmed
     * gone", which is the only reading a caller may act on.
     */
    fun remove(key: String): Boolean
}

/**
 * The five [KeyValueStore] operations [VaultSelector] uses, as an interface commonTest /
 * androidUnitTest can implement — the same constraint [DebugModeStore] and
 * [DeviceKeyCipher] document (an `expect class` whose actuals need a platform handle
 * cannot be constructed in common code). Same names and contracts as the members
 * above, exceptions included ([KeyUnavailableException] passes straight through);
 * [asSelectorStore] is pure delegation.
 */
internal interface SelectorStore {
    fun getString(key: String): String?
    fun contains(key: String): Boolean
    fun putStringSync(key: String, value: String)
    fun putStringsSync(values: Map<String, String>)
    fun remove(key: String): Boolean
}

/** Adapts the platform store for [VaultSelector]'s production constructor. */
internal fun KeyValueStore.asSelectorStore(): SelectorStore {
    val self = this
    return object : SelectorStore {
        override fun getString(key: String): String? = self.getString(key)
        override fun contains(key: String): Boolean = self.contains(key)
        override fun putStringSync(key: String, value: String) = self.putStringSync(key, value)
        override fun putStringsSync(values: Map<String, String>) = self.putStringsSync(values)
        override fun remove(key: String): Boolean = self.remove(key)
    }
}

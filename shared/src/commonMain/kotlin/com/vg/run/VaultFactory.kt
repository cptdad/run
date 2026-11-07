package com.vg.run

// ---------------------------------------------------------------------------
// VaultFactory — creates the VaultDatabase without coupling to the
// platform-specific implementation (DatabaseManager / IosVaultDatabase).
//
// This allows VaultSelector (in commonMain) to create the vault without
// directly referencing platform-only classes.
// ---------------------------------------------------------------------------

/**
 * Thrown by the provision guard when provisioning would overwrite an existing
 * vault database. Never allowed to cross the Swift bridge (Kotlin/Native
 * SIGABRT) — [VaultSelector.setRealCredential]'s Boolean overload converts it to
 * `false`, and the callers already treat `false` as a non-destructive failure.
 */
class ExistingVaultException : RuntimeException(
    "a vault database already exists — refusing to provision over it"
)

/**
 * Thrown when a provision's coupled credential pair
 * (`vlt_a` + `vlt_c`) could not be PROVEN to have persisted — the iOS
 * locked-keybag `kvPut` no-op, or any store fault that leaves one half missing.
 *
 * By the time this is thrown, `VaultSelector.rollBackFailedProvision` has already
 * undone everything the call created (both blobs, the iOS write-ahead journal, and
 * the `run.db` it materialised moments earlier), so the retry the UI offers meets a
 * clean slate rather than the half-state that used to strand the install: `vlt_a`
 * without `vlt_c` → the legacy purge clears both → `isConfigured()` false → the
 * protection-level chooser again on every launch, now over a vault file the
 * provision guard will (correctly) refuse to overwrite.
 *
 * Like [ExistingVaultException] it must never cross the Swift bridge (Kotlin/Native
 * SIGABRT): the Boolean [VaultSelector.setRealCredential] overload converts it to
 * the retryable `false` both setup UIs already handle.
 */
class ProvisionNotPersistedException : RuntimeException(
    "the vault credential pair did not persist — provision rolled back"
)

interface VaultFactory {
    /**
     * [dbKey] is the unwrapped 32-byte SQLCipher passphrase. The caller
     * (VaultSelector) is responsible for deriving it from the user PIN +
     * device key; the vault implementation must NOT derive its own key.
     *
     * [isProvision] is `true` ONLY for the one-time vault-provision open
     * (VaultSelector.provisionCredentialAndVault) and `false` on every unlock. It
     * gates the destructive delete-and-recreate of a "not a database" file: allowed
     * at provision (no real data yet), NEVER on unlock (a corrupt header then sits
     * on a vault full of the user's real data, so unlock must fail closed).
     */
    fun create(dbKey: ByteArray, isProvision: Boolean): VaultDatabase

    /**
     * True when a vault database FILE already exists on disk.
     *
     * The provision guard's independent witness. Every other "is there a vault?"
     * signal routes through the KeyValueStore (`isConfigured`, `credentialsReadable`),
     * and a bad read of THAT store is precisely what sends a provisioned install to
     * first-run setup — the scenario the internals doc calls
     * "provision-over-itself". The filesystem does not share that failure mode, so
     * asking it directly is what makes the guard hold when the store lies.
     *
     * Deliberately NOT defaulted: a default would have to be `false` (guard off) to
     * compile at every call site, which silently disarms the guard on any factory
     * that forgets to implement it. Fail-closed beats convenient.
     *
     * Must probe the SAME path [create] would open, or the guard checks one file
     * while the destructive recreate deletes another.
     */
    fun vaultFileExists(): Boolean

    /**
     * Delete the vault database file and every sidecar
     * (`-wal` / `-shm` / `-journal`) at the SAME path [vaultFileExists] probes and
     * [create] opens. Best-effort and never throws for a file that is not there.
     *
     * **This is the only file-deleting method on this interface, and it has exactly
     * ONE legal caller**: `VaultSelector.rollBackFailedProvision`, undoing a
     * provision that failed AFTER its guard proved no vault file existed — i.e.
     * unlinking a database this same call stack created seconds earlier, keyed with
     * a passphrase that never left that stack's locals and that holds no user data
     * at all. The name says "after failed provision" precisely so a future call site
     * has to type the contract it is breaking.
     *
     * It is NOT a wipe and must never be used as one: a real erase is
     * crypto-erase-FIRST (`WipeRoutine` / `IosAppController.emergencyWipe` destroy
     * the device key and the credential records before any file I/O). It is also not
     * a resolution for the "vault file present, credential absent" dead end in the
     * general case — that state is genuinely ambiguous between this rollback and a
     * REAL vault whose credential is transiently unreadable, which is why the app
     * routes it to the unlock screen's explicit, user-confirmed "Erase and start
     * over" (`VaultSelector.orphanedVaultFile`) instead of deciding on its own.
     */
    fun deleteVaultFileAfterFailedProvision()

    /**
     * True iff [dbKey] actually opens the EXISTING vault file.
     *
     * This is the independent proof that [VaultDatabase.rekey] cannot give you:
     * `rekey` returns `true` on both the commit and the rollback branch of
     * SQLCipher's `sqlite3_rekey_v2` (see its kdoc), so the only way to know
     * which key the file is really on is to open it. Used by the DB-key
     * rotation (`VaultSelector.rotateDbKeyAfterUpgrade`) to decide the outcome.
     *
     * Contract; all four parts are load-bearing:
     *
     *  - **Never creates or provisions.** It carries the unlock path's
     *    `isProvision = false` semantics: a missing or below-
     *    [MIN_VALID_VAULT_DB_BYTES] file answers `false`, it does not become a
     *    fresh empty vault. Both platforms' raw opens have CREATE semantics
     *    (`getWritableDatabase`, `sqlite3_open`), so this guard is what stops a
     *    probe from manufacturing the very file it was asked about.
     *  - **Never deletes.** A wrong key surfaces as SQLITE_NOTADB, the same code
     *    the provision-time delete-and-recreate branch keys on; this path has no
     *    such branch, and Android's `DefaultDatabaseErrorHandler.onCorruption`
     *    returns immediately once `hasCodec()` is true, so even the library's own
     *    corruption handler cannot delete a SQLCipher file.
     *  - **Never throws.** A wrong key is `false`, not an exception.
     *  - **Runs the same cheap verify the normal open path runs** — a
     *    `sqlite_master` read — and additionally requires it to be NON-EMPTY, so
     *    a file that was swapped for a freshly-created empty database between the
     *    size check and the open cannot answer `true`.
     *
     * Note for callers, because the naive reading is wrong: `false` is NOT
     * automatically the safe answer. In a re-key flow "the new key does not open
     * it" and "we could not tell" both arrive as `false`, and acting on the
     * second by keeping the old key is itself a brick if the file really was
     * re-keyed. Resolve ambiguity by probing the OLD key too and only acting when
     * exactly one of the two answers `true`.
     */
    fun probeKey(dbKey: ByteArray): Boolean

    // -----------------------------------------------------------------------
    // Raw-key ADOPTION (Android, 2026-10-07). See `docs/vault-relay-internals.md`
    // ("Android adopts SQLCipher's raw-key mode without a rekey").
    //
    // Android opens SQLCipher in PASSPHRASE mode: [create]/[probeKey] hand it the
    // 32-byte dbKey, which SQLCipher stretches with PBKDF2-HMAC-SHA512 × 256 000
    // on every open (2.08 s per unlock measured on a Samsung A13). "Adopting" a
    // vault means computing ONCE the key that stretch produces for this file
    // (K' = PBKDF2(dbKey, file salt)) and opening with it as a raw key from then
    // on — the file is byte-for-byte the same, nothing is re-encrypted.
    //
    // Every member below is DEFAULTED TO "UNSUPPORTED", and that default is the
    // fail-safe direction (unlike [vaultFileExists], whose default would disarm
    // a guard): a factory that does not implement adoption simply never adopts,
    // and VaultSelector's unlock always falls back to [create]. iOS uses these
    // defaults on purpose — it already opens in raw-key mode with the dbKey
    // itself (`x'<hex dbKey>'`), so it has no stretch to skip.
    // -----------------------------------------------------------------------

    /**
     * True when this factory implements adoption at all. A cheap, I/O-free gate
     * so a non-adopting platform (iOS) pays no extra store reads at unlock.
     */
    fun supportsRawKeyAdoption(): Boolean = false

    /**
     * K' for the EXISTING vault file — the raw key SQLCipher derives from
     * [dbKey] in passphrase mode with the salt stored in the file header — or
     * null when this platform does not adopt, or the salt cannot be read.
     *
     * A computation, never evidence: the caller must still prove K' with
     * [probeRawKey] against the real file before persisting it anywhere.
     */
    fun deriveAdoptedRawKey(dbKey: ByteArray): ByteArray? = null

    /**
     * Open the EXISTING vault with the adopted raw key [rawKey] (unlock
     * semantics only: `isProvision = false`, never creates, never deletes — the
     * same fail-closed guards [create] applies on unlock). Throws on any
     * failure, exactly like [create]. The default throws: a factory that never
     * hands out raw keys can never be asked to open with one, and if it ever is,
     * the caller's fallback to [create] takes over.
     */
    fun createWithRawKey(rawKey: ByteArray): VaultDatabase =
        throw UnsupportedOperationException("raw-key adoption not supported by this VaultFactory")

    /**
     * [probeKey]'s raw-key twin: true iff [rawKey] opens the existing file. Same
     * four-part contract (never creates, never deletes, never throws, non-empty
     * `sqlite_master`). Default `false` — "does not open" is the answer that
     * keeps a vault in its current mode.
     */
    fun probeRawKey(rawKey: ByteArray): Boolean = false
}

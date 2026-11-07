package com.vg.run

// ---------------------------------------------------------------------------
// VaultWriteProofs — the pure "did that store write land?" predicates and the
// failed-provision rollback lists.
//
// ProvisionWriteGuardTest pins the order of PROVISION_ROLLBACK_KEYS, and the
// order is the safety argument.
//
// The predicates deliberately have DIFFERENT fail directions and must not be
// harmonised (docs/vault-relay-internals.md, "iOS multi-key writes must be
// journalled" and "The provision itself is now ATOMIC and VERIFIED"):
//   - [plainDbKeyReadBackProves], [storeWriteProven],
//     [mayDeleteVaultFileAfterRollback] — PROOF REQUIRED: ambiguity answers false.
//   - [credentialWriteRefuted] — REFUTE ONLY ON EVIDENCE: ambiguity answers false
//     too, but false here means "keep the original report".
//   - [singleKeyDbKeyWriteAllowed] — only a CONFIRMED-absent journal permits.
// ---------------------------------------------------------------------------

internal object VaultWriteProofs {
    /**
     * May the recovery blob be DELETED now?
     *
     * Only on POSITIVE proof that the plain (non-auth-bound) DB-key blob the
     * caller just wrote is really in the store. [readBack] null (absent, or a
     * read that could not decide) ⇒ false: deleting the recovery blob is
     * IRREVERSIBLE and, if the write silently no-op'd (iOS `kvPut` on a locked
     * keybag returns without writing while `kvRemove` — a bare SecItemDelete
     * needing no class key — still succeeds), it strands an `ab:` blob wrapped
     * by an already-dead hardware key with its only recovery path gone:
     * permanently unopenable. Keeping a recovery blob is never a brick.
     */
    internal fun plainDbKeyReadBackProves(readBack: String?, isAuthBound: (String) -> Boolean): Boolean =
        readBack != null && !isAuthBound(readBack)

    /**
     * May a SINGLE-KEY credential-path write of
     * [VaultStoreKeys.WRAPPED_DBKEY] proceed right now?
     *
     * The iOS write-ahead journal ([VaultStoreKeys.BATCH_JOURNAL]) is REPLAYED at the
     * next `KeyValueStore` construction, and a torn batch keeps its journal on
     * purpose (see `putStringsSync`) — so a journal left behind by an earlier
     * `putStringsSync` still holds that batch's `vlt_c` and will write it back
     * at a LATER launch. A single-key `putStringSync(vlt_c, …)` issued in
     * between is therefore NOT durable: it reads back (the Keychain item really
     * did change), passes [plainDbKeyReadBackProves], and is then silently
     * REVERTED by the replay. The two writers that act on that read-back are
     * irreversible — `setDbKeyAuthBinding(false)` and `recoverWithCodeInner`
     * both delete [VaultStoreKeys.RECOVERY_BLOB] once the plain blob "landed", so the
     * replay restores an `ab:` blob whose hardware key may already be dead,
     * with its only recovery path gone. Permanent brick.
     *
     * Batch writers need no guard: `putStringsSync` OVERWRITES the journal with
     * its own contents before applying, so it cannot be reverted to an older
     * batch. It is only the single-key path that has nothing to displace a
     * stale journal.
     *
     * Tri-state input, and only one answer permits the write:
     *  - `false` — journal CONFIRMED absent ⇒ allowed.
     *  - `true`  — a journal is pending ⇒ refuse.
     *  - `null`  — the store could not tell (transient Keychain/prefs failure)
     *              ⇒ refuse, for the same reason [VaultSelector.plainDbKeyCommitted] fails
     *              toward keeping the recovery blob: "could not tell" must never
     *              authorise an irreversible delete.
     *
     * Refusing is brick-SAFE by construction: it changes nothing, so the vault
     * is left exactly as openable as it was (auth-bound blob + live recovery
     * blob, or the pre-recovery state), and the caller reports failure. It is
     * also self-healing — `recoverPendingBatch` clears the journal on the next
     * construction once the keybag is unlocked, so the refusal lasts at most
     * until the next launch. This is the same guard, in the same direction, that
     * `purgeAbandonedRecoveryEnable` already applies for the same reason.
     *
     * Android's actual has no journal, so `contains` there is a plain prefs
     * lookup that answers `false` and this is a no-op on that platform.
     */
    internal fun singleKeyDbKeyWriteAllowed(journalPending: Boolean?): Boolean =
        journalPending == false

    /**
     * Is there POSITIVE evidence that a just-issued
     * credential batch did NOT persist?
     *
     * The opposite fail direction to [plainDbKeyReadBackProves], deliberately.
     * Here BOTH answers are destructive if wrong: reporting SUCCESS over a
     * silently-dropped write leaves the user entering a PIN the app said it had
     * set (each wrong entry counts toward the wipe budget), and reporting FAILURE
     * over a write that DID land leaves them entering the old one with the same
     * consequence. So it refutes only on evidence — a value read back that is
     * confirmed different or confirmed absent — and never on an ambiguous read
     * (transient outage), which keeps the original report.
     *
     * Note the platform asymmetry this can and cannot see: on iOS `kvGet` is a
     * real Keychain read, so a locked-keybag no-op is caught. On Android
     * `getString` reads the in-memory map that `commit()` already updated, so a
     * failed DISK write still reads back — that is out of reach here and stays a
     * known limitation, not a false positive.
     */
    internal fun credentialWriteRefuted(
        expected: Map<String, String>,
        readBack: (String) -> String?,
    ): Boolean = try {
        expected.any { (key, value) -> readBack(key) != value }
    } catch (_: Exception) {
        false
    }

    /**
     * Did a store write read back?
     *
     * **Read the name as iOS-PROOF / Android-BEST-EFFORT, not as an unqualified
     * guarantee.** `true` means "every value read back verbatim through
     * [readBack]", and how much that proves is PLATFORM-DEPENDENT: on iOS
     * `getString` is a real Keychain round-trip, so a locked-keybag `kvPut`
     * no-op — the drop this whole change exists for — is genuinely caught; on
     * Android `getString` reads the SharedPreferences IN-MEMORY map that
     * `commit()` has already updated, so a failed DISK commit still reads back
     * and `true` there means only "the editor accepted it". That Android gap is
     * a known limitation, not a false positive, and it is covered by different
     * means: the batch is one atomic editor `commit()` rather than several
     * independent writes, and the actual now logs loudly when `commit()` returns
     * `false` (the only drop signal the platform offers). `false`, by contrast,
     * is trustworthy on both platforms.
     *
     * The DELIBERATE INVERSE of [credentialWriteRefuted], and the difference is
     * the whole point. THERE, a vault already exists and the user is entering
     * credentials against it, so both wrong answers are destructive and
     * ambiguity must refute NOTHING. HERE the write is one nothing depends on
     * yet — the first-run credential pair, or the protection tier — and the only
     * thing a false SUCCESS can produce is a state the app then treats as
     * permanent. Both shipped that way:
     *
     *  - the coupled `vlt_a` + `vlt_c` pair. iOS `kvPut` no-ops on a locked
     *    keybag and [KeyValueStore.putStringsSync] returns `Unit` regardless, so
     *    `vlt_a` could land without `vlt_c`. Next launch: hasCreds && !hasDbKeys
     *    → [VaultSelector.purgeHalfCredentialPairIfNeeded] clears the whole credential set →
     *    `isConfigured()` false → first-run setup again, over a `run.db`
     *    provisioning already materialised.
     *  - `vlt_lvl` ([VaultSelector.setProtectionLevel]). A dropped tier reads as "no level
     *    ever chosen", which is exactly the condition the one-time chooser and
     *    the forced-migration route trip on — so the user is sent through the
     *    protection chooser on EVERY unlock, and every pass silently drops the
     *    write again.
     *
     * So ambiguity here is NOT proof, and anything short of every value reading
     * back verbatim is reported to the caller as a failure. Failing that
     * direction costs one retry; the other direction costs the install.
     *
     * A read that THROWS (transient iOS Keychain outage) is likewise not proof —
     * the same conservative direction, for the same reason. See the header note
     * above for exactly how far a `true` reaches on each platform.
     */
    internal fun storeWriteProven(
        expected: Map<String, String>,
        readBack: (String) -> String?,
    ): Boolean = try {
        expected.isNotEmpty() && expected.all { (key, value) -> readBack(key) == value }
    } catch (_: Exception) {
        false
    }

    /**
     * The keys a FAILED provision rolls back, IN ORDER.
     *
     * The order is the safety argument, not cosmetics:
     *
     *  1. [VaultStoreKeys.BATCH_JOURNAL] FIRST. On iOS a torn `putStringsSync` leaves
     *     its write-ahead journal in place on purpose, and `recoverPendingBatch`
     *     re-applies it at the NEXT `KeyValueStore` construction. Removing the
     *     two blobs while that journal survives would let a later launch
     *     RESURRECT the credential pair over the `run.db` this rollback is about
     *     to delete — `isConfigured()` true, vault file gone, every unlock stuck
     *     on the fail-closed missing-DB guard forever, and `orphanedVaultFile()`
     *     false so the rescue screen never appears. Dropping the journal first
     *     makes every later step final. Safe to drop: the guard above proved no
     *     vault file existed when this provision started, so any journal that
     *     survived construction can only describe credentials that open nothing.
     *  2. the credential pair. Crypto-erase-first: the wrapped DB key record
     *     goes before the file it unwraps, so no interruption can leave a usable
     *     key record pointing at a file we are deleting.
     *
     *  3. the two selector-meta values this provision wrote. Pure metadata: the
     *     next provision rewrites both, and neither can open anything. They are
     *     here only so "clean slate" is literally true — the same set
     *     [VaultSelector.purgeHalfCredentialPairIfNeeded] already clears alongside a half credential pair.
     *
     * Every interruption point in that sequence lands on a state the app already
     * handles: a lone `vlt_a` is cleared by [VaultSelector.purgeHalfCredentialPairIfNeeded]; a vault file
     * with no credential is [VaultSelector.orphanedVaultFile], which routes to the unlock
     * screen's explicit "Erase and start over". None of them is a wipe.
     */
    internal val PROVISION_ROLLBACK_KEYS: List<String> = listOf(
        VaultStoreKeys.BATCH_JOURNAL,
        VaultStoreKeys.CREDENTIAL_VERIFIER,
        VaultStoreKeys.WRAPPED_DBKEY,
        VaultStoreKeys.CREDENTIAL_MODE,
        VaultStoreKeys.PROTECTION_LEVEL,
    )

    /**
     * The keys whose survival FORBIDS
     * the rollback from unlinking the vault file.
     *
     * THE INVERTED HAZARD this closes. Every removal in the rollback is issued
     * fire-and-forget: iOS `kvRemove` is a bare `SecItemDelete` whose `OSStatus`
     * is DISCARDED (`KeychainHelper.kvRemove`). That is normally the reliable
     * direction — a delete needs no class key — but "normally" is not "provably",
     * and the failure it can produce is worse than the one the rollback exists
     * for. If the vault file goes while any of these survives, the next launch
     * reads **configured WITHOUT a database**:
     *
     *  - a surviving `vlt_a` + `vlt_c` pair, or
     *  - a surviving write-ahead JOURNAL, which `recoverPendingBatch` replays at
     *    the next `KeyValueStore` construction and which therefore RESURRECTS
     *    that pair after the fact.
     *
     * `isConfigured()` then answers true over a missing `run.db`, so every unlock
     * hits the fail-closed missing-DB guard and returns the neutral, NON-COUNTING
     * `UnlockResult.Error` — forever. And nothing rescues it: `orphanedVaultFile()`
     * is `vaultFileExists() && !isConfigured()`, i.e. exactly the OPPOSITE
     * asymmetry, so the unlock screen never offers "Erase and start over" either.
     *
     * So the file delete is CONDITIONAL on proving all of these gone, and the
     * proof must fail toward NOT deleting — see [mayDeleteVaultFileAfterRollback].
     * Keeping the file is always the safe side: it degrades to a state the app
     * already handles (a working vault if the journal replays in full, otherwise
     * `orphanedVaultFile()` and the confirmed erase), and it never loses data,
     * because the only file at that path is the empty one this provision just
     * created.
     *
     * The selector-meta keys are deliberately NOT here: neither can make
     * `isConfigured()` true, so neither can produce the inverted state.
     */
    internal val PROVISION_FILE_DELETE_BLOCKERS: List<String> = listOf(
        VaultStoreKeys.BATCH_JOURNAL,
        VaultStoreKeys.CREDENTIAL_VERIFIER,
        VaultStoreKeys.WRAPPED_DBKEY,
    )

    /**
     * May the rollback unlink the freshly created vault
     * file now?
     *
     * Only on POSITIVE proof that every [PROVISION_FILE_DELETE_BLOCKERS] key is
     * CONFIRMED ABSENT. [present] is a presence probe that may THROW on an
     * ambiguous read (iOS `contains` raises [KeyUnavailableException] on anything
     * that is not a confirmed-absent Keychain read) — and an ambiguous read is
     * not proof, so it answers `false` and the file stays.
     *
     * Same fail direction as [storeWriteProven] and for a sharper reason: here
     * the two mistakes are NOT symmetric. Keeping the file costs at worst one
     * confirmed "Erase and start over" tap on a database that holds nothing;
     * deleting it while a credential record survives (or a journal can replay one
     * back) is the permanent configured-without-a-database dead end described on
     * [PROVISION_FILE_DELETE_BLOCKERS], which no screen in the app can escape.
     */
    internal fun mayDeleteVaultFileAfterRollback(present: (String) -> Boolean): Boolean = try {
        PROVISION_FILE_DELETE_BLOCKERS.none { present(it) }
    } catch (_: Exception) {
        false
    }
}

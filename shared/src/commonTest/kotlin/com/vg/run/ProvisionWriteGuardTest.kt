package com.vg.run

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// PROVISION-1 (2026-08-09) — the provision / protection-level write gate.
//
// THE FIELD BUG. `provisionCredentialAndVault` persisted the credential verifier
// (`vlt_a`) and the wrapped SQLCipher key (`vlt_c`) as TWO independent,
// un-journalled, un-verified `putString` calls, and `setProtectionLevel`
// persisted the tier (`vlt_lvl`) as one unverified `putStringSync`. All three
// reach iOS `KeychainHelper.kvPut`, which is fire-and-forget AND fail-closed: if
// the strict `WhenPasscodeSet` add fails while `deviceHasPasscode()` transiently
// answers true, the `AfterFirstUnlock` fallback is SKIPPED and the item is
// silently dropped. The caller is told nothing. Two self-re-arming loops follow:
//
//   • dropped `vlt_c` → next launch has hasCreds && !hasDbKeys →
//     purgeHalfCredentialPairIfNeeded() removes the whole credential set → isConfigured()
//     false → first-run setup AGAIN — now over a `run.db` the failed provision
//     already materialised, which the provision guard then (correctly) refuses.
//   • dropped `vlt_lvl` → reads as "no tier ever chosen" → the one-time chooser
//     and DeviceLockPolicy.needsForcedMigration re-trip on EVERY unlock, and
//     every pass reports success while dropping the write again.
//
// KeyValueStore and CryptoProvider are expect classes with no common fake seam,
// so — exactly as VaultSelectorGuardTest / SelectorMetaGuardTest / VaultKdfTest
// already do — this pins the extracted PURE decision units plus a faithful
// simulation of the sequence they drive. The real wiring (AEAD blobs, real store,
// real SQLCipher file) stays in the instrumented androidApp VaultSelectorTest.
// ---------------------------------------------------------------------------

class ProvisionWriteGuardTest {

    private companion object {
        const val CRED = "vlt_a"
        const val DBKEY = "vlt_c"
        const val MODE = "vlt_m"
        const val LEVEL = "vlt_lvl"
        const val JOURNAL = "vlt_txn_journal"

        /** What one provision hands to `putStringsSync`. */
        fun provisionBatch() = mapOf(
            CRED to "cred-blob-v3",
            DBKEY to "dbkey-blob-plain",
            MODE to "mode-blob",
            LEVEL to "level-blob",
        )
    }

    /**
     * A KeyValueStore stand-in that can DROP designated writes, the way iOS
     * `kvPut` silently does on a locked keybag. Deliberately reproduces the iOS
     * shape, because that is where the bug lives:
     *
     *  - `putStringsSync` writes a write-ahead journal, applies each pair
     *    (skipping the dropped ones), and only removes the journal once EVERY
     *    value reads back. It returns Unit either way — that is precisely the
     *    "returns success on a dropped write" property Part B verified and the
     *    reason the caller must do its own read-back.
     *  - `remove` usually succeeds even for keys `put` would drop (on iOS `kvRemove`
     *    is a bare `SecItemDelete` needing no class key), but [removeFailing] can
     *    make one silently no-op: `kvRemove` DISCARDS its `OSStatus`, so "removals
     *    are reliable" is an argument rather than evidence, and the rollback must
     *    not bet the vault file on it.
     */
    private class DroppingStore {
        val data = mutableMapOf<String, String>()
        val dropped = mutableSetOf<String>()
        val removeFailing = mutableSetOf<String>()

        fun getString(key: String): String? = data[key]
        fun contains(key: String): Boolean = data.containsKey(key)

        fun putStringsSync(values: Map<String, String>) {
            if (values.isEmpty()) return
            data[JOURNAL] = values.entries.joinToString("\n") { "${it.key}\n${it.value}" }
            for ((k, v) in values) if (k !in dropped) data[k] = v
            if (values.all { (k, v) -> data[k] == v }) data.remove(JOURNAL)
        }

        fun putStringSync(key: String, value: String) {
            if (key !in dropped) data[key] = value
        }

        fun remove(key: String) {
            if (key in removeFailing) return   // silent no-op, exactly like a discarded OSStatus
            data.remove(key)
        }

        /** `isConfigured()`: BOTH credential blobs present. */
        fun configured(): Boolean = contains(CRED) && contains(DBKEY)
    }

    /**
     * The NEXT LAUNCH: `KeyValueStore.init` → `recoverPendingBatch`, which re-applies
     * a surviving write-ahead journal before any value is read. This is the step that
     * makes a stuck journal dangerous — it can put the credential pair back long
     * after the rollback thought it was done.
     */
    private fun simulateNextLaunchJournalReplay(store: DroppingStore) {
        val journal = store.getString(JOURNAL) ?: return
        val entries = journal.split("\n").chunked(2).mapNotNull { if (it.size == 2) it[0] to it[1] else null }
        for ((k, v) in entries) if (k !in store.dropped) store.data[k] = v
        if (entries.all { (k, v) -> store.data[k] == v }) store.remove(JOURNAL)
    }

    /**
     * The provision sequence under test, reduced to the decisions that matter:
     * batch → read-back gate → (on failure) roll back the documented key set and
     * unlink the freshly created vault file. Returns true when the provision
     * would report SUCCESS.
     */
    private fun simulateProvision(store: DroppingStore, vaultFile: BooleanArray): Boolean {
        // The provision guard: never provision over an existing vault file.
        if (vaultFile[0]) throw ExistingVaultException()
        // vaultFactory.create(dbKey, isProvision = true) materialises run.db first.
        vaultFile[0] = true
        val batch = provisionBatch()
        store.putStringsSync(batch)
        if (VaultWriteProofs.storeWriteProven(batch) { store.getString(it) }) return true
        // rollBackFailedProvision(): documented key order, then the CONDITIONAL file
        // unlink — only once the store is proven clean.
        VaultWriteProofs.PROVISION_ROLLBACK_KEYS.forEach { store.remove(it) }
        if (VaultWriteProofs.mayDeleteVaultFileAfterRollback { store.contains(it) }) vaultFile[0] = false
        return false
    }

    // -- the pure gate ---------------------------------------------------------

    @Test
    fun healthyBatch_isProven() {
        // No false positives: an ordinary provision still reports success.
        val batch = provisionBatch()
        assertTrue(VaultWriteProofs.storeWriteProven(batch) { batch[it] })
    }

    @Test
    fun droppedWrappedDbKey_isNotProven() {
        // THE shipped failure: `vlt_a` lands, `vlt_c` is silently dropped.
        val landed = provisionBatch() - DBKEY
        assertFalse(
            VaultWriteProofs.storeWriteProven(provisionBatch()) { landed[it] },
            "a dropped vlt_c must never be reported as a successful provision",
        )
    }

    @Test
    fun droppedCredentialVerifier_isNotProven() {
        // The mirror half, which purgeHalfCredentialPairIfNeeded does NOT clean up (it only
        // fires on creds-without-dbkey), so it would strand a live wrap for a
        // vault nothing can open.
        val landed = provisionBatch() - CRED
        assertFalse(VaultWriteProofs.storeWriteProven(provisionBatch()) { landed[it] })
    }

    @Test
    fun droppedProtectionLevel_isNotProven() {
        // The chooser loop: absent vlt_lvl reads as "no tier ever chosen".
        val landed = provisionBatch() - LEVEL
        assertFalse(VaultWriteProofs.storeWriteProven(provisionBatch()) { landed[it] })
    }

    @Test
    fun droppedCredentialMode_isNotProven() {
        // Absent vlt_m reads as PIN mode. On a MAXIMUM/passphrase vault that
        // renders the 6-digit keypad, whose entries can never be the real
        // credential (Lever A's >=70-bit floor) — every one durably counted, and
        // MAXIMUM's budget of 5 emergency-wipes a vault with no recovery code.
        val landed = provisionBatch() - MODE
        assertFalse(VaultWriteProofs.storeWriteProven(provisionBatch()) { landed[it] })
    }

    @Test
    fun staleValue_isNotProven() {
        // A leftover from an earlier aborted attempt is not this attempt's write.
        val stale = provisionBatch() + (DBKEY to "dbkey-blob-from-a-previous-try")
        assertFalse(VaultWriteProofs.storeWriteProven(provisionBatch()) { stale[it] })
    }

    @Test
    fun ambiguousReadBack_isNotProven() {
        // The fail direction that separates this from credentialWriteRefuted: there,
        // a transient outage must refute NOTHING because a false failure is as
        // destructive as a false success. Here nothing depends on the write yet, so
        // "cannot tell" is not proof and the provision is rolled back and retried.
        assertFalse(
            VaultWriteProofs.storeWriteProven(provisionBatch()) { throw KeyUnavailableException("keybag locked") },
        )
        assertFalse(
            VaultWriteProofs.storeWriteProven(provisionBatch()) { throw IllegalStateException("store fault") },
        )
    }

    @Test
    fun emptyBatch_isNotProven() {
        // Degenerate guard: "nothing was asked for" must not read as "it landed".
        assertFalse(VaultWriteProofs.storeWriteProven(emptyMap()) { "anything" })
    }

    // -- the rollback key set + order -----------------------------------------

    @Test
    fun rollbackCoversEveryKeyTheProvisionBatchCanWrite() {
        // Coupling guard: any key added to the provision batch MUST be added to the
        // rollback list, or a failed provision leaves it behind and the "clean
        // slate" the retry depends on is a lie.
        for (key in provisionBatch().keys) {
            assertTrue(
                key in VaultWriteProofs.PROVISION_ROLLBACK_KEYS,
                "$key is written by the provision batch but never rolled back",
            )
        }
    }

    @Test
    fun rollbackDropsTheWriteAheadJournalFIRST() {
        // Load-bearing ordering. On iOS a torn putStringsSync deliberately KEEPS its
        // journal, and recoverPendingBatch re-applies it at the next KeyValueStore
        // construction. Removing the blobs while the journal survives would let a
        // LATER launch resurrect the credential pair over the run.db this rollback
        // just deleted: isConfigured() true, vault file gone, every unlock stuck on
        // the fail-closed missing-DB guard, and orphanedVaultFile() false so the
        // "Erase and start over" rescue never appears. Journal first makes every
        // later step final.
        assertEquals(
            "vlt_txn_journal",
            VaultWriteProofs.PROVISION_ROLLBACK_KEYS.first(),
            "the write-ahead journal must be dropped before anything it could replay",
        )
        // Crypto-erase-first: the wrapped DB-key record is removed by this list,
        // i.e. BEFORE the caller unlinks the file it unwraps — never after.
        assertTrue(
            DBKEY in VaultWriteProofs.PROVISION_ROLLBACK_KEYS,
            "the wrapped DB key must be destroyed before the file it opens",
        )
        assertContentEquals(
            listOf(JOURNAL, CRED, DBKEY, MODE, LEVEL),
            VaultWriteProofs.PROVISION_ROLLBACK_KEYS,
            "the rollback set is pinned: extend it deliberately, together with the batch",
        )
    }

    // -- end-to-end state machine ---------------------------------------------

    @Test
    fun droppedDbKey_provisionFails_leavesNoHalfState_andACleanRetrySucceeds() {
        val store = DroppingStore()
        val vaultFile = booleanArrayOf(false)
        store.dropped += DBKEY

        assertFalse(simulateProvision(store, vaultFile), "the provision must report failure")

        // Nothing half-written: no lone verifier for purgeHalfCredentialPairIfNeeded to find, no
        // orphan tier, and — the one that used to wedge the install — no journal
        // waiting to replay the pair back in on a later launch.
        assertTrue(store.data.isEmpty(), "leftovers after rollback: ${store.data.keys}")
        assertFalse(vaultFile[0], "the run.db this call created must be gone")

        // The retry meets a CLEAN slate: the provision guard does not trip, and with
        // the keybag healthy the whole batch lands.
        store.dropped.clear()
        assertTrue(simulateProvision(store, vaultFile), "the retry must succeed")
        assertEquals(provisionBatch(), store.data.toMap())
        assertTrue(vaultFile[0])
    }

    @Test
    fun droppedCredentialVerifier_behavesIdentically() {
        val store = DroppingStore()
        val vaultFile = booleanArrayOf(false)
        store.dropped += CRED

        assertFalse(simulateProvision(store, vaultFile))
        assertTrue(store.data.isEmpty(), "leftovers after rollback: ${store.data.keys}")
        assertFalse(vaultFile[0])

        store.dropped.clear()
        assertTrue(simulateProvision(store, vaultFile))
        assertEquals(provisionBatch(), store.data.toMap())
    }

    @Test
    fun withoutTheRollback_theRetryWouldTripTheProvisionGuardForever() {
        // The regression this whole change exists to prevent, demonstrated: leave the
        // run.db behind (pre-PROVISION-1 behaviour) and the SECOND attempt no longer
        // reaches the store at all — it is refused by the guard, with no clean-up
        // path of its own. That is the infinite setup-fail loop from the field.
        val store = DroppingStore()
        val vaultFile = booleanArrayOf(false)
        store.dropped += DBKEY

        // Pre-fix simulation: the file is materialised and never removed.
        vaultFile[0] = true
        var refused = false
        try {
            simulateProvision(store, vaultFile)
        } catch (_: ExistingVaultException) {
            refused = true
        }
        assertTrue(refused, "with the stale file present the guard refuses — correctly, and forever")

        // With the rollback the same guard is simply never reached: no stale file.
        vaultFile[0] = false
        assertFalse(simulateProvision(store, vaultFile))
        assertFalse(vaultFile[0])
        store.dropped.clear()
        assertTrue(simulateProvision(store, vaultFile), "no guard trip on the retry")
    }

    // -- the file-delete gate + the NEXT LAUNCH's journal replay ---------------

    @Test
    fun fileDeleteGate_needsPositiveProof_andAmbiguityKeepsTheFile() {
        // Ambiguity is not proof (iOS `contains` THROWS on anything that is not a
        // confirmed-absent Keychain read), and neither is a surviving blocker.
        assertTrue(VaultWriteProofs.mayDeleteVaultFileAfterRollback { false },
            "all blockers confirmed absent is the one state where the unlink is safe")
        assertFalse(VaultWriteProofs.mayDeleteVaultFileAfterRollback { it == JOURNAL },
            "a surviving journal can replay the credential pair back — keep the file")
        assertFalse(VaultWriteProofs.mayDeleteVaultFileAfterRollback { it == CRED })
        assertFalse(VaultWriteProofs.mayDeleteVaultFileAfterRollback { it == DBKEY })
        assertFalse(
            VaultWriteProofs.mayDeleteVaultFileAfterRollback { throw KeyUnavailableException("keybag locked") },
            "an ambiguous presence read is not proof — the file stays",
        )
        // The selector-meta keys are deliberately NOT blockers: neither can make
        // isConfigured() true, so neither can produce the inverted dead end.
        assertTrue(VaultWriteProofs.mayDeleteVaultFileAfterRollback { it == MODE || it == LEVEL })
    }

    @Test
    fun cleanRollback_leavesTheNextLaunchNothingToResurrect() {
        val store = DroppingStore()
        val vaultFile = booleanArrayOf(false)
        store.dropped += DBKEY

        assertFalse(simulateProvision(store, vaultFile))
        assertFalse(vaultFile[0], "a proven-clean store licenses the unlink")

        // The step that used to be invisible: the NEXT KeyValueStore construction.
        simulateNextLaunchJournalReplay(store)

        assertTrue(store.data.isEmpty(), "nothing may come back: ${store.data.keys}")
        assertFalse(store.configured(), "a fresh install, not a configured one")
        assertFalse(vaultFile[0])
        // Routing (isConfigured || vaultFileExists) → first-run setup. Clean.
    }

    @Test
    fun stuckJournal_keepsTheVaultFile_soTheReplayLandsOnTheEraseHatch() {
        // The refuted-but-worth-closing hazard. `kvRemove` discards its OSStatus, so
        // the journal delete can silently no-op while every other step succeeds.
        val store = DroppingStore()
        val vaultFile = booleanArrayOf(false)
        store.dropped += DBKEY            // the write that tore the batch
        store.removeFailing += JOURNAL    // …and the rollback step that silently failed

        assertFalse(simulateProvision(store, vaultFile))
        assertTrue(vaultFile[0],
            "an unprovable journal removal must BLOCK the unlink — the file stays")
        assertTrue(store.contains(JOURNAL), "precondition: the journal really did survive")

        // Next launch replays it. vlt_c is still being dropped, so only part returns.
        simulateNextLaunchJournalReplay(store)
        assertTrue(store.contains(CRED), "the replay resurrects what it can")
        assertFalse(store.configured(), "…but not the full pair")

        // THE PROPERTY: file present + not configured ⇒ orphanedVaultFile() ⇒ the
        // unlock screen's confirmed "Erase and start over". A recoverable dead end.
        assertTrue(vaultFile[0] && !store.configured(),
            "must land on orphanedVaultFile(), which the erase hatch covers")
    }

    @Test
    fun unconditionalDelete_wouldHaveProducedTheUNESCAPABLEState() {
        // The counterfactual that makes the gate worth its lines. Same stuck journal,
        // but the file is unlinked unconditionally (the pre-tightening behaviour) and
        // the keybag recovers before the next launch, so the journal replays IN FULL.
        val store = DroppingStore()
        store.dropped += DBKEY
        store.removeFailing += JOURNAL
        val vaultFile = booleanArrayOf(false)

        vaultFile[0] = true
        store.putStringsSync(provisionBatch())
        VaultWriteProofs.PROVISION_ROLLBACK_KEYS.forEach { store.remove(it) }
        vaultFile[0] = false               // <- unconditional unlink

        store.dropped.clear()              // the keybag recovers
        simulateNextLaunchJournalReplay(store)

        assertTrue(store.configured(), "the journal replayed the whole credential pair back")
        assertFalse(vaultFile[0], "…over a run.db that is gone")
        // isConfigured() true + no database ⇒ every unlock hits the fail-closed
        // missing-DB guard and returns the neutral, NON-COUNTING Error, forever; and
        // orphanedVaultFile() is (file present && !configured), the exact inverse, so
        // the erase hatch never appears. Nothing in the app escapes this.
        assertFalse(vaultFile[0] && !store.configured(),
            "orphanedVaultFile() does NOT catch the inverted state — hence the gate")
    }

    // -- PART E: the protection-tier write ------------------------------------

    @Test
    fun droppedProtectionLevelWrite_surfacesAsFailure_notSilentSuccess() {
        // setProtectionLevel's shape: single putStringSync, then the same gate.
        // Every shipped caller (ProtectionLevelSettingsScreen /
        // ProtectionLevelMigrationScreen on Android, ProtectionLevelView's
        // persistFailed on iOS) already aborts its apply on false, so surfacing the
        // drop needs no call-site change — and NOT surfacing it marched the user
        // through the chooser on every single unlock.
        val store = DroppingStore()
        store.dropped += LEVEL
        val blob = "level-blob-maximum"

        store.putStringSync(LEVEL, blob)
        assertFalse(
            VaultWriteProofs.storeWriteProven(mapOf(LEVEL to blob)) { store.getString(it) },
            "a dropped vlt_lvl must be reported as a failed persist",
        )

        // Control: the same write on a healthy store is proven, so the assertion
        // above is pinning the drop and not the mechanism.
        store.dropped.clear()
        store.putStringSync(LEVEL, blob)
        assertTrue(VaultWriteProofs.storeWriteProven(mapOf(LEVEL to blob)) { store.getString(it) })
    }

    @Test
    fun protectionLevelGate_mustCompareTheExactCiphertext_notARe_encryption() {
        // The selector-meta blob carries a fresh random IV, so two encrypts of the
        // SAME tier never produce the same bytes. A gate that re-encrypted for the
        // comparison would fail on every healthy write; the implementation captures
        // the blob it wrote. This pins the property that makes that necessary.
        val firstEncrypt = "level-blob-iv-A"
        val secondEncrypt = "level-blob-iv-B"
        val store = DroppingStore()
        store.putStringSync(LEVEL, firstEncrypt)
        assertTrue(VaultWriteProofs.storeWriteProven(mapOf(LEVEL to firstEncrypt)) { store.getString(it) })
        assertFalse(
            VaultWriteProofs.storeWriteProven(mapOf(LEVEL to secondEncrypt)) { store.getString(it) },
            "comparing against a re-encryption would reject a write that really landed",
        )
    }
}

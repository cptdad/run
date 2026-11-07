package com.vg.run

import com.vg.run.DbKeyRotationPolicy.RotationOutcome
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// The SQLCipher key rotation performed by a credential
// TIER UPGRADE, and the union invariant that makes it brick-safe:
//
//     union { vlt_c, vlt_cn } ALWAYS contains the key the vault file is on.
//
// SCOPE, deliberately narrow. `VaultSelector`'s store is the concrete
// `expect class KeyValueStore`, so commonTest cannot inject one — which means the
// only thing this file can honestly assert is the PURE decision units the
// implementation calls: [DbKeyRotationPolicy.mayRotateDbKey] and
// [DbKeyRotationPolicy.rotationOutcomeFromProbes].
//
// An earlier revision of this file also carried a hand-written MODEL of the store,
// the vault file and the unlock reconcile, and replayed crash points against
// it. That model was deleted: it asserted against its own copy of the algorithm, so
// deleting the read-back gate in `promotePendingRotation` and reversing the try
// order in `reconcilePendingRotation` left every one of those tests green. The
// crash points now live where the REAL store, the REAL SQLCipher re-key and the
// REAL VaultSelector are all available:
//
//   • androidApp `VaultSelectorTest` — the interrupted rotation (a real re-key that
//     lands while the promotion is skipped), the promote-then-crash cleanup, the
//     never-landed record, the undecidable both-keys-fail case, the recovery-blob
//     veto and the archived-weak-era replay;
//   • shared iosTest `IosDbKeyRotationTest` — the platform-specific halves: the
//     rolled-back re-key that reports SQLITE_OK, the poisoned write context that
//     moves the file afterwards, and the silently-dropped `vlt_c` promotion write
//     (a locked keybag), none of which Android's store can even express.
// ---------------------------------------------------------------------------

class DbKeyRotationTest {

    // -- 1. eligibility: every condition is a brick-safety gate ----------------

    private fun mayRotate(
        tierUpgrade: Boolean = true,
        hasRecoveryBlob: Boolean = false,
        dbKeyAuthBound: Boolean = false,
        hasVaultHandle: Boolean = true,
        rotationAlreadyPending: Boolean = false,
    ) = DbKeyRotationPolicy.mayRotateDbKey(
        tierUpgrade, hasRecoveryBlob, dbKeyAuthBound, hasVaultHandle, rotationAlreadyPending,
    )

    @Test
    fun rotation_fires_onlyOnAPlainRecoveryFreeTierUpgrade() {
        assertTrue(mayRotate(), "PIN → passphrase on a plain, recovery-free vault is the whole target case")
    }

    @Test
    fun rotation_neverOnASameTierPinRotation() {
        // The fix is about retiring the wrap the user just upgraded AWAY from.
        // An ordinary PIN change retires nothing and would pay the rotation's risk
        // for free — and it is the most common credential operation there is.
        assertFalse(mayRotate(tierUpgrade = false))
    }

    @Test
    fun rotation_neverWhenARecoveryCodeExists() {
        // THE objection that killed the original proposal: `vlt_rc` wraps the
        // STABLE passphrase under a 160-bit code shown once and never persisted, so a
        // re-key silently kills a code the user has written down — with no channel to
        // mint them a new one. A recovery blob is an absolute veto.
        assertFalse(mayRotate(hasRecoveryBlob = true))
    }

    @Test
    fun rotation_neverOverAnAuthBoundKeyBlob() {
        // A plain `vlt_c` is what guarantees the pending record is ALSO a plain wrap,
        // so the unlock reconcile's second unwrap can never raise a second biometric
        // prompt. (Every auth-bound vault also has a recovery blob, so this is belt
        // and braces — and it must stay that way.)
        assertFalse(mayRotate(dbKeyAuthBound = true))
    }

    @Test
    fun rotation_neverWithoutALiveVaultHandle() {
        // The re-key runs on the LIVE connection; with no handle there is nothing to
        // re-key, and writing a pending record for a rotation that cannot happen is
        // pure risk. Also the default for every VaultSelector built without a
        // vaultProvider (InactivityWipe, the orphan probe, tests).
        assertFalse(mayRotate(hasVaultHandle = false))
    }

    @Test
    fun rotation_neverStartsASecondOneOverAnUnresolvedRecord() {
        // The union invariant is stated over exactly TWO records. A second rotation
        // would overwrite `vlt_cn` — possibly the only remaining record of the key the
        // file is actually on.
        assertFalse(mayRotate(rotationAlreadyPending = true))
    }

    // -- 2. the outcome is decided by probes, never by the re-key return -------

    @Test
    fun probes_onlyTheNewKeyOpens_promotes() {
        assertEquals(
            RotationOutcome.PROMOTE,
            DbKeyRotationPolicy.rotationOutcomeFromProbes(newKeyOpens = true, oldKeyOpens = false),
        )
    }

    @Test
    fun probes_onlyTheOldKeyOpens_reportsARollback() {
        // NOTE the name: DROP_PENDING is what the PROBES concluded, not what the
        // caller does. `rotateDbKeyAfterUpgrade` deliberately does NOT remove the
        // record here — sqlite3_rekey_v2 reports SQLITE_OK on its rollback branch
        // AFTER installing the new key in the live handle's WRITE context, so a
        // "rolled back" file can still move to the new key on the next commit, and
        // `vlt_cn` is the only surviving record of that key. The record is dropped by
        // the unlock reconcile instead, on the positive evidence of `vlt_c` opening
        // the file. Pinned end-to-end in IosDbKeyRotationTest.
        assertEquals(
            RotationOutcome.DROP_PENDING,
            DbKeyRotationPolicy.rotationOutcomeFromProbes(newKeyOpens = false, oldKeyOpens = true),
        )
    }

    @Test
    fun probes_neitherOpens_changesNothing() {
        // "Could not tell" and "did not work" are indistinguishable — probeKey answers
        // false for a busy/moved/locked file too. Keeping the OLD key over a file that
        // really was re-keyed is a permanent brick, so ambiguity must never act.
        assertEquals(
            RotationOutcome.LEAVE_PENDING,
            DbKeyRotationPolicy.rotationOutcomeFromProbes(newKeyOpens = false, oldKeyOpens = false),
        )
    }

    @Test
    fun probes_bothOpen_changesNothing() {
        // Nonsensical for one file, therefore evidence that the probes are not
        // measuring what we think — the one situation where doing nothing is clearly
        // right. (Both records survive; the unlock reconcile resolves it by OPENING.)
        assertEquals(
            RotationOutcome.LEAVE_PENDING,
            DbKeyRotationPolicy.rotationOutcomeFromProbes(newKeyOpens = true, oldKeyOpens = true),
        )
    }

    // -- 3. a re-key that did not verifiably commit RETIRES the live handle ----
    //
    // Review 2026-08-03 — VaultDatabase.rekey's kdoc contract, previously ignored
    // by its only caller: sqlite3_rekey_v2's rollback branch leaves the live
    // handle's codec WRITE context on the new key over an old-key file, so one
    // later commit produces a MIXED-key file — and the next unlock's reconcile can
    // then promote `vlt_cn` and delete the only record of the key most pages are
    // still under. `rekeyOutcomeKeepsLiveHandle` is the shipped decision
    // `rotateDbKeyAfterUpgrade` acts on (close the handle + force the session
    // locked); the end-to-end halves live in IosDbKeyRotationTest and the
    // instrumented VaultSelectorTest, where a real handle exists to close.

    @Test
    fun liveHandle_keptOnlyOnAProbeProvenCommit() {
        // PROMOTE is the one outcome where the handle is provably consistent: the
        // success branch sets BOTH codec contexts to the new key, and the new-key
        // probe just opened the file under it.
        assertTrue(DbKeyRotationPolicy.rekeyOutcomeKeepsLiveHandle(RotationOutcome.PROMOTE))
    }

    @Test
    fun liveHandle_retiredOnAReportedRollback() {
        // DROP_PENDING = poisoned by construction (rekey ran, file did not move):
        // the write context holds the new key over an old-key file. Continuing to
        // write through it is the mixed-key data-loss path.
        assertFalse(DbKeyRotationPolicy.rekeyOutcomeKeepsLiveHandle(RotationOutcome.DROP_PENDING))
    }

    @Test
    fun liveHandle_retiredWhenNothingIsKnown() {
        // LEAVE_PENDING: a clean handle is indistinguishable from a poisoned one
        // from here (this also covers rekey == false after the native call ran).
        // Retiring a clean handle costs one forced re-unlock; keeping a poisoned
        // one can cost the vault. Both LEAVE_PENDING inputs must retire.
        assertFalse(DbKeyRotationPolicy.rekeyOutcomeKeepsLiveHandle(RotationOutcome.LEAVE_PENDING))
    }
}

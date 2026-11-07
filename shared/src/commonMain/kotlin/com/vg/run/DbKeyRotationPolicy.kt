package com.vg.run

// ---------------------------------------------------------------------------
// DbKeyRotationPolicy — the pure decisions of the SQLCipher key rotation on a
// credential TIER UPGRADE (`vlt_cn`, [VaultStoreKeys.PENDING_DBKEY]).
//
// The runtime (re-key, probes, promotion, unlock reconcile)
// stays in VaultSelector. The invariant every decision here serves:
//   union { vlt_c, vlt_cn } ALWAYS contains the key the file is encrypted with.
// See docs/vault-relay-internals.md, "`vlt_cn` — the SQLCipher key rotation".
// ---------------------------------------------------------------------------

internal object DbKeyRotationPolicy {
    // --- The SQLCipher key rotation on a credential tier upgrade -------------

    /**
     * May this credential change also RE-KEY the database?
     *
     * The rationale: the SQLCipher passphrase is minted once at provision and never
     * regenerated, so an archived `vlt_c` from a weak era, plus that old
     * credential, plus the still-current device key, opens TODAY's vault — a
     * vault's effective protection is the weakest configuration it has ever had,
     * for anyone holding a copy from that era. Re-keying on the upgrade is what
     * retires the archived copy.
     *
     * Every condition is a brick-safety gate, not caution:
     *
     *  - [tierUpgrade] — only a PIN → passphrase change. A same-tier PIN rotation
     *    gains nothing (the archived blob it would retire is one the user did not
     *    just strengthen away from) and would pay the rotation's risk for free.
     *  - [recoveryBlobVetoes] — `vlt_rc` wraps the STABLE passphrase under a 160-bit
     *    code that is displayed ONCE and never persisted. Re-keying would silently
     *    kill a code the user has written down, with no channel to mint a new one.
     *    This is exactly the objection that killed the original proposal.
     *    The caller no longer passes a PRESENCE probe
     *    here — it passes [RecoveryBlobPolicy.recoveryBlobVetoesRotation], so a planted plaintext
     *    `vlt_rc` can no longer veto the rotation for the life of the vault while
     *    an unreadable device key still does.
     *  - [dbKeyAuthBound] — a plain `vlt_c` guarantees the pending record is also a
     *    plain wrap, so the unlock reconcile's SECOND unwrap attempt can never
     *    raise a second biometric prompt. (An auth-bound vault is a PRIVATE vault,
     *    which always has a recovery blob anyway.)
     *  - [hasVaultHandle] — the re-key runs on the LIVE connection; without one
     *    there is nothing to re-key.
     *  - [rotationAlreadyPending] — never start a second rotation over an
     *    unresolved one: the union invariant is stated over exactly two records.
     */
    internal fun mayRotateDbKey(
        tierUpgrade: Boolean,
        recoveryBlobVetoes: Boolean,
        dbKeyAuthBound: Boolean,
        hasVaultHandle: Boolean,
        rotationAlreadyPending: Boolean,
    ): Boolean = tierUpgrade && !recoveryBlobVetoes && !dbKeyAuthBound &&
        hasVaultHandle && !rotationAlreadyPending

    /** What the post-re-key probe pair says to do with the two stored records. */
    internal enum class RotationOutcome {
        /** Only the NEW key opens the file ⇒ copy `vlt_cn` over `vlt_c`, then drop it. */
        PROMOTE,
        /** Only the OLD key opens the file ⇒ the re-key rolled back; drop `vlt_cn`. */
        DROP_PENDING,
        /** Both or neither ⇒ change NOTHING and keep both records. */
        LEAVE_PENDING,
    }

    /**
     * Decide a re-key's outcome from PROBES ONLY — never from
     * [VaultDatabase.rekey]'s return value, which is `SQLITE_OK` on both the
     * commit and the rollback branch (see its kdoc).
     *
     * Exactly one `true` is the only actionable answer. "Both" and "neither" are
     * lumped together deliberately: [VaultFactory.probeKey] answers `false` both
     * for "this key does not open it" and for "we could not tell" (busy, I/O,
     * a file that moved), so acting on a lone `false` by keeping the OLD key is
     * itself a brick if the file really was re-keyed. Keeping BOTH records costs
     * one extra store entry and one unlock-time open; the unlock reconcile then
     * resolves it from the only unambiguous evidence there is — which key actually
     * OPENS the vault.
     */
    internal fun rotationOutcomeFromProbes(
        newKeyOpens: Boolean,
        oldKeyOpens: Boolean,
    ): RotationOutcome = when {
        newKeyOpens && !oldKeyOpens -> RotationOutcome.PROMOTE
        oldKeyOpens && !newKeyOpens -> RotationOutcome.DROP_PENDING
        else -> RotationOutcome.LEAVE_PENDING
    }

    /**
     * After the re-key call, may the LIVE
     * handle keep serving this session?
     *
     * Only a probe-PROVEN commit ([RotationOutcome.PROMOTE]) may: on
     * `sqlite3_rekey_v2`'s success branch both codec contexts end on the new
     * key, consistent with the file the new-key probe just opened. Every other
     * outcome retires the handle, honouring [VaultDatabase.rekey]'s kdoc
     * ("prefer closing and re-opening the vault over continuing to write
     * through a handle whose re-key failed midway"):
     *
     *  - [RotationOutcome.DROP_PENDING] — poisoned BY CONSTRUCTION: the file
     *    is still on the old key while the rollback branch already installed
     *    the new key in this handle's WRITE context and never undoes it. One
     *    later commit dirties page 1 under the new key and produces a
     *    MIXED-key file — which the next unlock's reconcile can then "resolve"
     *    by promoting `vlt_cn` and dropping the only record of the key most
     *    pages are still under. Irrecoverable loss of everything not yet
     *    rewritten.
     *  - [RotationOutcome.LEAVE_PENDING] — nothing is known, including the
     *    handle's context state, and a clean handle is indistinguishable from
     *    a poisoned one from up here. Retiring a clean handle costs one forced
     *    re-unlock on a rare failure path; keeping a poisoned one can cost the
     *    vault. (This also covers `rekey == false` after the native call ran —
     *    the probes, not the return value, decide.)
     */
    internal fun rekeyOutcomeKeepsLiveHandle(outcome: RotationOutcome): Boolean =
        outcome == RotationOutcome.PROMOTE
}

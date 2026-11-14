package com.vg.run

// ---------------------------------------------------------------------------
// DbKeyRotationPolicy — the pure decisions of the SQLCipher key rotation on a
// protection-TIER STRENGTHENING (`vlt_cn`, [VaultStoreKeys.PENDING_DBKEY]).
//
// The runtime (re-key, probes, promotion, unlock reconcile)
// stays in VaultSelector. The invariant every decision here serves:
//   union { vlt_c, vlt_cn } ALWAYS contains the key the file is encrypted with.
// See docs/vault-relay-internals.md, "`vlt_cn` — the SQLCipher key rotation".
//
// Three transitions raise the tier, and each one re-keys (RUN-01, 2026-11-12):
//   • Decent → Maximum — inside the credential change ([mayRotateDbKey]);
//   • Decent → Secure  — inside the Lever B enable, while `vlt_c` is still
//     PLAIN and BEFORE the recovery code is minted, so the code the user is
//     shown wraps the NEW key ([strengtheningRotation]);
//   • Secure → Maximum — after the Lever B drop has removed the hardware layer
//     and `vlt_rc`, as its own step ([strengtheningRotation]).
// ---------------------------------------------------------------------------

internal object DbKeyRotationPolicy {
    // --- The SQLCipher key rotation on a credential tier upgrade -------------

    /**
     * May this credential change also RE-KEY the database?
     *
     * The rationale: the SQLCipher passphrase is minted once at provision and,
     * without a rotation, never regenerated, so an archived `vlt_c` from a weak era,
     * plus that old credential, plus the still-current device key, opens TODAY's
     * vault — a vault's effective protection is the weakest configuration it has
     * ever had, for anyone holding a copy from that era. Re-keying on every
     * strengthening is what retires the archived copy. This predicate covers the
     * credential-change transition (Decent → Maximum) only; the two transitions
     * whose credential change cannot re-key (Lever B is involved) are decided by
     * [strengtheningRotation].
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
     *    which always has a recovery blob anyway.) This is why Secure → Maximum
     *    cannot re-key HERE — its credential change runs while the hardware layer
     *    and `vlt_rc` are still in place — and re-keys after the Lever B drop
     *    instead ([strengtheningRotation]).
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

    // --- The rotation on a strengthening that is NOT a credential change ------

    /** What a Lever-B-related strengthening does about the DB key (see [strengtheningRotation]). */
    internal enum class StrengtheningRotation {
        /** Re-key now, before anything is bound to the key. */
        ROTATE,
        /**
         * Go on WITHOUT a re-key — the pre-RUN-01 behaviour. Only where a re-key is
         * either pointless (no live handle: nothing to re-key; the blob is auth-bound:
         * the step itself is refusing) or would silently kill a recovery code that is
         * provably live ([RecoveryBlobPolicy.RecoveryBlobState.PROVEN]).
         */
        SKIP,
        /**
         * Refuse the whole step benignly, nothing written — a transient state hides
         * whether a re-key is safe. The step is retried later and then rotates.
         */
        DEFER,
    }

    /**
     * The re-key decision for the two strengthening transitions whose credential
     * change cannot re-key ([mayRotateDbKey] vetoes both because Lever B is
     * involved):
     *
     *  - **Decent → Secure** (the Lever B enable): evaluated while `vlt_c` is still
     *    PLAIN, before the hardware wrap and BEFORE the recovery code is minted. A
     *    re-key there is decided by probes and promoted before the code is sealed,
     *    so the code the user is shown wraps the key the file is ON — never a dead
     *    code — and the record the unlock reconcile reads is a plain wrap (no second
     *    biometric prompt).
     *  - **Secure → Maximum** (after the Lever B drop): by then `vlt_c` is plain and
     *    `vlt_rc` is gone, which is exactly the shape [mayRotateDbKey] wanted.
     *
     * Ordered so a refusal is always the SAFE direction:
     *  - [dbKeyAuthBound] ⇒ SKIP: the step refuses on its own (enable: already on;
     *    post-drop: the drop did not land), and a record next to an `ab:` blob is
     *    the second-prompt hazard above.
     *  - no [hasVaultHandle] ⇒ SKIP: nothing to re-key (onboarding enables before
     *    the session owns the handle — a vault seconds old has no weaker era).
     *  - [rotationAlreadyPending] ⇒ DEFER: the union invariant is over two records.
     *  - [journalPending] true or unknown ⇒ DEFER: an iOS write-ahead batch could
     *    replay an older `vlt_c` / `vlt_a` over the record's KEK.
     *  - [recoveryBlob] UNREADABLE ⇒ DEFER: a device-key outage cannot tell a live
     *    code from no code; PROVEN ⇒ SKIP: a real code the user may hold wraps the
     *    CURRENT key, and a re-key would kill it with no replacement guaranteed.
     *    ABSENT and FORGED (a plant, never ours) release the veto, exactly as
     *    [RecoveryBlobPolicy.recoveryBlobVetoesRotation] does.
     */
    internal fun strengtheningRotation(
        dbKeyAuthBound: Boolean,
        hasVaultHandle: Boolean,
        rotationAlreadyPending: Boolean,
        journalPending: Boolean?,
        recoveryBlob: RecoveryBlobPolicy.RecoveryBlobState,
    ): StrengtheningRotation = when {
        dbKeyAuthBound -> StrengtheningRotation.SKIP
        !hasVaultHandle -> StrengtheningRotation.SKIP
        rotationAlreadyPending -> StrengtheningRotation.DEFER
        journalPending != false -> StrengtheningRotation.DEFER
        recoveryBlob == RecoveryBlobPolicy.RecoveryBlobState.UNREADABLE -> StrengtheningRotation.DEFER
        recoveryBlob == RecoveryBlobPolicy.RecoveryBlobState.PROVEN -> StrengtheningRotation.SKIP
        else -> StrengtheningRotation.ROTATE
    }

    /** What a completed rotation attempt lets its caller do next. */
    internal enum class RotationResult {
        /** The probes proved the file on the NEW key AND `vlt_c` now provably holds it. */
        ROTATED,
        /** Nothing was re-keyed and no record is left (the vault is exactly as before). */
        NOT_ROTATED,
        /** Anything else: records kept for the unlock reconcile (handle retired unless PROMOTE). */
        UNRESOLVED,
    }

    /**
     * Only a probe-PROVEN commit whose promotion also READ BACK is [RotationResult.ROTATED]
     * — the one state in which a caller may bind something new (a recovery code, an
     * `ab:` wrap) to the key `vlt_c` now holds. A PROMOTE whose promotion write did not
     * prove itself leaves `vlt_c` on the OLD key over a NEW-key file until the next
     * unlock promotes `vlt_cn`; binding anything to either record then is premature.
     */
    internal fun rotationResult(outcome: RotationOutcome, promotionProven: Boolean): RotationResult =
        if (outcome == RotationOutcome.PROMOTE && promotionProven) RotationResult.ROTATED
        else RotationResult.UNRESOLVED
}

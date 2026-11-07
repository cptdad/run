package com.vg.run

// ---------------------------------------------------------------------------
// RecoveryBlobPolicy — what the `vlt_rc` slot proves, and what an armed `vlt_rp`
// marker authorises.
//
// `vlt_rc` ([VaultStoreKeys.RECOVERY_BLOB]) is the SECOND, independent
// vault-decrypt path: the stable SQLCipher passphrase wrapped under a 160-bit
// user-held code, then device-AEAD'd under [VaultCryptoContexts.RECOVERY]. The three
// predicates over [RecoveryBlobState] are deliberately NOT equal — see each kdoc
// and docs/vault-relay-internals.md, "`vlt_rc` is classified, not
// presence-checked".
// ---------------------------------------------------------------------------

internal object RecoveryBlobPolicy {
    /** The recovery code's secret length: 160 bits → exactly 32 Base32 symbols. */
    const val RECOVERY_SECRET_LENGTH = 20

    /** `vlt_rp` token: a Lever B enable is in flight (see [VaultStoreKeys.RECOVERY_PENDING]). */
    const val RECOVERY_PENDING_ARMED = "1"

    /** What [abandonedEnableAction] decided about an in-flight Lever B enable. */
    internal enum class AbandonedEnableAction {
        /** No armed marker, or nothing can be concluded — touch nothing. */
        NONE,
        /** The enable COMPLETED (the DB key is auth-bound): drop the stale marker only. */
        CLEAR_MARKER_ONLY,
        /** The enable was ABANDONED over a still-plain DB key: revoke the orphan code. */
        PURGE_RECOVERY,
    }

    /**
     * Is the stored state an ABANDONED Lever B enable — i.e. an armed
     * [VaultStoreKeys.RECOVERY_PENDING] marker over a DB-key blob that is still PLAIN?
     *
     * Pure so commonTest can pin every branch (KeyValueStore / CryptoProvider are
     * expect classes with no common fake seam). The three no-op branches are the
     * whole safety argument:
     *
     *  - marker not exactly [RECOVERY_PENDING_ARMED], or not AUTHENTICATED (absent,
     *    legacy cleartext, planted, damaged — the caller maps a damaged read here
     *    too) ⇒ NONE. Deleting a recovery blob is irreversible, so it happens only
     *    on evidence WE wrote, never on an absence or on a forgeable byte. This is
     *    also what makes the purge prospective-only: an install that abandoned an
     *    enable BEFORE this marker existed keeps its orphan rather than having it
     *    revoked on a guess.
     *  - [dbKeyBlob] null ⇒ NONE (nothing can be concluded about the vault at all).
     *  - the blob IS auth-bound ⇒ CLEAR_MARKER_ONLY, and `vlt_rc` is NOT touched.
     *    A crash between finalize's atomic ab: commit and its marker clear must
     *    never revoke the recovery code of a live Lever B vault — that code is the
     *    ONLY way back once the hardware key invalidates.
     */
    internal fun abandonedEnableAction(
        markerValue: String?,
        markerAuthenticated: Boolean,
        dbKeyBlob: String?,
        isAuthBound: (String) -> Boolean,
    ): AbandonedEnableAction = when {
        !markerAuthenticated || markerValue != RECOVERY_PENDING_ARMED -> AbandonedEnableAction.NONE
        dbKeyBlob == null -> AbandonedEnableAction.NONE
        isAuthBound(dbKeyBlob) -> AbandonedEnableAction.CLEAR_MARKER_ONLY
        else -> AbandonedEnableAction.PURGE_RECOVERY
    }

    // --- What the `vlt_rc` slot actually proves --------------------------------

    /**
     * The PROVENANCE of [VaultStoreKeys.RECOVERY_BLOB].
     *
     * Every consumer used to ask `store.contains(VaultStoreKeys.RECOVERY_BLOB)`, i.e. a
     * PRESENCE probe over a slot that anyone able to write the app's files
     * (Android `vault_selector_prefs.xml`, the iOS NSUserDefaults fallback
     * slot) can create. One planted byte therefore (a) permanently vetoed the
     * DB-key re-key — so an archived weak-era `vlt_c` plus a grindable PIN kept
     * opening TODAY's vault, which is exactly the exposure the re-key exists to
     * retire — and (b) minted a PHANTOM recovery path: the unlock screen
     * offered "use your recovery code", and every attempt against a blob that
     * can never decrypt was counted as a wrong-code guess against the
     * emergency-wipe budget.
     *
     * `vlt_rc` is `encodeBase64(crypto.encrypt(recoveryOuter, VaultCryptoContexts.RECOVERY))`,
     * so proving it is one device-key AEAD open under [VaultCryptoContexts.RECOVERY] — no
     * user code, no biometric prompt, no vault.
     */
    internal enum class RecoveryBlobState {
        /** Decrypts under the device key + [VaultCryptoContexts.RECOVERY]. A real second decrypt path. */
        PROVEN,

        /** Confirmed absent. */
        ABSENT,

        /** Present but NOT ours: a plant, or a blob damaged past use. */
        FORGED,

        /** The device key is transiently unavailable — nothing can be concluded. */
        UNREADABLE,
    }

    /**
     * Classify the stored [raw] value. [open] performs the device-key AEAD
     * open and returns true on success; it must THROW
     * [KeyUnavailableException] (or [KeyPermanentlyInvalidException]) for a
     * transient/permanent key outage, which is the one case that must not be
     * confused with a forgery.
     *
     * Pure so commonTest can pin every branch — `KeyValueStore` and
     * `CryptoProvider` are expect classes with no common fake seam, the same
     * constraint [abandonedEnableAction] and [DbKeyRotationPolicy.mayRotateDbKey] document.
     */
    internal fun classifyRecoveryBlob(raw: String?, open: (String) -> Boolean): RecoveryBlobState {
        if (raw == null) return RecoveryBlobState.ABSENT
        return try {
            if (open(raw)) RecoveryBlobState.PROVEN else RecoveryBlobState.FORGED
        } catch (_: KeyUnavailableException) {
            RecoveryBlobState.UNREADABLE
        } catch (_: KeyPermanentlyInvalidException) {
            RecoveryBlobState.UNREADABLE
        } catch (_: Exception) {
            RecoveryBlobState.FORGED
        }
    }

    /**
     * Does the recovery slot VETO the DB-key re-key?
     *
     * Only a PROVEN-ABSENT or PROVEN-FORGED slot releases the veto. An
     * UNREADABLE one still vetoes, and that direction is brick-safety, not
     * caution: the re-key retires the SQLCipher passphrase `vlt_rc` wraps,
     * and a transient device-key outage is indistinguishable from a healthy
     * blob — rotating on it would orphan a code the user has written down,
     * with no channel to mint them a new one. Rotating over a FORGED slot
     * destroys nothing: a blob that cannot be opened under the device key
     * could never have been used to recover anything.
     */
    internal fun recoveryBlobVetoesRotation(state: RecoveryBlobState): Boolean =
        state != RecoveryBlobState.ABSENT && state != RecoveryBlobState.FORGED

    /**
     * May the UI offer the recovery-code path?
     *
     * Same split, same reason in the other direction: hiding it from a user
     * whose hardware key just died is the brick this whole subsystem exists
     * to prevent, so an UNREADABLE slot still offers it (the attempt then
     * returns the neutral `Error`, which both recovery screens roll back off
     * the wipe budget). A FORGED slot is hidden precisely so a plant cannot
     * spend that budget.
     */
    internal fun recoveryPathOffered(state: RecoveryBlobState): Boolean =
        recoveryBlobVetoesRotation(state)

    /**
     * May a path that ARMS Lever B treat this slot as its safety net?
     *
     * PROVEN only. These are the two places that make the DB key auth-bound —
     * `setDbKeyAuthBinding(true)` and the legacy-key strict re-mint — after
     * which the recovery code is the ONLY way back should the hardware key
     * invalidate. A planted or unreadable slot is not a net, and binding over
     * one is the brick.
     */
    internal fun recoveryBlobUsableAsNet(state: RecoveryBlobState): Boolean =
        state == RecoveryBlobState.PROVEN
}

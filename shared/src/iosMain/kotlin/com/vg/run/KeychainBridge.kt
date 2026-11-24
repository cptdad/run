package com.vg.run

import platform.Foundation.NSData

// ---------------------------------------------------------------------------
// KeychainBridge — interface fulfilled by Swift's KeychainHelper.
//
// Provides secure key storage in the iOS Keychain, replacing plaintext
// NSUserDefaults storage for the CryptoProvider device key.
// ---------------------------------------------------------------------------

/**
 * Result of a Keychain key lookup. Distinguishes the three outcomes that
 * matter for safety:
 *   - [data] non-null               → the key was read successfully.
 *   - [data] null, [keyMissing]==true  → the item genuinely does not exist
 *        (errSecItemNotFound); it is safe to create a fresh key.
 *   - [data] null, [keyMissing]==false → a transient failure, most importantly
 *        errSecInteractionNotAllowed (the device is locked). The key may still
 *        exist; callers MUST NOT delete/regenerate, or the vault would be
 *        cryptographically erased.
 * [status] is the raw OSStatus, for logging.
 */
class KeychainLoadResult(
    val data: NSData?,
    val keyMissing: Boolean,
    val status: Int,
)

/**
 * Result of a keyed-storage (kv) Keychain read. Mirrors [KeychainLoadResult]
 * for the credential-verifier / wrapped-DB-key / counter items:
 *   - [value] non-null                 → the item was read successfully.
 *   - [value] null, [itemMissing]==true  → the item genuinely does not exist
 *        (errSecItemNotFound); safe to treat as absent (first run / after wipe).
 *   - [value] null, [itemMissing]==false → a transient failure
 *        (errSecInteractionNotAllowed, errSecAuthFailed, daemon glitches…).
 *        The item may still exist; callers MUST NOT treat this as absent —
 *        "absent" here reads as a wrong PIN (counts toward the wipe budget) or
 *        as not-configured (re-provisions over the real vault).
 * [status] is the raw OSStatus, for logging.
 */
class KvReadResult(
    val value: String?,
    val itemMissing: Boolean,
    val status: Int,
)

/**
 * RÚN-02: the outcome of a CHECKED Keychain deletion, crossing the bridge as two
 * plain ints. [outcome] is an [EraseOutcome.code] (0 DELETED, 1 ALREADY_ABSENT,
 * 2 UNRESOLVED — anything else reads as UNRESOLVED); [status] is the OSStatus that
 * decided it, for logs as a number only. Swift decides DELETED / ALREADY_ABSENT only
 * when a verify probe after the delete answered `errSecItemNotFound`; Kotlin
 * additionally refuses to trust "absent" while protected data is unavailable
 * ([WipeEraser]).
 */
class KeychainDeleteResult(
    val outcome: Int,
    val status: Int,
) {
    fun toEraseResult(): EraseResult = EraseResult(EraseOutcome.fromCode(outcome), status)
}

/** errSecSuccess / errSecItemNotFound (Security framework). */
private const val ERR_SEC_SUCCESS = 0
private const val ERR_SEC_ITEM_NOT_FOUND = -25300

/**
 * RÚN-02: the decision for ONE checked Keychain delete — the Swift helpers
 * (`KeychainHelper.classifyDelete`) call this, so the mapping lives in one place
 * and iosTest pins it. DELETED / ALREADY_ABSENT need the verify probe to answer
 * errSecItemNotFound; anything else is UNRESOLVED, carrying the delete's status
 * when it failed, else the probe's.
 */
fun classifyKeychainDelete(deleteStatus: Int, probeStatus: Int): KeychainDeleteResult {
    if (probeStatus != ERR_SEC_ITEM_NOT_FOUND) {
        val status = if (deleteStatus != ERR_SEC_SUCCESS) deleteStatus else probeStatus
        return KeychainDeleteResult(EraseOutcome.UNRESOLVED.code, status)
    }
    return when (deleteStatus) {
        ERR_SEC_SUCCESS -> KeychainDeleteResult(EraseOutcome.DELETED.code, deleteStatus)
        ERR_SEC_ITEM_NOT_FOUND -> KeychainDeleteResult(EraseOutcome.ALREADY_ABSENT.code, deleteStatus)
        else -> KeychainDeleteResult(EraseOutcome.UNRESOLVED.code, deleteStatus)
    }
}

/** RÚN-02: worst of two service sweeps (one leftover makes the whole sweep unresolved). */
fun combineKeychainDeletes(a: KeychainDeleteResult, b: KeychainDeleteResult): KeychainDeleteResult = when {
    EraseOutcome.fromCode(a.outcome) == EraseOutcome.UNRESOLVED -> a
    EraseOutcome.fromCode(b.outcome) == EraseOutcome.UNRESOLVED -> b
    a.outcome == EraseOutcome.DELETED.code || b.outcome == EraseOutcome.DELETED.code ->
        KeychainDeleteResult(EraseOutcome.DELETED.code, ERR_SEC_SUCCESS)
    else -> a
}

interface KeychainBridge {
    fun loadKey(): KeychainLoadResult
    fun storeKey(key: NSData)
    /** Unchecked delete of the device key — the mint path's orphan cleanup only.
     *  Every wipe path uses [deleteKeyChecked]. */
    fun deleteKey()

    /** RÚN-02: deletes the device key and proves it gone (see [KeychainDeleteResult]). */
    fun deleteKeyChecked(): KeychainDeleteResult

    /** RÚN-02: sweeps the whole kv service AND the diagnostic service, then proves both empty. */
    fun kvDeleteAllChecked(): KeychainDeleteResult

    /** RÚN-02: deletes the block-list item (`com.vg.run.crypto` / `blocked_contacts_v1`), checked. */
    fun deleteBlockListChecked(): KeychainDeleteResult

    // ---- Generic keyed storage (vault credential verifier, wrapped DB key,
    // wrong-PIN counters). These were stored in NSUserDefaults, whose plist is
    // included in device backups and lacks a strong file-protection class. They
    // now live in the Keychain under kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
    // (not backed up, readable only while unlocked) — matching the device key.
    // Values are already CryptoProvider (device-AEAD) ciphertext.
    //
    // kvGet is the SINGLE read primitive (presence checks go through it too, so
    // a presence probe and a read can never disagree about the same item): it
    // returns the tri-state [KvReadResult] so KeyValueStore can discriminate
    // confirmed-absent from a transient Keychain error. There is
    // deliberately no boolean contains — the old kvContains collapsed every
    // failure to false, which read as "not provisioned".
    fun kvGet(key: String): KvReadResult
    fun kvPut(key: String, value: String)
    /**
     * Deletes one keyed item.
     *
     * @return true when the item is confirmed gone (deleted, or already
     * absent), false when `SecItemDelete` reported any other status — most
     * importantly a LOCKED KEYBAG, where the delete simply does not happen.
     * The OSStatus used to be discarded, which made a refused delete
     * indistinguishable from a successful one; [KeyValueStore.remove] now
     * reports it upward for the one caller that must not guess
     * ([DebugMode.setEnabledIn]).
     */
    fun kvRemove(key: String): Boolean

    /** Deletes every keyed item, unchecked (the DEBUG e2e wipe). The production
     *  wipe uses [kvDeleteAllChecked]. */
    fun kvDeleteAll()
}

object KeychainBridgeHolder {
    var bridge: KeychainBridge? = null
}

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

interface KeychainBridge {
    fun loadKey(): KeychainLoadResult
    fun storeKey(key: NSData)
    fun deleteKey()

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

    /** Deletes every keyed item (used by the wipe paths). */
    fun kvDeleteAll()
}

object KeychainBridgeHolder {
    var bridge: KeychainBridge? = null
}

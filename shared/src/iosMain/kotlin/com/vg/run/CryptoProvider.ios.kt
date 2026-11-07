package com.vg.run

import platform.Foundation.NSLock

actual class CryptoProvider {
    // Lazy: the key is NOT loaded at construction. Loading reads the Keychain,
    // which is unreadable while the device is locked — and iOS can launch an
    // app process (prewarm / after reboot, before first unlock) in that state.
    // Deferring the load until first crypto use (which only happens once the
    // user has unlocked) keeps construction safe under lock and avoids ever
    // mistaking "locked" for "no key" at launch.
    private var key: ByteArray? = null
    private var wiped = false

    // One lock guards the key field AND every crypto op that
    // reads it. requireKey() previously handed out the live `key` array while wipeKey()
    // (vault lock / emergency wipe) zeroed that SAME array with no synchronization — a
    // background encrypt/decrypt racing a lock-triggered wipe could seal a credential
    // verifier / wrapped-DB-key / wrong-PIN-counter blob under an all-zero key (a
    // corrupted, later-AEAD-failing artifact). Holding keyLock across the whole crypto
    // op makes wipeKey mutually exclusive with it: the op completes under a valid key,
    // or the wipe zeroes first and the next op reloads. (Android is safe because its
    // wipeKey only nulls the Tink reference — an in-flight op keeps a valid Aead.)
    private val keyLock = NSLock()

    // Caller MUST hold keyLock.
    // Parity (by design): unlike CryptoProvider.android's mapKeystoreFailure, nothing
    // here yields KeyPermanentlyInvalidException — a missing key is re-created, every
    // other Keychain status is KeyUnavailableException.
    private fun requireKeyLocked(): ByteArray {
        // After wipeKey() (vault lock OR emergency wipe), lazily
        // (re)load the device key instead of hard-throwing. The old `check(!wiped)`
        // raised IllegalStateException across the non-@Throws Kotlin/Native → Swift
        // boundary → SIGABRT when the UI re-provisions in the SAME process after an
        // emergency wipe (setRealCredential → encrypt → requireKey). Mirror Android,
        // whose manager() lazily regenerates after wipeKey(): getOrCreateKey()
        // reloads the existing Keychain key (normal lock) or generates a fresh one
        // when the item is genuinely absent (emergency wipe deleted it). It still
        // throws KeyUnavailableException on any non-missing Keychain status (a locked
        // keybag, errSecAuthFailed, …) — unchanged, and handled by the @Throws
        // tryDecrypt path.
        key?.let { return it }
        return getOrCreateKey().also { key = it; wiped = false }
    }

    // These are Swift-reachable and requireKeyLocked()
    // throws KeyUnavailableException on a transient Keychain failure (locked keybag,
    // errSecAuthFailed on an UNLOCKED device). A Kotlin exception crossing a
    // NON-@Throws Kotlin/Native → Swift boundary does not become a Swift error — it
    // ABORTS the process. Same SIGABRT class as above and the tryDecrypt path:
    // annotate so Swift can `try?` and defer instead of crashing on a glitch.
    @Throws(KeyUnavailableException::class)
    actual fun encrypt(plaintext: ByteArray, contextInfo: ByteArray): ByteArray =
        keyLock.withLock { aesGcmEncrypt(plaintext, requireKeyLocked(), contextInfo) }

    @Throws(KeyUnavailableException::class)
    actual fun decrypt(ciphertext: ByteArray, contextInfo: ByteArray): ByteArray =
        keyLock.withLock { aesGcmDecrypt(ciphertext, requireKeyLocked(), contextInfo) }

    /**
     * Decrypts [ciphertext], distinguishing the two failure modes the caller
     * (InactivityWipe) MUST treat differently:
     *
     *  - Returns null → the device key resolved but AEAD verification FAILED.
     *    That is a genuine key rotation / ciphertext tamper — the real
     *    "fail-safe → expired → wipe" signal.
     *  - Throws KeyUnavailableException → the device key could not be resolved at
     *    all: a locked keybag, a transient Keychain error (e.g. errSecAuthFailed)
     *    on an UNLOCKED device, or the key was wiped. This is NOT a key change.
     *    Folding it into null (the old behaviour) let InactivityWipe read a
     *    transient glitch as "expired" and WIPE THE VAULT on a normally-used
     *    phone. The caller must DEFER on this and let a later launch decide.
     *
     * @Throws makes the exception catchable in Swift instead of terminating the
     * process; KeyUnavailableException is the only type that escapes (AEAD
     * failure becomes null, and every other key-resolution failure is mapped to
     * KeyUnavailableException so ambiguity always defers, never destroys data).
     */
    @Throws(KeyUnavailableException::class)
    fun tryDecrypt(ciphertext: ByteArray, contextInfo: ByteArray): ByteArray? = keyLock.withLock {
        val k = try {
            requireKeyLocked()
        } catch (e: KeyUnavailableException) {
            throw e
        } catch (e: Exception) {
            // Wiped key, or any other key-resolution failure — a "cannot decide"
            // state, never tamper. Surface as KeyUnavailable so the caller defers
            // rather than destroying the vault on ambiguity.
            throw KeyUnavailableException("device key unavailable: ${e.message}")
        }
        try { aesGcmDecrypt(ciphertext, k, contextInfo) } catch (_: Exception) { null }
    }

    /**
     * Zeroes the key material in memory. Call when locking the vault.
     * After this, the next encrypt/decrypt LAZILY reloads the key from the
     * Keychain (see requireKeyLocked — the fix for the post-wipe SIGABRT), so they
     * do not throw merely because of the wipe; they throw KeyUnavailableException
     * only when that reload fails (e.g. a locked keybag). [isWiped] reports the
     * state; [reloadKey] reloads eagerly.
     */
    fun wipeKey() = keyLock.withLock {
        key?.secureWipe()
        key = null
        wiped = true
    }

    /**
     * Reloads the key from Keychain. Call on vault unlock after wipeKey().
     */
    @Throws(KeyUnavailableException::class)
    fun reloadKey() = keyLock.withLock {
        // Derive the fresh key BEFORE wiping the old one. If
        // getOrCreateKey throws (transient Keychain error on an unlocked device), `key`
        // must stay INTACT — the old order wiped first, so a throw left `key` pointing at
        // a zeroed array with wiped=false, and requireKeyLocked would hand that all-zero
        // key out as valid (the InactivityWipe sentinel would then AEAD-fail → false wipe).
        val fresh = getOrCreateKey()
        key?.secureWipe()
        key = fresh
        wiped = false
    }

    /** True if the key has been wiped since the last (re)load. */
    fun isWiped(): Boolean = keyLock.withLock { wiped }
}

/** PLAT-1: NSLock is not reentrant — no path re-acquires keyLock (getOrCreateKey uses a
 *  separate keyInitLock), so lock() → block → unlock() is deadlock-free. */
private inline fun <T> NSLock.withLock(block: () -> T): T {
    lock()
    try { return block() } finally { unlock() }
}

private val keyInitLock = NSLock()

internal fun getOrCreateKey(): ByteArray {
    keyInitLock.lock()
    try {
        val keychain = KeychainBridgeHolder.bridge
            ?: error("KeychainBridge not registered")

        val result = keychain.loadKey()
        val existing = result.data?.toByteArray()
        if (existing != null && existing.size == 32) {
            platformLog("CryptoProvider", "loaded existing key (${existing.size} bytes)")
            return existing
        }

        // Key not cleanly present. Only create a fresh key when the item is
        // GENUINELY absent (errSecItemNotFound). Any other failure — above all
        // errSecInteractionNotAllowed (device locked) — means the key may still
        // exist; deleting+regenerating here would crypto-erase the vault.
        // Fail loudly instead so the caller can defer until the device unlocks.
        if (!result.keyMissing) {
            throw KeyUnavailableException(
                "Keychain key unreadable (status=${result.status})"
            )
        }

        platformLogWarn("CryptoProvider", "no key in Keychain (first run), generating new")

        // Genuinely first run — generate a new key. First delete any orphan.
        keychain.deleteKey()

        val newKey = generateSecureRandom(32)
        // This argument is a CATEGORY-1 NSData by the
        // secureWipeBytes() contract — a private +[NSData dataWithBytes:length:]
        // copy minted HERE by toNSData(), holding the ROOT at-rest device key, and
        // referenced by nothing else once the SYNCHRONOUS storeKey() (SecItemUpdate
        // / SecItemAdd, KeychainHelper.swift:74-109) has returned. ARC frees it
        // WITHOUT zeroing, so until now it was the last unwiped copy of the device
        // key that this app actually OWNS — every sibling toNSData() of secret
        // material is already wiped (PlatformCrypto.ios.kt,
        // IosDbKeyProtector.kt). Wiped in a finally that deliberately SPANS the
        // store-verify read below, so the memset can never precede a read of these
        // bytes even under the (unsupported) hypothesis that the platform aliases
        // the written buffer into the verify result.
        //
        // Deliberately NOT extended to the NSData that loadKey() RETURNS: that
        // buffer is allocated by Security.framework, not by us, so its uniqueness
        // cannot be established from source and a memset there could corrupt a live
        // device key (a bricking event). Known limitation: the iOS device-key
        // bridge copies are not provably wipeable.
        val newKeyData = newKey.toNSData()
        try {
            keychain.storeKey(newKeyData)

            // Verify the key actually PERSISTED. storeKey() fails closed (stores
            // nothing) on a non-errSecParam Keychain error, so a store can silently
            // not happen. Returning the in-RAM key anyway (the old behaviour) let
            // provisioning encrypt the credential verifiers, the PIN-wrapped DB keys
            // and the wrong-PIN counter under a device key that vanishes on the next
            // launch — loadKey() would then report keyMissing, a DIFFERENT key would
            // be generated, every blob would be undecryptable, and the orphan
            // emergency-wipe would destroy the REAL vault. Fail CLOSED instead: throw
            // the same KeyUnavailableException the locked path uses (callers already
            // handle it) so provisioning aborts and can be retried, rather than
            // silently losing the vault on a later launch.
            // `verify` is a full duplicate of the freshly-stored device key. Compare
            // first, then scrub it on EVERY path (success and failure) in the finally
            // below: it must not linger past wipeKey(), which zeroes only the `key`
            // field, never this orphan copy of the root at-rest key.
            val verify = keychain.loadKey().data?.toByteArray()
            try {
                if (verify == null || !verify.contentEquals(newKey)) {
                    platformLogError("CryptoProvider", "Keychain store-verify FAILED (verify=${verify?.size}) — failing closed")
                    newKey.secureWipe()
                    keychain.deleteKey()  // don't leave a half-written item behind
                    throw KeyUnavailableException("Keychain store-verify failed; device key did not persist")
                }
                platformLog("CryptoProvider", "Keychain store+verify OK")
                return newKey
            } finally {
                verify?.secureWipe()
            }
        } finally {
            // Strictly AFTER storeKey() and the verify read: the memset only ever
            // reaches our own copy, never the ByteArray `newKey` we return
            // (toNSData() copies) and never a buffer a live object still reads.
            newKeyData.secureWipeBytes()
        }
    } finally {
        keyInitLock.unlock()
    }
}

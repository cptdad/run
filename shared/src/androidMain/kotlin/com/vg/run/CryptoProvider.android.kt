package com.vg.run

import android.content.Context

actual class CryptoProvider(private val context: Context) {
    // Construct the Tink/Keystore-backed manager LAZILY (and synchronized) so a
    // TRANSIENT Android Keystore failure during keyset unwrap surfaces at the
    // operation — translated to KeyUnavailableException, which callers DEFER on —
    // rather than as an opaque GeneralSecurityException that PinAttemptsStore
    // would misclassify as tampering and wipe the vault.
    private var cryptoManager: CryptoManager? = null

    @Synchronized
    private fun manager(): CryptoManager =
        cryptoManager ?: try {
            CryptoManager(context).also { cryptoManager = it }
        } catch (e: Exception) {
            throw mapKeystoreFailure(e)
        }

    actual fun encrypt(plaintext: ByteArray, contextInfo: ByteArray): ByteArray =
        try {
            manager().encrypt(plaintext, contextInfo)
        } catch (e: Exception) {
            throw mapKeystoreFailure(e)
        }

    actual fun decrypt(ciphertext: ByteArray, contextInfo: ByteArray): ByteArray =
        try {
            manager().decrypt(ciphertext, contextInfo)
        } catch (e: Exception) {
            throw mapKeystoreFailure(e)
        }

    /**
     * Drops the cached Tink/Keystore manager (and the unwrapped AES-256 data
     * keyset it holds) on vault lock, so the keyset stops residing in process
     * RAM while the app is locked-but-alive (backgrounded/cached) — narrowing the
     * live-RAM acquisition window on a seized device. Mirrors iOS
     * CryptoProvider.wipeKey(). Tink exposes no key zeroization, so this drops the
     * strong reference for GC rather than scrubbing bytes; [manager] lazily
     * re-creates it on the next crypto use after unlock.
     */
    @Synchronized
    fun wipeKey() {
        cryptoManager = null
    }

    companion object {
        /**
         * Translate a TRANSIENT Android Keystore failure (device just booted,
         * OEM Keystore hiccup, key temporarily unusable) into
         * [KeyUnavailableException] so the PIN-counter path DEFERS instead of
         * misreading it as tamper-and-wipe. A genuine AEAD-verification failure
         * (tampered/forged ciphertext or wrong AEAD context) carries NO Keystore
         * cause and is left to propagate, so the wipe-on-tamper behavior is
         * preserved. Internal so the discriminator is unit-testable without a
         * real Keystore.
         *
         * Parity (by design): only Android maps a DEVICE-key failure to
         * [KeyPermanentlyInvalidException]; iOS CryptoProvider re-creates a missing key
         * and reports every other Keychain status as [KeyUnavailableException].
         */
        internal fun mapKeystoreFailure(e: Exception): Exception =
            if (e is KeyUnavailableException || e is KeyPermanentlyInvalidException) e
            // Check PERMANENT invalidation first — KeyPermanentlyInvalidatedException
            // lives in android.security.keystore.* and so matched the transient
            // classifier below, making a removed lock screen look like a passing
            // Keystore hiccup forever.
            else if (isPermanentKeyInvalidation(e))
                KeyPermanentlyInvalidException("Android Keystore key permanently invalidated: ${e.message}")
            else if (isTransientKeystoreFailure(e))
                KeyUnavailableException("Android Keystore transiently unavailable: ${e.message}")
            else e

        /**
         * True when [e] (or a cause) is `KeyPermanentlyInvalidatedException` —
         * the key's auth binding was destroyed (lock screen removed / biometrics
         * re-enrolled). Matched by NAME rather than type so the classifier stays
         * unit-testable off-device, exactly like [isKeystoreClassName].
         */
        internal fun isPermanentKeyInvalidation(e: Throwable): Boolean =
            causeChainAny(e) { isPermanentKeyInvalidationName(it) }

        internal fun isPermanentKeyInvalidationName(name: String): Boolean =
            name == PERMANENTLY_INVALIDATED_CLASS

        /**
         * Name-level form of the transient rule, so a JVM unit test can pin it
         * without constructing a real `KeyPermanentlyInvalidatedException` (which
         * cannot be instantiated off-device).
         */
        internal fun isTransientKeystoreName(name: String): Boolean =
            !isPermanentKeyInvalidationName(name) && isKeystoreClassName(name)

        internal fun isTransientKeystoreFailure(e: Throwable): Boolean =
            // A permanent invalidation is NOT transient, even though its class
            // sits under the android.security.keystore. prefix.
            !isPermanentKeyInvalidation(e) && causeChainAny(e) { isKeystoreClassName(it) }

        internal const val PERMANENTLY_INVALIDATED_CLASS =
            "android.security.keystore.KeyPermanentlyInvalidatedException"

        private inline fun causeChainAny(e: Throwable, predicate: (String) -> Boolean): Boolean {
            var c: Throwable? = e
            var depth = 0
            while (c != null && depth < 12) {
                if (predicate(c::class.qualifiedName ?: "")) return true
                c = c.cause
                depth++
            }
            return false
        }

        internal fun isKeystoreClassName(name: String): Boolean =
            name.startsWith("android.security.keystore.") ||
                name == "android.security.KeyStoreException" ||
                name == "java.security.KeyStoreException"
    }
}

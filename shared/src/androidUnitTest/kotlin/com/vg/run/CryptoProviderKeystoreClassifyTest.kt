package com.vg.run

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * On Android the wrong-PIN counter is Tink-encrypted
 * under a Keystore-wrapped key. A TRANSIENT Keystore failure (device just
 * booted, OEM hiccup) must be translated to KeyUnavailableException so the PIN
 * path DEFERS — never confused with a genuine AEAD-verification failure
 * (tampered ciphertext), which must still wipe-on-tamper. Pins the discriminator
 * so the defer guard can't silently become dead code again.
 */
class CryptoProviderKeystoreClassifyTest {

    @Test
    fun keystoreClassNames_classifiedTransient() {
        assertTrue(CryptoProvider.isKeystoreClassName("android.security.KeyStoreException"))
        assertTrue(CryptoProvider.isKeystoreClassName("java.security.KeyStoreException"))
        assertTrue(CryptoProvider.isKeystoreClassName("android.security.keystore.UserNotAuthenticatedException"))
    }

    @Test
    fun permanentInvalidation_isNotTransient() {
        // KeyPermanentlyInvalidatedException lives under
        // the android.security.keystore. prefix, so the name matcher DOES match it —
        // but it is the OPPOSITE of transient: the user removed their lock screen and
        // the auth-bound key is destroyed. This test previously asserted it WAS
        // transient, pinning the bug in place: every unlock then reported a retryable
        // error and the recovery code — the only way back into the vault — was never
        // offered. Asserted at name level because the real exception cannot be
        // constructed in a JVM unit test.
        val permanent = CryptoProvider.PERMANENTLY_INVALIDATED_CLASS
        assertTrue(CryptoProvider.isKeystoreClassName(permanent),
            "still a keystore class name — the overlap is exactly why this needs its own rule")
        assertTrue(CryptoProvider.isPermanentKeyInvalidationName(permanent))
        assertFalse(CryptoProvider.isTransientKeystoreName(permanent),
            "a destroyed auth-bound key must never be classified transient")
        // A genuine transient keystore failure keeps its old classification.
        assertTrue(CryptoProvider.isTransientKeystoreName(
            "android.security.keystore.UserNotAuthenticatedException"))
    }

    @Test
    fun aeadAndOtherNames_notTransient() {
        // A tampered/forged ciphertext or wrong-context AEAD failure must NOT be
        // treated as transient — it must keep flowing to TamperException + wipe.
        assertFalse(CryptoProvider.isKeystoreClassName("java.security.GeneralSecurityException"))
        assertFalse(CryptoProvider.isKeystoreClassName("javax.crypto.AEADBadTagException"))
        assertFalse(CryptoProvider.isKeystoreClassName("com.google.crypto.tink.shaded.protobuf.InvalidProtocolBufferException"))
        assertFalse(CryptoProvider.isKeystoreClassName(""))
    }

    @Test
    fun causeChain_transientDetected_tamperNot() {
        // Genuine AEAD failure: no Keystore anywhere in the chain -> not transient.
        val tamper = java.security.GeneralSecurityException("decryption failed")
        assertFalse(CryptoProvider.isTransientKeystoreFailure(tamper))
        // A Keystore glitch wrapped by Tink/JCE -> transient (defer, don't wipe).
        val wrapped = RuntimeException("keyset unwrap failed", java.security.KeyStoreException("locked"))
        assertTrue(CryptoProvider.isTransientKeystoreFailure(wrapped))
    }

    @Test
    fun mapKeystoreFailure_onlyWrapsTransient() {
        val tamper = java.security.GeneralSecurityException("decryption failed")
        assertFalse(CryptoProvider.mapKeystoreFailure(tamper) is KeyUnavailableException)
        val glitch = RuntimeException("x", java.security.KeyStoreException("locked"))
        assertTrue(CryptoProvider.mapKeystoreFailure(glitch) is KeyUnavailableException)
    }
}

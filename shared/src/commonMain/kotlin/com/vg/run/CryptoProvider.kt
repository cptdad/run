package com.vg.run

// ---------------------------------------------------------------------------
// CryptoProvider — platform-agnostic encryption/decryption interface.
//
// On Android: backed by Google Tink with Android Keystore.
// On iOS: backed by CryptoKit / Security.framework via the Swift bridge (shipped).
// ---------------------------------------------------------------------------

expect class CryptoProvider {
    fun encrypt(plaintext: ByteArray, contextInfo: ByteArray): ByteArray
    fun decrypt(ciphertext: ByteArray, contextInfo: ByteArray): ByteArray
}

/**
 * Thrown when the CryptoProvider key cannot be loaded because the device is
 * currently locked (iOS Keychain errSecInteractionNotAllowed). Callers that
 * normally treat a decrypt failure as tampering MUST treat this as "defer /
 * try again later", NEVER as a reason to wipe.
 */
class KeyUnavailableException(message: String) : RuntimeException(message)

/**
 * Thrown when a hardware key is gone for good, not
 * merely unavailable right now — the user removed their lock screen (Android
 * `KeyPermanentlyInvalidatedException`) or their passcode (iOS purges the
 * `WhenPasscodeSet`-protected Secure Enclave key). Retrying can NEVER succeed,
 * so this must not be folded into [KeyUnavailableException]: that would show a
 * Lever-B user a "temporary problem, try again" loop forever while the recovery
 * code — which exists for exactly this — is never offered. The permanent/
 * transient distinction is only visible at the layer that catches the platform
 * exception, so it is preserved from there all the way to the unlock UI.
 */
class KeyPermanentlyInvalidException(message: String) : RuntimeException(message)

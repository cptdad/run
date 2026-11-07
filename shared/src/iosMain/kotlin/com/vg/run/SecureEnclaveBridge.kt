package com.vg.run

import platform.Foundation.NSData

// ---------------------------------------------------------------------------
// SecureEnclaveBridge — interface fulfilled by Swift's SecureEnclaveHelper.
//
// Provides the iOS half of Lever B: a Secure-Enclave
// EC (P-256) key that ECIES-wraps the DB-key OUTER layer. The PUBLIC-key wrap
// needs no authentication; the PRIVATE-key unwrap is gated by the SE with a
// `[.privateKeyUsage, .biometryCurrentSet]` access control over
// kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, so it prompts for BIOMETRY
// ONLY — there is deliberately NO device-passcode fallback — and the key
// material never leaves the Enclave. Mirrors the Android RSA auth-bound key
// ([AuthBoundKeyStore]) so both platforms share the [DbKeyProtector] contract.
//
// `.userPresence` MUST NOT be restored here (SecureEnclaveHelper.swift:14-18
// records the removal): that flag accepts the DEVICE PASSCODE as well as
// biometry, so a forensic tool that cracked the passcode — the assumed
// capability in this threat model — would get the SE to release a PRIVATE
// vault's DB key, which is the exact barrier the tier is sold on. The shipped
// Swift flags are the correct ones; if this comment and the code ever disagree
// again, fix the COMMENT. The cost of `.biometryCurrentSet` (any Face/Touch-ID
// re-enrollment invalidates the key) is accepted and paid for by the mandatory,
// read-back-verified recovery code VaultSelector mints before enabling Lever B.
// ---------------------------------------------------------------------------

interface SecureEnclaveBridge {
    /** True when the Secure Enclave is usable (real device + passcode/biometry set). */
    fun isAvailable(): Boolean

    /** Ensures the SE key exists (creating it if absent). Returns false on failure. */
    fun ensureKey(): Boolean

    /**
     * ECIES-encrypts [data] to the SE public key. No authentication — a pure
     * public-key op, so wrapping (provision / enable / re-wrap) never prompts.
     * Returns null on failure.
     */
    fun wrap(data: NSData): NSData?

    /**
     * ECIES-decrypts [data] with the SE private key. This TRIGGERS the SE
     * BIOMETRIC prompt (via the `.biometryCurrentSet` access control — Face/Touch
     * ID only; the device passcode is NOT accepted, by design, so a cracked
     * passcode cannot release a PRIVATE vault's DB key) and BLOCKS the calling
     * thread until the user authenticates. Returns null on cancel / failure —
     * the caller treats that as a deferrable unavailability (retry), never a
     * wipe. Call OFF the main thread.
     */
    fun unwrap(data: NSData): NSData?

    /**
     * True when the SE key ITEM still exists. [unwrap] returns null for both
     * "user cancelled" (retryable) and "the key is gone" (permanent — removing the
     * device passcode purges a `WhenPasscodeSetThisDeviceOnly` key, and any
     * Face/Touch-ID re-enrollment invalidates a `.biometryCurrentSet` one), and the
     * caller must not treat the second as retryable. Pure item lookup: no prompt.
     */
    fun isKeyPresent(): Boolean

    /** Deletes the SE key (called from the wipe path). */
    fun deleteKey()
}

object SecureEnclaveBridgeHolder {
    var bridge: SecureEnclaveBridge? = null
}

package com.vg.run

import com.vg.run.VaultKdf.CURRENT_KDF_VERSION
import com.vg.run.VaultKdf.buildCredentialBlob
import com.vg.run.DbKeyPayloadCodec.decodeDbKeyPayload

// ---------------------------------------------------------------------------
// VaultBlobCodecs — the at-rest FORMAT of VaultSelector's credential blobs, in
// one place. Every member performs exactly the primitive calls VaultSelector
// used to inline at each site, in the same order, under the same frozen
// contexts and labels (VaultCryptoContexts). No store access, no logging, no
// decisions: each member wipes the transient key material it creates itself and
// propagates EVERY exception unchanged, so the callers keep their own catch
// ladders — and those ladders carry the fail directions (KeyUnavailable ⇒
// defer, a code-layer tag miss ⇒ Denied, a device-layer failure ⇒ Error, …).
//
// Formats (see the "Credential evaluation (CR-1)" block in VaultSelector.kt):
//   vlt_a  = encodeBase64(deviceAEAD_CREDENTIAL( version ‖ salt ‖ verifier [‖ m ‖ t ‖ p] ))
//            verifier = sha256(stretched ‖ LABEL_VERIFIER)
//   vlt_c  = DbKeyProtector.wrap( AES-GCM(kek, payload, DBKEY_INNER) )   (same for vlt_cn)
//            kek = sha256(stretched ‖ LABEL_DBKEY_KEK)
//   vlt_rc = encodeBase64(deviceAEAD_RECOVERY( AES-GCM(recoveryKek, R, RECOVERY) ))
//            recoveryKek = sha256(secret ‖ LABEL_RECOVERY_KEK)
// ---------------------------------------------------------------------------

internal class VaultBlobCodecs(
    private val crypto: DeviceKeyCipher,
    private val dbKeyProtector: DbKeyProtector,
) {
    private fun credentialContext(): ByteArray = VaultCryptoContexts.CREDENTIAL.encodeToByteArray()
    private fun dbKeyInnerContext(): ByteArray = VaultCryptoContexts.DBKEY_INNER.encodeToByteArray()
    private fun recoveryContext(): ByteArray = VaultCryptoContexts.RECOVERY.encodeToByteArray()

    // `vlt_a` for a NEW credential: the verifier of [stretched], at the current KDF version, over [salt].
    fun sealCredentialVerifier(stretched: ByteArray, salt: ByteArray): String {
        val verifier = sha256WithLabel(stretched, VaultCryptoContexts.LABEL_VERIFIER.encodeToByteArray())
        return encodeBase64(
            crypto.seal(buildCredentialBlob(CURRENT_KDF_VERSION, salt, verifier), credentialContext())
        )
    }

    // The device layer of `vlt_a` off: the plaintext layout [VaultKdf.parseCredentialBlob] reads.
    fun openCredentialVerifier(storedB64: String): ByteArray =
        crypto.open(decodeBase64(storedB64), credentialContext())

    // The DB-key KEK of [stretched] (independent of the verifier: distinct label). The caller wipes it.
    fun dbKeyKek(stretched: ByteArray): ByteArray =
        sha256WithLabel(stretched, VaultCryptoContexts.LABEL_DBKEY_KEK.encodeToByteArray())

    // A `vlt_c` / `vlt_cn` value: [payloadPlain] sealed under [kek] (the inner PIN
    // layer), then wrapped by the outer [DbKeyProtector] layer — auth-bound when
    // [authBound]. The inner ciphertext is wiped here; [payloadPlain] and [kek] stay
    // the caller's.
    fun sealDbKeyBlob(payloadPlain: ByteArray, kek: ByteArray, authBound: Boolean): String {
        val inner = aesGcmEncrypt(payloadPlain, kek, dbKeyInnerContext())
        try {
            return dbKeyProtector.wrap(inner, authBound = authBound)
        } finally {
            inner.secureWipe()
        }
    }

    // The inner PIN layer off an already-unwrapped [inner] (the
    // [DbKeyProtector.unwrap] stays at each call site: it is the biometric prompt
    // point). Null for a malformed payload; an AEAD failure throws.
    fun openDbKeyInner(inner: ByteArray, kek: ByteArray): DbKeyPayload? {
        val plain = aesGcmDecrypt(inner, kek, dbKeyInnerContext())
        try {
            return decodeDbKeyPayload(plain)
        } finally {
            plain.secureWipe()
        }
    }

    // A `vlt_rc` value: R under the code KEK of [secret], then under the device key.
    fun sealRecoveryBlob(dbKey: ByteArray, secret: ByteArray): String {
        val recCtx = recoveryContext()
        var recoveryKek: ByteArray? = null
        var recoveryOuter: ByteArray? = null
        try {
            recoveryKek = sha256WithLabel(secret, VaultCryptoContexts.LABEL_RECOVERY_KEK.encodeToByteArray())
            recoveryOuter = aesGcmEncrypt(dbKey, recoveryKek, recCtx)
            return encodeBase64(crypto.seal(recoveryOuter, recCtx))
        } finally {
            recoveryKek?.secureWipe()
            recoveryOuter?.secureWipe()
        }
    }

    // The DEVICE layer of `vlt_rc` off. Kept a separate call from
    // [openRecoveryCodeLayer] on purpose: a failure HERE means the blob is not ours
    // (planted / damaged) and must never be reported as a wrong code.
    fun openRecoveryDeviceLayer(blobB64: String): ByteArray =
        crypto.open(decodeBase64(blobB64), recoveryContext())

    // The CODE layer of `vlt_rc` off: R, or a throw on a wrong code (AEAD tag miss).
    fun openRecoveryCodeLayer(outer: ByteArray, secret: ByteArray): ByteArray {
        val recoveryKek = sha256WithLabel(secret, VaultCryptoContexts.LABEL_RECOVERY_KEK.encodeToByteArray())
        try {
            return aesGcmDecrypt(outer, recoveryKek, recoveryContext())
        } finally {
            recoveryKek.secureWipe()
        }
    }

    // The plain → auth-bound transition of [inner]: delete any existing hardware
    // key (so the wrap mints a FRESH one), wrap auth-bound, and prove the result
    // unwraps back to [inner] on this device (ONE biometric prompt). Returns the
    // verified blob, or null when the round trip did not match. Only for the three
    // ENABLE paths over a plain blob — NOT the unlock-time legacy re-mint, which is
    // deliberately silent (no prompt, no round trip).
    fun wrapAuthBoundVerified(inner: ByteArray): String? {
        dbKeyProtector.deleteAuthBoundKeyBeforeEnable()
        val blob = dbKeyProtector.wrap(inner, authBound = true)
        val check = dbKeyProtector.unwrap(blob)  // PROMPTS once
        val ok = check.contentEquals(inner)
        check.secureWipe()
        return if (ok) blob else null
    }
}

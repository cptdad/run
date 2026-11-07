package com.vg.run

// ---------------------------------------------------------------------------
// The legacy (static-key) envelope, sealed and opened exactly as the production
// sender / receiver do it: key = sha256(sharedSecret), AAD =
// sha256(key ‖ "message-aead"), bucket padding inside the AEAD, base64 on the
// wire. The single shared copy for new suites (several older suites keep a
// private one; migrating them is optional).
//
// Models: the AEAD + padding layer and the epoch tag ([legacyEpochFor] mirrors
// MessageManager.messageEpoch). Does NOT model: the envelope JSON itself (the
// caller writes the exact bytes under test) or the ratchet wire.
// ---------------------------------------------------------------------------

// False on a target with no AES bridge (the iOS simulator test run); every crypto
// test opens with `if (!legacyEnvelopeCryptoUp()) return`.
internal fun legacyEnvelopeCryptoUp(): Boolean = try {
    aesGcmEncrypt(ByteArray(1), generateSecureRandom(32), ByteArray(0)); true
} catch (_: Exception) { false }

// The epoch tag the receiver expects for [secret].
internal fun legacyEpochFor(secret: ByteArray): String =
    bytesToHex(sha256(secret + "msg-epoch".encodeToByteArray()).copyOfRange(0, 6))

// [envelopeJson] padded, sealed under [secret] and base64-encoded: one relay blob.
internal fun sealLegacyEnvelope(secret: ByteArray, envelopeJson: String): String =
    encodeBase64(sealLegacyEnvelopeBytes(secret, envelopeJson))

// [sealLegacyEnvelope] without the base64 layer (what an append POSTs).
internal fun sealLegacyEnvelopeBytes(secret: ByteArray, envelopeJson: String): ByteArray {
    val key = sha256(secret)
    val aad = sha256(key + "message-aead".encodeToByteArray())
    return aesGcmEncrypt(padMessage(envelopeJson.encodeToByteArray()), key, aad)
}

// The un-padded envelope JSON inside one legacy blob (raw bytes, as POSTed).
internal fun openLegacyEnvelope(secret: ByteArray, blob: ByteArray): String {
    val key = sha256(secret)
    val aad = sha256(key + "message-aead".encodeToByteArray())
    return unpadMessage(aesGcmDecrypt(blob, key, aad)).decodeToString()
}

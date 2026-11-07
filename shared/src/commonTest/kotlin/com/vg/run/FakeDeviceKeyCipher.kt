package com.vg.run

// ---------------------------------------------------------------------------
// FakeDeviceKeyCipher — the commonTest stand-in for the platform device key
// behind [SealedPref].
//
// `CryptoProvider` is an `expect class` needing a platform handle, so commonTest
// cannot construct one. This implements the narrow [DeviceKeyCipher] seam
// instead, and it is deliberately NOT a toy "return the input" cipher: the
// properties the two consumers turn on are exactly the ones a toy would lose.
//
//   • CONTEXT BINDING. `open` verifies the context bytes it was sealed with, so
//     a test can prove a blob lifted from another slot does not open here — the
//     reason each consumer gets its own NEW context string.
//   • AUTHENTICATION. Anything that is not something this cipher sealed throws,
//     so a planted value is UNAUTHENTICATED rather than silently accepted. That
//     is the whole of the Debug-mode consent case and half of the push-opt-in case.
//   • THE OUTAGE. [throwOnOpen]/[throwOnSeal] raise [KeyUnavailableException],
//     which [SealedPref] must classify as UNREADABLE and never as a forgery —
//     the distinction the vault's KeyUnavailable = DEFER rule rests on.
//
// It is NOT confidential and makes no attempt to be: the plaintext is visible
// in the "ciphertext". Nothing here tests secrecy; these tests are about
// PROVENANCE.
// ---------------------------------------------------------------------------

internal class FakeDeviceKeyCipher(
    /** The device key cannot be used right now (locked screen / locked keybag). */
    var throwOnOpen: Boolean = false,
    var throwOnSeal: Boolean = false,
    /** The hardware key is gone for good — the distinct permanent case. */
    var permanentlyInvalid: Boolean = false,
) : DeviceKeyCipher {

    override fun seal(plaintext: ByteArray, context: ByteArray): ByteArray {
        if (permanentlyInvalid) throw KeyPermanentlyInvalidException("fake key invalidated")
        if (throwOnSeal) throw KeyUnavailableException("fake key unavailable")
        return MAGIC + byteArrayOf(context.size.toByte()) + context + plaintext
    }

    override fun open(ciphertext: ByteArray, context: ByteArray): ByteArray {
        if (permanentlyInvalid) throw KeyPermanentlyInvalidException("fake key invalidated")
        if (throwOnOpen) throw KeyUnavailableException("fake key unavailable")
        require(ciphertext.size > MAGIC.size + 1) { "not a fake blob" }
        for (i in MAGIC.indices) require(ciphertext[i] == MAGIC[i]) { "not a fake blob" }
        val ctxLen = ciphertext[MAGIC.size].toInt()
        val ctxStart = MAGIC.size + 1
        require(ciphertext.size >= ctxStart + ctxLen) { "truncated fake blob" }
        val sealedCtx = ciphertext.copyOfRange(ctxStart, ctxStart + ctxLen)
        require(sealedCtx.contentEquals(context)) { "AEAD context mismatch" }
        return ciphertext.copyOfRange(ctxStart + ctxLen, ciphertext.size)
    }

    companion object {
        private val MAGIC = byteArrayOf(0x52, 0x55, 0x4E, 0x2D)  // "RUN-"
    }
}

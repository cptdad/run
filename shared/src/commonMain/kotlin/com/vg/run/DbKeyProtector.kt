package com.vg.run

// ---------------------------------------------------------------------------
// DbKeyProtector — the OUTER device-key layer for the wrapped SQLCipher DB key
// (CR-1), split out from the credential-verifier / counter device-key ops so
// the DB-key layer alone can be hardware AUTH-BOUND (Lever B):
// unwrapping it requires a FRESH biometric / device-credential the
// forensic tool can't produce, while the pre-PIN counter/verifier reads keep
// using the non-auth device key (no biometric prompt just to read a counter).
//
// The stored DB-key value is self-describing so a single install can hold
// either scheme and migrate between them without a separate persisted flag.
// The at-rest form is hardened: the value carries no
// human-readable "ab:"/"cp:" scheme WORD. Every freshly written value
// — plain OR auth-bound — shares one scheme-NEUTRAL shape, with the scheme
// discriminator folded into a fixed 1-byte field inside the base64 payload (see
// [DbKeyScheme]). So an at-rest examiner can no longer `grep "ab:"` the store to
// learn which vaults carry the Lever B hardware barrier.
//
// The LENGTH channel is closed too:
// the auth-bound ciphertext (Android RSA-2048 OAEP = 256 B, iOS SE-ECIES ≈ 141 B)
// is structurally longer than the plain AES-GCM one (≈ 88 B), so the byte length
// of the stored value alone would fingerprint Lever B. The current neutral form
// PADS every blob — plain and auth-bound — to ONE fixed decoded length
// ([DbKeyScheme.NEUTRAL_PADDED_LEN]), so neither a zero-work length read nor a
// grep of THIS value distinguishes the scheme at rest.
//
// Legacy forms are still READ (never hard-break an existing vault) and rewritten
// to the current padded-neutral form on the next DB-key write (rotation / KDF
// migration / Lever B toggle / recovery):
//   "<no prefix>"  → legacy CryptoProvider ciphertext (pre-Lever-B installs)
//   "cp:<base64>"  → legacy CryptoProvider ciphertext, explicitly tagged
//   "ab:<base64>"  → legacy auth-bound platform-keystore ciphertext (Lever B)
//   "v:<base64>"   → legacy neutral form (same prefix as the current one, told
//                    apart by the first decoded byte); decoded = schemeByte(1) ‖ payload
//                    (variable length — READ ONLY, rewritten to the padded form)
//   "v:<base64>"   → CURRENT padded-neutral form (first decoded byte 0x02); decoded =
//                    fmt(1)=0x02 ‖ schemeByte(1) ‖ payloadLen(2 BE) ‖ payload ‖ zero-pad,
//                    ALWAYS a fixed NEUTRAL_PADDED_LEN decoded bytes (the leading
//                    0x02 fmt byte — never a legacy scheme byte 0x00/0x01 —
//                    distinguishes it from the legacy neutral form above)
//
// Both auth-bound platform impls route through [DbKeyScheme] — Android
// [AndroidDbKeyProtector] (Keystore RSA) and iOS [IosDbKeyProtector] (Secure
// Enclave ECIES); Lever B has shipped on both.
//
// Known limitation (fully closing it needs the platform
// auth-bound protectors, which are OUTSIDE this file): the LENGTH and grep
// channels are now CLOSED (every fresh blob is one fixed length regardless of
// scheme). What remains is the scheme BYTE itself — it is base64-cleartext, not
// AEAD, because the pure [DbKeyScheme.isAuthBound] classifier the platform
// protectors consume runs PRE-unlock and must decide WITHOUT the device key, so
// the bit cannot be hidden behind encryption in this (deliberately platform-
// crypto-free) file. An examiner who base64-decodes the blob and reads one byte
// can still tell the scheme; a zero-work length OR grep triage no longer can.
// Fully hiding the bit needs an outer device-key wrap of the scheme byte in the
// platform layer, which would break the pure pre-unlock classifier — so it is
// intentionally out of scope here.
// ---------------------------------------------------------------------------

interface DbKeyProtector {

    /** True when this platform/device can hardware auth-bind the DB-key layer. */
    fun supportsAuthBinding(): Boolean

    /** True if [stored] is an auth-bound blob (unwrap will require fresh auth). */
    fun isAuthBoundBlob(stored: String): Boolean

    /**
     * Delete any existing hardware auth-bound key so the NEXT [wrap]
     * (authBound=true) mints a FRESH one. (This only DELETES; the mint happens
     * lazily inside [wrap].) Exactly four callers in VaultSelector:
     *  - the three ENABLE paths — `setDbKeyAuthBinding(true)`, the phase-one
     *    `enableDbKeyAuthBindingWithRecovery` and the post-recovery
     *    `tryReEstablishLeverBAfterRecovery` — each while the stored DB-key blob is
     *    still PLAIN, so no auth-bound blob depends on the key and deleting it never
     *    strands a live ab: blob;
     *  - the unlock-time legacy re-mint (`maybeReconcileLegacyAuthBoundKey`), which
     *    DOES delete the key under a LIVE ab: blob (legacy weak scheme → strict). That
     *    window is netted by a PROVEN recovery blob plus the write-ahead-journal gate,
     *    both checked before the delete — see that function's SAFETY list.
     *
     * Why (PRIVATE-biometric hardening): the biometric-only key strict-invalidates
     * on any Face/Touch-ID re-enrollment. Without this, a stale INVALIDATED key
     * would be reused on the next enable / recovery re-establish, every round-trip
     * verify would fail, and Lever B could never be re-armed after a re-enrollment.
     * Re-minting also guarantees the freshly-armed key carries the CURRENT access
     * control (biometric-only, strict-invalidate) even on a device that once held an
     * older-scheme key. Default no-op — the plain protector has no hardware key.
     *
     * MUST NOT be called by change-PIN or any other re-wrap of an existing ab: blob
     * (change-PIN, the KDF migration and raw-key adoption reuse the SAME valid key;
     * deleting it there would strand the auth-bound blob it still wraps), nor by any
     * new unlock-path caller without the legacy re-mint's PROVEN-recovery net.
     */
    fun deleteAuthBoundKeyBeforeEnable() {}

    /**
     * Wrap the PIN-layer [inner] blob with the outer device-key layer. When
     * [authBound] is true (and [supportsAuthBinding]), the result requires a
     * fresh user authentication to unwrap; otherwise it uses the plain device
     * key. NEVER prompts (auth-bound wrap is an unauthenticated public-key /
     * encrypt op). Returns the string to persist under [VaultStoreKeys.WRAPPED_DBKEY]
     * (or [VaultStoreKeys.PENDING_DBKEY]).
     *
     * [inner] is NOT the raw SQLCipher key: it is the PIN-layer ciphertext
     * `aesGcmEncrypt(DbKeyPayload, kek, DBKEY_INNER)` — IV(12) ‖ payload ‖ tag(16),
     * i.e. 61 B for a passphrase-mode payload (33 B), 93 B for a raw-adopted one
     * (65 B), 60 B for a legacy untagged one (32 B). It is secret-equivalent together with the KEK, so implementations
     * still wipe their copies.
     */
    fun wrap(inner: ByteArray, authBound: Boolean): String

    /**
     * Unwrap a value previously produced by [wrap] (or a legacy untagged
     * CryptoProvider blob). For an auth-bound blob this MAY prompt for user
     * authentication and BLOCK the calling thread — call it off the main
     * thread. Throws [KeyUnavailableException] on any transient/deferrable
     * failure (device locked, biometric cancel/lockout, key temporarily
     * unusable) so the unlock caller retries WITHOUT counting or wiping.
     */
    @Throws(KeyUnavailableException::class)
    fun unwrap(stored: String): ByteArray
}

/**
 * Pure scheme tagging for the stored DB-key value. Kept free of any platform
 * crypto so it is unit-testable in commonTest without a Keystore/Keychain.
 *
 * [tagged] emits the scheme-NEUTRAL "v:<base64>" form for BOTH
 * schemes, with the 1-byte scheme discriminator folded INTO the payload and the
 * whole payload PADDED to one fixed decoded length ([NEUTRAL_PADDED_LEN]) — so
 * at rest neither the value's shape NOR its length gives away which vaults carry
 * the Lever B hardware barrier. [tagOf]/[payloadOf]/
 * [isAuthBound] keep parsing the three legacy forms (untagged, "cp:", "ab:") AND
 * the legacy variable-length neutral form so existing vaults still open;
 * VaultSelector rewrites them to the current padded form on the next DB-key write.
 */
object DbKeyScheme {
    const val TAG_CRYPTO_PROVIDER = "cp"
    const val TAG_AUTH_BOUND = "ab"
    private const val SEP = ':'

    // Scheme-neutral version marker for the indistinguishable form. Base64 never
    // contains ':', and neither the legacy untagged form (no ':') nor the legacy
    // "cp:"/"ab:" forms collide with a leading "v:", so all four are unambiguous.
    private const val MARKER = "v"
    private const val SCHEME_PLAIN: Byte = 0x00
    private const val SCHEME_AUTH_BOUND: Byte = 0x01

    // The CURRENT neutral form pads every DB-key blob
    // to ONE fixed decoded length so the at-rest byte length no longer reveals the
    // scheme. Decoded layout:
    //   fmt(1)=FMT_PADDED ‖ schemeByte(1) ‖ payloadLen(2, big-endian) ‖ payload ‖ zero-pad
    // padded out to exactly [NEUTRAL_PADDED_LEN]. The leading FMT_PADDED byte
    // (0x02) can never be a legacy neutral scheme byte (0x00/0x01), so it cleanly
    // distinguishes the padded form from the legacy variable-length neutral form
    // (decoded = schemeByte(1) ‖ payload), which is still read + rewritten.
    private const val FMT_PADDED: Byte = 0x02
    private const val PADDED_HEADER_LEN = 4          // fmt(1) + scheme(1) + payloadLen(2)

    /** Fixed decoded length of the padded neutral blob. Must exceed the largest
     *  platform auth-bound ciphertext (Android RSA-2048 OAEP = 256 B; iOS SE-ECIES
     *  ≈ 141 B) plus the 4-byte header, with generous headroom for a future larger
     *  key. Every scheme pads to this, so the length distinguishes nothing. */
    const val NEUTRAL_PADDED_LEN = 512

    /** True iff [stored] carries the auth-bound scheme (any format). */
    fun isAuthBound(stored: String): Boolean = tagOf(stored) == TAG_AUTH_BOUND

    /** The scheme tag, or null for the legacy untagged (CryptoProvider) form. */
    fun tagOf(stored: String): String? {
        val i = stored.indexOf(SEP)
        // Base64 never contains ':', so no ':' means the legacy untagged (plain) form.
        if (i <= 0) return null
        val marker = stored.substring(0, i)
        // Neutral form: schemeTagOf reads the folded scheme byte (padded or legacy layout).
        if (marker == MARKER) return schemeTagOf(stored.substring(i + 1))
        // Legacy explicit tags — still recognized so pre-existing vaults open.
        return if (marker == TAG_CRYPTO_PROVIDER || marker == TAG_AUTH_BOUND) marker else null
    }

    /** The base64 payload with any recognized scheme framing stripped. */
    fun payloadOf(stored: String): String {
        val i = stored.indexOf(SEP)
        if (i <= 0) return stored   // legacy untagged
        val marker = stored.substring(0, i)
        if (marker == MARKER) {
            // Neutral form: drop the scheme framing + any padding, hand back the
            // raw base64 payload the platform protector originally wrapped.
            val decoded = try { decodeBase64(stored.substring(i + 1)) } catch (_: Exception) { return stored }
            if (decoded.isEmpty()) return stored
            if (decoded[0] == FMT_PADDED) {
                // Current padded form: fmt(1) ‖ scheme(1) ‖ len(2 BE) ‖ payload ‖ pad.
                if (decoded.size < PADDED_HEADER_LEN) return stored
                val len = ((decoded[2].toInt() and 0xFF) shl 8) or (decoded[3].toInt() and 0xFF)
                if (len < 0 || PADDED_HEADER_LEN + len > decoded.size) return stored
                return encodeBase64(decoded.copyOfRange(PADDED_HEADER_LEN, PADDED_HEADER_LEN + len))
            }
            // Legacy neutral form: scheme(1) ‖ payload (variable length, no padding).
            return encodeBase64(decoded.copyOfRange(1, decoded.size))
        }
        if (marker == TAG_CRYPTO_PROVIDER || marker == TAG_AUTH_BOUND) return stored.substring(marker.length + 1)
        return stored   // unrecognized leading token → treat as a legacy payload
    }

    /**
     * Frame a base64 [base64Payload] under [tag] in the current scheme-neutral,
     * FIXED-LENGTH form: "v:" + base64(fmt ‖ schemeByte ‖ payloadLen(BE) ‖ payload
     * ‖ zero-pad), padded to [NEUTRAL_PADDED_LEN] decoded bytes. The scheme is
     * carried in a folded 1-byte field (no readable prefix word), and every scheme
     * pads to the SAME length so the stored value's length leaks nothing.
     */
    fun tagged(tag: String, base64Payload: String): String {
        val schemeByte = if (tag == TAG_AUTH_BOUND) SCHEME_AUTH_BOUND else SCHEME_PLAIN
        val payload = decodeBase64(base64Payload)
        require(payload.size <= NEUTRAL_PADDED_LEN - PADDED_HEADER_LEN) {
            "DB-key payload (${payload.size} B) too large to pad to the common length"
        }
        // Fixed-length frame; the zero-filled tail past the payload is the padding.
        val framed = ByteArray(NEUTRAL_PADDED_LEN)
        framed[0] = FMT_PADDED
        framed[1] = schemeByte
        framed[2] = ((payload.size ushr 8) and 0xFF).toByte()
        framed[3] = (payload.size and 0xFF).toByte()
        payload.copyInto(framed, PADDED_HEADER_LEN)
        return "$MARKER$SEP${encodeBase64(framed)}"
    }

    /** Map the folded scheme byte of a neutral-form payload back to its tag,
     *  handling both the current padded layout (scheme in byte[1] behind the fmt
     *  byte) and the legacy variable-length layout (scheme in byte[0]). */
    private fun schemeTagOf(base64WithScheme: String): String? {
        val decoded = try { decodeBase64(base64WithScheme) } catch (_: Exception) { return null }
        if (decoded.isEmpty()) return null
        val schemeByte = if (decoded[0] == FMT_PADDED) {
            if (decoded.size < 2) return null
            decoded[1]
        } else {
            decoded[0]   // legacy neutral: the first byte IS the scheme
        }
        return if (schemeByte == SCHEME_AUTH_BOUND) TAG_AUTH_BOUND else TAG_CRYPTO_PROVIDER
    }
}

/**
 * Default protector: the pre-Lever-B behavior. Wraps/unwraps with the platform
 * [CryptoProvider] device key (Tink on Android, Keychain on iOS) and NO
 * fresh-auth requirement. Emits the scheme-neutral "v:" form tagged as
 * CryptoProvider (no readable scheme word); reads the legacy untagged,
 * "cp:" and neutral forms, and (defensively) refuses "ab:" / neutral-auth-bound
 * blobs (it cannot unwrap an auth-bound blob — that needs the platform auth-bound
 * protector, so surface it as unavailable rather than a silent wrong-key error).
 */
class CryptoProviderDbKeyProtector(
    private val crypto: CryptoProvider,
    private val context: ByteArray,
) : DbKeyProtector {

    override fun supportsAuthBinding(): Boolean = false

    override fun isAuthBoundBlob(stored: String): Boolean = DbKeyScheme.isAuthBound(stored)

    override fun wrap(inner: ByteArray, authBound: Boolean): String =
        // authBound is ignored — this impl has no auth-bound key. That is safe ONLY
        // because supportsAuthBinding() is false: every Lever B enable path in
        // VaultSelector refuses before it reaches here, and the re-wrap paths
        // (change-PIN, KDF migration) pass authBound=true only after unwrapping an
        // auth-bound blob, which unwrap() below refuses. A plain blob written for a
        // genuine authBound=true request would otherwise silently drop Lever B. Emit the
        // scheme-neutral form so a plain vault is indistinguishable at rest from
        // an auth-bound one; legacy readers are unaffected because the
        // read path below parses the untagged form too.
        DbKeyScheme.tagged(DbKeyScheme.TAG_CRYPTO_PROVIDER, encodeBase64(crypto.encrypt(inner, context)))

    @Throws(KeyUnavailableException::class)
    override fun unwrap(stored: String): ByteArray {
        if (DbKeyScheme.isAuthBound(stored)) {
            // An auth-bound blob but no auth-bound protector on this build —
            // treat as a deferrable unavailability, never a wrong-key wipe.
            throw KeyUnavailableException("auth-bound DB key blob but no auth-bound protector available")
        }
        return crypto.decrypt(decodeBase64(DbKeyScheme.payloadOf(stored)), context)
    }
}

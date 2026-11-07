package com.vg.run

// ---------------------------------------------------------------------------
// PlatformCrypto — platform-agnostic cryptographic hash utilities.
//
// On Android: backed by java.security.MessageDigest.
// On iOS: backed by CryptoKit (via the Swift bridge — shipped).
// ---------------------------------------------------------------------------

/** Computes SHA-256 hash of [data]. */
expect fun sha256(data: ByteArray): ByteArray

/** Constant-time comparison of two byte arrays. Prevents timing attacks. */
expect fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean

/**
 * Encrypts [plaintext] with AES-256-GCM using [key] (32 bytes) and
 * [associatedData] for authentication. Returns IV + ciphertext + tag.
 *
 * Used for message encryption where the key is derived from the shared
 * secret (known to both devices), NOT from the device-local Keystore.
 */
expect fun aesGcmEncrypt(plaintext: ByteArray, key: ByteArray, associatedData: ByteArray): ByteArray

/**
 * Decrypts [ciphertext] (IV + ciphertext + tag) with AES-256-GCM using
 * [key] and [associatedData]. Returns the original plaintext.
 */
expect fun aesGcmDecrypt(ciphertext: ByteArray, key: ByteArray, associatedData: ByteArray): ByteArray

/** PBKDF2-SHA256 key derivation with configurable iteration count. */
expect fun pbkdf2Sha256(password: ByteArray, salt: ByteArray, iterations: Int, keyLengthBytes: Int): ByteArray

/**
 * Argon2id (RFC 9106) memory-hard key derivation. [memoryKiB] is the memory
 * cost in kibibytes, [iterations] the time cost (passes), [parallelism] the
 * lane/thread count. Argon2 version 0x13 (the current standard). Used for the
 * vault credential/DB-key KDF (KDF_VERSION_3) — memory-hardness is the real
 * defense for a low-entropy 6-digit PIN against GPU/ASIC brute force, which
 * PBKDF2 (compute-hard only) cannot provide.
 *
 * NOTE: the vault is device-local — a credential provisioned on one device is
 * only ever verified on that same device with the SAME platform impl — so the
 * Android (native vendored Argon2, BouncyCastle fallback) and iOS (vendored PHC reference) actuals need not agree
 * bit-for-bit with each other, only each be a correct Argon2id. Both are pinned
 * to the PHC reference implementation's published test vectors (P-H-C/
 * phc-winner-argon2 src/test.c, version 0x13) in VaultKdfTest to prove correctness.
 */
expect fun argon2id(
    password: ByteArray,
    salt: ByteArray,
    memoryKiB: Int,
    iterations: Int,
    parallelism: Int,
    keyLengthBytes: Int
): ByteArray

/** Platform-native HMAC-SHA256. */
expect fun platformHmacSha256(key: ByteArray, data: ByteArray): ByteArray

/**
 * Derives a shared secret from two independently generated secrets.
 * Orders the inputs by their SHA-256 (deterministic, not lexicographic) before hashing so both parties
 * compute the same result regardless of which secret is "local" vs
 * "remote".
 */
fun deriveSharedSecret(secretA: ByteArray, secretB: ByteArray): ByteArray {
    val (first, second) = if (compareBytes(secretA, secretB) <= 0) {
        secretA to secretB
    } else {
        secretB to secretA
    }
    // The concatenation is a verbatim copy of BOTH pairing halves — wipe it once
    // hashed (the digest is identical; only the transient copy is zeroed).
    val merged = first + second
    try {
        return sha256(merged)
    } finally {
        merged.secureWipe()
    }
}

/**
 * HMAC-SHA256 — used for HKDF-Extract in key derivation.
 * Implements RFC 2104 using the platform SHA-256.
 */
fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray =
    platformHmacSha256(key, data)

// ---------------------------------------------------------------------------
// X25519 (Curve25519) ECDH — asymmetric key agreement for REFERRED contacts.
//
// The IRL QR pairing builds a shared secret by combining two SYMMETRIC secrets
// (deriveSharedSecret = sha256(sort(a,b))). That can't be relayed through an
// introducer without the introducer learning both halves and being able to
// MITM. A referral therefore uses X25519: each introducee sends only its
// PUBLIC key through the introducer and derives the shared key from
// ECDH(myPriv, theirPub), which a PASSIVE introducer (seeing only public keys)
// cannot compute. The raw ECDH output is NOT a key — always run it through
// [hkdfSha256] first. (See referral.md.)
//
// CAVEAT: "cannot compute" applies to a passive introducer only. An ACTIVE
// introducer can still MITM by substituting her own X25519 public key in the
// relayed handshake (valid keypairs, so x25519EcdhChecked's low-order guard
// does not catch it) — a deliberate trade-off under referral.md "Decision C"
// (transitive trust, no out-of-band verification). See the fuller note in
// ReferralManager's header.
// ---------------------------------------------------------------------------

/** An X25519 keypair. [publicKey] is safe to send; [privateKey] never leaves the device. */
class X25519Keypair(val privateKey: ByteArray, val publicKey: ByteArray)

/** Generates a fresh ephemeral X25519 keypair (both 32 bytes). */
expect fun x25519GenerateKeypair(): X25519Keypair

/**
 * X25519 ECDH: the raw 32-byte shared point from our [privateKey] and the
 * peer's [peerPublicKey] (RFC 7748 scalar multiplication, no hashing). MUST be
 * passed through [hkdfSha256] before use as a key — never use it directly.
 */
expect fun x25519Ecdh(privateKey: ByteArray, peerPublicKey: ByteArray): ByteArray

/**
 * [x25519Ecdh] with a contributory-behaviour guard (RFC 7748 §6.1).
 *
 * A referral routes the peer's PUBLIC key through the introducer, so a malicious
 * introducer can substitute a *low-order* point. For such a point the X25519
 * scalar-mult collapses to the all-zero output — an attacker-PREDICTABLE
 * "shared secret" that would let the introducer derive the contact key and MITM
 * the channel, defeating the whole reason a referral uses X25519 instead of a
 * relayed symmetric secret.
 *
 * Android (Tink) already rejects low-order inputs inside [x25519Ecdh]; iOS
 * CryptoKit does NOT — it returns the all-zero point. This shared check closes
 * the gap on BOTH platforms by rejecting an all-zero result in constant time
 * (no early exit on the first non-zero byte). Throws [IllegalStateException] on
 * a degenerate result so the caller aborts the handshake rather than
 * establishing an introducer-known key.
 */
fun x25519EcdhChecked(privateKey: ByteArray, peerPublicKey: ByteArray): ByteArray {
    val shared = x25519Ecdh(privateKey, peerPublicKey)
    var acc = 0
    for (b in shared) acc = acc or b.toInt()
    if (acc == 0) {
        throw IllegalStateException(
            "X25519 produced a degenerate all-zero shared secret — low-order peer key rejected"
        )
    }
    return shared
}

/**
 * HKDF-SHA256 (RFC 5869): extract-then-expand. Turns a non-uniform input
 * (e.g. an X25519 ECDH shared point) into [length] bytes of uniformly-random
 * key material. Pure commonMain over [hmacSha256] — no platform surface.
 */
fun hkdfSha256(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
    require(length in 1..8160) { "HKDF length out of range" }  // 255 * 32
    // Extract: PRK = HMAC(salt, IKM); a zero-filled 32-byte salt when none given.
    val prk = hmacSha256(if (salt.isEmpty()) ByteArray(32) else salt, ikm)
    // Expand. RAM hygiene (output unchanged): the PRK, every block T(i) (together a
    // full copy of the output) and every `T(i-1) ‖ info ‖ i` input are wiped; a
    // block is wiped only AFTER the next one has been computed from it.
    val out = ByteArray(length)
    var t = ByteArray(0)
    try {
        var pos = 0
        var counter = 1
        while (pos < length) {
            val input = ByteArray(t.size + info.size + 1)
            t.copyInto(input, destinationOffset = 0)
            info.copyInto(input, destinationOffset = t.size)
            input[input.size - 1] = counter.toByte()
            val next = try {
                hmacSha256(prk, input)
            } finally {
                input.secureWipe()
            }
            t.secureWipe()
            t = next
            val n = minOf(t.size, length - pos)
            t.copyInto(out, destinationOffset = pos, startIndex = 0, endIndex = n)
            pos += n
            counter++
        }
        return out
    } finally {
        t.secureWipe()
        prk.secureWipe()
    }
}

// ---------------------------------------------------------------------------
// Message padding — hides plaintext length from traffic analysis.
//
// Pads to the next power-of-two bucket (min 256 bytes, max 131072 bytes).
// Format: 4-byte big-endian real length prefix + payload + random padding.
// ---------------------------------------------------------------------------

private const val PAD_MIN = 256
private const val PAD_MAX = 131072

/**
 * Largest plaintext [padMessage] can pack — the max bucket minus the 4-byte
 * length prefix. Callers should reject oversize payloads up-front
 * instead of relying on padMessage to throw mid-encrypt.
 */
const val MAX_PADDED_PAYLOAD_BYTES = PAD_MAX - 4

fun padMessage(plaintext: ByteArray): ByteArray {
    val totalNeeded = 4 + plaintext.size  // length prefix + payload
    // An oversize payload previously clamped the bucket to PAD_MAX and
    // then threw IndexOutOfBounds from copyInto (computing a negative
    // random-pad length) — an opaque crash swallowed as a silent send failure.
    // Fail fast with a clear message; callers pre-check against
    // MAX_PADDED_PAYLOAD_BYTES.
    require(totalNeeded <= PAD_MAX) {
        "message too large to pad: $totalNeeded > $PAD_MAX bytes"
    }
    var bucket = PAD_MIN
    while (bucket < totalNeeded && bucket < PAD_MAX) bucket *= 2

    val padded = ByteArray(bucket)
    // 4-byte big-endian length prefix
    padded[0] = (plaintext.size shr 24).toByte()
    padded[1] = (plaintext.size shr 16).toByte()
    padded[2] = (plaintext.size shr 8).toByte()
    padded[3] = (plaintext.size).toByte()
    plaintext.copyInto(padded, destinationOffset = 4)
    // Fill remaining bytes with random to prevent pattern detection
    val randomPad = generateSecureRandom(bucket - totalNeeded)
    randomPad.copyInto(padded, destinationOffset = totalNeeded)
    return padded
}

// ---------------------------------------------------------------------------
// Base64url-no-pad encoder.
//
// The relay's capability protocol uses base64url-no-pad (RFC 4648 §5) for
// inbox IDs (24 bytes → 32 chars) and capabilities (32 bytes → 43 chars).
// Standard base64 (`encodeBase64`) uses `+` / `/` which break URL parsers
// and don't match what the relay returns. This encoder produces only
// `[A-Za-z0-9_-]`. Pure Kotlin so it's available in commonMain without a
// new expect/actual.
// ---------------------------------------------------------------------------
private const val BASE64URL_ALPHABET =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

fun encodeBase64Url(bytes: ByteArray): String {
    if (bytes.isEmpty()) return ""
    val sb = StringBuilder(((bytes.size + 2) / 3) * 4)
    var i = 0
    while (i + 3 <= bytes.size) {
        val b0 = bytes[i].toInt() and 0xFF
        val b1 = bytes[i + 1].toInt() and 0xFF
        val b2 = bytes[i + 2].toInt() and 0xFF
        sb.append(BASE64URL_ALPHABET[b0 ushr 2])
        sb.append(BASE64URL_ALPHABET[((b0 and 0x03) shl 4) or (b1 ushr 4)])
        sb.append(BASE64URL_ALPHABET[((b1 and 0x0F) shl 2) or (b2 ushr 6)])
        sb.append(BASE64URL_ALPHABET[b2 and 0x3F])
        i += 3
    }
    val rem = bytes.size - i
    if (rem == 1) {
        val b0 = bytes[i].toInt() and 0xFF
        sb.append(BASE64URL_ALPHABET[b0 ushr 2])
        sb.append(BASE64URL_ALPHABET[(b0 and 0x03) shl 4])
    } else if (rem == 2) {
        val b0 = bytes[i].toInt() and 0xFF
        val b1 = bytes[i + 1].toInt() and 0xFF
        sb.append(BASE64URL_ALPHABET[b0 ushr 2])
        sb.append(BASE64URL_ALPHABET[((b0 and 0x03) shl 4) or (b1 ushr 4)])
        sb.append(BASE64URL_ALPHABET[(b1 and 0x0F) shl 2])
    }
    return sb.toString()
}

fun unpadMessage(padded: ByteArray): ByteArray {
    require(padded.size >= 4) { "Padded message too short" }
    val len = ((padded[0].toInt() and 0xFF) shl 24) or
              ((padded[1].toInt() and 0xFF) shl 16) or
              ((padded[2].toInt() and 0xFF) shl 8) or
               (padded[3].toInt() and 0xFF)
    require(len >= 0 && len <= padded.size - 4) { "Invalid padding length" }
    return padded.copyOfRange(4, 4 + len)
}

private fun compareBytes(a: ByteArray, b: ByteArray): Int {
    // Hash both and compare hashes to determine ordering (not constant-time).
    // The sort order just needs to be deterministic, not preserve byte ordering.
    val hashA = sha256(a)
    val hashB = sha256(b)
    for (i in hashA.indices) {
        val cmp = (hashA[i].toInt() and 0xFF) - (hashB[i].toInt() and 0xFF)
        if (cmp != 0) return cmp
    }
    return 0
}

/** Best-effort zeroing of sensitive byte arrays. */
fun ByteArray.secureWipe() { fill(0) }

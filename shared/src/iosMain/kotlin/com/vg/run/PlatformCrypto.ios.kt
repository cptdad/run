@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package com.vg.run

import kotlinx.cinterop.*
import runcrypto.*

// ---------------------------------------------------------------------------
// PlatformCrypto — iOS actual implementations.
//
// SHA-256:     CC_SHA256 from CommonCrypto / libSystem (stable public API).
// AES-256-GCM: Delegated to AesGcmBridge, implemented in Swift via CryptoKit.
//              Wire format: IV(12) + ciphertext + tag(16) — matches Android.
// ---------------------------------------------------------------------------

private const val GCM_IV_LEN  = 12
private const val GCM_TAG_LEN = 16

actual fun sha256(data: ByteArray): ByteArray {
    val digest = ByteArray(CC_SHA256_DIGEST_LENGTH)
    data.usePinned { pinnedData ->
        digest.usePinned { pinnedDigest ->
            CC_SHA256(
                pinnedData.addressOf(0),
                data.size.convert(),
                pinnedDigest.addressOf(0).reinterpret()
            )
        }
    }
    return digest
}

actual fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
    var diff = a.size xor b.size
    val minLen = minOf(a.size, b.size)
    for (i in 0 until minLen) diff = diff or (a[i].toInt() xor b[i].toInt())
    return diff == 0
}

actual fun aesGcmEncrypt(plaintext: ByteArray, key: ByteArray, associatedData: ByteArray): ByteArray {
    require(key.size == 32) { "AES-256-GCM requires a 32-byte key" }
    val bridge = AesGcmBridgeHolder.bridge ?: error("AesGcmBridge not registered — call AesGcmBridgeHolder.bridge = ... before use")
    // key.toNSData() copies the vault/device AES-256 key
    // into a fresh NSData on EVERY vault crypto op; ARC frees it without zeroing.
    // Hold the copy and wipe its bytes in a finally so the key does not linger in a
    // freed heap block.
    // The PLAINTEXT copy needs the identical treatment — on
    // the vault paths it IS the raw SQLCipher DB key (VaultSelector seals it here on
    // every provision / change-PIN / re-wrap), and commonMain can only wipe the
    // ByteArray it owns, never this bridge-boundary copy. Both NSData objects are
    // private +[NSData dataWithBytes:length:] copies minted by toNSData() and are
    // referenced by nothing else once the bridge call has returned, so the memset
    // can never reach storage shared with a live object. (associatedData is AEAD
    // context, not secret; the returned ciphertext is not secret either.)
    val keyData = key.toNSData()
    val plaintextData = plaintext.toNSData()
    val out = try {
        bridge.encrypt(plaintextData, keyData, associatedData.toNSData()).toByteArray()
    } finally {
        plaintextData.secureWipeBytes()
        keyData.secureWipeBytes()
    }
    // #24: a successful GCM seal always yields IV(12) + ciphertext + tag(16),
    // i.e. >= 28 bytes. SwiftAesGcm returns an empty Data when CryptoKit throws
    // (it cannot rethrow across the non-throwing bridge without trapping the
    // process via try!). Turn that failure signal into a catchable Kotlin
    // exception so the caller fails the send gracefully instead of crashing.
    check(out.size >= GCM_IV_LEN + GCM_TAG_LEN) { "AES-GCM encryption failed" }
    return out
}

actual fun aesGcmDecrypt(ciphertext: ByteArray, key: ByteArray, associatedData: ByteArray): ByteArray {
    require(key.size == 32) { "AES-256-GCM requires a 32-byte key" }
    require(ciphertext.size >= GCM_IV_LEN + GCM_TAG_LEN) { "Ciphertext too short" }
    val bridge = AesGcmBridgeHolder.bridge ?: error("AesGcmBridge not registered — call AesGcmBridgeHolder.bridge = ... before use")
    // Same vault/device AES-256 key NSData copy as the
    // encrypt sibling — wipe it in a finally so it does not linger in freed heap.
    val keyData = key.toNSData()
    val result = try {
        bridge.decrypt(ciphertext.toNSData(), keyData, associatedData.toNSData())
    } finally {
        keyData.secureWipeBytes()
    }
    val plaintextData = result
        ?: throw IllegalStateException("AES-GCM decryption failed: authentication tag mismatch or corrupted ciphertext")
    // `plaintextData` carries the RECOVERED PLAINTEXT — on
    // the unlock path that is the raw SQLCipher DB key, previously dropped to ARC
    // unzeroed on every unlock. Unlike the key/plaintext copies above this NSData was
    // NOT minted by toNSData(), so the uniqueness argument is worth spelling out:
    // SwiftAesGcm.decrypt (SwiftAesGcm.swift:44) returns AES.GCM.open's output, a
    // freshly allocated per-call Data that shares no storage with the SealedBox or the
    // ciphertext, and the Swift frame holding it is gone by the time we get here — so
    // this reference is the sole owner and the memset cannot corrupt live data.
    // Known limitation: for a plaintext short enough to use Data's INLINE representation the
    // Swift→ObjC bridge hands us a copy, so the memset zeroes only that copy (the
    // same "a value-returning bridge cannot wipe its own return value" residual
    // already documented in SwiftArgon2/SwiftX25519). Every vault secret routed
    // through here is >= 32 bytes and therefore heap-backed, i.e. genuinely zeroed.
    return try {
        plaintextData.toByteArray()
    } finally {
        plaintextData.secureWipeBytes()
    }
}

actual fun pbkdf2Sha256(password: ByteArray, salt: ByteArray, iterations: Int, keyLengthBytes: Int): ByteArray {
    require(salt.isNotEmpty()) { "PBKDF2 salt must not be empty" }
    val derived = ByteArray(keyLengthBytes)
    // The CommonCrypto cinterop binds `const char *password` to Kotlin String?,
    // so the password must be passed as a String. Decoding the bytes back to a
    // String round-trips exactly for valid UTF-8 (credentials always are), and
    // CCKeyDerivationPBKDF reads `passwordLen` bytes from the encoded buffer —
    // so we pass the true BYTE length (password.size). The old code passed
    // `passwordStr.length`, the UTF-16 unit count, which is smaller than the
    // UTF-8 byte length for any multibyte credential and derived the WRONG
    // key. We also capture and check the CCCryptorStatus instead of
    // ignoring it (a non-success status left `derived` all-zero — a silent
    // catastrophic failure).
    val passwordStr = password.decodeToString()
    val status: Int = derived.usePinned { pinnedDerived ->
        salt.usePinned { pinnedSalt ->
            CCKeyDerivationPBKDF(
                kCCPBKDF2.convert(),
                passwordStr,
                password.size.convert(),
                pinnedSalt.addressOf(0).reinterpret(),
                salt.size.convert(),
                kCCPRFHmacAlgSHA256.convert(),
                iterations.convert(),
                pinnedDerived.addressOf(0).reinterpret(),
                keyLengthBytes.convert()
            )
        }
    }
    // kCCSuccess == 0; anything else (e.g. kCCParamError) means the derivation
    // did not run and `derived` is still all-zero — fail loudly.
    check(status == 0) { "PBKDF2 key derivation failed (CCCryptorStatus=$status)" }
    return derived
}

actual fun argon2id(
    password: ByteArray,
    salt: ByteArray,
    memoryKiB: Int,
    iterations: Int,
    parallelism: Int,
    keyLengthBytes: Int
): ByteArray {
    require(salt.isNotEmpty()) { "Argon2 salt must not be empty" }
    val bridge = Argon2BridgeHolder.bridge
        ?: error("Argon2Bridge not registered — call Argon2BridgeHolder.bridge = ... before use")
    // password.toNSData() copies the raw PIN/passphrase
    // into a fresh NSData for the bridge; ARC frees it WITHOUT zeroing. Hold the copy
    // and wipe its bytes in a finally so the credential never lingers in a freed heap
    // block after an unlock/provision. (salt is not secret.)
    val pwData = password.toNSData()
    val derived = try {
        bridge.argon2id(
            pwData, salt.toNSData(),
            memoryKiB, iterations, parallelism, keyLengthBytes
        )
    } finally {
        pwData.secureWipeBytes()
    }
    // The RETURN value is `stretched` — the full Argon2id
    // output the vault derives BOTH the credential verifier (sha256(stretched‖
    // LABEL_CRED)) and the DB-key KEK (sha256(stretched‖LABEL_KEK)) from. commonMain
    // wipes the ByteArray it owns, but this bridge-boundary NSData used to be dropped
    // to ARC unzeroed on every unlock, handing an examiner a way to skip the
    // 64 MiB × 3 KDF entirely. It is uniquely owned: SwiftArgon2 (SwiftArgon2.swift:49)
    // deliberately returns an INDEPENDENT `Data(bytes:count:)` copy — its own working
    // buffer is memset_s'd by a defer — and the Swift frame is gone by the time we
    // hold it, so nothing else can observe the memset.
    val stretchedData = derived ?: throw IllegalStateException("Argon2id derivation failed")
    return try {
        val out = stretchedData.toByteArray()
        // A successful derivation always returns exactly keyLengthBytes; anything
        // else means the bridge misbehaved — fail loudly rather than hand the vault
        // a wrong-size (potentially all-zero) key.
        check(out.size == keyLengthBytes) { "Argon2id output length mismatch: ${out.size}" }
        out
    } finally {
        stretchedData.secureWipeBytes()
    }
}

actual fun platformHmacSha256(key: ByteArray, data: ByteArray): ByteArray {
    val mac = ByteArray(32)  // SHA-256 output is 32 bytes
    key.usePinned { pinnedKey ->
        data.usePinned { pinnedData ->
            mac.usePinned { pinnedMac ->
                CCHmac(
                    kCCHmacAlgSHA256.convert(),
                    pinnedKey.addressOf(0),
                    key.size.convert(),
                    pinnedData.addressOf(0),
                    data.size.convert(),
                    pinnedMac.addressOf(0)
                )
            }
        }
    }
    return mac
}

// --- X25519 ECDH (referral key agreement) — CryptoKit via SwiftX25519 --------
actual fun x25519GenerateKeypair(): X25519Keypair {
    val bridge = X25519BridgeHolder.bridge
        ?: error("X25519Bridge not registered — call X25519BridgeHolder.bridge = ... before use")
    // The bridge return holds the fresh X25519 PRIVATE key in
    // bytes 0..31 and was dropped to ARC unzeroed. Uniquely owned: SwiftX25519
    // (SwiftX25519.swift:34) returns `rawPriv + publicKey.rawRepresentation`, a new
    // buffer allocated by the concatenation (its `rawPriv` input is separately
    // memset_s'd by a defer), and the Swift frame is gone by the time we hold it — so
    // the memset cannot reach storage anything else still reads.
    val combinedData = bridge.generateKeypair()
    val combined = try {
        combinedData.toByteArray()
    } finally {
        combinedData.secureWipeBytes()
    }
    try {
        check(combined.size == 64) { "X25519 keypair generation failed" }
        return X25519Keypair(
            privateKey = combined.copyOfRange(0, 32),
            publicKey = combined.copyOfRange(32, 64),
        )
    } finally {
        // `combined` bytes 0..31 hold the ephemeral X25519 private key. The
        // copyOfRange sub-arrays returned above are independent copies (the
        // caller's, e.g. ReferralManager, to scrub), so wiping `combined` here
        // does not disturb them. Zero it on every path so this duplicate does
        // not linger past the caller's key-scrub.
        combined.secureWipe()
    }
}

actual fun x25519Ecdh(privateKey: ByteArray, peerPublicKey: ByteArray): ByteArray {
    require(privateKey.size == 32 && peerPublicKey.size == 32) { "X25519 keys must be 32 bytes" }
    val bridge = X25519BridgeHolder.bridge
        ?: error("X25519Bridge not registered — call X25519BridgeHolder.bridge = ... before use")
    // privateKey.toNSData() copies the ratchet/referral
    // X25519 PRIVATE key into a fresh NSData for the bridge; ARC frees it without
    // zeroing. Hold and wipe it in a finally. (peerPublicKey is public — not wiped.)
    val privData = privateKey.toNSData()
    val result = try {
        bridge.ecdh(privData, peerPublicKey.toNSData())
    } finally {
        privData.secureWipeBytes()
    }
    // The return value is the raw ECDH SHARED SECRET, which
    // feeds kdfRk — same problem, same fix. Uniquely owned: SwiftX25519
    // (SwiftX25519.swift:43) builds it with `shared.withUnsafeBytes { Data($0) }`, a
    // fresh copy out of CryptoKit's SharedSecret, and the Swift frame that held both
    // is gone by the time we get here. The caller still scrubs its own ByteArray.
    val sharedData = result ?: throw IllegalStateException("X25519 ECDH failed")
    return try {
        sharedData.toByteArray()
    } finally {
        sharedData.secureWipeBytes()
    }
}

package com.vg.run

import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

// One SHA-256 engine per thread, reused across calls. `MessageDigest.getInstance`
// does a JCA provider lookup + SPI allocation on every call — invisible for the
// occasional hash, but it dominated the PoW grind loop (millions of calls per
// inbox mint, e.g. ~10–20 s on a Pixel 9a). MessageDigest is stateful and NOT
// thread-safe, so it must be thread-local; digest() auto-resets the engine, and
// the parallel PoW solver runs one worker (hence one engine) per thread.
private val sha256ThreadLocal: ThreadLocal<MessageDigest> =
    ThreadLocal.withInitial { MessageDigest.getInstance("SHA-256") }

actual fun sha256(data: ByteArray): ByteArray {
    // withInitial guarantees a value; the explicit check turns the Java platform
    // type into a non-null Kotlin type (a Kotlin 2.4 warning on the way to an error).
    val digest = checkNotNull(sha256ThreadLocal.get())
    digest.reset()
    return digest.digest(data)
}

actual fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean =
    MessageDigest.isEqual(a, b)

actual fun aesGcmEncrypt(plaintext: ByteArray, key: ByteArray, associatedData: ByteArray): ByteArray {
    // Parity with the iOS actual + defense-in-depth: SecretKeySpec(key,"AES")
    // would silently accept a 16/24-byte key and select AES-128/192. Require
    // 32 bytes so a non-256-bit key can never reach the cipher.
    require(key.size == 32) { "AES-256-GCM requires a 32-byte key" }
    val iv = ByteArray(12).also { secureRandom.nextBytes(it) }
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
    cipher.updateAAD(associatedData)
    val encrypted = cipher.doFinal(plaintext)
    // Return IV (12 bytes) + ciphertext + GCM tag
    return iv + encrypted
}

actual fun aesGcmDecrypt(ciphertext: ByteArray, key: ByteArray, associatedData: ByteArray): ByteArray {
    // A well-formed payload is IV(12) ‖ ciphertext ‖ GCM tag(16) — minimum 28
    // bytes. Reject anything shorter with a clear error rather than letting
    // copyOfRange(0, 12) throw IndexOutOfBounds on a truncated/garbage blob.
    require(ciphertext.size >= 12 + 16) { "AES-GCM ciphertext too short: ${ciphertext.size}" }
    require(key.size == 32) { "AES-256-GCM requires a 32-byte key" }
    val iv = ciphertext.copyOfRange(0, 12)
    val data = ciphertext.copyOfRange(12, ciphertext.size)
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
    cipher.updateAAD(associatedData)
    return cipher.doFinal(data)
}

actual fun pbkdf2Sha256(password: ByteArray, salt: ByteArray, iterations: Int, keyLengthBytes: Int): ByteArray {
    // Defense-in-depth parity with the iOS actual: reject an empty salt rather
    // than derive a salt-less (rainbow-tableable) key.
    require(salt.isNotEmpty()) { "PBKDF2 salt must not be empty" }
    // Keep the exact char derivation (String(password, UTF-8).toCharArray()) so
    // the PBKDF2 output is byte-identical to before — must not break existing
    // stored credential verifiers / wrapped DB keys.
    val chars = String(password, Charsets.UTF_8).toCharArray()
    val spec = javax.crypto.spec.PBEKeySpec(chars, salt, iterations, keyLengthBytes * 8)
    chars.fill('\u0000')  // PBEKeySpec clones the array; zero our copy immediately.
    return try {
        javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            .generateSecret(spec).encoded
    } finally {
        spec.clearPassword()  // zero the char[] PBEKeySpec held.
    }
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
    // Native first: the vendored PHC reference C (the exact code iOS runs); BouncyCastle
    // took 3.79 s at the release cost on a Samsung A13. null ONLY when librunargon2.so cannot be
    // linked; an argon2 error THROWS out of here and is never retried on BouncyCastle
    // (see NativeArgon2). Both implementations are pinned to the same vectors and
    // proven byte-equal on device (VaultKdfTest, Argon2NativeEquivalenceTest), so a
    // vault provisioned by either keeps unlocking under the other.
    NativeArgon2.deriveOrNull(password, salt, memoryKiB, iterations, parallelism, keyLengthBytes)
        ?.let { return it }
    return argon2idBouncyCastle(password, salt, memoryKiB, iterations, parallelism, keyLengthBytes)
}

/**
 * The pure-Java Argon2id (BouncyCastle) — the fallback when the native library cannot
 * load, and the reference the native path is proven byte-equal against. Public (not
 * internal) only so the :androidApp instrumented equivalence test can call it.
 */
fun argon2idBouncyCastle(
    password: ByteArray,
    salt: ByteArray,
    memoryKiB: Int,
    iterations: Int,
    parallelism: Int,
    keyLengthBytes: Int
): ByteArray {
    require(salt.isNotEmpty()) { "Argon2 salt must not be empty" }
    // BouncyCastle's LOW-LEVEL generator (not the JCE provider) — invoked
    // directly, no Security.addProvider / reflection, so R8 can strip the rest
    // of bcprov and only Argon2BytesGenerator + Blake2b survive into the release
    // APK. The password is consumed as raw bytes (RFC 9106 takes a byte string),
    // unlike PBKDF2's UTF-8 char handling.
    val params = org.bouncycastle.crypto.params.Argon2Parameters
        .Builder(org.bouncycastle.crypto.params.Argon2Parameters.ARGON2_id)
        .withVersion(org.bouncycastle.crypto.params.Argon2Parameters.ARGON2_VERSION_13)
        .withSalt(salt)
        .withMemoryAsKB(memoryKiB)
        .withIterations(iterations)
        .withParallelism(parallelism)
        .build()
    val gen = org.bouncycastle.crypto.generators.Argon2BytesGenerator()
    gen.init(params)
    val out = ByteArray(keyLengthBytes)
    gen.generateBytes(password, out)
    return out
}

// One HMAC-SHA256 engine per thread, reused across calls — the exact sibling of the
// sha256 cache at the top of this file, and for the same reason: `Mac.getInstance`
// does a JCA provider lookup + SPI allocation on EVERY call. That was invisible while
// HMAC was an occasional primitive, but the Double Ratchet made it a hot loop — one
// chain-key derivation is 2 HMACs and a single decrypt can drive up to 2 x MAX_SKIP of
// them, which is what made a forged 72-byte ratchet blob a ~1000x CPU amplifier
// (the budget in RatchetWorkBudget is the other half of
// that fix). Mac is stateful and NOT thread-safe, so it must be thread-local;
// doFinal() resets the engine to its post-init state and init() re-keys it, so one
// instance serves every caller on that thread. iOS needs no sibling change: its actual
// calls CCHmac one-shot, with no object to allocate and no provider to look up.
private val hmacSha256ThreadLocal: ThreadLocal<javax.crypto.Mac> =
    ThreadLocal.withInitial { javax.crypto.Mac.getInstance("HmacSHA256") }

/** All-zero key used to re-key the cached engine after each use — see below. */
private val hmacScrubKey = javax.crypto.spec.SecretKeySpec(ByteArray(32), "HmacSHA256")

actual fun platformHmacSha256(key: ByteArray, data: ByteArray): ByteArray {
    // withInitial guarantees a value; the explicit check turns the Java platform type
    // into a non-null Kotlin type (same as sha256 above).
    val mac = checkNotNull(hmacSha256ThreadLocal.get())
    mac.init(javax.crypto.spec.SecretKeySpec(key, "HmacSHA256"))
    return try {
        mac.doFinal(data)
    } finally {
        // Caching is the ONE thing that lets a key outlive its call: an engine kept for
        // the life of the thread would hold the last key (a ratchet chain key, an HKDF
        // PRK) in its ipad/opad buffers until the next HMAC on that thread. Re-keying
        // with zeros overwrites those buffers in place — one init, no provider lookup —
        // so the cached path is no worse at rest than the per-call engine it replaces.
        // Never allowed to mask the result: a failed scrub is harmless (the next call
        // re-keys anyway).
        try { mac.init(hmacScrubKey) } catch (_: Exception) {}
    }
}

// --- X25519 ECDH (referral key agreement) — Tink's curve25519 ----------------
// Tink is already a dependency (AEAD). subtle.X25519 is raw RFC 7748 scalar
// multiplication: computeSharedSecret returns the raw 32-byte shared point
// (no hashing), matching iOS CryptoKit's raw SharedSecret. Callers run it
// through hkdfSha256 (commonMain) to derive a usable key.
actual fun x25519GenerateKeypair(): X25519Keypair {
    val priv = com.google.crypto.tink.subtle.X25519.generatePrivateKey()
    val pub = com.google.crypto.tink.subtle.X25519.publicFromPrivate(priv)
    return X25519Keypair(privateKey = priv, publicKey = pub)
}

actual fun x25519Ecdh(privateKey: ByteArray, peerPublicKey: ByteArray): ByteArray =
    com.google.crypto.tink.subtle.X25519.computeSharedSecret(privateKey, peerPublicKey)

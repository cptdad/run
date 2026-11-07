@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class, kotlinx.cinterop.BetaInteropApi::class, kotlin.experimental.ExperimentalNativeApi::class)

package com.vg.run

import kotlinx.cinterop.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import platform.Foundation.*
import platform.Security.SecRandomCopyBytes
import platform.Security.errSecSuccess
import platform.Security.kSecRandomDefault
import platform.posix.memcpy
import platform.posix.memset

// Debug flag — set to false for Release/TestFlight builds.
// Kotlin/Native doesn't have a built-in DEBUG flag, so this is manual.
private val IS_DEBUG: Boolean = Platform.isDebugBinary

actual fun platformLog(tag: String, message: String) {
    LogBuffer.append("D", tag, message)
    if (IS_DEBUG) println("D/$tag: $message")
}

actual fun platformLogWarn(tag: String, message: String) {
    LogBuffer.append("W", tag, message)
    if (IS_DEBUG) println("W/$tag: $message")
}

actual fun platformLogError(tag: String, message: String, throwable: Throwable?) {
    // The throwable's CLASS NAME only: Throwable.toString() appends its message,
    // which can carry a URL, a host or a file path, and LogBuffer lines reach the
    // Debug-mode upload (Android twin: Platform.android.kt).
    val msg = "$message${throwable?.let { " — ${it::class.simpleName}" } ?: ""}"
    LogBuffer.append("E", tag, msg)
    if (IS_DEBUG) println("E/$tag: $msg")
}

// Both of these mint an NSData admissible under the
// [secureWipeBytes] contract below — encode's is CATEGORY 1 (a `toNSData()` copy),
// decode's is CATEGORY 3 (a per-call Foundation computation) — and both carry a
// stronger uniqueness argument than any other site in iosMain: the object NEVER
// ESCAPES its function. It is allocated here, consumed synchronously by exactly
// one call, and dropped; no caller can retain or alias it because no caller can
// name it. `toNSData()` COPIES (`+[NSData dataWithBytes:length:]`), so the memset
// provably cannot reach the caller's `data`; `Base64SecretWipeTest` pins that
// independently rather than assuming it.
//
// Most of the ~17 callers pass ciphertext, where this buys nothing. TWO pass raw
// PLAINTEXT key material and are the reason this exists:
//   • `VaultRatchetStore` (RatchetManager.kt:43/45) — the serialized Double
//     Ratchet state: root key, both chain keys, the DH private key.
//   • `IosVaultDatabase` (:391 insert / :585 read) — the raw 32-byte pairing
//     `sharedSecret`, on every contact write AND every contact read.
// `PairingPayload.parse` (:85/:93) decodes a scanned pairing secret the same way.
//
// HONEST BOUND — this takes N copies to N-1, it does NOT remove the secret from
// RAM. The value encode RETURNS (and the value decode CONSUMES) is a base64
// String holding the same secret, and Kotlin/Native Strings are immutable and
// unwipeable. What it removes is the RAW-BINARY copy left in a freed malloc block
// — the cheapest form for a heap scanner to recognise — and it makes "every
// app-minted NSData of secret material in iosMain is wiped" true with no
// exception left for a future reader to generalise from. Claim no more than that.
actual fun encodeBase64(data: ByteArray): String {
    val nsData = data.toNSData()
    return try {
        nsData.base64EncodedStringWithOptions(0u)
    } finally {
        // Strictly AFTER the encode read. A memset moved above it would silently
        // emit base64 of ZEROES and corrupt every ratchet blob and sharedSecret
        // written thereafter — the catastrophic regression this ordering prevents.
        nsData.secureWipeBytes()
    }
}

actual fun decodeBase64(encoded: String): ByteArray {
    // `-[NSData initWithBase64EncodedString:options:]` is a per-call COMPUTATION
    // over a caller-supplied String with no stored identity to cache or dedupe on,
    // i.e. the same side of the contract's line as `SecKeyCreateDecryptedData`
    // (IosDbKeyProtector.kt:70), not the `SecItemCopyMatching` side (stored item
    // content — permanently not wiped, see CryptoProvider.ios.kt).
    // Cost note: this is the hottest base64 site (MessageManager's drain decodes up
    // to MAX_BLOBS_PER_POLL blobs), but every one of those bytes is already walked
    // by the base64 decode itself and then AES-GCM-opened, so one extra memset per
    // blob is a rounding error on work already being done.
    val nsData = NSData.create(base64EncodedString = encoded, options = 0u)
        ?: throw IllegalArgumentException("Invalid base64")
    return try {
        nsData.toByteArray()        // copy out FIRST …
    } finally {
        nsData.secureWipeBytes()    // … then scrub. Never the other order.
    }
}

actual fun generateSecureRandom(size: Int): ByteArray {
    // addressOf(0) on an empty ByteArray throws, so short-circuit size 0.
    // padMessage legitimately requests 0 random-fill bytes when a payload
    // lands exactly on a bucket boundary (e.g. the max-payload case) — this
    // previously crashed only on iOS.
    if (size <= 0) return ByteArray(0)
    val bytes = ByteArray(size)
    val status = bytes.usePinned { pinned ->
        SecRandomCopyBytes(kSecRandomDefault, size.convert(), pinned.addressOf(0))
    }
    // Fail CLOSED: on failure SecRandomCopyBytes leaves the buffer all-zero,
    // which would be catastrophic for keys/nonces/salts. The previous code
    // ignored the status and returned those zeros — throw instead so a caller
    // can never receive predictable "randomness".
    if (status != errSecSuccess) {
        throw IllegalStateException("SecRandomCopyBytes failed (status=$status)")
    }
    return bytes
}

actual fun secureRandomInt(bound: Int): Int {
    require(bound > 0) { "bound must be positive" }
    // Reject samples ≥ the largest multiple of bound that fits in [0, 2^31)
    // to remove modulo bias for non-power-of-two bounds. Two iterations
    // cover essentially all cases (bound = 2^30 gives ~50% reject; bound
    // ≤ 2^15 gives < 0.001% reject).
    val limit = Int.MAX_VALUE - (Int.MAX_VALUE % bound)
    // Bounded rejection sampling: the per-iteration reject probability is
    // < 50% for any bound, so 64 iterations make an unsatisfied loop
    // astronomically unlikely (< 2^-64). Cap it anyway so a degenerate
    // RNG can never spin forever; the fallback's residual modulo bias is
    // negligible.
    repeat(64) {
        val raw = readInt32() and Int.MAX_VALUE
        if (raw < limit) return raw % bound
    }
    return (readInt32() and Int.MAX_VALUE) % bound
}

private fun readInt32(): Int {
    val bytes = generateSecureRandom(4)
    return ((bytes[0].toInt() and 0xFF) shl 24) or
           ((bytes[1].toInt() and 0xFF) shl 16) or
           ((bytes[2].toInt() and 0xFF) shl 8)  or
            (bytes[3].toInt() and 0xFF)
}

actual fun currentTimeMillis(): Long = (NSDate().timeIntervalSince1970 * 1000.0).toLong()

actual fun sleepMillis(millis: Long) {
    if (millis > 0) NSThread.sleepForTimeInterval(millis / 1000.0)
}

// Native's Dispatchers.IO is a public EXTENSION property (the member is
// internal), so it must be imported (kotlinx.coroutines.IO) and referenced
// unqualified — the fully-qualified form resolves to the internal member.
internal actual val ioDispatcher: kotlinx.coroutines.CoroutineDispatcher
    get() = Dispatchers.IO

// Native's runBlocking is in the same boat as Dispatchers.IO above: the
// commonMain metadata view cannot name it, so the expect/actual carries it.
// Never reached from the main thread — its one caller (the control sweep's peek
// fan-out) already runs on a background Task.
internal actual fun <T> runBlockingIo(block: suspend kotlinx.coroutines.CoroutineScope.() -> T): T =
    kotlinx.coroutines.runBlocking(Dispatchers.IO, block)

// ---------------------------------------------------------------------------
// Internal helpers shared across iosMain Kotlin files.
// ---------------------------------------------------------------------------

@OptIn(ExperimentalForeignApi::class)
internal fun ByteArray.toNSData(): NSData {
    // addressOf(0) on an empty ByteArray throws ArrayIndexOutOfBoundsException —
    // exercised by the new mint POST (which sends a zero-byte body) where the
    // old protocol always carried at least one byte. Short-circuit to an
    // empty NSData rather than crashing.
    if (isEmpty()) return NSData()
    return usePinned { pinned ->
        NSData.create(bytes = pinned.addressOf(0), length = size.convert())
    }
}

@OptIn(ExperimentalForeignApi::class)
internal fun NSData.toByteArray(): ByteArray {
    val out = ByteArray(length.toInt())
    if (out.isNotEmpty()) {
        out.usePinned { pinned ->
            memcpy(pinned.addressOf(0), this.bytes, length)
        }
    }
    return out
}

/**
 * Zero the backing bytes of an NSData that holds secret material, using memset
 * (which the optimizer may not elide) through [bytes] — the NSData's own single
 * buffer. ARC frees an NSData WITHOUT zeroing it, so without this the secret
 * stays resident in the freed heap block until that block is reused.
 *
 * **Contract — exactly three admissible categories of argument.** All are
 * "allocated per call, retained by nobody else at the moment of the memset":
 *
 *  1. **An NSData built HERE by [toNSData]** — a private, exclusively-owned
 *     copy made via +[NSData dataWithBytes:length:]. The PlatformCrypto iOS
 *     bridge sites copy raw secret material (PIN/credential, X25519 private
 *     key, vault/device AES key, the SQLCipher DB key) into these to hand them
 *     to the Swift bridges.
 *  2. **An NSData RETURNED BY ONE OF OUR OWN SWIFT BRIDGES** — `SwiftAesGcm`,
 *     `SwiftArgon2`, `SwiftX25519` or `SecureEnclaveHelper`. Each of those
 *     returns a freshly allocated per-call `Data`/`CFData` (CryptoKit output, a
 *     deliberate independent copy, or a Create-Rule `SecKeyCreateDecryptedData`
 *     result) that aliases none of its inputs, is held by no cache or
 *     singleton, and whose Swift frame is gone by the time the value reaches
 *     Kotlin — so the memset cannot reach storage a live object still reads.
 *     These returns carry the highest-value secrets in the app (recovered
 *     plaintext = the DB key, the Argon2id `stretched` output, X25519 private
 *     keys / shared secrets), which is why wiping them is worth the care.
 *  3. **An NSData returned by a pure per-call FOUNDATION COMPUTATION over
 *     caller-supplied input, that never escapes the function that made it.**
 *     Today the only member is `-[NSData initWithBase64EncodedString:options:]`
 *     in [decodeBase64]. Admissible because the result has no stored
 *     identity for Foundation to cache or dedupe on (it is a transformation of an
 *     arbitrary String, and the output length differs from the input's), it is
 *     Create-Rule +1 owned by us, and its whole lifetime is lexically contained —
 *     the caller receives a [toByteArray] COPY, never the object. This is the
 *     same side of the line as `SecKeyCreateDecryptedData`, and it stops exactly
 *     where `SecItemCopyMatching` starts: a call that returns STORED ITEM CONTENT
 *     is a caching/dedup candidate and must NOT be wiped (see
 *     CryptoProvider.ios.kt — that one is a permanent won't-fix, not a backlog
 *     item). Adding a fourth member of this category requires the same two proofs
 *     spelled out at the site: no stored identity, and no escape.
 *
 * **Every call site of category 2 or 3 must state its OWN uniqueness argument in
 * a comment, naming the Swift file:line (or Foundation selector) that allocates
 * the buffer.** Those two categories are a per-function proof, never a blanket
 * licence: neither extends to any NSData Foundation may share, and wiping one of
 * those (a `+[NSData data]`/empty singleton, a `dispatch_data`/mapped-file or
 * `NoCopy` wrapper, an `NSData` handed to us by a system API that may have
 * cached or deduplicated it, or any object still referenced by a live Swift
 * value) corrupts live data — a far worse outcome than the residue it closes.
 * If uniqueness cannot be established from the source, DO NOT wipe.
 *
 * Two mechanical rules that go with it:
 *  - **Copy out BEFORE wiping** (`toByteArray()` first, `secureWipeBytes()` in
 *    the `finally`). A wipe-before-copy hands the caller all-zero key material —
 *    on the vault path that means an all-zero DB key.
 *  - **`length == 0` returns early**, deliberately: an empty NSData is the
 *    shared `+[NSData data]` singleton, so it must never be memset (there is
 *    nothing secret in it anyway).
 *
 * Known limitation (inherent): a Swift `Data` short enough to use the
 * INLINE representation (<= 14 bytes on 64-bit) is COPIED when it bridges to
 * ObjC, so a memset on the bridged NSData zeros only that copy and the original
 * still reaches ARC unzeroed — the "a value-returning bridge cannot wipe its
 * own return value" residual documented in SwiftArgon2/SwiftX25519. Every
 * secret routed through category 2 today is >= 32 bytes and therefore
 * heap-backed, i.e. genuinely zeroed; a future caller with a shorter payload
 * gets a no-op-in-effect, never corruption.
 */
@OptIn(ExperimentalForeignApi::class)
internal fun NSData.secureWipeBytes() {
    if (length.toInt() == 0) return
    val ptr = bytes ?: return
    memset(ptr, 0, length)
}

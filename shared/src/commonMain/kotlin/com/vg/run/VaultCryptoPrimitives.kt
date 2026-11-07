package com.vg.run

// Two small crypto/IO helpers VaultSelector (and its policy files) share.
// Top-level + internal so commonTest can pin both contracts directly.

/**
 * Shared guard for selector WRITES reachable from non-@Throws Swift bridge
 * methods and Compose click handlers ([VaultSelector.setProtectionLevel], the
 * level-aware provision): a transient device-key outage during crypto.encrypt
 * (or the store write) surfaces as `false` — nothing usable persisted, the
 * caller retries — never as an exception crossing the bridge (Kotlin/Native
 * SIGABRT) or an unguarded click handler. Any OTHER exception still propagates
 * (a real tamper/storage fault must stay visible). Top-level + internal so
 * commonTest can pin the contract directly — CryptoProvider is an expect class
 * with no common fake seam, so the guard itself is the testable unit.
 */
internal inline fun selectorWriteGuard(op: String, write: () -> Unit): Boolean = try {
    write()
    true
} catch (_: KeyUnavailableException) {
    platformLogWarn("VaultSelector", "$op deferred — device key unavailable")
    false
}

/**
 * Compute `sha256(secret ‖ label)` while ZEROING the transient concatenation
 * buffer that [ByteArray.plus] allocates. That buffer is a verbatim copy of
 * [secret] — an Argon2id/PBKDF2 KDF output ("stretched") or the 160-bit
 * recovery code — and, left un-wiped, it defeats the deliberate secureWipe of
 * [secret] itself: a live-RAM capture could otherwise recover the KDF output
 * (and thus re-derive the DB key from the on-disk wrapped blob) from the
 * leftover copy long after the named local was scrubbed.
 *
 * The returned digest IS the real derived output and is the caller's to use
 * (KEK / verifier / recovery-KEK). [secret] — the caller's OWN buffer — is
 * deliberately NOT wiped here: the caller owns its lifetime and routinely
 * reuses it for a second label (e.g. the cred verifier AND the db-key KEK are
 * both derived from the same `stretched`), then wipes it once in its own
 * finally. Top-level + internal so commonTest can pin the contract directly.
 */
internal fun sha256WithLabel(secret: ByteArray, label: ByteArray): ByteArray {
    val merged = secret + label
    return try {
        sha256(merged)
    } finally {
        merged.secureWipe()
    }
}

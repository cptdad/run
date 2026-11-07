package com.vg.run

// ---------------------------------------------------------------------------
// VaultKdf — the credential KDF policy and the stored credential-blob layout.
//
// Everything here is PART OF THE ON-DISK FORMAT
// of `vlt_a` ([VaultStoreKeys.CREDENTIAL_VERIFIER]): a v3 blob pins its own
// Argon2id cost and is re-derived with that pinned cost on every future unlock,
// so the ARGON2_* constants govern what a NEW blob pins, never what an existing
// vault uses (docs/vault-relay-internals.md, "Argon2id cost is pinned PER VAULT").
//
// scripts/verify-release-clean.sh greps THIS FILE by path for the release
// constant and for the single-line `if (isDebugBuild) … else ARGON2_*` gates
// below. Keep both runtimeArgon2* lines single-line, and move the path in that
// script in the same change if this block ever moves again.
// ---------------------------------------------------------------------------

internal object VaultKdf {
    const val SALT_LENGTH = 16
    const val DBKEY_LENGTH = 32
    const val VERIFIER_LENGTH = 32   // sha256(stretched ‖ label)

    // PBKDF2-HMAC-SHA256 iteration counts for the LEGACY KDF versions ONLY. New
    // provisions and change-PIN use **Argon2id (KDF_VERSION_3 = CURRENT_KDF_VERSION)**
    // — the memory-hard KDF is already shipped, NOT "future". These PBKDF2 counts
    // only re-verify pre-v3 vaults, each with the exact KDF it was written with:
    //   [PBKDF2_ITERATIONS]    = LEGACY v1 (210k, no version byte).
    //   [PBKDF2_ITERATIONS_V2] = v2 (OWASP-2023 600k).
    // The 1-byte version prefix makes the KDF upgrade-only; Argon2id slotted in as
    // v3 exactly this way. The stretched output is computed ONCE per unlock (reused
    // for the credential check + the DB-key KEK).
    //
    // Barrier model (do NOT overstate as "hardware-backed"): the device-key AEAD
    // layer is hardware-ROOTED AT REST, but on a *live, unlocked* device the
    // DEFAULT device key is software in RAM (iOS: a Keychain data item; Android:
    // the unwrapped Tink keyset) and is extractable there — so on a seized-unlocked
    // device the KDF is doing real work, not mere defense-in-depth. Opt-in Lever B
    // (HW auth-bound DB key) is what adds a true hardware barrier.
    const val PBKDF2_ITERATIONS = 210_000
    const val PBKDF2_ITERATIONS_V2 = 600_000

    // Credential KDF versions (the 1-byte prefix on the stored blob). v1 is
    // the legacy no-prefix layout (210k PBKDF2); v2 is 600k PBKDF2; v3 is
    // memory-hard Argon2id — the real defense for a low-entropy 6-digit PIN
    // against GPU/ASIC brute force, which PBKDF2 (compute-hard only) cannot
    // provide. New provisions and change-PIN write CURRENT_KDF_VERSION; an
    // older vault is transparently re-wrapped up to it on the next successful
    // unlock (see migrateCredentialToCurrentKdf).
    const val KDF_VERSION_1: Byte = 1   // synthetic (legacy blob has no prefix)
    const val KDF_VERSION_2: Byte = 2
    const val KDF_VERSION_3: Byte = 3
    const val CURRENT_KDF_VERSION: Byte = KDF_VERSION_3

    // Argon2id cost parameters for v3 (RFC 9106). 64 MiB × 3 passes × 1 lane:
    // memory-hard enough to blunt GPU/ASIC guessing of a 6-digit PIN while
    // staying within a mobile unlock budget (no in-tree measurement of the native
    // path is recorded; the internals doc's one figure is 3.79 s for the
    // BouncyCastle fallback on a Samsung A13). p=1 keeps the derivation
    // single-lane (matching the iOS vendored impl).
    const val ARGON2_MEMORY_KIB = 65_536
    const val ARGON2_ITERATIONS = 3
    const val ARGON2_PARALLELISM = 1

    // Release-build Argon2 FLOOR. A v3 blob pins its cost at
    // provision time and reads it back verbatim on every future unlock, so a debug
    // (1 MiB / 1-pass) cost pinned by a mis-built release would leave the vault
    // forensically-weak FOREVER with no runtime check to catch it. In a release build
    // buildCredentialBlob refuses to pin a cost below this floor. Well above the debug
    // cost, at/below the real release cost so a genuine release vault passes.
    const val RELEASE_ARGON2_FLOOR_KIB = 32_768
    const val RELEASE_ARGON2_ITER_FLOOR = 2

    // The Argon2id cost actually USED at runtime for v3. Release binaries use
    // the full memory-hard cost above. In a DEBUGGABLE/test build ([isDebugBuild])
    // the full-cost Argon2 makes every unlock slow, making the e2e suite and dev
    // inner loop unusable — so test builds use a cheap cost (1 MiB × 1 pass). This is DEBUG-ONLY; release (isDebugBuild=
    // false) is UNCHANGED, and the security guard in VaultKdfTest asserts the
    // release CONSTANTS above stay memory-hard. A debug vault is self-consistent
    // (provision + unlock use the same runtime cost); if a release build ever
    // opens one, it is re-pinned to the release floor (see [needsCredentialRewrap]). Verify-release-clean.sh asserts this gate is not removed.
    internal val runtimeArgon2MemoryKiB: Int get() = if (isDebugBuild) 1_024 else ARGON2_MEMORY_KIB
    internal val runtimeArgon2Iterations: Int get() = if (isDebugBuild) 1 else ARGON2_ITERATIONS

    /** Parsed KDF parameters from a stored credential blob. */
    internal class KdfParams(
        val version: Byte,
        val salt: ByteArray,
        val verifier: ByteArray,
        // Argon2id cost PINNED in the v3 blob. null = a legacy v3
        // blob written before cost pinning (derive with the runtime constants). Pinning the
        // cost makes a future ARGON2_MEMORY_KIB/ITERATIONS change a per-vault
        // migration, not a brick-everyone: each vault verifies with the exact cost
        // it was written with. Only meaningful for KDF_VERSION_3.
        val memoryKiB: Int? = null,
        val iterations: Int? = null,
        val parallelism: Int? = null,
    )

    /**
     * Derive the stretched key for [pin] under a credential's stored KDF
     * [params].version: Argon2id for v3, PBKDF2-600k for v2, PBKDF2-210k for
     * the legacy v1. The single choke point for PIN stretching — provision,
     * unlock, change-PIN and migration all route through it, so a credential
     * is always verified with the exact KDF it was written with.
     */
    internal fun stretch(pin: ByteArray, params: KdfParams): ByteArray = when (params.version) {
        // Use the cost PINNED in the blob when present, else the
        // runtime constants (legacy v3 blobs / provision). So a vault written with
        // one cost always re-derives with THAT cost even if the constant changes.
        KDF_VERSION_3 -> argon2id(
            pin, params.salt,
            params.memoryKiB ?: runtimeArgon2MemoryKiB,
            params.iterations ?: runtimeArgon2Iterations,
            params.parallelism ?: ARGON2_PARALLELISM,
            DBKEY_LENGTH,
        )
        KDF_VERSION_2 -> pbkdf2Sha256(pin, params.salt, PBKDF2_ITERATIONS_V2, DBKEY_LENGTH)
        else          -> pbkdf2Sha256(pin, params.salt, PBKDF2_ITERATIONS, DBKEY_LENGTH)  // v1 legacy
    }

    /** Stretch [pin] with the CURRENT KDF version and a fresh [salt] (provision / rotate / migrate). */
    internal fun stretchCurrent(pin: ByteArray, salt: ByteArray): ByteArray =
        stretch(pin, KdfParams(CURRENT_KDF_VERSION, salt, ByteArray(0)))

    // 4-byte big-endian codec for the pinned Argon2 cost.
    private fun intToBytesBE(v: Int): ByteArray =
        byteArrayOf((v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte())
    private fun bytesToIntBE(b: ByteArray, off: Int): Int =
        ((b[off].toInt() and 0xFF) shl 24) or ((b[off + 1].toInt() and 0xFF) shl 16) or
            ((b[off + 2].toInt() and 0xFF) shl 8) or (b[off + 3].toInt() and 0xFF)

    /** Bytes appended to a v3 blob to pin its Argon2id cost: m(4)‖t(4)‖p(1). */
    private const val V3_COST_LEN = 9

    /**
     * Stored credential plaintext.
     *   v1 (legacy):     `salt ‖ verifier`                      (48 bytes)
     *   v2 / legacy v3:  `version(1) ‖ salt ‖ verifier`         (49 bytes)
     *   v3 (pinned):     `version(1) ‖ salt ‖ verifier ‖ m(4) ‖ t(4) ‖ p(1)` (58 bytes)
     * The cost is appended AFTER the verifier so all three lengths stay
     * unambiguous (48 / 49 / 58). v3 now pins its Argon2id cost so
     * a future ARGON2_* change is a migration per vault, not a brick-everyone.
     */
    internal fun buildCredentialBlob(version: Byte, salt: ByteArray, verifier: ByteArray): ByteArray {
        // A RELEASE build must never PIN a sub-floor Argon2 cost —
        // that cost is authoritative for every future unlock, so a debug-cost blob
        // would be a permanently-weak vault. Fail loud rather than provision weak.
        // (Debug builds legitimately pin the cheap cost; the floor is release-only.)
        if (!isDebugBuild && version == KDF_VERSION_3) {
            check(runtimeArgon2MemoryKiB >= RELEASE_ARGON2_FLOOR_KIB &&
                  runtimeArgon2Iterations >= RELEASE_ARGON2_ITER_FLOOR) {
                "release Argon2 cost below floor: ${runtimeArgon2MemoryKiB} KiB / ${runtimeArgon2Iterations} it"
            }
        }
        val base = byteArrayOf(version) + salt + verifier
        return if (version == KDF_VERSION_3) {
            base + intToBytesBE(runtimeArgon2MemoryKiB) + intToBytesBE(runtimeArgon2Iterations) +
                byteArrayOf(ARGON2_PARALLELISM.toByte())
        } else base
    }

    /**
     * Should a stored credential be re-wrapped on this unlock?
     *
     * Extracted as a PURE function so the decision itself has direct test
     * coverage. Two independent triggers:
     *
     *  - an OLD KDF version (v1/v2 PBKDF2 → v3 Argon2id), and
     *  - a v3 blob whose PINNED Argon2 cost is below the release floor while
     *    this is a release build. The pinned cost is authoritative on every
     *    future unlock, so a debug-cost blob carried into a release binary stays
     *    forensically weak forever unless it is re-pinned.
     *
     * A pre-pinning v3 blob pins nothing ([pinnedMemKiB]/[pinnedIterations] null) and
     * derives with the runtime constants, so in a release build it is already at
     * release cost and needs nothing.
     */
    internal fun needsCredentialRewrap(
        storedVersion: Byte,
        pinnedMemKiB: Int?,
        pinnedIterations: Int?,
        isDebug: Boolean,
    ): Boolean {
        if (storedVersion < CURRENT_KDF_VERSION) return true
        if (isDebug || storedVersion != KDF_VERSION_3) return false
        return (pinnedMemKiB ?: ARGON2_MEMORY_KIB) < RELEASE_ARGON2_FLOOR_KIB ||
            (pinnedIterations ?: ARGON2_ITERATIONS) < RELEASE_ARGON2_ITER_FLOOR
    }

    /**
     * Parses a decrypted credential plaintext into its [KdfParams], handling the
     * cost-pinned v3 layout (58 bytes), the versioned v2/legacy-v3 layout (49
     * bytes) and the legacy v1 layout (48 bytes, no version byte). All three are
     * length-unambiguous. Returns null if malformed/unknown so the caller treats
     * it as a non-match (fail closed).
     */
    internal fun parseCredentialBlob(plain: ByteArray): KdfParams? {
        val versionedLen = 1 + SALT_LENGTH + VERIFIER_LENGTH        // 49
        // v3 with a pinned cost.
        if (plain.size == versionedLen + V3_COST_LEN && plain[0] == KDF_VERSION_3) {
            val m = bytesToIntBE(plain, versionedLen)
            val t = bytesToIntBE(plain, versionedLen + 4)
            val p = plain[versionedLen + 8].toInt() and 0xFF
            return KdfParams(
                KDF_VERSION_3,
                plain.copyOfRange(1, 1 + SALT_LENGTH),
                plain.copyOfRange(1 + SALT_LENGTH, versionedLen),
                memoryKiB = m, iterations = t, parallelism = p,
            )
        }
        // v2 or legacy (pre-pinning) v3 — no pinned cost.
        if (plain.size == versionedLen &&
            (plain[0] == KDF_VERSION_2 || plain[0] == KDF_VERSION_3)) {
            return KdfParams(
                plain[0],
                plain.copyOfRange(1, 1 + SALT_LENGTH),
                plain.copyOfRange(1 + SALT_LENGTH, plain.size),
            )
        }
        if (plain.size == SALT_LENGTH + VERIFIER_LENGTH) {
            return KdfParams(
                KDF_VERSION_1,
                plain.copyOfRange(0, SALT_LENGTH),
                plain.copyOfRange(SALT_LENGTH, plain.size),
            )
        }
        return null
    }
}

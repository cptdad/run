package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// Versioned credential-KDF tests (VaultSelector). These exercise the PURE
// parse/build + derivation logic (Argon2id / PBKDF2 / SHA-256 / constant-time
// compare are all reachable from commonMain), so ALL THREE credential layouts —
// legacy v1 (PBKDF2-210k, no version byte), v2 (PBKDF2-600k, version-prefixed)
// and the current v3 (Argon2id) — are proven to verify correctly WITHOUT
// needing the platform Keychain/Keystore. This is the safety net for the
// migration-safe KDF upgrades (Argon2id campaign).
//
// The platform argon2id() actuals are additionally pinned to the reference
// implementation's published test vectors (argon2idMatchesReferenceVectors),
// so "correct Argon2id" is proven per platform, not assumed.
// ---------------------------------------------------------------------------

class VaultKdfTest {

    private val salt = ByteArray(VaultKdf.SALT_LENGTH) { it.toByte() }
    private val label = VaultCryptoContexts.LABEL_VERIFIER.encodeToByteArray()

    private fun params(version: Byte, salt: ByteArray) =
        VaultKdf.KdfParams(version, salt, ByteArray(0))

    private fun verifierFor(pin: String, version: Byte, salt: ByteArray): ByteArray {
        val stretched = VaultKdf.stretch(pin.encodeToByteArray(), params(version, salt))
        return sha256(stretched + label)
    }

    private fun ByteArray.toHex(): String =
        joinToString("") { b -> (b.toInt() and 0xFF).toString(16).padStart(2, '0') }

    // -- Migration DECISION ---------------
    //
    // The rewrap decision used to live inline in migrateCredentialToCurrentKdf and
    // was never called by any test — this file re-implemented the migration steps
    // by hand instead, so the decision itself (the part with the bug surface) had
    // no coverage at all. It is now a pure function and is exercised here.

    @Test
    fun rewrap_isRequiredForOlderKdfVersions() {
        for (old in listOf(VaultKdf.KDF_VERSION_1, VaultKdf.KDF_VERSION_2)) {
            assertTrue(
                VaultKdf.needsCredentialRewrap(old, null, null, isDebug = false),
                "v$old must be migrated up to the current KDF",
            )
            assertTrue(
                VaultKdf.needsCredentialRewrap(old, null, null, isDebug = true),
                "the version upgrade applies in debug builds too",
            )
        }
    }

    @Test
    fun rewrap_isNotRequiredForACurrentReleaseCostBlob() {
        assertFalse(
            VaultKdf.needsCredentialRewrap(
                VaultKdf.KDF_VERSION_3,
                VaultKdf.ARGON2_MEMORY_KIB,
                VaultKdf.ARGON2_ITERATIONS,
                isDebug = false,
            ),
            "a healthy v3 blob must not be needlessly re-wrapped on every unlock",
        )
    }

    @Test
    fun rewrap_isRequiredForASubFloorPinnedCostInARelaseBuild() {
        // The exact carry-over this guards — a vault provisioned by a DEBUG
        // build (1 MiB × 1 pass) whose data survives into a release binary, e.g. an
        // iOS dev/TestFlight → App Store in-place upgrade. The pinned cost is
        // authoritative on every future unlock, so without this it stays
        // forensically weak forever and assertKdfBuildIntegrity never notices
        // (it checks what this build would WRITE, not what is STORED).
        assertTrue(
            VaultKdf.needsCredentialRewrap(
                VaultKdf.KDF_VERSION_3,
                pinnedMemKiB = 1_024,
                pinnedIterations = 1,
                isDebug = false,
            ),
        )
        // Either dimension below its floor is enough on its own.
        assertTrue(
            VaultKdf.needsCredentialRewrap(
                VaultKdf.KDF_VERSION_3,
                pinnedMemKiB = VaultKdf.ARGON2_MEMORY_KIB,
                pinnedIterations = 1,
                isDebug = false,
            ),
        )
        assertTrue(
            VaultKdf.needsCredentialRewrap(
                VaultKdf.KDF_VERSION_3,
                pinnedMemKiB = 1_024,
                pinnedIterations = VaultKdf.ARGON2_ITERATIONS,
                isDebug = false,
            ),
        )
    }

    @Test
    fun rewrap_neverFiresForASubFloorCostInADebugBuild() {
        // Debug builds legitimately run the cheap cost. Re-pinning there would make
        // every debug unlock pay the full 64 MiB × 3 and re-break the e2e inner loop.
        assertFalse(
            VaultKdf.needsCredentialRewrap(
                VaultKdf.KDF_VERSION_3,
                pinnedMemKiB = 1_024,
                pinnedIterations = 1,
                isDebug = true,
            ),
        )
    }

    @Test
    fun rewrap_isNotRequiredForAPreI1V3BlobThatPinsNothing() {
        // A legacy v3 blob carries no cost; it derives with the runtime constants,
        // which in a release build are already at release cost.
        assertFalse(
            VaultKdf.needsCredentialRewrap(
                VaultKdf.KDF_VERSION_3, null, null, isDebug = false,
            ),
        )
    }

    // -- Blob layout: build ↔ parse round trips -----------------------------

    @Test
    fun v3_blob_roundTripsThroughBuildAndParse() {
        val verifier = verifierFor("123456", VaultKdf.KDF_VERSION_3, salt)
        val blob = VaultKdf.buildCredentialBlob(VaultKdf.CURRENT_KDF_VERSION, salt, verifier)
        // a v3 blob now appends its pinned Argon2 cost (m(4)+t(4)+p(1))
        // after the verifier — 58 bytes, not 49. The round-trip below still recovers
        // the salt + verifier unchanged.
        assertEquals(1 + VaultKdf.SALT_LENGTH + VaultKdf.VERIFIER_LENGTH + 9, blob.size)
        assertEquals(VaultKdf.KDF_VERSION_3, blob[0])

        val p = VaultKdf.parseCredentialBlob(blob)!!
        assertEquals(VaultKdf.KDF_VERSION_3, p.version)
        assertTrue(p.salt.contentEquals(salt))
        assertTrue(p.verifier.contentEquals(verifier))
    }

    @Test
    fun v2_blob_roundTripsThroughBuildAndParse() {
        val verifier = verifierFor("123456", VaultKdf.KDF_VERSION_2, salt)
        val blob = VaultKdf.buildCredentialBlob(VaultKdf.KDF_VERSION_2, salt, verifier)
        assertEquals(1 + VaultKdf.SALT_LENGTH + VaultKdf.VERIFIER_LENGTH, blob.size)
        assertEquals(VaultKdf.KDF_VERSION_2, blob[0])

        val p = VaultKdf.parseCredentialBlob(blob)!!
        assertEquals(VaultKdf.KDF_VERSION_2, p.version)
        assertTrue(p.salt.contentEquals(salt))
        assertTrue(p.verifier.contentEquals(verifier))
    }

    @Test
    fun legacyV1_blob_parsesAsV1AndVerifies() {
        // A pre-versioning credential: salt ‖ verifier, no version byte,
        // derived with the legacy 210k PBKDF2.
        val verifier = verifierFor("123456", VaultKdf.KDF_VERSION_1, salt)
        val legacy = salt + verifier
        assertEquals(VaultKdf.SALT_LENGTH + VaultKdf.VERIFIER_LENGTH, legacy.size)

        val p = VaultKdf.parseCredentialBlob(legacy)!!
        assertEquals(VaultKdf.KDF_VERSION_1, p.version)
        // Re-derive with the parsed (legacy) KDF → must match → vault unlocks.
        val redux = sha256(VaultKdf.stretch("123456".encodeToByteArray(), p) + label)
        assertTrue(constantTimeEquals(p.verifier, redux))
    }

    @Test
    fun malformedBlob_returnsNull() {
        assertNull(VaultKdf.parseCredentialBlob(ByteArray(10)))               // too short
        assertNull(VaultKdf.parseCredentialBlob(ByteArray(1 + VaultKdf.SALT_LENGTH + VaultKdf.VERIFIER_LENGTH) { 9 })) // 49 bytes, unknown version 9
    }

    // -- v3 verification ------------------------------------------------------

    @Test
    fun v3_verifies_correctPin_andRejects_wrongPin() {
        val verifier = verifierFor("123456", VaultKdf.KDF_VERSION_3, salt)
        val p = VaultKdf.parseCredentialBlob(
            VaultKdf.buildCredentialBlob(VaultKdf.KDF_VERSION_3, salt, verifier)
        )!!
        val good = sha256(VaultKdf.stretch("123456".encodeToByteArray(), p) + label)
        val bad  = sha256(VaultKdf.stretch("654321".encodeToByteArray(), p) + label)
        assertTrue(constantTimeEquals(p.verifier, good))
        assertTrue(!constantTimeEquals(p.verifier, bad))
    }

    // -- v3 pins its Argon2 cost; layouts stay length-unambiguous --

    @Test
    fun v3Blob_pinsArgon2Cost_lengthsUnambiguous() {
        val verifier = ByteArray(VaultKdf.VERIFIER_LENGTH) { 7 }
        val v1len = VaultKdf.SALT_LENGTH + VaultKdf.VERIFIER_LENGTH            // 48
        val v2 = VaultKdf.buildCredentialBlob(VaultKdf.KDF_VERSION_2, salt, verifier)
        val v3 = VaultKdf.buildCredentialBlob(VaultKdf.KDF_VERSION_3, salt, verifier)
        assertEquals(1 + v1len, v2.size)          // 49 — v2 unchanged
        assertEquals(1 + v1len + 9, v3.size)      // 58 — v3 appends m(4)+t(4)+p(1)
        val p = VaultKdf.parseCredentialBlob(v3)!!
        assertEquals(VaultKdf.KDF_VERSION_3, p.version)
        assertEquals(VaultKdf.runtimeArgon2MemoryKiB, p.memoryKiB)
        assertEquals(VaultKdf.runtimeArgon2Iterations, p.iterations)
        assertEquals(VaultKdf.ARGON2_PARALLELISM, p.parallelism)
    }

    @Test
    fun legacyV3Blob_withoutCost_parses_andDerivesSameKeyAsPinned() {
        val verifier = ByteArray(VaultKdf.VERIFIER_LENGTH) { 3 }
        // Pre-I1 v3 blob: version ‖ salt ‖ verifier (49 bytes, no pinned cost).
        val legacy = byteArrayOf(VaultKdf.KDF_VERSION_3) + salt + verifier
        assertEquals(1 + VaultKdf.SALT_LENGTH + VaultKdf.VERIFIER_LENGTH, legacy.size)
        val pLegacy = VaultKdf.parseCredentialBlob(legacy)!!
        assertEquals(VaultKdf.KDF_VERSION_3, pLegacy.version)
        assertNull(pLegacy.memoryKiB)   // no pinned cost → runtime constants
        // Today the pinned cost equals the runtime cost, so a legacy blob and a new
        // pinned blob derive the IDENTICAL key from the same PIN — no migration break.
        val pinned = VaultKdf.parseCredentialBlob(
            VaultKdf.buildCredentialBlob(VaultKdf.KDF_VERSION_3, salt, verifier)
        )!!
        val kLegacy = VaultKdf.stretch("123456".encodeToByteArray(), pLegacy)
        val kPinned = VaultKdf.stretch("123456".encodeToByteArray(), pinned)
        assertTrue(constantTimeEquals(kLegacy, kPinned))
    }

    @Test
    fun stretchCurrent_isArgon2V3() {
        // Guard the intended hardening direction: new provisions are memory-hard.
        assertEquals(VaultKdf.KDF_VERSION_3, VaultKdf.CURRENT_KDF_VERSION)
        // The RELEASE cost stays memory-hard (this guard runs on the release
        // constants regardless of build type).
        assertTrue(VaultKdf.ARGON2_MEMORY_KIB >= 65_536)  // ≥ 64 MiB
        assertTrue(VaultKdf.ARGON2_ITERATIONS >= 3)
        // stretchCurrent uses the RUNTIME cost (release = the constants above;
        // debug/test = a cheap cost so the suite isn't dominated by interpreted
        // Argon2). Derive `direct` with the same runtime cost so the equality
        // holds in both build types.
        val direct = argon2id(
            "123456".encodeToByteArray(), salt,
            VaultKdf.runtimeArgon2MemoryKiB, VaultKdf.runtimeArgon2Iterations,
            VaultKdf.ARGON2_PARALLELISM, VaultKdf.DBKEY_LENGTH
        )
        assertTrue(VaultKdf.stretchCurrent("123456".encodeToByteArray(), salt).contentEquals(direct))
    }

    // -- Argon2id known-answer tests ------------------------------------------
    //
    // Vectors from the PHC reference implementation's test suite
    // (P-H-C/phc-winner-argon2 src/test.c, Argon2id version 0x13). RFC 9106's
    // own §5.3 vector needs the secret-key + associated-data inputs, which our
    // argon2id() surface deliberately does not expose — the PHC vectors cover
    // the same core with password+salt only. This pins the platform actual
    // (BouncyCastle on Android, vendored PHC C on iOS) to a correct Argon2id.

    @Test
    fun argon2id_matchesReferenceVector_m65536_t2_p1() {
        val out = argon2id("password".encodeToByteArray(), "somesalt".encodeToByteArray(), 65_536, 2, 1, 32)
        assertEquals("09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7", out.toHex())
    }

    @Test
    fun argon2id_matchesReferenceVector_m256_t2_p1() {
        val out = argon2id("password".encodeToByteArray(), "somesalt".encodeToByteArray(), 256, 2, 1, 32)
        assertEquals("9dfeb910e80bad0311fee20f9c0e2b12c17987b4cac90c2ef54d5b3021c68bfe", out.toHex())
    }

    @Test
    fun argon2id_matchesReferenceVector_m256_t2_p2() {
        val out = argon2id("password".encodeToByteArray(), "somesalt".encodeToByteArray(), 256, 2, 2, 32)
        assertEquals("6d093c501fd5999645e0ea3bf620d7b8be7fd2db59c20d9fff9539da2bf57037", out.toHex())
    }

    // -- v2 → v3 migration -----------------------------------------------------
    //
    // Blob-level proof of the on-unlock KDF upgrade (migrateCredentialToCurrentKdf):
    // starting from a v2 credential + a v2-KEK-wrapped DB key, re-wrapping with
    // the SAME PIN under the current KDF yields a v3 blob that (a) verifies that
    // PIN, (b) rejects a wrong PIN, and (c) whose KEK unwraps the SAME DB key.

    @Test
    fun migration_v2ToV3_samePinVerifies_andDbKeySurvives() {
        val pin = "123456"
        val dbCtx = VaultCryptoContexts.DBKEY_INNER.encodeToByteArray()
        val kekLabel = VaultCryptoContexts.LABEL_DBKEY_KEK.encodeToByteArray()
        val dbKey = ByteArray(VaultKdf.DBKEY_LENGTH) { (it * 7).toByte() }

        // Provisioned state: v2 credential + DB key wrapped under the v2 KEK.
        val v2Stretched = VaultKdf.stretch(pin.encodeToByteArray(), params(VaultKdf.KDF_VERSION_2, salt))
        val v2Blob = VaultKdf.buildCredentialBlob(
            VaultKdf.KDF_VERSION_2, salt, sha256(v2Stretched + label)
        )
        val v2Wrapped = aesGcmEncrypt(dbKey, sha256(v2Stretched + kekLabel), dbCtx)

        // Unlock-time evaluation sees v2 and the PIN matches.
        val p2 = VaultKdf.parseCredentialBlob(v2Blob)!!
        assertEquals(VaultKdf.KDF_VERSION_2, p2.version)
        assertTrue(p2.version < VaultKdf.CURRENT_KDF_VERSION)
        val checkStretched = VaultKdf.stretch(pin.encodeToByteArray(), p2)
        assertTrue(constantTimeEquals(p2.verifier, sha256(checkStretched + label)))
        val unwrapped = aesGcmDecrypt(v2Wrapped, sha256(checkStretched + kekLabel), dbCtx)
        assertTrue(unwrapped.contentEquals(dbKey))

        // Migration: fresh salt, current KDF, same PIN, same DB key re-wrapped.
        val newSalt = ByteArray(VaultKdf.SALT_LENGTH) { (255 - it).toByte() }
        val v3Stretched = VaultKdf.stretchCurrent(pin.encodeToByteArray(), newSalt)
        val v3Blob = VaultKdf.buildCredentialBlob(
            VaultKdf.CURRENT_KDF_VERSION, newSalt, sha256(v3Stretched + label)
        )
        val v3Wrapped = aesGcmEncrypt(unwrapped, sha256(v3Stretched + kekLabel), dbCtx)

        // Post-migration: parses as v3, same PIN verifies, wrong PIN doesn't,
        // and the v3 KEK unwraps the ORIGINAL DB key (vault keeps opening).
        val p3 = VaultKdf.parseCredentialBlob(v3Blob)!!
        assertEquals(VaultKdf.KDF_VERSION_3, p3.version)
        val goodStretched = VaultKdf.stretch(pin.encodeToByteArray(), p3)
        assertTrue(constantTimeEquals(p3.verifier, sha256(goodStretched + label)))
        assertTrue(!constantTimeEquals(p3.verifier, sha256(VaultKdf.stretch("654321".encodeToByteArray(), p3) + label)))
        assertTrue(aesGcmDecrypt(v3Wrapped, sha256(goodStretched + kekLabel), dbCtx).contentEquals(dbKey))
    }
}

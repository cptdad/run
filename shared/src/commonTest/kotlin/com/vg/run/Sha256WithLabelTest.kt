package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class Sha256WithLabelTest {

    // VaultSelector's KEK / verifier
    // / recovery-KEK derivations are sha256(secret ‖ label). ByteArray.plus copies
    // `secret` (an Argon2id/PBKDF2 "stretched" output or the recovery code) into a
    // fresh buffer that was left un-wiped, defeating the deliberate secureWipe of
    // `secret` itself. sha256WithLabel now wipes that concat copy in a finally.
    //
    // The wiped temp is a GC-reclaimed local with no external seam to observe, so
    // these pin the CONTRACT the fix must preserve rather than the wipe itself:
    // (1) the derived output is byte-identical to the old inline expression, and
    // (2) the caller's own `secret` buffer is untouched — the load-bearing
    // invariant, since `stretched` feeds BOTH the verifier and the db-key KEK in
    // sequence, so wiping the caller's buffer would derive the wrong KEK on the
    // second call and leave the vault unopenable.

    @Test
    fun producesSameDigestAsPlainConcat() {
        val secret = generateSecureRandom(32)
        val label = "dbkey-kek".encodeToByteArray()
        assertTrue(
            sha256WithLabel(secret, label).contentEquals(sha256(secret + label)),
            "sha256WithLabel must equal sha256(secret + label) — derivation unchanged",
        )
    }

    @Test
    fun doesNotModifyCallerSecret_soItCanBeReusedForASecondLabel() {
        val secret = generateSecureRandom(32)
        val snapshot = secret.copyOf()
        // First derivation.
        sha256WithLabel(secret, "cred-verifier".encodeToByteArray())
        assertTrue(secret.contentEquals(snapshot), "caller's secret must be left intact")
        // Second derivation with a different label off the SAME buffer (e.g. the
        // db-key KEK) still matches — proving the caller-reuse pattern is safe.
        assertTrue(
            sha256WithLabel(secret, "dbkey-kek".encodeToByteArray())
                .contentEquals(sha256(snapshot + "dbkey-kek".encodeToByteArray())),
            "second derivation off the reused secret must be correct",
        )
    }

    @Test
    fun differentLabelsProduceDifferentDigests() {
        val secret = generateSecureRandom(32)
        assertNotEquals(
            sha256WithLabel(secret, "cred-verifier".encodeToByteArray()).toList(),
            sha256WithLabel(secret, "dbkey-kek".encodeToByteArray()).toList(),
        )
    }

    @Test
    fun output_is_32_bytes() {
        assertEquals(32, sha256WithLabel(generateSecureRandom(32), "x".encodeToByteArray()).size)
    }
}

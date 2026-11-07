package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

// Base32 (Crockford) — the transcribable recovery-code encoding. A mistyped code
// must fail closed (null), a correctly-copied one must round-trip byte-for-byte,
// and the human-friendly foldings (case, spaces/hyphens, O→0, I/L→1) must decode
// to the SAME bytes as the canonical form.
class Base32Test {

    @Test
    fun roundTrips_the160BitRecoverySecretLength() {
        val secret = ByteArray(RecoveryBlobPolicy.RECOVERY_SECRET_LENGTH) { (it * 7 + 1).toByte() }
        val code = Base32.encode(secret)
        assertEquals(32, code.length, "20 bytes = 160 bits = exactly 32 Base32 symbols")
        assertTrue(Base32.decode(code)!!.contentEquals(secret), "decode(encode(secret)) == secret")
    }

    @Test
    fun roundTrips_variousLengths() {
        for (n in intArrayOf(1, 2, 5, 7, 16, 20, 32)) {
            val bytes = ByteArray(n) { (it * 31 + 5).toByte() }
            val decoded = Base32.decode(Base32.encode(bytes))!!
            assertTrue(decoded.contentEquals(bytes), "round-trip failed for length $n")
        }
    }

    @Test
    fun decode_ignoresSpacesHyphensAndCase() {
        val bytes = ByteArray(20) { (it * 13 + 2).toByte() }
        val code = Base32.encode(bytes)
        val grouped = Base32.formatGrouped(code, group = 4, separator = "-")
        assertTrue(grouped.contains("-"), "formatGrouped should insert separators")
        assertTrue(Base32.decode(grouped)!!.contentEquals(bytes), "hyphen-grouped code must decode identically")
        assertTrue(Base32.decode("  $code  ".lowercase())!!.contentEquals(bytes), "lowercase + spaces must decode identically")
    }

    @Test
    fun decode_foldsCrockfordLookAlikes() {
        // O→0, I→1, L→1: "O1IL" must equal "0111".
        assertTrue(Base32.decode("O1IL")!!.contentEquals(Base32.decode("0111")!!))
        assertTrue(Base32.decode("oil")!!.contentEquals(Base32.decode("011")!!))
    }

    @Test
    fun decode_rejectsInvalidSymbols() {
        assertNull(Base32.decode("U"), "U is not in the Crockford alphabet")
        assertNull(Base32.decode("!!!!"))
        assertNull(Base32.decode("0000U0"))
    }

    @Test
    fun encode_emptyIsEmpty() {
        assertEquals("", Base32.encode(ByteArray(0)))
    }

    @Test
    fun twoDistinctSecretsEncodeDifferently() {
        val a = ByteArray(20) { 0 }
        val b = ByteArray(20) { if (it == 19) 1 else 0 }
        assertTrue(Base32.encode(a) != Base32.encode(b))
    }
}

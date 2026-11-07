package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Pins the hoisted [secureShuffle] / [bytesToHex] so the ONE shared
 * commonMain implementation stays correct for both platforms (they replaced a
 * private GroupManager extension + two verbatim inlined copies in MessageManager).
 */
class SharedUtilTest {

    // ---- bytesToHex — deterministic, exact vectors ----

    @Test
    fun bytesToHex_knownVectors() {
        assertEquals("", bytesToHex(byteArrayOf()))
        assertEquals("00", bytesToHex(byteArrayOf(0x00)))
        assertEquals("0f", bytesToHex(byteArrayOf(0x0F)))
        assertEquals("ff", bytesToHex(byteArrayOf(0xFF.toByte())))
        assertEquals("0ab3", bytesToHex(byteArrayOf(0x0A, 0xB3.toByte())))
        assertEquals("deadbeef", bytesToHex(byteArrayOf(0xDE.toByte(), 0xAD.toByte(), 0xBE.toByte(), 0xEF.toByte())))
    }

    @Test
    fun bytesToHex_isLowercaseAndTwoCharsPerByte() {
        // every one of the 256 byte values encodes to exactly 2 lowercase hex chars
        val all = ByteArray(256) { it.toByte() }
        val hex = bytesToHex(all)
        assertEquals(512, hex.length)
        assertTrue(hex.all { it in "0123456789abcdef" }, "expected lowercase hex only")
        // spot-check the boundaries: 0x00 first, 0x7f mid, 0x80 sign-flip, 0xff last
        assertEquals("00", hex.substring(0, 2))
        assertEquals("7f", hex.substring(0x7F * 2, 0x7F * 2 + 2))
        assertEquals("80", hex.substring(0x80 * 2, 0x80 * 2 + 2))
        assertEquals("ff", hex.substring(510, 512))
    }

    // ---- secureShuffle — CSPRNG-driven, so assert invariants, not order ----

    @Test
    fun secureShuffle_isAPermutation() {
        repeat(200) {
            val original = (0 until 25).toList()
            val shuffled = original.toMutableList().also { it.secureShuffle() }
            assertEquals(original.size, shuffled.size)
            // same multiset — nothing dropped, duplicated, or corrupted
            assertEquals(original.toSet(), shuffled.toSet())
            assertEquals(original.sorted(), shuffled.sorted())
        }
    }

    @Test
    fun secureShuffle_emptyAndSingleton_areNoOps() {
        val empty = mutableListOf<Int>()
        empty.secureShuffle()
        assertEquals(emptyList(), empty)

        val one = mutableListOf(42)
        one.secureShuffle()
        assertEquals(listOf(42), one)
    }

    @Test
    fun secureShuffle_doesReorder() {
        // Over many runs of a large list it must produce a non-identity ordering
        // at least once (P(all 200 runs identity) is astronomically small).
        val original = (0 until 50).toList()
        val reordered = (0 until 200).any { original.toMutableList().also { it.secureShuffle() } != original }
        assertTrue(reordered, "secureShuffle never changed the order across 200 runs")
    }
}

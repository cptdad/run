@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package com.vg.run

import platform.Foundation.NSData
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

/**
 * Regression for the iOS mint crash (post-capability-protocol migration):
 *
 * `ByteArray.toNSData()` used to call `pinned.addressOf(0)` unconditionally,
 * which throws `ArrayIndexOutOfBoundsException` on an empty ByteArray. The
 * old wire protocol always carried at least one byte in every POST, so the
 * empty-body branch was never exercised. The new mint POST sends an empty
 * body (`POST /inbox`, headers carry the PoW solution, body is unused), and
 * that triggered the crash on every iOS mint attempt.
 *
 * Fix: short-circuit empty arrays to `NSData()`.
 */
class ToNSDataTest {

    @Test
    fun empty_byteArray_returnsEmptyNSData() {
        val nsData = ByteArray(0).toNSData()
        assertNotNull(nsData)
        assertEquals(0UL, nsData.length)
    }

    @Test
    fun single_byte_roundtrips() {
        val src = byteArrayOf(0x2A)
        val nsData = src.toNSData()
        assertEquals(1UL, nsData.length)
        val roundTrip = nsData.toByteArray()
        assertEquals(1, roundTrip.size)
        assertEquals(0x2A.toByte(), roundTrip[0])
    }

    @Test
    fun multi_byte_roundtrips() {
        val src = ByteArray(32) { (it * 7).toByte() }
        val nsData = src.toNSData()
        assertEquals(32UL, nsData.length)
        val roundTrip = nsData.toByteArray()
        assertEquals(32, roundTrip.size)
        for (i in 0 until 32) {
            assertEquals(src[i], roundTrip[i])
        }
    }
}

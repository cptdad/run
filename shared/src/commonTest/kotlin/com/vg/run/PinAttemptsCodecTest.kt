package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals

class PinAttemptsCodecTest {

    @Test
    fun encode_then_decode_roundtrips() {
        for (n in listOf(0, 1, 5, 4, 100, 0x7FFFFFFE, Int.MAX_VALUE)) {
            assertEquals(n, decodeCounter(encodeCounter(n)))
        }
    }

    @Test
    fun encode_produces_4_bytes() {
        assertEquals(4, encodeCounter(0).size)
        assertEquals(4, encodeCounter(Int.MAX_VALUE).size)
    }

    @Test
    fun decode_reads_first_four_bytes_only() {
        val payload = encodeCounter(42) + byteArrayOf(0xAA.toByte(), 0xBB.toByte(), 0xCC.toByte())
        assertEquals(42, decodeCounter(payload))
    }

    @Test
    fun encoded_value_is_big_endian() {
        val bytes = encodeCounter(0x01020304)
        assertEquals(0x01.toByte(), bytes[0])
        assertEquals(0x02.toByte(), bytes[1])
        assertEquals(0x03.toByte(), bytes[2])
        assertEquals(0x04.toByte(), bytes[3])
    }

    @Test
    fun decode_does_not_sign_extend_high_byte() {
        val bytes = byteArrayOf(0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0xFE.toByte())
        assertEquals(-2, decodeCounter(bytes))
    }
}

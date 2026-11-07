package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.assertFailsWith

class MessagePaddingTest {

    @Test
    fun padAndUnpad_roundTrip() {
        val original = "Hello, World!".encodeToByteArray()
        val padded = padMessage(original)
        val unpadded = unpadMessage(padded)
        assertTrue(original.contentEquals(unpadded))
    }

    @Test
    fun padded_size_is_power_of_two() {
        for (size in listOf(1, 10, 100, 200, 500, 1000, 5000)) {
            val plaintext = generateSecureRandom(size)
            val padded = padMessage(plaintext)
            // Must be power of two or PAD_MAX
            assertTrue(padded.size >= 256)
            assertTrue(padded.size and (padded.size - 1) == 0 || padded.size == 131072,
                "Size ${padded.size} is not power of two")
        }
    }

    @Test
    fun minimum_padded_size_is_256() {
        val tiny = "Hi".encodeToByteArray()
        val padded = padMessage(tiny)
        assertEquals(256, padded.size)
    }

    @Test
    fun empty_message_pads_and_unpads() {
        val empty = ByteArray(0)
        val padded = padMessage(empty)
        val unpadded = unpadMessage(padded)
        assertEquals(0, unpadded.size)
    }

    @Test
    fun large_message_pads_correctly() {
        val large = generateSecureRandom(60000)
        val padded = padMessage(large)
        val unpadded = unpadMessage(padded)
        assertTrue(large.contentEquals(unpadded))
        assertTrue(padded.size >= large.size + 4)
    }

    @Test
    fun max_payload_pads_to_ceiling() {
        val atLimit = generateSecureRandom(MAX_PADDED_PAYLOAD_BYTES)
        val padded = padMessage(atLimit)
        assertEquals(131072, padded.size)
        assertTrue(atLimit.contentEquals(unpadMessage(padded)))
    }

    @Test
    fun oversize_message_throws_clearly() {
        // a payload that doesn't fit the max bucket must fail fast with a
        // clear IllegalArgumentException, not an opaque IndexOutOfBounds that
        // sendMessage swallowed as a silent failure.
        assertFailsWith<IllegalArgumentException> {
            padMessage(ByteArray(MAX_PADDED_PAYLOAD_BYTES + 1))
        }
    }
}

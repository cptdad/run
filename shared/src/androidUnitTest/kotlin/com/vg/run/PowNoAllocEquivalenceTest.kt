package com.vg.run

import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Pins Android's allocation-free PoW grind ([powSearchStridedNoAlloc] /
 * [PowPreimage], PowSolver.android.kt) to the shared, relay-coupled definition
 * ([computePowHash] / [powSearchStrided]). If the no-alloc preimage ever drifted
 * from `"$nonce:$counter".encodeToByteArray()` by a single byte, every Android
 * inbox mint would submit counters the relay rejects — so this compares BYTES,
 * HASHES and SEARCH RESULTS, not just "it finds something".
 */
class PowNoAllocEquivalenceTest {

    private val nonces = listOf(
        "AAAAAAAAAAAAAAAAAAAAAA",
        "Ab-_cdEFghIJklMNopQRst",   // both base64url specials — the wrong-alphabet tripwire
        "x",
        "",
    )

    private val counters = listOf(
        0L, 1L, 9L, 10L, 11L, 99L, 100L, 101L, 999L, 1_000L,
        123_456_789L, 1_048_575L, 1_048_576L, 9_999_999_999L,
        Long.MAX_VALUE - 1, Long.MAX_VALUE,
    )

    @Test
    fun preimage_isByteIdenticalToTheSharedTemplate() {
        for (nonce in nonces) {
            val pre = PowPreimage(nonce)
            for (c in counters) {
                val len = pre.set(c)
                assertContentEquals(
                    "$nonce:$c".encodeToByteArray(),
                    pre.bytes.copyOf(len),
                    "preimage drift for nonce='$nonce' counter=$c",
                )
            }
        }
    }

    @Test
    fun preimage_survivesShrinkingCounters() {
        // The buffer is reused: a SHORTER counter after a longer one must not
        // leave stale trailing digits inside the reported length.
        val pre = PowPreimage("n")
        pre.set(Long.MAX_VALUE)
        val len = pre.set(7L)
        assertContentEquals("n:7".encodeToByteArray(), pre.bytes.copyOf(len))
    }

    @Test
    fun preimage_hashesToComputePowHash() {
        val md = MessageDigest.getInstance("SHA-256")
        val out = ByteArray(32)
        for (nonce in nonces) {
            val pre = PowPreimage(nonce)
            for (c in counters) {
                md.update(pre.bytes, 0, pre.set(c))
                md.digest(out, 0, out.size)
                assertContentEquals(computePowHash(nonce, c), out, "hash drift nonce='$nonce' counter=$c")
            }
        }
    }

    @Test
    fun preimage_refusesNegativeCounters() {
        assertFailsWith<IllegalArgumentException> { PowPreimage("n").set(-1L) }
    }

    @Test
    fun search_returnsExactlyTheSharedSearchesCounter() {
        // Small difficulties keep this fast while still exercising many misses
        // before each hit, across the strides the parallel solver uses.
        for (nonce in listOf("AAAAAAAAAAAAAAAAAAAAAA", "Ab-_cdEFghIJklMNopQRst")) {
            for (difficulty in listOf(1, 4, 8, 12)) {
                for (stride in listOf(1L, 2L, 3L, 8L)) {
                    for (start in 0L until stride) {
                        val shared = powSearchStrided(nonce, difficulty, start, stride) { false }
                        val noAlloc = powSearchStridedNoAlloc(nonce, difficulty, start, stride) { false }
                        assertEquals(
                            shared, noAlloc,
                            "search drift nonce='$nonce' d=$difficulty start=$start stride=$stride",
                        )
                        assertTrue(hashHasLeadingZeroBits(computePowHash(nonce, noAlloc!!), difficulty))
                    }
                }
            }
        }
    }

    @Test
    fun search_honoursStopOnTheFirstPoll() {
        // Same contract as powSearchStrided: [stop] is polled before the first
        // hash, so an already-signalled stop returns null without a solution.
        assertNull(powSearchStridedNoAlloc("AAAAAAAAAAAAAAAAAAAAAA", 30, 0L, 1L) { true })
    }

    @Test
    fun solvePow_android_stillSatisfiesTheRelayPredicate() {
        val nonce = "Ab-_cdEFghIJklMNopQRst"
        val counter = solvePow(nonce, 14)
        assertTrue(hashHasLeadingZeroBits(computePowHash(nonce, counter), 14))
    }
}

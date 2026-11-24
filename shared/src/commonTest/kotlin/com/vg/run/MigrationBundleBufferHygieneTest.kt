package com.vg.run

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertSame
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// RÚN-04 part (b): the bundle encoder's own buffers are zeroed.
//
// Observed through WipingByteSink's `onRetired` seam (each backing array is handed
// over AFTER it was zeroed), not inferred. Every retired array once held a prefix of
// the document starting with '{' (0x7B) — `copyOf` carries the prefix into the next
// one — so "all zero" here can only mean "wiped".
//
// What this cannot show (stated, not tested): JIT/GC copies, the per-field Strings of
// the String-typed VaultSnapshot (D2), each escaped value's String and the base64
// String of each secret, platform buffers, swap. That no String of the WHOLE document
// is built on either side is pinned by MigrationBundleSourceGuardTest (a source guard).
// ---------------------------------------------------------------------------
class MigrationBundleBufferHygieneTest {

    private fun richBundle(): MigrationBundle = migGoldenBundles().getValue("schema10_rich")

    @Test
    fun everyOutgrownArray_andTheFinalWorkingArray_areZeroed() {
        val retired = ArrayList<ByteArray>()
        val sink = WipingByteSink(initialCapacity = 16, onRetired = { retired += it })
        val out = MigrationBundleCodec.encodeInto(richBundle(), sink)

        assertContentEquals(MigrationBundleCodec.encode(richBundle()), out, "the seam must not change the bytes")
        assertTrue(retired.size >= 6, "a 16-byte start must have grown several times: ${retired.size}")
        // Growth doubles: 16, 32, 64, … and the last retired array is the final working one.
        for (j in 0 until retired.size - 1) assertEquals(16 shl j, retired[j].size, "growth step $j")
        assertTrue(retired.last().size >= out.size)
        for ((j, a) in retired.withIndex()) assertTrue(a.all { it == 0.toByte() }, "retired array #$j (${a.size} B) not zeroed")
        // The result is a separate, exact-size array.
        assertTrue(retired.none { it === out })
        assertEquals('{'.code.toByte(), out.first())
    }

    @Test
    fun theLargeBundle_retiresOnlyZeroedArrays_andGrowsLogarithmically() {
        val retired = ArrayList<ByteArray>()
        val out = MigrationBundleCodec.encodeInto(migLargeBundle(), WipingByteSink(onRetired = { retired += it }))
        // 4 KiB → ≥ 11.9 MB in doublings: 12 growths + the final working array.
        assertTrue(retired.size in 2..16, "growth count ${retired.size} is not logarithmic")
        for ((j, a) in retired.withIndex()) assertTrue(a.all { it == 0.toByte() }, "retired array #$j (${a.size} B) not zeroed")
        assertEquals(MigrationBundleGoldenData.ENCODED_DIGESTS.getValue("large_near_limit").first, out.size)
    }

    @Test
    fun aFailureMidEncode_zeroesThePartialDocument() {
        // The seam throws on the first growth: by then the old array is zeroed and the
        // live buffer is the new copy holding the partial document — the encoder's
        // `finally` must zero that one too before the exception leaves.
        val retired = ArrayList<ByteArray>()
        val boom = IllegalStateException("injected")
        val sink = WipingByteSink(initialCapacity = 16, onRetired = {
            retired += it
            if (retired.size == 1) throw boom
        })
        val thrown = assertFailsWith<IllegalStateException> { MigrationBundleCodec.encodeInto(richBundle(), sink) }
        assertSame(boom, thrown)
        assertEquals(2, retired.size, "the outgrown array and then the partial working array")
        assertEquals(32, retired[1].size)
        for (a in retired) assertTrue(a.all { it == 0.toByte() })
    }

    @Test
    fun aRefusedBundle_releasesTheSinkToo() {
        val retired = ArrayList<ByteArray>()
        assertFailsWith<MigrationBundleCodec.FormatException> {
            MigrationBundleCodec.encodeInto(richBundle().copy(version = 2), WipingByteSink(initialCapacity = 16, onRetired = { retired += it }))
        }
        assertEquals(1, retired.size)
        assertTrue(retired.single().all { it == 0.toByte() })
    }

    @Test
    fun theSink_refusesUseAfterRelease_andWipeIsIdempotent() {
        val retired = ArrayList<ByteArray>()
        val sink = WipingByteSink(initialCapacity = 16, onRetired = { retired += it })
        sink.ascii("{\"a\":").bytes(byteArrayOf(0x31)).ascii('}')
        val out = sink.toByteArrayAndWipe()
        assertEquals("{\"a\":1}", out.decodeToString())
        sink.wipe()
        assertEquals(1, retired.size, "a second wipe must not retire anything again")
        assertFailsWith<IllegalStateException> { sink.ascii('x') }
        assertFailsWith<IllegalStateException> { sink.toByteArrayAndWipe() }
        assertFailsWith<IllegalArgumentException> { WipingByteSink().ascii("é") }
    }

    @Test
    fun decode_neitherModifiesNorRetainsItsInput() {
        val bytes = MigrationBundleCodec.encode(richBundle())
        val copy = bytes.copyOf()
        val decoded = MigrationBundleCodec.decode(bytes)
        assertContentEquals(copy, bytes, "decode must not touch the caller's buffer")
        // The caller wipes it right after (MoveManager.importFromHandle); the model must
        // not alias it.
        bytes.secureWipe()
        assertEquals(renderMigBundle(migExpectedAfterDecode(richBundle())), renderMigBundle(decoded))
    }
}

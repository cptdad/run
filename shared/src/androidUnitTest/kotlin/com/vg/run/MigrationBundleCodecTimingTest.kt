package com.vg.run

import kotlin.test.Test
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// RÚN-04 part (b): encode + decode time of the large fixture (~11.9 MB, every array at
// 8192 rows) for the production codec and the frozen String-based reference
// (LegacyMigrationBundleCodec), on the JVM. Prints the medians to stdout (the test
// report's system-out) so a before/after comparison is a matter of reading two runs.
//
// The only assertion is a generous ratio bound — a quadratic regression (e.g. a
// buffer that grows by a constant instead of doubling) is orders of magnitude, not
// percent, and a wall-clock threshold on a shared CI box would only be flaky.
// ---------------------------------------------------------------------------
class MigrationBundleCodecTimingTest {

    private fun medianMs(runs: Int, block: () -> Unit): Double {
        val times = DoubleArray(runs)
        for (i in 0 until runs) {
            val t0 = System.nanoTime()
            block()
            times[i] = (System.nanoTime() - t0) / 1e6
        }
        times.sort()
        return times[runs / 2]
    }

    @Test
    fun largeBundle_encodeAndDecodeTimes() {
        val b = migLargeBundle()
        val bytes = MigrationBundleCodec.encode(b)
        repeat(2) { // warm-up, both codecs
            MigrationBundleCodec.decode(MigrationBundleCodec.encode(b))
            LegacyMigrationBundleCodec.decode(LegacyMigrationBundleCodec.encode(b))
        }
        val runs = 7
        val encNew = medianMs(runs) { MigrationBundleCodec.encode(b) }
        val encRef = medianMs(runs) { LegacyMigrationBundleCodec.encode(b) }
        val decNew = medianMs(runs) { MigrationBundleCodec.decode(bytes) }
        val decRef = medianMs(runs) { LegacyMigrationBundleCodec.decode(bytes) }
        println(
            "RUN04-TIMING bytes=${bytes.size} runs=$runs " +
                "encode: production=%.1f ms reference=%.1f ms | decode: production=%.1f ms reference=%.1f ms"
                    .format(encNew, encRef, decNew, decRef),
        )
        assertTrue(encNew < encRef * 10 + 200, "encode regressed: $encNew ms vs reference $encRef ms")
        assertTrue(decNew < decRef * 10 + 200, "decode regressed: $decNew ms vs reference $decRef ms")
    }
}

package com.vg.run

import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

// ---------------------------------------------------------------------------
// Android PoW solver — fans the counter search across CPU cores.
//
// The grind is embarrassingly parallel: each worker scans a disjoint stride of
// the counter space (worker w: w, w+N, w+2N, …) using the SAME shared predicate
// [hashHasLeadingZeroBits] over the SAME preimage bytes [computePowHash] hashes
// (see the 2026-10-02 note below for why the scan loop itself is Android's own
// allocation-free copy, and the test that pins it). The relay accepts ANY
// counter meeting the difficulty, so the first worker to find one wins.
//
// Combined with the thread-local SHA-256 engine (PlatformCrypto.android.kt),
// this takes a Pixel-9a-class inbox mint from ~10–20 s (single thread,
// getInstance per hash) down to ~1 s.
//
// 2026-10-02: each worker now grinds with [powSearchStridedNoAlloc] instead of
// the shared [powSearchStrided]. Budget Samsungs (A20e Exynos 7884, A13
// Exynos 850) solved difficulty 20 in ~5–13 s on the allocating path — close
// enough to POW_MAX_SOLVE_MILLIS (15 s) that a geometric unlucky solve hit
// PowTimedOut, which is TERMINAL for the mint (the A20e logged
// "mintInbox: PoW exceeded 15000ms budget" at 07:54:40Z, 15 s after its
// challenge, and the move export sat on "Could not prepare the transfer").
// The allocating path built a String template, a UTF-8 ByteArray and a
// 32-byte digest per hash (~1 M hashes per solve × 8 threads of garbage);
// the no-alloc path writes the SAME preimage bytes into one reused buffer.
// The predicate is still [hashHasLeadingZeroBits] and the preimage is pinned
// byte-for-byte to [computePowHash] by PowNoAllocEquivalenceTest.
// ---------------------------------------------------------------------------

/**
 * Reusable `"<nonce>:<counter>"` UTF-8 preimage — byte-identical to
 * `"$nonce:$counter".encodeToByteArray()` (what [computePowHash] hashes) for
 * every NON-NEGATIVE counter, without allocating per counter. One instance per
 * worker thread; NOT thread-safe.
 */
internal class PowPreimage(nonce: String) {
    private val prefixLen: Int
    /** The preimage bytes; valid in `[0, length)` after [set]. */
    val bytes: ByteArray
    private val digits = ByteArray(MAX_LONG_DIGITS)

    init {
        val prefix = "$nonce:".encodeToByteArray()
        prefixLen = prefix.size
        bytes = ByteArray(prefixLen + MAX_LONG_DIGITS)
        prefix.copyInto(bytes)
    }

    /** Writes [counter] (must be >= 0) after the prefix; returns the preimage length. */
    fun set(counter: Long): Int {
        require(counter >= 0) { "PoW counters are non-negative" }
        var v = counter
        var k = 0
        do {
            digits[k++] = ('0'.code + (v % 10).toInt()).toByte()
            v /= 10
        } while (v > 0)
        var len = prefixLen
        while (k > 0) bytes[len++] = digits[--k]
        return len
    }

    private companion object {
        /** Long.MAX_VALUE has 19 decimal digits. */
        const val MAX_LONG_DIGITS = 19
    }
}

/**
 * Allocation-free twin of [powSearchStrided]: same strided scan, same
 * poll-every-16k [stop] contract, same predicate ([hashHasLeadingZeroBits] over
 * SHA-256 of the [PowPreimage] bytes), so it returns exactly the counter the
 * shared search would. Uses its OWN MessageDigest (one per worker), not the
 * thread-local one, so a hash is one `update` + one `digest(out)` and nothing
 * else.
 */
internal inline fun powSearchStridedNoAlloc(
    nonce: String,
    difficulty: Int,
    start: Long,
    stride: Long,
    stop: () -> Boolean,
): Long? {
    val md = java.security.MessageDigest.getInstance("SHA-256")
    val pre = PowPreimage(nonce)
    val out = ByteArray(32)
    var counter = start
    var sincePoll = 0
    while (true) {
        if ((sincePoll++ and 0x3FFF) == 0 && stop()) return null
        md.update(pre.bytes, 0, pre.set(counter))
        md.digest(out, 0, out.size)
        if (hashHasLeadingZeroBits(out, difficulty)) return counter
        counter += stride
    }
}

internal actual fun solvePowParallel(
    nonce: String,
    difficulty: Int,
    abort: PowAbort,
    concurrentGrinds: Int,
): Long {
    // Short CPU burst; one worker per core (capped) is plenty. availableProcessors
    // reports the cores schedulable to us right now. MINT-2: divide by the number
    // of grinds running at once (>=1) so concurrent mints don't oversubscribe the
    // cores and push either grind past the per-solve cap on a slow device.
    val workers = (Runtime.getRuntime().availableProcessors() / concurrentGrinds.coerceAtLeast(1))
        .coerceIn(1, 8)

    if (workers == 1) {
        return powSearchStridedNoAlloc(nonce, difficulty, start = 0L, stride = 1L) { abort.shouldAbort() }
            ?: throw PowSolveAborted()
    }

    val solution = AtomicLong(0L)
    val solved = AtomicBoolean(false)   // a winning counter was found
    val aborted = AtomicBoolean(false)  // the caller asked to cancel

    val threads = (0 until workers).map { w ->
        Thread {
            val found = powSearchStridedNoAlloc(
                nonce,
                difficulty,
                start = w.toLong(),
                stride = workers.toLong(),
            ) {
                // Stop this worker if a sibling already won, the caller aborted,
                // or this poll observes a fresh abort. Short-circuits so
                // abort.shouldAbort() isn't called once we're already stopping.
                solved.get() || aborted.get() ||
                    abort.shouldAbort().also { if (it) aborted.set(true) }
            }
            if (found != null && solved.compareAndSet(false, true)) {
                solution.set(found)
            }
        }.apply {
            // Daemon so a stray worker can never hold up process exit.
            isDaemon = true
            name = "pow-$w"
            start()
        }
    }
    threads.forEach { it.join() }

    if (solved.get()) return solution.get()
    // No worker found a counter and they all stopped -> the only reason is abort.
    throw PowSolveAborted()
}

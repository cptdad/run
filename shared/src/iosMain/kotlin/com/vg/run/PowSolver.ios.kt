package com.vg.run

import kotlin.native.concurrent.Future
import kotlin.native.concurrent.ObsoleteWorkersApi
import kotlin.native.concurrent.TransferMode
import kotlin.native.concurrent.Worker
import platform.Foundation.NSLock
import platform.Foundation.NSProcessInfo

// ---------------------------------------------------------------------------
// iOS PoW solver — fans the counter search across CPU cores with Workers.
//
// Each worker scans a disjoint stride of the counter space (worker w:
// w, w+N, w+2N, …) using the SAME shared predicate [powSearchStrided] ->
// [computePowHash]/[hashHasLeadingZeroBits], so there is no second copy of the
// relay-coupled hashing logic and the first worker to find a counter wins (the
// relay accepts ANY counter meeting the difficulty). This mirrors the Android
// solver.
//
// Was single-threaded (start=0/stride=1): a near-ceiling (23-bit) honest solve
// could hit the [POW_MAX_SOLVE_MILLIS] wall on one core and fail an otherwise-
// valid mint, and it let a hostile relay pin one core for the full budget.
// Fanning across cores both makes honest mints reliable and shrinks that DoS
// window.
//
// State is shared via [PowShared] (an NSLock + plain fields), passed to each
// worker through the producer — no captured state crosses the thread boundary.
// ---------------------------------------------------------------------------

/** Shared, lock-guarded coordination between PoW workers. */
private class PowShared {
    private val lock = NSLock()
    private var stop = false
    private var solution = -1L   // -1 = no winner yet (no real counter is negative)

    /** Polled ~every 16k hashes by each worker. Returns true to abandon the grind. */
    fun shouldStop(abort: PowAbort): Boolean {
        lock.lock()
        val alreadyStopping = stop
        lock.unlock()
        if (alreadyStopping) return true
        // Poll the caller's abort (deadline + cancel) OUTSIDE the lock; if it
        // fires, latch stop so siblings exit on their next poll.
        if (abort.shouldAbort()) {
            lock.lock(); stop = true; lock.unlock()
            return true
        }
        return false
    }

    /** First winning counter wins; signals siblings to stop. */
    fun offer(counter: Long) {
        lock.lock()
        if (solution < 0L) {
            solution = counter
            stop = true
        }
        lock.unlock()
    }

    /** The winning counter, or -1 if none (all workers stopped via abort/deadline). */
    fun winner(): Long {
        lock.lock()
        val s = solution
        lock.unlock()
        return s
    }
}

/** Per-worker job bundle, transferred through the producer (no thread-crossing captures). */
private class PowWork(
    val nonce: String,
    val difficulty: Int,
    val start: Long,
    val stride: Long,
    val shared: PowShared,
    val abort: PowAbort,
)

// The Workers API is @ObsoleteWorkersApi ("will be replaced with threads
// eventually"), but no stable kotlin.native threads API has shipped yet, and
// kotlinx.coroutines' Native dispatchers are themselves built on Workers — so
// migrating would only hide the same primitive behind a library while risking
// the per-core parallelism this grind needs to stay under POW_MAX_SOLVE_MILLIS.
// Opt in explicitly and revisit when a stable threads API lands.
@OptIn(ObsoleteWorkersApi::class)
internal actual fun solvePowParallel(
    nonce: String,
    difficulty: Int,
    abort: PowAbort,
    concurrentGrinds: Int,
): Long {
    // MINT-2: divide the core budget by the number of grinds running at once
    // (>=1) so a concurrent inbox-pair mint doesn't oversubscribe the cores.
    val workerCount = (NSProcessInfo.processInfo.activeProcessorCount.toInt() / concurrentGrinds.coerceAtLeast(1))
        .coerceIn(1, 8)

    // One core: no worker/lock overhead — grind inline (also the path JVM-less
    // unit tests and low-core devices take).
    if (workerCount == 1) {
        return powSearchStrided(nonce, difficulty, start = 0L, stride = 1L) { abort.shouldAbort() }
            ?: throw PowSolveAborted()
    }

    val shared = PowShared()
    val workers = List(workerCount) { Worker.start() }
    try {
        val futures: List<Future<Unit>> = workers.mapIndexed { idx, worker ->
            worker.execute(
                TransferMode.SAFE,
                { PowWork(nonce, difficulty, idx.toLong(), workerCount.toLong(), shared, abort) },
            ) { work ->
                val found = powSearchStrided(
                    work.nonce, work.difficulty,
                    start = work.start, stride = work.stride,
                ) { work.shared.shouldStop(work.abort) }
                if (found != null) work.shared.offer(found)
            }
        }
        // Join: every worker has either found the winner or observed stop.
        futures.forEach { it.result }
    } finally {
        workers.forEach { it.requestTermination(processScheduledJobs = false) }
    }

    val winner = shared.winner()
    if (winner >= 0L) return winner
    // No worker found a counter and they all stopped -> the only reason is abort
    // (caller cancel or the deadline folded into [abort] by solvePow).
    throw PowSolveAborted()
}

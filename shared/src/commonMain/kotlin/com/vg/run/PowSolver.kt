package com.vg.run

import kotlin.time.TimeSource

// ---------------------------------------------------------------------------
// PowSolver — proof-of-work for `POST /inbox` on the relay (capability proto).
//
// The relay issues a SINGLE-USE, HMAC-bound challenge per mint. Minting is a
// two-request handshake (see MessageManager.mintInbox):
//
//   1. POST /inbox  (no PoW headers, empty body)  → 400 { challenge }
//   2. solve locally, then
//      POST /inbox  with X-PoW-Token + X-PoW-Counter → 201 { inbox + caps }
//
// The 400 body carries:
//   { nonce, token, difficulty, ttlSeconds, algorithm:"sha256",
//     preimage:"nonce:counter" }
//
// The client builds `preimage = "<nonce>:<counter>"`, hashes its UTF-8 bytes
// with SHA-256, and searches `counter = 0, 1, 2, …` for a hash with at least
// `difficulty` leading zero bits (MSB-first). The winning counter and the
// opaque `token` (echoed verbatim) are submitted as the two headers.
//
// The challenge nonce is server-random and single-use, so no precompute is
// possible. There is no time-window (precomputable) fallback path — adding one
// would re-open the precompute hole.
//
// IMPORTANT: the nonce is hashed as the relay-issued base64url STRING, used
// verbatim. Do NOT base64-decode / re-encode / repad it — the relay hashes
// the same characters it sent.
//
// The solver is CPU-bound and fans the counter search across CPU cores (up to 8
// workers) on BOTH platforms (see solvePowParallel); callers MUST still invoke it
// from a background dispatcher (Dispatchers.Default on Android, a detached Task on
// iOS via the Swift bridge) — never from the UI thread.
//
// The PoW gates inbox CREATION only. POST /inbox/{id} (send), GET /inbox/{id}
// (poll), etc. carry no PoW — they are gated by the per-cap auth machinery.
// ---------------------------------------------------------------------------

/**
 * Hard client-side ceiling on PoW difficulty (leading zero bits). The honest
 * relay issues at most 22 bits (hard-capped 23 server-side); any challenge
 * above this is treated as hostile — a relay trying to pin the client's CPU —
 * and [solvePow] refuses to grind it. This preserves the "PoW cannot DoS
 * the client" property: a malicious relay can never make us burn unbounded
 * CPU on a single mint. 23 = the relay's server-side hard cap (honest mints
 * issue <=22), so the client ceiling matches the server cap rather than sitting
 * above it.
 */
const val MAX_POW_DIFFICULTY_BITS: Int = 23

// Max length of a relay-supplied PoW nonce/token before it
// is echoed verbatim into an HTTP header. A legitimate nonce is a ~43-char base64
// value and the token is a short opaque string, so 256 (matching the capability
// cap) is far above any real value while bounding a hostile relay's amplification.
const val MAX_POW_FIELD_LEN: Int = 256

/**
 * Hard wall-clock cap on a single PoW solve. A solve may NEVER run longer than
 * this, regardless of difficulty or device speed — [solvePow] abandons the
 * grind and throws [PowTimedOut] once the budget elapses. This bounds a
 * malicious relay's CPU attack on the client (a stronger, more direct form of
 * the "PoW cannot DoS the client" guarantee than the difficulty ceiling alone):
 * even a near-ceiling challenge can only ever cost the user this many ms.
 *
 * 15000 ms. Total CPU per mint is independently bounded by
 * MINT_TOTAL_POW_BUDGET_MS (<=20 s aggregate, summed across re-solves) — that
 * aggregate, NOT this per-solve cap, is the "PoW cannot DoS the client"
 * guarantee, so widening one solve's slice of it doesn't loosen the bound. An
 * honest <=22-bit solve is ~1 s on a modern device at rest, but a real device
 * can be FAR slower: pairing mints TWO inboxes back-to-back (the second on a
 * warm CPU), and a physical phone doing repeated runs thermally throttles its
 * SoC — an honest difficulty-20 solve was observed taking ~8 s on a hot Pixel 7
 * and being KILLED by the old 8 s cap with 12 s of aggregate budget still unused
 * (mint → null → "Could not reach the relay"). 15 s lets one slow/throttled
 * solve use more of the already-budgeted 20 s; the aggregate still bounds the
 * total grind, so the DoS guarantee is intact.
 */
const val POW_MAX_SOLVE_MILLIS: Long = 15000

/**
 * Cancellation hook for [solvePow]. Polled every ~16k iterations of the
 * inner loop. Caller wires it to whatever cancellation primitive their
 * surrounding coroutine / Task uses, e.g.:
 *
 *   solvePow(nonce, difficulty, abort = PowAbort { !coroutineContext.isActive })
 *
 * The default sentinel never aborts.
 */
fun interface PowAbort {
    fun shouldAbort(): Boolean
}

/** Raised when [solvePow] is cancelled via its [PowAbort] sentinel. */
class PowSolveAborted : RuntimeException("PoW solve cancelled")

/**
 * Raised when a [solvePow] grind exceeds its wall-clock budget
 * ([POW_MAX_SOLVE_MILLIS] by default) before finding a counter. The mint that
 * triggered it fails cleanly (returns null); the user can retry.
 */
class PowTimedOut(val budgetMs: Long) :
    RuntimeException("PoW solve exceeded its ${budgetMs}ms budget")

/**
 * Raised when a relay-issued challenge demands more leading-zero bits than
 * [MAX_POW_DIFFICULTY_BITS]. [solvePow] throws this BEFORE hashing anything,
 * so a hostile difficulty costs the client nothing.
 */
class PowDifficultyTooHigh(val difficulty: Int) :
    RuntimeException("PoW difficulty $difficulty exceeds client ceiling $MAX_POW_DIFFICULTY_BITS")

/**
 * Checks whether [hash] starts with at least [bits] zero bits. Keep this
 * in lock-step with the relay's `hashHasLeadingZeroBits` — a divergence
 * here will silently make every minted-inbox request fail to verify.
 */
fun hashHasLeadingZeroBits(hash: ByteArray, bits: Int): Boolean {
    if (bits <= 0) return true
    val fullBytes = bits / 8
    val remBits = bits % 8
    for (i in 0 until fullBytes) {
        if (hash[i] != 0.toByte()) return false
    }
    if (remBits == 0) return true
    val mask = (0xff shl (8 - remBits)) and 0xff
    return (hash[fullBytes].toInt() and mask) == 0
}

/**
 * Computes the SHA-256 of the challenge preimage `"<nonce>:<counter>"`
 * (UTF-8). The [nonce] is the relay-issued base64url string, used VERBATIM —
 * it is not base64-decoded, re-encoded, or repadded. Matches the relay's
 * verifier exactly; a change here without a matching server change will make
 * every inbox-creation request fail to verify.
 *
 * Reference Python (for cross-check):
 *   hashlib.sha256(f"{nonce}:{counter}".encode()).digest()
 * SHA-256("AAAAAAAAAAAAAAAAAAAAAA:0") ==
 *   7b15d49ca96b0245c68901fdc919ab88f6980de00f1a3975a0725138d9f42de7
 */
fun computePowHash(nonce: String, counter: Long): ByteArray =
    sha256("$nonce:$counter".encodeToByteArray())

/**
 * Brute-force search for a counter such that
 * `SHA-256("<nonce>:<counter>")` has [difficulty] leading zero bits.
 *
 * Throws [PowDifficultyTooHigh] (before any hashing) when [difficulty]
 * exceeds [MAX_POW_DIFFICULTY_BITS], and [PowSolveAborted] if [abort] fires
 * before a solution is found. Otherwise blocks the calling thread until a
 * winning counter is found and returns it.
 *
 * The actual grind is delegated to [solvePowParallel], which fans the counter
 * search across CPU cores on BOTH platforms (Android + iOS). The relay
 * accepts ANY counter meeting the difficulty, so a strided multi-worker search
 * is equivalent to the old linear one — the predicate ([computePowHash] +
 * [hashHasLeadingZeroBits]) is unchanged and lives only here, so nothing can
 * drift from the relay's verifier.
 *
 * Caller MUST invoke from a background dispatcher.
 */
fun solvePow(
    nonce: String,
    difficulty: Int,
    abort: PowAbort = PowAbort { false },
    maxDurationMs: Long = POW_MAX_SOLVE_MILLIS,
    // How many PoW grinds may run at once (e.g. the two halves
    // of a concurrent inbox-pair mint). The parallel solver divides the core
    // budget by this so N simultaneous grinds don't oversubscribe an N-core (or
    // throttled) device and breach the per-solve cap. Default 1 = use all cores.
    concurrentGrinds: Int = 1,
): Long {
    if (difficulty > MAX_POW_DIFFICULTY_BITS) throw PowDifficultyTooHigh(difficulty)
    // counter 0 trivially satisfies "zero leading-zero bits required" — return
    // it directly so a 0-difficulty challenge is a no-op and the parallel
    // workers (which would race to claim a counter) are never spun up.
    if (difficulty <= 0) return 0L

    // Hard wall-clock cap. The deadline is folded into the abort the workers
    // already poll (~every 16k hashes), so the platform grinders need no
    // change. A monotonic clock is used so a wall-clock/NTP adjustment can't
    // extend or shorten the budget. [timedOut] is written by worker threads but
    // only read AFTER [solvePowParallel] returns (all workers joined), so the
    // join barrier makes the read safe without an atomic.
    val started = TimeSource.Monotonic.markNow()
    var timedOut = false
    val deadlineAbort = PowAbort {
        if (started.elapsedNow().inWholeMilliseconds >= maxDurationMs) {
            timedOut = true
            true
        } else {
            abort.shouldAbort()
        }
    }
    return try {
        solvePowParallel(nonce, difficulty, deadlineAbort, concurrentGrinds)
    } catch (e: PowSolveAborted) {
        // The grinders signal any stop as PowSolveAborted; translate a
        // deadline-triggered stop into PowTimedOut, leave a real caller abort
        // as-is.
        if (timedOut) throw PowTimedOut(maxDurationMs) else throw e
    }
}

/**
 * Strided counter search shared by every platform's [solvePowParallel] so the
 * PoW predicate lives in exactly ONE place. Scans `start, start+stride,
 * start+2*stride, …` and returns the first winning counter, or `null` if [stop]
 * fires first. [stop] is polled ~once per 16k hashes (cheap relative to the SHA
 * call, responsive enough for a UI cancel button). `inline` so the [stop]
 * lambda costs nothing in the hot loop.
 */
internal inline fun powSearchStrided(
    nonce: String,
    difficulty: Int,
    start: Long,
    stride: Long,
    stop: () -> Boolean,
): Long? {
    var counter = start
    var sincePoll = 0
    while (true) {
        if ((sincePoll++ and 0x3FFF) == 0 && stop()) return null
        if (hashHasLeadingZeroBits(computePowHash(nonce, counter), difficulty)) {
            return counter
        }
        counter += stride
    }
}

/**
 * Platform grind. [difficulty] is pre-validated by [solvePow] (in `1..
 * MAX_POW_DIFFICULTY_BITS`), so actuals need not re-check the ceiling. MUST
 * return a counter whose [computePowHash] has [difficulty] leading zero bits,
 * or throw [PowSolveAborted] if [abort] fires before a solution is found.
 */
internal expect fun solvePowParallel(
    nonce: String,
    difficulty: Int,
    abort: PowAbort,
    concurrentGrinds: Int,
): Long

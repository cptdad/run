package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Tests for PowSolver (server-challenge scheme). The most important assertions
 * here are the cross-language regression vectors
 * ([computePowHash_pinnedVectors_matchPython]): if these drift, every
 * minted-inbox request will silently fail to verify against the relay.
 */
class PowSolverTest {

    private fun ByteArray.toHexLower(): String = joinToString("") {
        val v = it.toInt() and 0xFF
        "0123456789abcdef"[v ushr 4].toString() + "0123456789abcdef"[v and 0xF]
    }

    // -----------------------------------------------------------------------
    // Cross-language regression — keep in lock-step with the relay's verifier
    // and the reference Python below. A change here that doesn't also land on
    // the relay will silently kill every POST /inbox.
    //
    //   import hashlib
    //   def h(nonce): return hashlib.sha256(f"{nonce}:0".encode()).hexdigest()
    //
    // The third nonce contains BOTH '-' and '_' — a wrong-alphabet tripwire:
    // if anyone "normalizes" the nonce by base64-decoding/re-encoding it, the
    // hash changes and this vector fails.
    // -----------------------------------------------------------------------

    @Test
    fun computePowHash_pinnedVectors_matchPython() {
        assertEquals(
            "7b15d49ca96b0245c68901fdc919ab88f6980de00f1a3975a0725138d9f42de7",
            computePowHash("AAAAAAAAAAAAAAAAAAAAAA", 0L).toHexLower(),
        )
        assertEquals(
            "257253f403d8c14256b43a925d69f5b39db42e432e3db39de2cf5e0d5385eb5f",
            computePowHash("AAECAwQFBgcICQoLDA0ODw", 0L).toHexLower(),
        )
        assertEquals(
            "438594af8e2661dce5ffd5894a6bfeb1141acf1d2f935f74bd47f2e14d90b5d3",
            computePowHash("_-A_----ABEiM6q7zN3u_w", 0L).toHexLower(),
        )
    }

    @Test
    fun computePowHash_isDeterministic() {
        val a = computePowHash("nonce", 67890L)
        val b = computePowHash("nonce", 67890L)
        assertTrue(a.contentEquals(b))
    }

    @Test
    fun computePowHash_differentInputsDiffer() {
        assertTrue(!computePowHash("a", 0L).contentEquals(computePowHash("b", 0L)))
        assertTrue(!computePowHash("a", 0L).contentEquals(computePowHash("a", 1L)))
    }

    // -----------------------------------------------------------------------
    // hashHasLeadingZeroBits — must agree with the relay's verifier exactly.
    // -----------------------------------------------------------------------

    @Test
    fun zeroBits_alwaysTrue() {
        assertTrue(hashHasLeadingZeroBits(byteArrayOf(0xFF.toByte()), 0))
    }

    @Test
    fun byteAlignedBits() {
        val h = byteArrayOf(0x00, 0x00, 0xFF.toByte(), 0x00)
        assertTrue(hashHasLeadingZeroBits(h, 16))
        assertTrue(!hashHasLeadingZeroBits(h, 17))
    }

    @Test
    fun subByteBits_checksHighBitsOfNextByte() {
        // 0x0F = 0000_1111 — first 4 bits are zero, fifth bit is 1, so a hash
        // of 0x000F has exactly 12 leading zero bits: 12 yes, 13 no.
        val h = byteArrayOf(0x00, 0x0F)
        assertTrue(hashHasLeadingZeroBits(h, 12))
        assertTrue(!hashHasLeadingZeroBits(h, 13))
    }

    @Test
    fun firstBitOne_failsAnyPositiveBits() {
        // 0x80 == 1000_0000 — zero leading zero bits.
        val h = byteArrayOf(0x80.toByte())
        assertTrue(!hashHasLeadingZeroBits(h, 1))
    }

    @Test
    fun smallLeadingValue_passesUpToSomeBitCount() {
        // 0x01 == 0000_0001 — exactly 7 leading zero bits.
        val h = byteArrayOf(0x01)
        assertTrue(hashHasLeadingZeroBits(h, 7))
        assertTrue(!hashHasLeadingZeroBits(h, 8))
    }

    // -----------------------------------------------------------------------
    // solvePow — smoke test at low difficulty. 8 bits is ~256 hashes
    // expected, sub-millisecond on any device.
    // -----------------------------------------------------------------------

    @Test
    fun solvePow_lowDifficulty_findsCounter() {
        val counter = solvePow(nonce = "round-trip-nonce", difficulty = 8)
        // Verify the returned counter actually satisfies the difficulty.
        val hash = computePowHash("round-trip-nonce", counter)
        assertTrue(hashHasLeadingZeroBits(hash, 8))
    }

    @Test
    fun solvePow_withConcurrentGrinds_stillSolves() {
        // The concurrent inbox-pair mint passes concurrentGrinds
        // so the parallel solver splits the core budget. That must NOT change
        // correctness — the returned counter still satisfies the difficulty.
        val counter = solvePow(nonce = "concurrent-nonce", difficulty = 8, concurrentGrinds = 2)
        val hash = computePowHash("concurrent-nonce", counter)
        assertTrue(hashHasLeadingZeroBits(hash, 8))
        // A large concurrentGrinds coerces workers down to 1 (never below), and
        // still solves — the divisor can't wedge the solver.
        val counter2 = solvePow(nonce = "single-worker-nonce", difficulty = 8, concurrentGrinds = 64)
        assertTrue(hashHasLeadingZeroBits(computePowHash("single-worker-nonce", counter2), 8))
    }

    @Test
    fun solvePow_zeroDifficulty_returnsCounterZero() {
        // With zero leading-zero-bits required, counter=0 always satisfies.
        assertEquals(0L, solvePow(nonce = "anything", difficulty = 0))
    }

    @Test
    fun solvePow_abortFlag_throwsPowSolveAborted() {
        // Difficulty high enough that the solve can't finish quickly, then
        // abort immediately on the first poll.
        var pollCount = 0
        assertFailsWith<PowSolveAborted> {
            solvePow(
                nonce = "n",
                // At the ceiling (~16M expected hashes) — within the clamp so
                // we exercise the abort path, not PowDifficultyTooHigh.
                difficulty = MAX_POW_DIFFICULTY_BITS,
                abort = PowAbort {
                    pollCount++
                    true   // abort on first check
                },
            )
        }
        assertTrue(pollCount >= 1)
    }

    // -----------------------------------------------------------------------
    // Difficulty ceiling clamp (security: a hostile relay must not be able to
    // pin the client CPU with an absurd difficulty).
    // -----------------------------------------------------------------------

    @Test
    fun solvePow_difficultyAboveCeiling_refusesWithoutGrinding() {
        var hashed = false
        val ex = assertFailsWith<PowDifficultyTooHigh> {
            solvePow(
                nonce = "n",
                difficulty = MAX_POW_DIFFICULTY_BITS + 1,
                // If the solver entered its loop it would poll abort; assert
                // it never did — the clamp must trip BEFORE any hashing.
                abort = PowAbort { hashed = true; false },
            )
        }
        assertEquals(MAX_POW_DIFFICULTY_BITS + 1, ex.difficulty)
        assertTrue(!hashed, "clamp must refuse before entering the solve loop")
    }

    @Test
    fun solvePow_difficultyAtCeiling_isNotClamped() {
        // Exactly at the ceiling must be ALLOWED (enters the loop). We prove it
        // entered the loop by aborting on the first poll: a PowSolveAborted
        // (not PowDifficultyTooHigh) means the clamp let this difficulty pass.
        assertFailsWith<PowSolveAborted> {
            solvePow(
                nonce = "n",
                difficulty = MAX_POW_DIFFICULTY_BITS,
                abort = PowAbort { true },
            )
        }
    }

    @Test
    fun ceiling_matchesServerHardCap_23() {
        // The client ceiling must equal the relay's server-side hard cap so a
        // hostile relay cannot make us grind beyond it.
        assertEquals(23, MAX_POW_DIFFICULTY_BITS)
    }

    // -----------------------------------------------------------------------
    // Wall-clock cap: a solve can NEVER outrun its time budget, regardless of
    // difficulty or device speed.
    // -----------------------------------------------------------------------

    @Test
    fun solvePow_overBudget_throwsPowTimedOut() {
        // A zero-millisecond budget trips on the very first abort poll (before
        // any hash is computed), so this is deterministic — never flaky on the
        // chance of solving a hard difficulty quickly. At the ceiling so the
        // grind can't trivially finish first.
        assertFailsWith<PowTimedOut> {
            solvePow(
                nonce = "n",
                difficulty = MAX_POW_DIFFICULTY_BITS,
                maxDurationMs = 0,
            )
        }
    }

    @Test
    fun solvePow_timeoutTakesPriorityOverCallerAbort() {
        // When both the deadline and the caller's abort would fire, the result
        // is reported as a timeout (the deadline is checked first).
        val ex = assertFailsWith<PowTimedOut> {
            solvePow(
                nonce = "n",
                difficulty = MAX_POW_DIFFICULTY_BITS,
                abort = PowAbort { true },
                maxDurationMs = 0,
            )
        }
        assertEquals(0L, ex.budgetMs)
    }

    @Test
    fun solvePow_lowDifficultyWithinBudget_stillSolves() {
        // The cap must not interfere with a normal fast solve under the default
        // (8 s) budget.
        val counter = solvePow(nonce = "in-budget", difficulty = 8)
        assertTrue(hashHasLeadingZeroBits(computePowHash("in-budget", counter), 8))
    }

    @Test
    fun powMaxSolveMillis_isFifteenSeconds() {
        // 15 s (was 8 s, was 2 s): an honest <=22-bit solve must finish even on a
        // warm/throttled device — a hot Pixel 7 doing back-to-back runs took ~8 s
        // on a difficulty-20 solve and the old 8 s cap killed it (with 12 s of the
        // aggregate budget unused). Total grind is still bounded by the <=20 s
        // aggregate (MINT_TOTAL_POW_BUDGET_MS), so the DoS bound is intact.
        assertEquals(15000L, POW_MAX_SOLVE_MILLIS)
    }
}

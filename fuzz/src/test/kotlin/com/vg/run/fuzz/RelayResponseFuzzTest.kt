package com.vg.run.fuzz

import com.code_intelligence.jazzer.api.FuzzedDataProvider
import com.code_intelligence.jazzer.junit.FuzzTest
import com.vg.run.MAX_POW_DIFFICULTY_BITS
import com.vg.run.MAX_POW_FIELD_LEN
import com.vg.run.MessageManager
import com.vg.run.PowDifficultyTooHigh
import com.vg.run.computePowHash
import com.vg.run.hashHasLeadingZeroBits
import com.vg.run.parseJsonStringArray
import com.vg.run.solvePow
import org.junit.jupiter.api.Test

/**
 * Relay-controlled response bodies.
 *
 * Everything here is parsed BEFORE any authentication — the relay is hostile by
 * assumption (never-trust-the-relay is the whole capability model), and the PoW
 * challenge in particular is the PRE-AUTH mint handshake.
 *
 *   poll      {"blobs":["<base64>", …]}          → parseJsonStringArray
 *   peek      {"pending":N}                      → parseTopLevelJson
 *   challenge {"nonce":…, "token":…, "difficulty":N} → parseChallenge
 *
 * DOCUMENTED CONTRACTS:
 *  - `parseJsonStringArray` throws IllegalArgumentException and nothing else.
 *  - `parseChallenge` returns null on anything malformed or unsafe; the token and
 *    nonce it DOES return are echoed verbatim into HTTP headers, so they must
 *    carry no control characters and be at most [MAX_POW_FIELD_LEN] chars — a
 *    CRLF there is header injection on the iOS raw-HTTP transport.
 *  - `solvePow` throws [PowDifficultyTooHigh] BEFORE hashing anything when the
 *    relay demands more than [MAX_POW_DIFFICULTY_BITS], "so a hostile difficulty
 *    costs the client nothing".
 */
class RelayResponseFuzzTest {

    @FuzzTest(maxDuration = "60s")
    fun fuzzPollResponse(data: FuzzedDataProvider) {
        val body = data.consumeRemainingAsString()

        onlyThrows(IllegalArgumentException::class) {
            val blobs = bounded("parseJsonStringArray(blobs)") { parseJsonStringArray(body, "blobs") }
            check(blobs.size <= com.vg.run.MAX_PARSE_ARRAY_ELEMENTS) {
                "poll response yielded ${blobs.size} blobs, past the parser's own cap"
            }
        }

        // The /peek response shape — a bare count the caller does `toIntOrNull()` on.
        // Nothing to assert beyond "did not throw": an absent or negative count is
        // the caller's problem, and it handles both.
        bounded("peek") { com.vg.run.parseTopLevelJson(body)["pending"]?.text?.toIntOrNull() }
    }

    @FuzzTest(maxDuration = "60s")
    fun fuzzPowChallenge(data: FuzzedDataProvider) {
        val body = data.consumeRemainingAsString()

        val challenge = bounded("parseChallenge") { manager.parseChallenge(body) } ?: return

        // Header-injection guard: these two strings go into X-PoW-Token / the
        // nonce field verbatim.
        for ((name, value) in listOf("token" to challenge.token, "nonce" to challenge.nonce)) {
            check(value.length <= MAX_POW_FIELD_LEN) {
                "parseChallenge accepted a ${value.length}-char $name (cap $MAX_POW_FIELD_LEN)"
            }
            check(value.none { it.code < 0x20 || it.code == 0x7F }) {
                "parseChallenge accepted a control character in $name — header injection"
            }
        }

        // A hostile difficulty must cost nothing: either it is inside the client
        // ceiling, or solvePow refuses it BEFORE grinding. Anything else (a long
        // grind, a different exception) is a finding.
        if (challenge.difficulty > MAX_POW_DIFFICULTY_BITS) {
            var refused = false
            try {
                solvePow(challenge.nonce, challenge.difficulty, maxDurationMs = 50L)
            } catch (_: PowDifficultyTooHigh) {
                refused = true
            } catch (_: Throwable) {
                // Any OTHER outcome means it started working on the hostile
                // difficulty instead of refusing it outright.
            }
            check(refused) { "solvePow did not refuse difficulty ${challenge.difficulty}" }
        }
    }

    /**
     * The PoW predicate itself, on relay-chosen difficulty.
     *
     * `hashHasLeadingZeroBits` indexes `hash[bits / 8]` with no bound of its own —
     * it relies entirely on its callers having clamped `difficulty` to
     * [MAX_POW_DIFFICULTY_BITS] (23) against a 32-byte digest. That is true today,
     * so an IndexOutOfBounds beyond the digest is the DOCUMENTED precondition
     * rather than a live bug; anything else escaping is not.
     */
    @FuzzTest(maxDuration = "60s")
    fun fuzzPowPredicate(data: FuzzedDataProvider) {
        val bits = data.consumeInt()
        val counter = data.consumeLong()
        val nonce = data.consumeRemainingAsString().take(MAX_POW_FIELD_LEN)

        val hash = bounded("computePowHash") { computePowHash(nonce, counter) }
        check(hash.size == 32) { "computePowHash returned ${hash.size} bytes" }

        if (bits in 0..(hash.size * 8)) {
            // Inside the precondition: must simply answer.
            bounded("hashHasLeadingZeroBits") { hashHasLeadingZeroBits(hash, bits) }
        } else {
            onlyThrows(IndexOutOfBoundsException::class) {
                bounded("hashHasLeadingZeroBits(oob)") { hashHasLeadingZeroBits(hash, bits) }
            }
        }
    }

    // ------------------------------------------------------------------
    // Fixed regression tests.
    // ------------------------------------------------------------------

    @Test
    fun challengeWithCrlfInTokenIsRefused() {
        val hostile = """{"nonce":"abc","token":"tok\r\nX-Evil: 1","difficulty":1}"""
        check(manager.parseChallenge(hostile) == null) { "CRLF token accepted — header injection" }
    }

    @Test
    fun overlongChallengeFieldIsRefused() {
        val long = "a".repeat(MAX_POW_FIELD_LEN + 1)
        check(manager.parseChallenge("""{"nonce":"$long","token":"t","difficulty":1}""") == null)
        check(manager.parseChallenge("""{"nonce":"n","token":"$long","difficulty":1}""") == null)
    }

    @Test
    fun hostileDifficultyIsRefusedBeforeHashing() {
        val started = System.nanoTime()
        var refused = false
        try {
            solvePow("nonce", MAX_POW_DIFFICULTY_BITS + 1)
        } catch (_: PowDifficultyTooHigh) {
            refused = true
        }
        val elapsedMs = (System.nanoTime() - started) / 1_000_000
        check(refused) { "an over-ceiling difficulty was not refused" }
        check(elapsedMs < 1_000) { "refusal took ${elapsedMs}ms — it hashed first" }
    }

    /** A negative difficulty is accepted by the PARSER; solvePow must short-circuit it. */
    @Test
    fun negativeDifficultyIsANoOpGrind() {
        val parsed = manager.parseChallenge("""{"nonce":"n","token":"t","difficulty":-5}""")
        check(parsed?.difficulty == -5) { "parseChallenge silently rewrote a negative difficulty" }
        check(solvePow("n", -5) == 0L) { "a negative difficulty did not short-circuit" }
    }

    private companion object {
        val manager: MessageManager = MessageManager(
            InMemoryVault(),
            "http://127.0.0.1:1",
            DeadRelayHttp(),
            "1.0.0",
        )
    }
}

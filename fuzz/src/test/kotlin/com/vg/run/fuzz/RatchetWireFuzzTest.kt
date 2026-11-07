package com.vg.run.fuzz

import com.code_intelligence.jazzer.api.FuzzedDataProvider
import com.code_intelligence.jazzer.junit.FuzzTest
import com.vg.run.DoubleRatchet
import com.vg.run.MessageManager
import com.vg.run.RatchetManager
import com.vg.run.decodeRatchetWire
import org.junit.jupiter.api.Test

/**
 * The Double Ratchet's two untrusted-input surfaces.
 *
 * 1. THE WIRE. A ratchet blob is `RAT1` ‖ header(40) ‖ IV(12) ‖ ct ‖ tag(16),
 *    fetched from the RELAY, which is hostile by assumption. The cleartext
 *    header (`dhPub(32) ‖ pn(4) ‖ n(4)`) is read and ACTED ON — skip-key
 *    derivation and a DH ratchet step — BEFORE the AEAD tag is checked. So the
 *    header is parsed and trusted-for-state-mutation on unauthenticated bytes.
 *
 * 2. THE PERSISTED STATE. `DoubleRatchet.deserialize` reads a versioned binary
 *    blob out of the vault. That blob is authenticated at rest, but the code
 *    documents an explicit contract for corrupt/truncated records — "must fail
 *    as a clean IllegalArgumentException rather than an IndexOutOfBounds — the
 *    latter is an uncaught Kotlin exception that SIGABRTs iOS" — which is
 *    exactly the sort of claim a fuzzer should be made to break.
 *
 * INVARIANTS asserted against a REAL initialized session (`decryptBatch`):
 *   a. `decryptBatch` never throws. Every per-blob failure is documented as
 *      `null` in the result list.
 *   b. A rejected blob leaves the PERSISTED state byte-identical — the
 *      documented rollback ("a forgery advances nothing").
 *   c. A rejected blob cannot poison a LATER genuine blob in the same batch.
 *      This is the real security property behind (b): the harness puts the
 *      fuzzed blob FIRST and Alice's next genuine message SECOND, and requires
 *      the genuine one to still decrypt to its exact plaintext.
 *   d. Bounded wall time per input (MAX_SKIP caps the HMAC grind at 256).
 */
class RatchetWireFuzzTest {

    /** The relay-facing wire decoder. Declared failure: `require` ⇒ IllegalArgumentException. */
    @FuzzTest(maxDuration = "60s")
    fun fuzzDecodeRatchetWire(data: FuzzedDataProvider) {
        val blob = data.consumeRemainingAsBytes()

        // Companion helper on the same path — pure, must never throw at all.
        bounded("isRatchetWire") { MessageManager.isRatchetWire(blob) }

        // The relay ships `RAT1` ‖ wire; the decoder sees the wire. Try both so
        // an off-by-four in the magic strip is reachable from one corpus.
        val stripped = if (blob.size >= 4) blob.copyOfRange(4, blob.size) else blob
        for (candidate in listOf(blob, stripped)) {
            onlyThrows(IllegalArgumentException::class) {
                bounded("decodeRatchetWire") { decodeRatchetWire(candidate) }
            }
        }
    }

    /** The persisted-state decoder. Declared failure: `require` ⇒ IllegalArgumentException. */
    @FuzzTest(maxDuration = "60s")
    fun fuzzDeserializeRatchetState(data: FuzzedDataProvider) {
        val blob = data.consumeRemainingAsBytes()
        val ratchet = try {
            bounded("DoubleRatchet.deserialize") { DoubleRatchet.deserialize(blob) { FIXED_CLOCK_MS } }
        } catch (_: IllegalArgumentException) {
            null   // the one documented rejection
        }
        if (ratchet != null) {
            // Accepted. The state must then survive a serialize round trip: a
            // record the READER accepts but the WRITER cannot reproduce means the
            // two halves of the format disagree, and the next save would brick
            // the ratchet. Anything thrown from here is a finding, not a reject.
            val reserialized = ratchet.serialize()
            DoubleRatchet.deserialize(reserialized) { FIXED_CLOCK_MS }.wipe()
            ratchet.wipe()
        }
    }

    /**
     * The real thing: fuzzed bytes fed to a LIVE, bootstrapped receiver, with a
     * genuine message right behind them.
     */
    @FuzzTest(maxDuration = "120s")
    fun fuzzDecryptBatchAgainstLiveSession(data: FuzzedDataProvider) {
        val forged = data.consumeRemainingAsBytes()

        val session = Session.get()
        session.store.restore(session.snapshot)

        val results = bounded("decryptBatch", budgetMs = PER_INPUT_BUDGET_MS) {
            session.manager.decryptBatch(
                FuzzIds.CONTACT,
                CHANNEL,
                FuzzIds.SHARED_SECRET,
                FuzzIds.INBOX_A,
                FuzzIds.INBOX_B,
                listOf(forged, session.genuineSecondWire),
            )
        }

        check(results.size == 2) { "decryptBatch dropped an entry: ${results.size}" }

        // (c) the genuine message behind the forgery must be unaffected.
        val genuine = results[1]
        check(genuine != null) { "a forged blob suppressed the genuine message behind it" }
        check(genuine.decodeToString() == GENUINE_SECOND_PLAINTEXT) {
            "genuine plaintext corrupted after a forged blob"
        }

        // (b) if the forged blob was rejected AND nothing else advanced state
        // beyond the genuine message, the persisted blob must match what a clean
        // run produces. Compare against the state reached by decrypting ONLY the
        // genuine message from the same snapshot.
        if (results[0] == null) {
            val after = session.store.snapshot()
            val expected = session.cleanAdvanceSnapshot
            check(after.keys == expected.keys) { "rollback changed the set of persisted ratchets" }
            for ((k, v) in after) {
                check(v.contentEquals(expected[k]!!)) {
                    "a REJECTED blob left different persisted ratchet state under '$k'"
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // Fixed regression tests.
    // ------------------------------------------------------------------

    @Test
    fun truncatedWireIsRejectedCleanly() {
        for (size in 0..67) {
            try {
                decodeRatchetWire(ByteArray(size))
                throw AssertionError("decodeRatchetWire accepted a $size-byte blob")
            } catch (_: IllegalArgumentException) {
                // documented
            }
        }
    }

    @Test
    fun corruptPersistedStateIsRejectedCleanly() {
        val corrupt = listOf(
            ByteArray(0),
            byteArrayOf(3),                       // version only
            byteArrayOf(3, 0xFF.toByte()),        // unknown flag bits
            byteArrayOf(9, 0),                    // future version
            byteArrayOf(3, 0) + ByteArray(95),    // truncated mid-key
        )
        for (blob in corrupt) {
            try {
                DoubleRatchet.deserialize(blob) { FIXED_CLOCK_MS }
                throw AssertionError("deserialize accepted ${blob.size} corrupt bytes")
            } catch (_: IllegalArgumentException) {
                // documented
            }
        }
    }

    @Test
    fun forgedBlobDoesNotPoisonTheGenuineOneBehindIt() {
        val session = Session.get()
        session.store.restore(session.snapshot)
        val forged = ByteArray(100) { 0x41 }
        val results = session.manager.decryptBatch(
            FuzzIds.CONTACT, CHANNEL, FuzzIds.SHARED_SECRET,
            FuzzIds.INBOX_A, FuzzIds.INBOX_B,
            listOf(forged, session.genuineSecondWire),
        )
        check(results[0] == null)
        check(results[1]?.decodeToString() == GENUINE_SECOND_PLAINTEXT)
    }

    /**
     * A bootstrapped receiver plus the two genuine wires its peer produced.
     *
     * Built ONCE per JVM: `initAsAlice` generates a random X25519 keypair, so
     * rebuilding per input would make the harness non-reproducible, and Jazzer
     * needs a crash input to replay identically.
     */
    private class Session private constructor(
        val store: InMemoryRatchetStore,
        val manager: RatchetManager,
        val snapshot: Map<String, ByteArray>,
        val cleanAdvanceSnapshot: Map<String, ByteArray>,
        val genuineSecondWire: ByteArray,
    ) {
        companion object {
            private var instance: Session? = null

            @Synchronized
            fun get(): Session = instance ?: build().also { instance = it }

            private fun build(): Session {
                val secret = FuzzIds.SHARED_SECRET
                val store = InMemoryRatchetStore()
                val manager = RatchetManager(store)
                // Pin the skipped-key stamp clock: an out-of-order burst stamps
                // every cached key with `nowMs()`, and a real clock would make the
                // serialized snapshot differ run to run, turning the state-rollback
                // invariant below into a flaky false positive.
                manager.clockMs = { FIXED_CLOCK_MS }

                // The PEER. Our receiver is Bob because INBOX_A < INBOX_B
                // (ratchetSelfIsBob compares the two inbox ids lexicographically).
                val alice = DoubleRatchet.initAsAlice(secret)
                val wire1 = alice.encrypt("bootstrap".encodeToByteArray()).encodeWire()
                val wire2 = alice.encrypt(GENUINE_SECOND_PLAINTEXT.encodeToByteArray()).encodeWire()

                val boot = manager.decryptBatch(
                    FuzzIds.CONTACT, CHANNEL, secret,
                    FuzzIds.INBOX_A, FuzzIds.INBOX_B, listOf(wire1),
                )
                require(boot[0] != null) { "harness setup: bootstrap message did not decrypt" }
                val snapshot = store.snapshot()

                // The reference "clean" end state: same snapshot, genuine message only.
                val clean = manager.decryptBatch(
                    FuzzIds.CONTACT, CHANNEL, secret,
                    FuzzIds.INBOX_A, FuzzIds.INBOX_B, listOf(wire2),
                )
                require(clean[0] != null) { "harness setup: second message did not decrypt" }
                val cleanAdvance = store.snapshot()

                return Session(store, manager, snapshot, cleanAdvance, wire2)
            }
        }
    }

    private companion object {
        const val CHANNEL = "m"
        const val GENUINE_SECOND_PLAINTEXT = "genuine-second-message"
        const val FIXED_CLOCK_MS = 1_700_000_000_000L
    }
}

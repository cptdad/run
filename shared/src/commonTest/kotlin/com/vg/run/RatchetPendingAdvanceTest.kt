package com.vg.run

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// Retrieve-ack (2026-11-03): the UNCOMMITTED ratchet advance a conversation
// screen's drain keeps in RAM until it has shown the messages, and the six rules
// for everything else that touches the same ratchet meanwhile (RatchetManager
// header, docs/vault-relay-internals.md "Retrieve-ack"). Two devices over a
// byte-passing "relay", each RatchetManager on its own in-memory store.
// ---------------------------------------------------------------------------
class RatchetPendingAdvanceTest {

    private class MapStore : RatchetStore {
        val m = mutableMapOf<String, ByteArray>()
        override fun load(contactId: String, channel: String) = m["$contactId/$channel"]?.copyOf()
        override fun save(contactId: String, channel: String, blob: ByteArray) { m["$contactId/$channel"] = blob.copyOf() }
        fun blob(): ByteArray? = m["$CID/$CH"]?.copyOf()
    }

    private val secret = generateSecureRandom(32)
    private val aIn = "bbb"; private val aOut = "aaa"   // A = Alice (initiator)
    private val bIn = "aaa"; private val bOut = "bbb"   // B = Bob (responder)

    private val storeB = MapStore()
    private var now = 1_000_000L
    private val a = RatchetManager(MapStore())
    private val b = RatchetManager(storeB).also { it.clockMs = { now } }

    private fun aEnc(s: String) = a.tryEncrypt(CID, CH, secret, aIn, aOut, s.encodeToByteArray())!!
    private fun aDec(w: ByteArray) = a.decrypt(CID, CH, secret, aIn, aOut, w)
    private fun bEnc(s: String) = b.tryEncrypt(CID, CH, secret, bIn, bOut, s.encodeToByteArray())!!

    /** One Bob drain. */
    private fun bDrain(
        wires: List<ByteArray>,
        group: Any? = null,
        report: RatchetManager.DecryptBatchReport = RatchetManager.DecryptBatchReport(),
        mgr: RatchetManager = b,
        deferDamaging: Boolean = false,
    ): List<String?> = mgr.decryptBatch(
        CID, CH, secret, bIn, bOut, wires,
        deferDamaging = deferDamaging, report = report,
        persist = group == null, drainGroup = group,
    ).map { it?.decodeToString() }

    /** Bob has received once (persisted), so the store holds a real state. */
    private fun bootstrapped() {
        assertEquals(listOf("a0"), bDrain(listOf(aEnc("a0"))))
    }

    @Test
    fun anUncommittedDrain_persistsNothing_untilCommit_andCommitIsIdempotent() {
        bootstrapped()
        val before = storeB.blob()!!
        val w1 = aEnc("a1")
        val rep = RatchetManager.DecryptBatchReport()
        assertEquals(listOf("a1"), bDrain(listOf(w1), group = Any(), report = rep))
        val ticket = assertNotNull(rep.pendingTicket, "an advancing pending drain leaves a ticket")
        assertContentEquals(before, storeB.blob(), "nothing may reach the store before the screen commits")

        assertTrue(b.commitPending(ticket))
        val after = storeB.blob()!!
        assertFalse(before.contentEquals(after), "commit persists the advance")
        assertTrue(b.commitPending(ticket), "commit is idempotent")
        assertContentEquals(after, storeB.blob())
        // The committed advance consumed a1's one-shot key: a re-delivery is a duplicate.
        assertEquals(listOf<String?>(null), bDrain(listOf(w1)))
    }

    @Test
    fun noCommit_theRedeliveryAfterTheLeaseDecryptsAgain() {
        bootstrapped()
        val w1 = aEnc("a1")
        assertEquals(listOf("a1"), bDrain(listOf(w1), group = Any()))   // never committed (teardown / abandoned)
        now += RatchetManager.PENDING_ADVANCE_MAX_AGE_MS                   // rule 5: aged out by the next touch
        assertEquals(listOf("a1"), bDrain(listOf(w1)), "the re-delivered blob must decrypt — the message is not lost")
    }

    @Test
    fun aPersistingDrain_neverBuildsOnAnUncommittedAdvance_itsWiresAreNotProcessed() {
        bootstrapped()
        val w1 = aEnc("a1"); val w2 = aEnc("a2")
        val rep = RatchetManager.DecryptBatchReport()
        assertEquals(listOf("a1"), bDrain(listOf(w1), group = Any(), report = rep))
        val held = storeB.blob()!!
        val bg = RatchetManager.DecryptBatchReport()
        assertEquals(listOf<String?>(null), bDrain(listOf(w2), report = bg))
        assertEquals(setOf(0), bg.notProcessed, "rule 3: the background wire is NOT_PROCESSED (not acked, comes back)")
        assertContentEquals(held, storeB.blob(), "…and nothing was written")
        assertTrue(b.commitPending(rep.pendingTicket!!))
        assertEquals(listOf("a2"), bDrain(listOf(w2)), "after the commit the next background drain takes it")
    }

    @Test
    fun theSameDrainGroup_chains_andCommittingTheHeadCommitsTheBase() {
        bootstrapped()
        val g = Any()
        val r1 = RatchetManager.DecryptBatchReport(); val r2 = RatchetManager.DecryptBatchReport()
        assertEquals(listOf("a1"), bDrain(listOf(aEnc("a1")), group = g, report = r1))
        assertEquals(listOf("a2"), bDrain(listOf(aEnc("a2")), group = g, report = r2))
        assertTrue(r2.baseTicket === r1.pendingTicket, "rule 1: the group inbox drain builds on the text inbox drain")
        assertTrue(b.commitPending(r2.pendingTicket!!))
        assertTrue(b.isCommitted(r1.pendingTicket!!), "the base is in the store with its head")
        assertTrue(b.commitPending(r1.pendingTicket!!))
    }

    @Test
    fun anotherDrainGroup_discardsTheStaleAdvance_releasesIt_andNothingIsLost() {
        bootstrapped()
        val w1 = aEnc("a1"); val w2 = aEnc("a2")
        val r1 = RatchetManager.DecryptBatchReport()
        assertEquals(listOf("a1"), bDrain(listOf(w1), group = Any(), report = r1))
        var released = 0
        r1.pendingTicket!!.onDiscarded = { released++ }
        val r2 = RatchetManager.DecryptBatchReport()
        assertEquals(listOf("a2"), bDrain(listOf(w2), group = Any(), report = r2))   // the NEXT screen poll
        assertEquals(1, released, "rule 2: the stale drain's lease is released at once")
        assertFalse(b.commitPending(r1.pendingTicket!!), "a late commit of the stale drain must not persist")
        assertTrue(b.commitPending(r2.pendingTicket!!))
        assertEquals(listOf("a1"), bDrain(listOf(w1)), "the released blob opens from the skipped key — not lost")
    }

    @Test
    fun aSend_discardsTheUncommittedAdvance_neverCommitsItImplicitly() {
        bootstrapped()
        val w1 = aEnc("a1")
        val r1 = RatchetManager.DecryptBatchReport()
        assertEquals(listOf("a1"), bDrain(listOf(w1), group = Any(), report = r1))
        var released = 0
        r1.pendingTicket!!.onDiscarded = { released++ }
        val reply = bEnc("b1")                                        // rule 4
        assertEquals(1, released)
        assertFalse(b.commitPending(r1.pendingTicket!!))
        assertEquals(listOf("a1"), bDrain(listOf(w1)), "the unshown message comes back")
        assertEquals("b1", aDec(reply).decodeToString(), "and the reply sent meanwhile still opens at the peer")
    }

    @Test
    fun aCommitOverAStoreSomeoneElseMoved_isDiscarded_notAFork() {
        bootstrapped()
        val w1 = aEnc("a1"); val w2 = aEnc("a2")
        val r1 = RatchetManager.DecryptBatchReport()
        assertEquals(listOf("a1"), bDrain(listOf(w1), group = Any(), report = r1))
        // A Tor restart rebuilt MessageManager (no scrub): a NEW RatchetManager on the
        // same vault persists an advance while the old screen's drain is uncommitted.
        val b2 = RatchetManager(storeB).also { it.clockMs = { now } }
        assertEquals(listOf("a2"), bDrain(listOf(w2), mgr = b2))
        val moved = storeB.blob()!!
        assertFalse(b.commitPending(r1.pendingTicket!!), "compare-and-swap: the stale snapshot must not overwrite")
        assertContentEquals(moved, storeB.blob())
        assertEquals(listOf("a1"), bDrain(listOf(w1), mgr = b2), "the discarded drain's blob re-delivers and opens")
    }

    @Test
    fun scrub_discardsUncommittedAdvances_withoutFiringReleaseHooks() {
        bootstrapped()
        val before = storeB.blob()!!
        val r1 = RatchetManager.DecryptBatchReport()
        bDrain(listOf(aEnc("a1")), group = Any(), report = r1)
        var released = 0
        r1.pendingTicket!!.onDiscarded = { released++ }
        b.scrubInMemory()
        assertEquals(0, released, "a lock / wipe must cause no network I/O")
        assertFalse(b.commitPending(r1.pendingTicket!!), "and no commit writes after teardown")
        assertContentEquals(before, storeB.blob())
    }

    @Test
    fun abandon_discardsTheAdvance_andTheBlobDecryptsAgain() {
        bootstrapped()
        val w1 = aEnc("a1")
        val r1 = RatchetManager.DecryptBatchReport()
        bDrain(listOf(w1), group = Any(), report = r1)
        b.abandonPending(r1.pendingTicket!!)
        assertFalse(b.commitPending(r1.pendingTicket!!))
        assertEquals(listOf("a1"), bDrain(listOf(w1)))
    }

    @Test
    fun theCutoffTail_isReportedNotProcessed_notRejected() {
        bootstrapped()
        val junk = List(RatchetManager.MAX_CONSECUTIVE_FAILURES_PER_BATCH) { ByteArray(40) + generateSecureRandom(48) }
        val rep = RatchetManager.DecryptBatchReport()
        val out = bDrain(junk + aEnc("a1"), report = rep)
        assertTrue(out.all { it == null })
        assertEquals(setOf(junk.size), rep.notProcessed, "only the genuine blob behind the cutoff is left for the next drain")
    }

    /**
     * Retrieve-ack plan, decision 2 (R): after a LOST ack and a DH step, a duplicate
     * control blob can be classed OLD_CHAIN and parked in the H-1b deferral buffer
     * instead of being rejected outright. Pinned here — and that it stays harmless:
     * once it is actually tried it is refused and changes nothing.
     */
    @Test
    fun aDuplicateFromAnOldChain_afterADhStep_isDeferredAsOldChain_andHarmlessWhenTried() {
        val a1 = aEnc("a1")
        assertEquals(listOf("a1"), bDrain(listOf(a1)))
        aDec(bEnc("b1"))                                  // Alice ratchets → chain A2
        aEnc("a2-withheld")                               // a2: Bob will only ever see a3
        assertEquals(listOf("a3"), bDrain(listOf(aEnc("a3"))))   // a2's key is now SKIPPED on chain A2
        aDec(bEnc("b2"))                                  // Alice ratchets → chain A3
        assertEquals(listOf("a4"), bDrain(listOf(aEnc("a4"))))   // Bob DH-steps; A2's skipped key is kept
        val rep = RatchetManager.DecryptBatchReport()
        assertEquals(listOf<String?>(null), bDrain(listOf(a1), report = rep, deferDamaging = true))
        assertEquals(DoubleRatchet.SkipDamage.OLD_CHAIN, rep.deferred[0], "the duplicate lands in the deferral, not a rejection")
        assertTrue(rep.notProcessed.isEmpty(), "deferred is PROCESSED (acked + kept in the vault), not left on the relay")
        val held = storeB.blob()!!
        assertEquals(listOf<String?>(null), bDrain(listOf(a1)), "tried for real it is refused")
        assertContentEquals(held, storeB.blob(), "…and advances nothing")
    }

    private companion object {
        const val CID = "contact-1"
        const val CH = "text"
    }
}

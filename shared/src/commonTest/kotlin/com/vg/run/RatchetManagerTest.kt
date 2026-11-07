package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// RatchetManager end-to-end: two simulated devices, each with its own store,
// exchanging wire blobs through a trivial "relay" (just passing bytes). Every
// op goes load→mutate→persist, so this also exercises the persistence path the
// live vault will use. No device, no SQLCipher, no Tor.
// ---------------------------------------------------------------------------
class RatchetManagerTest {

    /** In-memory RatchetStore standing in for the vault-backed one. `load` returns a
     *  FRESH copy each call, matching VaultRatchetStore (decodeBase64 mints a new array):
     *  RatchetManager now secureWipe()s the loaded blob after use, so handing back
     *  the stored reference would zero the at-rest copy. */
    private class MapStore : RatchetStore {
        private val m = mutableMapOf<String, ByteArray>()
        override fun load(contactId: String, channel: String) = m["$contactId/$channel"]?.copyOf()
        override fun save(contactId: String, channel: String, blob: ByteArray) { m["$contactId/$channel"] = blob.copyOf() }
    }

    /** Like MapStore, but retains every blob array it hands out from `load`, so a test can
     *  assert RatchetManager zeroized the transient copy once the op finished. Also
     *  snapshots what was SAVED (taken inside `save`, i.e. before persist()'s own wipe of
     *  the serialized array) so a test can prove the drop-site wipe runs AFTER the
     *  persist and never serializes zeroed keys into the store. */
    private class SpyStore : RatchetStore {
        private val m = mutableMapOf<String, ByteArray>()
        val loadedBlobs = mutableListOf<ByteArray>()
        var lastSaved: ByteArray? = null
            private set
        var saves = 0
            private set
        override fun load(contactId: String, channel: String) =
            m["$contactId/$channel"]?.copyOf()?.also { loadedBlobs.add(it) }
        override fun save(contactId: String, channel: String, blob: ByteArray) {
            saves++
            lastSaved = blob.copyOf()
            m["$contactId/$channel"] = blob.copyOf()
        }
    }

    // A pairing, with ids chosen so device A is the INITIATOR (Alice) and device
    // B the responder (Bob): role = (myInbound < myOutbound) ⇒ Bob, so Alice needs
    // myInbound > myOutbound. A reads "bbb", writes to B's "aaa"; B is the mirror.
    private val secret = generateSecureRandom(32)
    private val aIn = "bbb"; private val aOut = "aaa"   // A: "bbb" > "aaa" ⇒ Alice (initiator)
    private val bIn = "aaa"; private val bOut = "bbb"   // B: "aaa" < "bbb" ⇒ Bob (responder)
    private val CH = "text"
    private val CID = "contact-1"

    private fun mgr() = RatchetManager(MapStore())
    private fun bytes(s: String) = s.encodeToByteArray()
    private fun str(b: ByteArray) = b.decodeToString()

    private fun aEnc(m: RatchetManager, s: String) = m.tryEncrypt(CID, CH, secret, aIn, aOut, bytes(s))
    private fun aDec(m: RatchetManager, w: ByteArray) = m.decrypt(CID, CH, secret, aIn, aOut, w)
    private fun bEnc(m: RatchetManager, s: String) = m.tryEncrypt(CID, CH, secret, bIn, bOut, bytes(s))
    private fun bDec(m: RatchetManager, w: ByteArray) = m.decrypt(CID, CH, secret, bIn, bOut, w)

    @Test
    fun aliceBootstrapThenFullDuplex_survivesPersistencePerOp() {
        val a = mgr(); val b = mgr()
        // Alice auto-sends the pairing bootstrap; Bob receives → now bootstrapped.
        val boot = aEnc(a, "::bootstrap::"); assertNotNull(boot)
        assertEquals("::bootstrap::", str(bDec(b, boot!!)))

        // Full duplex, several rounds. Each call reloads state from the store,
        // proving the ratchet round-trips through persistence every single time.
        repeat(5) { i ->
            val aw = aEnc(a, "a$i")!!; assertEquals("a$i", str(bDec(b, aw)))
            val bw = bEnc(b, "b$i")!!; assertEquals("b$i", str(aDec(a, bw)))
        }
    }

    @Test
    fun bobSendsFirst_isBufferedUntilBootstrap() {
        val a = mgr(); val b = mgr()
        // Bob (responder) tries to send before receiving anything → not ready.
        assertNull(bEnc(b, "early"), "responder must report not-ready before bootstrap")
        assertTrue(!b.isBootstrapped(CID, CH, secret, bIn, bOut))
        assertTrue(a.isBootstrapped(CID, CH, secret, aIn, aOut), "initiator is always ready")

        // Alice bootstraps the channel; Bob receives it.
        val boot = aEnc(a, "hi")!!
        assertEquals("hi", str(bDec(b, boot)))

        // Now Bob's buffered message goes through.
        assertTrue(b.isBootstrapped(CID, CH, secret, bIn, bOut))
        val bw = bEnc(b, "early")!!
        assertEquals("early", str(aDec(a, bw)))
    }

    @Test
    fun outOfOrderDelivery_throughTheManager() {
        val a = mgr(); val b = mgr()
        val boot = aEnc(a, "boot")!!; bDec(b, boot)
        val m0 = aEnc(a, "m0")!!
        val m1 = aEnc(a, "m1")!!
        val m2 = aEnc(a, "m2")!!
        // Relay reorders: 2, 0, 1. The skipped-key cache (persisted each op) recovers.
        assertEquals("m2", str(bDec(b, m2)))
        assertEquals("m0", str(bDec(b, m0)))
        assertEquals("m1", str(bDec(b, m1)))
    }

    @Test
    fun textAndControlChannelsAreIndependentRatchets() {
        val a = mgr(); val b = mgr()
        // Same contact, two channels → two independent ratchet states in the store.
        val tBoot = a.tryEncrypt(CID, "text", secret, aIn, aOut, bytes("t"))!!
        val cBoot = a.tryEncrypt(CID, "ctl", secret, aIn, aOut, bytes("c"))!!
        assertEquals("t", str(b.decrypt(CID, "text", secret, bIn, bOut, tBoot)))
        assertEquals("c", str(b.decrypt(CID, "ctl", secret, bIn, bOut, cBoot)))
        // Continued independent traffic on each.
        val t1 = a.tryEncrypt(CID, "text", secret, aIn, aOut, bytes("t1"))!!
        assertEquals("t1", str(b.decrypt(CID, "text", secret, bIn, bOut, t1)))
    }

    @Test
    fun tamperedWireBlobIsRejected() {
        val a = mgr(); val b = mgr()
        val boot = aEnc(a, "boot")!!; bDec(b, boot)
        val w = aEnc(a, "secret")!!
        w[w.size - 1] = (w[w.size - 1] + 1).toByte()
        assertFailsWith<RatchetException> { bDec(b, w) }
    }

    @Test
    fun forwardSecrecy_replayedBlobCannotReopen_throughTheManager() {
        val a = mgr(); val b = mgr()
        val boot = aEnc(a, "boot")!!; bDec(b, boot)
        val w0 = aEnc(a, "w0")!!; val w1 = aEnc(a, "w1")!!
        assertEquals("w0", str(bDec(b, w0)))
        assertEquals("w1", str(bDec(b, w1)))
        // A relay re-serving an already-consumed blob cannot be reopened from the
        // advanced, persisted state — forward secrecy survives the store round-trip.
        assertFailsWith<RatchetException> { bDec(b, w0) }
    }

    // --- decryptBatch (one ratchet load per poll) ------------

    private fun corrupt(w: ByteArray) = w.copyOf().also { it[it.size - 1] = (it[it.size - 1] + 1).toByte() }

    @Test
    fun decryptBatch_decryptsWholeSequence_andPersistsForLaterOps() {
        val a = mgr(); val b = mgr()
        val boot = aEnc(a, "boot")!!
        val wires = listOf(boot) + (0 until 5).map { aEnc(a, "m$it")!! }
        val results = b.decryptBatch(CID, CH, secret, bIn, bOut, wires)
        assertEquals(listOf("boot", "m0", "m1", "m2", "m3", "m4"), results.map { str(it!!) })
        // State was persisted once at the end: Bob can now send + a further Alice
        // message still decrypts through the store round-trip.
        val bw = bEnc(b, "reply")!!; assertEquals("reply", str(aDec(a, bw)))
        assertEquals("m5", str(bDec(b, aEnc(a, "m5")!!)))
    }

    @Test
    fun decryptBatch_forgedBlob_isDropped_andDoesNotCorruptLaterRealBlobs() {
        val a = mgr(); val b = mgr()
        val boot = aEnc(a, "boot")!!; bDec(b, boot)
        val m0 = aEnc(a, "m0")!!
        val m1 = aEnc(a, "m1")!!
        // A forged blob carrying m1's header but a corrupted tag: decrypt advances the
        // receiving chain (skip/derive) BEFORE the AEAD rejects it. Without rollback that
        // mutation would consume m1's chain key and the real m1 would then be lost.
        val results = b.decryptBatch(CID, CH, secret, bIn, bOut, listOf(m0, corrupt(m1), m1))
        assertEquals("m0", str(results[0]!!))
        assertNull(results[1], "forged blob must be dropped")
        assertEquals("m1", str(results[2]!!), "real m1 survives the forgery — the snapshot rollback worked")
    }

    @Test
    fun decryptBatch_allForged_dropsAll_andAdvancesNothing() {
        val a = mgr(); val b = mgr()
        val boot = aEnc(a, "boot")!!; bDec(b, boot)
        val m0 = aEnc(a, "m0")!!
        val forged = (0 until 8).map { corrupt(m0) }
        val results = b.decryptBatch(CID, CH, secret, bIn, bOut, forged)
        assertTrue(results.all { it == null }, "every forged blob dropped")
        // Nothing was persisted: the genuine m0 still decrypts afterward.
        assertEquals("m0", str(bDec(b, m0)))
    }

    @Test
    fun decryptBatch_toleratesMalformedAndTooShortWires() {
        val a = mgr(); val b = mgr()
        val boot = aEnc(a, "boot")!!; bDec(b, boot)
        val m0 = aEnc(a, "m0")!!
        val results = b.decryptBatch(CID, CH, secret, bIn, bOut,
            listOf(ByteArray(3), bytes("garbage-not-a-wire"), m0))
        assertNull(results[0]); assertNull(results[1])
        assertEquals("m0", str(results[2]!!))
    }

    // --- decryptBatchLocked characterisation (pins the order a split must keep) ---

    // R5: a malformed wire costs no crypto and is NEUTRAL for the consecutive-failure
    // cutoff: 7 forgeries + 1 malformed leave the run at 7, so the genuine wire behind
    // them still decrypts and nothing is reported not-processed.
    @Test
    fun decryptBatch_malformedWire_isNeutralForTheCutoff() {
        val a = mgr(); val b = mgr()
        val boot = aEnc(a, "boot")!!; bDec(b, boot)
        val m0 = aEnc(a, "m0")!!
        val wires = List(RatchetManager.MAX_CONSECUTIVE_FAILURES_PER_BATCH - 1) { corrupt(m0) } +
            listOf(ByteArray(3), m0)
        val report = RatchetManager.DecryptBatchReport()
        val results = b.decryptBatch(CID, CH, secret, bIn, bOut, wires, report = report)
        assertEquals("m0", str(results.last()!!), "a neutral malformed wire must not trip the cutoff")
        assertTrue(report.notProcessed.isEmpty(), "nothing is past a cutoff: ${report.notProcessed}")
    }

    // R7 (persist mode): the drain saves the ratchet exactly once when something
    // decrypted, and not at all when nothing did.
    @Test
    fun decryptBatch_persistMode_savesExactlyOnce_iffSomethingAdvanced() {
        val sb = SpyStore()
        val a = mgr(); val b = RatchetManager(sb)
        b.decrypt(CID, CH, secret, bIn, bOut, aEnc(a, "boot")!!)
        val m0 = aEnc(a, "m0")!!; val m1 = aEnc(a, "m1")!!
        val before = sb.saves
        b.decryptBatch(CID, CH, secret, bIn, bOut, listOf(corrupt(m0), corrupt(m1)))
        assertEquals(before, sb.saves, "an all-refused drain persists nothing")
        val results = b.decryptBatch(CID, CH, secret, bIn, bOut, listOf(m0, m1))
        assertEquals(listOf("m0", "m1"), results.map { str(it!!) })
        assertEquals(before + 1, sb.saves, "one save for the whole drain")
    }

    // R1 (rule 3): a PERSISTING drain while a screen drain's advance is uncommitted
    // loads nothing, writes nothing, reports every wire not-processed — and the
    // uncommitted head still commits afterwards.
    @Test
    fun decryptBatch_rule3_persistingDrainOverAnUncommittedAdvance_touchesNothing_andTheHeadStillCommits() {
        val sb = SpyStore()
        val a = mgr(); val b = RatchetManager(sb)
        b.decrypt(CID, CH, secret, bIn, bOut, aEnc(a, "boot")!!)
        val m0 = aEnc(a, "m0")!!; val m1 = aEnc(a, "m1")!!
        val screen = RatchetManager.DecryptBatchReport()
        val shown = b.decryptBatch(CID, CH, secret, bIn, bOut, listOf(m0), report = screen, persist = false, drainGroup = Any())
        assertEquals("m0", str(shown.single()!!))
        val head = screen.pendingTicket
        assertTrue(head != null, "precondition: the screen drain holds an uncommitted advance")
        val loads = sb.loadedBlobs.size; val saves = sb.saves
        val sweep = RatchetManager.DecryptBatchReport()
        val blocked = b.decryptBatch(CID, CH, secret, bIn, bOut, listOf(m1), report = sweep)
        assertTrue(blocked.all { it == null })
        assertEquals(setOf(0), sweep.notProcessed.toSet(), "rule 3: every wire is left for the next drain")
        assertEquals(loads, sb.loadedBlobs.size, "rule 3 loads nothing")
        assertEquals(saves, sb.saves, "rule 3 writes nothing")
        assertTrue(b.commitPending(head!!), "the uncommitted head still commits")
        assertEquals("m1", str(b.decryptBatch(CID, CH, secret, bIn, bOut, listOf(m1)).single()!!))
    }

    // --- Loaded ratchet-state blob is zeroized -----

    /** Every plaintext ratchet-state blob loaded from the store must be fill(0)'d once
     *  the encrypt/decrypt op that deserialized it has finished — on both sides, across
     *  the send AND receive paths. (The first op on a fresh store inits without a load;
     *  subsequent ops load the persisted state → that transient copy must be wiped.) */
    @Test
    fun everyLoadedRatchetStateBlobIsZeroed_acrossEncryptAndDecrypt() {
        val sa = SpyStore(); val sb = SpyStore()
        val a = RatchetManager(sa); val b = RatchetManager(sb)
        val boot = a.tryEncrypt(CID, CH, secret, aIn, aOut, bytes("boot"))!!
        b.decrypt(CID, CH, secret, bIn, bOut, boot)
        repeat(3) { i ->
            val aw = a.tryEncrypt(CID, CH, secret, aIn, aOut, bytes("a$i"))!!  // Alice loads
            assertEquals("a$i", str(b.decrypt(CID, CH, secret, bIn, bOut, aw)))  // Bob loads
            val bw = b.tryEncrypt(CID, CH, secret, bIn, bOut, bytes("b$i"))!!  // Bob loads
            assertEquals("b$i", str(a.decrypt(CID, CH, secret, aIn, aOut, bw)))  // Alice loads
        }
        val all = sa.loadedBlobs + sb.loadedBlobs
        assertTrue(all.isNotEmpty(), "ops after the first must have loaded persisted state")
        assertTrue(all.all { blob -> blob.all { it == 0.toByte() } },
            "every transient ratchet-state blob loaded from the store must be zeroized after its op")
    }

    /** decryptBatch loads the ratchet once for the whole drain — that single transient
     *  blob must also be zeroized when the batch returns. */
    @Test
    fun decryptBatch_zeroesLoadedRatchetStateBlob() {
        val sb = SpyStore()
        val a = mgr(); val b = RatchetManager(sb)
        val boot = aEnc(a, "boot")!!
        b.decrypt(CID, CH, secret, bIn, bOut, boot)   // Bob inits + persists (load returns null)
        sb.loadedBlobs.clear()                         // ignore the init op — it did not load
        val wires = (0 until 4).map { aEnc(a, "m$it")!! }
        val results = b.decryptBatch(CID, CH, secret, bIn, bOut, wires)
        assertEquals(listOf("m0", "m1", "m2", "m3"), results.map { str(it!!) })
        assertTrue(sb.loadedBlobs.isNotEmpty(), "decryptBatch must have loaded persisted state")
        assertTrue(sb.loadedBlobs.all { blob -> blob.all { it == 0.toByte() } },
            "decryptBatch's loaded ratchet-state blob must be zeroized after the drain")
    }

    // --- Drop-site zeroization -------------
    //
    // Every ratchet op deserializes a DoubleRatchet, mutates it, persists it and
    // drops it. Before the wipe the dropped object kept the root key, the DH private
    // key, both chain keys and up to MAX_SKIPPED_STORE skipped message keys live in
    // freed heap — and hasRatchetedPastBootstrap runs on EVERY non-control poll
    // (~1 Hz with a conversation open), so one session scattered hundreds of copies.
    // The fix wipes at the drop sites, in a `finally` that runs strictly AFTER the
    // persist. These tests lock BOTH halves: that wipe() really covers every secret
    // field, and that it can never run before the persist.

    // Serialized layout (see DoubleRatchet.serialize):
    //   ver(1) ‖ flags(1) ‖ root(32) ‖ dhSelfPriv(32) ‖ dhSelfPub(32) ‖
    //   [dhRemotePub(32)] ‖ [sendChain(32)] ‖ [recvChain(32)] ‖ sN(4) ‖ rN(4) ‖
    //   pN(4) ‖ skCount(4) ‖ skipped… ‖ dhRecvSteps(4)
    // flags: 0x1 dhRemotePub present, 0x2 sendChain present, 0x4 recvChain present.

    /** Byte offset of the skipped-key count in a serialized ratchet, plus its value. */
    private fun skippedCount(blob: ByteArray): Int {
        val flags = blob[1].toInt() and 0xFF
        var o = 98
        if (flags and 0x1 != 0) o += 32
        if (flags and 0x2 != 0) o += 32
        if (flags and 0x4 != 0) o += 32
        o += 12   // sendN, recvN, prevSendN
        return ((blob[o].toInt() and 0xFF) shl 24) or ((blob[o + 1].toInt() and 0xFF) shl 16) or
            ((blob[o + 2].toInt() and 0xFF) shl 8) or (blob[o + 3].toInt() and 0xFF)
    }

    /** Asserts that every SECRET region of a serialized ratchet is ([zeroed]) or is not
     *  all-zero. The public halves (dhSelfPub / dhRemotePub) are skipped — wipe()
     *  deliberately leaves them, and the object is discarded anyway. */
    private fun assertSecretKeysZeroed(blob: ByteArray, zeroed: Boolean) {
        fun allZero(from: Int, len: Int) = (from until from + len).all { blob[it] == 0.toByte() }
        val flags = blob[1].toInt() and 0xFF
        assertEquals(zeroed, allZero(2, 32), "root key")
        assertEquals(zeroed, allZero(34, 32), "DH private key")
        var o = 98
        if (flags and 0x1 != 0) o += 32   // dhRemotePub — PUBLIC, deliberately kept
        if (flags and 0x2 != 0) { assertEquals(zeroed, allZero(o, 32), "sending chain key"); o += 32 }
        if (flags and 0x4 != 0) { assertEquals(zeroed, allZero(o, 32), "receiving chain key"); o += 32 }
    }

    /** The contract the drop-site wipes depend on: DoubleRatchet.wipe() must zero the
     *  root key, the DH private key, BOTH chain keys and the skipped-key cache — every
     *  secret the object holds. Public halves stay (they are not secret and the object
     *  is discarded anyway). Proven through serialize(), which reads the real fields. */
    @Test
    fun doubleRatchetWipe_zeroesEverySecretField() {
        val a = DoubleRatchet.initAsAlice(secret)
        val b = DoubleRatchet.initAsBob(secret)
        // Deliver only Alice's SECOND message: Bob performs a DH step (→ remote pub +
        // both chains) and caches a skipped key for the undelivered first, so every
        // secret field is populated before the wipe.
        a.encrypt(bytes("m0"))
        val m1 = a.encrypt(bytes("m1"))
        b.decrypt(m1.header, m1.ciphertext)

        val before = b.serialize()
        assertEquals(0x7, before[1].toInt() and 0xFF, "fixture must populate remote pub + both chains")
        assertEquals(1, skippedCount(before), "fixture must cache a skipped message key")
        assertSecretKeysZeroed(before, zeroed = false)

        b.wipe()
        val after = b.serialize()
        assertSecretKeysZeroed(after, zeroed = true)
        assertEquals(0, skippedCount(after), "skipped-key cache must be cleared")
    }

    /** Every RatchetManager op wipes the transient ratchet it built — but only AFTER
     *  persist(). A wipe-before-persist regression would serialize all-zero key material
     *  into the store and break the very next op, so this drives all five ops (tryEncrypt,
     *  decrypt, decryptBatch, isBootstrapped, hasRatchetedPastBootstrap) interleaved and
     *  then checks the store directly: the persisted root key must be NON-zero, and a
     *  FRESH manager over the same store must continue the conversation. */
    @Test
    fun everyOpWipesItsRatchetOnlyAfterPersist_soPersistedStateStaysUsable() {
        val sa = SpyStore(); val sb = SpyStore()
        val a = RatchetManager(sa); val b = RatchetManager(sb)

        val boot = a.tryEncrypt(CID, CH, secret, aIn, aOut, bytes("boot"))!!
        assertEquals("boot", str(b.decrypt(CID, CH, secret, bIn, bOut, boot)))
        // The two pure probes now wipe the ratchet they load — neither may damage state.
        assertTrue(a.isBootstrapped(CID, CH, secret, aIn, aOut))
        assertTrue(b.isBootstrapped(CID, CH, secret, bIn, bOut))
        b.hasRatchetedPastBootstrap(CID, CH)

        repeat(3) { i ->
            val aw = a.tryEncrypt(CID, CH, secret, aIn, aOut, bytes("a$i"))!!
            assertEquals("a$i", str(b.decrypt(CID, CH, secret, bIn, bOut, aw)))
            b.hasRatchetedPastBootstrap(CID, CH)          // the ~1 Hz poll probe
            val bw = b.tryEncrypt(CID, CH, secret, bIn, bOut, bytes("b$i"))!!
            assertEquals("b$i", str(a.decrypt(CID, CH, secret, aIn, aOut, bw)))
        }
        // The drain path persists once at the end of the batch; its wipe must follow.
        val wires = (0 until 3).map { a.tryEncrypt(CID, CH, secret, aIn, aOut, bytes("d$it"))!! }
        assertEquals(
            listOf("d0", "d1", "d2"),
            b.decryptBatch(CID, CH, secret, bIn, bOut, wires).map { str(it!!) },
        )

        // Direct ordering proof: what actually reached the store still carries live key
        // material. (A wipe before persist would have written 32 zero bytes here.)
        assertSecretKeysZeroed(sb.lastSaved!!, zeroed = false)
        assertSecretKeysZeroed(sa.lastSaved!!, zeroed = false)
        // …and the at-rest state is genuinely usable from a brand-new manager instance.
        val b2 = RatchetManager(sb)
        val later = a.tryEncrypt(CID, CH, secret, aIn, aOut, bytes("later"))!!
        assertEquals("later", str(b2.decrypt(CID, CH, secret, bIn, bOut, later)))
        // Every transient blob the store handed out was zeroized (still holds).
        assertTrue((sa.loadedBlobs + sb.loadedBlobs).all { blob -> blob.all { it == 0.toByte() } })
    }

    /** hasRatchetedPastBootstrap is the hottest drop site (MessageManager.maybeArmRecvLock
     *  calls it on every non-control poll). Hammer it: the answer must stay stable, the
     *  persisted state must survive, and every blob it loaded must come back zeroized. */
    @Test
    fun hasRatchetedPastBootstrapProbe_isRepeatable_andLeavesStateIntact() {
        val a = mgr(); val sb = SpyStore(); val b = RatchetManager(sb)
        val boot = aEnc(a, "boot")!!
        assertEquals("boot", str(b.decrypt(CID, CH, secret, bIn, bOut, boot)))
        // One receiving DH step so far → still inside the bootstrap window.
        repeat(20) { assertTrue(!b.hasRatchetedPastBootstrap(CID, CH)) }
        // A second Alice→Bob DH step (Bob replies, Alice sends again) crosses the gate.
        val bw = b.tryEncrypt(CID, CH, secret, bIn, bOut, bytes("reply"))!!
        assertEquals("reply", str(aDec(a, bw)))
        val a2 = aEnc(a, "again")!!
        assertEquals("again", str(b.decrypt(CID, CH, secret, bIn, bOut, a2)))
        repeat(50) { assertTrue(b.hasRatchetedPastBootstrap(CID, CH)) }
        // The probe never persists, so the state must be byte-identical afterwards and
        // the conversation must continue.
        assertEquals("m", str(b.decrypt(CID, CH, secret, bIn, bOut, aEnc(a, "m")!!)))
        assertTrue(sb.loadedBlobs.isNotEmpty())
        assertTrue(sb.loadedBlobs.all { blob -> blob.all { it == 0.toByte() } },
            "every blob the probe loaded must be zeroized")
    }

    // --- Skipped-key age-out through the manager -----
    //
    // The manager is stateless between calls, so every op re-loads the persisted
    // ratchet — which is exactly where the age-out is evaluated. These drive the
    // 24 h window through the store round-trip via the clockMs seam (production
    // never sets it), because that is the path the vault actually takes.

    private val T0 = 1_700_000_000_000L

    /** A manager whose clock the test drives. */
    private fun clockedMgr(store: RatchetStore, now: () -> Long) =
        RatchetManager(store).also { it.clockMs = now }

    @Test
    fun delayedBlobInsideTheWindow_stillDecrypts_throughTheStore() {
        var now = T0
        val a = mgr(); val b = clockedMgr(MapStore()) { now }
        val boot = aEnc(a, "boot")!!
        assertEquals("boot", str(b.decrypt(CID, CH, secret, bIn, bOut, boot)))
        val m0 = aEnc(a, "m0")!!
        val m1 = aEnc(a, "m1")!!
        assertEquals("m1", str(b.decrypt(CID, CH, secret, bIn, bOut, m1)))   // caches m0's key

        // Ordinary Tor reordering, hours later but inside the window: no message lost.
        now = T0 + DoubleRatchet.SKIPPED_KEY_TTL_MS - 1
        assertEquals("m0", str(b.decrypt(CID, CH, secret, bIn, bOut, m0)))
    }

    @Test
    fun withheldBlobPastTheWindow_isNoLongerDecryptable_andTheChannelKeepsWorking() {
        var now = T0
        val a = mgr(); val b = clockedMgr(MapStore()) { now }
        val boot = aEnc(a, "boot")!!
        assertEquals("boot", str(b.decrypt(CID, CH, secret, bIn, bOut, boot)))
        val m0 = aEnc(a, "m0")!!
        val m1 = aEnc(a, "m1")!!
        assertEquals("m1", str(b.decrypt(CID, CH, secret, bIn, bOut, m1)))

        // A relay that withheld m0 for a day gains nothing from a later vault seizure:
        // the cached key is gone (dropped + zeroed on the next load).
        now = T0 + DoubleRatchet.SKIPPED_KEY_TTL_MS
        assertFailsWith<RatchetException> { b.decrypt(CID, CH, secret, bIn, bOut, m0) }
        assertNull(
            b.decryptBatch(CID, CH, secret, bIn, bOut, listOf(m0)).single(),
            "the drain path must drop it too, not throw out of the batch",
        )
        // Expiry is never a brick: the live conversation continues in both directions.
        assertEquals("m2", str(b.decrypt(CID, CH, secret, bIn, bOut, aEnc(a, "m2")!!)))
        val reply = b.tryEncrypt(CID, CH, secret, bIn, bOut, bytes("reply"))!!
        assertEquals("reply", str(aDec(a, reply)))
    }

    /**
     * The point of the age-out is that the key leaves the VAULT, not merely RAM. Any
     * op that loads the ratchet must write the pruned state back, or a pairing that
     * goes silent right after the expiry would keep the dead keys at rest.
     * (`skippedCount` reads the persisted blob directly — see the layout note above.)
     */
    @Test
    fun expiredSkippedKeys_areWrittenOutOfTheSTORE_notJustDroppedFromRam() {
        var now = T0
        val store = SpyStore()
        val a = mgr(); val b = clockedMgr(store) { now }
        val boot = aEnc(a, "boot")!!
        assertEquals("boot", str(b.decrypt(CID, CH, secret, bIn, bOut, boot)))
        aEnc(a, "m0")   // withheld by the relay → its key is cached
        val m1 = aEnc(a, "m1")!!
        assertEquals("m1", str(b.decrypt(CID, CH, secret, bIn, bOut, m1)))
        assertEquals(1, skippedCount(store.lastSaved!!), "precondition: one key cached at rest")

        now = T0 + DoubleRatchet.SKIPPED_KEY_TTL_MS
        b.isBootstrapped(CID, CH, secret, bIn, bOut)   // any load-bearing op
        assertEquals(0, skippedCount(store.lastSaved!!),
            "an expired skipped key must be persisted AWAY, not just pruned in RAM")
    }

    // --- scrubInMemory teardown hook ----------

    /** RatchetManager is STATELESS between calls (load→mutate→persist→drop under the
     *  lock), so it retains NO live ratchet for scrubInMemory() to zero — and since the drop-site wipe
     *  each op zeroes its own transient DoubleRatchet in a finally after persist, so
     *  there is genuinely nothing left resident by the time the hook runs. What the hook
     *  guarantees, and what this asserts, is that it is safe + idempotent on both roles,
     *  FENCES any in-flight op (it can only be entered once that op has persisted and
     *  wiped), and never corrupts the persisted state — so the platform lock/panic-wipe
     *  paths can call it uniformly (parity with GroupManager/ReferralManager). */
    @Test
    fun scrubInMemory_isIdempotent_andDoesNotCorruptPersistedState() {
        val a = mgr(); val b = mgr()
        val boot = aEnc(a, "boot")!!; assertEquals("boot", str(bDec(b, boot)))
        a.scrubInMemory(); a.scrubInMemory(); b.scrubInMemory()   // idempotent, both roles
        // The store round-trip still works after the hook — nothing retained was corrupted.
        repeat(3) { i ->
            val aw = aEnc(a, "a$i")!!; assertEquals("a$i", str(bDec(b, aw)))
            b.scrubInMemory()
            val bw = bEnc(b, "b$i")!!; assertEquals("b$i", str(aDec(a, bw)))
        }
    }

    /** The wipe must not corrupt the AT-REST state: a fresh manager over the same store
     *  still decrypts the messages produced above (the store holds an independent copy). */
    @Test
    fun wipingLoadedBlob_doesNotCorruptPersistedState() {
        val sa = SpyStore()
        val a = RatchetManager(sa)
        val boot = a.tryEncrypt(CID, CH, secret, aIn, aOut, bytes("boot"))!!
        val w1 = a.tryEncrypt(CID, CH, secret, aIn, aOut, bytes("m1"))!!  // loads + wipes the blob
        assertTrue(sa.loadedBlobs.isNotEmpty())
        val b = mgr()
        assertEquals("boot", str(b.decrypt(CID, CH, secret, bIn, bOut, boot)))
        assertEquals("m1", str(b.decrypt(CID, CH, secret, bIn, bOut, w1)))
    }

    // --- The drain is budgeted ----------------
    //
    // A 72-byte RAT1 blob with a fresh random dhPub and n = MAX_SKIP used to buy
    // ~1024 HMAC + 2 ECDH + 1 keypair generation from an unauthenticated sender, and
    // decryptBatch rolled the state back after every rejection, so each of up to
    // MAX_BLOBS_PER_POLL blobs repeated the whole price under the process-wide lock.
    // Two bounds now: a per-drain RatchetWorkBudget (charges refunded by every blob
    // that authenticates) and a consecutive-failure cutoff. The tests that matter
    // most are the ones proving honest traffic is untouched.

    /** An attacker's wire blob: a fresh (never-seen) ratchet key forces a DH step. */
    private fun forgedNewKeyWire(n: Int = 0, pn: Int = 0) =
        RatchetHeader(generateSecureRandom(32), pn = pn, n = n).encode() + generateSecureRandom(28)

    @Test
    fun decryptBatch_honestBacklogOfSixHundred_decryptsEveryMessage() {
        // A week offline, then one drain. Nothing here fails, so neither bound can
        // engage: the cutoff counter never leaves 0 and every charge is refunded.
        val a = mgr(); val b = mgr()
        val budget = RatchetWorkBudget()
        b.workBudgetFactory = { budget }
        val boot = aEnc(a, "boot")!!
        val wires = listOf(boot) + (0 until 599).map { aEnc(a, "m$it")!! }
        val results = b.decryptBatch(CID, CH, secret, bIn, bOut, wires)
        assertEquals(600, results.size)
        assertEquals(600, results.count { it != null }, "a legitimate backlog must decrypt in full")
        assertEquals("boot", str(results.first()!!))
        assertEquals("m598", str(results.last()!!))
        assertEquals(0, budget.spentDhSteps(), "authenticated work must be refunded")
        assertEquals(0, budget.spentChainDerivations())
        // The drain persisted: the conversation continues in both directions.
        assertEquals("after", str(bDec(b, aEnc(a, "after")!!)))
        assertEquals("reply", str(aDec(a, bEnc(b, "reply")!!)))
    }

    @Test
    fun decryptBatch_sixHundredMessagesAcrossSixtyDhSteps_allDecrypt() {
        // The same 600 messages, but spread over 60 direction changes — i.e. 60
        // receiving DH ratchet steps, one per drain. (One per drain is not a test
        // artefact: the peer's ratchet key only changes when the peer RECEIVES from
        // us, and ours only changes when we decrypt a new peer key, so a device that
        // is not draining can be ratcheted at most once.)
        val a = mgr(); val b = mgr()
        val budget = RatchetWorkBudget()
        b.workBudgetFactory = { budget }
        assertEquals("boot", str(bDec(b, aEnc(a, "boot")!!)))
        var decrypted = 0
        repeat(60) { r ->
            // Bob replies; Alice ratchets on receiving it, so her next batch carries a
            // NEW ratchet key and Bob's drain below contains a DH step.
            assertEquals("r$r", str(aDec(a, bEnc(b, "r$r")!!)))
            val wires = (0 until 10).map { aEnc(a, "m$r-$it")!! }
            val results = b.decryptBatch(CID, CH, secret, bIn, bOut, wires)
            assertEquals(10, results.count { it != null }, "round $r must decrypt in full")
            assertEquals("m$r-9", str(results.last()!!))
            decrypted += results.count { it != null }
        }
        assertEquals(600, decrypted)
        assertEquals(0, budget.spentDhSteps(), "60 legitimate DH steps must cost the budget nothing")
    }

    @Test
    fun decryptBatch_outOfOrderHonestDrain_isUnaffectedByTheBudget() {
        // Worst realistic Tor reordering: newest first, so the first blob legitimately
        // skips 99 message keys. Every blob still authenticates ⇒ nothing is charged.
        val a = mgr(); val b = mgr()
        val budget = RatchetWorkBudget()
        b.workBudgetFactory = { budget }
        val boot = aEnc(a, "boot")!!; bDec(b, boot)
        val wires = (0 until 100).map { aEnc(a, "m$it")!! }
        val results = b.decryptBatch(CID, CH, secret, bIn, bOut, wires.reversed())
        assertEquals(100, results.count { it != null }, "reordering must not lose a message")
        assertEquals(0, budget.spentChainDerivations(), "a successful skip burst is refunded")
    }

    @Test
    fun decryptBatch_consecutiveFailureCutoff_stopsTheDrain_withoutDamagingState() {
        val a = mgr(); val b = mgr()
        val boot = aEnc(a, "boot")!!; bDec(b, boot)
        val m0 = aEnc(a, "m0")!!
        val junk = (0 until RatchetManager.MAX_CONSECUTIVE_FAILURES_PER_BATCH).map { corrupt(m0) }
        val results = b.decryptBatch(CID, CH, secret, bIn, bOut, junk + listOf(m0))
        assertEquals(junk.size + 1, results.size, "one entry per wire, always")
        assertTrue(results.all { it == null },
            "the drain stops at the cutoff: the blob behind it is reported undecryptable")
        // Nothing advanced and nothing was persisted, so the state is exactly as it
        // was — a cutoff is never a corruption, and the same blob opens afterwards.
        assertEquals("m0", str(bDec(b, m0)))
    }

    @Test
    fun decryptBatch_aSuccessResetsTheCutoffCounter() {
        val a = mgr(); val b = mgr()
        val boot = aEnc(a, "boot")!!; bDec(b, boot)
        val m0 = aEnc(a, "m0")!!; val m1 = aEnc(a, "m1")!!
        val k = RatchetManager.MAX_CONSECUTIVE_FAILURES_PER_BATCH - 1
        val wires = (0 until k).map { corrupt(m0) } + listOf(m0) +
            (0 until k).map { corrupt(m1) } + listOf(m1)
        val results = b.decryptBatch(CID, CH, secret, bIn, bOut, wires)
        assertEquals("m0", str(results[k]!!))
        assertEquals("m1", str(results.last()!!),
            "a real blob resets the run, so junk in front of it never ends the drain")
        assertEquals(2, results.count { it != null })
    }

    @Test
    fun decryptBatch_interleavedJunk_stopsPayingForDhSteps_whileRealBlobsStillDecrypt() {
        // A hostile relay can interleave the peer's REAL blobs with junk, which resets
        // the cutoff on every real one. The aggregate budget is what bounds that case:
        // past the ceiling each further forgery is refused before any crypto runs.
        val a = mgr(); val b = mgr()
        val budget = RatchetWorkBudget()
        b.workBudgetFactory = { budget }
        val boot = aEnc(a, "boot")!!; bDec(b, boot)
        val wires = mutableListOf<ByteArray>()
        val expected = mutableListOf<String>()
        repeat(20) { r ->
            repeat(4) { wires.add(forgedNewKeyWire(n = DoubleRatchet.MAX_SKIP)) }
            wires.add(aEnc(a, "m$r")!!); expected.add("m$r")
        }
        val results = b.decryptBatch(CID, CH, secret, bIn, bOut, wires)
        assertEquals(expected, results.filterNotNull().map { str(it) },
            "every real blob must still decrypt with junk interleaved")
        assertEquals(RatchetWorkBudget.MAX_FAILED_DH_STEPS, budget.spentDhSteps(),
            "80 forged ratchet keys must not buy more DH steps than the ceiling")
        assertTrue(budget.spentChainDerivations() <= RatchetWorkBudget.MAX_FAILED_CHAIN_DERIVATIONS)
    }

    @Test
    fun decryptBatch_junkFlood_isBoundedAndLeavesTheRatchetUsable() {
        // The shape: MAX_BLOBS_PER_POLL-scale junk on the control/text inbox.
        val a = mgr(); val b = mgr()
        val budget = RatchetWorkBudget()
        b.workBudgetFactory = { budget }
        val boot = aEnc(a, "boot")!!; bDec(b, boot)
        val flood = (0 until 2048).map { forgedNewKeyWire(n = DoubleRatchet.MAX_SKIP, pn = DoubleRatchet.MAX_SKIP) }
        val results = b.decryptBatch(CID, CH, secret, bIn, bOut, flood)
        assertEquals(2048, results.size)
        assertTrue(results.all { it == null }, "not one forgery may decrypt")
        assertTrue(budget.spentDhSteps() <= RatchetWorkBudget.MAX_FAILED_DH_STEPS,
            "DH steps spent: ${budget.spentDhSteps()}")
        assertTrue(budget.spentChainDerivations() <= RatchetWorkBudget.MAX_FAILED_CHAIN_DERIVATIONS,
            "derivations spent: ${budget.spentChainDerivations()}")
        // Nothing persisted, nothing poisoned: the peer's next real message opens.
        assertEquals("m0", str(bDec(b, aEnc(a, "m0")!!)))
    }

    @Test
    fun decryptBatch_junkFlood_doesNotBlockTheNextHonestDrain() {
        // The budget and the cutoff are strictly PER DRAIN — an attacker must not be
        // able to spend one drain's allowance and have the next drain inherit it.
        val a = mgr(); val b = mgr()
        val boot = aEnc(a, "boot")!!; bDec(b, boot)
        repeat(3) {
            b.decryptBatch(CID, CH, secret, bIn, bOut, (0 until 50).map { forgedNewKeyWire() })
            val wires = (0 until 20).map { aEnc(a, "x$it")!! }
            assertEquals(20, b.decryptBatch(CID, CH, secret, bIn, bOut, wires).count { it != null })
        }
    }

}

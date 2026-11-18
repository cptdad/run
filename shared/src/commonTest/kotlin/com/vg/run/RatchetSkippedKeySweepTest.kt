package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// The unlock-time skipped-key sweep (plan G1, docs/ratchet-bootstrap-plan.md §5).
// RatchetManager.sweepExpiredSkippedKeys must take EXPIRED skipped message keys out
// of the STORE for a conversation that went quiet — with no ratchet operation —
// and must otherwise leave the store alone: no write when nothing expired, no
// fresh init for an absent blob, no corrupt-state callback for an undecodable one,
// nothing under a live uncommitted advance.
// ---------------------------------------------------------------------------
class RatchetSkippedKeySweepTest {

    /** Store double: fresh copy per load (as VaultRatchetStore), counts saves, keeps every
     *  array it handed out so a test can check the sweep zeroed its transient copies. */
    private class SpyStore : RatchetStore {
        val m = mutableMapOf<String, ByteArray>()
        val loaded = mutableListOf<ByteArray>()
        var saves = 0
        val throwOnLoadFor = mutableSetOf<String>()
        override fun load(contactId: String, channel: String): ByteArray? {
            if (contactId in throwOnLoadFor) throw IllegalStateException("read failed")
            return m["$contactId/$channel"]?.copyOf()?.also { loaded.add(it) }
        }
        override fun save(contactId: String, channel: String, blob: ByteArray) {
            saves++
            m["$contactId/$channel"] = blob.copyOf()
        }
        fun raw(contactId: String, channel: String): ByteArray? = m["$contactId/$channel"]?.copyOf()
    }

    private val secret = generateSecureRandom(32)
    // A = initiator (Alice): inbound "bbb" > outbound "aaa". B = responder (Bob).
    private val aIn = "bbb"; private val aOut = "aaa"
    private val bIn = "aaa"; private val bOut = "bbb"
    private val ch = "text"
    private val cid = "contact-1"
    private val t0 = 1_700_000_000_000L
    private val ttl = DoubleRatchet.SKIPPED_KEY_TTL_MS

    private var clock = t0

    private fun bytes(s: String) = s.encodeToByteArray()
    private fun str(b: ByteArray) = b.decodeToString()

    /** How many skipped keys the STORED blob holds, read at [atMs] (≤ t0 so nothing is pruned by the read). */
    private fun storedSkipped(store: SpyStore, contactId: String = cid, atMs: Long = t0): Int {
        val blob = store.raw(contactId, ch)!!
        val r = DoubleRatchet.deserialize(blob, nowMs = { atMs })
        return r.skippedKeyCount().also { r.wipe() }
    }

    private class Fixture(val alice: RatchetManager, val bob: RatchetManager, val bobStore: SpyStore, val withheld: ByteArray)

    /**
     * Alice sends m0 and m1; the relay withholds m0, so Bob's committed state caches
     * one skipped key stamped at [t0]. Bob's manager runs on [clock].
     */
    private fun quietConversationWithOneSkippedKey(onCorrupt: (String, String) -> Unit = { _, _ -> }): Fixture {
        val alice = RatchetManager(SpyStore())
        val bobStore = SpyStore()
        val bob = RatchetManager(bobStore, onCorruptReinit = onCorrupt).also { it.clockMs = { clock } }
        val m0 = alice.tryEncrypt(cid, ch, secret, aIn, aOut, bytes("m0"))!!
        val m1 = alice.tryEncrypt(cid, ch, secret, aIn, aOut, bytes("m1"))!!
        assertEquals("m1", str(bob.decrypt(cid, ch, secret, bIn, bOut, m1)))
        assertEquals(1, storedSkipped(bobStore), "precondition: one skipped key at rest")
        return Fixture(alice, bob, bobStore, m0)
    }

    @Test
    fun expiredSkippedKey_isRemovedFromTheStore_withoutAnyRatchetOperation() {
        val f = quietConversationWithOneSkippedKey()
        val savesBefore = f.bobStore.saves
        f.bobStore.loaded.clear()

        clock = t0 + ttl
        val result = f.bob.sweepExpiredSkippedKeys(listOf(cid), ch)

        assertEquals(1, result.rewritten)
        assertEquals(savesBefore + 1, f.bobStore.saves, "exactly one write")
        // Read the stored blob at t0: if the key were still on disk it would load.
        assertEquals(0, storedSkipped(f.bobStore), "the expired key must be gone from the STORE, not just from RAM")
        assertTrue(f.bobStore.loaded.isNotEmpty())
        assertTrue(f.bobStore.loaded.all { b -> b.all { it == 0.toByte() } }, "every blob copy the sweep loaded is zeroed")

        // The withheld message is now undecryptable…
        assertFailsWith<Exception> { f.bob.decrypt(cid, ch, secret, bIn, bOut, f.withheld) }
        // …and the conversation itself carries on normally, both ways.
        val m2 = f.alice.tryEncrypt(cid, ch, secret, aIn, aOut, bytes("m2"))!!
        assertEquals("m2", str(f.bob.decrypt(cid, ch, secret, bIn, bOut, m2)))
        val reply = f.bob.tryEncrypt(cid, ch, secret, bIn, bOut, bytes("reply"))!!
        assertEquals("reply", str(f.alice.decrypt(cid, ch, secret, aIn, aOut, reply)))
    }

    @Test
    fun unexpiredSkippedKey_staysAndNothingIsWritten() {
        val f = quietConversationWithOneSkippedKey()
        val before = f.bobStore.raw(cid, ch)!!
        val savesBefore = f.bobStore.saves

        clock = t0 + ttl - 1
        val result = f.bob.sweepExpiredSkippedKeys(listOf(cid), ch)

        assertEquals(0, result.rewritten)
        assertEquals(savesBefore, f.bobStore.saves, "no persist when nothing expired")
        assertTrue(before.contentEquals(f.bobStore.raw(cid, ch)!!), "stored bytes unchanged")
        // The delayed message still opens — the cache did its job.
        assertEquals("m0", str(f.bob.decrypt(cid, ch, secret, bIn, bOut, f.withheld)))
    }

    @Test
    fun stateWithNoSkippedKeys_isNeverWritten() {
        val alice = RatchetManager(SpyStore())
        val bobStore = SpyStore()
        val bob = RatchetManager(bobStore).also { it.clockMs = { clock } }
        val m0 = alice.tryEncrypt(cid, ch, secret, aIn, aOut, bytes("m0"))!!
        assertEquals("m0", str(bob.decrypt(cid, ch, secret, bIn, bOut, m0)))
        val before = bobStore.raw(cid, ch)!!
        val savesBefore = bobStore.saves
        clock = t0 + ttl * 30
        assertEquals(0, bob.sweepExpiredSkippedKeys(listOf(cid), ch).rewritten)
        assertEquals(savesBefore, bobStore.saves)
        assertTrue(before.contentEquals(bobStore.raw(cid, ch)!!))
    }

    @Test
    fun absentBlob_isNeitherInitialisedNorWritten() {
        val store = SpyStore()
        var callbacks = 0
        val mgr = RatchetManager(store, onCorruptReinit = { _, _ -> callbacks++ })
        val result = mgr.sweepExpiredSkippedKeys(listOf("never-paired-1", "never-paired-2"), ch)
        assertEquals(0, result.rewritten)
        assertEquals(0, store.saves, "the sweep must never fresh-init a ratchet")
        assertNull(store.raw("never-paired-1", ch))
        assertEquals(0, callbacks)
    }

    @Test
    fun corruptBlob_isLeftUntouched_andTheCorruptStateCallbackNeverFires() {
        val store = SpyStore()
        var callbacks = 0
        val mgr = RatchetManager(store, onCorruptReinit = { _, _ -> callbacks++ })
        val garbage = ByteArray(77) { 7 }   // version byte 7: rejected by deserialize
        store.m["$cid/$ch"] = garbage.copyOf()
        clock = t0 + ttl * 2

        val result = mgr.sweepExpiredSkippedKeys(listOf(cid), ch)

        assertEquals(1, result.unreadable)
        assertEquals(0, result.rewritten)
        assertEquals(0, store.saves, "no write over an undecodable blob")
        assertTrue(garbage.contentEquals(store.raw(cid, ch)!!), "the stored bytes are exactly what they were")
        assertEquals(0, callbacks, "onCorruptReinit (which clears dr-rxlock / dr-on) must not run from the sweep")
    }

    @Test
    fun pendingUncommittedAdvance_isSkipped_andTheLaterCommitStillSucceeds() {
        val f = quietConversationWithOneSkippedKey()
        val m2 = f.alice.tryEncrypt(cid, ch, secret, aIn, aOut, bytes("m2"))!!

        // A conversation screen decrypts m2 WITHOUT persisting, one millisecond
        // before the cached key's window closes.
        clock = t0 + ttl - 1
        val report = RatchetManager.DecryptBatchReport()
        val out = f.bob.decryptBatch(
            cid, ch, secret, bIn, bOut, listOf(m2), report = report, persist = false, drainGroup = Any(),
        )
        assertEquals("m2", str(out.single()!!))
        val ticket = assertNotNull(report.pendingTicket)
        val before = f.bobStore.raw(cid, ch)!!
        val savesBefore = f.bobStore.saves

        // The window closes while the ticket is still live (2 ms old, far under the
        // pending-advance age bound). The sweep would prune — but must not write.
        clock = t0 + ttl + 1
        val result = f.bob.sweepExpiredSkippedKeys(listOf(cid), ch)
        assertEquals(1, result.heldByPendingAdvance)
        assertEquals(0, result.rewritten)
        assertEquals(savesBefore, f.bobStore.saves)
        assertTrue(before.contentEquals(f.bobStore.raw(cid, ch)!!))

        // The compare-and-swap commit still matches the store and lands.
        assertTrue(f.bob.commitPending(ticket), "the sweep must not have moved the store under the ticket")
        assertTrue(f.bob.isCommitted(ticket))

        // With the lineage gone, the next sweep takes the expired key out.
        assertEquals(1, f.bob.sweepExpiredSkippedKeys(listOf(cid), ch).rewritten)
        assertEquals(0, storedSkipped(f.bobStore))
        val m3 = f.alice.tryEncrypt(cid, ch, secret, aIn, aOut, bytes("m3"))!!
        assertEquals("m3", str(f.bob.decrypt(cid, ch, secret, bIn, bOut, m3)))
    }

    @Test
    fun legacyUnstampedSkippedKey_isMigratedSoItCanAgeOut() {
        val f = quietConversationWithOneSkippedKey()
        // The same state as written by the build before skipped-key stamps (SER_VERSION 2).
        f.bobStore.m["$cid/$ch"] = downgradeToV2(f.bobStore.raw(cid, ch)!!)
        assertEquals(2, f.bobStore.raw(cid, ch)!![0].toInt())

        // A v2 entry is stamped "now" at every load, so without a write it would never
        // expire. The sweep migrates it (one write, v3, stamped at this sweep)…
        clock = t0 + ttl * 5
        assertEquals(1, f.bob.sweepExpiredSkippedKeys(listOf(cid), ch).rewritten)
        assertEquals(3, f.bobStore.raw(cid, ch)!![0].toInt())
        assertEquals(1, storedSkipped(f.bobStore, atMs = clock), "migrated, not dropped: the key starts its window now")
        // …a sweep inside that window changes nothing…
        val savesMid = f.bobStore.saves
        clock += ttl - 1
        assertEquals(0, f.bob.sweepExpiredSkippedKeys(listOf(cid), ch).rewritten)
        assertEquals(savesMid, f.bobStore.saves)
        // …and the first sweep past it removes the key.
        clock += 1
        assertEquals(1, f.bob.sweepExpiredSkippedKeys(listOf(cid), ch).rewritten)
        assertEquals(0, storedSkipped(f.bobStore, atMs = t0))
    }

    @Test
    fun oneContactFailing_doesNotStopTheOthers() {
        val f = quietConversationWithOneSkippedKey()
        f.bobStore.throwOnLoadFor.add("broken")
        clock = t0 + ttl
        val result = f.bob.sweepExpiredSkippedKeys(listOf("broken", "absent", cid), ch)
        assertEquals(1, result.failed)
        assertEquals(1, result.rewritten)
        assertEquals(0, storedSkipped(f.bobStore))
    }

    @Test
    fun shouldContinueFalse_stopsBeforeAnyWrite() {
        val f = quietConversationWithOneSkippedKey()
        val savesBefore = f.bobStore.saves
        clock = t0 + ttl
        val result = f.bob.sweepExpiredSkippedKeys(listOf(cid), ch, shouldContinue = { false })
        assertTrue(result.stoppedEarly)
        assertEquals(0, result.rewritten)
        assertEquals(savesBefore, f.bobStore.saves)
        assertEquals(1, storedSkipped(f.bobStore))
    }

    @Test
    fun sessionEndingBetweenLoadAndWrite_stopsBeforeTheWrite() {
        // The first check (before the load) passes, the second (right before the write)
        // does not: the session ended while this contact was being swept. Nothing may be
        // written, and the stored state — expired key included — stays as it was.
        val f = quietConversationWithOneSkippedKey()
        val savesBefore = f.bobStore.saves
        val before = f.bobStore.raw(cid, ch)!!
        var checks = 0
        clock = t0 + ttl
        val result = f.bob.sweepExpiredSkippedKeys(listOf(cid), ch, shouldContinue = { ++checks < 2 })
        assertEquals(2, checks, "the stop condition is consulted again right before the write")
        assertTrue(result.stoppedEarly)
        assertEquals(0, result.rewritten)
        assertEquals(savesBefore, f.bobStore.saves)
        assertTrue(before.contentEquals(f.bobStore.raw(cid, ch)!!), "the stored state must be untouched")
    }

    @Test
    fun storeMovedBetweenReadAndWrite_isNotOverwritten() {
        // A second manager over the same vault (the transport-restart case) persisted in
        // between: the sweep's compare-and-swap must leave the newer state alone.
        val f = quietConversationWithOneSkippedKey()
        val other = byteArrayOf(9, 9, 9)
        var checks = 0
        clock = t0 + ttl
        val result = f.bob.sweepExpiredSkippedKeys(listOf(cid), ch, shouldContinue = {
            // The second check runs right before the write: simulate the other writer there.
            if (++checks == 2) f.bobStore.m["$cid/$ch"] = other.copyOf()
            true
        })
        assertEquals(0, result.rewritten)
        assertTrue(other.contentEquals(f.bobStore.raw(cid, ch)!!), "the newer state must survive")
    }

    // -- MessageManager entry point -------------------------------------------------

    @Test
    fun messageManagerSweep_coversEveryContactsTextRatchet_andCreatesNothing() {
        val vault = InMemoryVault()
        val now = currentTimeMillis()
        // Contact 1: a stored ratchet whose one skipped key was cached two days ago.
        val alice = DoubleRatchet.initAsAlice(secret)
        val bob = DoubleRatchet.initAsBob(secret, nowMs = { now - 2 * ttl })
        alice.encrypt(bytes("withheld"))
        val m1 = alice.encrypt(bytes("m1"))
        assertEquals("m1", str(bob.decrypt(m1.header, m1.ciphertext)))
        vault.insertContact(ContactRecord(contactId = "c1", sharedSecret = secret.copyOf(), trustLevel = 0, alias = "p", aliasLastRotated = 0))
        vault.putMeta(VaultRatchetStore.stateKey("c1", MessageManager.RATCHET_TEXT_CHANNEL), encodeBase64(bob.serialize()))
        // Contact 2: paired, no ratchet state yet.
        vault.insertContact(ContactRecord(contactId = "c2", sharedSecret = generateSecureRandom(32), trustLevel = 0, alias = "q", aliasLastRotated = 0))

        val mm = MessageManager(vault, "http://relay.test", InboxQueueRelay())
        assertEquals(1, mm.sweepExpiredSkippedKeys())

        val stored = decodeBase64(vault.getMeta(VaultRatchetStore.stateKey("c1", MessageManager.RATCHET_TEXT_CHANNEL))!!)
        assertEquals(0, DoubleRatchet.deserialize(stored, nowMs = { now - 2 * ttl }).skippedKeyCount())
        assertNull(vault.getMeta(VaultRatchetStore.stateKey("c2", MessageManager.RATCHET_TEXT_CHANNEL)), "no ratchet is created")
        assertFalse(vault.metaKeys().any { it.startsWith("dr-") }, "no ratchet marker is written or cleared")
    }

    // -- helpers ------------------------------------------------------------------

    private fun readIntBE(b: ByteArray, off: Int): Int =
        ((b[off].toInt() and 0xFF) shl 24) or ((b[off + 1].toInt() and 0xFF) shl 16) or
            ((b[off + 2].toInt() and 0xFF) shl 8) or (b[off + 3].toInt() and 0xFF)

    /** Same down-conversion as DoubleRatchetTest: drop the per-entry stamp, set version 2. */
    private fun downgradeToV2(v3: ByteArray): ByteArray {
        val flags = v3[1].toInt() and 0xFF
        var o = 98
        if (flags and 0x1 != 0) o += 32
        if (flags and 0x2 != 0) o += 32
        if (flags and 0x4 != 0) o += 32
        o += 12
        val count = readIntBE(v3, o); o += 4
        val out = ByteArray(o + count * 68 + 4)
        v3.copyInto(out, 0, 0, o)
        out[0] = 2
        var src = o; var dst = o
        repeat(count) {
            v3.copyInto(out, dst, src, src + 68)
            src += 76; dst += 68
        }
        v3.copyInto(out, dst, src, src + 4)
        return out
    }
}

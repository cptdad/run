package com.vg.run

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// RatchetManager's "no fresh init, ever" rule for v3 contacts
// (docs/ratchet-bootstrap-plan.md §3.5), at the ratchet layer:
//   - absent / unreadable state ⇒ RatchetStateUnavailableException, NOTHING written,
//     no callback, and the next operation retries;
//   - present but undecodable ⇒ only when byte-identical across CORRUPT_PROOF_READS
//     reads is it proven corrupt: onStateLost runs, RatchetStateLostException is
//     thrown — onCorruptReinit NEVER runs and the stored bytes are untouched;
//   - the legacy path (noFreshInit = false) is unchanged: it still inits / re-inits.
// ---------------------------------------------------------------------------
class RatchetV3NoInitTest {

    private class Store : RatchetStore {
        val blobs = mutableMapOf<String, ByteArray>()
        var saves = 0
        var loads = 0
        // Per-load override (index = load number from 1); returning null means absent.
        var loadHook: ((Int) -> ByteArray?)? = null
        var throwOnLoad = 0
        override fun load(contactId: String, channel: String): ByteArray? {
            loads++
            if (throwOnLoad > 0) { throwOnLoad--; throw RuntimeException("injected read error") }
            loadHook?.let { return it(loads)?.copyOf() }
            return blobs["$contactId/$channel"]?.copyOf()
        }
        override fun save(contactId: String, channel: String, blob: ByteArray) {
            saves++
            blobs["$contactId/$channel"] = blob.copyOf()
        }
    }

    private val cid = "c"
    private val ch = MessageManager.RATCHET_TEXT_CHANNEL
    private val ss = ByteArray(32) { 7 }

    private class Calls { var reinit = 0; var lost = 0 }

    private fun manager(store: Store, calls: Calls) = RatchetManager(
        store,
        onCorruptReinit = { _, _ -> calls.reinit++ },
        onStateLost = { _, _ -> calls.lost++ },
    )

    private fun encrypt(m: RatchetManager) =
        m.tryEncrypt(cid, ch, ss, "", "", "x".encodeToByteArray(), noFreshInit = true)

    @Test
    fun absentState_throwsUnavailable_writesNothing_noCallback_andRetryWorks() {
        if (!x25519Up()) return
        val store = Store(); val calls = Calls(); val m = manager(store, calls)
        val e = assertFailsWith<RatchetStateUnavailableException> { encrypt(m) }
        assertTrue(e !is RatchetStateLostException, "an absent state is never 'lost'")
        assertEquals(0, store.saves, "no fresh init, nothing written")
        assertTrue(store.blobs.isEmpty())
        assertEquals(0, calls.reinit); assertEquals(0, calls.lost)
        assertFailsWith<RatchetStateUnavailableException> {
            m.decryptBatch(cid, ch, ss, "", "", emptyList(), noFreshInit = true)
        }
        assertEquals(false, m.isBootstrapped(cid, ch, ss, "", "", noFreshInit = true))
        assertEquals(0, store.saves)

        // The state appears (it was only not readable): the next op uses it.
        val p = V3PairingFixture.pair()
        store.blobs["$cid/$ch"] = p.alice.ratchet.serialize()
        assertNotNull(encrypt(m))
        assertEquals(1, store.saves)
    }

    @Test
    fun aThrowingRead_isUnavailable_neverLatched() {
        if (!x25519Up()) return
        val store = Store(); val calls = Calls(); val m = manager(store, calls)
        val p = V3PairingFixture.pair()
        store.blobs["$cid/$ch"] = p.bob.ratchet.serialize()
        store.throwOnLoad = 1
        assertFailsWith<RatchetStateUnavailableException> { encrypt(m) }
        assertEquals(0, calls.lost); assertEquals(0, calls.reinit); assertEquals(0, store.saves)
        assertNotNull(encrypt(m), "the next operation retries and works")
    }

    @Test
    fun corruptState_stableAcrossReads_isProvenLost_withoutReinitOrWrite() {
        val store = Store(); val calls = Calls(); val m = manager(store, calls)
        val junk = ByteArray(40) { (it * 7 + 1).toByte() }
        store.blobs["$cid/$ch"] = junk.copyOf()
        assertFailsWith<RatchetStateLostException> { encrypt(m) }
        assertEquals(1, calls.lost)
        assertEquals(0, calls.reinit, "onCorruptReinit never runs for a v3 contact")
        assertEquals(0, store.saves)
        assertContentEquals(junk, store.blobs["$cid/$ch"], "the stored bytes are left exactly as they were")
        assertTrue(store.loads >= RatchetManager.CORRUPT_PROOF_READS)
    }

    @Test
    fun corruptState_thatChangesBetweenReads_isOnlyUnavailable() {
        val store = Store(); val calls = Calls(); val m = manager(store, calls)
        store.loadHook = { n -> ByteArray(40) { (it + n).toByte() } }   // different junk every read
        val e = assertFailsWith<RatchetStateUnavailableException> { encrypt(m) }
        assertTrue(e !is RatchetStateLostException)
        assertEquals(0, calls.lost); assertEquals(0, calls.reinit); assertEquals(0, store.saves)
    }

    @Test
    fun corruptState_thatTurnsAbsentOnARereadIsOnlyUnavailable() {
        val store = Store(); val calls = Calls(); val m = manager(store, calls)
        store.loadHook = { n -> if (n == 1) ByteArray(40) { 3 } else null }
        val e = assertFailsWith<RatchetStateUnavailableException> { encrypt(m) }
        assertTrue(e !is RatchetStateLostException)
        assertEquals(0, calls.lost)
    }

    /** A stored value that is present but not decodable at the storage layer (not base64). */
    private class UndecodableStore(val raw: (Int) -> ByteArray) : RatchetStore {
        var loads = 0
        var saves = 0
        override fun load(contactId: String, channel: String): ByteArray? { loads++; throw RatchetStoreUndecodableException(raw(loads)) }
        override fun save(contactId: String, channel: String, blob: ByteArray) { saves++ }
    }

    @Test
    fun aStableUndecodableStoredValue_isProvenLost() {
        val calls = Calls()
        val store = UndecodableStore { "not base64".encodeToByteArray() }
        val m = RatchetManager(store, onCorruptReinit = { _, _ -> calls.reinit++ }, onStateLost = { _, _ -> calls.lost++ })
        assertFailsWith<RatchetStateLostException> {
            m.tryEncrypt(cid, ch, ss, "", "", "x".encodeToByteArray(), noFreshInit = true)
        }
        assertEquals(1, calls.lost); assertEquals(0, calls.reinit); assertEquals(0, store.saves)
        assertEquals(RatchetManager.CORRUPT_PROOF_READS, store.loads)
    }

    @Test
    fun anUndecodableStoredValueThatChanges_isOnlyUnavailable() {
        val calls = Calls()
        val store = UndecodableStore { n -> "junk $n".encodeToByteArray() }
        val m = RatchetManager(store, onCorruptReinit = { _, _ -> calls.reinit++ }, onStateLost = { _, _ -> calls.lost++ })
        val e = assertFailsWith<RatchetStateUnavailableException> {
            m.tryEncrypt(cid, ch, ss, "", "", "x".encodeToByteArray(), noFreshInit = true)
        }
        assertTrue(e !is RatchetStateLostException)
        assertEquals(0, calls.lost)
    }

    /** Pin: the LEGACY path is unchanged — absent ⇒ fresh init + persist; corrupt ⇒ re-init + callback. */
    @Test
    fun legacyPath_unchanged_initsOnAbsent_andReinitsOnCorrupt() {
        if (!x25519Up()) return
        val store = Store(); val calls = Calls(); val m = manager(store, calls)
        val ib = "A".repeat(32); val ob = "B".repeat(32)   // ib < ob ⇒ Bob: no sending chain
        assertNull(m.tryEncrypt(cid, ch, ss, ib, ob, "x".encodeToByteArray()))
        assertEquals(1, store.saves, "legacy fresh init persists")
        store.blobs["$cid/$ch"] = ByteArray(40) { 1 }
        assertNull(m.tryEncrypt(cid, ch, ss, ib, ob, "x".encodeToByteArray()))
        assertEquals(1, calls.reinit, "legacy corrupt state re-inits through the callback")
        assertEquals(0, calls.lost)
    }

    @Test
    fun v3State_bothRolesSendFromBirth_throughTheManager() {
        if (!x25519Up()) return
        val p = V3PairingFixture.pair()
        for (side in listOf(p.alice, p.bob)) {
            val store = Store(); val m = manager(store, Calls())
            store.blobs["$cid/$ch"] = side.ratchet.serialize()
            assertTrue(m.isBootstrapped(cid, ch, ss, "", "", noFreshInit = true))
            assertIs<ByteArray>(encrypt(m))
        }
    }
}

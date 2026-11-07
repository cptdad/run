package com.vg.run

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import java.util.concurrent.locks.ReentrantLock
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// Read-capability rotation races that need REAL threads (same reason ContactEditCounterRaceTest
// lives here rather than in commonTest):
//
//  1. a contact delete racing the rotation commit's check-then-write must not
//     resurrect the deleted contact's inbox row (the commit would hand the row a
//     LIVE owner capability for a contact the user just deleted); and
//  2. the per-(contact, direction) rotation locks are SHARED across MessageManager
//     instances (ContactRowLocks.forRotation) — both platforms recreate
//     MessageManager on a Tor reconnect via an unawaited cancel of the old poll
//     job, so two instance-local locks would let two rotations run unserialised
//     and wedge the contact on an unresolvable marker.
// ---------------------------------------------------------------------------

private const val RACE_INBOX = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYX"               // 32 chars
private const val RACE_CAP = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"      // 43 chars
private const val RACE_RELAY = "http://relay.test"

private fun raceOk(body: String = "{}") = HttpResult(code = 200, body = body, isSuccess = true)
private fun racePeekOk() = HttpResult(code = 200, body = """{"pending":0}""", isSuccess = true)

private fun raceSeed(vault: InMemoryVault, contactId: String) {
    vault.insertContact(ContactRecord(contactId, generateSecureRandom(32), 1, "T", 0L))
    vault.insertInboxId(
        InboxIdRecord(
            inboxId = RACE_INBOX, contactId = contactId,
            createdAt = 1L, expiresAt = Long.MAX_VALUE, direction = "inbound", cap = RACE_CAP,
        )
    )
}

/**
 * Wraps [inner] with REAL transaction mutual exclusion — the one thing the plain
 * in-memory double deliberately lacks. Mirrors the platform actuals: Android's
 * withTransaction holds the connection's transaction lock, iOS's holds the
 * reentrant DB lock across BEGIN..COMMIT, and BOTH platforms' deleteContact runs
 * inside its own withTransaction (deleteMeta is likewise a serialised single
 * statement on both).
 */
private class TxLockingRaceVault(
    val inner: InMemoryVault,
    private val victim: String,
) : VaultDatabase by inner {
    val txLock = ReentrantLock()

    /** Fires once, right after the commit's guarded live re-read returns the row. */
    var onGuardedReRead: (() -> Unit)? = null
    private val reads = AtomicInteger(0)

    override fun withTransaction(block: () -> Unit) {
        txLock.lock()
        try { inner.withTransaction(block) } finally { txLock.unlock() }
    }

    override fun deleteContact(contactId: String) {
        txLock.lock()
        try { inner.deleteContact(contactId) } finally { txLock.unlock() }
    }

    override fun deleteMeta(key: String) {
        txLock.lock()
        try { inner.deleteMeta(key) } finally { txLock.unlock() }
    }

    override fun getInboxIdForContact(contactId: String, direction: String): InboxIdRecord? {
        val r = inner.getInboxIdForContact(contactId, direction)
        // Read #1 is reconcileLocked's top-of-function rec read; read #2 is the
        // LIVE re-read guarding the commit write — the exact TOCTOU point.
        if (contactId == victim && direction == "inbound" && reads.incrementAndGet() == 2) {
            onGuardedReRead?.invoke()
        }
        return r
    }
}

class CapRotationDeleteRaceTest {

    @Test
    fun deleteRacingTheCommit_cannotResurrectTheInboxRow() {
        val inner = InMemoryVault()
        val contactId = "c-del-race"
        raceSeed(inner, contactId)
        // An in-flight rotation: the candidate is durable, the relay holds it.
        inner.putMeta(MessageManager.capPendingKey(contactId, "inbound"), "E".repeat(43))

        val vault = TxLockingRaceVault(inner, contactId)
        val http = RecordingRelayHttp()
        http.script(
            racePeekOk(),   // the candidate /peek → live, so the reconcile will commit
            raceOk(),       // push-eviction DELETE after the commit
        )
        val mgr = MessageManager(vault, RACE_RELAY, http as RelayHttp)

        val deleterDone = CountDownLatch(1)
        val deleter = Thread {
            vault.deleteContact(contactId)
            deleterDone.countDown()
        }
        vault.onGuardedReRead = {
            // The delete tries to land exactly between the commit's row check and
            // its write. The fixed code holds the transaction lock across both, so
            // the delete can only queue up BEHIND the commit (and then erases the
            // row again); check-then-write as two separate vault calls lets the
            // delete complete inside this window and the commit resurrects the row.
            deleter.start()
            deleterDone.await(700, TimeUnit.MILLISECONDS)
        }

        mgr.reconcileReadCapRotation(contactId, "inbound")
        assertTrue(deleterDone.await(10, TimeUnit.SECONDS), "the delete must complete")
        deleter.join(10_000)

        assertNull(inner.getContact(contactId), "the contact stays deleted")
        assertNull(
            inner.getInboxIdForContact(contactId, "inbound"),
            "the rotation commit must not resurrect a deleted contact's inbox row — a " +
                "resurrected row bears a LIVE owner capability for a contact the user deleted",
        )
        assertNull(
            inner.getMeta(MessageManager.capPendingKey(contactId, "inbound")),
            "no orphaned pending marker may survive either",
        )
    }
}

class SharedRotationLockCrossInstanceTest {

    @Test
    fun twoInstancesRotatingTheSamePair_serialiseOnTheSharedLock() {
        val inner = InMemoryVault()
        val contactId = "c-two-instances"
        raceSeed(inner, contactId)

        val inPut = CountDownLatch(1)
        val gate = CountDownLatch(1)
        // Instance 1 parks inside its rotation PUT — i.e. mid-rotation, holding the
        // (contact, direction) rotation lock across network I/O, exactly where a
        // dying pre-reconnect instance would sit.
        val http1 = object : RelayHttp {
            override fun post(url: String, body: ByteArray, contentType: String, headers: Map<String, String>, timeoutSeconds: Int) =
                HttpResult(code = -1, body = null, isSuccess = false)
            override fun put(url: String, body: ByteArray, contentType: String, headers: Map<String, String>, timeoutSeconds: Int): HttpResult {
                inPut.countDown()
                gate.await(10, TimeUnit.SECONDS)
                return raceOk()
            }
            override fun get(url: String, headers: Map<String, String>, timeoutSeconds: Int) = racePeekOk()
            override fun delete(url: String, headers: Map<String, String>, timeoutSeconds: Int) = raceOk()
        }
        val http2 = RecordingRelayHttp()
        http2.script(
            raceOk(),       // instance 2's own rotation PUT
            racePeekOk(),   // its candidate /peek
            raceOk(),       // its push-eviction DELETE
        )

        // Two MessageManager instances over ONE vault — the Tor-reconnect recreate.
        val mgr1 = MessageManager(inner, RACE_RELAY, http1)
        val mgr2 = MessageManager(inner, RACE_RELAY, http2 as RelayHttp)

        val r1 = AtomicReference<CapRotationOutcome>()
        val r2 = AtomicReference<CapRotationOutcome>()
        val t1 = Thread { r1.set(mgr1.rotateReadCap(contactId, "inbound")) }
        t1.start()
        assertTrue(inPut.await(5, TimeUnit.SECONDS), "instance 1 never reached its rotation PUT")

        val t2 = Thread { r2.set(mgr2.rotateReadCap(contactId, "inbound")) }
        t2.start()
        t2.join(500)
        // Instance-scoped registries would let t2 run NOW, concurrently, over t1's
        // live pending marker — two unserialised rotations, the loser resolving
        // neither cap (the wedged-on-UNKNOWN failure). The shared registry makes
        // it queue: while t1 is parked, t2 cannot even reach the vault or network.
        assertTrue(t2.isAlive, "the second instance must serialise behind the first's in-flight rotation")
        assertEquals(0, http2.calls.size, "…and must not touch the network while the first holds the lock")

        gate.countDown()
        t1.join(10_000)
        t2.join(10_000)
        assertTrue(!t1.isAlive && !t2.isAlive, "both rotations must complete")

        assertEquals(CapRotationOutcome.ROTATED, r1.get(), "instance 1's rotation commits")
        assertEquals(
            CapRotationOutcome.ROTATED, r2.get(),
            "instance 2 then rotates cleanly on its turn — never wedged on the first's marker",
        )
        val cap = inner.getInboxIdForContact(contactId, "inbound")?.cap
        assertNotNull(cap)
        assertTrue(isValidCapability(cap))
        assertNull(
            inner.getMeta(MessageManager.capPendingKey(contactId, "inbound")),
            "no unresolved marker may survive — a survivor blocks every future rotation on BUSY",
        )
    }
}

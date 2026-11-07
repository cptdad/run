package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

// ---------------------------------------------------------------------------
// Read-capability rotation (durable pending marker + probe-decided
// reconcile), explicit inbox delete, and the delete-contact relay purge.
//
// The read cap is the inbox OWNER capability — it authorises the destructive
// drain, DELETE /inbox/{id}, BOTH capability rotations and push register — so an
// imaged vault grants indefinite remote control of the user's inboxes until it
// is rotated. These tests pin the two properties that make rotating it SAFE:
//
//   1. the union {record cap, pending marker} always contains whatever cap the
//      relay holds, at every interruption point, so no failure can leave the
//      user without a usable capability for their own inbox; and
//   2. every probe is a NON-DESTRUCTIVE /peek — a bare GET /inbox/{id} would
//      DRAIN the inbox and silently destroy every queued message.
// ---------------------------------------------------------------------------

private const val ROT_INBOX_MAIN = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYX"          // 32 chars
private const val ROT_INBOX_CTL  = "BBECAwQFBgcICQoLDA0ODxAREhMUFRYX"          // 32 chars
private const val ROT_CAP_MAIN   = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  // 43 chars
private const val ROT_CAP_CTL    = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"  // 43 chars

private const val RELAY = "http://relay.test"

private fun ok(body: String = "{}") = HttpResult(code = 200, body = body, isSuccess = true)
private fun gone() = HttpResult(code = 404, body = """{"error":"request rejected"}""", isSuccess = false)
private fun rateLimited() = HttpResult(code = 429, body = """{"error":"rate limited"}""", isSuccess = false)
private fun dropped() = HttpResult(code = -1, body = null, isSuccess = false)
private fun peekOk() = HttpResult(code = 200, body = """{"pending":0}""", isSuccess = true)

/** Seeds a contact with an inbound TEXT inbox and (optionally) an inbound CONTROL inbox. */
private fun seedRotContact(vault: InMemoryVault, contactId: String, ctl: Boolean = false) {
    vault.insertContact(
        ContactRecord(
            contactId = contactId,
            sharedSecret = ByteArray(32) { 3 },
            trustLevel = 1,
            alias = "T",
            aliasLastRotated = 0L,
        )
    )
    vault.insertInboxId(
        InboxIdRecord(
            inboxId = ROT_INBOX_MAIN, contactId = contactId,
            createdAt = 1L, expiresAt = Long.MAX_VALUE,
            direction = "inbound", cap = ROT_CAP_MAIN,
        )
    )
    if (ctl) {
        vault.insertInboxId(
            InboxIdRecord(
                inboxId = ROT_INBOX_CTL, contactId = contactId,
                createdAt = 1L, expiresAt = Long.MAX_VALUE,
                direction = MessageManager.DIR_INBOUND_CTL, cap = ROT_CAP_CTL,
            )
        )
    }
}

private fun pendKey(contactId: String, direction: String = "inbound") =
    MessageManager.capPendingKey(contactId, direction)

private fun capOf(vault: InMemoryVault, contactId: String, direction: String = "inbound") =
    vault.getInboxIdForContact(contactId, direction)?.cap

class ReadCapRotationTest {

    // ---- the durable marker is written BEFORE any network I/O ----------------

    @Test
    fun rotate_markerPersistFails_returnsFailed_withoutTouchingTheNetwork() {
        // The marker is the ONLY thing that keeps a lost response from stranding the
        // relay on a cap this device never stored. If it can't be written, nothing
        // may be sent — otherwise a successful relay rotation would be invisible
        // locally and the inbox unreachable forever.
        val inner = InMemoryVault()
        val contactId = "c-marker"
        seedRotContact(inner, contactId)
        val vault = object : VaultDatabase by inner {
            override fun putMeta(key: String, value: String) {
                throw RuntimeException("simulated vault write failure")
            }
        }
        val http = RecordingRelayHttp()   // any call would fail — must not happen
        val mgr = MessageManager(vault, RELAY, http as RelayHttp)

        assertEquals(CapRotationOutcome.FAILED, mgr.rotateReadCap(contactId, "inbound"))
        assertEquals(0, http.calls.size, "nothing may be sent before the marker is durable")
        assertEquals(ROT_CAP_MAIN, capOf(inner, contactId), "the stored cap must be untouched")
    }

    @Test
    fun rotate_writesTheMarkerBeforeThePut() {
        // Ordering proof: the marker must already be on disk when the PUT is issued.
        val inner = InMemoryVault()
        val contactId = "c-order"
        seedRotContact(inner, contactId)
        var markerAtPutTime: String? = null
        val http = FakeRelayHttp(
            onPost = { dropped() },
            onPut = {
                markerAtPutTime = inner.getMeta(pendKey(contactId))
                dropped()
            },
            onGet = { dropped() },
        )
        val mgr = MessageManager(inner, RELAY, http)

        mgr.rotateReadCap(contactId, "inbound")

        assertNotNull(markerAtPutTime, "the pending marker must be durable BEFORE the rotation PUT")
        assertTrue(isValidCapability(markerAtPutTime!!))
        assertEquals(markerAtPutTime, inner.getMeta(pendKey(contactId)), "an inconclusive rotation keeps the marker")
        assertEquals(ROT_CAP_MAIN, capOf(inner, contactId), "…and keeps the old cap: BOTH are retained")
    }

    // ---- the four decided outcomes ------------------------------------------

    @Test
    fun rotate_relayOkAndNewCapProbesOk_commitsAndClearsPending() {
        val vault = InMemoryVault()
        val contactId = "c-ok"
        seedRotContact(vault, contactId)
        val http = RecordingRelayHttp()
        // PUT /read-capability → 200, /peek with the NEW cap → 200, push eviction DELETE.
        http.script(ok(), peekOk(), ok())
        val mgr = MessageManager(vault, RELAY, http as RelayHttp)

        assertEquals(CapRotationOutcome.ROTATED, mgr.rotateReadCap(contactId, "inbound"))

        val newCap = capOf(vault, contactId)
        assertNotNull(newCap)
        assertTrue(isValidCapability(newCap!!), "the committed cap must be a well-formed capability")
        assertTrue(newCap != ROT_CAP_MAIN, "the record must carry the ROTATED cap")
        assertNull(vault.getMeta(pendKey(contactId)), "a committed rotation clears the marker")

        val put = http.calls.first { it.method == "PUT" }
        assertEquals("$RELAY/inbox/$ROT_INBOX_MAIN/read-capability", put.url)
        assertEquals(ROT_CAP_MAIN, put.headers["X-Read-Capability"], "rotation authenticates with the CURRENT cap")
        assertEquals(newCap, put.headers["X-New-Read-Capability"])
        // Push eviction: the registration is deleted with the cap that just proved
        // current — an attacker's token must not keep receiving wake pushes.
        val del = http.calls.single { it.method == "DELETE" }
        assertEquals("$RELAY/inbox/$ROT_INBOX_MAIN/push", del.url)
        assertEquals(newCap, del.headers["X-Read-Capability"])
        assertEquals(setOf(ROT_INBOX_MAIN), mgr.drainRotatedPushInboxIds())
        assertEquals(emptySet(), mgr.drainRotatedPushInboxIds(), "the eviction set drains once")
    }

    @Test
    fun rotate_recordPersistThrows_keepsPending_andALaterReconcileCommits() {
        // The relay rotated but the local cap write failed. Keeping BOTH is what
        // saves the inbox: the marker survives, so the next reconcile commits it.
        val inner = InMemoryVault()
        val contactId = "c-persist"
        seedRotContact(inner, contactId)
        var failInsert = true
        val vault = object : VaultDatabase by inner {
            override fun insertInboxId(record: InboxIdRecord): Long {
                if (failInsert) throw RuntimeException("simulated vault write failure")
                return inner.insertInboxId(record)
            }
        }
        val http = RecordingRelayHttp()
        http.script(ok(), peekOk())
        val mgr = MessageManager(vault, RELAY, http as RelayHttp)

        assertEquals(CapRotationOutcome.UNKNOWN, mgr.rotateReadCap(contactId, "inbound"))
        val pending = inner.getMeta(pendKey(contactId))
        assertNotNull(pending, "a failed persist must KEEP the pending marker")
        assertEquals(ROT_CAP_MAIN, capOf(inner, contactId), "the record cap is unchanged")

        // …and the next reconcile (poll-loop self-heal) finishes the job.
        failInsert = false
        http.script(peekOk(), ok())
        assertEquals(CapRotationOutcome.ROTATED, mgr.reconcileReadCapRotation(contactId, "inbound"))
        assertEquals(pending, capOf(inner, contactId), "reconcile commits the pending cap")
        assertNull(inner.getMeta(pendKey(contactId)))
    }

    @Test
    fun reconcile_newCap404_oldCap200_dropsPending_andKeepsTheOldCap() {
        // Proof the rotation never landed: the candidate is rejected AND the cap we
        // still hold works. Only then is it safe to forget the candidate.
        val vault = InMemoryVault()
        val contactId = "c-notapplied"
        seedRotContact(vault, contactId)
        val http = RecordingRelayHttp()
        http.script(gone(), gone(), peekOk())   // PUT 404, new-cap peek 404, old-cap peek 200
        val mgr = MessageManager(vault, RELAY, http as RelayHttp)

        assertEquals(CapRotationOutcome.NOT_APPLIED, mgr.rotateReadCap(contactId, "inbound"))
        assertNull(vault.getMeta(pendKey(contactId)), "a provably-dead candidate is dropped")
        assertEquals(ROT_CAP_MAIN, capOf(vault, contactId), "the working cap is kept")
    }

    @Test
    fun reconcile_bothCaps404_keepsBoth_andChangesNothing() {
        val vault = InMemoryVault()
        val contactId = "c-both404"
        seedRotContact(vault, contactId)
        val http = RecordingRelayHttp()
        http.script(gone(), gone(), gone())
        val mgr = MessageManager(vault, RELAY, http as RelayHttp)

        assertEquals(CapRotationOutcome.UNKNOWN, mgr.rotateReadCap(contactId, "inbound"))
        assertNotNull(vault.getMeta(pendKey(contactId)), "unresolved → keep the candidate")
        assertEquals(ROT_CAP_MAIN, capOf(vault, contactId), "unresolved → keep the current cap")
    }

    @Test
    fun reconcile_rateLimited_keepsBoth() {
        val vault = InMemoryVault()
        val contactId = "c-429"
        seedRotContact(vault, contactId)
        val http = RecordingRelayHttp()
        http.script(rateLimited(), rateLimited())
        val mgr = MessageManager(vault, RELAY, http as RelayHttp)

        assertEquals(CapRotationOutcome.UNKNOWN, mgr.rotateReadCap(contactId, "inbound"))
        assertNotNull(vault.getMeta(pendKey(contactId)))
        assertEquals(ROT_CAP_MAIN, capOf(vault, contactId))
    }

    @Test
    fun reconcile_transportThrows_keepsBoth() {
        val vault = InMemoryVault()
        val contactId = "c-throw"
        seedRotContact(vault, contactId)
        val http = FakeRelayHttp(
            onPost = { throw RuntimeException("circuit dead") },
            onPut = { throw RuntimeException("circuit dead") },
            onGet = { throw RuntimeException("circuit dead") },
        )
        val mgr = MessageManager(vault, RELAY, http)

        assertEquals(CapRotationOutcome.UNKNOWN, mgr.rotateReadCap(contactId, "inbound"))
        assertNotNull(vault.getMeta(pendKey(contactId)), "a thrown probe must not resolve anything")
        assertEquals(ROT_CAP_MAIN, capOf(vault, contactId))
    }

    // ---- the highest-value regression: probes must never DRAIN ---------------

    @Test
    fun reconcile_probesPeek_andNeverIssuesABareInboxGet() {
        // GET /inbox/{id} DRAINS the queue. If a probe ever regressed to a bare GET,
        // every queued message would be silently destroyed on each reconcile — a
        // catastrophic, invisible data-loss bug. Both probe paths are covered here
        // (the candidate probe, then the old-cap fallback).
        val vault = InMemoryVault()
        val contactId = "c-peek"
        seedRotContact(vault, contactId)
        val http = RecordingRelayHttp()
        http.script(gone(), gone(), peekOk())
        val mgr = MessageManager(vault, RELAY, http as RelayHttp)

        mgr.rotateReadCap(contactId, "inbound")

        val gets = http.calls.filter { it.method == "GET" }
        assertEquals(2, gets.size, "both the candidate and the old-cap fallback were probed")
        for (g in gets) {
            assertEquals("$RELAY/inbox/$ROT_INBOX_MAIN/peek", g.url, "probes MUST use the non-destructive /peek")
        }
        assertTrue(
            http.calls.none { it.url == "$RELAY/inbox/$ROT_INBOX_MAIN" },
            "a bare GET/POST on the inbox itself would drain it — never issue one from a probe",
        )
    }

    // ---- never chain rotations ----------------------------------------------

    @Test
    fun rotate_refusesWhileAnUnresolvedPendingExists() {
        val vault = InMemoryVault()
        val contactId = "c-busy"
        seedRotContact(vault, contactId)
        val stalePending = "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"
        vault.putMeta(pendKey(contactId), stalePending)
        val http = RecordingRelayHttp()
        http.script(dropped())   // the reconcile probe is inconclusive
        val mgr = MessageManager(vault, RELAY, http as RelayHttp)

        assertEquals(CapRotationOutcome.BUSY, mgr.rotateReadCap(contactId, "inbound"))
        assertTrue(http.calls.none { it.method == "PUT" }, "a second rotation must not be started")
        assertEquals(stalePending, vault.getMeta(pendKey(contactId)), "the first candidate is kept")
        assertEquals(ROT_CAP_MAIN, capOf(vault, contactId), "…and so is the current cap")
    }

    @Test
    fun reconcile_unusableMarker_isRetiredOnlyAgainstAProvenAliveCap() {
        // A marker that can never be sent as a header (at-rest corruption of a value
        // validated before it was written) would otherwise wedge EVERY future
        // rotation on BUSY forever. It is retired — but only once the cap we still
        // hold is proven alive, so the union invariant is never violated.
        val vault = InMemoryVault()
        val contactId = "c-corruptmarker"
        seedRotContact(vault, contactId)
        vault.putMeta(pendKey(contactId), "cap\r\nX-Inject: 1")
        val http = RecordingRelayHttp()
        http.script(dropped())   // the FIRST probe is the old-cap one: inconclusive
        val mgr = MessageManager(vault, RELAY, http as RelayHttp)

        assertEquals(CapRotationOutcome.UNKNOWN, mgr.reconcileReadCapRotation(contactId, "inbound"))
        assertNotNull(vault.getMeta(pendKey(contactId)), "unproven → the marker stays")

        // Now the current cap answers → the unusable marker is provably irrelevant.
        http.script(peekOk())
        assertEquals(CapRotationOutcome.NOT_APPLIED, mgr.reconcileReadCapRotation(contactId, "inbound"))
        assertNull(vault.getMeta(pendKey(contactId)))
        assertEquals(ROT_CAP_MAIN, capOf(vault, contactId))
        assertTrue(
            http.calls.all { it.url == "$RELAY/inbox/$ROT_INBOX_MAIN/peek" },
            "an unusable candidate is never sent as a header",
        )
    }

    @Test
    fun reconcile_withNoPendingMarker_isAFreeNoOp() {
        val vault = InMemoryVault()
        val contactId = "c-idle"
        seedRotContact(vault, contactId)
        val http = RecordingRelayHttp()
        val mgr = MessageManager(vault, RELAY, http as RelayHttp)

        assertEquals(CapRotationOutcome.NOTHING_TO_DO, mgr.reconcileReadCapRotation(contactId, "inbound"))
        assertEquals(0, http.calls.size, "the steady state costs ZERO network calls")
    }

    // ---- generated material + both directions --------------------------------

    @Test
    fun rotate_generatesValidDistinctCapabilities() {
        val vault = InMemoryVault()
        val http = RecordingRelayHttp()
        val mgr = MessageManager(vault, RELAY, http as RelayHttp)
        val seen = mutableSetOf<String>()
        for (n in 1..4) {
            val contactId = "c-$n"
            seedRotContact(vault, contactId)
            // Each contact re-inserts the same inboxId row, so re-point it per contact.
            vault.insertInboxId(
                InboxIdRecord(
                    inboxId = ROT_INBOX_MAIN, contactId = contactId,
                    createdAt = 1L, expiresAt = Long.MAX_VALUE,
                    direction = "inbound", cap = ROT_CAP_MAIN,
                )
            )
            http.script(ok(), peekOk(), ok())
            assertEquals(CapRotationOutcome.ROTATED, mgr.rotateReadCap(contactId, "inbound"))
            val cap = capOf(vault, contactId)
            assertNotNull(cap)
            assertTrue(isValidCapability(cap!!), "generated cap must match the relay's cap shape")
            assertTrue(seen.add(cap), "every rotation must mint a FRESH capability")
        }
    }

    @Test
    fun resetRelayAccess_rotatesBothInboundInboxes() {
        // The CONTROL inbox's read cap is exactly as powerful as the text inbox's,
        // so leaving it unrotated would leave the attacker an owner capability.
        val vault = InMemoryVault()
        val contactId = "c-both"
        seedRotContact(vault, contactId, ctl = true)
        val http = RecordingRelayHttp()
        http.script(ok(), peekOk(), ok(), ok(), peekOk(), ok())
        val mgr = MessageManager(vault, RELAY, http as RelayHttp)

        assertTrue(mgr.resetRelayAccess(contactId))

        val mainCap = capOf(vault, contactId, "inbound")
        val ctlCap = capOf(vault, contactId, MessageManager.DIR_INBOUND_CTL)
        assertNotNull(mainCap); assertNotNull(ctlCap)
        assertTrue(mainCap != ROT_CAP_MAIN, "text inbox rotated")
        assertTrue(ctlCap != ROT_CAP_CTL, "control inbox rotated")
        assertTrue(mainCap != ctlCap, "the two inboxes get independent caps")
        assertNull(vault.getMeta(pendKey(contactId, "inbound")))
        assertNull(vault.getMeta(pendKey(contactId, MessageManager.DIR_INBOUND_CTL)))
        val rotatePuts = http.calls.filter { it.method == "PUT" }.map { it.url }
        assertEquals(
            listOf(
                "$RELAY/inbox/$ROT_INBOX_MAIN/read-capability",
                "$RELAY/inbox/$ROT_INBOX_CTL/read-capability",
            ),
            rotatePuts,
        )
    }

    @Test
    fun resetRelayAccess_withNoControlInbox_stillSucceeds() {
        // A pre-v7 pairing has no control inbox — "nothing to rotate there" is not a
        // failure, or the action would look broken on every legacy contact.
        val vault = InMemoryVault()
        val contactId = "c-legacy"
        seedRotContact(vault, contactId, ctl = false)
        val http = RecordingRelayHttp()
        http.script(ok(), peekOk(), ok())
        val mgr = MessageManager(vault, RELAY, http as RelayHttp)

        assertTrue(mgr.resetRelayAccess(contactId))
        assertTrue(capOf(vault, contactId) != ROT_CAP_MAIN)
    }

    @Test
    fun resetRelayAccess_unknownOutcome_reportsFailure_butKeepsAUsableCap() {
        val vault = InMemoryVault()
        val contactId = "c-unknown"
        seedRotContact(vault, contactId)
        val http = RecordingRelayHttp()
        http.script(dropped(), dropped())
        val mgr = MessageManager(vault, RELAY, http as RelayHttp)

        assertTrue(!mgr.resetRelayAccess(contactId), "an unproven rotation must not report success")
        assertEquals(ROT_CAP_MAIN, capOf(vault, contactId), "the user still holds a working capability")
        assertNotNull(vault.getMeta(pendKey(contactId)), "the durable marker survives for the poll-loop reconcile")
    }

    @Test
    fun rotate_refusesAMalformedStoredCap_withoutNetworkCall() {
        // Mirrors send/poll: a corrupt/legacy row must never reach header construction.
        val vault = InMemoryVault()
        val contactId = "c-corrupt"
        seedRotContact(vault, contactId)
        vault.insertInboxId(
            InboxIdRecord(
                inboxId = ROT_INBOX_MAIN, contactId = contactId,
                createdAt = 1L, expiresAt = Long.MAX_VALUE,
                direction = "inbound", cap = "cap\r\nX-Inject: 1",
            )
        )
        val http = RecordingRelayHttp()
        val mgr = MessageManager(vault, RELAY, http as RelayHttp)

        assertEquals(CapRotationOutcome.FAILED, mgr.rotateReadCap(contactId, "inbound"))
        assertEquals(0, http.calls.size)
        assertNull(vault.getMeta(pendKey(contactId)), "a refused rotation writes no marker")
    }

    @Test
    fun reconcile_doesNotResurrectADeletedContactsInboxRow() {
        // The contact is deleted during the probe round-trip. Committing the cap
        // would re-create a capability-bearing row for a purged contact (the
        // non-resurrection rule).
        val inner = InMemoryVault()
        val contactId = "c-gone"
        seedRotContact(inner, contactId)
        inner.putMeta(pendKey(contactId), "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE")
        val http = FakeRelayHttp(
            onPost = { dropped() },
            onPut = { dropped() },
            onGet = {
                // The delete lands while the probe is in flight.
                inner.deleteContact(contactId)
                peekOk()
            },
        )
        val mgr = MessageManager(inner, RELAY, http)

        assertEquals(CapRotationOutcome.UNKNOWN, mgr.reconcileReadCapRotation(contactId, "inbound"))
        assertNull(inner.getInboxIdForContact(contactId, "inbound"), "no inbox row may be resurrected")
        assertNull(inner.getContact(contactId))
    }

    // ---- delete-vs-rotation TOCTOU: check-then-write is transactional --------

    @Test
    fun rotate_checkThenWriteUnits_runInsideOneVaultTransactionEach() {
        // commonTest can't exercise real DB isolation (the in-memory double's
        // withTransaction just runs the block — the same limitation
        // GroupTransactionTest documents), so this pins the WIRING that closes the
        // delete-vs-rotation TOCTOU: each of the two check-then-write units (the
        // pending-marker write in rotateLocked, the cap commit in reconcileLocked)
        // runs its guarding row re-read INSIDE the same withTransaction scope as
        // the write, where deleteContact's own transaction cannot land between
        // them. The real-thread interleaving is covered by androidUnitTest's
        // CapRotationDeleteRaceTest.
        val inner = InMemoryVault()
        val contactId = "c-txn"
        seedRotContact(inner, contactId)
        val vault = RotationTxTrackingVault(inner)
        val http = RecordingRelayHttp()
        http.script(ok(), peekOk(), ok())
        val mgr = MessageManager(vault, RELAY, http as RelayHttp)

        assertEquals(CapRotationOutcome.ROTATED, mgr.rotateReadCap(contactId, "inbound"))

        val markerTx = vault.metaWriteTx[pendKey(contactId)]
        assertNotNull(markerTx, "the pending-marker write must be inside a withTransaction scope")
        assertTrue(vault.rowReadTx.contains(markerTx),
            "the marker write's transaction must contain the row re-check that guards it")

        val commitTx = vault.inboxWriteTx.single()
        assertNotNull(commitTx, "the cap commit must be inside a withTransaction scope")
        assertTrue(vault.rowReadTx.contains(commitTx),
            "the commit's transaction must contain the live row re-read that guards it")
        assertTrue(markerTx != commitTx, "two check-then-write units, two separate transactions")
    }

    @Test
    fun rotate_deleteLandingBeforeTheMarkerWrite_writesNoOrphanMarker() {
        // The sibling of the commit-branch TOCTOU: the contact is deleted between
        // rotateLocked's row/marker reads and its pending-marker write. Unfixed,
        // the marker landed anyway — capability-bearing `_meta` state re-created
        // for a deleted contact AFTER deleteContact's purge already ran — and the
        // rotation PUT then re-keyed a relay inbox the local vault no longer knows.
        // The transactional row re-check refuses instead.
        val inner = InMemoryVault()
        val contactId = "c-del-marker"
        seedRotContact(inner, contactId)
        var pendReads = 0
        val vault = object : VaultDatabase by inner {
            override fun getMeta(key: String): String? {
                val v = inner.getMeta(key)
                // Read #1 is reconcileLocked's step-0 gate; read #2 is rotateLocked's
                // "is a marker pending?" check — the delete lands right after it,
                // in the window before the marker write.
                if (key == pendKey(contactId) && ++pendReads == 2) inner.deleteContact(contactId)
                return v
            }
        }
        val http = RecordingRelayHttp()
        val mgr = MessageManager(vault, RELAY, http as RelayHttp)

        assertEquals(CapRotationOutcome.FAILED, mgr.rotateReadCap(contactId, "inbound"))
        assertNull(inner.getMeta(pendKey(contactId)),
            "no orphan cap-pend marker may be re-created for a deleted contact")
        assertEquals(0, http.calls.size,
            "a rotation whose contact was deleted must never reach the relay")
    }

    // ---- the rotation-lock registry is process-wide (cross-instance) ---------

    @Test
    fun rotationLock_isOneStableSharedInstancePerContactAndDirection() {
        // Mirrors ContactEditsTest's forContact pin. Both platforms recreate
        // MessageManager on a Tor reconnect via an unawaited cancel of the old
        // poll job, so the registry must be object-scoped (shared across
        // instances), per (contact, direction), and DISTINCT from the counter
        // lock — a rotation critical section spans network I/O by design, the
        // counter lock's must never.
        val a1 = ContactRowLocks.forRotation("rot-lock-a", "inbound")
        val a2 = ContactRowLocks.forRotation("rot-lock-a", "inbound")
        val aCtl = ContactRowLocks.forRotation("rot-lock-a", MessageManager.DIR_INBOUND_CTL)
        val b = ContactRowLocks.forRotation("rot-lock-b", "inbound")
        assertTrue(a1 === a2, "the same (contact, direction) must map to the same lock instance")
        assertTrue(a1 !== aCtl, "the two inbound channels rotate independently — no shared lock")
        assertTrue(a1 !== b, "different contacts must not share a lock")
        assertTrue(a1 !== ContactRowLocks.forContact("rot-lock-a"),
            "the rotation lock must not be the counter lock (it spans network I/O)")
    }
}

/**
 * Wiring probe: records, for every row read / inbox write / `_meta`
 * write, WHICH withTransaction invocation (1, 2, …) it ran inside — or null for
 * outside any transaction — so the tests above can assert a check and its write
 * share one transaction. Same depth-tracking idea as [TxTrackingVault].
 */
private class RotationTxTrackingVault(private val d: InMemoryVault) : VaultDatabase by d {
    private var txDepth = 0
    private var txSeq = 0
    private fun cur(): Int? = if (txDepth > 0) txSeq else null
    val rowReadTx = mutableListOf<Int?>()
    val inboxWriteTx = mutableListOf<Int?>()
    val metaWriteTx = mutableMapOf<String, Int?>()
    override fun withTransaction(block: () -> Unit) {
        txDepth++; txSeq++
        try { block() } finally { txDepth-- }
    }
    override fun getInboxIdForContact(contactId: String, direction: String): InboxIdRecord? {
        rowReadTx.add(cur())
        return d.getInboxIdForContact(contactId, direction)
    }
    override fun insertInboxId(record: InboxIdRecord): Long {
        inboxWriteTx.add(cur())
        return d.insertInboxId(record)
    }
    override fun putMeta(key: String, value: String) {
        metaWriteTx[key] = cur()
        d.putMeta(key, value)
    }
}

class DeleteInboxTest {

    @Test
    fun deleteInbox_malformedIdOrCap_refusesWithoutNetworkCall() {
        val http = RecordingRelayHttp()
        val mgr = MessageManager(InMemoryVault(), RELAY, http as RelayHttp)

        assertTrue(!mgr.deleteInbox("not-an-inbox-id", ROT_CAP_MAIN))
        assertTrue(!mgr.deleteInbox(ROT_INBOX_MAIN, "cap\r\nX-Inject: 1"))
        assertTrue(!mgr.deleteInbox(ROT_INBOX_MAIN, ""))
        assertEquals(0, http.calls.size, "a malformed id/cap must never reach the network")
    }

    @Test
    fun deleteInbox_sendsDeleteWithTheReadCapHeader() {
        val http = RecordingRelayHttp()
        http.script(ok())
        val mgr = MessageManager(InMemoryVault(), RELAY, http as RelayHttp)

        assertTrue(mgr.deleteInbox(ROT_INBOX_MAIN, ROT_CAP_MAIN))

        val call = http.calls.single()
        assertEquals("DELETE", call.method)
        assertEquals("$RELAY/inbox/$ROT_INBOX_MAIN", call.url)
        assertEquals(ROT_CAP_MAIN, call.headers["X-Read-Capability"])
    }

    @Test
    fun deleteInbox_404_returnsFalse_andNeverThrows() {
        val http = RecordingRelayHttp()
        http.script(gone())
        val mgr = MessageManager(InMemoryVault(), RELAY, http as RelayHttp)

        assertTrue(!mgr.deleteInbox(ROT_INBOX_MAIN, ROT_CAP_MAIN), "already-gone is not a success")
        assertEquals(1, http.calls.size, "no retry loop — a lost DELETE costs only the orphan")
    }

    @Test
    fun deleteInbox_transportThrows_returnsFalse() {
        val http = FakeRelayHttp(
            onPost = { dropped() },
            onPut = { dropped() },
            onGet = { dropped() },
            onDelete = { throw RuntimeException("circuit dead") },
        )
        val mgr = MessageManager(InMemoryVault(), RELAY, http)
        assertTrue(!mgr.deleteInbox(ROT_INBOX_MAIN, ROT_CAP_MAIN))
    }
}

class DeleteContactRelayPurgeTest {

    @Test
    fun deletesLocally_evenWithNoTransport() {
        // The user's delete is NEVER gated on Tor being up.
        val vault = InMemoryVault()
        val contactId = "c-del"
        seedRotContact(vault, contactId, ctl = true)

        assertTrue(deleteContactAndPurgeRelay(vault, null, contactId))

        assertNull(vault.getContact(contactId))
        assertNull(vault.getInboxIdForContact(contactId, "inbound"))
        assertNull(vault.getInboxIdForContact(contactId, MessageManager.DIR_INBOUND_CTL))
    }

    @Test
    fun issuesDeleteForBothInboundInboxes_withThePreDeleteCaps() {
        val vault = InMemoryVault()
        val contactId = "c-purge"
        seedRotContact(vault, contactId, ctl = true)
        val http = RecordingRelayHttp()
        http.script(ok(), ok())
        val mgr = MessageManager(vault, RELAY, http as RelayHttp)

        assertTrue(deleteContactAndPurgeRelay(vault, mgr, contactId))

        assertNull(vault.getContact(contactId), "the local delete happened first")
        val deletes = http.calls.filter { it.method == "DELETE" }
        assertEquals(2, deletes.size, "both inbound inboxes are destroyed on the relay")
        // Order is CSPRNG-shuffled, so assert the SET of (url, cap) pairs.
        assertEquals(
            setOf(
                "$RELAY/inbox/$ROT_INBOX_MAIN" to ROT_CAP_MAIN,
                "$RELAY/inbox/$ROT_INBOX_CTL" to ROT_CAP_CTL,
            ),
            deletes.map { it.url to it.headers["X-Read-Capability"] }.toSet(),
        )
    }

    @Test
    fun onLocalDeleted_firesBeforeAnyRelayRoundTrip() {
        // The UI drops the row on THIS callback, so it must land before the relay
        // I/O — otherwise a deleted contact lingers on screen for the length of a
        // wedged Tor circuit.
        val vault = InMemoryVault()
        val contactId = "c-hook"
        seedRotContact(vault, contactId, ctl = true)
        val http = RecordingRelayHttp()
        http.script(ok(), ok())
        val mgr = MessageManager(vault, RELAY, http as RelayHttp)
        var httpCallsAtHook = -1
        var contactAtHook: ContactRecord? = null

        deleteContactAndPurgeRelay(vault, mgr, contactId) {
            httpCallsAtHook = http.calls.size
            contactAtHook = vault.getContact(contactId)
        }

        assertEquals(0, httpCallsAtHook, "the row must be dropped BEFORE the relay deletes")
        assertNull(contactAtHook, "…and only AFTER the local delete actually landed")
        assertEquals(2, http.calls.size, "the relay cleanup still runs behind it")
    }

    @Test
    fun localDeleteThrows_issuesNoRelayDeletes() {
        // The local delete is atomic on both platforms, so a throw means the contact
        // and its inboxes are still INTACT — relay-deleting them would destroy a live
        // channel the user still has. (Deliberately not a `finally`.)
        val inner = InMemoryVault()
        val contactId = "c-throws"
        seedRotContact(inner, contactId, ctl = true)
        val vault = object : VaultDatabase by inner {
            override fun deleteContact(contactId: String) {
                throw RuntimeException("simulated vault failure")
            }
        }
        val http = RecordingRelayHttp()
        val mgr = MessageManager(vault, RELAY, http as RelayHttp)
        var hookFired = false

        assertTrue(!deleteContactAndPurgeRelay(vault, mgr, contactId) { hookFired = true })

        assertTrue(!hookFired, "the UI must not drop a row whose delete failed")
        assertEquals(0, http.calls.size, "a failed local delete must NOT trigger relay deletes")
        assertNotNull(inner.getInboxIdForContact(contactId, "inbound"), "the inbox row is still live")
    }

    @Test
    fun skipsRowsWithNoUsableCapability() {
        val vault = InMemoryVault()
        val contactId = "c-nocap"
        seedRotContact(vault, contactId, ctl = true)
        vault.insertInboxId(
            InboxIdRecord(
                inboxId = ROT_INBOX_CTL, contactId = contactId,
                createdAt = 1L, expiresAt = Long.MAX_VALUE,
                direction = MessageManager.DIR_INBOUND_CTL, cap = null,
            )
        )
        val http = RecordingRelayHttp()
        http.script(ok())
        val mgr = MessageManager(vault, RELAY, http as RelayHttp)

        assertTrue(deleteContactAndPurgeRelay(vault, mgr, contactId))
        assertEquals(1, http.calls.size, "only the inbox we can actually authenticate is deleted")
        assertEquals("$RELAY/inbox/$ROT_INBOX_MAIN", http.calls.single().url)
    }
}

/**
 * A mint double whose FIRST inbox mints and whose SECOND fails terminally (507),
 * so [MessageManager.mintInboxPair] hits the partial-failure branch. Records the
 * DELETE the orphan cleanup issues.
 */
private class OrphanMintRelayHttp : MintingRelay(
    // 507 = inbox limit — TERMINAL, so the second mint gives up at once.
    mintReply = { n ->
        if (n == 1) HttpResult(code = 201, body = ORPHAN_MINT_BODY, isSuccess = true)
        else HttpResult(code = 507, body = """{"error":"inbox limit"}""", isSuccess = false)
    },
    challengeBody = ORPHAN_CHALLENGE_BODY,
    putReply = dropped(),
    // The relay base GET is the mint warm-gate probe; a live code passes it at once.
    onGet = { gone() },
    deleteReply = ok(),
) {
    val deletes: List<Pair<String, Map<String, String>>> get() = deleteCalls
}

private val ORPHAN_CHALLENGE_BODY = POW_CHALLENGE_BODY
private const val ORPHAN_MINT_BODY =
    """{"inboxId":"$ROT_INBOX_MAIN","readCapability":"$ROT_CAP_MAIN","writeCapability":"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC","expiresAt":12345}"""

class MintPairOrphanCleanupTest {

    @Test
    fun ctlMintFails_destroysTheOrphanedMainInbox() = runTest {
        // The main inbox was minted but the pair is abandoned: it is unpersisted and
        // unshared, so destroying it is unambiguous — otherwise a failed pairing
        // attempt leaves a live, drainable inbox parked on the relay for a year.
        val http = OrphanMintRelayHttp()
        val mgr = MessageManager(InMemoryVault(), RELAY, http)

        assertNull(mgr.mintInboxPair())

        assertEquals(1, http.deletes.size, "the orphaned main inbox must be deleted")
        assertEquals("$RELAY/inbox/$ROT_INBOX_MAIN", http.deletes.single().first)
        assertEquals(ROT_CAP_MAIN, http.deletes.single().second["X-Read-Capability"])
    }
}

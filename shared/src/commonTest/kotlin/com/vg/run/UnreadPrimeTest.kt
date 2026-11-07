package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

// ---------------------------------------------------------------------------
// Connect-time UNREAD PRIME — MessageManager.peekInboxRef /
// MessageManager.inboundTextPeekTargets / GroupManager.primeUnreadCounts.
//
// The one-shot bounded-parallel /peek burst fired the instant the transport is
// wired, so the contact-list "message waiting" dot appears in ~one round-trip
// instead of after a full sequential jittered sweep. The properties pinned here
// are the ones that make it safe rather than merely fast:
//
//   • it PEEKS, never drains (a bare GET /inbox/{id} destroys queued messages);
//   • every vault read happens in the up-front snapshot — the parallel workers
//     touch no vault at all (VaultDatabase thread-safety under concurrent
//     access is unproven on both platforms);
//   • concurrency is BOUNDED (6a0c138: unbounded bursts over one Tor circuit
//     were tried and reverted), and a caller cannot widen it;
//   • emission is MERGE-ONLY (a failed peek emits nothing — never a 0 that
//     would blank a live dot) and STRICTLY SERIAL (the platform drivers merge
//     with no lock of their own);
//   • it makes no vault WRITE either — the W2 lease re-stamp stays with the
//     steady-state peekInbox, which is the regression this pins.
// ---------------------------------------------------------------------------

/**
 * URL-aware relay double: answers `{"pending":N}` keyed by the inbox id in the
 * `/peek` url, 404s anything in [reject], and records the peak number of
 * SIMULTANEOUS in-flight requests so the concurrency bound is observable.
 * [holdMs] keeps each request in flight long enough for overlap to be possible.
 *
 * Thread-safe by construction: it is called from several worker threads at once,
 * which is the entire point of these tests (plain maps/counters race on Native).
 */
private class PrimeRelay(
    pendingByInbox: Map<String, Int>,
    reject: Set<String> = emptySet(),
    holdMs: Long = 0L,
    // Read at the moment the FIRST request lands, so a test can assert that no
    // vault read happened after the fan-out began.
    private val vaultReadsNow: () -> Int = { 0 },
) : PeekCountRelay(pendingByInbox.toMutableMap(), reject, unknownPending = 0, peekOnly = true, holdMs = holdMs) {
    private var vaultReadsAtFirstRequest = -1

    fun urlsSeen(): List<String> = requestsOf("GET").map { it.url }
    fun peak(): Int = peakConcurrentPeeks
    fun vaultReadsWhenFanOutStarted(): Int = lock.withLock { vaultReadsAtFirstRequest }

    override fun onGetRequest(r: FakeRelayHttp.Request): HttpResult {
        lock.withLock { if (vaultReadsAtFirstRequest < 0) vaultReadsAtFirstRequest = vaultReadsNow() }
        return super.onGetRequest(r)
    }
}

/** Counts every vault READ, from any thread — see [PrimeRelay.vaultReadsNow]. */
private class CountingVault : InMemoryVault() {
    private val countLock = SyncLock()
    private var reads = 0
    fun readCount(): Int = countLock.withLock { reads }
    private fun note() = countLock.withLock { reads++ }
    override fun getAllContacts(): List<ContactRecord> { note(); return super.getAllContacts() }
    override fun getContact(contactId: String): ContactRecord? { note(); return super.getContact(contactId) }
    override fun getInboxIdForContact(contactId: String, direction: String): InboxIdRecord? {
        note(); return super.getInboxIdForContact(contactId, direction)
    }
    override fun getMeta(key: String): String? { note(); return super.getMeta(key) }
}

/** 32-char base64url-alphabet inbox id derived from [tag]. */
private fun inbox(tag: String) = ("in$tag".padEnd(32, 'A')).take(32)

private fun seedPeekable(
    vault: InMemoryVault,
    contactId: String,
    inboxId: String = inbox(contactId),
    cap: String? = "R".repeat(43),
    expiresAt: Long = Long.MAX_VALUE,
) {
    vault.insertContact(ContactRecord(contactId, generateSecureRandom(32), 1, "A-$contactId", 0L))
    vault.insertInboxId(InboxIdRecord(
        inboxId = inboxId, contactId = contactId, createdAt = 1L,
        expiresAt = expiresAt, direction = "inbound", cap = cap,
    ))
}

// ---------------------------------------------------------------------------
// peekInboxRef — the pure-HTTP core
// ---------------------------------------------------------------------------

class PeekInboxRefTest {

    @Test
    fun parsesPendingCount_fromTheNonDestructivePeekEndpoint() {
        val id = inbox("ref1")
        val relay = PrimeRelay(mapOf(id to 4))
        val mgr = MessageManager(InMemoryVault(), "http://relay.test", relay)
        assertEquals(4, mgr.peekInboxRef(id, "R".repeat(43)))
        assertEquals(1, relay.urlsSeen().size)
        assertTrue(
            relay.urlsSeen()[0].endsWith("/inbox/$id/peek"),
            "must hit /peek — a bare GET /inbox/{id} DRAINS the queued messages it is counting",
        )
    }

    @Test
    fun needsNoVaultAtAll() {
        // The vault is deliberately EMPTY: no contact, no inbox row. peekInboxRef
        // works off the caller's snapshot alone, which is what makes it safe to run
        // from several coroutines at once.
        val id = inbox("ref2")
        val mgr = MessageManager(InMemoryVault(), "http://relay.test", PrimeRelay(mapOf(id to 7)))
        assertEquals(7, mgr.peekInboxRef(id, "R".repeat(43)))
    }

    @Test
    fun relayRejection_isNullNotZero() {
        val id = inbox("ref3")
        val mgr = MessageManager(InMemoryVault(), "http://relay.test", PrimeRelay(emptyMap(), reject = setOf(id)))
        // 404 = gone / wrong cap / locked / mid-rotation. "Unknown", never "zero".
        assertNull(mgr.peekInboxRef(id, "R".repeat(43)))
    }

    @Test
    fun malformedCapOrInboxId_isRefusedBeforeAnyNetworkCall() {
        val relay = PrimeRelay(emptyMap())
        val mgr = MessageManager(InMemoryVault(), "http://relay.test", relay)
        // CRLF in a value bound for an HTTP header (the injection guard).
        assertNull(mgr.peekInboxRef(inbox("ref4"), "bad\r\nX-Evil: 1"))
        assertNull(mgr.peekInboxRef("", "R".repeat(43)))
        assertNull(mgr.peekInboxRef("not-a-valid-inbox-id", "R".repeat(43)))
        assertTrue(relay.urlsSeen().isEmpty(), "a malformed ref must never reach the transport")
    }

    @Test
    fun doesNotRestampTheLease_butPeekInboxStillDoes() {
        // W2 lease re-stamp = a vault WRITE. peekInbox (steady state) keeps it;
        // peekInboxRef must not, because its callers run in parallel.
        val id = inbox("ref5")
        val refVault = InMemoryVault()
        seedPeekable(refVault, "c1", id, expiresAt = 1L)
        val refMgr = MessageManager(refVault, "http://relay.test", PrimeRelay(mapOf(id to 1)))
        assertEquals(1, refMgr.peekInboxRef(id, "R".repeat(43)))
        assertEquals(1L, refVault.inboxes.first { it.inboxId == id }.expiresAt, "peekInboxRef must write nothing")

        val sweepVault = InMemoryVault()
        seedPeekable(sweepVault, "c1", id, expiresAt = 1L)
        val sweepMgr = MessageManager(sweepVault, "http://relay.test", PrimeRelay(mapOf(id to 1)))
        assertEquals(1, sweepMgr.peekInbox("c1"))
        assertTrue(
            sweepVault.inboxes.first { it.inboxId == id }.expiresAt > 1L,
            "peekInbox must keep renewing the informational lease (W2 regression guard)",
        )
    }

    @Test
    fun peekInbox_stillReturnsNull_onAnUnparsableButSuccessfulBody() {
        // Refactor guard: a 2xx with no readable `pending` is still proof-of-life
        // (the lease is re-stamped) but yields no count.
        val id = inbox("ref6")
        val vault = InMemoryVault()
        seedPeekable(vault, "c1", id, expiresAt = 1L)
        val relay = FakeRelayHttp(
            onPost = { HttpResult(202, "", true) },
            onPut = { HttpResult(202, "", true) },
            onGet = { HttpResult(code = 200, body = """{"unexpected":"shape"}""", isSuccess = true) },
        )
        val mgr = MessageManager(vault, "http://relay.test", relay)
        assertNull(mgr.peekInbox("c1"))
        assertTrue(vault.inboxes.first { it.inboxId == id }.expiresAt > 1L, "a 2xx still proves the inbox live")
    }
}

// ---------------------------------------------------------------------------
// inboundTextPeekTargets — the up-front snapshot
// ---------------------------------------------------------------------------

class InboundTextPeekTargetsTest {

    @Test
    fun carriesContactIdInboxAndCap_forEveryHealthyContact() {
        val vault = InMemoryVault()
        seedPeekable(vault, "alice")
        seedPeekable(vault, "bob")
        val mgr = MessageManager(vault, "http://relay.test", PrimeRelay(emptyMap()))
        val targets = mgr.inboundTextPeekTargets()
        assertEquals(setOf("alice", "bob"), targets.map { it.contactId }.toSet())
        assertEquals(setOf(inbox("alice"), inbox("bob")), targets.map { it.inboxId }.toSet())
        assertTrue(targets.all { it.readCap == "R".repeat(43) })
    }

    @Test
    fun skipsBlockedContacts() {
        val vault = InMemoryVault()
        seedPeekable(vault, "keep")
        seedPeekable(vault, "blocked")
        val mgr = MessageManager(vault, "http://relay.test", PrimeRelay(emptyMap()))
        // A blocked contact's inbox is never even resolved for polling.
        assertEquals(listOf("keep"), mgr.inboundTextPeekTargets(setOf("blocked")).map { it.contactId })
    }

    @Test
    fun skipsContactsWithNothingPeekable() {
        val vault = InMemoryVault()
        seedPeekable(vault, "healthy")
        // No inbound inbox at all (pairing still pending).
        vault.insertContact(ContactRecord("no-inbox", generateSecureRandom(32), 1, "a", 0L))
        // Inbound row with no capability (legacy/stale — needs a re-pair).
        seedPeekable(vault, "no-cap", inbox("nocap"), cap = null)
        // Pre-migration UUID-shaped inbox id: fails isValidInboxId.
        seedPeekable(vault, "legacy-id", "0f8c3a11-1111-2222-3333-444455556666")
        val mgr = MessageManager(vault, "http://relay.test", PrimeRelay(emptyMap()))
        assertEquals(listOf("healthy"), mgr.inboundTextPeekTargets().map { it.contactId })
    }

    @Test
    fun neverIncludesTheControlInbox() {
        val vault = InMemoryVault()
        seedPeekable(vault, "alice")
        vault.insertInboxId(InboxIdRecord(
            inboxId = inbox("ctlalice"), contactId = "alice", createdAt = 1L,
            expiresAt = Long.MAX_VALUE, direction = MessageManager.DIR_INBOUND_CTL, cap = "C".repeat(43),
        ))
        val mgr = MessageManager(vault, "http://relay.test", PrimeRelay(emptyMap()))
        // The control inbox is drained every background cycle, so it never
        // accumulates and is not user-visible "unread".
        assertEquals(listOf(inbox("alice")), mgr.inboundTextPeekTargets().map { it.inboxId })
    }

    @Test
    fun readCapIsNeverPrintedByToString() {
        val vault = InMemoryVault()
        seedPeekable(vault, "alice")
        val mgr = MessageManager(vault, "http://relay.test", PrimeRelay(emptyMap()))
        val rendered = mgr.inboundTextPeekTargets().first().toString()
        assertFalse(rendered.contains("R".repeat(43)), "the inbox OWNER capability must never reach a log line")
        assertTrue(rendered.contains("redacted"))
    }
}

// ---------------------------------------------------------------------------
// primeUnreadCounts — the bounded-parallel pass
// ---------------------------------------------------------------------------

class PrimeUnreadCountsTest {

    private fun contacts(n: Int) = (1..n).map { "c$it" }

    @Test
    fun emitsOnePerContact_withTheRelayCount() = runTest {
        val vault = InMemoryVault()
        contacts(3).forEach { seedPeekable(vault, it) }
        val relay = PrimeRelay(mapOf(inbox("c1") to 2, inbox("c2") to 0, inbox("c3") to 5))
        val gm = GroupManager(vault) { MessageManager(vault, "http://relay.test", relay) }

        val seen = mutableMapOf<String, Int>()
        gm.primeUnreadCounts(emptySet()) { id, n -> seen[id] = n }

        // A genuine 0 IS emitted (unlike peekUnreadCounts, which omits it): the
        // driver merges "no messages waiting" as an authoritative absence.
        assertEquals(mapOf("c1" to 2, "c2" to 0, "c3" to 5), seen)
    }

    @Test
    fun failedPeekEmitsNothingForThatContact() = runTest {
        val vault = InMemoryVault()
        contacts(2).forEach { seedPeekable(vault, it) }
        val relay = PrimeRelay(mapOf(inbox("c1") to 3), reject = setOf(inbox("c2")))
        val gm = GroupManager(vault) { MessageManager(vault, "http://relay.test", relay) }

        val seen = mutableMapOf<String, Int>()
        gm.primeUnreadCounts(emptySet()) { id, n -> seen[id] = n }

        // MERGE-ONLY. c2's peek 404'd — which is also what an in-flight read-cap
        // rotation looks like — so it gets NO callback at all, rather than a 0 that
        // would blank a dot the steady-state sweep may already have set.
        assertEquals(mapOf("c1" to 3), seen)
    }

    @Test
    fun subtractsGroupPending_andClampsAtZero() = runTest {
        val vault = InMemoryVault()
        seedPeekable(vault, "c-bob")
        val relay = PrimeRelay(mapOf(inbox("c-bob") to 2))
        val mgr = MessageManager(vault, "http://relay.test", relay)
        val gm = GroupManager(vault) { mgr }
        // Two group texts announced on bob's TEXT inbox (KIND_ACTIVITY): they
        // belong to the group dot, not the 1:1 one.
        val gid = GroupManager.newGroupId()
        val me = "0000000000000001"
        vault.insertGroup(GroupRecord(gid, "crew", 1, adminMemberId = me, myMemberId = me, createdAt = 0L))
        vault.insertGroupMember(GroupMemberRecord(gid, me, null, 0L))
        vault.insertGroupMember(GroupMemberRecord(gid, "0000000000000002", "c-bob", 0L))
        repeat(3) { gm.handleControl("c-bob", gid, GroupManager.KIND_ACTIVITY, "{}") }

        val seen = mutableMapOf<String, Int>()
        gm.primeUnreadCounts(emptySet()) { id, n -> seen[id] = n }

        // 2 pending on the relay, 3 of them attributed to the group → clamped to 0,
        // still emitted (the peek SUCCEEDED, so the absence is authoritative).
        assertEquals(mapOf("c-bob" to 0), seen)
    }

    @Test
    fun blockedContactIsNeitherPolledNorEmitted() = runTest {
        val vault = InMemoryVault()
        seedPeekable(vault, "keep")
        seedPeekable(vault, "blocked")
        val relay = PrimeRelay(mapOf(inbox("keep") to 1, inbox("blocked") to 9))
        val gm = GroupManager(vault) { MessageManager(vault, "http://relay.test", relay) }

        val seen = mutableMapOf<String, Int>()
        gm.primeUnreadCounts(setOf("blocked")) { id, n -> seen[id] = n }

        assertEquals(mapOf("keep" to 1), seen)
        assertEquals(1, relay.urlsSeen().size, "a blocked contact's inbox must not be polled at all")
        assertTrue(relay.urlsSeen()[0].contains(inbox("keep")))
    }

    @Test
    fun concurrencyIsBoundedAtThree() = runTest {
        val vault = InMemoryVault()
        contacts(9).forEach { seedPeekable(vault, it) }
        // Each request is held briefly so overlap is actually possible; without the
        // Semaphore this would peak at 9.
        val relay = PrimeRelay(contacts(9).associate { inbox(it) to 1 }, holdMs = 25L)
        val gm = GroupManager(vault) { MessageManager(vault, "http://relay.test", relay) }

        var emitted = 0
        gm.primeUnreadCounts(emptySet()) { _, _ -> emitted++ }

        assertEquals(9, emitted)
        // 6a0c138: unbounded concurrent bursts over one Tor circuit were tried and
        // reverted as unreliable. Only the UPPER bound is asserted — the lower one
        // would depend on how many cores the test host has.
        assertTrue(
            relay.peak() <= GroupManager.PRIME_CONCURRENCY,
            "peak in-flight ${relay.peak()} exceeded the bound ${GroupManager.PRIME_CONCURRENCY}",
        )
    }

    @Test
    fun callerCannotWidenTheConcurrencyBound() = runTest {
        val vault = InMemoryVault()
        contacts(8).forEach { seedPeekable(vault, it) }
        val relay = PrimeRelay(contacts(8).associate { inbox(it) to 1 }, holdMs = 25L)
        val gm = GroupManager(vault) { MessageManager(vault, "http://relay.test", relay) }

        // A caller asking for 32 is CLAMPED to the ceiling, not obeyed.
        gm.primeUnreadCounts(emptySet(), maxConcurrency = 32) { _, _ -> }
        assertTrue(relay.peak() <= GroupManager.PRIME_CONCURRENCY, "maxConcurrency must be a clamp, not a request")
    }

    @Test
    fun zeroOrNegativeConcurrency_stillCompletes() = runTest {
        // Semaphore(0) would deadlock the whole pass (and, on iOS, never fire
        // onComplete) — the clamp's lower bound is what stops that.
        val vault = InMemoryVault()
        contacts(2).forEach { seedPeekable(vault, it) }
        val relay = PrimeRelay(contacts(2).associate { inbox(it) to 1 })
        val gm = GroupManager(vault) { MessageManager(vault, "http://relay.test", relay) }

        var emitted = 0
        gm.primeUnreadCounts(emptySet(), maxConcurrency = 0) { _, _ -> emitted++ }
        assertEquals(2, emitted)
    }

    @Test
    fun callbackIsInvokedStrictlySerially() = runTest {
        val vault = InMemoryVault()
        contacts(9).forEach { seedPeekable(vault, it) }
        val relay = PrimeRelay(contacts(9).associate { inbox(it) to 1 })
        val gm = GroupManager(vault) { MessageManager(vault, "http://relay.test", relay) }

        val lock = SyncLock()
        var inCallback = 0
        var overlapped = false
        var total = 0
        gm.primeUnreadCounts(emptySet()) { _, _ ->
            lock.withLock { inCallback++; if (inCallback > 1) overlapped = true }
            sleepMillis(5)   // widen the window a missing emission mutex would expose
            lock.withLock { inCallback--; total++ }
        }

        assertEquals(9, total)
        // The platform drivers merge into shared UI state with NO lock of their own,
        // so two workers must never be inside the callback at once.
        assertFalse(overlapped, "onContactUnread was invoked concurrently")
    }

    @Test
    fun noVaultReadHappensOnceTheFanOutHasStarted() = runTest {
        // PRECONDITION: no groups in this vault, so the pass's control pre-drain
        // (GroupManager.drainGroupMemberControlsForPrime) has no target and issues no
        // request — the FIRST request the relay sees is therefore the fan-out's first
        // peek, which is what makes the snapshot comparison below meaningful. Seed a
        // group here and this stops measuring what it claims to.
        val vault = CountingVault()
        contacts(6).forEach { seedPeekable(vault, it) }
        val relay = PrimeRelay(
            contacts(6).associate { inbox(it) to 1 },
            holdMs = 10L,
            vaultReadsNow = { vault.readCount() },
        )
        val gm = GroupManager(vault) { MessageManager(vault, "http://relay.test", relay) }

        gm.primeUnreadCounts(emptySet()) { _, _ -> }

        // The snapshot is complete BEFORE the first request leaves, and the workers
        // add nothing to it. DatabaseManager / IosVaultDatabase thread-safety under
        // concurrent access is unproven — this prime must not be its first
        // concurrent caller.
        assertEquals(
            relay.vaultReadsWhenFanOutStarted(), vault.readCount(),
            "a vault read happened after the fan-out began — the workers must be vault-free",
        )
    }

    @Test
    fun noTransport_isASilentNoOp() = runTest {
        val vault = InMemoryVault()
        contacts(2).forEach { seedPeekable(vault, it) }
        val gm = GroupManager(vault) { null }   // Tor still bootstrapping

        var emitted = 0
        gm.primeUnreadCounts(emptySet()) { _, _ -> emitted++ }
        assertEquals(0, emitted)
    }

    @Test
    fun noContacts_isANoOp() = runTest {
        val vault = InMemoryVault()
        val relay = PrimeRelay(emptyMap())
        val gm = GroupManager(vault) { MessageManager(vault, "http://relay.test", relay) }

        var emitted = 0
        gm.primeUnreadCounts(emptySet()) { _, _ -> emitted++ }
        assertEquals(0, emitted)
        assertTrue(relay.urlsSeen().isEmpty())
    }

    @Test
    fun aThrowingCallbackNeverFailsThePass() = runTest {
        val vault = InMemoryVault()
        contacts(3).forEach { seedPeekable(vault, it) }
        val relay = PrimeRelay(contacts(3).associate { inbox(it) to 1 })
        val gm = GroupManager(vault) { MessageManager(vault, "http://relay.test", relay) }

        var attempts = 0
        gm.primeUnreadCounts(emptySet()) { _, _ ->
            attempts++
            throw IllegalStateException("driver blew up")
        }
        // One contact's badge is never worth failing the prime (or crossing the
        // Swift bridge with an exception).
        assertEquals(3, attempts)
        assertEquals(3, relay.urlsSeen().size)
    }

    @Test
    fun everyPeekUsesTheNonDestructivePeekEndpoint() = runTest {
        // No groups → no control pre-drain, so every url recorded here belongs to the
        // text-peek fan-out. (The pre-drain's own control DRAIN is a bare GET by
        // design and is covered in UnreadPrimeControlFirstTest.)
        val vault = InMemoryVault()
        contacts(4).forEach { seedPeekable(vault, it) }
        val relay = PrimeRelay(contacts(4).associate { inbox(it) to 1 })
        val gm = GroupManager(vault) { MessageManager(vault, "http://relay.test", relay) }

        gm.primeUnreadCounts(emptySet()) { _, _ -> }

        assertEquals(4, relay.urlsSeen().size)
        assertTrue(
            relay.urlsSeen().all { it.endsWith("/peek") },
            "a bare GET /inbox/{id} DRAINS — the prime must never touch it",
        )
    }
}

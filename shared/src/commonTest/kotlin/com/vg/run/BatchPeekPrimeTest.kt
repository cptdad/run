package com.vg.run

import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

// ---------------------------------------------------------------------------
// ONE-ROUND-TRIP CONNECT-TIME UNREAD PRIME (2026-09-20).
//
// The prime used to cost one sequential control round trip per group member plus
// a 3-wide /peek fan-out over every contact — all on the coldest circuit of the
// session, all inside the wait before the contact list appears.
// MessageManager.peekInboxesBatch asks the relay for every one of those depths in
// a single `POST /peek`.
//
// What is pinned here is what makes that SAFE rather than merely fast:
//
//   • ONE request really does replace the whole pass — no per-inbox GET /peek,
//     and a control inbox the batch reported EMPTY is not drained at all;
//   • an OLD relay (404/405 on the route) falls back to the pre-batch path and
//     costs exactly ONE wasted round trip per transport, never one per prime;
//   • a per-item `status` is UNKNOWN, never zero: that control inbox is still
//     DRAINED and that text inbox emits NOTHING (merge-only);
//   • a transport failure is UNKNOWN for every ref — the pass falls back, it
//     never "assumes empty";
//   • the control drains the batch identified are applied BEFORE any unread count
//     is emitted, so a group text still lights the GROUP dot and not the sender's
//     1:1 dot (the 2026-09-05 production bug, pinned for the sequential pre-drain
//     by UnreadPrimeControlFirstTest and re-pinned here for the batch);
//   • the request CHUNKS at 64 items, the relay's ceiling.
//
// Anti-vacuity: every test asserts the relay's REQUESTS (method, url, and for the
// batch its BODY — the exact item set), not merely the outcome.
// ---------------------------------------------------------------------------

/** 32-char base64url-alphabet inbox id derived from [tag] (the real shape). */
private fun bpInbox(tag: String) = ("bp$tag".padEnd(32, 'A')).take(32)

private const val BP_CAP = "RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR"

/**
 * Relay double that implements BOTH peek routes plus the destructive control
 * drain, and records every request it was asked to serve.
 *
 *  - `POST /peek`            — the batch. Answers one result per requested id, in
 *                              request order: `pending` for an inbox it knows,
 *                              `status` for one declared unknown, and `status:404`
 *                              for an id it has never heard of.
 *  - `GET /inbox/{id}/peek`  — the single peek (the pre-batch path).
 *  - `GET /inbox/{id}`       — the DESTRUCTIVE drain (control inboxes only here).
 *
 * Thread-safe: the fallback path peeks from several worker coroutines at once.
 */
private class BatchRelay : PeekCountRelay(notFoundBody = """{"error":"gone"}""") {
    private val statusItems = mutableMapOf<String, Int>()

    /** Non-2xx (or unsupported) answer for the batch route; null = serve it. */
    var batchCode: Int? = null
    /** Transport-level failure of the batch route (throws, like a dead circuit). */
    var batchThrows = false
    /** 2xx with a body the client cannot read. */
    var batchGarbageBody = false

    init {
        onPost = { r -> if (r.url.endsWith("/peek")) batchReply(r) else RELAY_OK_202 }
    }

    /** This inbox answers with `status` in the batch (and 404 on the single peek). */
    fun answerStatus(inboxId: String, code: Int) {
        lock.withLock { statusItems[inboxId] = code }
        reject(inboxId)
    }

    /** The batch POSTs and every GET, as "VERB url", in order. */
    fun calls(): List<String> = requests
        .filter { it.method == "GET" || (it.method == "POST" && it.url.endsWith("/peek")) }
        .map { "${it.method} ${it.url}" }
    fun batchBodies(): List<String> = requestsOf("POST").filter { it.url.endsWith("/peek") }.map { it.bodyText }
    fun batchPosts(): Int = calls().count { it.startsWith("POST ") }
    fun singlePeeks(): List<String> = calls().filter { it.endsWith("/peek") && it.startsWith("GET ") }
    fun drains(): List<String> = calls().filter { it.startsWith("GET ") && !it.endsWith("/peek") }

    private fun batchReply(r: FakeRelayHttp.Request): HttpResult {
        val text = r.bodyText
        if (batchThrows) throw IllegalStateException("transport died")
        batchCode?.let {
            return HttpResult(code = it, body = """{"error":"nope"}""", isSuccess = it in 200..299)
        }
        if (batchGarbageBody) return HttpResult(code = 200, body = "not json at all", isSuccess = true)
        assertEquals("application/json", r.contentType, "the batch body is JSON, not a blob")
        val results = idsIn(text).joinToString(",") { id ->
            val status = lock.withLock { statusItems[id] }
            val n = pendingOf(id)
            when {
                status != null -> """{"id":"$id","status":$status}"""
                n == null -> """{"id":"$id","status":404}"""
                else -> """{"id":"$id","pending":$n}"""
            }
        }
        return HttpResult(code = 200, body = """{"v":1,"results":[$results]}""", isSuccess = true)
    }
}

/**
 * Pulls the `"id"` values out of a batch body with a scan that shares NO code with
 * the production writer — so a body the client never actually built cannot satisfy
 * these tests.
 */
private fun idsIn(body: String): List<String> {
    val out = mutableListOf<String>()
    var from = 0
    while (true) {
        val k = body.indexOf("\"id\":\"", from)
        if (k < 0) return out
        val start = k + 6
        val end = body.indexOf('"', start)
        if (end < 0) return out
        out.add(body.substring(start, end))
        from = end
    }
}

/** Same, for the `"rc"` capability values. */
private fun capsIn(body: String): List<String> {
    val out = mutableListOf<String>()
    var from = 0
    while (true) {
        val k = body.indexOf("\"rc\":\"", from)
        if (k < 0) return out
        val start = k + 6
        val end = body.indexOf('"', start)
        if (end < 0) return out
        out.add(body.substring(start, end))
        from = end
    }
}

private fun seedTextContact(vault: InMemoryVault, contactId: String, inboxId: String = bpInbox(contactId)) {
    vault.insertContact(ContactRecord(contactId, generateSecureRandom(32), 1, "A-$contactId", 0L))
    vault.insertInboxId(
        InboxIdRecord(
            inboxId = inboxId, contactId = contactId, createdAt = 1L,
            expiresAt = Long.MAX_VALUE, direction = "inbound", cap = BP_CAP,
        )
    )
}

private fun seedControlInbox(vault: InMemoryVault, contactId: String, inboxId: String) {
    vault.insertInboxId(
        InboxIdRecord(
            inboxId = inboxId, contactId = contactId, createdAt = 1L,
            expiresAt = Long.MAX_VALUE, direction = MessageManager.DIR_INBOUND_CTL, cap = BP_CAP,
        )
    )
}

/** A group in which [memberContactIds] are RESOLVED members (so the prime peeks their control inboxes). */
private fun seedGroup(vault: InMemoryVault, tagBase: Int, memberContactIds: List<String>): String {
    val gid = GroupManager.newGroupId()
    val me = bytesToHex(ByteArray(8) { (tagBase + 1).toByte() })
    vault.insertGroup(GroupRecord(gid, "g$tagBase", 1, adminMemberId = me, myMemberId = me, createdAt = 0L))
    vault.insertGroupMember(GroupMemberRecord(gid, me, null, 0L))
    for ((i, cid) in memberContactIds.withIndex()) {
        vault.insertGroupMember(
            GroupMemberRecord(gid, bytesToHex(ByteArray(8) { (tagBase * 16 + i + 2).toByte() }), cid, 0L)
        )
    }
    return gid
}

class BatchPeekPrimeTest {

    @BeforeTest
    fun setUp() = ConnectionLog.clear()

    @AfterTest
    fun tearDown() = ConnectionLog.clear()

    // -----------------------------------------------------------------------
    // 1. One round trip for the whole pass
    // -----------------------------------------------------------------------

    @Test
    fun batchPeek_oneRoundTripPrimesEveryContact() = runTest {
        val vault = InMemoryVault()
        val relay = BatchRelay()
        val contacts = (1..12).map { "c$it" }
        contacts.forEach { seedTextContact(vault, it); relay.setTextPending(bpInbox(it), 2) }
        // Three groups; six of the twelve contacts are resolved members, so their
        // CONTROL inboxes are part of the same single request.
        val groupMembers = listOf(
            listOf("c1", "c2"), listOf("c3", "c4"), listOf("c5", "c6"),
        )
        groupMembers.forEachIndexed { i, members -> seedGroup(vault, i + 1, members) }
        val controlInboxes = groupMembers.flatten().map { cid ->
            val ctl = bpInbox("ctl$cid")
            seedControlInbox(vault, cid, ctl)
            relay.declareControlInbox(ctl)     // empty: nothing to drain
            ctl
        }
        val mgr = MessageManager(vault, "http://relay.test", relay)
        val gm = GroupManager(vault) { mgr }

        val seen = mutableMapOf<String, Int>()
        gm.primeUnreadCounts(emptySet()) { id, n -> seen[id] = n }

        // THE HEADLINE: the entire pass is ONE relay request.
        assertEquals(1, relay.batchPosts(), "the whole prime must be one POST: ${relay.calls()}")
        assertTrue(
            relay.singlePeeks().isEmpty(),
            "no per-inbox GET /peek may survive the batch: ${relay.calls()}",
        )
        assertTrue(
            relay.drains().isEmpty(),
            "a control inbox the batch reported EMPTY must not be drained: ${relay.calls()}",
        )
        assertEquals(1, relay.calls().size, "exactly one relay request for the whole prime")

        // Every contact got its dot.
        assertEquals(contacts.associateWith { 2 }, seen)

        // The BODY carried exactly the union of both inbox sets, once each, with
        // their capabilities — not merely "a request happened".
        val body = relay.batchBodies().single()
        assertTrue(body.startsWith("""{"v":1,"items":["""), "unexpected batch body: $body")
        val ids = idsIn(body)
        assertEquals(18, ids.size, "12 text + 6 control inboxes")
        assertEquals(ids.size, ids.toSet().size, "no inbox may be asked about twice")
        assertEquals(
            (contacts.map { bpInbox(it) } + controlInboxes).toSet(), ids.toSet(),
            "the batch must cover exactly the inboxes the two snapshots resolved",
        )
        assertEquals(List(18) { BP_CAP }, capsIn(body), "every item must carry its read capability")
    }

    @Test
    fun batchPeek_panelLineCountsAndSecondsOnly() = runTest {
        val vault = InMemoryVault()
        val relay = BatchRelay()
        listOf("alice", "bob").forEach { seedTextContact(vault, it); relay.setTextPending(bpInbox(it), 1) }
        val gm = GroupManager(vault) { MessageManager(vault, "http://relay.test", relay) }
        var reads = 0
        gm.clockMs = { if (reads++ == 0) 10_000L else 13_400L }

        gm.primeUnreadCounts(emptySet()) { _, _ -> }

        val texts = ConnectionLog.snapshot()
            .filter { it.code == ConnectionLog.Code.PRIME_PASS }
            .map { it.text }
        assertTrue(
            texts.any { it.startsWith("unread prime batch: 2 inboxes in ") && it.endsWith(" s") },
            "the batch line must report counts and seconds: $texts",
        )
        // The existing bracket lines are kept.
        assertTrue(texts.any { it == "unread prime started: 2 inboxes" }, texts.toString())
        assertTrue(texts.any { it.startsWith("unread prime done: 2/2 answered in ") }, texts.toString())
        for (text in texts) {
            assertFalse(text.contains(bpInbox("alice")), "inbox id reached the panel: $text")
            assertFalse(text.contains(BP_CAP), "read capability reached the panel: $text")
            assertFalse(text.contains("alice"), "contact id reached the panel: $text")
            assertFalse(text.contains("relay.test"), "relay host reached the panel: $text")
        }
    }

    // -----------------------------------------------------------------------
    // 2. An old relay: fall back once, then never ask again
    // -----------------------------------------------------------------------

    @Test
    fun batchPeek_unsupportedRelayFallsBackOnce() = runTest {
        val vault = InMemoryVault()
        val relay = BatchRelay()
        relay.batchCode = 404                       // an OLD relay has no such route
        listOf("c1", "c2").forEach { seedTextContact(vault, it); relay.setTextPending(bpInbox(it), 3) }
        val mgr = MessageManager(vault, "http://relay.test", relay)
        val gm = GroupManager(vault) { mgr }

        val first = mutableMapOf<String, Int>()
        gm.primeUnreadCounts(emptySet()) { id, n -> first[id] = n }

        // The pre-batch path ran in full: every contact peeked individually, and the
        // dots are exactly what they were before the batch existed.
        assertEquals(mapOf("c1" to 3, "c2" to 3), first)
        assertEquals(1, relay.batchPosts(), "the discovery costs exactly one round trip")
        assertEquals(2, relay.singlePeeks().size, "the fallback must peek every contact: ${relay.calls()}")
        assertTrue(mgr.isBatchPeekUnsupported(), "the outcome must latch on this transport")

        val second = mutableMapOf<String, Int>()
        gm.primeUnreadCounts(emptySet()) { id, n -> second[id] = n }

        assertEquals(mapOf("c1" to 3, "c2" to 3), second)
        assertEquals(1, relay.batchPosts(), "a latched relay must never be asked again on this transport")
        assertEquals(4, relay.singlePeeks().size)
    }

    @Test
    fun batchPeek_methodNotAllowedIsAlsoUnsupported() = runTest {
        val vault = InMemoryVault()
        val relay = BatchRelay()
        relay.batchCode = 405
        seedTextContact(vault, "c1"); relay.setTextPending(bpInbox("c1"), 1)
        val mgr = MessageManager(vault, "http://relay.test", relay)
        val gm = GroupManager(vault) { mgr }

        gm.primeUnreadCounts(emptySet()) { _, _ -> }

        assertTrue(mgr.isBatchPeekUnsupported(), "405 on a GET-only path is the same signal as 404")
        assertEquals(1, relay.singlePeeks().size)
    }

    @Test
    fun batchPeek_rateLimitIsAFailure_notAnUnsupportedLatch() = runTest {
        // 429 says "not now", not "no such route". Latching it would disable the
        // batch for the whole session over one throttled request.
        val vault = InMemoryVault()
        val relay = BatchRelay()
        relay.batchCode = 429
        seedTextContact(vault, "c1"); relay.setTextPending(bpInbox("c1"), 1)
        val mgr = MessageManager(vault, "http://relay.test", relay)
        val gm = GroupManager(vault) { mgr }

        gm.primeUnreadCounts(emptySet()) { _, _ -> }
        assertFalse(mgr.isBatchPeekUnsupported())

        relay.batchCode = null
        val seen = mutableMapOf<String, Int>()
        gm.primeUnreadCounts(emptySet()) { id, n -> seen[id] = n }
        assertEquals(2, relay.batchPosts(), "the next pass must try the batch again")
        assertEquals(mapOf("c1" to 1), seen)
    }

    // -----------------------------------------------------------------------
    // 3. A per-item status is UNKNOWN, never empty
    // -----------------------------------------------------------------------

    @Test
    fun batchPeek_perItemStatusMeansUnknownNotEmpty() = runTest {
        val vault = InMemoryVault()
        val relay = BatchRelay()
        // Two contacts, both group members so both control inboxes are in the batch.
        listOf("known", "unknown").forEach { seedTextContact(vault, it) }
        relay.setTextPending(bpInbox("known"), 4)
        relay.setTextPending(bpInbox("unknown"), 7)      // the relay will refuse to say
        val ctlKnown = bpInbox("ctlknown")
        val ctlUnknown = bpInbox("ctlunknown")
        seedControlInbox(vault, "known", ctlKnown)
        seedControlInbox(vault, "unknown", ctlUnknown)
        relay.declareControlInbox(ctlKnown)              // positively EMPTY → no drain
        relay.queueControl(ctlUnknown, "not-a-blob")     // and answered with a status
        seedGroup(vault, 1, listOf("known", "unknown"))
        // The relay answers `status:404` for one text inbox and one control inbox —
        // what an in-flight read-cap rotation looks like on the single peek too.
        relay.answerStatus(bpInbox("unknown"), 404)
        relay.answerStatus(ctlUnknown, 404)
        val gm = GroupManager(vault) { MessageManager(vault, "http://relay.test", relay) }

        val seen = mutableMapOf<String, Int>()
        gm.primeUnreadCounts(emptySet()) { id, n -> seen[id] = n }

        // TEXT: merge-only. A status is not a count, and must never become a 0 that
        // blanks a dot the steady-state sweep may already have set.
        assertEquals(mapOf("known" to 4), seen)
        // CONTROL: unknown DRAINS (the blob would otherwise sit there until the next
        // sweep), while the positively-empty one is left alone.
        assertEquals(
            listOf("GET http://relay.test/inbox/$ctlUnknown?lease=1"), relay.drains(),
            "unknown must drain and empty must not: ${relay.calls()}",
        )
        assertEquals(1, relay.batchPosts())
        assertTrue(relay.singlePeeks().isEmpty(), "a status must not trigger a second peek")
    }

    // -----------------------------------------------------------------------
    // 4. A failed batch never assumes empty
    // -----------------------------------------------------------------------

    @Test
    fun batchPeek_transportFailureNeverAssumesEmpty() = runTest {
        val vault = InMemoryVault()
        val relay = BatchRelay()
        relay.batchThrows = true
        listOf("c1", "c2").forEach { seedTextContact(vault, it); relay.setTextPending(bpInbox(it), 5) }
        val mgr = MessageManager(vault, "http://relay.test", relay)
        val gm = GroupManager(vault) { mgr }

        val seen = mutableMapOf<String, Int>()
        gm.primeUnreadCounts(emptySet()) { id, n -> seen[id] = n }

        // The pass fell back and asked every inbox individually — it did NOT decide
        // the inboxes were empty, and it did not latch the route as missing.
        assertEquals(mapOf("c1" to 5, "c2" to 5), seen)
        assertEquals(2, relay.singlePeeks().size, "every ref must be re-asked: ${relay.calls()}")
        assertFalse(mgr.isBatchPeekUnsupported(), "a transport failure says nothing about the route")
    }

    @Test
    fun batchPeek_unreadableBodyFallsBack_andEmitsNothingWhenThePeeksAlsoFail() = runTest {
        val vault = InMemoryVault()
        val relay = BatchRelay()
        relay.batchGarbageBody = true                 // 2xx, unreadable
        listOf("c1", "c2").forEach { seedTextContact(vault, it) }
        relay.answerStatus(bpInbox("c1"), 404)        // …and the single peeks 404 too
        relay.answerStatus(bpInbox("c2"), 404)
        val mgr = MessageManager(vault, "http://relay.test", relay)
        val gm = GroupManager(vault) { mgr }

        val seen = mutableMapOf<String, Int>()
        gm.primeUnreadCounts(emptySet()) { id, n -> seen[id] = n }

        // NOTHING is emitted — not a single 0. "Unknown" is the one answer an
        // unreadable relay response may produce.
        assertTrue(seen.isEmpty(), "an unreadable batch plus failing peeks must emit nothing at all: $seen")
        assertEquals(2, relay.singlePeeks().size)
        assertFalse(mgr.isBatchPeekUnsupported())
    }

    // -----------------------------------------------------------------------
    // 5. Control drains apply BEFORE the text emissions
    // -----------------------------------------------------------------------

    @Test
    fun batchPeek_controlDrainsApplyBeforeTextEmission() = runTest {
        // The 2026-09-05 production bug, re-pinned for the batch path: a group text
        // rides the sender's 1:1 TEXT inbox, and only the KIND_ACTIVITY notice on
        // their CONTROL inbox says so. The batch learns both depths in one request,
        // but the notice must still be APPLIED before the count is attributed.
        if (!aeadUp()) return@runTest
        val shared = generateSecureRandom(32)
        val txt = bpInbox("txt")
        val ctl = bpInbox("ctl")

        // Sender A — only used to mint one real, AEAD-sealed activity notice.
        val aVault = InMemoryVault()
        val aHttp = RecordingRelayHttp()
        val aMgr = MessageManager(aVault, "http://relay.test", aHttp as RelayHttp)
        aVault.insertContact(ContactRecord("b", shared, 0, "B", 0L))
        aVault.insertInboxId(InboxIdRecord(txt, "b", 1L, Long.MAX_VALUE, "outbound", BP_CAP))
        aVault.insertInboxId(InboxIdRecord(ctl, "b", 1L, Long.MAX_VALUE, MessageManager.DIR_OUTBOUND_CTL, BP_CAP))

        // Receiver B — the device under test.
        val bVault = InMemoryVault()
        val relay = BatchRelay()
        bVault.insertContact(ContactRecord("a", shared, 0, "A", 0L))
        bVault.insertInboxId(InboxIdRecord(txt, "a", 1L, Long.MAX_VALUE, "inbound", BP_CAP))
        bVault.insertInboxId(InboxIdRecord(ctl, "a", 1L, Long.MAX_VALUE, MessageManager.DIR_INBOUND_CTL, BP_CAP))
        val myMemberId = bytesToHex(ByteArray(8) { 1 })
        val peerMemberId = bytesToHex(ByteArray(8) { 2 })
        val gid = GroupManager.newGroupId()
        bVault.insertGroup(GroupRecord(gid, "crew", 1, adminMemberId = myMemberId, myMemberId = myMemberId, createdAt = 0L))
        bVault.insertGroupMember(GroupMemberRecord(gid, myMemberId, null, 0L))
        bVault.insertGroupMember(GroupMemberRecord(gid, peerMemberId, "a", 0L))
        val gm = GroupManager(bVault) { MessageManager(bVault, "http://relay.test", relay) }

        // One group text waiting on the 1:1 text inbox, its notice on the control one.
        relay.setTextPending(txt, 1)
        aHttp.script(HttpResult(202, "", true))
        val hash = GroupManager.membershipHash(gid, 1, listOf(myMemberId, peerMemberId))
        assertTrue(
            aMgr.sendGroupControl("b", gid, GroupManager.KIND_ACTIVITY, "{}", hash, noPush = true),
            "the harness must be able to mint a real activity notice",
        )
        relay.queueControl(ctl, encodeBase64(aHttp.calls.last().body))

        val seen = mutableMapOf<String, Int>()
        gm.primeUnreadCounts(emptySet()) { id, n -> seen[id] = n }

        assertEquals(mapOf("a" to 0), seen, "a group text must not light the SENDER's 1:1 dot")
        assertEquals(1, gm.groupUnreadCounts()[gid], "it must light the GROUP dot instead")
        // The batch came first, then the control DRAIN; the text inbox is peeked by
        // the batch and NEVER drained (a bare GET destroys what it counts).
        val requests = relay.calls()
        assertEquals("POST http://relay.test/peek", requests.first(), "$requests")
        assertEquals(listOf("GET http://relay.test/inbox/$ctl?lease=1"), relay.drains(), "$requests")
        assertEquals(2, requests.size, "one batch + one control drain: $requests")
    }

    // -----------------------------------------------------------------------
    // 6. Chunking at the relay's 64-item ceiling
    // -----------------------------------------------------------------------

    @Test
    fun batchPeek_chunksAt64_atThreeRefsPerContact() = runTest {
        // The group inbox put THREE inboxes per contact in this body (text + control + group),
        // so the 64-item ceiling is now reached ~21 contacts in and the boundary
        // falls MID-CONTACT — 64 is not a multiple of 3. That is the shape to pin:
        // a chunker that split per contact rather than per item would either
        // over-fill a body (the relay answers 413) or drop a ref.
        val vault = InMemoryVault()
        val relay = BatchRelay()
        val contacts = (1..25).map { "c$it" }
        val allInboxes = mutableListOf<String>()
        contacts.forEach { cid ->
            seedTextContact(vault, cid); relay.setTextPending(bpInbox(cid), 1)
            val ctl = bpInbox("ctl$cid")
            seedControlInbox(vault, cid, ctl); relay.declareControlInbox(ctl)   // empty: no drain
            val grp = bpInbox("grp$cid")
            vault.insertInboxId(
                InboxIdRecord(
                    inboxId = grp, contactId = cid, createdAt = 1L,
                    expiresAt = Long.MAX_VALUE, direction = MessageManager.DIR_INBOUND_GRP, cap = BP_CAP,
                )
            )
            relay.setTextPending(grp, 0)   // exists, nothing queued
            allInboxes += listOf(bpInbox(cid), ctl, grp)
        }
        // Every contact is a RESOLVED group member, so all three refs are in scope.
        contacts.chunked(5).forEachIndexed { i, members -> seedGroup(vault, i + 1, members) }
        val gm = GroupManager(vault) { MessageManager(vault, "http://relay.test", relay) }

        val seen = mutableMapOf<String, Int>()
        gm.primeUnreadCounts(emptySet()) { id, n -> seen[id] = n }

        val total = 25 * 3
        assertEquals(2, relay.batchPosts(), "75 inboxes must ride two bodies, not one over-long one")
        val bodies = relay.batchBodies()
        assertEquals(MessageManager.BATCH_PEEK_MAX_ITEMS, idsIn(bodies[0]).size)
        assertEquals(total - MessageManager.BATCH_PEEK_MAX_ITEMS, idsIn(bodies[1]).size)
        val all = bodies.flatMap { idsIn(it) }
        assertEquals(total, all.size, "no ref may be dropped at the boundary")
        assertEquals(allInboxes.toSet(), all.toSet(), "every inbox must appear exactly once across the chunks")
        assertEquals(contacts.associateWith { 1 }, seen)
        assertTrue(relay.singlePeeks().isEmpty())
        assertTrue(relay.drains().isEmpty(), "every control inbox was positively empty")
    }

    // -----------------------------------------------------------------------
    // Guards on the batch itself
    // -----------------------------------------------------------------------

    @Test
    fun batchPeek_neverSendsAMalformedIdOrCap() {
        val relay = BatchRelay()
        val mgr = MessageManager(InMemoryVault(), "http://relay.test", relay)
        val outcome = mgr.peekInboxesBatch(
            listOf(
                MessageManager.PeekRef(bpInbox("good"), BP_CAP),
                MessageManager.PeekRef(bpInbox("crlf"), "bad\r\nX-Evil: 1"),
                MessageManager.PeekRef("not-a-valid-inbox-id", BP_CAP),
                MessageManager.PeekRef(bpInbox("nocap"), ""),
                MessageManager.PeekRef(bpInbox("good"), BP_CAP),   // duplicate
            )
        )
        assertTrue(outcome is MessageManager.BatchPeekOutcome.Counts)
        val body = relay.batchBodies().single()
        assertEquals(listOf(bpInbox("good")), idsIn(body), "only the valid, de-duplicated ref may be sent")
        assertFalse(body.contains("X-Evil"), "a header-injection shape must never reach the wire")
    }

    /** A relay whose batch answer is fixed text, whatever was asked. */
    private fun scriptedBatchRelay(answer: String) = FakeRelayHttp(
        onPost = { HttpResult(code = 200, body = answer, isSuccess = true) },
        onPut = { HttpResult(202, "", true) },
        onGet = { HttpResult(404, "", false) },
    )

    @Test
    fun batchPeek_matchesByIndex_andAMismatchedEchoIsUnknown() {
        // The relay answers one result per item IN REQUEST ORDER; the echoed id is a
        // cross-check only. An answer that names a different inbox at this position
        // must never have its count attributed to the inbox we asked about.
        val asked = bpInbox("asked")
        val forged = bpInbox("forged")
        val mgr = MessageManager(
            InMemoryVault(), "http://relay.test",
            scriptedBatchRelay("""{"v":1,"results":[{"id":"$forged","pending":9}]}"""),
        )
        val counts = (mgr.peekInboxesBatch(listOf(MessageManager.PeekRef(asked, BP_CAP)))
            as MessageManager.BatchPeekOutcome.Counts).byInboxId
        assertEquals(1, counts.size)
        assertEquals(null, counts[asked], "a mismatched echo is UNKNOWN, never the count it carried")
        assertFalse(counts.containsKey(forged), "an inbox we never asked about must not enter the map")
    }

    @Test
    fun batchPeek_anOverLongAnswerFailsClosed() {
        // More results than items is a protocol violation; the whole batch is
        // refused (→ the caller falls back and re-asks) rather than half-read.
        val asked = bpInbox("asked")
        val mgr = MessageManager(
            InMemoryVault(), "http://relay.test",
            scriptedBatchRelay("""{"v":1,"results":[{"id":"$asked","pending":2},{"id":"x","pending":9}]}"""),
        )
        assertTrue(
            mgr.peekInboxesBatch(listOf(MessageManager.PeekRef(asked, BP_CAP)))
                is MessageManager.BatchPeekOutcome.Failed,
        )
    }

    @Test
    fun batchPeek_aShortAnswerLeavesTheRestUnknown() {
        // Fewer results than items: the tail is simply ABSENT, which every caller
        // already reads as UNKNOWN (drain / emit nothing).
        val a = bpInbox("a")
        val b = bpInbox("b")
        val mgr = MessageManager(
            InMemoryVault(), "http://relay.test",
            scriptedBatchRelay("""{"v":1,"results":[{"id":"$a","pending":2}]}"""),
        )
        val counts = (mgr.peekInboxesBatch(
            listOf(MessageManager.PeekRef(a, BP_CAP), MessageManager.PeekRef(b, BP_CAP))
        ) as MessageManager.BatchPeekOutcome.Counts).byInboxId
        assertEquals(2, counts[a])
        assertFalse(counts.containsKey(b), "an unanswered ref must be absent, never 0")
    }

    @Test
    fun batchPeek_noRefs_makesNoRequest() {
        val relay = BatchRelay()
        val mgr = MessageManager(InMemoryVault(), "http://relay.test", relay)
        val outcome = mgr.peekInboxesBatch(emptyList())
        assertTrue(outcome is MessageManager.BatchPeekOutcome.Counts)
        assertEquals(0, relay.batchPosts())
    }

    @Test
    fun batchPeek_readCapIsNeverPrintedByToString() {
        val rendered = MessageManager.PeekRef(bpInbox("x"), BP_CAP).toString()
        assertFalse(rendered.contains(BP_CAP), "the inbox OWNER capability must never reach a log line")
        assertTrue(rendered.contains("redacted"))
    }
}

// ---------------------------------------------------------------------------
// The relay's answer is parsed by a bounded, regex-free, non-recursive scan.
// ---------------------------------------------------------------------------

class ParseObjectArrayFieldTest {

    @Test
    fun parsesEachElementAsItsRawObject() {
        val body = """{"v":1,"results":[{"id":"a","pending":1},{"id":"b","status":404}]}"""
        val parsed = parseObjectArrayField(body, "results", 8)
        assertEquals(listOf("""{"id":"a","pending":1}""", """{"id":"b","status":404}"""), parsed)
    }

    @Test
    fun emptyArrayParsesToNothing() {
        assertEquals(0, parseObjectArrayField("""{"results":[]}""", "results", 8)!!.size)
    }

    @Test
    fun aBraceInsideAStringNeverEndsAnElement() {
        val body = """{"results":[{"id":"}{","pending":3},{"id":"b","pending":0}]}"""
        val parsed = parseObjectArrayField(body, "results", 8)!!
        assertEquals(2, parsed.size)
        assertEquals(3, parseTopLevelJson(parsed[0])["pending"]?.text?.toInt())
    }

    @Test
    fun overCapFailsClosed() {
        val body = """{"results":[{"id":"a"},{"id":"b"},{"id":"c"}]}"""
        assertEquals(null, parseObjectArrayField(body, "results", 2))
    }

    @Test
    fun malformationFailsClosed() {
        assertEquals(null, parseObjectArrayField("""{"results":[{"id":"a"}""", "results", 8))
        assertEquals(null, parseObjectArrayField("""{"results":["a"]}""", "results", 8))
        assertEquals(null, parseObjectArrayField("""{"results":[{"id":"a}]}""", "results", 8))
        assertEquals(null, parseObjectArrayField("""{"other":[]}""", "results", 8))
    }
}

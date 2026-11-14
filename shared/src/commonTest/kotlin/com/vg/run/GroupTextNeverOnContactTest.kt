package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext

// ---------------------------------------------------------------------------
// THE INVARIANT: **a group message must NEVER put the unread bubble on the
// contact name.**
//
// Each pairing has a THIRD relay inbox so group texts and 1:1 texts land on
// DIFFERENT inboxes; this file pins the half that makes the dots follow — the
// publish rules (§4.3), the drain routing (GRP-DRAIN-1, §4.4) and the bounded
// backfill (§1.6) that converges the pairings which predate the third inbox.
//
// THE ACCEPTANCE CRITERION IS ZERO: no group-inbox signal may
// reach a contact row by ANY path. It is pinned three ways —
//
//   1. behaviourally, across the whole rollout matrix, below;
//   2. structurally, by `contactCountsFrom` / `primeUnreadCountFor` being the
//      only two functions that compute a contact number;
//   3. lexically, by `GroupTextNeverOnContactSourceGuardTest` (androidUnitTest —
//      commonTest has no filesystem), which fails if either of those bodies ever
//      mentions a group-inbox symbol.
//
// Anti-vacuity: every dot assertion here runs against a relay double that really
// queues blobs, really answers /peek with a count and really DESTROYS what a bare
// GET returns, and every count is produced by the production code path (the
// sweep, or the connect-time prime) rather than by poking a map.
// ---------------------------------------------------------------------------

/** 32-char base64url-alphabet inbox id derived from [tag] (the real shape). */
private fun gtInbox(tag: String) = ("gt$tag".padEnd(32, 'A')).take(32)

private const val GT_CAP = "QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ"
private const val GT_CAP2 = "SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS"

/**
 * Relay double with a real MODEL of the three verbs this design turns on:
 *
 *  - `POST /inbox/{id}`       — append (the blob is really stored);
 *  - `GET  /inbox/{id}/peek`  — the non-destructive count;
 *  - `GET  /inbox/{id}`       — the DESTRUCTIVE drain;
 *  - `POST /peek`             — the batch, when [batchSupported] (else 404, which
 *                               sends the prime down its pre-batch path);
 *  - `POST /inbox` (no id)    — the PoW mint handshake, so the backfill can mint.
 *
 * An inbox id it has never been told about answers 404 on every route — which is
 * exactly how a reaped inbox behaves, and what the §3.4 self-heal is armed by.
 *
 * Thread-safe: the prime peeks from several worker coroutines at once.
 */
private class GtRelay : InboxQueueRelay(
    strict = true,
    peek = true,
    postReply = HttpResult(202, "", true),
    putReply = HttpResult(202, "", true),
) {
    private val lock = SyncLock()
    private val requests = mutableListOf<String>()

    /** Answer the batch route, or 404 it (an old relay) to force the fallback. */
    var batchSupported = true

    /** Inbox ids whose single `/peek` THROWS out of the transport (a Tor timeout /
     *  socket error), as opposed to [forget]'s clean 404. Sweep-completeness tests. */
    var throwOnPeekOf: Set<String> = emptySet()

    /** What the next successful mint hands back. */
    var mintInboxId = gtInbox("minted")
    var mintReadCap = GT_CAP2
    var mintWriteCap = GT_CAP2
    var mintFails = false
    var mintCount = 0; private set

    /** Test-only: invoked inside the `POST /peek` handler, before it answers (the
     *  prime concurrency pins park or re-enter here). */
    var onBatchPeek: (() -> Unit)? = null

    fun depth(inboxId: String): Int = pending(inboxId)
    fun requests(): List<String> = lock.withLock { requests.toList() }
    fun drains(): List<String> = lock.withLock {
        requests.filter { it.startsWith("GET ") && !it.endsWith("/peek") && it.contains("/inbox/") }
    }
    fun reset() = lock.withLock { requests.clear() }

    override fun post(url: String, body: ByteArray, contentType: String, headers: Map<String, String>, timeoutSeconds: Int): HttpResult {
        lock.withLock { requests.add("POST $url") }
        return super.post(url, body, contentType, headers, timeoutSeconds)
    }

    override fun nonInboxRoute(method: String, url: String, body: ByteArray, headers: Map<String, String>): HttpResult {
        // The relay base-path GET is the mint warm-gate probe; a real relay 404s.
        if (method != "POST") return HttpResult(404, "up", false)
        if (url.endsWith("/peek")) {
            if (!batchSupported) return HttpResult(404, """{"error":"no"}""", false)
            onBatchPeek?.invoke()
            val results = gtIdsIn(body.decodeToString()).joinToString(",") { id ->
                val n = pendingOrNull(id)
                if (n == null) """{"id":"$id","status":404}""" else """{"id":"$id","pending":$n}"""
            }
            return HttpResult(200, """{"v":1,"results":[$results]}""", true)
        }
        // The mint handshake: challenge first, then the minted bundle.
        if (!headers.containsKey("X-PoW-Token")) return HttpResult(400, POW_CHALLENGE_BODY, false)
        lock.withLock { mintCount++ }
        if (mintFails) return HttpResult(507, """{"error":"server inbox limit reached"}""", false)
        declare(mintInboxId)
        return HttpResult(
            201,
            """{"inboxId":"$mintInboxId","readCapability":"$mintReadCap","writeCapability":"$mintWriteCap","expiresAt":12345}""",
            true,
        )
    }

    override fun delete(url: String, headers: Map<String, String>, timeoutSeconds: Int): HttpResult {
        lock.withLock { requests.add("DELETE $url") }
        forget(relayInboxIdOf(url))
        return HttpResult(200, "", true)
    }

    override fun get(url: String, headers: Map<String, String>, timeoutSeconds: Int): HttpResult {
        lock.withLock { requests.add("GET $url") }
        if (url.contains("/inbox/") && url.endsWith("/peek") && relayInboxIdOf(url) in throwOnPeekOf) {
            throw RuntimeException("simulated transport timeout")
        }
        return super.get(url, headers, timeoutSeconds)
    }
}

/** Pulls `"id"` values out of a batch body with a scan sharing no code with the writer. */
private fun gtIdsIn(body: String): List<String> {
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

/**
 * Sender A and receiver B over one shared secret, both fully wired for all three
 * channels, with B holding a group in which A is a RESOLVED member.
 *
 * [aHasGrpRow] / [bHasGrpRow] are independent because the rollout matrix's whole
 * point is that the two sides upgrade at different times:
 *  - `aHasGrpRow = false` ⇒ A is a LEGACY sender (cell 3): its group texts ride
 *    B's TEXT inbox and its notices carry no `gi`;
 *  - `bHasGrpRow = false` ⇒ B has no group inbox at all (the pre-backfill vault).
 */
private class GtHarness(
    aHasGrpRow: Boolean = true,
    bHasGrpRow: Boolean = true,
    extraGroups: Int = 0,
) {
    val shared = generateSecureRandom(32)
    val txtToB = gtInbox("btxt")
    val ctlToB = gtInbox("bctl")
    val grpToB = gtInbox("bgrp")
    val txtToA = gtInbox("atxt")
    val ctlToA = gtInbox("actl")
    val grpToA = gtInbox("agrp")

    val relay = GtRelay()
    val aVault = InMemoryVault()
    val aMgr = MessageManager(aVault, "http://relay.test", relay)
    val bVault = InMemoryVault()
    val bMgr = MessageManager(bVault, "http://relay.test", relay)
    val gm = GroupManager(bVault) { bMgr }.also { it.noticeGraceClockMs = { monoMs } }

    /** B's monotonic clock for the presence bump's notice grace (advanced by hand). */
    var monoMs = 1_000_000L

    val myMemberId = bytesToHex(ByteArray(8) { 1 })
    val peerMemberId = bytesToHex(ByteArray(8) { 2 })
    val gid = GroupManager.newGroupId()
    /** The extra groups A is also a member of — the multi-group bump case. */
    val otherGids = mutableListOf<String>()

    init {
        relay.declare(txtToB, ctlToB, txtToA, ctlToA)
        if (bHasGrpRow) relay.declare(grpToB)
        if (aHasGrpRow) relay.declare(grpToA)

        aVault.insertContact(ContactRecord("b", shared, 0, "B", 0L))
        aVault.insertInboxId(InboxIdRecord(txtToB, "b", 1L, Long.MAX_VALUE, "outbound", GT_CAP))
        aVault.insertInboxId(InboxIdRecord(ctlToB, "b", 1L, Long.MAX_VALUE, MessageManager.DIR_OUTBOUND_CTL, GT_CAP))
        aVault.insertInboxId(InboxIdRecord(txtToA, "b", 1L, Long.MAX_VALUE, "inbound", GT_CAP))
        aVault.insertInboxId(InboxIdRecord(ctlToA, "b", 1L, Long.MAX_VALUE, MessageManager.DIR_INBOUND_CTL, GT_CAP))
        // `aHasGrpRow` is "A is an upgraded build": it holds B's group inbox (so its
        // group text routes there) AND has one of its own that B knows about.
        if (aHasGrpRow) {
            aVault.insertInboxId(InboxIdRecord(grpToB, "b", 1L, Long.MAX_VALUE, MessageManager.DIR_OUTBOUND_GRP, GT_CAP))
            aVault.insertInboxId(InboxIdRecord(grpToA, "b", 1L, Long.MAX_VALUE, MessageManager.DIR_INBOUND_GRP, GT_CAP))
        }

        bVault.insertContact(ContactRecord("a", shared, 0, "A", 0L))
        bVault.insertInboxId(InboxIdRecord(txtToB, "a", 1L, Long.MAX_VALUE, "inbound", GT_CAP))
        bVault.insertInboxId(InboxIdRecord(ctlToB, "a", 1L, Long.MAX_VALUE, MessageManager.DIR_INBOUND_CTL, GT_CAP))
        if (bHasGrpRow) {
            bVault.insertInboxId(InboxIdRecord(grpToB, "a", 1L, Long.MAX_VALUE, MessageManager.DIR_INBOUND_GRP, GT_CAP))
        }
        bVault.insertInboxId(InboxIdRecord(txtToA, "a", 1L, Long.MAX_VALUE, "outbound", GT_CAP))
        bVault.insertInboxId(InboxIdRecord(ctlToA, "a", 1L, Long.MAX_VALUE, MessageManager.DIR_OUTBOUND_CTL, GT_CAP))
        if (aHasGrpRow) {
            bVault.insertInboxId(InboxIdRecord(grpToA, "a", 1L, Long.MAX_VALUE, MessageManager.DIR_OUTBOUND_GRP, GT_CAP))
        }

        seedGroup(gid)
        repeat(extraGroups) {
            val g = GroupManager.newGroupId()
            otherGids.add(g)
            seedGroup(g)
        }
    }

    private fun seedGroup(groupId: String) {
        bVault.insertGroup(
            GroupRecord(groupId, "crew", 1, adminMemberId = myMemberId, myMemberId = myMemberId, createdAt = 0L)
        )
        bVault.insertGroupMember(GroupMemberRecord(groupId, myMemberId, contactId = null, addedAt = 0L))
        bVault.insertGroupMember(GroupMemberRecord(groupId, peerMemberId, contactId = "a", addedAt = 0L))
    }

    fun hash(groupId: String = gid) =
        GroupManager.membershipHash(groupId, 1, listOf(myMemberId, peerMemberId))

    /** A sends one GROUP text (routed by A's own capability signal). */
    fun sendGroupText(text: String, groupId: String = gid): MessageManager.GroupTextRoute =
        aMgr.sendGroupTextRouted("b", groupId, hash(groupId), text)

    /** A sends one 1:1 text. */
    fun sendDirect(text: String): Boolean = aMgr.sendMessage("b", text)

    /** A sends the KIND_ACTIVITY notice, with or without the `gi` marker. */
    fun sendNotice(gi: Boolean, groupId: String = gid): Boolean = aMgr.sendGroupControl(
        "b", groupId, GroupManager.KIND_ACTIVITY,
        if (gi) GroupManager.ACTIVITY_BODY_GRP else "{}",
        hash(groupId), noPush = true,
    )

    /** One background control sweep on B — the path that applies the notices. */
    fun sweepControl(): Boolean = gm.pollAllControls()

    /**
     * The presence bump's NOTICE GRACE runs out with the notice still missing: the
     * clock moves past [GroupUnreadTally.NOTICE_LANDING_GRACE_MS] and the next control
     * cycle checks B's control inbox (its peek answers 0), then that cycle's unread
     * sweep — the production publish order on both platforms.
     */
    fun waitOutNoticeGrace() {
        monoMs += GroupUnreadTally.NOTICE_LANDING_GRACE_MS
        sweepControl()
        gm.contactUnreadCounts()
    }

    /** Latches B's "the relay answered once" flag without draining anything. */
    fun latchRelayRoundTrip() { bMgr.peekControlPending("a") }
}

// ---------------------------------------------------------------------------
// §4.3 — the publish rules, across the rollout matrix of §5.
// ---------------------------------------------------------------------------

class GroupTextNeverOnContactTest {

    // --- cell 1: new ↔ new, the structural case ----------------------------

    @Test
    fun newToNew_aGroupText_lightsTheGroupRowAndLeavesTheContactRowDARK() {
        if (!aeadUp()) return
        val h = GtHarness()
        assertEquals(MessageManager.GroupTextRoute.GRP, h.sendGroupText("hello crew"))
        assertTrue(h.sendNotice(gi = true))
        assertEquals(1, h.relay.depth(h.grpToB), "the text must be queued on the GROUP inbox")
        assertEquals(0, h.relay.depth(h.txtToB), "…and NOT on the text inbox")

        h.sweepControl()

        assertEquals(emptyMap(), h.gm.contactUnreadCounts(), "the contact row must never light")
        assertEquals(mapOf(h.gid to 1), h.gm.groupUnreadCounts())
    }

    @Test
    fun newToNew_aOneToOneText_stillLightsTheContactRow() {
        if (!aeadUp()) return
        val h = GtHarness()
        assertTrue(h.sendDirect("just for you"))

        assertEquals(mapOf("a" to 1), h.gm.contactUnreadCounts())
        assertTrue(h.gm.groupUnreadCounts().isEmpty())
    }

    // --- sweep completeness (2026-10-14, Android late-FCM-wake suppression) ----
    // `onSweepFinished` may report `true` ONLY when every inbox the sweep peeked
    // answered; PushWakeFreshness stamps "the app has seen every inbox" on it.

    private fun sweepCompleteness(h: GtHarness): Pair<Map<String, Int>, Boolean?> {
        var complete: Boolean? = null
        val counts = h.gm.contactUnreadCounts(onSweepFinished = { complete = it })
        return counts to complete
    }

    @Test
    fun sweepCompleteness_everyInboxAnswered_reportsComplete() {
        if (!aeadUp()) return
        val h = GtHarness()
        assertTrue(h.sendDirect("hi"))
        val (counts, complete) = sweepCompleteness(h)
        assertEquals(true, complete)
        assertEquals(mapOf("a" to 1), counts, "the callback must not change the count")
    }

    @Test
    fun sweepCompleteness_aTextPeekFails_reportsIncomplete() {
        if (!aeadUp()) return
        val h = GtHarness()
        h.relay.forget(h.txtToB)
        assertEquals(false, sweepCompleteness(h).second)
    }

    @Test
    fun sweepCompleteness_aGroupPeekFails_reportsIncomplete() {
        if (!aeadUp()) return
        val h = GtHarness()
        h.relay.forget(h.grpToB)
        assertEquals(false, sweepCompleteness(h).second)
    }

    @Test
    fun sweepCompleteness_aGroupSharingContactWithNoGroupInbox_isConservativelyIncomplete() {
        if (!aeadUp()) return
        val h = GtHarness(bHasGrpRow = false)
        assertEquals(false, sweepCompleteness(h).second)
    }

    @Test
    fun sweepCompleteness_noTransport_reportsIncomplete() {
        val gm = GroupManager(InMemoryVault()) { null }
        var complete: Boolean? = null
        assertEquals(emptyMap(), gm.contactUnreadCounts(onSweepFinished = { complete = it }))
        assertEquals(false, complete)
    }

    // Edge cases added 2026-10-15. Each must fail toward INCOMPLETE (stamp
    // withheld) — except the two that document shipped behaviour by name.

    @Test
    fun sweepCompleteness_aTextPeekThrows_reportsIncomplete() {
        // A transport exception (Tor timeout / socket error), not a clean 404:
        // peekOnce catches it and the peek answers null = unknown.
        if (!aeadUp()) return
        val h = GtHarness()
        assertTrue(h.sendDirect("hi"))
        h.relay.throwOnPeekOf = setOf(h.txtToB)
        val (counts, complete) = sweepCompleteness(h)
        assertEquals(false, complete)
        assertEquals(emptyMap(), counts, "an unknown peek must not invent a count either")
    }

    @Test
    fun sweepCompleteness_aGroupPeekThrows_reportsIncomplete() {
        if (!aeadUp()) return
        val h = GtHarness()
        h.relay.throwOnPeekOf = setOf(h.grpToB)
        assertEquals(false, sweepCompleteness(h).second)
    }

    @Test
    fun sweepCompleteness_moveFrozen_reportsIncomplete() {
        // The sweep refused by the move freeze makes no request at all, so it
        // has observed nothing: never a stamp.
        if (!aeadUp()) return
        val h = GtHarness()
        h.bVault.putMeta(MoveMetaKeys.FROZEN, "1")
        val (counts, complete) = sweepCompleteness(h)
        assertEquals(false, complete)
        assertEquals(emptyMap(), counts)
    }

    /**
     * SHIPPED BEHAVIOUR, documented by name: a FAILED control-inbox drain (404 —
     * the inbox was reaped) does NOT throw out of [GroupManager.pollAllControls],
     * so `RunViewModel`'s `controlPassOk` flag is still set, and the unread sweep's
     * own completeness is judged on the TEXT + GROUP peeks alone. The stamp is
     * therefore NOT withheld by a lost control drain. Rationale as shipped: the
     * control channel carries no user-visible "unread" (it is drained, never
     * peeked, and a wake for a control append is `X-No-Push`), so its failure
     * says nothing about whether a text wake is stale. If that rationale ever
     * changes, this is the test to flip.
     */
    @Test
    fun sweepCompleteness_aFailedControlDrain_doesNotWithholdTheStamp_shippedBehaviour() {
        if (!aeadUp()) return
        val h = GtHarness()
        h.relay.forget(h.ctlToB)
        // The control pass returns normally (no throw) — `controlPassOk` would be
        // set on Android — and reports nothing drained.
        assertFalse(h.sweepControl(), "a 404 control drain is a quiet pass, not a throw")
        assertTrue(
            h.relay.requests().any { it == "GET http://relay.test/inbox/${h.ctlToB}" ||
                it == "GET http://relay.test/inbox/${h.ctlToB}/peek" },
            "precondition: the control inbox really was asked for",
        )
        // …and the unread sweep is complete on its own terms.
        assertEquals(true, sweepCompleteness(h).second)
    }

    /**
     * SHIPPED BEHAVIOUR, documented by name: with no contacts there is no inbox
     * to peek, so "every inbox answered" is vacuously true and the sweep reports
     * complete. Harmless — a device with no contacts has no inbox a wake could
     * be about, and the relay registers pushes per inbox.
     */
    @Test
    fun sweepCompleteness_zeroContacts_reportsComplete_shippedBehaviour() {
        if (!aeadUp()) return
        val vault = InMemoryVault()
        val mgr = MessageManager(vault, "http://relay.test", GtRelay())
        val gm = GroupManager(vault) { mgr }
        var complete: Boolean? = null
        assertEquals(emptyMap(), gm.contactUnreadCounts(onSweepFinished = { complete = it }))
        assertEquals(true, complete)
    }

    @Test
    fun newToNew_bothKindsFromTheSameSender_landOnDifferentRows() {
        if (!aeadUp()) return
        val h = GtHarness()
        assertEquals(MessageManager.GroupTextRoute.GRP, h.sendGroupText("crew"))
        assertTrue(h.sendNotice(gi = true))
        assertTrue(h.sendDirect("you"))
        assertTrue(h.sendDirect("you again"))

        h.sweepControl()

        assertEquals(mapOf("a" to 2), h.gm.contactUnreadCounts(), "exactly the 1:1 count, with no group term")
        assertEquals(mapOf(h.gid to 1), h.gm.groupUnreadCounts())
    }

    // --- cell 5: the notice is lost, the text is not -----------------------

    @Test
    fun noticeLost_raisesAPresenceBumpOnTheSharedGroup_andNothingOnTheContact() {
        if (!aeadUp()) return
        val h = GtHarness()
        assertEquals(MessageManager.GroupTextRoute.GRP, h.sendGroupText("crew"))
        // No notice at all — the exact race the third inbox exists to survive.

        assertEquals(emptyMap(), h.gm.contactUnreadCounts(), "the invariant holds with NO notice at all")
        // The fallback waits for the notice it stands in for (notice grace, 2026-11-13).
        assertTrue(h.gm.groupUnreadCounts().isEmpty(), "nothing lights while the notice may still be in flight")
        h.waitOutNoticeGrace()
        assertEquals(emptyMap(), h.gm.contactUnreadCounts(), "…and still nothing on the contact after it")
        assertEquals(mapOf(h.gid to 1), h.gm.groupUnreadCounts(), "+1 presence bump, never n")
    }

    @Test
    fun noticeLost_bumpsEVERYsharedGroupByExactlyOne_neverTheDepth() {
        if (!aeadUp()) return
        // The true per-group split is not knowable before a decrypt,
        // so every shared group lights and the NUMBER is a lower bound.
        val h = GtHarness(extraGroups = 2)
        repeat(3) { assertEquals(MessageManager.GroupTextRoute.GRP, h.sendGroupText("crew $it")) }

        assertEquals(emptyMap(), h.gm.contactUnreadCounts())
        h.waitOutNoticeGrace()   // the notice grace (2026-11-13) runs out first
        val groups = h.gm.groupUnreadCounts()
        assertEquals(3, groups.size, "every shared group shows the bump")
        assertTrue(groups.values.all { it == 1 }, "+1, never the 3 blobs actually queued: $groups")
    }

    @Test
    fun aContactWeShareNoGroupWith_lightsNothingAnywhere() {
        if (!aeadUp()) return
        // §4.3's hard edge: unattributed > 0 and no shared group ⇒ nothing lights,
        // and we do NOT drain to clear — the blobs expire on the relay in 24 h.
        val h = GtHarness()
        assertEquals(MessageManager.GroupTextRoute.GRP, h.sendGroupText("crew"))
        h.bVault.deleteGroup(h.gid)

        assertEquals(emptyMap(), h.gm.contactUnreadCounts())
        assertTrue(h.gm.groupUnreadCounts().isEmpty())
        assertEquals(1, h.relay.depth(h.grpToB), "peek never drains — the blob stays put")
    }

    @Test
    fun aNoticedGroupTextRaisesNoSecondBump() {
        if (!aeadUp()) return
        // max(), not +: the `gi` notice and the queued blob describe ONE message.
        val h = GtHarness(extraGroups = 1)
        assertEquals(MessageManager.GroupTextRoute.GRP, h.sendGroupText("crew"))
        assertTrue(h.sendNotice(gi = true))

        h.sweepControl()

        // The sweep is what publishes the group-inbox depth, so it must run BEFORE
        // the group dot is read or this assertion would be vacuous.
        assertEquals(emptyMap(), h.gm.contactUnreadCounts())
        assertEquals(mapOf(h.gid to 1), h.gm.groupUnreadCounts(), "the OTHER shared group must stay dark")
    }

    // --- cells 2/3/4: the legacy compensator, pinned so it cannot rot ------

    @Test
    fun legacySender_keepsTodaysSubtraction_onTheTextInbox() {
        if (!aeadUp()) return
        // a peer with no group inbox row puts its group
        // text on our TEXT inbox, its notice carries no `gi`, and the subtraction is
        // what keeps the contact dot honest. Deleted in release N+2.
        val h = GtHarness(aHasGrpRow = false)
        assertEquals(MessageManager.GroupTextRoute.MAIN, h.sendGroupText("crew"))
        assertTrue(h.sendNotice(gi = false))
        assertTrue(h.sendDirect("you"))
        assertEquals(2, h.relay.depth(h.txtToB), "both rode the text inbox")

        h.sweepControl()

        assertEquals(mapOf("a" to 1), h.gm.contactUnreadCounts(), "raw 2 − 1 legacy group text")
        assertEquals(mapOf(h.gid to 1), h.gm.groupUnreadCounts())
    }

    @Test
    fun legacySenderWhoseNoticeIsLost_stillLightsTheContactRow() {
        if (!aeadUp()) return
        // Known limitation: for a PRE-CHANGE peer there is no
        // structural fix, and this is today's behaviour, pinned so a future cleanup
        // of the compensator has to face it deliberately.
        val h = GtHarness(aHasGrpRow = false)
        assertEquals(MessageManager.GroupTextRoute.MAIN, h.sendGroupText("crew"))

        assertEquals(mapOf("a" to 1), h.gm.contactUnreadCounts())
        assertTrue(h.gm.groupUnreadCounts().isEmpty())
    }

    @Test
    fun aLegacyNoticeNeverFeedsThePresenceBump_andAGiNoticeNeverFeedsTheSubtraction() {
        if (!aeadUp()) return
        // The two tallies must not leak into each other, and BOTH directions are
        // asserted here because each one is a different way to get the dot wrong.
        //
        // (a) a `gi` notice describes a blob on the GROUP inbox, so subtracting it
        //     from the TEXT count would hide a real 1:1 message (the phantom unread from partial group delivery,
        //     in the new shape).
        val gi = GtHarness()
        assertTrue(gi.sendNotice(gi = true))
        assertTrue(gi.sendDirect("you"))
        gi.sweepControl()
        assertEquals(mapOf("a" to 1), gi.gm.contactUnreadCounts(), "a gi notice must not hide a 1:1 text")
        assertEquals(mapOf(gi.gid to 1), gi.gm.groupUnreadCounts())

        // (b) a LEGACY notice (no `gi`) describes a blob on the TEXT inbox, so
        //     counting it against the GROUP-inbox depth would cancel the presence
        //     bump for a group text that really is queued there — a dark group dot.
        //     Two shared groups, so a leaked bump would also be visible as a second
        //     lit row.
        val legacy = GtHarness(extraGroups = 1)
        assertEquals(MessageManager.GroupTextRoute.GRP, legacy.sendGroupText("crew"))
        // THREE blobs on the TEXT inbox, one of which a LEGACY notice claims as a
        // group text. That claim is unverifiable by design — a bare /peek count is
        // all the sweep has — and it is precisely the pre-change behaviour the
        // compensator reproduces.
        repeat(3) { assertTrue(legacy.sendDirect("you $it")) }
        assertTrue(legacy.sendNotice(gi = false))
        legacy.sweepControl()

        // raw 3 on the text inbox (1 group + 2 direct) − 1 legacy group text = 2.
        assertEquals(
            mapOf("a" to 2), legacy.gm.contactUnreadCounts(),
            "the LEGACY notice compensates exactly one TEXT-inbox blob and nothing else",
        )
        // The group-inbox text has no `gi` notice: its bump waits out the notice grace.
        legacy.waitOutNoticeGrace()
        val groups = legacy.gm.groupUnreadCounts()
        assertEquals(
            2, groups[legacy.gid],
            "its own group counts the noticed text AND the unattributed group-inbox one: $groups",
        )
        assertEquals(
            1, groups[legacy.otherGids.single()],
            "the other shared group gets the presence bump only — never the legacy notice: $groups",
        )
    }

    // --- the derivation itself ---------------------------------------------

    @Test
    fun theContactCountIsByteIdenticalWithAndWithoutAnyGroupInboxDepth() {
        if (!aeadUp()) return
        // The behavioural form of the criterion: run the SAME 1:1 traffic with an empty group
        // inbox and with a loaded one, and the contact map must not move at all.
        val empty = GtHarness()
        assertTrue(empty.sendDirect("one"))
        assertTrue(empty.sendDirect("two"))
        val withoutGroup = empty.gm.contactUnreadCounts()

        val loaded = GtHarness()
        assertTrue(loaded.sendDirect("one"))
        assertTrue(loaded.sendDirect("two"))
        repeat(5) { assertEquals(MessageManager.GroupTextRoute.GRP, loaded.sendGroupText("crew $it")) }
        assertTrue(loaded.sendNotice(gi = true))
        loaded.sweepControl()
        val withGroup = loaded.gm.contactUnreadCounts()

        assertEquals(mapOf("a" to 2), withoutGroup)
        assertEquals(withoutGroup, withGroup, "a group-inbox depth may not move a contact count")
    }

    // --- cold connect: the prime, both routes ------------------------------

    @Test
    fun coldPrime_batched_neverAttributesAGroupTextToTheContact() = runTest {
        if (!aeadUp()) return@runTest
        val h = GtHarness()
        assertEquals(MessageManager.GroupTextRoute.GRP, h.sendGroupText("crew"))
        assertTrue(h.sendNotice(gi = true))
        assertTrue(h.sendDirect("you"))

        val seen = mutableMapOf<String, Int>()
        h.gm.primeUnreadCounts(emptySet()) { id, n -> seen[id] = n }

        assertEquals(mapOf("a" to 1), seen, "exactly the 1:1 text")
        assertEquals(mapOf(h.gid to 1), h.gm.groupUnreadCounts())
        assertTrue(
            h.relay.drains().none { it.endsWith("/inbox/${h.grpToB}") },
            "the prime must PEEK the group inbox, never drain it: ${h.relay.requests()}",
        )
        assertEquals(1, h.relay.depth(h.grpToB), "peek never drains")
    }

    @Test
    fun coldPrime_batched_carriesTheGroupInboxInTheSameSingleRequest() = runTest {
        if (!aeadUp()) return@runTest
        val h = GtHarness()
        assertEquals(MessageManager.GroupTextRoute.GRP, h.sendGroupText("crew"))

        h.gm.primeUnreadCounts(emptySet()) { _, _ -> }

        val posts = h.relay.requests().filter { it == "POST http://relay.test/peek" }
        assertEquals(1, posts.size, "three inboxes per contact must still be ONE round trip")
        assertTrue(
            h.relay.requests().none { it.startsWith("GET ") && it.endsWith("/peek") },
            "no per-inbox peek may survive the batch: ${h.relay.requests()}",
        )
        // No notice: the prime's own pre-drain ran BEFORE its peek, so it is not the
        // check the notice grace waits for — the next qualifying control cycle is.
        assertTrue(h.gm.groupUnreadCounts().isEmpty(), "no bump at reveal for a notice-less text")
        h.waitOutNoticeGrace()
        assertEquals(mapOf(h.gid to 1), h.gm.groupUnreadCounts(), "…and the bump still lands")
    }

    @Test
    fun coldPrime_onAnOldRelay_fallsBackAndStillKeepsTheContactRowDark() = runTest {
        if (!aeadUp()) return@runTest
        val h = GtHarness()
        h.relay.batchSupported = false
        assertEquals(MessageManager.GroupTextRoute.GRP, h.sendGroupText("crew"))
        assertTrue(h.sendNotice(gi = true))

        val seen = mutableMapOf<String, Int>()
        h.gm.primeUnreadCounts(emptySet()) { id, n -> seen[id] = n }

        assertEquals(mapOf("a" to 0), seen, "the text inbox really is empty")
        assertEquals(mapOf(h.gid to 1), h.gm.groupUnreadCounts())
        assertTrue(
            h.relay.requests().any { it == "GET http://relay.test/inbox/${h.grpToB}/peek" },
            "the fallback fan-out must peek the group inbox too: ${h.relay.requests()}",
        )
    }

    @Test
    fun coldPrime_isCorrectEvenWhenTheControlPreDrainCannotLandAtAll() = runTest {
        if (!aeadUp()) return@runTest
        // THE CLASS OF BUG BEING CLOSED. The 3f0d582 pre-drain is KEPT as a
        // mechanism and DELETED as a correctness dependency: before the group inbox the contact
        // dot was only right if this drain WON A RACE against the peek, over Tor,
        // on the coldest circuit of the session — and the 2026-09-24 iOS 1.6.29
        // sighting was exactly a slow connect where it did not.
        //
        // Modelled at its harshest: the relay REAPS the control inbox, so the
        // pre-drain 404s and the `gi` notice can never be applied. The cold prime
        // must still leave the contact row dark and still light the group.
        val h = GtHarness()
        assertEquals(MessageManager.GroupTextRoute.GRP, h.sendGroupText("crew"))
        assertTrue(h.sendNotice(gi = true))
        h.relay.forget(h.ctlToB)   // the notice can never be drained

        val seen = mutableMapOf<String, Int>()
        h.gm.primeUnreadCounts(emptySet()) { id, n -> seen[id] = n }

        assertEquals(mapOf("a" to 0), seen, "the contact dot is right with NO notice applied at all")
        // A reaped control inbox can never answer the notice grace's check, so the
        // fallback comes from the backstop ceiling.
        h.monoMs += GroupUnreadTally.FALLBACK_CEILING_MS
        assertEquals(
            mapOf(h.gid to 1), h.gm.groupUnreadCounts(),
            "and the group still lights — via the presence bump rather than the lost notice",
        )
        assertEquals(1, h.relay.depth(h.grpToB), "peek never drains")
    }

    // --- the `gi` marker itself ---------------------------------------------

    /** Makes A a real sender: its own group row with B as a resolved member, so
     *  `sendGroupMessage`'s production fan-out (text copy + interleaved notice) can
     *  be driven end to end. */
    private fun senderSideGroup(h: GtHarness): GroupManager {
        val me = bytesToHex(ByteArray(8) { 9 })
        h.aVault.insertGroup(
            GroupRecord(h.gid, "crew", 1, adminMemberId = me, myMemberId = me, createdAt = 0L)
        )
        h.aVault.insertGroupMember(GroupMemberRecord(h.gid, me, null, 0L))
        h.aVault.insertGroupMember(GroupMemberRecord(h.gid, h.peerMemberId, "b", 0L))
        return GroupManager(h.aVault) { h.aMgr }
    }

    @Test
    fun theProductionFanOut_marksTheNoticeGi_whenTheCopyRodeTheGroupInbox() {
        if (!aeadUp()) return
        // The marker follows the ROUTE, not the intent (a §3.4 404 fallback puts the
        // copy back on the text inbox even though the group row exists), so this
        // drives the real `sendGroupMessage` fan-out rather than a hand-built body.
        val h = GtHarness()
        assertEquals(1, senderSideGroup(h).sendGroupMessage(h.gid, "crew").delivered)
        assertEquals(1, h.relay.depth(h.grpToB), "the text copy rode the GROUP inbox")

        h.sweepControl()

        assertEquals(emptyMap(), h.gm.contactUnreadCounts(), "a `gi` notice never touches the contact row")
        assertEquals(mapOf(h.gid to 1), h.gm.groupUnreadCounts())
    }

    @Test
    fun theProductionFanOut_omitsGi_whenTheCopyRodeTheTextInbox() {
        if (!aeadUp()) return
        // The same fan-out against a peer with no group inbox: the copy is on the
        // TEXT inbox, the notice must carry no marker, and today's subtraction is
        // what keeps the contact dot honest (cell 2/3).
        val h = GtHarness(aHasGrpRow = false)
        assertEquals(1, senderSideGroup(h).sendGroupMessage(h.gid, "crew").delivered)
        assertEquals(1, h.relay.depth(h.txtToB), "the text copy rode the TEXT inbox")

        h.sweepControl()

        assertEquals(emptyMap(), h.gm.contactUnreadCounts(), "raw 1 − 1 legacy group text")
        assertEquals(mapOf(h.gid to 1), h.gm.groupUnreadCounts())
    }

    @Test
    fun oneMemberCannotPushTheGroupDotPastTheL11Ceiling_byAlternatingTheGiMarker() {
        if (!aeadUp()) return
        // The per-member ceiling bounds how far ONE member may push the group dot. The group inbox split that one
        // counter into two on a PEER-CHOSEN field, so the ceiling has to apply to
        // their SUM — a per-tally ceiling would hand a flooding member exactly
        // twice the budget for the price of alternating one character.
        val h = GtHarness()
        val over = GroupManager.MAX_PENDING_ACTIVITY_PER_MEMBER + 25
        repeat(over) { i ->
            h.gm.handleControl(
                "a", h.gid, GroupManager.KIND_ACTIVITY,
                if (i % 2 == 0) GroupManager.ACTIVITY_BODY_GRP else "{}",
                0L,
            )
        }

        assertEquals(
            GroupManager.MAX_PENDING_ACTIVITY_PER_MEMBER, h.gm.groupUnreadCounts()[h.gid],
            "the ceiling is on the SUM of the two tallies, not on each of them",
        )
        assertEquals(emptyMap(), h.gm.contactUnreadCounts(), "…and none of it reaches the contact row")
    }

    @Test
    fun aNoticeWhoseTextExpired_doesNotSuppressTheBumpForTheNextRealGroupText() {
        if (!aeadUp()) return
        // The drain is AUTHORITATIVE for BOTH tallies. A `gi` notice outlives its
        // text by design — a control append is retained 7 days, a group TEXT only
        // 24 h — so a stale notice can leave `grpNoticed` standing over an empty
        // inbox. If the drain cleared only the DEPTH, `unattributed = depth −
        // noticed` would then be ≤ 0 for the next real group text and swallow its
        // presence bump: a permanently dark group dot with a message behind it.
        val h = GtHarness()
        assertTrue(h.sendNotice(gi = true))
        h.sweepControl()
        assertEquals(0, h.relay.depth(h.grpToB), "the text this notice described never arrived")

        h.gm.pollGroup(h.gid)   // opening the group drains an EMPTY group inbox

        // A REAL group text now arrives, and its own notice is lost.
        assertEquals(MessageManager.GroupTextRoute.GRP, h.sendGroupText("the real one"))

        assertEquals(emptyMap(), h.gm.contactUnreadCounts())
        h.waitOutNoticeGrace()
        assertEquals(
            mapOf(h.gid to 1), h.gm.groupUnreadCounts(),
            "a stale notice must not cancel a later real group text's bump",
        )
    }

    @Test
    fun anUnknownGiValueIsTreatedAsLegacy_neverAsARejection() {
        if (!aeadUp()) return
        // Absent-is-legacy, and so is anything that is not exactly "1": the field is
        // peer-controlled and must never be a rejection reason.
        val h = GtHarness(aHasGrpRow = false)
        assertEquals(MessageManager.GroupTextRoute.MAIN, h.sendGroupText("crew"))
        assertTrue(
            h.aMgr.sendGroupControl(
                "b", h.gid, GroupManager.KIND_ACTIVITY, """{"gi":"yes"}""", h.hash(), noPush = true,
            )
        )

        h.sweepControl()

        assertEquals(emptyMap(), h.gm.contactUnreadCounts(), "raw 1 − 1 legacy group text")
        assertEquals(mapOf(h.gid to 1), h.gm.groupUnreadCounts())
    }
}

// ---------------------------------------------------------------------------
// The four unread tallies' lifecycle, pinned ahead of moving them into their own
// class: the heal-down WRITE in the contact arithmetic and the scrub of all four.
// ---------------------------------------------------------------------------

class GroupUnreadTallyPinTest {

    @Test
    fun legacyPending_isClampedToTheRelayDepth_andStaysHealed() {
        if (!aeadUp()) return
        // Three LEGACY notices claim three group texts on the TEXT inbox, but only
        // one is really there. The contact arithmetic clamps the compensator to the
        // relay depth AND writes the clamp back (the heal-down), so a later 1:1 text
        // is counted. Without the write the tally stays 3 against a depth of 2 and
        // the second read below is empty.
        val h = GtHarness(aHasGrpRow = false)
        repeat(3) { h.gm.handleControl("a", h.gid, GroupManager.KIND_ACTIVITY, "{}", 0L) }
        assertEquals(MessageManager.GroupTextRoute.MAIN, h.sendGroupText("crew"))

        assertEquals(emptyMap(), h.gm.contactUnreadCounts(), "raw 1 − min(3, 1) legacy group texts")

        assertTrue(h.sendDirect("you"))
        assertEquals(mapOf("a" to 1), h.gm.contactUnreadCounts(), "the healed tally (1) leaves the 1:1 text lit")
    }

    @Test
    fun scrubInMemory_emptiesAllFourUnreadTallies() {
        if (!aeadUp()) return
        val h = GtHarness()

        // (i) The LEGACY compensator dies with the scrub: two notices claimed two
        // text-inbox blobs, and after the scrub two real 1:1 texts both count.
        repeat(2) { h.gm.handleControl("a", h.gid, GroupManager.KIND_ACTIVITY, "{}", 0L) }
        h.gm.scrubInMemory()
        repeat(2) { assertTrue(h.sendDirect("you $it")) }
        assertEquals(mapOf("a" to 2), h.gm.contactUnreadCounts(), "the legacy tally is gone")

        // (ii) The `gi`-notice tally dies too: a group text whose notice was scrubbed
        // is unattributed again, so the presence bump fires.
        h.gm.handleControl("a", h.gid, GroupManager.KIND_ACTIVITY, GroupManager.ACTIVITY_BODY_GRP, 0L)
        h.gm.scrubInMemory()
        assertEquals(MessageManager.GroupTextRoute.GRP, h.sendGroupText("crew"))
        h.gm.contactUnreadCounts()   // publishes the group-inbox depth
        h.waitOutNoticeGrace()
        assertEquals(mapOf(h.gid to 1), h.gm.groupUnreadCounts(), "the bump fires: grpNoticed was cleared")

        // (iii) The published depth and the per-group count die with the next scrub,
        // with no new sweep in between.
        h.gm.scrubInMemory()
        assertTrue(h.gm.groupUnreadCounts().isEmpty(), "depth map and group count are cleared")
    }
}

// ---------------------------------------------------------------------------
// GRP-DRAIN-1 (§4.4) — a conversation poll drains BOTH text-carrying inboxes.
// ---------------------------------------------------------------------------

class GroupInboxDrainOrderTest {

    @Test
    fun pollDirect_drainsTheTextInboxTHENTheGroupInbox() {
        if (!aeadUp()) return
        val h = GtHarness()
        assertTrue(h.sendDirect("you"))
        assertEquals(MessageManager.GroupTextRoute.GRP, h.sendGroupText("crew"))
        h.relay.reset()

        val direct = h.gm.pollDirect("a")

        assertEquals(listOf("you"), direct.filter { !it.isGroupEcho }.map { it.text })
        val drains = h.relay.drains()
        assertEquals(
            listOf("GET http://relay.test/inbox/${h.txtToB}?lease=1", "GET http://relay.test/inbox/${h.grpToB}?lease=1"),
            drains,
            "the ORDER is pinned: text first, group second",
        )
        // The group text is not LOST — NO-PARK: it is shown in THIS 1:1 screen as a
        // GROUP_ECHO naming its group, and nothing is parked for the group.
        assertEquals(listOf("crew"), direct.filter { it.isGroupEcho }.map { it.text })
        assertEquals(h.gid, direct.single { it.isGroupEcho }.groupId)
        assertTrue(h.gm.takeGroupScreenItems(h.gid).isEmpty())
    }

    @Test
    fun pollDirect_makesNoGroupRequestForAContactWeShareNoGroupWith() {
        if (!aeadUp()) return
        val h = GtHarness()
        h.bVault.deleteGroup(h.gid)
        assertTrue(h.sendDirect("you"))
        h.relay.reset()

        assertEquals(listOf("you"), h.gm.pollDirect("a").map { it.text })

        assertEquals(
            listOf("GET http://relay.test/inbox/${h.txtToB}?lease=1"), h.relay.drains(),
            "a 1:1-only conversation must pay exactly what it always did",
        )
    }

    @Test
    fun pollGroup_drainsBothInboxesOfEveryMember() {
        if (!aeadUp()) return
        val h = GtHarness()
        assertEquals(MessageManager.GroupTextRoute.GRP, h.sendGroupText("from the group inbox"))
        h.relay.reset()

        val msgs = h.gm.pollGroup(h.gid)

        assertEquals(listOf("from the group inbox"), msgs.map { it.text })
        // GROUP-FANOUT (2026-10-06): a group poll's GETs run concurrently, so their
        // ORDER on the wire is not pinned here (pollDirect's still is, above); the
        // PROCESSING order — text before group, per member — is serial.
        assertEquals(
            setOf("GET http://relay.test/inbox/${h.txtToB}?lease=1", "GET http://relay.test/inbox/${h.grpToB}?lease=1"),
            h.relay.drains().toSet(),
        )
        assertEquals(2, h.relay.drains().size)
    }

    @Test
    fun aGroupTextFromALegacyPeerOnTheTEXTinbox_isStillRoutedToTheGroup() {
        if (!aeadUp()) return
        // The rule that keeps the backfill window and every legacy peer lossless:
        // the TEXT inbox's receive routing is UNCHANGED.
        val h = GtHarness(aHasGrpRow = false)
        assertEquals(MessageManager.GroupTextRoute.MAIN, h.sendGroupText("legacy crew"))

        assertEquals(listOf("legacy crew"), h.gm.pollGroup(h.gid).map { it.text })
    }

    @Test
    fun outOfOrderArrivalAcrossTheTwoInboxes_keepsTheONEratchetChainInSync() {
        if (!aeadUp()) return
        // Both text channels ride the ONE `dr/{id}/text` chain, so interleaving them
        // is what GRP-DRAIN-1 exists to make safe: draining both together collapses
        // the skipped-key window to "whatever arrived between the two GETs".
        val h = GtHarness()
        MessageManager.markRatchetCapable(h.aVault, "b")
        MessageManager.markRatchetCapable(h.bVault, "a")
        // Bootstrap the ratchet in both directions (the documented legacy first hop).
        assertTrue(h.aMgr.sendMessage("b", "a0"))
        assertEquals(listOf("a0"), h.bMgr.pollMessages("a").map { it.text })
        assertTrue(h.bMgr.sendMessage("a", "b0"))
        assertEquals(listOf("b0"), h.aMgr.pollMessages("b").map { it.text })
        assertEquals("1", h.aVault.getMeta("dr-on/b"))

        // Now interleave the two channels: 1:1, group, 1:1, group — all on one chain.
        assertTrue(h.aMgr.sendMessage("b", "d1"))
        assertEquals(MessageManager.GroupTextRoute.GRP, h.sendGroupText("g1"))
        assertTrue(h.aMgr.sendMessage("b", "d2"))
        assertEquals(MessageManager.GroupTextRoute.GRP, h.sendGroupText("g2"))

        val direct = h.gm.pollDirect("a")

        assertEquals(listOf("d1", "d2"), direct.filter { !it.isGroupEcho }.map { it.text }, "no 1:1 message may be lost")
        assertEquals(
            listOf("g1", "g2"), direct.filter { it.isGroupEcho }.map { it.text },
            "…and no group message either (shown here as GROUP_ECHO) — one chain, two inboxes, one drain",
        )
    }
}

// ---------------------------------------------------------------------------
// §1.6 / §3.4 — the bounded backfill and the group-inbox self-heal.
// ---------------------------------------------------------------------------

class GroupInboxBackfillTest {

    /** A vault paired the OLD way: text + control rows only, no group pair. */
    private fun legacyHarness() = GtHarness(aHasGrpRow = false, bHasGrpRow = false)

    /** Mints 1 and 2 succeed with distinct ids; the THIRD is refused (507). */
    private class ThirdMintFailsRelay : MintingRelay(
        putReply = HttpResult(202, "", true),
        deleteReply = HttpResult(200, "", true),
    ) {
        val minted = mutableListOf<String>()
        val deletes: List<String> get() = deleteCalls.map { it.first }
        init {
            mintReply = { n ->
                if (n >= 3) HttpResult(507, """{"error":"server inbox limit reached"}""", false)
                else {
                    val id = ("mint$n".padEnd(32, 'Z')).take(32)
                    minted.add(id)
                    HttpResult(201, """{"inboxId":"$id","readCapability":"$GT_CAP","writeCapability":"$GT_CAP2","expiresAt":12345}""", true)
                }
            }
        }
    }

    @Test
    fun aFailedTHIRDmintStillPairs_withGrpNull_andDestroysNeitherGoodInbox() = runTest {
        // A failed third mint is NOT a failed pairing. `grp == null` is a fully
        // supported state at every layer — it is the state EVERY pairing made
        // before the group inbox existed is in — so failing the user's IRL pairing
        // (and throwing away two good inboxes plus two completed 20-bit grinds)
        // over an optional optimisation would be strictly worse. The §1.6 backfill
        // converges it later; see
        // `aLegacyPairingWeShareAGroupWith_getsAnInboxMintedAndAnnouncedOnce`.
        val relay = ThirdMintFailsRelay()
        val mgr = MessageManager(InMemoryVault(), "http://relay.test", relay)

        val pair = mgr.mintInboxPair()

        assertNotNull(pair, "the pairing must survive a failed third mint")
        assertNull(pair.grp, "…with no group inbox, which every layer treats as legacy")
        assertEquals(2, relay.minted.size)
        assertEquals(relay.minted[0], pair.main.inboxId)
        assertEquals(relay.minted[1], pair.ctl.inboxId)
        assertTrue(
            relay.deletes.isEmpty(),
            "neither successfully minted inbox may be destroyed: ${relay.deletes}",
        )

        // …and the pairing that lands from it writes no `*-grp` row, which is
        // exactly what BOTH platform add-contact flows now hand to PairingVault.
        val vault = InMemoryVault()
        PairingVault.savePairedContact(
            vault = vault, contactId = "c", sharedSecret = ByteArray(32) { 1 },
            peerInboxId = gtInbox("peer"), peerWriteCap = GT_CAP,
            peerCtlInboxId = gtInbox("peerctl"), peerCtlWriteCap = GT_CAP,
            myInboxId = pair.main.inboxId, myReadCap = pair.main.readCapability,
            myCtlInboxId = pair.ctl.inboxId, myCtlReadCap = pair.ctl.readCapability,
            alias = "A",
            myGrpInboxId = pair.grp?.inboxId, myGrpReadCap = pair.grp?.readCapability,
        )
        assertNotNull(vault.getContact("c"), "the contact is fully paired")
        assertNull(vault.getInboxIdForContact("c", MessageManager.DIR_INBOUND_GRP))
        assertEquals(pair.main.inboxId, vault.getInboxIdForContact("c", "inbound")?.inboxId)
        assertEquals(pair.ctl.inboxId, vault.getInboxIdForContact("c", MessageManager.DIR_INBOUND_CTL)?.inboxId)
    }

    @Test
    fun aLegacyPairingWeShareAGroupWith_getsAnInboxMintedAndAnnouncedOnce() {
        if (!aeadUp()) return
        val h = legacyHarness()
        h.latchRelayRoundTrip()
        assertNull(h.bVault.getInboxIdForContact("a", MessageManager.DIR_INBOUND_GRP))

        assertEquals(MessageManager.GroupBackfillOutcome.ANNOUNCED, h.bMgr.maybeBackfillGroupInbox("a"))

        val row = h.bVault.getInboxIdForContact("a", MessageManager.DIR_INBOUND_GRP)
        assertNotNull(row)
        assertEquals(h.relay.mintInboxId, row.inboxId)
        assertEquals(h.relay.mintReadCap, row.cap)
        assertEquals(1, h.relay.mintCount, "exactly one mint")
        // The announce really went out, on the CONTROL inbox, and carries the group
        // pair only — our own inbound WRITE cap is never persisted, so a later
        // announce physically cannot re-state `ib`/`wc`.
        assertEquals(1, h.relay.depth(h.ctlToA), "the announce must reach the peer's control inbox")
        h.aMgr.pollControlMessages("b")
        val learned = h.aVault.getInboxIdForContact("b", MessageManager.DIR_OUTBOUND_GRP)
        assertNotNull(learned)
        assertEquals(h.relay.mintInboxId, learned.inboxId)
        assertEquals(h.relay.mintWriteCap, learned.cap)
        // A group-only announce must not disturb the pairing's other two rows.
        assertEquals(h.txtToB, h.aVault.getInboxIdForContact("b", "outbound")?.inboxId)
        assertEquals(h.ctlToB, h.aVault.getInboxIdForContact("b", MessageManager.DIR_OUTBOUND_CTL)?.inboxId)
    }

    // --- EAGER establishment: the durability half of the group unread-dot fix -----
    // A membership event converges the pair's group inbox PROMPTLY (off the critical
    // path), so a sender's first group message rides the GROUP inbox (GRP route) and
    // its dot becomes the peek-derivable presence bump — durable across a session
    // teardown with nothing persisted. Found by the dynamic real-life e2e
    // (run 202611100650): the first messages into fresh groups were MAIN-routed and
    // lost their dot after a background→return.

    @Test
    fun eagerEstablishment_onAMembershipEvent_makesTheFirstGroupMessageGrpRouted() {
        if (!aeadUp()) return
        val h = legacyHarness()                 // no group inboxes either way → A→B would be MAIN
        h.latchRelayRoundTrip()
        // Precondition: today's lazy state — A has no group route to B, so its first
        // group text rides the shared 1:1 MAIN inbox (dot not peek-derivable).
        assertNull(h.aVault.getInboxIdForContact("b", MessageManager.DIR_OUTBOUND_GRP))

        // A membership event fires the EAGER establishment. Production launches it on
        // the platform's per-session background scope; the test seam runs it inline.
        h.gm.groupBackfillLauncher = { work -> work() }
        h.gm.armGroupInboxBackfill("a")         // B mints its inbound-grp inbox + announces to A

        // B really minted + announced NOW (not deferred to a later sweep)…
        assertNotNull(h.bVault.getInboxIdForContact("a", MessageManager.DIR_INBOUND_GRP))
        assertEquals(1, h.relay.mintCount, "exactly one eager mint")
        // …and A learns the route from the announce.
        h.aMgr.pollControlMessages("b")
        assertNotNull(h.aVault.getInboxIdForContact("b", MessageManager.DIR_OUTBOUND_GRP))

        // THE POINT: the first group message now rides the GROUP inbox, so its dot is
        // the peek-depth presence bump — re-derived from the relay on every session.
        assertEquals(MessageManager.GroupTextRoute.GRP, h.sendGroupText("first line into the group"))

        // Idempotent: a second membership event does not re-mint (case-3 / converged
        // is a no-op, and the throttle gates it regardless).
        h.gm.armGroupInboxBackfill("a")
        assertEquals(1, h.relay.mintCount, "eager is one-time per pairing, not per event")
    }

    @Test
    fun eagerEstablishment_onAColdCircuit_isANoopAndLeavesTheLazyPathToConverge() {
        if (!aeadUp()) return
        // FAIL-SOFT: before the relay has answered this transport even once, eager
        // must grind no PoW (the connect-wait rule) — it falls straight back to the
        // already-armed lazy sweep, consuming no budget and breaking nothing.
        val h = legacyHarness()                 // NO latchRelayRoundTrip(): a cold circuit
        h.gm.groupBackfillLauncher = { work -> work() }

        h.gm.armGroupInboxBackfill("a")

        assertEquals(0, h.relay.mintCount, "eager grinds nothing on a cold circuit")
        assertNull(h.bVault.getInboxIdForContact("a", MessageManager.DIR_INBOUND_GRP), "no inbox minted")

        // Once the relay HAS answered, the lazy path still converges it — eager spent
        // no attempt, so the budget is intact (today's behaviour, unchanged).
        h.latchRelayRoundTrip()
        assertEquals(MessageManager.GroupBackfillOutcome.ANNOUNCED, h.bMgr.maybeBackfillGroupInbox("a"))
        assertEquals(1, h.relay.mintCount)
    }

    @Test
    fun theBackfillIsThrottledToOneAttemptPerWindow_andStopsAfterFour() {
        if (!aeadUp()) return
        val h = legacyHarness()
        h.latchRelayRoundTrip()
        // Make every mint fail, so the pairing never converges and the BOUND is what
        // has to stop it — the "announce lost 4× ⇒ permanent fallback" case.
        h.relay.mintFails = true

        assertEquals(MessageManager.GroupBackfillOutcome.FAILED, h.bMgr.maybeBackfillGroupInbox("a"))
        assertEquals(1, h.relay.mintCount)
        // A second pass inside the window must not spend a mint.
        assertEquals(MessageManager.GroupBackfillOutcome.SKIPPED, h.bMgr.maybeBackfillGroupInbox("a"))
        assertEquals(1, h.relay.mintCount, "the 24 h window is what stops the second attempt")

        // Walk the clock forward attempt by attempt; the ATTEMPT CAP is the real bound.
        for (attempt in 2..MessageManager.GROUP_BACKFILL_MAX_ATTEMPTS) {
            h.bVault.putMeta(MessageManager.groupBackfillKey("a"), "${attempt - 1}|1")
            assertEquals(MessageManager.GroupBackfillOutcome.FAILED, h.bMgr.maybeBackfillGroupInbox("a"))
        }
        assertEquals(MessageManager.GROUP_BACKFILL_MAX_ATTEMPTS, h.relay.mintCount)

        // Exhausted: no window, no clock, nothing re-opens it.
        h.bVault.putMeta(
            MessageManager.groupBackfillKey("a"),
            "${MessageManager.GROUP_BACKFILL_MAX_ATTEMPTS}|1",
        )
        assertEquals(MessageManager.GroupBackfillOutcome.SKIPPED, h.bMgr.maybeBackfillGroupInbox("a"))
        assertEquals(
            MessageManager.GROUP_BACKFILL_MAX_ATTEMPTS, h.relay.mintCount,
            "a pairing that never converges falls back permanently and SILENTLY",
        )
    }

    @Test
    fun aConvergedPairingIsANoop_andClearsASpentRecordSoASelfHealGetsAFullBudget() {
        if (!aeadUp()) return
        val h = GtHarness()   // both rows present
        h.latchRelayRoundTrip()
        h.bVault.putMeta(MessageManager.groupBackfillKey("a"), "3|1")

        assertEquals(MessageManager.GroupBackfillOutcome.CONVERGED, h.bMgr.maybeBackfillGroupInbox("a"))

        assertEquals(0, h.relay.mintCount)
        assertNull(
            h.bVault.getMeta(MessageManager.groupBackfillKey("a")),
            "convergence is the only re-arm besides a re-pair, and it is evidence WE produced",
        )
    }

    @Test
    fun ourInboxExistsButThePeerNeverAnnouncedTheirs_mintsNOTHING() {
        if (!aeadUp()) return
        // Case 3: re-minting here would replace an inbox the peer may already know
        // from our QR — destroying queued group texts, or orphaning a row whose live
        // read cap `resetRelayAccess` would never rotate. It converges from the
        // PEER's side instead.
        val h = GtHarness(aHasGrpRow = false, bHasGrpRow = true)
        h.latchRelayRoundTrip()
        assertNull(h.bVault.getInboxIdForContact("a", MessageManager.DIR_OUTBOUND_GRP))
        h.bVault.deleteMeta(MessageManager.groupBackfillKey("a"))

        assertEquals(MessageManager.GroupBackfillOutcome.SKIPPED, h.bMgr.maybeBackfillGroupInbox("a"))

        assertEquals(0, h.relay.mintCount)
        assertEquals(
            h.grpToB, h.bVault.getInboxIdForContact("a", MessageManager.DIR_INBOUND_GRP)?.inboxId,
            "our own inbox must be left exactly where it was",
        )
        assertTrue(h.relay.requests().none { it.startsWith("DELETE ") })
    }

    @Test
    fun aPersistentGroupInbox404_reMintsAndReAnnounces_neverARePairBadge() {
        if (!aeadUp()) return
        val h = GtHarness()
        h.latchRelayRoundTrip()
        var clock = 0L
        h.bMgr.relayLostClockMs = { clock }
        // The relay forgets our group inbox: every route 404s for it.
        h.relay.forget(h.grpToB)
        h.relay.reset()
        repeat(h.bMgr.RELAY_LOST_404_STREAK) { h.bMgr.pollGroupInbox("a") }
        clock = h.bMgr.RELAY_LOST_MIN_WINDOW_MS
        h.bMgr.pollGroupInbox("a")
        assertTrue(h.bMgr.groupInboxSelfHealDue("a"))
        assertFalse("a" in h.bMgr.relayLostContacts(), "we own that inbox — never a re-pair badge")

        assertEquals(MessageManager.GroupBackfillOutcome.ANNOUNCED, h.bMgr.maybeBackfillGroupInbox("a"))

        assertEquals(
            h.relay.mintInboxId,
            h.bVault.getInboxIdForContact("a", MessageManager.DIR_INBOUND_GRP)?.inboxId,
            "the row is swapped only AFTER the new inbox exists",
        )
        assertFalse(h.bMgr.groupInboxSelfHealDue("a"), "the streak must not keep re-arming the self-heal")
        assertFalse("a" in h.bMgr.relayLostContacts())
    }

    /** Drives B's GRP channel into a tripped 404 streak for its CURRENT inbound-grp
     *  inbox (the relay forgets it), starting at [clock]. Returns the clock after. */
    private fun forceGroupInbox404Streak(h: GtHarness, clock: Long, setClock: (Long) -> Unit): Long {
        val current = h.bVault.getInboxIdForContact("a", MessageManager.DIR_INBOUND_GRP)!!.inboxId
        h.relay.forget(current)
        setClock(clock)
        repeat(h.bMgr.RELAY_LOST_404_STREAK) { h.bMgr.pollGroupInbox("a") }
        setClock(clock + h.bMgr.RELAY_LOST_MIN_WINDOW_MS)
        h.bMgr.pollGroupInbox("a")
        assertTrue(h.bMgr.groupInboxSelfHealDue("a"), "precondition: the streak armed the self-heal")
        return clock + h.bMgr.RELAY_LOST_MIN_WINDOW_MS
    }

    @Test
    fun aRelayForcedSelfHeal_isBoundedToOneReMintPer24h_theThrottleRecordSurvivesAHealthySweep() {
        if (!aeadUp()) return
        // The healthy branch of maybeBackfillGroupInbox
        // deleted `grp-ann/<id>` whenever the GRP streak was untripped, and the
        // self-heal clears the streak itself — so a relay alternating 404 (streak)
        // and 200 (healthy) forced one PoW mint + announce per streak window with
        // the 24 h / 4-attempt bound never accumulating. Now the record survives a
        // healthy sweep until its last attempt is 24 h old.
        val h = GtHarness()
        h.latchRelayRoundTrip()
        var clock = 0L
        h.bMgr.relayLostClockMs = { clock }
        val key = MessageManager.groupBackfillKey("a")

        // 1. A genuine-looking loss: the relay 404s our group inbox past the streak
        //    → exactly ONE self-heal mint (the existing, correct behaviour).
        clock = forceGroupInbox404Streak(h, clock) { clock = it }
        assertEquals(MessageManager.GroupBackfillOutcome.ANNOUNCED, h.bMgr.maybeBackfillGroupInbox("a"))
        assertEquals(1, h.relay.mintCount)
        val record = h.bVault.getMeta(key)
        assertNotNull(record, "the attempt is spent durably")
        assertTrue(record.startsWith("1|"), "one attempt recorded: $record")
        assertFalse(h.bMgr.groupInboxSelfHealDue("a"), "the self-heal cleared its own streak")

        // 2. The relay now answers 200 for the new inbox: a healthy sweep is a no-op
        //    and must NOT drop the day-old-or-younger record (this was the hole).
        assertEquals(MessageManager.GroupBackfillOutcome.CONVERGED, h.bMgr.maybeBackfillGroupInbox("a"))
        assertEquals(record, h.bVault.getMeta(key), "a healthy sweep inside 24 h keeps the record, attempts included")

        // 3. The relay forces a SECOND streak the same day → no second mint.
        clock = forceGroupInbox404Streak(h, clock) { clock = it }
        assertEquals(MessageManager.GroupBackfillOutcome.SKIPPED, h.bMgr.maybeBackfillGroupInbox("a"))
        assertEquals(1, h.relay.mintCount, "a relay cannot force more than one re-mint per 24 h")
        assertEquals(record, h.bVault.getMeta(key))

        // 4. After 24 h (the record's stamp aged a day) the self-heal is allowed
        //    again — the record is a floor, not a permanent exhaustion.
        h.bVault.putMeta(key, "1|1")
        h.relay.mintInboxId = gtInbox("minted2")   // a fresh id, as a real mint would hand back
        assertEquals(MessageManager.GroupBackfillOutcome.ANNOUNCED, h.bMgr.maybeBackfillGroupInbox("a"))
        assertEquals(2, h.relay.mintCount, "a day later a self-heal mints again")
        assertTrue(h.bVault.getMeta(key)!!.startsWith("2|"), "attempts ACCUMULATE across relay-forced heals")

        // 5. …and a healthy sweep once the record is ≥ 24 h old does clear it, so
        //    four GENUINE losses over months never exhaust the budget for good.
        h.bVault.putMeta(key, "2|1")
        assertEquals(MessageManager.GroupBackfillOutcome.CONVERGED, h.bMgr.maybeBackfillGroupInbox("a"))
        assertNull(h.bVault.getMeta(key), "a record whose last attempt is a day old is dropped on a healthy sweep")
    }

    @Test
    fun theBackfillRefusesWhileMoveFrozen_andMakesZEROrelayCalls() {
        if (!aeadUp()) return
        val h = legacyHarness()
        h.latchRelayRoundTrip()
        h.bVault.putMeta(MoveMetaKeys.FROZEN, "1")
        h.bMgr.setMoveFrozen(true)
        h.relay.reset()

        assertEquals(MessageManager.GroupBackfillOutcome.SKIPPED, h.bMgr.maybeBackfillGroupInbox("a"))

        assertEquals(0, h.relay.mintCount, "mintInbox is NOT freeze-gated — this must carry its own gate")
        assertTrue(h.relay.requests().isEmpty(), "a frozen phone must reach the relay zero times")
        assertNull(h.bVault.getInboxIdForContact("a", MessageManager.DIR_INBOUND_GRP))
    }

    @Test
    fun theBackfillRefusesBeforeTheRelayHasAnsweredOnce() {
        if (!aeadUp()) return
        // PoW on a cold circuit is the 6a0c138 lesson; the connect wait is what
        // a month of connect-time work shortened.
        val h = legacyHarness()
        assertFalse(h.bMgr.hasCompletedRelayRoundTrip())

        assertEquals(MessageManager.GroupBackfillOutcome.SKIPPED, h.bMgr.maybeBackfillGroupInbox("a"))
        assertEquals(0, h.relay.mintCount)
    }

    @Test
    fun theControlSweepArmsTheBackfillForGroupSharingContactsOnly() {
        if (!aeadUp()) return
        val h = legacyHarness()
        h.latchRelayRoundTrip()
        // A second contact we share NO group with, paired the old way too.
        val soloTxt = gtInbox("solotxt")
        val soloCtl = gtInbox("soloctl")
        h.relay.declare(soloTxt, soloCtl)
        h.bVault.insertContact(ContactRecord("solo", generateSecureRandom(32), 0, "S", 0L))
        h.bVault.insertInboxId(InboxIdRecord(soloTxt, "solo", 1L, Long.MAX_VALUE, "inbound", GT_CAP))
        h.bVault.insertInboxId(InboxIdRecord(soloCtl, "solo", 1L, Long.MAX_VALUE, MessageManager.DIR_INBOUND_CTL, GT_CAP))
        h.bVault.insertInboxId(InboxIdRecord(gtInbox("soloout"), "solo", 1L, Long.MAX_VALUE, "outbound", GT_CAP))

        h.sweepControl()
        assertEquals(0, h.relay.mintCount, "the session's FIRST sweep is inside the connect wait")
        h.sweepControl()

        assertEquals(
            h.relay.mintInboxId,
            h.bVault.getInboxIdForContact("a", MessageManager.DIR_INBOUND_GRP)?.inboxId,
            "the group co-member is topped up",
        )
        assertNull(
            h.bVault.getInboxIdForContact("solo", MessageManager.DIR_INBOUND_GRP),
            "a pairing that will never carry a group text needs no group inbox",
        )
        assertEquals(1, h.relay.mintCount, "at most ONE mint per sweep — a grind must not stall the sweep")
    }

    @Test
    fun aSecondSweepDoesNotReMint_becauseTheThrottleIsDurable() {
        if (!aeadUp()) return
        val h = legacyHarness()
        h.latchRelayRoundTrip()

        repeat(4) { h.sweepControl() }

        assertEquals(1, h.relay.mintCount, "the sweep runs every 60–90 s; the throttle is what bounds it")
    }

    /** Spins (wall clock, bounded at 5 s) until [cond]; run it on Dispatchers.Default. */
    private fun waitUntil(cond: () -> Boolean) {
        val deadline = currentTimeMillis() + 5_000
        while (!cond()) {
            if (currentTimeMillis() > deadline) throw AssertionError("condition not reached within 5 s")
            sleepMillis(2)
        }
    }

    @Test
    fun aSecondPrimeWhileOneIsInFlight_isSkipped() = runTest {
        if (!aeadUp()) return@runTest
        // The prime's admission flag: a Tor reconnect can re-fire the prime while the
        // previous pass is still in its batch peek; the second must return at once
        // and the relay must see ONE pass.
        val h = GtHarness()
        val gate = SyncLock()
        var released = false
        var batchPeeks = 0
        h.relay.onBatchPeek = {
            gate.withLock { batchPeeks++ }
            val deadline = currentTimeMillis() + 5_000
            while (!gate.withLock { released } && currentTimeMillis() < deadline) sleepMillis(2)
        }
        val first = launch(Dispatchers.Default) { h.gm.primeUnreadCounts(emptySet()) { _, _ -> } }
        withContext(Dispatchers.Default) { waitUntil { gate.withLock { batchPeeks } == 1 } }

        h.gm.primeUnreadCounts(emptySet()) { _, _ -> }   // must return at once

        assertEquals(1, gate.withLock { batchPeeks })
        assertEquals(
            0, h.relay.requests().count { it.startsWith("GET ") && it.endsWith("/peek") },
            "the skipped prime issued no per-inbox peek",
        )
        gate.withLock { released = true }
        first.join()
        assertEquals(1, gate.withLock { batchPeeks }, "the relay saw ONE pass")
    }

    @Test
    fun aControlSweepDuringAnInFlightPrime_neverMints() = runTest {
        if (!aeadUp()) return@runTest
        // The backfill reads the prime's in-flight flag: a control sweep that runs
        // while the prime is still inside its batch peek (the connect wait) must not
        // mint. The batch peek runs BEFORE the prime takes the control sweep, so the
        // nested sweeps are admitted and reach the backfill step.
        val h = legacyHarness()
        h.latchRelayRoundTrip()
        h.relay.onBatchPeek = {
            h.relay.onBatchPeek = null
            h.gm.pollAllControls()
            h.gm.pollAllControls()
        }

        h.gm.primeUnreadCounts(emptySet()) { _, _ -> }
        assertEquals(0, h.relay.mintCount, "no mint while the prime was in flight")

        // The first sweep past the in-flight gate only flips the session's
        // first-sweep latch (the in-flight check runs BEFORE it); the second mints.
        h.sweepControl()
        h.sweepControl()
        assertEquals(1, h.relay.mintCount)
    }

    @Test
    fun theConnectTimePrimeNeverTriggersAMint() = runTest {
        if (!aeadUp()) return@runTest
        // PoW on the coldest circuit of the session is the 6a0c138 lesson, and the
        // contact list is hidden until the prime settles — the backfill must not be
        // anywhere inside that wait.
        val h = legacyHarness()

        h.gm.primeUnreadCounts(emptySet()) { _, _ -> }

        assertEquals(0, h.relay.mintCount, "the prime must never mint")
        assertNull(h.bVault.getInboxIdForContact("a", MessageManager.DIR_INBOUND_GRP))
    }
}

// ---------------------------------------------------------------------------
// Push: the wake surface must be the SAME enumeration for register and dereg.
// ---------------------------------------------------------------------------

class GroupInboxPushSurfaceTest {

    @Test
    fun theWakeSurfaceCoversAllThreeInboundDirections_forBothRegisterAndDereg() {
        val vault = InMemoryVault()
        vault.insertContact(ContactRecord("c", generateSecureRandom(32), 0, "C", 0L))
        vault.insertInboxId(InboxIdRecord(gtInbox("p1"), "c", 1L, Long.MAX_VALUE, "inbound", GT_CAP))
        vault.insertInboxId(InboxIdRecord(gtInbox("p2"), "c", 1L, Long.MAX_VALUE, MessageManager.DIR_INBOUND_CTL, GT_CAP))
        vault.insertInboxId(InboxIdRecord(gtInbox("p3"), "c", 1L, Long.MAX_VALUE, MessageManager.DIR_INBOUND_GRP, GT_CAP2))
        // An OUTBOUND group row must never be registered — we do not own its caps.
        vault.insertInboxId(InboxIdRecord(gtInbox("p4"), "c", 1L, Long.MAX_VALUE, MessageManager.DIR_OUTBOUND_GRP, GT_CAP))

        // Both surfaces are the SAME function, which is the property: a group text
        // used to wake the device through the sender's TEXT inbox and now arrives
        // here instead, so a missing direction is a silently un-wakeable message.
        val pushable = allPushableInboxes(vault).map { it.inboxId }.toSet()
        val enumerated = allInboundInboxes(vault).map { it.inboxId }.toSet()
        assertEquals(setOf(gtInbox("p1"), gtInbox("p2"), gtInbox("p3")), pushable)
        assertEquals(pushable, enumerated, "register and de-register must enumerate the identical set")
        assertEquals(GT_CAP2, allPushableInboxes(vault).single { it.inboxId == gtInbox("p3") }.readCap)
    }
}

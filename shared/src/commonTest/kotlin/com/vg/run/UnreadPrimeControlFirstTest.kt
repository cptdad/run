package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

// ---------------------------------------------------------------------------
// GROUP UNREAD ATTRIBUTION AT CONNECT TIME (production bug, 2026-09-05: a group
// text from member B lit B's CONTACT row instead of the GROUP row).
//
// A group text rides the recipient's ordinary 1:1 TEXT inbox and `GET
// /inbox/{id}/peek` answers with nothing but a COUNT, so group-vs-1:1 is knowable
// only from the sender's separate KIND_ACTIVITY notice on the CONTROL channel.
// The connect-time unread prime peeked the text inboxes the instant the transport
// wired, while the first thing that drained CONTROL ran 3-7 s later — so the prime
// attributed the pending group text to the contact and the control loop moved the
// dot seconds afterwards.
//
// The two halves of the fix are pinned here:
//
//   • RECEIVER — the prime PRE-DRAINS the group members' control inboxes before it
//     peeks any text inbox, so groupUnread/groupPendingByContact are populated at
//     attribution time. It must stay CONTROL-ONLY (a text inbox is burn-on-read and
//     may only ever be peeked), must cost nothing on a device with no groups, must
//     never drain concurrently with the background control sweep, and must hand the
//     sweep back the UI nudge it took.
//
//   • SENDER — each member's KIND_ACTIVITY notice is POSTed immediately after THAT
//     member's text copy, so the notice is on the relay by the time the text's push
//     wake reaches the recipient — instead of up to 2·(k−1) jitter gaps later.
// ---------------------------------------------------------------------------

/** 32-char base64url-alphabet inbox id derived from [tag]. */
private fun gpInbox(tag: String) = ("gp$tag".padEnd(32, 'A')).take(32)

private val GP_CAP = "R".repeat(43)

/**
 * URL-aware relay double with a MODEL of the two inbox kinds this bug is about:
 *
 *  - CONTROL inboxes hold real blobs; `/peek` reports how many are queued and the
 *    bare `GET /inbox/{id}` DRAINS them (destructive, exactly like the relay).
 *  - TEXT inboxes are peek-only: `/peek` reports [textPending] and a bare GET is
 *    recorded so a test can prove the prime never drained one.
 *
 * Thread-safe: the prime's peeks run from several worker coroutines at once.
 */
private class GroupPrimeRelay : PeekCountRelay() {
    /** The GETs so far as "GET url", in order. */
    fun urls(): List<String> = requestsOf("GET").map { "GET ${it.url}" }
    fun countMatching(predicate: (String) -> Boolean): Int = urls().count(predicate)
}

/**
 * Sender A (paired with B, text + control outbound) and receiver B (text +
 * control inbound), sharing one pairwise secret and one group in which A is a
 * RESOLVED member of B's roster.
 */
private class GroupPrimeHarness {
    val shared = generateSecureRandom(32)
    val gid = GroupManager.newGroupId()
    val myMemberId = bytesToHex(ByteArray(8) { 1 })
    val peerMemberId = bytesToHex(ByteArray(8) { 2 })

    val txtInbox = gpInbox("txt")
    val ctlInbox = gpInbox("ctl")

    // Sender side — only used to mint one real KIND_ACTIVITY blob.
    val aVault = InMemoryVault()
    val aHttp = RecordingRelayHttp()
    val aMgr = MessageManager(aVault, "http://relay.test", aHttp as RelayHttp)

    // Receiver side — the device under test.
    val bVault = InMemoryVault()
    val relay = GroupPrimeRelay()
    val bMgr = MessageManager(bVault, "http://relay.test", relay)
    val gm = GroupManager(bVault) { bMgr }

    init {
        aVault.insertContact(ContactRecord("b", shared, 0, "B", 0L))
        aVault.insertInboxId(InboxIdRecord(txtInbox, "b", 1L, Long.MAX_VALUE, "outbound", GP_CAP))
        aVault.insertInboxId(InboxIdRecord(ctlInbox, "b", 1L, Long.MAX_VALUE, MessageManager.DIR_OUTBOUND_CTL, GP_CAP))

        bVault.insertContact(ContactRecord("a", shared, 0, "A", 0L))
        bVault.insertInboxId(InboxIdRecord(txtInbox, "a", 1L, Long.MAX_VALUE, "inbound", GP_CAP))
        bVault.insertInboxId(InboxIdRecord(ctlInbox, "a", 1L, Long.MAX_VALUE, MessageManager.DIR_INBOUND_CTL, GP_CAP))
        relay.declareControlInbox(ctlInbox)

        bVault.insertGroup(GroupRecord(gid, "crew", 1, adminMemberId = myMemberId, myMemberId = myMemberId, createdAt = 0L))
        bVault.insertGroupMember(GroupMemberRecord(gid, myMemberId, contactId = null, addedAt = 0L))
        bVault.insertGroupMember(GroupMemberRecord(gid, peerMemberId, contactId = "a", addedAt = 0L))
    }

    /** Mints ONE real, AEAD-sealed KIND_ACTIVITY notice from A and queues it on B's
     *  control inbox — the exact blob sendGroupMessage's interleaved fan-out emits. */
    fun queueActivityNotice() {
        aHttp.script(HttpResult(202, "", true))
        val hash = GroupManager.membershipHash(gid, 1, listOf(myMemberId, peerMemberId))
        assertTrue(
            aMgr.sendGroupControl("b", gid, GroupManager.KIND_ACTIVITY, "{}", hash, noPush = true),
            "the harness must be able to mint a real activity notice",
        )
        relay.queueControl(ctlInbox, encodeBase64(aHttp.calls.last().body))
    }
}

// ---------------------------------------------------------------------------
// RECEIVER — the prime's control pre-drain
// ---------------------------------------------------------------------------

class UnreadPrimeControlFirstTest {

    @Test
    fun pendingGroupText_lightsTheGroupDot_notTheContactDot() = runTest {
        if (!aeadUp()) return@runTest
        val h = GroupPrimeHarness()
        // One group text from A is sitting on A's 1:1 TEXT inbox (peek-only: the
        // relay must keep holding it until the conversation is opened) and A's
        // KIND_ACTIVITY notice for it is waiting on the CONTROL inbox.
        h.relay.setTextPending(h.txtInbox, 1)
        h.queueActivityNotice()

        val seen = mutableMapOf<String, Int>()
        h.gm.primeUnreadCounts(emptySet()) { id, n -> seen[id] = n }

        // THE BUG: without the pre-drain this emitted 1 for the contact and left the
        // group dot dark until the control loop's first cycle 3-7 s later.
        assertEquals(mapOf("a" to 0), seen, "a group text must not light the SENDER's 1:1 dot")
        assertEquals(1, h.gm.groupUnreadCounts()[h.gid], "it must light the GROUP dot instead")
    }

    @Test
    fun withoutTheNotice_theTextStillCountsAsDirect() = runTest {
        // The complement, and the reason the ordering matters at all: the notice is
        // the ONLY thing that reclassifies the peek count. With nothing queued on the
        // control inbox the same pending blob is a 1:1 text, and must still show.
        val h = GroupPrimeHarness()
        h.relay.setTextPending(h.txtInbox, 1)

        val seen = mutableMapOf<String, Int>()
        h.gm.primeUnreadCounts(emptySet()) { id, n -> seen[id] = n }

        assertEquals(mapOf("a" to 1), seen)
        assertTrue(h.gm.groupUnreadCounts().isEmpty())
    }

    @Test
    fun theTextInboxIsOnlyEverPeeked_neverDrained() = runTest {
        if (!aeadUp()) return@runTest
        val h = GroupPrimeHarness()
        h.relay.setTextPending(h.txtInbox, 2)
        h.queueActivityNotice()

        h.gm.primeUnreadCounts(emptySet()) { _, _ -> }

        // A bare GET on a TEXT inbox DESTROYS the queued messages it is counting —
        // unread texts must survive on the relay until their conversation opens.
        assertEquals(
            0,
            h.relay.countMatching { it.contains("/inbox/${h.txtInbox}") && !it.endsWith("/peek") },
            "the prime must never drain a text inbox",
        )
        // …while the CONTROL inbox is drained, which is safe (no retention
        // requirement) and is the whole point of the pre-drain.
        assertEquals(
            1,
            h.relay.countMatching { it.contains("/inbox/${h.ctlInbox}") && !it.endsWith("/peek") },
            "the control inbox must be drained exactly once",
        )
    }

    @Test
    fun controlIsDrainedBeforeTheTextInboxIsPeeked() = runTest {
        if (!aeadUp()) return@runTest
        val h = GroupPrimeHarness()
        h.relay.setTextPending(h.txtInbox, 1)
        h.queueActivityNotice()

        h.gm.primeUnreadCounts(emptySet()) { _, _ -> }

        val urls = h.relay.urls()
        val ctlDrain = urls.indexOfFirst { it.endsWith("/inbox/${h.ctlInbox}?lease=1") }
        val txtPeek = urls.indexOfFirst { it.endsWith("/inbox/${h.txtInbox}/peek") }
        assertTrue(ctlDrain >= 0 && txtPeek >= 0, "both requests must happen: $urls")
        assertTrue(ctlDrain < txtPeek, "the control drain must precede the text peek: $urls")
    }

    @Test
    fun aDeviceInNoGroup_makesNoControlRequestAtAll() = runTest {
        // The latency guard. The prime exists to show the dot in ~1 RTT (d772dac);
        // a device with no groups has nothing to reattribute, so it must not pay a
        // single sequential control round-trip.
        val vault = InMemoryVault()
        val relay = GroupPrimeRelay()
        val txt = gpInbox("solo")
        val ctl = gpInbox("soloctl")
        vault.insertContact(ContactRecord("solo", generateSecureRandom(32), 0, "S", 0L))
        vault.insertInboxId(InboxIdRecord(txt, "solo", 1L, Long.MAX_VALUE, "inbound", GP_CAP))
        vault.insertInboxId(InboxIdRecord(ctl, "solo", 1L, Long.MAX_VALUE, MessageManager.DIR_INBOUND_CTL, GP_CAP))
        relay.declareControlInbox(ctl)
        relay.setTextPending(txt, 3)
        val gm = GroupManager(vault) { MessageManager(vault, "http://relay.test", relay) }

        val seen = mutableMapOf<String, Int>()
        gm.primeUnreadCounts(emptySet()) { id, n -> seen[id] = n }

        assertEquals(mapOf("solo" to 3), seen)
        assertEquals(listOf("GET http://relay.test/inbox/$txt/peek"), relay.urls())
    }

    @Test
    fun aBlockedGroupMembersControlInboxIsNotPreDrained() = runTest {
        // a block severs the polling relationship, not just the row.
        if (!aeadUp()) return@runTest
        val h = GroupPrimeHarness()
        h.relay.setTextPending(h.txtInbox, 1)
        h.queueActivityNotice()

        h.gm.primeUnreadCounts(setOf("a")) { _, _ -> }

        assertTrue(h.relay.urls().isEmpty(), "neither inbox of a blocked contact may be touched")
    }

    @Test
    fun theNudgeTheSweepWouldHaveReported_isHandedBackToIt() = runTest {
        if (!aeadUp()) return@runTest
        val h = GroupPrimeHarness()
        h.relay.setTextPending(h.txtInbox, 1)
        h.queueActivityNotice()

        h.gm.primeUnreadCounts(emptySet()) { _, _ -> }

        // Both platform loops nudge their vault-observing UIs off pollAllControls'
        // return value (an applied invite must surface a group row with NO
        // navigation). The pre-drain took that batch, so it must hand the nudge back
        // — even though its own sweep now finds the inbox empty.
        assertTrue(h.gm.pollAllControls(), "the drained batch must still be reported once")
        assertFalse(h.gm.pollAllControls(), "…and exactly once — the latch is consumed")
    }

    @Test
    fun aControlSweepAlreadyInFlight_isNeverJoinedByASecondDrain() {
        // Two concurrent drains of one control inbox double the "a response lost on a
        // cold circuit destroys those invites for good" exposure and race the
        // per-contact anti-replay counters. Modelled by re-entering pollAllControls
        // from inside a drain, which is exactly what the 3-7 s poll loop does to a
        // still-running prime pre-drain.
        val h = GroupPrimeHarness()
        h.relay.queueControl(h.ctlInbox, "not-a-blob")   // forces a drain; body is dropped
        var nested: Boolean? = null
        var nestedRequests = -1
        h.relay.onControlDrain = {
            val before = h.relay.urls().size
            nested = h.gm.pollAllControls()
            nestedRequests = h.relay.urls().size - before
        }

        h.gm.pollAllControls()

        assertEquals(false, nested, "the second sweep must decline, not report a drain it never made")
        assertEquals(0, nestedRequests, "a re-entrant sweep must not issue one single request")
    }
}

// ---------------------------------------------------------------------------
// SENDER — the interleaved activity notice
// ---------------------------------------------------------------------------

/** Contact with BOTH outbound directions, so a text copy and its activity notice
 *  land on DIFFERENT urls and the interleave is observable. */
private fun seedInterleaveContact(vault: InMemoryVault, contactId: String, tag: String) {
    vault.insertContact(ContactRecord(contactId, generateSecureRandom(32), 1, "A-$contactId", 0L))
    vault.insertInboxId(InboxIdRecord(gpInbox("t$tag"), contactId, 1L, Long.MAX_VALUE, "outbound", GP_CAP))
    vault.insertInboxId(InboxIdRecord(gpInbox("c$tag"), contactId, 1L, Long.MAX_VALUE, MessageManager.DIR_OUTBOUND_CTL, GP_CAP))
}

class GroupSendInterleaveTest {

    private class Fixture {
        val vault = InMemoryVault()
        val http = RecordingRelayHttp()
        val mgr = MessageManager(vault, "http://relay.test", http as RelayHttp)
        val gm = GroupManager(vault) { mgr }
        val gid = GroupManager.newGroupId()

        init {
            seedInterleaveContact(vault, "c-bob", "bob")
            seedInterleaveContact(vault, "c-carol", "carol")
            val me = bytesToHex(ByteArray(8) { 1 })
            vault.insertGroup(GroupRecord(gid, "crew", 1, adminMemberId = me, myMemberId = me, createdAt = 0L))
            vault.insertGroupMember(GroupMemberRecord(gid, me, null, 0L))
            vault.insertGroupMember(GroupMemberRecord(gid, bytesToHex(ByteArray(8) { 2 }), "c-bob", 0L))
            vault.insertGroupMember(GroupMemberRecord(gid, bytesToHex(ByteArray(8) { 3 }), "c-carol", 0L))
        }

        fun textUrl(contactId: String) =
            "http://relay.test/inbox/" + gpInbox("t" + contactId.removePrefix("c-"))
        fun ctlUrl(contactId: String) =
            "http://relay.test/inbox/" + gpInbox("c" + contactId.removePrefix("c-"))
        fun contactOfTextUrl(url: String) =
            listOf("c-bob", "c-carol").firstOrNull { textUrl(it) == url }
    }

    @Test
    fun eachMembersNoticeFollowsThatMembersText_beforeTheNextMembersText() {
        if (!aeadUp()) return
        val f = Fixture()
        repeat(4) { f.http.script(HttpResult(code = 202, body = "", isSuccess = true)) }

        val result = f.gm.sendGroupMessage(f.gid, "hello group")
        assertEquals(2, result.delivered)

        // Every CONTROL append now carries the uniform
        // `?ttl` while a TEXT append still carries none, so compare the PATHS — the
        // property here is the ORDER, and the ttl has its own tests.
        val urls = f.http.calls.map { it.url.substringBefore("?") }
        assertEquals(4, urls.size, "one text + one notice per member")
        // The member ORDER is CSPRNG-shuffled, so assert the SHAPE: text(X),
        // notice(X), text(Y), notice(Y) — never text(X), text(Y), notice…, which is
        // what left the last member's notice 2·(k−1) jitter gaps behind its text.
        val first = f.contactOfTextUrl(urls[0])
        assertTrue(first != null, "the first POST must be a member's TEXT copy: $urls")
        val second = listOf("c-bob", "c-carol").first { it != first }
        assertEquals(
            listOf(f.textUrl(first!!), f.ctlUrl(first), f.textUrl(second), f.ctlUrl(second)),
            urls,
            "the activity notice must be interleaved per member",
        )
    }

    @Test
    fun theNoticeRidesTheControlChannelWithPushSuppressed() {
        if (!aeadUp()) return
        val f = Fixture()
        repeat(4) { f.http.script(HttpResult(code = 202, body = "", isSuccess = true)) }

        f.gm.sendGroupMessage(f.gid, "hello group")

        // noPush: the text copy already fired this event's one wake. A second wake
        // for the notice would double-banner a single message.
        val notices = f.http.calls.filter { it.url.contains(gpInbox("cbob")) || it.url.contains(gpInbox("ccarol")) }
        assertEquals(2, notices.size)
        assertTrue(notices.all { it.headers["X-No-Push"] == "1" }, "the activity notice must never wake a device")
        val texts = f.http.calls.filter { it.url.contains(gpInbox("tbob")) || it.url.contains(gpInbox("tcarol")) }
        assertEquals(2, texts.size)
        assertTrue(texts.none { it.headers.containsKey("X-No-Push") }, "the text copy still wakes the recipient")
    }

    @Test
    fun aMemberWhoseTextFailed_getsNoNotice() {
        if (!aeadUp()) return
        val f = Fixture()
        // The FIRST text copy is rejected; everything after it succeeds.
        f.http.script(HttpResult(code = 500, body = "nope", isSuccess = false))
        repeat(3) { f.http.script(HttpResult(code = 202, body = "", isSuccess = true)) }

        val result = f.gm.sendGroupMessage(f.gid, "hello group")
        assertEquals(1, result.delivered)
        assertEquals(2, result.total)

        val urls = f.http.calls.map { it.url.substringBefore("?") }
        assertEquals(3, urls.size, "the failed member must cost exactly one POST")
        val failed = f.contactOfTextUrl(urls[0])!!
        // a notice to a member who never got the text leaves a PHANTOM
        // "group text pending" on their side that hides their real 1:1 badge.
        assertFalse(urls.contains(f.ctlUrl(failed)), "no activity notice may announce a text that never sent")
        val delivered = listOf("c-bob", "c-carol").first { it != failed }
        assertEquals(listOf(f.textUrl(failed), f.textUrl(delivered), f.ctlUrl(delivered)), urls)
    }
}

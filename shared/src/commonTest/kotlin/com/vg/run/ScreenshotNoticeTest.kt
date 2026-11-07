package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

// ---------------------------------------------------------------------------
// "Screenshot taken" control notice (ScreenshotNotice.kt / ScreenshotNoticeStore.kt).
//
// Five properties are pinned here:
//   1. ROUND TRIP — the kind survives the real envelope pipeline (AEAD, counter+
//      epoch, "ch"/"di" binding, padding) and surfaces on the receiver as a
//      notice, never as a message.
//   2. PERSISTENCE — the notice is written to the vault on receipt and is still
//      there for a NEW session over the same vault. That is the production bug
//      The notice arrives on
//      the DESTRUCTIVE background control sweep, and before this it lived only in
//      a RAM buffer that every backgrounding cleared.
//   3. FORWARD COMPAT — an UNKNOWN kind is dropped silently on both dispatches
//      (direct/transport and group/GroupManager). These are the "old build meets
//      a newer kind" cases, driven with a kind neither build knows. UNCHANGED by
//      the persistence work: the wire is byte-identical.
//   4. GROUP FAN-OUT + ATTRIBUTION — one control copy per resolved member, and
//      the receiver attributes it to the sender's pairwise channel, not to any
//      sender-supplied field.
//   5. UNREAD — an UNSEEN persisted notice lights the conversation's dot on its
//      own (even with a zero relay peek) and is cleared by opening it.
//
// No migration exists and none is needed: an install with no `ssn:` rows simply
// has nothing to show.
// ---------------------------------------------------------------------------

private const val SS_MAIN_OUT = "SSMAINxxxxxxxxxxxxxxxxxxxxxxxxxx"   // 32 chars
private const val SS_CTL_OUT  = "SSCTLxxxxxxxxxxxxxxxxxxxxxxxxxxx"   // 32 chars
private const val SS_CAP      = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  // 43 chars

private fun ssMemberId(seed: Int) = bytesToHex(ByteArray(8) { (seed + it).toByte() })

/** Every persisted-notice key currently in a vault. */
private fun InMemoryVault.ssnKeys(): List<String> =
    meta.keys.filter { it.startsWith(ScreenshotNoticeMetaKeys.PREFIX) }.sorted()

/**
 * Sender A (fully paired, incl. the control inbox) + receiver B, sharing one
 * pairwise secret. B additionally has a GroupManager — the conversation layer
 * that owns the notice surface. Mirrors ControlChannelTest's harness.
 */
private class ScreenshotHarness {
    val shared = generateSecureRandom(32)
    val aVault = InMemoryVault()
    val aHttp = RecordingRelayHttp()
    val aMgr = MessageManager(aVault, "http://relay.test", aHttp as RelayHttp)
    val bVault = InMemoryVault()
    val bHttp = RecordingRelayHttp()
    val bMgr = MessageManager(bVault, "http://relay.test", bHttp as RelayHttp)
    val bGm = GroupManager(bVault) { bMgr }

    init {
        aVault.insertContact(ContactRecord("b", shared, 0, "B", 0L))
        aVault.insertInboxId(InboxIdRecord(SS_MAIN_OUT, "b", 1L, Long.MAX_VALUE, "outbound", SS_CAP))
        aVault.insertInboxId(InboxIdRecord(SS_CTL_OUT, "b", 1L, Long.MAX_VALUE, MessageManager.DIR_OUTBOUND_CTL, SS_CAP))
        bVault.insertContact(ContactRecord("a", shared, 0, "Alias-A", 0L))
        bVault.insertInboxId(InboxIdRecord(SS_MAIN_OUT, "a", 1L, Long.MAX_VALUE, "inbound", SS_CAP))
        bVault.insertInboxId(InboxIdRecord(SS_CTL_OUT, "a", 1L, Long.MAX_VALUE, MessageManager.DIR_INBOUND_CTL, SS_CAP))
    }

    /** A sends one direct control of [kind]; returns the base64 blob it POSTed. */
    fun aSendsDirectControl(kind: String): String {
        aHttp.script(HttpResult(202, "", true))
        assertTrue(aMgr.sendDirectControl("b", kind, "{}"), "control send must reach the relay")
        return encodeBase64(aHttp.calls.last().body)
    }

    /** A sends a real screenshot notice; returns the base64 blob it POSTed. */
    fun aSendsScreenshotNotice(): String {
        aHttp.script(HttpResult(202, "", true))
        assertTrue(aMgr.sendScreenshotNotice("b"), "the notice must reach the relay")
        return encodeBase64(aHttp.calls.last().body)
    }

    /** Serves [blobs] on B's CONTROL inbox and drains it. */
    fun bDrainsControl(vararg blobs: String): List<ReceivedMessage> {
        bHttp.script(
            HttpResult(200, """{"blobs":[${blobs.joinToString(",") { "\"$it\"" }}]}""", true)
        )
        return bMgr.pollControlMessages("a")
    }
}

class ScreenshotNoticeWireTest {

    @Test
    fun kind_isWithinTheControlKindLengthCap() {
        // pollChannel drops any control kind longer than 16 chars, on both
        // receive paths — a kind that overflows it would be undeliverable.
        assertTrue(
            MessageManager.CONTROL_KIND_SCREENSHOT.length <= 16,
            "the direct kind must fit the receive-side control-kind cap",
        )
        assertTrue(GroupManager.KIND_SCREENSHOT.length <= 16, "the group kind must fit the same cap")
    }

    @Test
    fun oneToOne_roundTrips_asANotice_neverAsAMessage_andIsPersisted() {
        if (!aeadUp()) return
        val h = ScreenshotHarness()
        val blob = h.aSendsScreenshotNotice()
        // Control traffic → the dedicated control inbox, like every other notice.
        // Uniform `?ttl` on every control append — compare the PATH.
        assertTrue(h.aHttp.calls.last().url.substringBefore("?").endsWith("/inbox/$SS_CTL_OUT"))

        val surfaced = h.bDrainsControl(blob)
        assertEquals(0, surfaced.size, "a screenshot notice must never surface as a message")

        val notices = h.bGm.drainScreenshotNotices("a")
        assertEquals(1, notices.size)
        assertEquals("a", notices[0].conversationId)
        assertEquals("a", notices[0].senderContactId)
        assertEquals("Alias-A", notices[0].senderAlias, "alias comes from the vault, not the wire")
        assertEquals(false, notices[0].isGroup)
        assertTrue(notices[0].receivedAt > 0, "the notice carries a local receive timestamp")
        assertEquals(notices[0].receivedAt + SCREENSHOT_NOTICE_TTL_MS, notices[0].expiresAt,
            "expiry is anchored on OUR receive clock, never on the sender's claim")
        // The DISPLAY time is the sender's own capture time, minute-rounded on the
        // wire (roundTimestampToMinute) and inside the accepted window.
        assertEquals(0L, notices[0].timestamp % 60_000L, "the wire stamp is minute-rounded")
        assertTrue(notices[0].timestamp <= notices[0].receivedAt, "a claim is never rendered in the future")
        assertTrue(notices[0].receivedAt - notices[0].timestamp < 5 * 60_000L, "and is the peer's real capture time")

        // PERSISTED: exactly one `ssn:` row, and the drain did not consume it.
        assertEquals(1, h.bVault.ssnKeys().size, "the notice must be durable, not RAM-only")
        assertTrue(h.bVault.ssnKeys()[0].startsWith("ssn:a:a:"))
        val reopened = h.bGm.screenshotNotices("a")
        assertEquals(1, reopened.size, "re-opening the conversation still shows it")
        assertEquals(notices[0], reopened[0])

        // The RAM drain is still one-shot — the poll tick appends each arrival once.
        assertEquals(0, h.bGm.drainScreenshotNotices("a").size)
        // …and the anti-replay baseline advanced: a notice consumes counter space
        // exactly like its control siblings.
        assertEquals(1L, h.bVault.getContact("a")!!.inboundCtlCounter)
    }

    @Test
    fun notice_survivesSessionTeardown_andIsRenderedOnReopen() {
        // THE PRODUCTION FAILURE MODE (design §0): the notice arrives on the
        // background control sweep with no conversation open, the session is torn
        // down (scrubInMemory + a brand-new GroupManager on the next unlock), and
        // only then does the user open the conversation.
        if (!aeadUp()) return
        val h = ScreenshotHarness()
        val blob = h.aSendsScreenshotNotice()
        h.bHttp.script(
            HttpResult(200, """{"pending":1}""", true),
            HttpResult(200, """{"blobs":["$blob"]}""", true),
        )
        h.bGm.pollAllControls()               // no conversation open
        h.bGm.scrubInMemory()                 // background → lock

        val fresh = GroupManager(h.bVault) { h.bMgr }   // next unlock
        val notices = fresh.screenshotNotices("a")
        assertEquals(1, notices.size, "a notice drained with no conversation open must survive the teardown")
        assertEquals("Alias-A", notices[0].senderAlias)
        assertFalse(notices[0].isGroup)
    }

    @Test
    fun replayedNotice_isRejectedByTheCounter_andFiresOnce() {
        if (!aeadUp()) return
        val h = ScreenshotHarness()
        val blob = h.aSendsScreenshotNotice()

        h.bDrainsControl(blob)
        assertEquals(1, h.bGm.drainScreenshotNotices("a").size)

        // A hostile relay re-serves the identical blob: counter <= baseline → drop,
        // so the notice does NOT fire a second time — and no second row is written.
        h.bDrainsControl(blob)
        assertEquals(0, h.bGm.drainScreenshotNotices("a").size, "a replayed notice must not fire again")
        assertEquals(1L, h.bVault.getContact("a")!!.inboundCtlCounter)
        assertEquals(1, h.bVault.ssnKeys().size, "a replay must not duplicate the persisted row")
    }

    @Test
    fun notice_surfacesViaTheBackgroundControlSweep() {
        if (!aeadUp()) return
        val h = ScreenshotHarness()
        val blob = h.aSendsScreenshotNotice()
        // The normal delivery path: no conversation open, the background sweep
        // drains the control inbox. The sweep is PEEK-FIRST, so the (url-agnostic,
        // strictly ordered) script serves the non-destructive `/peek` count before
        // the drain it authorises — exactly the two-request shape the relay sees.
        h.bHttp.script(
            HttpResult(200, """{"pending":1}""", true),
            HttpResult(200, """{"blobs":["$blob"]}""", true),
        )
        h.bGm.pollAllControls()
        val notices = h.bGm.drainScreenshotNotices("a")
        assertEquals(1, notices.size)
        assertEquals("a", notices[0].senderContactId)
    }

    @Test
    fun blockedContactsNotice_isDropped_andNeverPersisted() {
        if (!aeadUp()) return
        val h = ScreenshotHarness()
        val blob = h.aSendsScreenshotNotice()
        h.bDrainsControl(blob)                    // applied at the transport…
        h.bGm.blockedContacts = { setOf("a") }    // …but the block silences every surface
        assertEquals(0, h.bGm.drainScreenshotNotices("a").size)
        assertEquals(0, h.bVault.ssnKeys().size, "a blocked sender's notice must not reach the vault")
        assertEquals(0, h.bGm.screenshotNotices("a").size)
    }

    @Test
    fun screenshotNotices_isNonDestructive_andFiltersABlockedSenderAtReadTime() {
        // The block set can be applied AFTER a notice was already persisted, so the
        // read surface must filter too — not merely the write surface.
        if (!aeadUp()) return
        val h = ScreenshotHarness()
        h.bDrainsControl(h.aSendsScreenshotNotice())
        h.bGm.drainScreenshotNotices("a")

        assertEquals(1, h.bGm.screenshotNotices("a").size)
        assertEquals(1, h.bGm.screenshotNotices("a").size, "the load surface is repeatable, not a drain")
        h.bGm.blockedContacts = { setOf("a") }
        assertEquals(0, h.bGm.screenshotNotices("a").size, "blocking hides an already-persisted notice")
    }

    @Test
    fun contactUnreadCounts_includesUnseenNotice_whenPeekIsZero() {
        if (!aeadUp()) return
        val h = ScreenshotHarness()
        h.bDrainsControl(h.aSendsScreenshotNotice())
        h.bGm.drainScreenshotNotices("a")          // collects → persists, still UNSEEN

        // The relay holds no text at all for that contact — peekUnreadCounts omits a
        // zero, so without the union term the dot would never appear.
        h.bHttp.script(HttpResult(200, """{"pending":0}""", true))
        assertEquals(1, h.bGm.contactUnreadCounts()["a"],
            "an unseen screenshot notice must light the contact dot on its own")

        // Opening the 1:1 (polling it) marks it seen and the dot goes out.
        h.bGm.pollDirect("a")
        h.bHttp.script(HttpResult(200, """{"pending":0}""", true))
        assertTrue(h.bGm.contactUnreadCounts().isEmpty(), "opening the conversation clears it")
        assertEquals(1, h.bGm.screenshotNotices("a").size, "…without deleting the notice")
    }

    @Test
    fun contactUnreadCounts_blockedContactsUnseenNoticeIsNotCounted() {
        if (!aeadUp()) return
        val h = ScreenshotHarness()
        h.bDrainsControl(h.aSendsScreenshotNotice())
        h.bGm.drainScreenshotNotices("a")
        h.bHttp.script(HttpResult(200, """{"pending":0}""", true))
        assertTrue(h.bGm.contactUnreadCounts(setOf("a")).isEmpty(),
            "a blocked contact must not light a dot through a stale notice either")
    }

    @Test
    fun primeUnreadCounts_emitsUnseenNotice_onZeroPeek() = runTest {
        if (!aeadUp()) return@runTest
        val h = ScreenshotHarness()
        h.bDrainsControl(h.aSendsScreenshotNotice())
        h.bGm.drainScreenshotNotices("a")

        // The connect-time prime is ONE batch `POST /peek` (2026-09-20), so the
        // scripted answer is the batch's — one result for the text inbox, positively
        // zero. (The per-inbox `{"pending":0}` shape is still what the steady-state
        // sweep gets; see contactUnreadCounts_includesUnseenNotice_whenPeekIsZero
        // above, which is unchanged.)
        h.bHttp.script(
            HttpResult(200, """{"v":1,"results":[{"id":"$SS_MAIN_OUT","pending":0}]}""", true)
        )
        val emitted = mutableMapOf<String, Int>()
        h.bGm.primeUnreadCounts(emptySet()) { id, n -> emitted[id] = n }
        assertEquals(mapOf("a" to 1), emitted,
            "a zero peek plus an unseen notice must still emit 1, not 0")
    }

    @Test
    fun sendScreenshotNotice_withNoContact_isANonThrowingFalse() {
        val vault = InMemoryVault()
        val http = RecordingRelayHttp()
        val mgr = MessageManager(vault, "http://relay.test", http as RelayHttp)
        // Fire-and-forget: an unsendable notice is a quiet false, never a throw
        // and never anything the conversation has to render.
        assertEquals(false, mgr.sendScreenshotNotice("nobody"))
        assertEquals(0, http.calls.size)
    }

    // --- FORWARD COMPAT: what an OLD build does with a kind it predates -------
    // Deliberately UNCHANGED by the persistence work — the wire is byte-identical,
    // so an old receiver keeps its burn-on-read behaviour and a new receiver takes
    // an old sender's notice (with or without a "t") in full.

    @Test
    fun unknownDirectKind_isDroppedSilently_atTheTransport() {
        if (!aeadUp()) return
        val h = ScreenshotHarness()
        // A newer peer sends a direct control kind this build has never heard of —
        // exactly the position an old build is in when it receives "screenshot".
        val blob = h.aSendsDirectControl("future-kind")

        val surfaced = h.bDrainsControl(blob)
        assertEquals(0, surfaced.size, "an unknown direct control must never surface as a bubble")
        assertEquals(0, h.bGm.drainScreenshotNotices("a").size, "and must produce no notice")
        assertEquals(0, h.bVault.ssnKeys().size, "and must write nothing to the vault")
        // Nothing else changed: no vault mutation, and the drain still completed
        // (the blob was dropped in the first pass, so its counter is not adopted).
        assertEquals(0L, h.bVault.getContact("a")!!.inboundCtlCounter)

        // …and the channel is NOT poisoned: a real notice sent afterwards still lands.
        h.bDrainsControl(h.aSendsScreenshotNotice())
        assertEquals(1, h.bGm.drainScreenshotNotices("a").size, "an unknown kind must not break later traffic")
    }

    @Test
    fun knownDirectKindAllowlist_isTheOneUsedByBothReceivePaths() {
        // The allowlist both pollChannel and receiveOverTextRatchet consult. Pinning it
        // stops the two paths from drifting apart on a future kind.
        assertTrue(MessageManager.isKnownDirectControlKind(MessageManager.CONTROL_KIND_SCREENSHOT))
        assertTrue(MessageManager.isKnownDirectControlKind(MessageManager.CONTROL_KIND_REFERRAL_OFFER))
        assertTrue(MessageManager.isKnownDirectControlKind(MessageManager.CONTROL_KIND_REFERRAL_ACCEPT))
        assertEquals(false, MessageManager.isKnownDirectControlKind("future-kind"))
        // The inbox announce is handled AHEAD of the allowlist (it mutates vault
        // state), so it is deliberately not a member.
        assertEquals(false, MessageManager.isKnownDirectControlKind(MessageManager.CONTROL_KIND_INBOX))
    }
}

class ScreenshotNoticeGroupTest {

    /** Admin device with [bob] resolved; no createGroup, so the only HTTP calls
     *  are the ones a test triggers. */
    private fun fixture(): Triple<GroupManager, InMemoryVault, String> {
        val vault = InMemoryVault()
        vault.insertContact(ContactRecord("c-bob", generateSecureRandom(32), 1, "Bob", 0L))
        val gm = GroupManager(vault) { null }
        val gid = GroupManager.newGroupId()
        val me = ssMemberId(1)
        vault.insertGroup(GroupRecord(gid, "crew", 1, adminMemberId = me, myMemberId = me, createdAt = 0L))
        vault.insertGroupMember(GroupMemberRecord(gid, me, null, 0L))
        vault.insertGroupMember(GroupMemberRecord(gid, ssMemberId(2), "c-bob", 0L))
        return Triple(gm, vault, gid)
    }

    @Test
    fun groupNotice_isAttributedToTheSendingMember_andIsPersisted() {
        val (gm, vault, gid) = fixture()
        gm.handleControl("c-bob", gid, GroupManager.KIND_SCREENSHOT, "{}")

        val notices = gm.drainScreenshotNotices(gid)
        assertEquals(1, notices.size)
        assertEquals(gid, notices[0].conversationId)
        assertTrue(notices[0].isGroup)
        assertEquals("c-bob", notices[0].senderContactId, "attribution is the pairwise channel")
        assertEquals("Bob", notices[0].senderAlias)
        assertTrue(notices[0].receivedAt > 0)
        assertEquals(notices[0].receivedAt + SCREENSHOT_NOTICE_TTL_MS, notices[0].expiresAt)

        // It never became a message, and the RAM drain is still one-shot…
        assertEquals(0, gm.drainScreenshotNotices(gid).size)
        assertEquals(0, gm.takeGroupScreenItems(gid).size)
        // …but it IS durable, and re-opening the group still renders it.
        assertEquals(listOf("ssn:$gid:c-bob:${notices[0].receivedAt}"), vault.ssnKeys())
        assertEquals(notices, gm.screenshotNotices(gid))
    }

    @Test
    fun groupNotice_displayTimeIsTheSendersClaim_expiryIsOurs() {
        // The envelope's "t" reaches handleControl through ingest and is used for
        // DISPLAY only; a peer that backdates it cannot expire its own notice early.
        val (gm, _, gid) = fixture()
        val backdated = 1L    // absurdly old → not believable, falls back to our clock
        gm.handleControl("c-bob", gid, GroupManager.KIND_SCREENSHOT, "{}", backdated)
        val n = gm.screenshotNotices(gid).single()
        assertEquals(n.receivedAt, n.timestamp, "an unbelievable claim renders as our receive time")
        assertEquals(n.receivedAt + SCREENSHOT_NOTICE_TTL_MS, n.expiresAt)
    }

    @Test
    fun groupNotice_lightsTheUnseenCount_untilTheGroupIsPolled() {
        // DELIBERATE REVERSAL of the old `groupNotice_doesNotTouchTheUnreadCounters`
        // (design §2.7). A notice is still not a queued message — it never touches
        // the KIND_ACTIVITY tally — but it is now DURABLE, so something has to point
        // the user at it: an UNSEEN persisted notice adds its own term to the dot,
        // and opening the conversation clears it.
        val (gm, _, gid) = fixture()
        gm.handleControl("c-bob", gid, GroupManager.KIND_SCREENSHOT, "{}")
        assertEquals(1, gm.groupUnreadCounts()[gid], "an unseen notice lights the group dot")

        gm.pollGroup(gid)      // opening the group marks its notices seen
        assertTrue(gm.groupUnreadCounts().isEmpty(), "opening the group clears the dot")
        assertEquals(1, gm.screenshotNotices(gid).size, "…without deleting the notice")
    }

    @Test
    fun groupNotice_fromNonMemberOrUnknownGroup_isIgnored() {
        val (gm, vault, gid) = fixture()
        vault.insertContact(ContactRecord("c-mallory", generateSecureRandom(32), 1, "M", 0L))
        // Known group, sender is not a member.
        gm.handleControl("c-mallory", gid, GroupManager.KIND_SCREENSHOT, "{}")
        assertEquals(0, gm.drainScreenshotNotices(gid).size)
        // Unknown group id.
        val other = GroupManager.newGroupId()
        gm.handleControl("c-bob", other, GroupManager.KIND_SCREENSHOT, "{}")
        assertEquals(0, gm.drainScreenshotNotices(other).size)
        assertEquals(0, vault.ssnKeys().size, "a rejected notice must write nothing to the vault")
    }

    @Test
    fun groupNotice_reachesHandleControl_throughIngest() {
        val (gm, _, gid) = fixture()
        // The real delivery shape: a control ReceivedMessage carrying the group id.
        gm.ingest(
            "c-bob",
            listOf(ReceivedMessage("", 0L, counter = 1, groupId = gid, controlKind = GroupManager.KIND_SCREENSHOT, controlBody = "{}")),
            wantGroupId = null,
        )
        assertEquals(1, gm.drainScreenshotNotices(gid).size)
    }

    @Test
    fun unknownGroupKind_isDroppedSilently_byHandleControl() {
        val (gm, vault, gid) = fixture()
        val epochBefore = vault.getGroup(gid)!!.epoch
        val membersBefore = vault.getGroupMembers(gid).size
        // An old build receiving "screenshot" lands here: the `else` arm.
        gm.handleControl("c-bob", gid, "future-kind", """{"n":"x","ep":99}""")
        gm.ingest(
            "c-bob",
            listOf(ReceivedMessage("", 0L, counter = 1, groupId = gid, controlKind = "future-kind", controlBody = "{}")),
            wantGroupId = null,
        )
        // Nothing rendered, nothing buffered, no vault mutation, no throw.
        assertEquals(0, gm.drainScreenshotNotices(gid).size)
        assertEquals(0, gm.takeGroupScreenItems(gid).size)
        assertEquals(epochBefore, vault.getGroup(gid)!!.epoch)
        assertEquals(membersBefore, vault.getGroupMembers(gid).size)
        assertEquals(0, vault.ssnKeys().size)
        assertTrue(gm.groupUnreadCounts().isEmpty())
    }

    @Test
    fun pendingNotices_areBounded_perConversation() {
        val (gm, vault, gid) = fixture()
        val flood = GroupManager.MAX_PENDING_SCREENSHOT_NOTICES_PER_CONVERSATION + 20
        repeat(flood) { gm.handleControl("c-bob", gid, GroupManager.KIND_SCREENSHOT, "{}") }
        assertEquals(
            GroupManager.MAX_PENDING_SCREENSHOT_NOTICES_PER_CONVERSATION,
            gm.drainScreenshotNotices(gid).size,
            "an authenticated member must not be able to park unbounded notices",
        )
        assertEquals(
            ScreenshotNoticeStore.MAX_PER_CONVERSATION, vault.ssnKeys().size,
            "…nor grow the vault without bound",
        )
    }

    @Test
    fun scrubInMemory_dropsPendingNotices_butKeepsTheDurableRows() {
        val (gm, vault, gid) = fixture()
        gm.handleControl("c-bob", gid, GroupManager.KIND_SCREENSHOT, "{}")
        gm.scrubInMemory()
        assertEquals(0, gm.drainScreenshotNotices(gid).size, "lock/wipe must drop the RAM buffer")
        // scrubInMemory runs on ORDINARY backgrounding. Dropping the durable row
        // there would reinstate exactly the loss this feature fixes; the vault-wide
        // crypto-erase is what removes it on a real wipe.
        assertEquals(1, vault.ssnKeys().size, "an ordinary lock must NOT drop the persisted notice")
        assertEquals(1, gm.screenshotNotices(gid).size)
    }

    @Test
    fun wipeAllTables_erasesThePersistedNotices() {
        // The iOS wipe path (and every test double) clears `_meta` wholesale; the
        // Android wipe deletes the whole encrypted file. Either way, nothing survives.
        val (gm, vault, gid) = fixture()
        gm.handleControl("c-bob", gid, GroupManager.KIND_SCREENSHOT, "{}")
        assertEquals(1, vault.ssnKeys().size)
        vault.wipeAllTables()
        assertEquals(0, vault.ssnKeys().size, "a wipe must take the notices with it")
    }

    @Test
    fun sendGroupScreenshotNotice_fansOutOneControlCopyPerResolvedMember() {
        if (!aeadUp()) return
        val vault = InMemoryVault()
        for (id in listOf("c-bob", "c-carol")) {
            vault.insertContact(ContactRecord(id, generateSecureRandom(32), 1, "A-$id", 0L))
            val base = id.hashCode().toUInt().toString(16).padStart(8, '0')
            vault.insertInboxId(InboxIdRecord(
                ("ou$base".padEnd(32, 'B')).take(32), id, 1L, Long.MAX_VALUE, "outbound", SS_CAP,
            ))
        }
        val http = RecordingRelayHttp()
        repeat(2) { http.script(HttpResult(202, "", true)) }
        val mgr = MessageManager(vault, "http://relay.test", http as RelayHttp)
        val gm = GroupManager(vault) { mgr }
        val gid = GroupManager.newGroupId()
        val me = ssMemberId(1)
        vault.insertGroup(GroupRecord(gid, "crew", 1, adminMemberId = me, myMemberId = me, createdAt = 0L))
        vault.insertGroupMember(GroupMemberRecord(gid, me, null, 0L))
        vault.insertGroupMember(GroupMemberRecord(gid, ssMemberId(2), "c-bob", 0L))
        vault.insertGroupMember(GroupMemberRecord(gid, ssMemberId(3), "c-carol", 0L))
        vault.insertGroupMember(GroupMemberRecord(gid, ssMemberId(4), null, 0L))   // unresolved → skipped

        gm.sendGroupScreenshotNotice(gid)

        assertEquals(2, http.calls.size, "one control copy per RESOLVED member, self excluded")
        assertEquals(2, http.calls.map { it.url }.toSet().size, "each copy goes to its own member inbox")
        // No push wake for a non-message.
        assertTrue(http.calls.all { it.headers["X-No-Push"] == "1" }, "a notice must not wake the peer's device")
        // Sending is not receiving: our own screenshot writes nothing locally.
        assertEquals(0, vault.ssnKeys().size)
    }

    @Test
    fun sendGroupScreenshotNotice_withNoResolvedMembers_sendsNothing() {
        val vault = InMemoryVault()
        val http = RecordingRelayHttp()
        val mgr = MessageManager(vault, "http://relay.test", http as RelayHttp)
        val gm = GroupManager(vault) { mgr }
        val gid = GroupManager.newGroupId()
        val me = ssMemberId(1)
        vault.insertGroup(GroupRecord(gid, "g", 1, adminMemberId = me, myMemberId = me, createdAt = 0L))
        vault.insertGroupMember(GroupMemberRecord(gid, me, null, 0L))
        vault.insertGroupMember(GroupMemberRecord(gid, ssMemberId(2), null, 0L))   // unresolved
        gm.sendGroupScreenshotNotice(gid)
        gm.sendGroupScreenshotNotice(GroupManager.newGroupId())                    // unknown group
        assertEquals(0, http.calls.size, "nothing to fan out — and no throw")
    }

    @Test
    fun notices_areKeyedPerConversation() {
        val (gm, vault, gid) = fixture()
        // A second group with the same member.
        val gid2 = GroupManager.newGroupId()
        val me2 = ssMemberId(5)
        vault.insertGroup(GroupRecord(gid2, "crew2", 1, adminMemberId = me2, myMemberId = me2, createdAt = 0L))
        vault.insertGroupMember(GroupMemberRecord(gid2, me2, null, 0L))
        vault.insertGroupMember(GroupMemberRecord(gid2, ssMemberId(6), "c-bob", 0L))

        gm.handleControl("c-bob", gid, GroupManager.KIND_SCREENSHOT, "{}")
        gm.handleControl("c-bob", gid2, GroupManager.KIND_SCREENSHOT, "{}")

        assertEquals(1, gm.drainScreenshotNotices(gid).size)
        val second = gm.drainScreenshotNotices(gid2)
        assertEquals(1, second.size)
        assertEquals(gid2, second[0].conversationId)
        assertEquals("Bob", second[0].senderAlias)
        // …and the durable rows are keyed per conversation too.
        assertEquals(1, gm.screenshotNotices(gid).size)
        assertEquals(1, gm.screenshotNotices(gid2).size)
        assertEquals(2, vault.ssnKeys().size)
    }

    @Test
    fun expiredNotices_areNotRendered_andArePruned() {
        val (gm, vault, gid) = fixture()
        gm.handleControl("c-bob", gid, GroupManager.KIND_SCREENSHOT, "{}")
        assertEquals(1, gm.screenshotNotices(gid).size)

        // Age the persisted row past the TTL by rewriting its key (the receivedAt
        // suffix IS the anchor), then let the sweep hook GC it.
        val key = vault.ssnKeys().single()
        val value = vault.getMeta(key)!!
        vault.deleteMeta(key)
        val stale = currentTimeMillis() - SCREENSHOT_NOTICE_TTL_MS - 1
        vault.putMeta("ssn:$gid:c-bob:$stale", value)

        assertEquals(0, gm.screenshotNotices(gid).size, "an expired notice is never rendered")
        gm.pruneExpiredScreenshotNotices()
        assertEquals(0, vault.ssnKeys().size, "and the sweep hook removes the row")
    }
}

package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// Control-channel (v7) tests.
//
// Each pairing now has TWO inbox pairs: text + control. Control inboxes are
// drained by the background poller at any time (which is what delivers group
// invites to every member's device), so the two channels advance their
// anti-replay counters independently — a shared counter space would
// false-reject cross-channel reordering as replays.
// ---------------------------------------------------------------------------

private const val MAIN_IN   = "MAINyyyyyyyyyyyyyyyyyyyyyyyyyyyy"
private const val MAIN_OUT  = "MAINxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
private const val CTL_IN    = "CTLyyyyyyyyyyyyyyyyyyyyyyyyyyyyy"
private const val CTL_OUT   = "CTLxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
private const val CAP       = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

/** Sender A (fully paired incl. ctl) + receiver B sharing one secret. */
private class ChannelHarness {
    val shared = generateSecureRandom(32)
    val aVault = InMemoryVault()
    val aHttp = RecordingRelayHttp()
    val aMgr = MessageManager(aVault, "http://relay.test", aHttp as RelayHttp)
    val bVault = InMemoryVault()
    val bHttp = RecordingRelayHttp()
    val bMgr = MessageManager(bVault, "http://relay.test", bHttp as RelayHttp)

    init {
        aVault.insertContact(ContactRecord("b", shared, 0, "B", 0L))
        aVault.insertInboxId(InboxIdRecord(MAIN_OUT, "b", 1L, Long.MAX_VALUE, "outbound", CAP))
        aVault.insertInboxId(InboxIdRecord(CTL_OUT, "b", 1L, Long.MAX_VALUE, MessageManager.DIR_OUTBOUND_CTL, CAP))
        bVault.insertContact(ContactRecord("a", shared, 0, "A", 0L))
        bVault.insertInboxId(InboxIdRecord(MAIN_OUT, "a", 1L, Long.MAX_VALUE, "inbound", CAP))
        bVault.insertInboxId(InboxIdRecord(CTL_OUT, "a", 1L, Long.MAX_VALUE, MessageManager.DIR_INBOUND_CTL, CAP))
    }

    fun lastBlobB64(): String = encodeBase64(aHttp.calls.last().body)
}

class ControlChannelTest {

    @Test
    fun controlTraffic_prefersTheCtlInbox_andFallsBackForOldPeers() {
        if (!aeadUp()) return
        val h = ChannelHarness()
        h.aHttp.script(HttpResult(202, "", true), HttpResult(202, "", true))

        // Announce (control) → must hit the CTL inbox URL.
        assertTrue(h.aMgr.sendInboxAnnounce("b", MAIN_IN, CAP))
        // Every control append now carries the uniform `?ttl`, so compare the
        // PATH — which inbox it went to is what this test is about.
        assertTrue(h.aHttp.calls.last().url.substringBefore("?").endsWith("/inbox/$CTL_OUT"))

        // Text → main inbox URL.
        assertTrue(h.aMgr.sendMessage("b", "hi"))
        assertTrue(h.aHttp.calls.last().url.endsWith("/inbox/$MAIN_OUT"))

        // Old peer (no ctl outbound row): control falls back to main.
        val old = InMemoryVault()
        val oldHttp = RecordingRelayHttp()
        val oldMgr = MessageManager(old, "http://relay.test", oldHttp as RelayHttp)
        old.insertContact(ContactRecord("b", generateSecureRandom(32), 0, "B", 0L))
        old.insertInboxId(InboxIdRecord(MAIN_OUT, "b", 1L, Long.MAX_VALUE, "outbound", CAP))
        oldHttp.script(HttpResult(202, "", true))
        assertTrue(oldMgr.sendInboxAnnounce("b", MAIN_IN, CAP))
        assertTrue(oldHttp.calls.last().url.substringBefore("?").endsWith("/inbox/$MAIN_OUT"))
        // …and the MAIN counter space was consumed (fallback channel's space).
        assertEquals(1L, old.getContact("b")!!.outboundCounter)
        assertEquals(0L, old.getContact("b")!!.outboundCtlCounter)
    }

    @Test
    fun channels_haveIndependentCounterSpaces() {
        if (!aeadUp()) return
        val h = ChannelHarness()
        repeat(4) { h.aHttp.script(HttpResult(202, "", true)) }

        // Interleave: ctl, text, ctl — per-channel counters advance separately.
        assertTrue(h.aMgr.sendInboxAnnounce("b", MAIN_IN, CAP))
        val ctlBlob1 = h.lastBlobB64()
        assertTrue(h.aMgr.sendMessage("b", "text-1"))
        val textBlob = h.lastBlobB64()
        assertTrue(h.aMgr.sendInboxAnnounce("b", MAIN_IN, CAP, CTL_IN, CAP))
        val ctlBlob2 = h.lastBlobB64()
        assertEquals(2L, h.aVault.getContact("b")!!.outboundCtlCounter)
        assertEquals(1L, h.aVault.getContact("b")!!.outboundCounter)

        // B drains the CTL channel FIRST (background poller beats the user
        // opening the conversation) — both ctl messages accepted…
        h.bHttp.script(HttpResult(200, """{"blobs":["$ctlBlob1","$ctlBlob2"]}""", true))
        val ctlSurfaced = h.bMgr.pollControlMessages("a")
        assertEquals(0, ctlSurfaced.size)   // announces never surface
        assertEquals(2L, h.bVault.getContact("a")!!.inboundCtlCounter)
        // …including the ctl-pair upsert from the second announce.
        assertNotNull(h.bVault.getInboxIdForContact("a", MessageManager.DIR_OUTBOUND_CTL))

        // …then the MAIN channel: counter 1 on a separate space must still be
        // accepted (a shared space would call it a replay of ctl counter 1).
        h.bHttp.script(HttpResult(200, """{"blobs":["$textBlob"]}""", true))
        val texts = h.bMgr.pollMessages("a")
        assertEquals(1, texts.size)
        assertEquals("text-1", texts[0].text)
        assertEquals(false, texts[0].sequenceGap)
        assertEquals(1L, h.bVault.getContact("a")!!.inboundCounter)
    }

    @Test
    fun pollControlMessages_withoutCtlInbox_isANetworklessNoop() {
        val vault = InMemoryVault()
        val http = RecordingRelayHttp()
        val mgr = MessageManager(vault, "http://relay.test", http as RelayHttp)
        vault.insertContact(ContactRecord("c", generateSecureRandom(32), 0, "C", 0L))
        vault.insertInboxId(InboxIdRecord(MAIN_OUT, "c", 1L, Long.MAX_VALUE, "inbound", CAP))
        assertEquals(0, mgr.pollControlMessages("c").size)
        assertEquals(0, http.calls.size, "pre-v7 contact: control poll must not touch the network")
    }

    @Test
    fun groupInvite_travelsTheControlChannel() {
        if (!aeadUp()) return
        // Admin creates a group with one fully-paired (incl. ctl) member —
        // the invite must be posted to the member's CONTROL inbox, which is
        // what the member's background poller drains.
        val vault = InMemoryVault()
        val http = RecordingRelayHttp()
        val mgr = MessageManager(vault, "http://relay.test", http as RelayHttp)
        vault.insertContact(ContactRecord("m", generateSecureRandom(32), 0, "M", 0L))
        vault.insertInboxId(InboxIdRecord(MAIN_OUT, "m", 1L, Long.MAX_VALUE, "outbound", CAP))
        vault.insertInboxId(InboxIdRecord(MAIN_IN, "m", 1L, Long.MAX_VALUE, "inbound", CAP))
        vault.insertInboxId(InboxIdRecord(CTL_OUT, "m", 1L, Long.MAX_VALUE, MessageManager.DIR_OUTBOUND_CTL, CAP))
        vault.insertInboxId(InboxIdRecord(CTL_IN, "m", 1L, Long.MAX_VALUE, MessageManager.DIR_INBOUND_CTL, CAP))
        http.script(HttpResult(202, "", true))
        val gm = GroupManager(vault) { mgr }

        val gid = gm.createGroup("crew", listOf("m"))
        assertNotNull(gid)
        val url = http.calls.single().url
        assertTrue(
            url.substringBefore("?").endsWith("/inbox/$CTL_OUT"),
            "invite must go to the member's control inbox",
        )
        // Membership-change control outlives the relay's
        // 24 h default so an absent member still receives it.
        assertTrue(url.endsWith("?ttl=${GroupManager.MEMBERSHIP_CONTROL_TTL_SECONDS}"), "invite must carry the 7-day TTL: $url")
    }

    // The CONTROL channel must honor the Block set exactly as the
    // text peek does — a blocked contact's control inbox is NOT polled, so it can
    // neither surface an invite/offer modal nor mutate the vault via inbox-announce.
    @Test
    fun blockedContact_controlInbox_isNotPolled() {
        if (!aeadUp()) return
        fun setup(): Pair<GroupManager, RecordingRelayHttp> {
            val vault = InMemoryVault()
            val http = RecordingRelayHttp()
            val mgr = MessageManager(vault, "http://relay.test", http as RelayHttp)
            vault.insertContact(ContactRecord("m", generateSecureRandom(32), 0, "M", 0L))
            vault.insertInboxId(InboxIdRecord(CTL_IN, "m", 1L, Long.MAX_VALUE, MessageManager.DIR_INBOUND_CTL, CAP))
            http.script(HttpResult(200, "[]", true), HttpResult(200, "[]", true))
            return GroupManager(vault) { mgr } to http
        }
        // Not blocked → the control inbox IS polled (baseline: the filter isn't a no-op).
        val (gmAllowed, httpAllowed) = setup()
        gmAllowed.pollAllControls()
        assertTrue(httpAllowed.calls.isNotEmpty(), "an un-blocked contact's control inbox should be polled")

        // Blocked → NO relay poll for that contact at all.
        val (gmBlocked, httpBlocked) = setup()
        gmBlocked.blockedContacts = { setOf("m") }
        gmBlocked.pollAllControls()
        assertTrue(httpBlocked.calls.isEmpty(), "a blocked contact's control inbox must NOT be polled (M1)")
    }

    // The SIBLING on-demand path. Opening a group with a blocked
    // co-member must not poll their inbox either — pollGroup honors the block set.
    @Test
    fun blockedGroupMember_isNotPolled_byPollGroup() {
        if (!aeadUp()) return
        fun setup(): Pair<GroupManager, RecordingRelayHttp> {
            val vault = InMemoryVault()
            val http = RecordingRelayHttp()
            val mgr = MessageManager(vault, "http://relay.test", http as RelayHttp)
            vault.insertContact(ContactRecord("m", generateSecureRandom(32), 0, "M", 0L))
            vault.insertInboxId(InboxIdRecord(MAIN_IN, "m", 1L, Long.MAX_VALUE, "inbound", CAP))
            vault.insertGroup(GroupRecord("g", "crew", 1L, "aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb", 0L))
            vault.insertGroupMember(GroupMemberRecord("g", "cccccccccccccccc", "m", 0L))
            http.script(HttpResult(200, "{\"blobs\":[]}", true), HttpResult(200, "{\"blobs\":[]}", true))
            return GroupManager(vault) { mgr } to http
        }
        // Not blocked → the member's inbox IS polled.
        val (gmAllowed, httpAllowed) = setup()
        gmAllowed.pollGroup("g")
        assertTrue(httpAllowed.calls.isNotEmpty(), "an un-blocked group member should be polled")

        // Blocked → NOT polled on the on-demand pollGroup path.
        val (gmBlocked, httpBlocked) = setup()
        gmBlocked.blockedContacts = { setOf("m") }
        gmBlocked.pollGroup("g")
        assertTrue(httpBlocked.calls.isEmpty(), "a blocked group member's inbox must NOT be polled (M1-R1)")
    }
}

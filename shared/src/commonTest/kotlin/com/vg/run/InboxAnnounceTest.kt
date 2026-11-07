package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// In-band inbox announce (instant-QR pairing) tests.
//
// The announce is the message that closes the pairing loop when one device
// showed a secret-only QR: the device that scanned the FULL code delivers
// its own (inboxId, writeCap) through the peer's inbox; the peer's poll
// applies it as an outbound record without surfacing anything in the UI.
// ---------------------------------------------------------------------------

private const val A_INBOX  = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"   // announced inbox (A's inbound)
private const val A_WCAP   = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
private const val B_INBOX  = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"   // B's inbound (A sends here)
private const val B_RCAP   = "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"
private const val B_WCAP   = "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE"
// Eclipse fixtures: a THIRD party C, already paired with B, plus A's rotated cap.
private const val B_C_INBOX = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"  // B's inbound for contact C
private const val C_INBOX  = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"   // C's inbound (B sends here)
private const val C_WCAP   = "GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG"
private const val C_CTL_INBOX = "cccccccccccccccccccccccccccccccc"   // C's control inbox
private const val C_CTL_WCAP  = "HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH"
private const val A_WCAP2  = "IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII"   // A's rotated write cap
private const val A_INBOX2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB"   // A's rotated inbox
private const val A_CTL_INBOX = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"   // A's control inbox
private const val A_CTL_WCAP  = "JJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJ"

class InboxAnnounceTest {

    /** Sets up sender (A, fully paired) and receiver (B, PENDING — no
     *  outbound yet) sharing one pairwise secret. */
    private class Harness {
        val shared = generateSecureRandom(32)
        val aVault = InMemoryVault()
        val aHttp = RecordingRelayHttp()
        val aMgr = MessageManager(aVault, "http://relay.test", aHttp as RelayHttp)
        val bVault = InMemoryVault()
        val bHttp = RecordingRelayHttp()
        val bMgr = MessageManager(bVault, "http://relay.test", bHttp as RelayHttp)

        init {
            // A: knows B's inbox (scanned the full QR) + its own inbound.
            aVault.insertContact(ContactRecord("peer-b", shared, 0, "B", 0L))
            aVault.insertInboxId(InboxIdRecord(B_INBOX, "peer-b", 1L, Long.MAX_VALUE, "outbound", B_WCAP))
            aVault.insertInboxId(InboxIdRecord(A_INBOX, "peer-b", 1L, Long.MAX_VALUE, "inbound", "F".repeat(43)))
            // B: scanned A's secret-only QR — inbound only, outbound PENDING.
            bVault.insertContact(ContactRecord("peer-a", shared, 0, "A", 0L))
            bVault.insertInboxId(InboxIdRecord(B_INBOX, "peer-a", 1L, Long.MAX_VALUE, "inbound", B_RCAP))
        }

        /**
         * Sends A's announce, captures the blob, serves it to B's poll. The
         * announced values default to A's own inbox (the honest case); a test can
         * override them to model a peer claiming an inbox that isn't its own.
         */
        fun deliverAnnounce(
            ib: String = A_INBOX,
            wc: String = A_WCAP,
            cib: String? = null,
            cwc: String? = null,
        ): List<ReceivedMessage> {
            aHttp.script(HttpResult(code = 202, body = "", isSuccess = true))
            assertTrue(aMgr.sendInboxAnnounce("peer-b", ib, wc, cib, cwc), "announce send must succeed")
            val blob = aHttp.calls.last().body
            bHttp.script(
                HttpResult(
                    code = 200,
                    body = """{"blobs":["${encodeBase64(blob)}"]}""",
                    isSuccess = true,
                )
            )
            return bMgr.pollMessages("peer-a")
        }

        /** Gives B a THIRD, fully-paired contact C — the eclipse victim. */
        fun addVictimContactC() {
            bVault.insertContact(ContactRecord("peer-c", generateSecureRandom(32), 0, "C", 0L))
            // Our inbound inbox for C, then C's inboxes we send to.
            bVault.insertInboxId(InboxIdRecord(B_C_INBOX, "peer-c", 1L, Long.MAX_VALUE, "inbound", B_RCAP))
            bVault.insertInboxId(InboxIdRecord(C_INBOX, "peer-c", 1L, Long.MAX_VALUE, "outbound", C_WCAP))
            bVault.insertInboxId(InboxIdRecord(
                C_CTL_INBOX, "peer-c", 1L, Long.MAX_VALUE, MessageManager.DIR_OUTBOUND_CTL, C_CTL_WCAP,
            ))
        }
    }

    @Test
    fun announce_completesThePendingPairing_withoutSurfacingAMessage() {
        if (!aeadUp()) return
        val h = Harness()
        assertTrue(contactAwaitingPeerInbox(h.bVault, "peer-a"), "B must start pending")
        assertEquals(false, contactFullyPaired(h.bVault, "peer-a"))

        val surfaced = h.deliverAnnounce()

        // Nothing reaches the UI…
        assertEquals(0, surfaced.size, "an announce must never surface as a message")
        // …but the outbound record landed, with exactly the announced values.
        val outbound = h.bVault.getInboxIdForContact("peer-a", "outbound")
        assertNotNull(outbound)
        assertEquals(A_INBOX, outbound.inboxId)
        assertEquals(A_WCAP, outbound.cap)
        assertEquals(false, contactAwaitingPeerInbox(h.bVault, "peer-a"))
        assertTrue(contactFullyPaired(h.bVault, "peer-a"))
        // The anti-replay baseline advanced — announces consume counter space.
        assertEquals(1L, h.bVault.getContact("peer-a")!!.inboundCounter)
    }

    @Test
    fun replayedAnnounce_isRejectedByTheCounter() {
        if (!aeadUp()) return
        val h = Harness()
        h.deliverAnnounce()
        val blobBody = h.bHttp.calls.last()  // poll GET — re-serve the same blob
        // Manually re-serve the identical blob: counter 1 <= baseline 1 → drop.
        val firstBlob = h.aHttp.calls.last().body
        h.bHttp.script(
            HttpResult(code = 200, body = """{"blobs":["${encodeBase64(firstBlob)}"]}""", isSuccess = true)
        )
        h.bMgr.pollMessages("peer-a")
        // Baseline unchanged, outbound unchanged (no duplicate rows / resets).
        assertEquals(1L, h.bVault.getContact("peer-a")!!.inboundCounter)
        assertEquals(A_INBOX, h.bVault.getInboxIdForContact("peer-a", "outbound")!!.inboxId)
        // (suppress unused-variable warning)
        assertNotNull(blobBody)
    }

    @Test
    fun announce_withMalformedValues_isRefusedBeforeTheNetwork() {
        val vault = InMemoryVault()
        val http = RecordingRelayHttp()
        val mgr = MessageManager(vault, "http://relay.test", http as RelayHttp)
        // Bad inbox shape and bad cap shape: both refused with zero calls.
        assertEquals(false, mgr.sendInboxAnnounce("c", "not-an-inbox", A_WCAP))
        assertEquals(false, mgr.sendInboxAnnounce("c", A_INBOX, "short-cap"))
        assertEquals(0, http.calls.size)
    }

    // --- Cross-contact eclipse ------------
    //
    // `inbox_ids` is keyed by inboxId (PRIMARY KEY + INSERT-OR-REPLACE on both
    // platforms), so an accepted announce MOVES the row. A paired contact that
    // learned a THIRD party's inbox id — the referral handshake relays the
    // introducee's `ib`/`wc`/`cib`/`cwc` through the introducer in plaintext —
    // could therefore announce it as its own inside a fully AEAD-authenticated
    // control blob and destroy that contact's outbound route.

    @Test
    fun announce_cannotClaimAnotherContactsOutboundInbox() {
        if (!aeadUp()) return
        val h = Harness()
        h.addVictimContactC()
        assertTrue(contactFullyPaired(h.bVault, "peer-c"), "victim C must start fully paired")

        // A (authenticated, e.g. the introducer that saw C's accept body) announces
        // C's inbox id as its own. The blob passes AEAD/epoch/counter/ch/di.
        val surfaced = h.deliverAnnounce(ib = C_INBOX, wc = A_WCAP)

        assertEquals(0, surfaced.size, "an announce must never surface as a message")
        // C's route is untouched — same owner, same cap, still sendable.
        val cRow = h.bVault.getInboxId(C_INBOX)
        assertNotNull(cRow)
        assertEquals("peer-c", cRow.contactId, "C's outbound row must not be reassigned")
        assertEquals(C_WCAP, cRow.cap, "C's write cap must not be replaced")
        assertTrue(contactFullyPaired(h.bVault, "peer-c"), "C must stay sendable")
        // …and A gained nothing: it is still awaiting an inbox of its own.
        assertNull(h.bVault.getInboxIdForContact("peer-a", "outbound"))
        assertTrue(contactAwaitingPeerInbox(h.bVault, "peer-a"))
    }

    @Test
    fun announce_cannotClaimAnotherContactsControlOutboundInbox() {
        if (!aeadUp()) return
        val h = Harness()
        h.addVictimContactC()

        // The ctl half of the same attack: a well-formed own `ib` paired with a
        // `cib` that belongs to C. The WHOLE announce is dropped (both-or-neither),
        // so A doesn't even get the main-channel row.
        h.deliverAnnounce(ib = A_INBOX, wc = A_WCAP, cib = C_CTL_INBOX, cwc = A_CTL_WCAP)

        val cCtl = h.bVault.getInboxId(C_CTL_INBOX)
        assertNotNull(cCtl)
        assertEquals("peer-c", cCtl.contactId, "C's control row must not be reassigned")
        assertEquals(C_CTL_WCAP, cCtl.cap)
        assertNull(h.bVault.getInboxIdForContact("peer-a", "outbound"))
        assertNull(h.bVault.getInboxIdForContact("peer-a", MessageManager.DIR_OUTBOUND_CTL))
    }

    @Test
    fun announce_namingOurOwnInboundInbox_isStillRejected() {
        if (!aeadUp()) return
        val h = Harness()
        // The pre-existing half of the same predicate: a relay
        // reflecting our own announce back would repoint our sends at our own inbox.
        h.deliverAnnounce(ib = B_INBOX, wc = A_WCAP)
        assertNull(h.bVault.getInboxIdForContact("peer-a", "outbound"))
        // Our inbound row is intact — still ours, still the read cap.
        val own = h.bVault.getInboxId(B_INBOX)
        assertNotNull(own)
        assertEquals("inbound", own.direction)
        assertEquals(B_RCAP, own.cap)
    }

    @Test
    fun reAnnounceByTheRightfulOwner_stillLands_evenWithARotatedCap() {
        if (!aeadUp()) return
        val h = Harness()
        h.addVictimContactC()          // an unrelated contact must not interfere
        h.deliverAnnounce()            // first announce: unknown id → accepted
        assertEquals(A_INBOX, h.bVault.getInboxIdForContact("peer-a", "outbound")!!.inboxId)

        // A rotates its write capability and re-announces the SAME inbox id. The row
        // is already ours-for-this-contact, so it must be UPDATED, not rejected —
        // this is the in-band rotation path the announce doubles as.
        h.deliverAnnounce(ib = A_INBOX, wc = A_WCAP2)
        val row = h.bVault.getInboxIdForContact("peer-a", "outbound")
        assertNotNull(row)
        assertEquals(A_INBOX, row.inboxId)
        assertEquals(A_WCAP2, row.cap, "a rightful re-announce must refresh the cap")

        // And a genuinely NEW inbox id from the same contact (inbox rotation /
        // re-pair after a 404 streak) is still unknown → still accepted. Asserted on
        // the row itself: `getInboxIdForContact` picks one of the two same-direction
        // rows by recency, which the in-memory double doesn't model.
        h.deliverAnnounce(ib = A_INBOX2, wc = A_WCAP2)
        val rotated = h.bVault.getInboxId(A_INBOX2)
        assertNotNull(rotated)
        assertEquals("peer-a", rotated.contactId)
        assertEquals("outbound", rotated.direction)
        // Throughout, C's route was never touched.
        assertEquals("peer-c", h.bVault.getInboxId(C_INBOX)!!.contactId)
    }

    // --- The two announced ids collide with EACH OTHER ------------------
    //
    // The old ownership check ran per id against the vault, so `ib == cib` passed
    // both times (nothing owned the id yet, or the announcer owned it). The two
    // inserts then landed on ONE primary key and the ctl row REPLACED the outbound
    // row — an authenticated peer could silently un-send its own conversation, and
    // a hostile one could do it deliberately. The batch check rejects the announce
    // whole, so the established route survives.

    @Test
    fun announce_withSameIdForBothChannels_leavesTheEstablishedOutboundRowIntact() {
        if (!aeadUp()) return
        val h = Harness()
        h.deliverAnnounce()                                  // establish A_INBOX as outbound
        assertEquals(A_INBOX, h.bVault.getInboxIdForContact("peer-a", "outbound")!!.inboxId)

        // Re-announce the SAME (rightfully owned) id as BOTH the message and the
        // control inbox. Without the batch check the ctl insert replaces the
        // outbound row in place and the contact becomes un-sendable.
        h.deliverAnnounce(ib = A_INBOX, wc = A_WCAP, cib = A_INBOX, cwc = A_CTL_WCAP)

        val out = assertNotNull(
            h.bVault.getInboxIdForContact("peer-a", "outbound"),
            "the established outbound row must survive an ib==cib announce",
        )
        assertEquals(A_INBOX, out.inboxId)
        assertEquals(A_WCAP, out.cap)
        assertEquals("outbound", h.bVault.getInboxId(A_INBOX)!!.direction)
        assertNull(
            h.bVault.getInboxIdForContact("peer-a", MessageManager.DIR_OUTBOUND_CTL),
            "no control row may be created from a rejected announce",
        )
        assertTrue(contactFullyPaired(h.bVault, "peer-a"), "the contact must stay sendable")
    }

    @Test
    fun announce_withSameIdForBothChannels_onAPendingContact_writesNothing() {
        if (!aeadUp()) return
        val h = Harness()
        // Never-announced contact: both ids are unknown, so the per-id check passed
        // and the pairing landed with ONE row in the WRONG direction.
        h.deliverAnnounce(ib = A_INBOX, wc = A_WCAP, cib = A_INBOX, cwc = A_CTL_WCAP)

        assertNull(h.bVault.getInboxId(A_INBOX), "a rejected announce must write no row at all")
        assertNull(h.bVault.getInboxIdForContact("peer-a", "outbound"))
        assertNull(h.bVault.getInboxIdForContact("peer-a", MessageManager.DIR_OUTBOUND_CTL))
        assertTrue(contactAwaitingPeerInbox(h.bVault, "peer-a"))
    }

    @Test
    fun firstAnnounceWithBothChannels_isAccepted_whenNothingOwnsThoseIds() {
        if (!aeadUp()) return
        val h = Harness()
        h.addVictimContactC()
        // The normal v7 pairing case: two freshly-minted, unknown ids → accepted.
        h.deliverAnnounce(ib = A_INBOX, wc = A_WCAP, cib = A_CTL_INBOX, cwc = A_CTL_WCAP)
        assertEquals(A_INBOX, h.bVault.getInboxIdForContact("peer-a", "outbound")!!.inboxId)
        val ctl = h.bVault.getInboxIdForContact("peer-a", MessageManager.DIR_OUTBOUND_CTL)
        assertNotNull(ctl)
        assertEquals(A_CTL_INBOX, ctl.inboxId)
        assertEquals(A_CTL_WCAP, ctl.cap)
    }
}

class PairingStateTest {

    @Test
    fun pendingContact_isNotStale_andNotFullyPaired() {
        val vault = InMemoryVault()
        vault.insertContact(ContactRecord("c", generateSecureRandom(32), 0, "C", 0L))
        vault.insertInboxId(InboxIdRecord(B_INBOX, "c", 1L, Long.MAX_VALUE, "inbound", B_RCAP))
        assertEquals(false, contactNeedsRepair(vault, "c"))
        assertTrue(contactAwaitingPeerInbox(vault, "c"))
        assertEquals(false, contactFullyPaired(vault, "c"))
    }

    @Test
    fun missingInbound_isStale_notPending() {
        val vault = InMemoryVault()
        vault.insertContact(ContactRecord("c", generateSecureRandom(32), 0, "C", 0L))
        // Outbound only — broken state, must read as repair.
        vault.insertInboxId(InboxIdRecord(A_INBOX, "c", 1L, Long.MAX_VALUE, "outbound", A_WCAP))
        assertTrue(contactNeedsRepair(vault, "c"))
        assertEquals(false, contactAwaitingPeerInbox(vault, "c"))
        assertEquals(false, contactFullyPaired(vault, "c"))
    }

    @Test
    fun legacyOutbound_isStillStale() {
        val vault = InMemoryVault()
        vault.insertContact(ContactRecord("c", generateSecureRandom(32), 0, "C", 0L))
        vault.insertInboxId(InboxIdRecord(B_INBOX, "c", 1L, Long.MAX_VALUE, "inbound", B_RCAP))
        vault.insertInboxId(InboxIdRecord(
            // Pre-migration UUID-shaped outbound — repair, not pending.
            "550e8400-e29b-41d4-a716-446655440000", "c", 1L, Long.MAX_VALUE, "outbound", A_WCAP,
        ))
        assertTrue(contactNeedsRepair(vault, "c"))
        assertEquals(false, contactAwaitingPeerInbox(vault, "c"))
    }

    @Test
    fun fullyPairedContact_isNeitherStaleNorPending() {
        val vault = InMemoryVault()
        vault.insertContact(ContactRecord("c", generateSecureRandom(32), 0, "C", 0L))
        vault.insertInboxId(InboxIdRecord(B_INBOX, "c", 1L, Long.MAX_VALUE, "inbound", B_RCAP))
        vault.insertInboxId(InboxIdRecord(A_INBOX, "c", 1L, Long.MAX_VALUE, "outbound", A_WCAP))
        assertEquals(false, contactNeedsRepair(vault, "c"))
        assertEquals(false, contactAwaitingPeerInbox(vault, "c"))
        assertTrue(contactFullyPaired(vault, "c"))
    }

    @Test
    fun unknownDirectControl_isDroppedNotSurfaced() {
        // Parse-level rule: a "k" without "g" other than "inbox" must never
        // become a visible bubble (no downgrade to text).
        val mm = MessageManager(InMemoryVault(), "http://x.onion", RecordingRelayHttp())
        val env = mm.parseEnvelope("""{"e":"abc","c":1,"t":0,"k":"weird","b":"{}","m":"x"}""")
        assertNotNull(env)            // parses…
        assertEquals("weird", env.controlKind)
        assertNull(env.groupId)       // …and poll's validation drops it (kind != inbox, no group)
    }
}

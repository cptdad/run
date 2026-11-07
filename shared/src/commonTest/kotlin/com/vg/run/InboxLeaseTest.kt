package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// Inbox rows used to HARD-EXPIRE 365 days after pairing, and nothing ever
// refreshed them.
//
// Every `inbox_ids` row is stamped `expiresAt = now + INBOX_LIFETIME_MS` at
// pairing, and BOTH actuals enforced that stamp in the operational lookup
// (`getInboxIdForContact`). The RELAY's TTL, by contrast, SLIDES on every
// authenticated operation. So on day 366 a perfectly healthy, actively-polled
// pairing died locally without a single packet leaving the device: poll returned
// empty, peek returned null, push registration dropped the inbox, send refused —
// while the peer's sends kept getting 2xx and piling up undrained. Recovery meant
// a fresh pairing: new contactId, reset ratchet, orphaned history.
//
// The fix is a read-path one: `selectOperationalInbox` (the ONE chooser both
// actuals and the in-memory double now call) does not consult `expiresAt`, and a
// relay response that PROVES an inbox alive lazily re-stamps the row so the stored
// value stops being a lie. "The inbox is really gone" keeps its evidence-based
// detector — the persistent-404 streak that flags the contact for re-pair — which
// these tests also pin, because a repair that hid a genuine re-pair need would be
// worse than the bug.
// ---------------------------------------------------------------------------

private const val LEASE_INBOX_IN  = "LEASEinbound00000000000000000001"   // 32 chars
private const val LEASE_INBOX_OUT = "LEASEoutbound0000000000000000001"
private val LEASE_CAP_R = "R".repeat(43)
private val LEASE_CAP_W = "W".repeat(43)

private const val DAY_MS = 24L * 60 * 60 * 1000

/**
 * Seeds a contact whose inbox rows were stamped [ageDays] ago with the production
 * 365-day lifetime — i.e. at 400 days they are long past their stamp, exactly the
 * state a vault reaches by simply staying paired.
 */
private fun seedAgedContact(vault: InMemoryVault, contactId: String, ageDays: Long): Long {
    val created = currentTimeMillis() - ageDays * DAY_MS
    val expires = created + VaultSeedDefaults.INBOX_LIFETIME_MS
    vault.insertContact(ContactRecord(contactId, generateSecureRandom(32), 1, "Aged", 0L))
    vault.insertInboxId(InboxIdRecord(LEASE_INBOX_IN, contactId, created, expires, "inbound", LEASE_CAP_R))
    vault.insertInboxId(InboxIdRecord(LEASE_INBOX_OUT, contactId, created, expires, "outbound", LEASE_CAP_W))
    return expires
}

class InboxLeaseSelectionTest {

    @Test
    fun expiredRow_isStillTheOperationalRow() {
        // THE fix. Before it, both actuals' SQL carried `expires_at > now`, so this
        // row was invisible to send, poll, peek, push and contactNeedsRepair.
        val expired = InboxIdRecord(LEASE_INBOX_IN, "c", createdAt = 1L, expiresAt = 2L, direction = "inbound", cap = LEASE_CAP_R)
        assertEquals(expired, selectOperationalInbox(listOf(expired)))
    }

    @Test
    fun newestByCreatedAt_wins_evenWhenTheOlderRowIsTheUnexpiredOne() {
        // A peer's in-band announce inserts a NEW primary key and leaves the old row
        // behind, so "which row wins" is live routing. Recency decides it — and must
        // keep deciding it when the newest row happens to be the expired one (the
        // day-366 pairing), which is the combination the old SQL got backwards.
        val old = InboxIdRecord("OLDoutbound000000000000000000001", "c", createdAt = 1_000L, expiresAt = Long.MAX_VALUE, direction = "outbound", cap = LEASE_CAP_W)
        val new = InboxIdRecord(LEASE_INBOX_OUT, "c", createdAt = 9_000L, expiresAt = 9_001L, direction = "outbound", cap = LEASE_CAP_W)
        assertEquals(new, selectOperationalInbox(listOf(old, new)))
        assertEquals(new, selectOperationalInbox(listOf(new, old)))
    }

    @Test
    fun noCandidates_isNull() {
        assertNull(selectOperationalInbox(emptyList()))
    }

    @Test
    fun expiredRow_stillBlocksAnOwnershipClaim_viaThePrimaryKeyLookup() {
        // The lookup the ownership gate uses is `getInboxId` (PRIMARY KEY) and is
        // deliberately NOT expiry-filtered — an expired row still occupies the key and
        // would still be silently overwritten by INSERT-OR-REPLACE. the operational-lookup change altered the
        // OPERATIONAL lookup only; this pins that the gate did not move with it.
        val vault = InMemoryVault()
        vault.insertInboxId(
            InboxIdRecord(LEASE_INBOX_OUT, "alice", createdAt = 1L, expiresAt = 2L, direction = "outbound", cap = LEASE_CAP_W)
        )
        assertNotNull(vault.getInboxId(LEASE_INBOX_OUT), "the PK lookup must still see an expired row")
        assertNotNull(
            firstUnavailableInboxClaim(vault, listOf(InboxClaim(LEASE_INBOX_OUT, "bob", "outbound"))),
            "a claim on another contact's expired row must still be refused",
        )
    }
}

class InboxLeaseUsabilityTest {

    @Test
    fun contactPast400Days_isStillPollable() {
        val vault = InMemoryVault()
        seedAgedContact(vault, "aged", ageDays = 400)
        val http = RecordingRelayHttp()
        http.script(HttpResult(code = 200, body = """{"blobs":[]}""", isSuccess = true))
        val mgr = MessageManager(vault, "http://relay.test", http as RelayHttp)

        mgr.pollMessages("aged")

        assertEquals(1, http.calls.size, "a 400-day-old pairing must still reach the relay")
        assertTrue(http.calls[0].url.contains(LEASE_INBOX_IN), "…on its own inbound inbox")
    }

    @Test
    fun contactPast400Days_isStillPeekable() {
        val vault = InMemoryVault()
        seedAgedContact(vault, "aged", ageDays = 400)
        val mgr = MessageManager(vault, "http://relay.test", peekOnlyRelay(pending = 2))
        assertEquals(2, mgr.peekInbox("aged"), "the unread badge must survive day 366")
    }

    @Test
    fun contactPast400Days_isStillSendable() {
        if (!aeadUp()) return
        val vault = InMemoryVault()
        seedAgedContact(vault, "aged", ageDays = 400)
        val http = RecordingRelayHttp()
        http.script(HttpResult(code = 202, body = "", isSuccess = true))
        val mgr = MessageManager(vault, "http://relay.test", http as RelayHttp)

        assertTrue(mgr.sendMessage("aged", "still here"), "send must not refuse on a stamp the relay never honoured")
        assertEquals(1, http.calls.size)
        assertTrue(http.calls[0].url.contains(LEASE_INBOX_OUT))
    }

    @Test
    fun contactPast400Days_isNotFlaggedForRepair() {
        // contactNeedsRepair drives the "tap to re-pair" badge and runs off the same
        // expiry-filtered lookup, so the old behaviour told the user to re-pair a
        // pairing the relay was perfectly happy with.
        val vault = InMemoryVault()
        seedAgedContact(vault, "aged", ageDays = 400)
        assertEquals(false, contactNeedsRepair(vault, "aged"))
        assertTrue(contactFullyPaired(vault, "aged"))
    }
}

class InboxLeaseRepairTest {

    @Test
    fun successfulPoll_repairsAStaleLease() {
        val vault = InMemoryVault()
        val staleExpiry = seedAgedContact(vault, "aged", ageDays = 400)
        val http = RecordingRelayHttp()
        http.script(HttpResult(code = 200, body = """{"blobs":[]}""", isSuccess = true))
        val mgr = MessageManager(vault, "http://relay.test", http as RelayHttp)

        mgr.pollMessages("aged")

        val after = assertNotNull(vault.getInboxId(LEASE_INBOX_IN))
        assertTrue(after.expiresAt > staleExpiry, "a proven-live inbox must have its lease re-stamped")
        assertTrue(after.expiresAt > currentTimeMillis(), "…forward of now, not just forward of the old stamp")
        assertEquals(LEASE_CAP_R, after.cap, "the re-stamp must not disturb the capability")
        assertEquals(
            staleExpiry,
            assertNotNull(vault.getInboxId(LEASE_INBOX_OUT)).expiresAt,
            "an inbound poll proves nothing about the OUTBOUND inbox — leave it alone",
        )
    }

    @Test
    fun successfulSend_repairsTheOutboundLease() {
        if (!aeadUp()) return
        val vault = InMemoryVault()
        val staleExpiry = seedAgedContact(vault, "aged", ageDays = 400)
        val http = RecordingRelayHttp()
        http.script(HttpResult(code = 202, body = "", isSuccess = true))
        val mgr = MessageManager(vault, "http://relay.test", http as RelayHttp)

        assertTrue(mgr.sendMessage("aged", "hi"))

        assertTrue(
            assertNotNull(vault.getInboxId(LEASE_INBOX_OUT)).expiresAt > staleExpiry,
            "an accepted append proves the outbound inbox alive",
        )
    }

    @Test
    fun successfulPeek_repairsTheInboundLease() {
        val vault = InMemoryVault()
        val staleExpiry = seedAgedContact(vault, "aged", ageDays = 400)
        val mgr = MessageManager(vault, "http://relay.test", peekOnlyRelay(pending = 0))

        assertEquals(0, mgr.peekInbox("aged"))

        assertTrue(
            assertNotNull(vault.getInboxId(LEASE_INBOX_IN)).expiresAt > staleExpiry,
            "peek is the only refresh point for a conversation that is never opened",
        )
    }

    @Test
    fun relay404_doesNotRepairTheLease() {
        // Brick-safety / honesty: the repair must never paper over an inbox the relay
        // has genuinely reaped. Only a 2xx on that exact inbox counts as evidence.
        val vault = InMemoryVault()
        val staleExpiry = seedAgedContact(vault, "aged", ageDays = 400)
        val http = RecordingRelayHttp()
        http.script(HttpResult(code = 404, body = """{"error":"request rejected"}""", isSuccess = false))
        val mgr = MessageManager(vault, "http://relay.test", http as RelayHttp)

        mgr.pollMessages("aged")

        assertEquals(staleExpiry, assertNotNull(vault.getInboxId(LEASE_INBOX_IN)).expiresAt)
    }

    @Test
    fun persistent404_stillFlagsTheContactForRepair() {
        // The evidence-based re-pair signal is what replaces the local expiry guess;
        // if that change had silenced it, a genuinely dead inbox would have become invisible.
        val vault = InMemoryVault()
        seedAgedContact(vault, "aged", ageDays = 400)
        val http = RecordingRelayHttp()
        val mgr = MessageManager(vault, "http://relay.test", http as RelayHttp)
        var clock = 1_000_000L
        mgr.relayLostClockMs = { clock }

        repeat(mgr.RELAY_LOST_404_STREAK) {
            http.script(HttpResult(code = 404, body = """{"error":"request rejected"}""", isSuccess = false))
            mgr.pollMessages("aged")
        }
        clock += mgr.RELAY_LOST_MIN_WINDOW_MS + 1
        http.script(HttpResult(code = 404, body = """{"error":"request rejected"}""", isSuccess = false))
        mgr.pollMessages("aged")

        assertTrue("aged" in mgr.relayLostContacts(), "a genuinely reaped inbox must still surface as re-pair")
    }

    @Test
    fun healthyLease_isNotRewritten() {
        // Cost control: the repair is lazy. A row minted today must survive a poll
        // with its stamp byte-identical, so the steady state costs zero vault writes.
        val vault = InMemoryVault()
        val now = currentTimeMillis()
        vault.insertContact(ContactRecord("fresh", generateSecureRandom(32), 1, "F", 0L))
        vault.insertInboxId(InboxIdRecord(
            LEASE_INBOX_IN, "fresh", now, now + VaultSeedDefaults.INBOX_LIFETIME_MS, "inbound", LEASE_CAP_R,
        ))
        val expected = assertNotNull(vault.getInboxId(LEASE_INBOX_IN)).expiresAt
        val http = RecordingRelayHttp()
        http.script(HttpResult(code = 200, body = """{"blobs":[]}""", isSuccess = true))

        MessageManager(vault, "http://relay.test", http as RelayHttp).pollMessages("fresh")

        assertEquals(expected, assertNotNull(vault.getInboxId(LEASE_INBOX_IN)).expiresAt)
    }

    @Test
    fun touchInboxExpiry_neverLowersTheStamp() {
        val vault = InMemoryVault()
        vault.insertInboxId(InboxIdRecord(LEASE_INBOX_IN, "c", 1L, 10_000L, "inbound", LEASE_CAP_R))
        vault.touchInboxExpiry(LEASE_INBOX_IN, 5_000L)
        assertEquals(10_000L, assertNotNull(vault.getInboxId(LEASE_INBOX_IN)).expiresAt)
        vault.touchInboxExpiry(LEASE_INBOX_IN, 20_000L)
        assertEquals(20_000L, assertNotNull(vault.getInboxId(LEASE_INBOX_IN)).expiresAt)
    }

    @Test
    fun touchInboxExpiry_onAMissingRow_writesNothing() {
        // Non-resurrection: the repair is an UPDATE keyed by the primary key,
        // so a row deleted during the round-trip is never re-created.
        val vault = InMemoryVault()
        vault.touchInboxExpiry(LEASE_INBOX_IN, currentTimeMillis() + DAY_MS)
        assertNull(vault.getInboxId(LEASE_INBOX_IN))
        assertTrue(vault.inboxes.isEmpty())
    }

    @Test
    fun deletedContactMidPoll_leavesNoResurrectedInboxRow() {
        // End-to-end shape of the same rule: the poll reads the row, the contact is
        // deleted during the (here, synchronous) round-trip, and the repair must not
        // put the capability-bearing row back.
        val inner = InMemoryVault()
        seedAgedContact(inner, "aged", ageDays = 400)
        val http = FakeRelayHttp(
            onPost = { HttpResult(code = -1, body = null, isSuccess = false) },
            onPut = { HttpResult(code = -1, body = null, isSuccess = false) },
            onGet = {
                inner.deleteContact("aged")   // the delete lands mid-round-trip
                HttpResult(code = 200, body = """{"blobs":[]}""", isSuccess = true)
            },
        )
        MessageManager(inner, "http://relay.test", http).pollMessages("aged")

        assertTrue(inner.inboxes.isEmpty(), "no inbox row may be resurrected by the lease repair")
    }
}

/** Minimal `/peek`-answering relay: 200 with a pending count, nothing else. */
private fun peekOnlyRelay(pending: Int) = FakeRelayHttp(
    onPost = { HttpResult(code = -1, body = null, isSuccess = false) },
    onPut = { HttpResult(code = -1, body = null, isSuccess = false) },
    onGet = { HttpResult(code = 200, body = """{"pending":$pending}""", isSuccess = true) },
)

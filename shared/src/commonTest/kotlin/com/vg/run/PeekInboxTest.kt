package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// MessageManager.peekInbox / peekUnreadContactIds — the relay /peek probe that
// drives the contact-list unread badge. Non-destructive: it must never drain.
//
// Uses a URL-aware RelayHttp fake so per-contact assertions hold regardless of
// the sweep's shuffled order (RecordingRelayHttp's FIFO replies can't be
// mapped to a specific contact once the order is randomised).
// ---------------------------------------------------------------------------

/** Returns {"pending":N} keyed by the inbox id embedded in the GET url; a 404
 *  reject for any inbox id in [reject]; never drains (GET /inbox/{id} proper
 *  is not modelled — peek only ever hits the /peek suffix). */
private class PeekRelay(
    pendingByInbox: Map<String, Int>,
    reject: Set<String> = emptySet(),
) : PeekCountRelay(pendingByInbox.toMutableMap(), reject, unknownPending = 0, peekOnly = true) {
    val peekUrls: List<String> get() = requestsOf("GET").map { it.url }
}

private fun seedInbound(vault: InMemoryVault, contactId: String, inboxId: String, cap: String? = "R".repeat(43)) {
    vault.insertContact(ContactRecord(contactId, generateSecureRandom(32), 1, "A-$contactId", 0L))
    vault.insertInboxId(InboxIdRecord(
        inboxId = inboxId, contactId = contactId, createdAt = 1L,
        expiresAt = Long.MAX_VALUE, direction = "inbound", cap = cap,
    ))
}

class PeekInboxTest {

    @Test
    fun peekInbox_parsesPendingCount() {
        val vault = InMemoryVault()
        val id = "INBOXpeek0000000000000000000000A"  // 32 chars, valid alphabet
        seedInbound(vault, "c1", id)
        val mgr = MessageManager(vault, "http://relay.test", PeekRelay(mapOf(id to 3)))
        assertEquals(3, mgr.peekInbox("c1"))
    }

    @Test
    fun peekInbox_zeroPending_returnsZero() {
        val vault = InMemoryVault()
        val id = "INBOXpeek0000000000000000000000B"
        seedInbound(vault, "c1", id)
        val mgr = MessageManager(vault, "http://relay.test", PeekRelay(mapOf(id to 0)))
        assertEquals(0, mgr.peekInbox("c1"))
    }

    @Test
    fun peekInbox_relayReject_returnsNull() {
        val vault = InMemoryVault()
        val id = "INBOXpeek0000000000000000000000C"
        seedInbound(vault, "c1", id)
        val mgr = MessageManager(vault, "http://relay.test", PeekRelay(emptyMap(), reject = setOf(id)))
        assertNull(mgr.peekInbox("c1"))
    }

    @Test
    fun peekInbox_noInboundInbox_returnsNullWithoutNetworkCall() {
        val vault = InMemoryVault()
        vault.insertContact(ContactRecord("c1", generateSecureRandom(32), 1, "a", 0L))
        val relay = PeekRelay(emptyMap())
        val mgr = MessageManager(vault, "http://relay.test", relay)
        assertNull(mgr.peekInbox("c1"))
        assertTrue(relay.peekUrls.isEmpty(), "no inbox → no relay call")
    }

    @Test
    fun peekInbox_nullCap_returnsNullWithoutNetworkCall() {
        val vault = InMemoryVault()
        seedInbound(vault, "c1", "INBOXpeek0000000000000000000000D", cap = null)
        val relay = PeekRelay(emptyMap())
        val mgr = MessageManager(vault, "http://relay.test", relay)
        assertNull(mgr.peekInbox("c1"))
        assertTrue(relay.peekUrls.isEmpty(), "stale (cap-less) contact → no relay call")
    }

    @Test
    fun peekInbox_hitsThePeekSuffix_notTheDrainPath() {
        val vault = InMemoryVault()
        val id = "INBOXpeek0000000000000000000000E"
        seedInbound(vault, "c1", id)
        val relay = PeekRelay(mapOf(id to 1))
        val mgr = MessageManager(vault, "http://relay.test", relay)
        mgr.peekInbox("c1")
        assertEquals(1, relay.peekUrls.size)
        assertTrue(relay.peekUrls[0].endsWith("/inbox/$id/peek"), "must call the non-destructive /peek endpoint")
    }

    @Test
    fun peekUnreadCounts_returnsCountsForContactsWithPending() {
        val vault = InMemoryVault()
        val idA = "INBOXAAAA0000000000000000000000A"
        val idB = "INBOXBBBB0000000000000000000000B"
        val idC = "INBOXCCCC0000000000000000000000C"
        seedInbound(vault, "has-msgs",   idA)
        seedInbound(vault, "empty",      idB)
        seedInbound(vault, "also-msgs",  idC)
        val relay = PeekRelay(mapOf(idA to 2, idB to 0, idC to 5))
        val mgr = MessageManager(vault, "http://relay.test", relay)
        // Empty inbox is omitted; the others carry their exact pending counts.
        assertEquals(mapOf("has-msgs" to 2, "also-msgs" to 5), mgr.peekUnreadCounts())
        // Every contact was probed exactly once.
        assertEquals(3, relay.peekUrls.size)
    }

    @Test
    fun peekUnreadCounts_rejectedContact_isOmittedNotBadged() {
        val vault = InMemoryVault()
        val idA = "INBOXAAAA0000000000000000000000D"
        val idB = "INBOXBBBB0000000000000000000000E"
        seedInbound(vault, "good", idA)
        seedInbound(vault, "gone", idB)
        // "gone" 404s (inbox expired / cap rotated) → unknown → no badge.
        val relay = PeekRelay(mapOf(idA to 1), reject = setOf(idB))
        val mgr = MessageManager(vault, "http://relay.test", relay)
        assertEquals(mapOf("good" to 1), mgr.peekUnreadCounts())
    }

    @Test
    fun peekUnreadCounts_noContacts_isEmpty() {
        val mgr = MessageManager(InMemoryVault(), "http://relay.test", PeekRelay(emptyMap()))
        assertTrue(mgr.peekUnreadCounts().isEmpty())
    }

    @Test
    fun peekUnreadCounts_blockedContact_isNotPolled_norBadged() {
        val vault = InMemoryVault()
        val idA = "INBOXAAAA0000000000000000000000G"
        val idB = "INBOXBBBB0000000000000000000000G"
        seedInbound(vault, "keep",    idA)
        seedInbound(vault, "blocked", idB)
        val relay = PeekRelay(mapOf(idA to 2, idB to 9))
        val mgr = MessageManager(vault, "http://relay.test", relay)
        // A blocked contact is neither badged NOR polled — the block must
        // stop the network fetch, not merely hide the row.
        assertEquals(mapOf("keep" to 2), mgr.peekUnreadCounts(blockedContactIds = setOf("blocked")))
        assertEquals(1, relay.peekUrls.size, "the blocked contact's inbox must not be polled")
        assertTrue(relay.peekUrls[0].contains(idA), "only the non-blocked contact is polled")
    }
}

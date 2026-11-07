package com.vg.run

import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

// ---------------------------------------------------------------------------
// The two relay loops that share the connect-time circuit with the health probe
// and used to write NOTHING into the connection-log panel: the one-shot unread
// prime ([GroupManager.primeUnreadCounts]) and the periodic control sweep
// ([GroupManager.pollAllControls], the per-pass body both platform loops call).
//
// A 2026-09-14 production iPhone connect took 160 s: Tor bootstrapped in 0.5 s,
// the first HEALTH probe only launched 40 s later, and the panel showed 40 s of
// silence because these two passes held streams on the cold circuit without
// narrating a single line. What is pinned here is (a) that each pass now
// brackets/closes itself with a coded line, and (b) that those lines carry
// COUNTS AND SECONDS ONLY — the passes know inbox ids, read capabilities,
// contact ids and aliases, and the panel ships in RELEASE and is screenshot-able.
// ---------------------------------------------------------------------------

/** Flat relay double: every /peek answers `pending`, anything in [reject] 404s. */
private fun PanelRelay(
    pendingByInbox: Map<String, Int> = emptyMap(),
    reject: Set<String> = emptySet(),
) = PeekCountRelay(pendingByInbox.toMutableMap(), reject, unknownPending = 0, peekOnly = true)

/**
 * First read is the pass's start stamp, EVERY later read is the end stamp — so
 * the elapsed the line prints is exactly [spanMs] no matter how many times the
 * pass happens to read the clock in between.
 */
private class StepClock(private val startMs: Long = 10_000L, spanMs: Long = 2_500L) {
    private val endMs = startMs + spanMs
    private var reads = 0
    fun now(): Long = if (reads++ == 0) startMs else endMs
}

/** The real 43-char capability shape — it must never reach a panel line. */
private const val PANEL_CAP_FULL = "RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR"

/** 32-char base64url-alphabet inbox id derived from [tag] (the real shape). */
private fun panelInbox(tag: String) = ("in$tag".padEnd(32, 'A')).take(32)

private fun seedContact(
    vault: InMemoryVault,
    contactId: String,
    alias: String = "A-$contactId",
    inboxId: String = panelInbox(contactId),
) {
    vault.insertContact(ContactRecord(contactId, generateSecureRandom(32), 1, alias, 0L))
    vault.insertInboxId(
        InboxIdRecord(
            inboxId = inboxId, contactId = contactId, createdAt = 1L,
            expiresAt = Long.MAX_VALUE, direction = "inbound", cap = PANEL_CAP_FULL,
        )
    )
}

private fun panelLines(code: ConnectionLog.Code) =
    ConnectionLog.snapshot().filter { it.code == code }

/**
 * Fixed words, digits, and the punctuation those two phrases use — nothing else.
 * An inbox id, a capability, an alias or a contact id would all have to smuggle
 * themselves through a character outside this set or through a bare word, so the
 * word check below runs alongside it.
 */
private val ALLOWED_WORDS = setOf(
    "unread", "prime", "started", "done", "inboxes", "answered", "in", "s",
    "control", "poll", "contacts",
)

private fun assertCountsAndSecondsOnly(text: String) {
    for (token in text.split(' ')) {
        val bare = token.removeSuffix(":")
        if (bare.isEmpty()) continue
        val numeric = bare.isNotEmpty() && bare.all { it.isDigit() || it == '.' || it == '/' }
        assertTrue(
            numeric || bare in ALLOWED_WORDS,
            "connection-log line leaked a non-fixed token: '$bare' in \"$text\"",
        )
    }
}

class GroupManagerConnectPanelLinesTest {

    @BeforeTest
    fun setUp() = ConnectionLog.clear()

    @AfterTest
    fun tearDown() = ConnectionLog.clear()

    // -----------------------------------------------------------------------
    // Unread prime
    // -----------------------------------------------------------------------

    @Test
    fun primePass_bracketsItselfWithCountsAndSeconds() = runTest {
        val vault = InMemoryVault()
        listOf("c1", "c2", "c3").forEach { seedContact(vault, it) }
        val relay = PanelRelay(mapOf(panelInbox("c1") to 2, panelInbox("c2") to 0, panelInbox("c3") to 5))
        val gm = GroupManager(vault) { MessageManager(vault, "http://relay.test", relay) }
        val clock = StepClock()
        gm.clockMs = { clock.now() }

        gm.primeUnreadCounts(emptySet()) { _, _ -> }

        val lines = panelLines(ConnectionLog.Code.PRIME_PASS)
        assertEquals(2, lines.size, "one line at pass start, one at pass end — never one per inbox")
        assertEquals("unread prime started: 3 inboxes", lines[0].text)
        assertEquals("unread prime done: 3/3 answered in 2.5 s", lines[1].text)
        assertTrue(lines.all { it.kind == ConnectionLog.Kind.RELAY })
        // The code is set AT THE PRODUCER and is what the telemetry timeline reads.
        assertTrue(
            ConnectionLog.snapshot().any { it.code == ConnectionLog.Code.PRIME_PASS },
            "snapshot() must expose the producer-set code",
        )
    }

    @Test
    fun primePass_countsOnlyThePeeksThatAnswered() = runTest {
        val vault = InMemoryVault()
        listOf("c1", "c2", "c3").forEach { seedContact(vault, it) }
        // c2's peek 404s (what an in-flight read-cap rotation also looks like): it is
        // NOT an answer, and the denominator still shows it was attempted.
        val relay = PanelRelay(
            pendingByInbox = mapOf(panelInbox("c1") to 1, panelInbox("c3") to 1),
            reject = setOf(panelInbox("c2")),
        )
        val gm = GroupManager(vault) { MessageManager(vault, "http://relay.test", relay) }
        val clock = StepClock(spanMs = 61_000L)
        gm.clockMs = { clock.now() }

        gm.primeUnreadCounts(emptySet()) { _, _ -> }

        val lines = panelLines(ConnectionLog.Code.PRIME_PASS)
        assertEquals("unread prime started: 3 inboxes", lines[0].text)
        assertEquals("unread prime done: 2/3 answered in 61.0 s", lines[1].text)
    }

    @Test
    fun primePass_withNothingToPeek_stillBracketsThePass() = runTest {
        // A pass that peeks nothing still paid for the control pre-drain, so it must
        // still show up — "the prime did nothing for 2.5 s" is the diagnosis.
        val vault = InMemoryVault()
        val gm = GroupManager(vault) { MessageManager(vault, "http://relay.test", PanelRelay()) }
        val clock = StepClock()
        gm.clockMs = { clock.now() }

        gm.primeUnreadCounts(emptySet()) { _, _ -> }

        val lines = panelLines(ConnectionLog.Code.PRIME_PASS)
        assertEquals(2, lines.size)
        assertEquals("unread prime started: 0 inboxes", lines[0].text)
        assertEquals("unread prime done: 0/0 answered in 2.5 s", lines[1].text)
    }

    @Test
    fun primePass_emitsNoIdentifier() = runTest {
        val vault = InMemoryVault()
        seedContact(vault, "contact-alice", alias = "Alice Example", inboxId = panelInbox("alice"))
        val gm = GroupManager(vault) {
            MessageManager(vault, "http://relay.test", PanelRelay(mapOf(panelInbox("alice") to 4)))
        }
        val clock = StepClock()
        gm.clockMs = { clock.now() }

        gm.primeUnreadCounts(emptySet()) { _, _ -> }

        val texts = panelLines(ConnectionLog.Code.PRIME_PASS).map { it.text }
        assertTrue(texts.isNotEmpty())
        for (text in texts) {
            assertFalse(text.contains(panelInbox("alice")), "inbox id reached the panel: $text")
            assertFalse(text.contains(PANEL_CAP_FULL), "read capability reached the panel: $text")
            assertFalse(text.contains("contact-alice"), "contact id reached the panel: $text")
            assertFalse(text.contains("Alice"), "alias reached the panel: $text")
            assertFalse(text.contains("relay.test"), "relay host reached the panel: $text")
            assertCountsAndSecondsOnly(text)
        }
    }

    // -----------------------------------------------------------------------
    // Control sweep
    // -----------------------------------------------------------------------

    @Test
    fun controlPollPass_emitsOneLinePerPass_neverPerContact() {
        val vault = InMemoryVault()
        listOf("c1", "c2", "c3", "c4").forEach { seedContact(vault, it) }
        val gm = GroupManager(vault) { MessageManager(vault, "http://relay.test", PanelRelay()) }
        val clock = StepClock()
        gm.clockMs = { clock.now() }

        gm.pollAllControls()

        val lines = panelLines(ConnectionLog.Code.CONTROL_POLL_PASS)
        assertEquals(1, lines.size, "one line per PASS — four contacts must not write four lines")
        assertEquals("control poll done: 4 contacts in 2.5 s", lines[0].text)
        assertEquals(ConnectionLog.Kind.RELAY, lines[0].kind)
        assertTrue(
            ConnectionLog.snapshot().any { it.code == ConnectionLog.Code.CONTROL_POLL_PASS },
            "snapshot() must expose the producer-set code",
        )
    }

    @Test
    fun controlPollPass_skipsBlockedContactsInItsCount() {
        val vault = InMemoryVault()
        listOf("keep1", "keep2", "blocked").forEach { seedContact(vault, it) }
        val gm = GroupManager(vault) { MessageManager(vault, "http://relay.test", PanelRelay()) }
        gm.blockedContacts = { setOf("blocked") }
        val clock = StepClock()
        gm.clockMs = { clock.now() }

        gm.pollAllControls()

        // The count is what the sweep actually polled — a blocked contact's inbox is
        // never fetched, so counting it would misreport the pass's cost.
        assertEquals("control poll done: 2 contacts in 2.5 s", panelLines(ConnectionLog.Code.CONTROL_POLL_PASS)[0].text)
    }

    @Test
    fun controlPollPass_emitsNoIdentifier() {
        val vault = InMemoryVault()
        seedContact(vault, "contact-bob", alias = "Bob Example", inboxId = panelInbox("bob"))
        val gm = GroupManager(vault) { MessageManager(vault, "http://relay.test", PanelRelay()) }
        val clock = StepClock()
        gm.clockMs = { clock.now() }

        gm.pollAllControls()

        val text = panelLines(ConnectionLog.Code.CONTROL_POLL_PASS)[0].text
        assertFalse(text.contains(panelInbox("bob")), "inbox id reached the panel: $text")
        assertFalse(text.contains(PANEL_CAP_FULL), "read capability reached the panel: $text")
        assertFalse(text.contains("contact-bob"), "contact id reached the panel: $text")
        assertFalse(text.contains("Bob"), "alias reached the panel: $text")
        assertCountsAndSecondsOnly(text)
    }

    @Test
    fun noTransport_writesNothingAtAll() {
        // No MessageManager (Tor not up yet): both passes are networkless no-ops and
        // must not narrate a pass that never ran.
        val vault = InMemoryVault()
        seedContact(vault, "c1")
        val gm = GroupManager(vault) { null }

        gm.pollAllControls()

        assertTrue(panelLines(ConnectionLog.Code.CONTROL_POLL_PASS).isEmpty())
        assertTrue(panelLines(ConnectionLog.Code.PRIME_PASS).isEmpty())
    }
}

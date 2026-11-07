package com.vg.run

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// MessageManager relay-loss detection.
//
// The relay can't be reached from the Appium simulator/emulator suites — there
// the relay URL is rewritten to a dead localhost, so it's always UNREACHABLE
// (a connection error, never a 404). Detection needs the opposite: the relay
// UP and 404-ing a specific inbox. So it's exercised here against a fake relay
// we can toggle, on the JVM — deterministic, no device.
//
// Rule under test: a PERSISTENT 404 on a contact's inbox (relay up — it answered
// 404 — but the inbox is gone) flags the contact for re-pair once the 404 streak
// crosses the threshold; a healthy 200 clears it; a 404 run broken by a success
// never flags. Detection now runs on BOTH the control AND the message channel:
// an attacker who rotates a victim's read cap out from under them would otherwise
// silently kill text delivery with no UI signal. Each channel keeps its own
// streak and the flag clears only when BOTH are healthy. Inbox IDs are
// relay-minted, so a lost ID can't be re-registered — re-pair is the only
// recovery, which is what the flag drives.
// ---------------------------------------------------------------------------

private val LOSS_REJECTED = HttpResult(code = 404, body = """{"error":"request rejected"}""", isSuccess = false)

/** Toggleable relay: GET 404s while [dropping]; otherwise a healthy empty inbox. */
private class DropRelay(var dropping: Boolean) : FakeRelayHttp() {
    init { onGet = { if (dropping) LOSS_REJECTED else RELAY_EMPTY_DRAIN } }
}

private const val CTL_INBOX = "INBOXctl0000000000000000000000AA"   // 32 chars, valid alphabet
private const val MSG_INBOX = "INBOXmsg0000000000000000000000AA"

/** Drops GETs per-inbox so the control and message channels can be toggled independently. */
private class PerInboxDropRelay(var dropCtl: Boolean, var dropMsg: Boolean) : FakeRelayHttp() {
    init {
        onGet = { val url = it.url; if ((CTL_INBOX in url && dropCtl) || (MSG_INBOX in url && dropMsg)) LOSS_REJECTED else RELAY_EMPTY_DRAIN }
    }
}

private fun seedContact(vault: InMemoryVault, contactId: String, ctl: Boolean = true, msg: Boolean = false) {
    vault.insertContact(ContactRecord(contactId, generateSecureRandom(32), 1, "A-$contactId", 0L))
    if (ctl) vault.insertInboxId(InboxIdRecord(
        inboxId = CTL_INBOX, contactId = contactId, createdAt = 1L,
        expiresAt = Long.MAX_VALUE, direction = "inbound-ctl", cap = "R".repeat(43),
    ))
    if (msg) vault.insertInboxId(InboxIdRecord(
        inboxId = MSG_INBOX, contactId = contactId, createdAt = 1L,
        expiresAt = Long.MAX_VALUE, direction = "inbound", cap = "R".repeat(43),
    ))
}

class RelayLossTest {

    @Test
    fun persistentControl404_flagsPastThreshold_thenClearsOnRecovery() {
        val vault = InMemoryVault()
        seedContact(vault, "c1")
        val relay = DropRelay(dropping = true)
        val mgr = MessageManager(vault, "http://relay.test", relay)
        var clock = 0L
        mgr.relayLostClockMs = { clock }   // drive the wall-clock window deterministically

        // One short of the streak threshold → still not flagged.
        repeat(mgr.RELAY_LOST_404_STREAK - 1) { mgr.pollControlMessages("c1") }
        assertFalse("c1" in mgr.relayLostContacts(), "must not flag before the 404 streak threshold")

        // Crossing the COUNT threshold but still WITHIN the window → not flagged.
        mgr.pollControlMessages("c1")
        assertFalse("c1" in mgr.relayLostContacts(), "count threshold alone must not flag within the window (L8)")

        // The streak persists past RELAY_LOST_MIN_WINDOW_MS → flagged for re-pair.
        clock = mgr.RELAY_LOST_MIN_WINDOW_MS
        mgr.pollControlMessages("c1")
        assertTrue("c1" in mgr.relayLostContacts(), "a persistent control-inbox 404 past the window must flag")

        // Relay recovers (healthy 200, even an empty inbox) → flag clears.
        relay.dropping = false
        mgr.pollControlMessages("c1")
        assertFalse("c1" in mgr.relayLostContacts(), "a healthy poll must clear the relay-lost flag")
    }

    @Test
    fun a404RunBrokenByASuccess_doesNotFlag() {
        val vault = InMemoryVault()
        seedContact(vault, "c1")
        val relay = DropRelay(dropping = true)
        val mgr = MessageManager(vault, "http://relay.test", relay)

        repeat(mgr.RELAY_LOST_404_STREAK - 1) { mgr.pollControlMessages("c1") }
        relay.dropping = false; mgr.pollControlMessages("c1")   // a success resets the streak
        relay.dropping = true;  mgr.pollControlMessages("c1")   // streak restarts at 1
        assertFalse("c1" in mgr.relayLostContacts(), "a transient 404 run broken by a success must not flag")
    }

    @Test
    fun persistentMessage404_flagsPastThreshold_thenClearsOnRecovery() {
        val vault = InMemoryVault()
        seedContact(vault, "c1", ctl = false, msg = true)
        val relay = DropRelay(dropping = true)
        val mgr = MessageManager(vault, "http://relay.test", relay)
        var clock = 0L
        mgr.relayLostClockMs = { clock }

        // One short of the threshold on the MESSAGE channel → not yet flagged.
        repeat(mgr.RELAY_LOST_404_STREAK - 1) { mgr.pollMessages("c1") }
        assertFalse("c1" in mgr.relayLostContacts(), "must not flag before the message-channel 404 streak")

        // Crossing the count threshold + persisting past the window → flagged for
        // re-pair. This is the cap-rotation attack the control-only design missed.
        mgr.pollMessages("c1")
        clock = mgr.RELAY_LOST_MIN_WINDOW_MS
        mgr.pollMessages("c1")
        assertTrue("c1" in mgr.relayLostContacts(), "a persistent message-inbox 404 must flag the contact")

        // Relay recovers → flag clears (message channel is the only one seeded).
        relay.dropping = false
        mgr.pollMessages("c1")
        assertFalse("c1" in mgr.relayLostContacts(), "a healthy message poll must clear the relay-lost flag")
    }

    @Test
    fun flagClearsOnlyWhenBothChannelsAreHealthy() {
        // Per-inbox relay so each channel can be healed independently. Drive the
        // control channel past the threshold (flag set), heal ONLY the message
        // channel (flag must persist — control still 404s), then heal control too
        // (flag clears). Pins the "clear only when BOTH channels are healthy" rule.
        val vault = InMemoryVault()
        seedContact(vault, "c1", ctl = true, msg = true)
        val relay = PerInboxDropRelay(dropCtl = true, dropMsg = true)
        val mgr = MessageManager(vault, "http://relay.test", relay)
        var clock = 0L
        mgr.relayLostClockMs = { clock }

        repeat(mgr.RELAY_LOST_404_STREAK) { mgr.pollControlMessages("c1") }
        clock = mgr.RELAY_LOST_MIN_WINDOW_MS
        mgr.pollControlMessages("c1")   // streak now spans the window
        assertTrue("c1" in mgr.relayLostContacts(), "control-channel streak must flag the contact")

        // Heal the message channel only — control still 404s, so the flag holds.
        relay.dropMsg = false
        mgr.pollMessages("c1")
        assertTrue("c1" in mgr.relayLostContacts(), "flag must persist while the control channel still 404s")

        // Heal the control channel too → now both are healthy → flag clears.
        relay.dropCtl = false
        mgr.pollControlMessages("c1")
        assertFalse("c1" in mgr.relayLostContacts(), "flag clears once BOTH channels are healthy")
    }

    @Test
    fun healthyContact_isNeverFlagged() {
        val vault = InMemoryVault()
        seedContact(vault, "good")
        val mgr = MessageManager(vault, "http://relay.test", DropRelay(dropping = false))
        repeat(mgr.RELAY_LOST_404_STREAK + 2) { mgr.pollControlMessages("good") }
        assertTrue(mgr.relayLostContacts().isEmpty(), "a healthy contact must never be flagged")
    }

    // a BURST of 404s all within RELAY_LOST_MIN_WINDOW_MS must not
    // flag — a hostile relay (or a fast-poll window) can't force a spurious re-pair
    // badge on count alone. Once the streak persists past the window, it DOES flag.
    @Test
    fun burst404sWithinTheWindow_doNotFlag_butDoOnceItPersists() {
        val vault = InMemoryVault()
        seedContact(vault, "c1")
        val relay = DropRelay(dropping = true)
        val mgr = MessageManager(vault, "http://relay.test", relay)
        var clock = 1_000L
        mgr.relayLostClockMs = { clock }   // never advances during the burst

        repeat(mgr.RELAY_LOST_404_STREAK + 3) { mgr.pollControlMessages("c1") }
        assertFalse("c1" in mgr.relayLostContacts(), "a burst of 404s within the window must not flag (L8)")

        // Time passes with the streak still live → now it flags.
        clock += mgr.RELAY_LOST_MIN_WINDOW_MS
        mgr.pollControlMessages("c1")
        assertTrue("c1" in mgr.relayLostContacts(), "a streak that persists past the window flags for re-pair")
    }
}

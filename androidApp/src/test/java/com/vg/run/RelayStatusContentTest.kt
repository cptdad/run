package com.vg.run

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Unit tests for [relayStatusContent] — the pure phase→content decision
 * shared by ContactListScreen's contacts-present relay-status strip (and,
 * conceptually, the empty-contacts state above it).
 *
 * Regression context: before this function existed, the contacts-present
 * strip only ever branched on [torBootstrapStalled] and had NO case for
 * [RunViewModel.RelayConnectPhase.Stalled] at all — so once Tor connected
 * but the relay stayed unreachable long enough for
 * `RunViewModel.startRelayStallWatch` to exhaust its self-heal, a user WITH
 * contacts was stuck on a frozen "Connecting to Relay… 95%" forever with no
 * Reconnect action, even though the empty-contacts state already handled
 * this exact case. These tests pin the priority order — RelayStalled
 * outranks TorBootstrapStalled outranks the default StatusLine — so the two
 * render sites in ContactListScreen.kt cannot silently diverge again.
 */
class RelayStatusContentTest {

    @Test
    fun stalledPhase_alwaysWinsRegardlessOfTorBootstrapFlag() {
        assertEquals(
            RelayStatusContent.RelayStalled,
            relayStatusContent(
                relayConnectPhase = RunViewModel.RelayConnectPhase.Stalled,
                torBootstrapStalled = false,
            ),
        )
        assertEquals(
            "RelayConnectPhase.Stalled must outrank torBootstrapStalled — the self-heal-" +
                "exhausted case with an actionable Reconnect matters more than the still-" +
                "running pre-connect stall hint.",
            RelayStatusContent.RelayStalled,
            relayStatusContent(
                relayConnectPhase = RunViewModel.RelayConnectPhase.Stalled,
                torBootstrapStalled = true,
            ),
        )
    }

    @Test
    fun torBootstrapStalled_winsOverTheDefaultStatusLine_whenRelayPhaseIsNotStalled() {
        assertEquals(
            RelayStatusContent.TorBootstrapStalled,
            relayStatusContent(
                relayConnectPhase = RunViewModel.RelayConnectPhase.Connecting,
                torBootstrapStalled = true,
            ),
        )
    }

    @Test
    fun neitherStalledSignal_fallsBackToTheTwoPhaseStatusLine() {
        assertEquals(
            RelayStatusContent.StatusLine,
            relayStatusContent(
                relayConnectPhase = RunViewModel.RelayConnectPhase.Connecting,
                torBootstrapStalled = false,
            ),
        )
    }
}

package com.vg.run

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for [RelayConnectHints] — the pure copy behind the PRE-CONNECT
 * relay surfaces (contact-list empty state + contacts-present strip +
 * Add-Contact mint snackbar).
 *
 * Why this is worth a test: App Store review 2.1 rejected iOS 0.8.159 because
 * those surfaces showed a FROZEN caption for 15+ minutes when Tor never
 * bootstrapped. A follow-up fix (2026-08-26) then found the single-phase
 * "…100%" caption misleading in the other direction — it hit 100% the moment
 * Tor connected, long before the relay handshake had actually landed. The
 * properties pinned here are pure and cheap: (a) the two phases never collide
 * (Tor-phase text vs Relay-phase text) and neither ever renders a percent
 * digit any more, and (b) the stall copy stays NON-TERMINAL (it never claims
 * failure).
 *
 * The NUMBER (bootstrap percent) is no longer part of this text at all
 * (2026-09-16: replaced on-screen by an animated dots cadence — see
 * ContactListScreen.kt's `connectCaptionWithDots` / `rememberConnectDotsStep`).
 * It is still computed by the shared, clock-injected BootstrapProgressPacer
 * (pinned by shared/src/commonTest BootstrapProgressPacerTest for BOTH
 * platforms) and still drives the ring-pulse opacity / ConnectionLog — only
 * this caption's own text stopped rendering the digits.
 *
 * The lifecycle half (watchdog arm/clear, the 1 Hz pacer tick, the dots
 * cadence, the hint escalation timer, SwiftUI/Compose rendering) is verified
 * by build + e2e, not here.
 */
class RelayConnectHintsTest {

    @Test
    fun connectStatusLine_torNotConnected_isThePlainCaption() {
        assertEquals(
            "Connecting to Tor…",
            RelayConnectHints.connectStatusLine(torConnected = false),
        )
    }

    @Test
    fun connectStatusLine_torConnected_switchesToTheRelayPhase() {
        // Once Tor is connected the line must say "Relay", never "Tor" —
        // the two phases can never collide on the same wording.
        val line = RelayConnectHints.connectStatusLine(torConnected = true)
        assertTrue("must name the relay phase: $line", line.startsWith("Connecting to Relay…"))
        assertTrue("must not mention Tor once connected: $line", !line.contains("Tor"))
    }

    @Test
    fun connectStatusLine_neitherPhase_everShowsAPercent() {
        // The percent moved to a purely visual (animated dots) render-layer
        // concern; the text itself must never contain digits again.
        val digitRe = Regex("\\d")
        assertTrue(!digitRe.containsMatchIn(RelayConnectHints.connectStatusLine(torConnected = false)))
        assertTrue(!digitRe.containsMatchIn(RelayConnectHints.connectStatusLine(torConnected = true)))
    }

    @Test
    fun stalledHints_stayNonTerminalAndActionable() {
        for (hint in listOf(RelayConnectHints.TOR_STALLED_HINT, RelayConnectHints.MINT_STALLED_HINT)) {
            // Non-terminal: never says failed/can't/give up — the bootstrap is
            // still running and can still succeed minutes later.
            assertTrue("must promise a retry: $hint", hint.contains("keep trying"))
            assertTrue("must name the likely cause: $hint", hint.contains("may be blocking"))
            // The one action a user can actually take.
            assertTrue("must suggest another network: $hint", hint.contains("Wi-Fi"))
            assertTrue("must suggest another network: $hint", hint.contains("mobile data"))
            assertTrue("must not claim failure: $hint", !hint.contains("Failed"))
        }
    }

    @Test
    fun torStalledHint_leadsWithTheStatusLine() {
        // Two-line shape: status first, explanation + action second — the contact
        // list renders it centered under the (disabled) Add-contact button.
        val lines = RelayConnectHints.TOR_STALLED_HINT.split("\n")
        assertEquals(2, lines.size)
        assertEquals("Still connecting…", lines[0])
    }
}

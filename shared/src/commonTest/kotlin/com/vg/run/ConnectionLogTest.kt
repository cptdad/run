package com.vg.run

import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * ConnectionLog — the RAM-only ring buffer behind the live connection-log
 * panel (triple-tap the "Connecting to…" caption).
 *
 * Two things are pinned here:
 *  - the buffer itself (cap, eviction order, clear), because the panel is the
 *    only consumer and a silently-growing buffer is a RAM-residue regression;
 *  - [ConnectionLog.redact], which is the defence-in-depth net under every
 *    producer. The panel ships in RELEASE builds, so a leaked inbox id /
 *    capability / onion host would be user-visible and screenshot-able.
 */
class ConnectionLogTest {

    @BeforeTest
    fun setUp() = ConnectionLog.clear()

    @AfterTest
    fun tearDown() = ConnectionLog.clear()

    // -----------------------------------------------------------------------
    // Ring buffer
    // -----------------------------------------------------------------------

    @Test
    fun appendsInOrderAndExposesThemOnTheFlow() {
        ConnectionLog.append(ConnectionLog.Kind.SYSTEM, "one")
        ConnectionLog.append(ConnectionLog.Kind.TOR, "two")
        ConnectionLog.append(ConnectionLog.Kind.HEALTH, "three")

        val lines = ConnectionLog.lines.value
        assertEquals(3, lines.size)
        assertEquals(listOf("one", "two", "three"), lines.map { it.text })
        assertEquals(
            listOf(ConnectionLog.Kind.SYSTEM, ConnectionLog.Kind.TOR, ConnectionLog.Kind.HEALTH),
            lines.map { it.kind },
        )
        // snapshot() is the Swift-side read; it must agree with the flow.
        assertEquals(lines, ConnectionLog.snapshot())
    }

    @Test
    fun capsAtMaxLinesAndEvictsTheOldestFirst() {
        val total = ConnectionLog.MAX_LINES + 50
        for (i in 0 until total) ConnectionLog.append(ConnectionLog.Kind.TOR, "line $i")

        val lines = ConnectionLog.lines.value
        assertEquals(ConnectionLog.MAX_LINES, lines.size)
        // The first 50 are gone; the newest is last.
        assertEquals("line 50", lines.first().text)
        assertEquals("line ${total - 1}", lines.last().text)
    }

    @Test
    fun clearEmptiesTheBufferAndTheFlow() {
        ConnectionLog.append(ConnectionLog.Kind.STALL, "escalating")
        assertEquals(1, ConnectionLog.lines.value.size)

        ConnectionLog.clear()

        assertTrue(ConnectionLog.lines.value.isEmpty())
        assertTrue(ConnectionLog.snapshot().isEmpty())
        assertTrue(ConnectionLog.snapshotFormatted().isEmpty())
    }

    @Test
    fun formattedCarriesTheClockTheKindAndTheText() {
        // 01:02:03.004 UTC on an arbitrary day.
        val stamp = 5L * 86_400_000L + 1L * 3_600_000L + 2L * 60_000L + 3L * 1_000L + 4L
        val line = ConnectionLog.Line(stamp, ConnectionLog.Kind.HEALTH, "probe #1: 404 in 1.8 s")
        assertEquals("01:02:03.004 HEALTH probe #1: 404 in 1.8 s", line.formatted())
    }

    @Test
    fun formatSecondsRendersOneDecimalWithADot() {
        assertEquals("0.0", formatSeconds(0))
        assertEquals("1.8", formatSeconds(1_834))
        assertEquals("20.0", formatSeconds(20_000))
        assertEquals("1.0", formatSeconds(960))
    }

    // -----------------------------------------------------------------------
    // Code — the closed producer vocabulary attached alongside a line's text
    // -----------------------------------------------------------------------

    @Test
    fun appendWithACodeKeepsItInTheSnapshot() {
        ConnectionLog.append(ConnectionLog.Kind.HEALTH, "probe #1: 404 in 1.8 s", ConnectionLog.Code.PROBE_OK)

        val line = ConnectionLog.snapshot().single()
        assertEquals(ConnectionLog.Code.PROBE_OK, line.code)
        assertEquals(ConnectionLog.Code.PROBE_OK, ConnectionLog.lines.value.single().code)
    }

    @Test
    fun twoArgAppendYieldsANullCode() {
        ConnectionLog.append(ConnectionLog.Kind.RELAY, "rendezvous warm-up started")

        assertEquals(null, ConnectionLog.snapshot().single().code)
    }

    @Test
    fun theCodeDoesNotChangeFormattedOutput() {
        ConnectionLog.append(ConnectionLog.Kind.HEALTH, "probe #1: 404 in 1.8 s", ConnectionLog.Code.PROBE_OK)
        ConnectionLog.append(ConnectionLog.Kind.HEALTH, "probe #1: 404 in 1.8 s", null)

        val (coded, uncoded) = ConnectionLog.snapshot()
        // Same kind/text ⇒ same panel text, regardless of the attached code.
        assertEquals(
            coded.formatted().substringAfter(' '),
            uncoded.formatted().substringAfter(' '),
        )
        assertEquals("HEALTH probe #1: 404 in 1.8 s", coded.formatted().substringAfter(' '))
    }

    @Test
    fun clearDropsCodedLinesToo() {
        ConnectionLog.append(ConnectionLog.Kind.RELAY, "rendezvous warm-up done in 0.4 s", ConnectionLog.Code.WARMUP_DONE)
        assertEquals(1, ConnectionLog.lines.value.size)

        ConnectionLog.clear()

        assertTrue(ConnectionLog.lines.value.isEmpty())
        assertTrue(ConnectionLog.snapshot().isEmpty())
    }

    // -----------------------------------------------------------------------
    // Redaction — each shape, and the "ordinary text survives" control
    // -----------------------------------------------------------------------

    @Test
    fun stripsAnInboxId() {
        // 32 chars of the base64url alphabet — the exact inbox-id shape.
        val inboxId = "aB3-_xYz9QwErTyUiOpAsDfGhJkLzXcV"
        assertEquals(32, inboxId.length)
        assertTrue(isValidInboxId(inboxId))

        val out = ConnectionLog.redact("posting to inbox $inboxId now")
        assertFalse(out.contains(inboxId))
        assertTrue(out.contains(ConnectionLog.PLACEHOLDER_TOKEN))
        assertEquals("posting to inbox ${ConnectionLog.PLACEHOLDER_TOKEN} now", out)
    }

    @Test
    fun stripsACapabilityAndAnyOtherLongBase64url() {
        val cap = "A".repeat(43)                 // capability shape (43 chars)
        val blob = "z9_-".repeat(16)             // 64 chars of base64url
        val out = ConnectionLog.redact("cap=$cap blob=$blob")
        assertFalse(out.contains(cap))
        assertFalse(out.contains(blob))
        assertEquals(
            "cap=${ConnectionLog.PLACEHOLDER_TOKEN} blob=${ConnectionLog.PLACEHOLDER_TOKEN}",
            out,
        )
    }

    @Test
    fun keepsShortTokensThatMerelyLookOpaque() {
        // 31 chars — one under the threshold, so it is NOT an inbox id.
        val short = "a".repeat(31)
        assertEquals(short, ConnectionLog.redact(short))
    }

    @Test
    fun stripsABareOnionHost() {
        val out = ConnectionLog.redact("connected to jtlc2abcdefghijklmnopqrstuvwxyz234567.onion ok")
        assertFalse(out.contains("jtlc2"))
        assertFalse(out.contains(".onion"))
        assertEquals("connected to ${ConnectionLog.PLACEHOLDER_ONION} ok", out)
    }

    @Test
    fun stripsAShortOnionHostToo() {
        // Even a host too short to trip the base64url rule must not survive.
        val out = ConnectionLog.redact("host abc.onion down")
        assertEquals("host ${ConnectionLog.PLACEHOLDER_ONION} down", out)
    }

    @Test
    fun stripsWholeUrlsIncludingTheirHost() {
        val out = ConnectionLog.redact("GET http://jtlc2abcdefghij.onion/inbox/xyz failed")
        assertFalse(out.contains("jtlc2"))
        assertFalse(out.contains(".onion"))
        assertFalse(out.contains("/inbox/"))
        assertEquals("GET ${ConnectionLog.PLACEHOLDER_URL} failed", out)

        val https = ConnectionLog.redact("probe https://example.org/a?b=c done")
        assertEquals("probe ${ConnectionLog.PLACEHOLDER_URL} done", https)
    }

    @Test
    fun ordinaryPhaseTextSurvivesUntouched() {
        val samples = listOf(
            "bootstrap 80% (loading_descriptors): Loading relay descriptors",
            "bootstrap 100% (done): Done",
            "SOCKS listener ready on port 41235",
            "probe #3: 404 in 1.8 s",
            "probe #4: timeout after 20 s",
            "probe #5: error IllegalStateException",
            "health schedule: fast retry (1-2 s)",
            "health schedule: heartbeat (8-12 s)",
            "relay unreachable - requesting fresh circuits (NEWNYM 1/3)",
            "relay unreachable - requesting fresh circuits (NEWNYM 1, stall watch)",
            "relay unreachable - requesting fresh circuits (NEWNYM 1/2, warm)",
            "contact list revealed",
            "unread prime cap 3 s — revealing contacts",
            "session locked",
            "app foregrounded",
            "Tor stopped",
        )
        for (s in samples) assertEquals(s, ConnectionLog.redact(s), "redacted an ordinary line: $s")
    }

    @Test
    fun appendStoresTheRedactedForm() {
        ConnectionLog.append(ConnectionLog.Kind.RELAY, "cap ${"Q".repeat(43)} used")
        val stored = ConnectionLog.lines.value.single().text
        assertFalse(stored.contains("QQQ"))
        assertTrue(stored.contains(ConnectionLog.PLACEHOLDER_TOKEN))
    }
}

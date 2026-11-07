package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * FIX 2a (2026-09-16) — the ONE transport log line per relay request, and the
 * decision about WHERE the HTTP status lives.
 *
 * Before this, iOS wrote three lines per request (a `HttpClient` pre-flight
 * line, SwiftTorHttp's `<METHOD> <path> socksPort=NNNNN` and its
 * `<METHOD> ← code=NNN`) while Android wrote one — and the control-port tap
 * added two more for the stream. In the first real-device uploads that plumbing
 * was >90 % of every batch, and it was spending the 500-line / 64 KiB batch cap
 * and the 1 Hz tick budget.
 *
 * The shape is single-sourced in commonMain so the two platforms cannot drift,
 * and this test pins the two properties that matter about it:
 *
 *  1. it carries the STATUS, so the transport half of every request is
 *     self-contained in one line;
 *  2. it carries NO SOCKS PORT — that number is a per-process constant with no
 *     diagnostic value, and it used to be on every single request line.
 *
 * THE OTHER HALF OF THE DECISION: `MessageManager`'s `poll → code=NNN` /
 * `send → code=NNN` lines KEEP their status (that is what fix 1 exists for).
 * Both survive redaction, and they are not redundant — the transport line's
 * PATH redacts to `[path]`, so after scrubbing it can no longer tell a poll from
 * a peek from a send, while the MessageManager line names the operation and
 * covers nothing else. See the bottom of this file.
 */
class HttpLogLineTest {

    @Test
    fun oneLinePerRequest_carriesMethodPathAndStatus() {
        assertEquals("GET /inbox/abc/peek → 200", httpLogLine("GET", "/inbox/abc/peek", 200))
        assertEquals("POST /inbox/abc → 202", httpLogLine("POST", "/inbox/abc", 202))
        assertEquals("DELETE /inbox/abc/push → 404", httpLogLine("DELETE", "/inbox/abc/push", 404))
        // A transport failure has no HTTP status; the actuals pass the -1 both
        // platforms already use for it.
        assertEquals("GET /inbox/abc → -1", httpLogLine("GET", "/inbox/abc", -1))
    }

    @Test
    fun theLineNeverCarriesTheSocksPort() {
        val line = httpLogLine("GET", "/inbox/abc/peek", 200)
        assertFalse(line.contains("socks"), line)
        assertFalse(line.contains("9050"), line)
        assertFalse(line.contains("58450"), line)
    }

    @Test
    fun bothSurvivingStatusCarriersSurviveTheRedactor() {
        // The transport line: the path goes (it holds a 32-char inbox id), the
        // method and the status stay.
        val inbox = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
        val transport = DebugLogRedactor.redactLine(
            "12:34:56.789 D/HttpClient: " + httpLogLine("GET", "/inbox/$inbox/peek", 200)
        )
        assertEquals("12:34:56.789 D/HttpClient: GET [path] → 200", transport)
        assertFalse(transport.contains(inbox))

        // The MessageManager line: the inbox id goes, `poll` and the status stay
        // — and `poll` is the ONLY thing left that says which request this was,
        // which is why both lines are kept.
        val semantic = DebugLogRedactor.redactLine(
            "12:34:56.789 D/MessageManager: poll → code=200 inbox=$inbox "
        )
        assertTrue(semantic.contains("poll"), semantic)
        assertTrue(semantic.contains("code=200"), semantic)
        assertFalse(semantic.contains(inbox), semantic)
    }
}

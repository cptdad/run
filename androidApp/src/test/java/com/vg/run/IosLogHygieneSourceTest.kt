package com.vg.run

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * iOS log / copy hygiene (review it3 S6 F1, F3, F4). The owner rule for every
 * log producer is "fixed phrases + numbers": no identifier (8-char prefixes
 * count), no exception / error text, no raw relay bytes. [LogLineNoIdentifierSourceGuardTest]
 * covers commonMain only; this guard covers the Swift app layer.
 *
 *  - no `localizedDescription` / `sqlite3_errmsg` text / bare `\(error)` inside a
 *    LogBuffer / torLog / ConnectionLog / wipeDiag call in ANY iosApp Swift file;
 *  - no `.prefix(<n>)` id fragment in the conversation / add-contact / move-import
 *    log lines;
 *  - SwiftTorHttp never echoes raw response bytes into a failure body (that body is
 *    logged by PlatformHttpClient.ios.kt);
 *  - the release connection-log panel copies only through SensitivePasteboard
 *    (local-only, expiring) via an explicit button, never system text selection.
 *
 * SOURCE-LEVEL (no Swift host in this tier); comments are stripped first, so prose
 * can neither satisfy nor trip a check.
 */
class IosLogHygieneSourceTest {

    private val dir = File(repoRoot(), "iosApp/iosApp")

    private fun swift(name: String): String = SourcePins.stripped("iosApp/iosApp/$name")

    private val logCalls = listOf(
        "LogBuffer.shared.append(", "torLog(", "torLogLocal(", "ConnectionLog.shared.append(", "wipeDiag(",
    )

    /** Every log-call argument span in [src] (paren-balanced, capped so a stray paren cannot run away). */
    private fun logSpans(src: String): List<String> {
        val out = mutableListOf<String>()
        for (call in logCalls) {
            var i = src.indexOf(call)
            while (i >= 0) {
                var j = i + call.length
                var depth = 1
                val cap = minOf(src.length, j + 800)
                while (depth > 0 && j < cap) {
                    when (src[j]) { '(' -> depth++; ')' -> depth-- }
                    j++
                }
                out += src.substring(i, j)
                i = src.indexOf(call, j)
            }
        }
        return out
    }

    @Test
    fun noErrorTextInAnySwiftLogLine() {
        val files = dir.listFiles { f -> f.isFile && f.name.endsWith(".swift") }!!.sortedBy { it.name }
        assertTrue("precondition: the Swift sources must be found", files.size > 10)
        val bad = Regex("""localizedDescription|sqlite3_errmsg|\\\((error|err|e)\)""")
        val hits = files.flatMap { f ->
            logSpans(swift(f.name)).filter { bad.containsMatchIn(it) }.map { "${f.name}: ${it.take(120)}" }
        }
        assertEquals("log lines carry the error TYPE (or a numeric code), never its text:\n" +
            hits.joinToString("\n"), 0, hits.size)
    }

    @Test
    fun noIdPrefixInConversationAddContactOrMoveImportLogLines() {
        val prefix = Regex("""\.prefix\(\s*\d""")
        for (name in listOf("ConversationView.swift", "AddContactView.swift", "MoveFromDeviceView.swift")) {
            val hits = logSpans(swift(name)).filter { prefix.containsMatchIn(it) }
            assertEquals("$name: no identifier fragment in a log line:\n" + hits.joinToString("\n"), 0, hits.size)
        }
        assertFalse("never log a (redacted) transfer handle — its form carries id prefixes",
            logSpans(swift("MoveFromDeviceView.swift")).any { it.contains("MoveHandleCodec") })
    }

    @Test
    fun swiftTorHttpNeverEchoesRawResponseBytes() {
        val src = swift("SwiftTorHttp.swift")
        assertFalse(src.contains("raw.prefix("))
        assertFalse(src.contains("statusLine.prefix("))
    }

    @Test
    fun connectionLogPanelCopiesOnlyThroughSensitivePasteboard() {
        val src = swift("ConnectionLogPanel.swift")
        assertFalse("no system text selection on the panel", src.contains(".textSelection(.enabled)"))
        assertTrue("explicit copy via SensitivePasteboard",
            Regex("""SensitivePasteboard\.copy\(\s*ConnectionLogPanel\.copyableText\(lines\)""").containsMatchIn(src))
        assertTrue("the copy button has its own id", src.contains(".accessibilityIdentifier(\"connect_log_copy\")"))
        val ui = swift("UIComponents.swift")
        val copy = functionBody(ui, "static func copy(_ value: String, expiresAfter:", "UIComponents.swift")
        assertTrue("SensitivePasteboard stays local-only", copy.contains(".localOnly: true"))
        assertTrue("SensitivePasteboard sets an OS expiry", copy.contains(".expirationDate:"))
    }
}

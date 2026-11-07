package com.vg.run

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The connection log reaches the clipboard only through SensitiveClipboard
 * (flagged sensitive, cleared after 60 s), never through plain text selection,
 * and the copied form carries relative times instead of wall-clock stamps.
 */
class ConnectionLogCopySourceTest {

    private val panel = SourcePins.stripped("androidApp/src/main/java/com/vg/run/ConnectionLogPanel.kt")

    @Test
    fun theLogIsNotSelectable_andCopiesThroughSensitiveClipboard() {
        assertFalse("plain selection would copy the log unflagged and never clear it", panel.contains("SelectionContainer"))
        assertTrue(
            Regex("""SensitiveClipboard\.copy\(\s*context,\s*"connection log",\s*connectionLogCopyText\(ConnectionLog\.snapshot\(\)\),\s*CONNECTION_LOG_CLEAR_AFTER_MS,\s*\)""")
                .containsMatchIn(panel),
        )
        assertTrue(panel.contains("internal const val CONNECTION_LOG_CLEAR_AFTER_MS = 60_000L"))
        assertFalse("the copied form must not use the wall-clock formatted() line", panel.contains("formatted() }"))
    }

    @Test
    fun copyText_usesRelativeTimes_noClockValues() {
        val t0 = 1_762_400_000_123L
        val lines = listOf(
            ConnectionLog.Line(t0, ConnectionLog.Kind.SYSTEM, "app foregrounded"),
            ConnectionLog.Line(t0 + 1_250L, ConnectionLog.Kind.TOR, "bootstrap 10%"),
            ConnectionLog.Line(t0 + 62_049L, ConnectionLog.Kind.TOR, "bootstrap 100%"),
        )
        val text = connectionLogCopyText(lines)
        assertEquals(
            "+0.0s SYSTEM app foregrounded\n+1.2s TOR bootstrap 10%\n+62.0s TOR bootstrap 100%",
            text,
        )
        assertFalse(text.contains(t0.toString()))
        assertFalse(Regex("""\d{2}:\d{2}:\d{2}""").containsMatchIn(text))
        assertEquals("", connectionLogCopyText(emptyList()))
    }
}

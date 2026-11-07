package com.vg.run

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Cross-platform guard for the connect diagnostics of 2026-10-23. The iOS
 * control-event parser is pure Swift (no `shared` import, by design), so it
 * carries its own copies of Tor's REASON sets and of the HS_DESC REASON → code
 * split. No Swift test target exercises that file, so this scans its source
 * (comments stripped) and pins it to commonMain [TorReasonVocabulary]:
 *  - the five REASON allowlists are equal on both platforms (the panel prints
 *    the same word for the same event);
 *  - `hsDescFailCodes` maps the same reasons to the same codes as
 *    [TorReasonVocabulary.hsDescFailureCode], and the bridge maps each new
 *    Swift case to its same-named commonMain code;
 *  - Android's warm-Tor reuse line carries [ConnectionLog.Code.TOR_REUSED];
 *  - RunViewModel keeps the `reveal` per session (never the process latch).
 */
class TorReasonParitySourceTest {

    private fun src(path: String) = stripComments(File(repoRoot(), path).readText())

    private val swiftParser by lazy { src("iosApp/iosApp/TorControlEvents.swift") }

    /** The string literals of `static let <name>: Set<String> = [ … ]`. */
    private fun swiftSet(name: String): Set<String> {
        val m = Regex("""static let $name: Set<String> = \[(.*?)]""", RegexOption.DOT_MATCHES_ALL)
            .find(swiftParser)
        assertTrue("Swift set `$name` not found — the scanner is stale", m != null)
        return STRING_LITERAL.findAll(m!!.groupValues[1]).map { it.groupValues[1] }.toSet()
    }

    @Test
    fun swiftReasonAllowlistsEqualTheCommonMainVocabulary() {
        assertEquals(TorReasonVocabulary.HS_DESC_FAIL, swiftSet("hsDescReasons"))
        assertEquals(TorReasonVocabulary.CIRC_FAIL, swiftSet("circReasons"))
        assertEquals(TorReasonVocabulary.STREAM_FAIL, swiftSet("streamReasons"))
        assertEquals(TorReasonVocabulary.ORCONN_FAIL, swiftSet("orConnReasons"))
        assertEquals(TorReasonVocabulary.BOOTSTRAP_PROBLEM, swiftSet("bootstrapReasons"))
    }

    @Test
    fun swiftHsDescFailCodesEqualTheCommonMainSplit() {
        val m = Regex("""static let hsDescFailCodes: \[String: TorLogCode] = \[(.*?)]""", RegexOption.DOT_MATCHES_ALL)
            .find(swiftParser)
        assertTrue("Swift hsDescFailCodes not found — the scanner is stale", m != null)
        val swift = Regex(""""([A-Z_]+)"\s*:\s*\.(\w+)""").findAll(m!!.groupValues[1])
            .associate { it.groupValues[1] to it.groupValues[2] }
        assertTrue("the Swift map is empty — the scanner is broken", swift.isNotEmpty())

        // Same reasons split, to the same-named code on both sides.
        val kotlin = TorReasonVocabulary.HS_DESC_FAIL
            .associateWith { TorReasonVocabulary.hsDescFailureCode(it) }
            .filterValues { it != ConnectionLog.Code.HSDESC_FAILED }
            .mapValues { swiftCaseName(it.value) }
        assertEquals(kotlin, swift)

        // Unknown reasons fall back to the pre-split case on iOS too.
        assertTrue(swiftParser.contains("""hsDescFailCodes[raw.uppercased()] ?? .hsdescFailed"""))
        assertTrue(swiftParser.contains("""guard let raw else { return .hsdescFailed }"""))

        // Every new Swift case is bridged to the same-named commonMain code.
        val tap = src("iosApp/iosApp/TorControlEventTap.swift")
        for (code in TorReasonVocabulary.HS_DESC_FAILURE_CODES) {
            val case = swiftCaseName(code)
            assertTrue("bridge misses .$case", Regex("""case \.$case:\s+return \.$case\b""").containsMatchIn(tap))
        }
    }

    @Test
    fun theWarmTorReuseLineIsCoded() {
        val vm = src(SourcePins.RUN_VIEW_MODEL)
        assertTrue(
            "the keep-alive reuse line must carry TOR_REUSED",
            vm.contains("TorKeepAlive.PHRASE_REUSED, ConnectionLog.Code.TOR_REUSED)"),
        )
        // No uncoded copy left behind.
        assertFalse(vm.contains("TorKeepAlive.PHRASE_REUSED)"))
    }

    @Test
    fun androidRevealIsPerSessionNeverTheProcessLatch() {
        val vm = src(SourcePins.RUN_VIEW_MODEL)
        // The reveal stamp and the report moved into ConnectTelemetryRecorder.
        val recorder = src(SourcePins.CONNECT_TELEMETRY_RECORDER)
        for ((name, file) in listOf("RunViewModel" to vm, "ConnectTelemetryRecorder" to recorder)) {
            assertFalse(
                "Android must not use the process-scoped reveal latch (its anchor is per session): $name",
                file.contains("ConnectTelemetry.markRevealed("),
            )
        }
        assertTrue(recorder.contains("revealElapsedMs = { revealElapsedMsThisSession }"))
        assertTrue(recorder.contains("ConnectTelemetry.latchedReveal("))
        assertFalse("no stale reveal copy left in RunViewModel", vm.contains("ConnectTelemetry.latchedReveal("))
    }

    /** `HSDESC_NO_HSDIR` → `hsdescNoHsdir` — the Kotlin/Native + Swift enum case convention. */
    private fun swiftCaseName(code: ConnectionLog.Code): String {
        val parts = code.name.lowercase().split('_')
        return parts.first() + parts.drop(1).joinToString("") { it.replaceFirstChar(Char::uppercaseChar) }
    }

    private companion object {
        private val STRING_LITERAL = Regex(""""([^"]*)"""")
    }
}

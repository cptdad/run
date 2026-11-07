package com.vg.run

import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Cross-platform guard for the hung onion-circuit rung (2026-10-08,
 * [HsCircuitWatchdog]). The decision is shared commonMain code (pinned by
 * `HsCircuitWatchdogTest`); this scans the platform glue (comments stripped):
 *  - both platforms feed the SAME watchdog from their event stream, gate it on
 *    the session's first relay answer, tell it about NEWNYM, and send
 *    `CLOSECIRCUIT` with the validated argument;
 *  - both log only through the shared fixed-phrase helpers;
 *  - no log / ConnectionLog / LogBuffer call site interpolates a circuit id.
 */
class HsCircuitRungParitySourceTest {

    private fun src(path: String) = stripComments(SourcePins.text(path), keepUrls = true)

    private val kt by lazy { src("shared/src/androidMain/kotlin/com/vg/run/TorManager.kt") }
    private val swift by lazy { src("iosApp/iosApp/TorManager.swift") }
    private val tap by lazy { src("iosApp/iosApp/TorControlEventTap.swift") }
    private val reader by lazy { src("shared/src/androidMain/kotlin/com/vg/run/TorControlEvents.kt") }
    private val vm by lazy { src(SourcePins.RUN_VIEW_MODEL) }
    private val appState by lazy { stripComments(iosAppStateSources(), keepUrls = true) }

    @Test
    fun bothPlatformsWireTheSameHook() {
        // Feed
        assertTrue("Android must feed the watchdog from the event reader",
            kt.contains("hsCircuitWatchdog.observe(raw, relayHsAddresses)") && reader.contains("onControlEvent?.let"))
        assertTrue("iOS must feed the watchdog from the tap",
            tap.contains("TorManager.hsCircuitWatchdog.observe("))
        // Decide, gated on the first answer
        assertTrue(kt.contains("hsCircuitWatchdog.due(answered())"))
        assertTrue(swift.contains("watchdog.due(relayAnsweredThisSession: gate())"))
        assertTrue(vm.contains("hsCircuitAnswered = ::relayAnsweredForCircuitWatchdog"))
        assertTrue(appState.contains("controller.relayAnsweredForCircuitWatchdog("))
        // NEWNYM + reschedule
        assertTrue(kt.contains("hsCircuitWatchdog.noteNewnym()"))
        assertTrue(swift.contains("TorManager.hsCircuitWatchdog.noteNewnym()"))
        assertTrue(kt.contains("hsCircuitWatchdog.msUntilNextDeadline()"))
        assertTrue(swift.contains("watchdog.msUntilNextDeadline()"))
        // The command, with the validated argument
        assertTrue(kt.contains("CLOSECIRCUIT \$circuitId") && kt.contains("HsCircuitWatchdog.isValidCircuitId(circuitId)"))
        assertTrue(swift.contains("sendCommand(\"CLOSECIRCUIT\", arguments: [circuitId]") &&
            swift.contains("HsCircuitWatchdog.companion.isValidCircuitId(id: circuitId)"))
        assertTrue(kt.contains("closeCircuit(closure.commandArgument())"))
        assertTrue(swift.contains("closeCircuit(closure.commandArgument())"))
    }

    @Test
    fun bothPlatformsLogOnlyThroughTheSharedPhrases() {
        assertTrue(kt.contains("HsCircuitWatchdog.logClosing(closure.kind)") && kt.contains("HsCircuitWatchdog.logBudgetSpent()"))
        assertTrue(swift.contains("HsCircuitWatchdog.companion.logClosing(kind: closure.kind)") &&
            swift.contains("HsCircuitWatchdog.companion.logBudgetSpent()"))
        for (s in listOf(kt, swift, tap)) {
            assertTrue("no platform may spell the phrase itself", !s.contains("closing it so Tor retries"))
        }
    }

    @Test
    fun noLogCallSiteInterpolatesACircuitId() {
        var scanned = 0
        // Every Android Tor source (TorManager.kt + the files split out of it), not
        // TorManager.kt alone: a block moved into a new Tor*.kt file must stay scanned.
        val androidTor = stripComments(androidTorSources(strip = false), keepUrls = true)
        for ((name, source) in listOf("Android Tor sources ${androidTorSourceNames()}" to androidTor,
            "TorManager.swift" to swift, "TorControlEventTap.swift" to tap,
            "HsCircuitWatchdog.kt" to src("shared/src/commonMain/kotlin/com/vg/run/HsCircuitWatchdog.kt"))) {
            for (call in logCalls(source)) {
                scanned++
                assertTrue("$name: log call interpolates a circuit-id-bearing value:\n$call",
                    !KOTLIN_INTERP.containsMatchIn(call) && !SWIFT_INTERP.containsMatchIn(call))
                assertTrue("$name: log call references a circuit id:\n$call",
                    !call.contains("commandArgument") && !call.contains("circuitId"))
            }
        }
        assertTrue("the scanner found no log calls — its pattern is broken", scanned > 20)
    }

    private fun logCalls(source: String): List<String> {
        val out = ArrayList<String>()
        for (m in LOG_CALL.findAll(source)) {
            var depth = 0
            var i = m.range.last
            while (i < source.length) {
                when (source[i]) {
                    '(' -> depth++
                    ')' -> { depth--; if (depth == 0) break }
                }
                i++
            }
            out += source.substring(m.range.first, minOf(i + 1, source.length))
        }
        return out
    }

    private companion object {
        private val LOG_CALL = Regex(
            """\b(platformLog|platformLogWarn|platformLogError|torLog|LogBuffer\.append|LogBuffer\.shared\.append|ConnectionLog\.append|ConnectionLog\.shared\.append)\s*\("""
        )
        private const val SENSITIVE = "circuitId|id|closure|arg|argument|raw|replyLine"
        private val KOTLIN_INTERP = Regex("""\$\{?\s*($SENSITIVE)\b""")
        private val SWIFT_INTERP = Regex("""\\\(\s*($SENSITIVE)\b""")
    }
}

package com.vg.run

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Cross-platform guard for the HSDir pin (2026-10-08, [HsDirLedger]). The HSDir
 * fingerprint is SENSITIVE for logging purposes: it may be written into an
 * `HSFETCH … SERVER=$<fp>` command and nowhere else. The pure parts are pinned by
 * `HsDirLedgerTest`; what no JVM test or the Swift compiler can check is the
 * platform glue, so this scans the source (comments stripped, same technique as
 * [WarmNewnymParitySourceTest]):
 *  - no log / ConnectionLog / LogBuffer call site in the files that handle the
 *    fingerprint interpolates a fingerprint-bearing variable;
 *  - both platforms log the pin only through the shared fixed phrases;
 *  - both platforms run the same fire sequence (stall → pin → 551/552 → plain);
 *  - the HS_DESC subscription is live before the first fetch on both platforms,
 *    and iOS's first SETEVENTS still carries STATUS_CLIENT.
 */
class HsDirPinParitySourceTest {

    private fun src(path: String) = stripComments(SourcePins.text(path), keepUrls = true)

    private val files = listOf(
        // Stands for EVERY Android Tor source ([androidTorSources]), not TorManager.kt
        // alone: a block moved into a new Tor*.kt file must stay scanned.
        ANDROID_TOR_SOURCES,
        "shared/src/androidMain/kotlin/com/vg/run/TorControlEvents.kt",
        "shared/src/commonMain/kotlin/com/vg/run/HsDirLedger.kt",
        "shared/src/commonMain/kotlin/com/vg/run/RelayDescriptorWatchdog.kt",
        "iosApp/iosApp/TorManager.swift",
        "iosApp/iosApp/TorControlEventTap.swift",
    )

    /** Every log-ish call, from its name to the balanced closing paren. */
    private fun logCalls(source: String): List<String> {
        val out = ArrayList<String>()
        for (m in LOG_CALL.findAll(source)) {
            var depth = 0
            var i = m.range.last          // the opening paren
            val start = m.range.first
            while (i < source.length) {
                when (source[i]) {
                    '(' -> depth++
                    ')' -> { depth--; if (depth == 0) break }
                }
                i++
            }
            out += source.substring(start, minOf(i + 1, source.length))
        }
        return out
    }

    @Test
    fun noLogCallSiteInterpolatesAFingerprintBearingValue() {
        var scanned = 0
        for (path in files) {
            val text = if (path == ANDROID_TOR_SOURCES) stripComments(androidTorSources(strip = false), keepUrls = true) else src(path)
            for (call in logCalls(text)) {
                scanned++
                assertTrue("$path: log call interpolates a fingerprint-bearing value:\n$call",
                    !KOTLIN_INTERP.containsMatchIn(call) && !SWIFT_INTERP.containsMatchIn(call))
                for (name in RAW_NAMES) {
                    assertTrue("$path: log call references `$name`:\n$call", !call.contains(name))
                }
            }
        }
        assertTrue("the scanner found no log calls — its pattern is broken", scanned > 20)
    }

    @Test
    fun bothPlatformsLogThePinOnlyThroughTheSharedFixedPhrases() {
        assertEquals("descriptor refetch pinned to the last good directory", HsDirLedger.PINNED_PHRASE)
        assertEquals("descriptor directory pin dropped", HsDirLedger.PIN_DROPPED_PHRASE)
        val kt = src("shared/src/androidMain/kotlin/com/vg/run/TorManager.kt")
        val swift = src("iosApp/iosApp/TorManager.swift")
        assertTrue(kt.contains("HsDirLedger.logPinned()") && kt.contains("HsDirLedger.logPinDropped()"))
        assertTrue(swift.contains("HsDirLedger.companion.logPinned()") && swift.contains("HsDirLedger.companion.logPinDropped()"))
        assertTrue("no platform may spell the phrase itself",
            !kt.contains("pinned to the last good directory") && !swift.contains("pinned to the last good directory"))
    }

    @Test
    fun bothPlatformsRunTheSameFireSequence() {
        val kt = src("shared/src/androidMain/kotlin/com/vg/run/TorManager.kt")
        val swift = src("iosApp/iosApp/TorManager.swift")
        for ((name, s) in listOf("Android" to kt, "iOS" to swift)) {
            val stall = s.indexOf("noteStallFired()")
            val pin = s.indexOf("pinnedServerArgument()")
            val rejected = s.indexOf("isPinRejectedReply(")
            val drop = s.indexOf("dropPin()")
            assertTrue("$name: stall must be booked before the pin is chosen", stall in 0 until pin)
            assertTrue("$name: a 551/552 must drop the pin", rejected > pin && drop > rejected)
            assertTrue("$name: NEWNYM must forget pending requests only", s.contains("hsDirLedger.noteNewnym()"))
        }
        assertTrue("Android must reset the ledger per Tor child", kt.contains("hsDirLedger.resetForNewTorProcess()"))
        assertTrue("iOS must feed the ledger from the tap",
            src("iosApp/iosApp/TorControlEventTap.swift").contains("TorManager.hsDirLedger.observe(event: event)"))
        assertTrue("Android must feed the ledger from the event hook", kt.contains("hsDirLedger.observe(event)"))
    }

    @Test
    fun hsDescIsSubscribedBeforeTheFirstFetch() {
        val events = src("shared/src/androidMain/kotlin/com/vg/run/TorControlEvents.kt")
        assertTrue(Regex("\"SETEVENTS HS_DESC ").containsMatchIn(events))
        val kt = src("shared/src/androidMain/kotlin/com/vg/run/TorManager.kt")
        assertTrue("Android must hold Connected (bounded) for the event subscription",
            kt.contains("reader.subscribed.await()") && kt.contains("withTimeoutOrNull(EVENTS_SUBSCRIBE_HOLD_MS)"))
        val swift = src("iosApp/iosApp/TorManager.swift")
        val core = Regex("""controlEventsCore = \[(.*?)]""", RegexOption.DOT_MATCHES_ALL).find(swift)!!.groupValues[1]
        assertTrue("iOS's FIRST SETEVENTS must carry HS_DESC", core.contains("\"HS_DESC\""))
        assertTrue("iOS's FIRST SETEVENTS must keep STATUS_CLIENT", core.contains("\"STATUS_CLIENT\""))
    }

    private companion object {
        private const val ANDROID_TOR_SOURCES = "shared/src/androidMain/kotlin/com/vg/run/Tor*.kt (TorManager.kt + its split-out files)"
        private val LOG_CALL = Regex(
            """\b(platformLog|platformLogWarn|platformLogError|torLog|LogBuffer\.append|LogBuffer\.shared\.append|ConnectionLog\.append|ConnectionLog\.shared\.append)\s*\("""
        )
        private const val SENSITIVE = "server|serverArgument|command|arguments|fp|hex|token|hsDirFingerprint|goodHsDir|pin|ledger"
        private val KOTLIN_INTERP = Regex("""\$\{?\s*($SENSITIVE)\b""")
        private val SWIFT_INTERP = Regex("""\\\(\s*($SENSITIVE)\b""")
        private val RAW_NAMES = listOf("hsDirFingerprint", "goodHsDir", "badHsDirs", "pendingHsDirs", "pinnedServerArgument")
    }
}

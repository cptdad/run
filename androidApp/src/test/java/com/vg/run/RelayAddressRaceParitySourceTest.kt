package com.vg.run

import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Cross-platform guard for the descriptor race over several onion addresses
 * (2026-10-23, `RelayAddressRace`). The decision is shared commonMain code
 * (pinned by `RelayAddressRaceTest`); what no JVM test or the Swift compiler can
 * check is the platform glue, so this scans the source (comments stripped):
 *  - both platforms parse HS_DESC through the race (every configured address),
 *    let the race decide BEFORE the hedge, and feed the hedge only what the race
 *    says is the hedge's business;
 *  - both re-race on an accepted NEWNYM (reset first), and Android per Tor child;
 *  - both send hedges to the race's target address and pin via that address's
 *    ledger;
 *  - both bind the switch hook to the session's MessageManager;
 *  - no log call site in the glue interpolates an address.
 */
class RelayAddressRaceParitySourceTest {

    private fun src(path: String) = stripComments(SourcePins.text(path), keepUrls = true)

    private val kt by lazy { src("shared/src/androidMain/kotlin/com/vg/run/TorManager.kt") }
    private val reader by lazy { src("shared/src/androidMain/kotlin/com/vg/run/TorControlEvents.kt") }
    private val swift by lazy { src("iosApp/iosApp/TorManager.swift") }
    private val tap by lazy { src("iosApp/iosApp/TorControlEventTap.swift") }
    private val vm by lazy { src(SourcePins.RUN_VIEW_MODEL) }
    private val ios by lazy { src("shared/src/iosMain/kotlin/com/vg/run/IosAppController.kt") }

    @Test
    fun bothPlatformsParseThroughTheRace_andDecideBeforeTheHedge() {
        assertTrue(reader.contains("relayRace?.parseDescriptorEvent(raw)"))
        assertTrue(tap.contains("race.parseDescriptorEvent(rawEventLine: replyLine)"))
        val ktObserve = kt.indexOf("relayRace.observe(event)")
        val ktFeed = kt.indexOf("if (!observation.feedHedge) return")
        val ktHedge = kt.indexOf("hedge.observe(event.action")
        assertTrue("Android: race decides, then gates the hedge", ktObserve in 0 until ktFeed && ktFeed < ktHedge)
        val swObserve = tap.indexOf("race.observe(event: event)")
        val swFeed = tap.indexOf("if observation.feedHedge")
        val swHedge = tap.indexOf("noteRelayDescriptorAction(ordinal)")
        assertTrue("iOS: race decides, then gates the hedge", swObserve in 0 until swFeed && swFeed < swHedge)
        // Nobody matches a single address any more.
        assertTrue(!kt.contains("hsFetchAddress(RelayConfig.BASE_URL)") && !swift.contains("hsFetchAddress(relayUrl:"))
        assertTrue(tap.contains("relayOnionAddresses: TorManager.relayHsFetchAddresses"))
    }

    @Test
    fun bothPlatformsReRaceOnNewnym_andAndroidPerTorChild() {
        for ((name, s, reset, start) in listOf(
            Quad("Android", kt, "relayRace.noteTorHsStateReset()", "launchRelayAddressRace()"),
            Quad("iOS", swift, "TorManager.relayRace.noteTorHsStateReset()", "startRelayAddressRace()"),
        )) {
            val newnym = s.indexOf(if (name == "Android") "private fun onNewnymAccepted()" else "private func onNewnymAccepted()")
            val r = s.indexOf(reset, newnym)
            val b = s.indexOf(start, r)
            assertTrue("$name: NEWNYM must reset the race, then re-race", newnym >= 0 && r > newnym && b > r)
        }
        val attempt = kt.indexOf("private suspend fun startAttempt()")
        assertTrue("Android: a new Tor child resets the race", kt.indexOf("relayRace.noteTorHsStateReset()", attempt) > attempt)
        // Stronger form: the reset sits in the per-process reset, and every attempt runs it.
        val attemptBody = kt.substring(attempt, kt.indexOf("\n    }", attempt))
        val reset = kt.indexOf("private fun resetPerProcessState() {")
        assertTrue("Android: startAttempt must run the per-process reset", attempt >= 0 && attemptBody.contains("resetPerProcessState()"))
        assertTrue("Android: the per-process reset must reset the race",
            reset >= 0 && kt.substring(reset, kt.indexOf("\n    }", reset)).contains("relayRace.noteTorHsStateReset()"))
        val race = swift.indexOf("self.startRelayAddressRace()")
        val connected = swift.indexOf("self.state = .connected", maxOf(race, 0))
        assertTrue("iOS: the race begins right BEFORE .connected is published", race >= 0 && connected > race)
        assertTrue("Android: the race starts at Connected or at control-up",
            kt.contains("if (controlSocket != null) launchRelayAddressRace()") &&
                kt.contains("if (_state.value is ConnectionState.Connected) launchRelayAddressRace()"))
        assertTrue("the warm-up's single HSFETCH is kept for one address",
            kt.contains("if (relayRace.isRacing) startRelayAddressRace() else requestHsDescriptorFetch(RelayConfig.BASE_URL)") &&
                vm.contains("tor.requestRelayDescriptorFetch()"))
    }

    @Test
    fun bothPlatformsHedgeTheRacesTarget_andPinPerAddress() {
        assertTrue(kt.contains("relayRace.urlAt(relayRace.hedgeTargetSlot())"))
        assertTrue(kt.contains("val ledger = hsDirLedger.forSlot(slot)"))
        assertTrue(swift.contains("let slot = TorManager.relayRace.hedgeTargetSlot()"))
        assertTrue(swift.contains("let ledger = TorManager.hsDirLedger.forSlot(slot: slot)"))
        assertTrue(kt.contains("HsDirLedgerSet(relayRace.slotCount)") && swift.contains("HsDirLedgerSet(slots: relayRace.slotCount)"))
    }

    @Test
    fun bothSessionsBindTheSwitchHook() {
        assertTrue(vm.contains("RelayEndpoints.race.bindSwitchListener(this) { messageManager?.noteRelayAddressSwitched() }"))
        assertTrue(vm.contains("RelayEndpoints.race.unbindSwitchListener(this)"))
        assertTrue(ios.contains("RelayEndpoints.race.bindSwitchListener(this) { messageManager?.noteRelayAddressSwitched() }"))
    }

    @Test
    fun noGlueLogLineInterpolatesAnAddress() {
        val logCall = Regex("""\b(platformLog|platformLogWarn|platformLogError|torLog|LogBuffer\.append|ConnectionLog\.append|ConnectionLog\.shared\.append)\s*\(([^\n]*)""")
        val names = Regex("""(\$\{?|\\\()\s*(address|target|addresses|relayHsAddresses|relayHsFetchAddresses|urlAt|url)\b""")
        // Every Android Tor source, not TorManager.kt alone: a block moved into a new
        // Tor*.kt file must stay scanned.
        val androidTor = stripComments(androidTorSources(strip = false), keepUrls = true)
        for ((path, s) in listOf("Android Tor sources ${androidTorSourceNames()}" to androidTor,
            "TorManager.swift" to swift, "TorControlEventTap.swift" to tap)) {
            for (m in logCall.findAll(s)) {
                assertTrue("$path: log call interpolates an address: ${m.value}", !names.containsMatchIn(m.groupValues[2]))
            }
        }
    }

    private data class Quad(val a: String, val b: String, val c: String, val d: String)
}

package com.vg.run

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * EXTERNAL SOCKS PROXY MODE (ExternalTorProxy.kt) — the Android wiring.
 *
 * The mode is a TRUST feature: the user must be able to rely on "while this is
 * on, the embedded Tor is never constructed, nothing falls back to it or to
 * direct HTTP, and no automatic report is sent". None of that is reachable from
 * this plain-JVM tier (RunViewModel needs a real Application + vault; no
 * Robolectric here), so — same technique and justification as
 * [SpeculativeTorAdoptionSourceTest] — the properties are pinned structurally,
 * on comment-STRIPPED source so prose can neither satisfy nor trip a guard.
 */
class ExternalProxyModeSourceTest {

    private val viewModel: String by lazy {
        SourcePins.stripped(SourcePins.RUN_VIEW_MODEL)
    }
    private val telemetryRecorder: String by lazy {
        SourcePins.stripped(SourcePins.CONNECT_TELEMETRY_RECORDER)
    }
    private val wipeRoutine: String by lazy {
        SourcePins.stripped(SourcePins.WIPE_ROUTINE)
    }
    private val contactListScreen: String by lazy {
        SourcePins.stripped(SourcePins.CONTACT_LIST_SCREEN)
    }

    // --- the embedded Tor can never be built -------------------------------

    @Test
    fun theSingleTorConstructionSite_refusesInExternalMode() {
        val fn = viewModel.functionBody("    private fun newTorManager(): TorManager {")
        val check = fn.indexOf("check(!externalProxyMode)")
        val ctor = fn.indexOf("return TorManager(")
        assertTrue("newTorManager must refuse in external proxy mode", check >= 0)
        assertTrue("…BEFORE constructing anything", ctor > check)
        assertTrue(
            "newTorManager must stay the ONLY TorManager construction site in the ViewModel",
            Regex("""(?<![A-Za-z_])TorManager\(""").findAll(viewModel).count() == 1,
        )
    }

    @Test
    fun speculativeStart_returnsBeforeAnyTorWork() {
        val fn = viewModel.functionBody("    private fun startSpeculativeTor() {")
        val ext = fn.indexOf("if (externalProxyMode) {")
        assertTrue("startSpeculativeTor must branch on external mode", ext >= 0)
        for (later in listOf("adoptWarmTorFromPreviousSession()", "newTorManager()", "armPreUnlockRelayWarmup(", "armBootStamp(")) {
            val at = fn.indexOf(later)
            assertTrue("precondition: `$later` still in startSpeculativeTor", at >= 0)
            assertTrue("external mode must return before `$later`", ext < at)
        }
        val branch = fn.substring(ext, fn.indexOf("return", ext))
        assertTrue(
            "a Tor kept warm by the previous session must be stopped, not adopted",
            branch.contains("retireKeptTorForExternalProxyMode()"),
        )
    }

    @Test
    fun connectViaTor_divertsFirst() {
        val fn = viewModel.functionBody("    private fun connectViaTor(openedVault: VaultDatabase, forceFresh: Boolean = false) {")
        val ext = fn.indexOf("if (externalProxyMode) {")
        assertTrue(ext >= 0)
        assertTrue("diverts to the proxy", fn.indexOf("connectViaExternalProxy(openedVault)", ext) > ext)
        for (later in listOf("startTorMonitor(", "newTorManager()", "torManager?.stop()")) {
            assertTrue("external mode must divert before `$later`", fn.indexOf(later) > ext)
        }
    }

    @Test
    fun onVaultOpened_checksExternalModeBeforeTheTorAndDirectBranches() {
        // The transport branches moved into onVaultOpened's connectRelayForSession() (R5 it3).
        assertTrue(
            "onVaultOpened must connect through connectRelayForSession",
            viewModel.functionBody("    fun onVaultOpened(openedVault: VaultDatabase) {")
                .contains("connectRelayForSession(openedVault)"),
        )
        val fn = viewModel.functionBody("    private fun connectRelayForSession(openedVault: VaultDatabase) {")
        val ext = fn.indexOf("if (externalProxyMode) {")
        val tor = fn.indexOf("} else if (RelayConfig.isTorRequired) {", ext)
        val direct = fn.indexOf("PlatformHttpClient.direct()", ext)
        assertTrue("the external branch connects via the proxy", fn.indexOf("connectViaExternalProxy(openedVault)", ext) in ext..tor)
        assertTrue("onVaultOpened's external-mode branch must exist", ext >= 0)
        assertTrue("…ahead of the embedded-Tor branch", tor > ext)
        assertTrue("…and ahead of the debug direct client", direct > tor)
    }

    @Test
    fun stallWatch_divertsBeforeAnyNewnymOrRestart() {
        val fn = viewModel.functionBody("    private fun startRelayStallWatch() {")
        val ext = fn.indexOf("if (externalProxyMode) {")
        assertTrue(ext >= 0)
        assertTrue(fn.indexOf("requestNewCircuit()") > ext)
        assertTrue(fn.indexOf("restartTor()") > ext)
        val watch = viewModel.functionBody("    private fun startExternalProxyStallWatch() {")
        for (forbidden in listOf("requestNewCircuit", "restartTor", "torManager", "torProxy(", "TorManager(")) {
            assertFalse("the external stall watch must not touch `$forbidden`", watch.contains(forbidden))
        }
    }

    @Test
    fun externalConnect_usesOnlyTheUsersProxy() {
        val fn = viewModel.functionBody("    private fun connectViaExternalProxy(openedVault: VaultDatabase) {")
        assertTrue(fn.contains("PlatformHttpClient.socksProxy(cfg.host, cfg.port)"))
        assertTrue(fn.contains("PlatformHttpClient.socksProxyReachable("))
        for (forbidden in listOf("torProxy(", "direct()", "TorManager(", "newTorManager", "requestNewCircuit", "torManager")) {
            assertFalse("connectViaExternalProxy must not touch `$forbidden`", fn.contains(forbidden))
        }
        assertTrue(
            "an unreachable proxy must publish Failed (fail closed), never wire a transport",
            fn.contains("TorManager.ConnectionState.Failed(\"external proxy unreachable\")"),
        )
        assertFalse(
            "no identifier in a log line: never interpolate the proxy host/port into LogBuffer",
            Regex("""LogBuffer\.append\([^)]*cfg\.""").containsMatchIn(fn),
        )
    }

    @Test
    fun pushSeam_resolvesExternalModeBeforeTheTorClient() {
        val fn = viewModel.functionBody("    private fun currentRelayHttp(): RelayHttp? = when {")
        val ext = fn.indexOf("externalProxyMode ->")
        val tor = fn.indexOf("PlatformHttpClient.torProxy(")
        assertTrue(ext >= 0 && tor > ext)
    }

    @Test
    fun noConnectTelemetryInExternalMode() {
        // The report lives in ConnectTelemetryRecorder; externalProxyMode is the
        // ViewModel's flag handed in as a lambda, read at arm time.
        val fn = telemetryRecorder.functionBody("    private fun armConnectTelemetry() {")
        val gate = fn.indexOf("if (externalProxyMode()) return")
        assertTrue("armConnectTelemetry must return in external mode", gate >= 0)
        assertTrue("…before arming the send", fn.indexOf("ConnectTelemetry.send(") > gate)
        assertFalse(
            "the report body must not linger in RunViewModel next to the recorder's copy",
            viewModel.contains("ConnectTelemetry.send("),
        )
        assertTrue(
            "RunViewModel must hand the recorder its external-mode flag",
            viewModel.contains("externalProxyMode = { externalProxyMode }"),
        )
    }

    // --- storage + wipe ----------------------------------------------------

    @Test
    fun everyWipePath_deletesTheSetting() {
        assertTrue(
            "WipeRoutine.PREFS_FILES must delete the external-proxy prefs file",
            wipeRoutine.contains("RunViewModel.EXT_TOR_PROXY_PREFS_NAME"),
        )
    }

    @Test
    fun aCorruptStoredValue_failsClosed_notOff() {
        assertTrue(
            "mode must key on PRESENCE of a stored value, not on it parsing",
            viewModel.contains("val externalProxyMode: Boolean = externalProxyRead.modeOn"),
        )
    }

    // --- settings row ------------------------------------------------------

    @Test
    fun settingsRow_isNotRelayGated() {
        val idAt = contactListScreen.indexOf("\"settings_ext_proxy\"")
        assertTrue("the external proxy settings row must exist", idAt >= 0)
        val blockStart = contactListScreen.lastIndexOf("DropdownMenuItem(", idAt)
        val block = contactListScreen.substring(blockStart, idAt)
        assertFalse(
            "the external proxy row must be reachable while the relay is unavailable — " +
                "it is how a user fixes a dead proxy. Block was:\n$block",
            block.contains("enabled = "),
        )
    }

    // --- iOS: the Kotlin-side belt on every proxied relay client ----------

    /**
     * In external-proxy mode the user's proxy must get the plain no-auth SOCKS
     * handshake (no RendezvousHedge isolation credential). SwiftTorHttp enforces
     * it; IosAppController carries the same flag on EVERY SOCKS client it builds
     * — [connectTor]'s transport and the one `proxiedRelayHttp` helper — so a new
     * bare `PlatformHttpClient(port)` fails the count.
     */
    @Test
    fun iosController_everyProxiedClientCarriesTheExternalBelt() {
        val c = stripComments(File(repoRoot(), "shared/src/iosMain/kotlin/com/vg/run/IosAppController.kt").readText())
        val withPort = Regex("""PlatformHttpClient\(\s*[A-Za-z_]""").findAll(c).map { m ->
            c.substring(m.range.first, c.indexOf(')', m.range.first) + 1)
        }.toList()
        assertEquals("only connectTor + proxiedRelayHttp may build a SOCKS client: $withPort", 2, withPort.size)
        assertTrue(
            "every SOCKS client must carry the external-proxy belt: $withPort",
            withPort.all { it.contains("socksIsolationCapable = !externalProxyMode") },
        )
        assertTrue(c.contains("private fun proxiedRelayHttp(socksPort: Int): RelayHttp"))
    }

    // -----------------------------------------------------------------------

    private fun String.functionBody(signature: String): String {
        val start = indexOf(signature)
        assertTrue("precondition: `$signature` must exist", start >= 0)
        val indent = signature.takeWhile { it == ' ' }
        val closer = "\n$indent}"
        val end = indexOf(closer, start)
        assertTrue("precondition: `$signature` must be closed", end > start)
        return substring(start, end)
    }
}

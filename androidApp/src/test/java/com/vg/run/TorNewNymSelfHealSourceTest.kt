package com.vg.run

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Guards the Android Tor control-channel self-heal package:
 * a cheap in-process circuit-recovery lever (`SIGNAL NEWNYM` over a
 * cookie-authenticated AF_UNIX control socket) as an escalation rung BEFORE the
 * existing expensive full-process [restartTor]. Android parity with iOS
 * (AppState.requestNewCircuit / TorManager.swift).
 *
 * WHY THIS TIER. Everything real here needs either a live Tor daemon
 * (`connectControlChannel` connects a `LocalSocket` to Tor's control socket) or
 * a real `Context`/`AndroidViewModel`, so none of it is reachable from a plain
 * JVM test and there is no Robolectric in this module. The properties below are
 * the ones a future edit is most likely to break silently, and each is a real
 * defect (a regressed security invariant or a broken escalation), not a style
 * rule. Same technique and justification as [SpeculativeTorAdoptionSourceTest];
 * bodies are scanned with comments STRIPPED so prose that merely names a call
 * can neither satisfy nor trip a shape guard.
 */
class TorNewNymSelfHealSourceTest {

    private val viewModel: String by lazy {
        SourcePins.stripped(SourcePins.RUN_VIEW_MODEL)
    }
    private val torManager: String by lazy {
        stripComments(
            File(repoRoot(), "shared/src/androidMain/kotlin/com/vg/run/TorManager.kt").readText()
        )
    }
    /** The torrc text + working-dir names, split out of TorManager.kt. */
    private val torrcWriter: String by lazy {
        stripComments(
            File(repoRoot(), "shared/src/androidMain/kotlin/com/vg/run/TorrcWriter.kt").readText()
        )
    }

    // -----------------------------------------------------------------------
    // 1. HARD SECURITY CONSTRAINT: UNIX-domain control socket, never TCP
    // -----------------------------------------------------------------------

    /**
     * A localhost TCP `ControlPort` is discoverable/bindable by any co-installed
     * app and regresses the control-channel hardening. The control channel
     * MUST be a UNIX-domain `ControlSocket`, cookie-authenticated, and connected
     * via `LocalSocketAddress.Namespace.FILESYSTEM` — never a TCP socket.
     */
    @Test
    fun controlChannel_isUnixDomainAndCookieAuthed_neverTcp() {
        assertFalse(
            "torrc must NEVER open a TCP ControlPort — L8 regression (a localhost control " +
                "listener is bindable by any co-installed app)",
            androidTorSources().contains("ControlPort"),
        )
        assertTrue(
            "the torrc must set a UNIX-domain ControlSocket derived from the dataDir + " +
                "TOR_CONTROL_SOCKET_NAME (never hardcoded)",
            torrcWriter.contains("ControlSocket \$dataDirPath/\$TOR_CONTROL_SOCKET_NAME"),
        )
        assertTrue(
            "the torrc must enable cookie authentication for the control socket",
            torrcWriter.contains("CookieAuthentication 1"),
        )
        assertTrue(
            "the control socket must be connected over AF_UNIX (FILESYSTEM namespace), never TCP",
            torManager.contains("android.net.LocalSocketAddress.Namespace.FILESYSTEM"),
        )
        assertTrue(
            "the control socket name is the iOS-parity `cp`",
            torrcWriter.contains("TOR_CONTROL_SOCKET_NAME = \"cp\""),
        )
    }

    /**
     * Mirror of iOS P4a: the auth cookie must be required EXACTLY 32 bytes before
     * AUTHENTICATE. A short read is a cookie Tor is still writing; authenticating
     * with it would burn the effectively one-shot AUTHENTICATE, so it must retry,
     * never authenticate.
     */
    @Test
    fun cookie_mustBeExactly32Bytes_beforeAuthenticating() {
        assertTrue(
            "the cookie length constant must be Tor's AUTHENTICATION_COOKIE_LEN (32)",
            torManager.contains("TOR_CONTROL_COOKIE_LEN = 32"),
        )
        assertTrue(
            "readTorControlCookie must return the bytes ONLY when the length is exactly 32 — a short " +
                "read must yield null so the caller retries, never authenticates",
            torManager.contains("it.size == TOR_CONTROL_COOKIE_LEN"),
        )
    }

    // -----------------------------------------------------------------------
    // 2. requestNewCircuit degrades gracefully; a failed connect is non-fatal
    // -----------------------------------------------------------------------

    /**
     * `requestNewCircuit` must return false (never throw) when the control channel
     * is not up, so the caller escalates to the full restart. And a control
     * connect/auth failure must NOT fail Tor bring-up — Tor is already usable via
     * SOCKS; the connect helper only logs and returns, leaving `controlSocket` null.
     */
    @Test
    fun requestNewCircuit_returnsFalseWhenControlDown_andNeverBlocksBringUp() {
        assertTrue(
            "requestNewCircuit must be a suspend fun returning Boolean",
            torManager.contains("suspend fun requestNewCircuit(): Boolean"),
        )
        val fn = torManager.functionBody("    suspend fun requestNewCircuit(): Boolean {")
        assertTrue(
            "requestNewCircuit must short-circuit to false when there is no control socket",
            fn.contains("if (controlSocket == null)") && fn.contains("return false"),
        )
        // The connect is launched on its OWN detached coroutine after SOCKS
        // detection, so it can never delay or fail the bootstrap return.
        val channels = torManager.functionBody("    private fun startControlAndEventChannels(process: Process): TorControlEventReader {")
        assertTrue(
            "the control channel must be established on its own launched coroutine after SOCKS " +
                "detection, so a failure never fails Tor bring-up",
            channels.contains("controlJob = CoroutineScope(Dispatchers.IO).launch { connectControlChannel() }"),
        )
        // startAttempt runs the phases in order; the channels phase must follow
        // the SOCKS-port detection.
        val start = torManager.functionBody("    private suspend fun startAttempt(): Int {")
        val socksIdx = start.indexOf("SOCKS port detected")
        val controlIdx = start.indexOf("startControlAndEventChannels(")
        assertTrue("the control connect must come AFTER SOCKS-port detection", socksIdx in 0 until controlIdx)
        assertTrue(
            "the control connect must be launched from startControlAndEventChannels only",
            torManager.indexOf("connectControlChannel() }") ==
                torManager.lastIndexOf("connectControlChannel() }"),
        )
    }

    /**
     * The control channel is per-session and must be torn down with the daemon:
     * [stop] cancels the connect coroutine and closes the socket. Without this a
     * stale socket outlives the Tor child it belonged to.
     */
    @Test
    fun stop_tearsDownTheControlChannel() {
        val stop = torManager.functionBody("    fun stop() {")
        assertTrue("stop must cancel the control connect coroutine", stop.contains("controlJob?.cancel()"))
        assertTrue("stop must close the control socket", stop.contains("controlSocket?.close()"))
        assertTrue("stop must null the control socket so future NEWNYM calls short-circuit", stop.contains("controlSocket = null"))
    }

    // -----------------------------------------------------------------------
    // 3. The escalation composes with restartTor / isMidInternalRetry
    // -----------------------------------------------------------------------

    /**
     * The marquee property. In [startRelayStallWatch] the NEWNYM rung must fire
     * BEFORE the full [restartTor], be bounded so it can't loop forever, defer to
     * TorManager's own corrupt-state retry, and fall straight through to the
     * restart when the control channel is down (requestNewCircuit()==false).
     */
    @Test
    fun stallWatch_triesNewNymFirst_thenEscalatesToRestart() {
        val fn = viewModel.functionBody("    private fun startRelayStallWatch() {")
        val newnymIdx = fn.indexOf("requestNewCircuit()")
        val restartIdx = fn.indexOf("restartTor()")
        assertTrue("startRelayStallWatch must call requestNewCircuit()", newnymIdx >= 0)
        assertTrue("startRelayStallWatch must still call restartTor()", restartIdx >= 0)
        assertTrue(
            "the cheap NEWNYM rung must fire BEFORE the expensive full restart",
            newnymIdx < restartIdx,
        )
        assertTrue(
            "the NEWNYM loop must be bounded so it can never loop forever before escalating",
            fn.contains("RELAY_NEWNYM_MAX_TRIES"),
        )
        assertTrue(
            "NEWNYM must defer to TorManager's own corrupt-state retry (don't NEWNYM into a " +
                "daemon already re-bootstrapping)",
            fn.contains("if (torManager?.isMidInternalRetry == true) break"),
        )
        assertTrue(
            "a control channel that never came up must escalate straight to restart (no added delay)",
            fn.contains("if (!fired)") && fn.contains("break"),
        )
    }

    /**
     * NEWNYM must not be misread as the restart: it does not tear the session
     * down, and [restartTor] must still force a FRESH instance (the forceFresh
     * semantics are untouched — cross-checked by [SpeculativeTorAdoptionSourceTest]).
     */
    @Test
    fun restartTor_stillForcesFresh_soNewNymNeverCountsAsTheRestart() {
        val fn = viewModel.functionBody("    private fun restartTor() {")
        assertTrue(
            "restartTor must still force a fresh Tor instance — NEWNYM is a separate, lighter rung",
            fn.contains("connectViaTor(v, forceFresh = true)"),
        )
        assertFalse(
            "restartTor must not itself fire NEWNYM — that rung belongs to the stall watch",
            fn.contains("requestNewCircuit"),
        )
    }

    // -----------------------------------------------------------------------

    /**
     * The body of the function starting at [signature], up to the first line that
     * closes it at the same indentation. Fails loudly if the signature is gone.
     */
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

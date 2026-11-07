package com.vg.run

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The set-once anchors of [ConnectTelemetryRecorder], with an injected clock.
 * Every anchor measures the user's ONE wait, so a self-heal restart, a manual
 * Reconnect or a move resume (which all re-enter the same marks) must never move
 * one. Only the synchronous marks are exercised: nothing here launches a
 * coroutine, so the scope is a plain, never-started one.
 */
class ConnectTelemetryRecorderTest {

    private var clock = 0L

    private fun recorder() = ConnectTelemetryRecorder(
        scope = CoroutineScope(Job()),
        isRelayReachable = MutableStateFlow(false),
        contactsReady = MutableStateFlow(false),
        debugMode = MutableStateFlow(false),
        relayHttp = { null },
        relayTransport = { null },
        externalProxyMode = { false },
        now = { clock },
    )

    @Test
    fun markConnectStart_isSetOnce() {
        val r = recorder()
        assertNull(r.connectStartElapsedMs)
        clock = 1_000L
        r.markConnectStart()
        clock = 9_000L
        r.markConnectStart()
        assertEquals(1_000L, r.connectStartElapsedMs)
    }

    @Test
    fun markTorConnected_isMeasuredOffTheConnectAnchor_andSetOnce() {
        val r = recorder()
        // No anchor yet: nothing to measure against, so nothing is stamped.
        clock = 500L
        r.markTorConnected()
        assertNull(r.torConnectedElapsedMsForTest)
        clock = 1_000L
        r.markConnectStart()
        clock = 4_000L
        r.markTorConnected()
        clock = 60_000L
        r.markTorConnected()
        assertEquals(3_000L, r.torConnectedElapsedMsForTest)
    }

    @Test
    fun markTorProcessStart_isSetOnce() {
        val r = recorder()
        clock = 200L
        r.markTorProcessStart()
        clock = 90_000L
        r.markTorProcessStart()
        assertEquals(200L, r.torProcessStartedAtElapsedMsForTest)
    }

    @Test
    fun markBootConnected_firstStampWins_offTheProcessAnchor() {
        val r = recorder()
        // Debug/direct path: no Tor process, `boot` stays omitted.
        clock = 1_000L
        r.markBootConnected()
        assertNull(r.bootConnectedElapsedMsForTest)
        clock = 2_000L
        r.markTorProcessStart()
        clock = 7_000L
        r.markBootConnected()
        clock = 40_000L
        r.markBootConnected()
        assertEquals(5_000L, r.bootConnectedElapsedMsForTest)
    }

    @Test
    fun theReportLatchStartsUnsent() {
        assertFalse(recorder().connectTelemetrySentForTest)
    }

    /**
     * INIT-ORDER HAZARD (not compiler-checked): the recorder is handed three
     * StateFlows, and `init {}` (startSpeculativeTor) already calls into it, so it
     * must be declared below all three and above `init`.
     */
    @Test
    fun theRecorderIsDeclaredBelowItsFlowsAndAboveInit() {
        val vm = SourcePins.stripped(SourcePins.RUN_VIEW_MODEL)
        val at = vm.indexOf("private val telemetry = ConnectTelemetryRecorder(")
        assertTrue("precondition: RunViewModel declares the recorder", at >= 0)
        for (flow in listOf(
            "val isRelayReachable: StateFlow<Boolean>",
            "val contactsReady: StateFlow<Boolean>",
            "val debugMode: StateFlow<Boolean>",
        )) {
            val flowAt = vm.indexOf(flow)
            assertTrue("precondition: `$flow` exists", flowAt >= 0)
            assertTrue("the recorder must be declared BELOW `$flow`", flowAt < at)
        }
        val initAt = vm.indexOf("\n    init {")
        assertTrue("…and ABOVE init {}", initAt > at)
    }
}

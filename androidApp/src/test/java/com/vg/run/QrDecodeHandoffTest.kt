package com.vg.run

import java.util.concurrent.Executor
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The camera scanner's decode hand-off ([QrDecodeHandoff]).
 *
 * Reproduces the 2026-09-27 GrapheneOS report (logcat, `com.vg.run:1022`): "Move
 * to new device" crashed on every QR scan with
 * `IllegalStateException: Method setCurrentState must be called on the main
 * thread` from `pool-N-thread-1`. [QrCameraScanner] invoked the decode callback
 * on its single-thread CameraX analysis executor; the move screen's callback
 * NAVIGATES (`navController.navigate("setup_pin")`), which moves a back-stack
 * entry's lifecycle and is main-thread-only. The pairing scanner shares the code
 * but only sets Compose state, so it never crashed. The paste path runs on main,
 * which is why the e2e move suites (they paste) never saw it.
 *
 * Contract: decode on the analysis thread, ACCEPT on the main executor; while an
 * acceptance is in flight, further frames are dropped (no duplicate callbacks);
 * once accepted, the gate latches and nothing is offered again.
 */
class QrDecodeHandoffTest {

    /** A "main executor" whose queue the test drains by hand. */
    private class ManualExecutor : Executor {
        val queue = ArrayDeque<Runnable>()
        override fun execute(r: Runnable) { queue.addLast(r) }
        fun drainOne() { queue.removeFirst().run() }
    }

    @Test
    fun acceptanceRunsOnTheMainExecutor_neverOnTheCallingThread() {
        val main = ManualExecutor()
        var calledOn: Thread? = null
        val gate = QrDecodeHandoff(main) { calledOn = Thread.currentThread(); true }

        gate.offer("payload")
        assertEquals("the callback must not run inline on the analysis thread", null, calledOn)
        assertEquals(1, main.queue.size)

        main.drainOne()
        assertEquals(Thread.currentThread(), calledOn)
    }

    @Test
    fun framesWhileAnAcceptanceIsInFlight_areDropped() {
        val main = ManualExecutor()
        var calls = 0
        val gate = QrDecodeHandoff(main) { calls++; true }

        assertTrue(gate.offer("a"))
        assertFalse("a second frame before main ran the first must be dropped", gate.offer("a"))
        assertFalse(gate.offer("b"))
        assertEquals(1, main.queue.size)
        main.drainOne()
        assertEquals(1, calls)
    }

    @Test
    fun anAcceptedDecode_latchesTheGateForGood() {
        val main = ManualExecutor()
        var calls = 0
        val gate = QrDecodeHandoff(main) { calls++; true }
        gate.offer("a"); main.drainOne()
        assertTrue(gate.done)
        assertFalse(gate.offer("a"))
        assertFalse(gate.offer("b"))
        assertEquals(0, main.queue.size)
        assertEquals(1, calls)
    }

    @Test
    fun aRejectedDecode_reopensTheGate_soScanningContinues() {
        // A stray non-move / non-pairing QR in frame is rejected and the camera
        // keeps looking — the callback's `false` is honoured.
        val main = ManualExecutor()
        val seen = mutableListOf<String>()
        val gate = QrDecodeHandoff(main) { seen += it; it == "good" }

        assertTrue(gate.offer("junk")); main.drainOne()
        assertFalse(gate.done)
        assertTrue(gate.offer("good")); main.drainOne()
        assertTrue(gate.done)
        assertEquals(listOf("junk", "good"), seen)
    }

    @Test
    fun aCallbackThatThrows_doesNotWedgeTheGate() {
        val main = ManualExecutor()
        var first = true
        val gate = QrDecodeHandoff(main) { if (first) { first = false; throw IllegalStateException("boom") } else true }
        gate.offer("a")
        try { main.drainOne() } catch (_: IllegalStateException) { }
        assertFalse(gate.done)
        assertTrue("the in-flight flag must be released even when the callback throws", gate.offer("a"))
    }
}

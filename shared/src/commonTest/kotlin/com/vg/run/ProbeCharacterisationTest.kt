package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// Characterisation of `probeRelayReachable`'s two paths no other suite drives
// end to end: the NEWNYM re-probe cap (an abandoned attempt is free twice, then
// spends a booked attempt) and the exception path (booked as PROBE_ERROR, breaks
// the full-budget timeout run, and — when a NEWNYM abandoned that attempt — is
// re-run unbooked like any other abandon).
// ---------------------------------------------------------------------------

// The first [abortFirst] GETs fire the NEWNYM hook mid-flight and then either
// return the aborted-call result (-1) or, with [throwOnAbort], throw; afterwards
// the relay's by-design 404.
private class ProbeAbortRelay(private val abortFirst: Int, private val throwOnAbort: Boolean = false) : FakeRelayHttp() {
    lateinit var mgr: MessageManager
    private var aborted = 0
    val gets: Int get() = requestsOf("GET").size
    init {
        onGet = {
            if (aborted < abortFirst) {
                aborted++
                mgr.noteNewCircuitRequested()
                if (throwOnAbort) throw IllegalStateException("aborted")
                HttpResult(code = -1, body = "Canceled", isSuccess = false)
            } else RELAY_WARM_404
        }
    }
}

private fun probeCodes(): List<ConnectionLog.Code?> = ConnectionLog.snapshot().map { it.code }
private fun probeTexts(): List<String> = ConnectionLog.snapshot().map { it.text }

class ProbeCharacterisationTest {

    private fun managerOver(relay: ProbeAbortRelay): MessageManager =
        MessageManager(InMemoryVault(), "http://relay.test", relay).also { relay.mgr = it }

    // T1: two abandons are re-run for free, the next ones spend booked attempts — so
    // four abandons exhaust the two attempts and report unreachable, three leave one
    // attempt for the answer. No abandon is booked as a timeout / failure / error.
    @Test
    fun newnymReprobeCap_thenAbandonsSpendAttempts() {
        ConnectionLog.clear()
        val exhausted = ProbeAbortRelay(abortFirst = 4)
        val m1 = managerOver(exhausted)
        assertFalse(m1.isRelayReachable())
        assertEquals(4, exhausted.gets)
        assertEquals(0, m1.consecutiveFullBudgetProbeTimeouts())
        assertEquals(4, probeTexts().count { "abandoned" in it }, probeTexts().toString())
        val codes = probeCodes()
        assertFalse(ConnectionLog.Code.PROBE_TIMEOUT in codes || ConnectionLog.Code.PROBE_FAILED in codes || ConnectionLog.Code.PROBE_ERROR in codes, codes.toString())

        ConnectionLog.clear()
        val answered = ProbeAbortRelay(abortFirst = 3)
        val m2 = managerOver(answered)
        assertTrue(m2.isRelayReachable(), "two free re-probes, one spent attempt, then the answer")
        assertEquals(4, answered.gets)
        ConnectionLog.clear()
    }

    // T2: a probe whose transport THROWS is booked once per attempt as PROBE_ERROR
    // (class name only), reports unreachable, and leaves no full-budget timeout run.
    @Test
    fun aThrowingProbe_booksProbeErrorPerAttempt_andReportsUnreachable() {
        ConnectionLog.clear()
        val relay = FakeRelayHttp.throwing("x")
        val mgr = MessageManager(InMemoryVault(), "http://relay.test", relay)
        assertFalse(mgr.isRelayReachable())
        assertEquals(MessageManager.RELAY_HEALTH_ATTEMPTS, relay.requestsOf("GET").size)
        val errors = ConnectionLog.snapshot().filter { it.code == ConnectionLog.Code.PROBE_ERROR }
        assertEquals(MessageManager.RELAY_HEALTH_ATTEMPTS, errors.size)
        assertTrue(errors.all { Regex("""^probe #\d+: error IllegalStateException$""").matches(it.text) }, errors.map { it.text }.toString())
        assertEquals(0, mgr.consecutiveFullBudgetProbeTimeouts())
        ConnectionLog.clear()
    }

    // T3: an attempt that THREW after a NEWNYM abandoned it is re-run unbooked — no
    // PROBE_ERROR, one abandon line — and the re-run's answer is the result.
    @Test
    fun anExceptionOnAnAttemptANewnymAbandoned_isRerunUnbooked() {
        ConnectionLog.clear()
        val relay = ProbeAbortRelay(abortFirst = 1, throwOnAbort = true)
        val mgr = managerOver(relay)
        assertTrue(mgr.isRelayReachable())
        assertEquals(2, relay.gets)
        assertFalse(ConnectionLog.Code.PROBE_ERROR in probeCodes())
        assertEquals(1, probeTexts().count { "abandoned" in it }, probeTexts().toString())
        ConnectionLog.clear()
    }
}

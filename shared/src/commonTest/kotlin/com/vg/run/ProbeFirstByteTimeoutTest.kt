package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// FIRST-BYTE BUDGET. Field signature: the first probe's stream
// connected through Tor in 0.35 s and then got no answer for the whole 20 s
// cold budget. Rules pinned here (commonMain, both platforms):
//   • the COLD probe hands the transport an 8 s first-byte budget; a warm probe
//     hands none;
//   • a first-byte timeout counts as a FULL-BUDGET timeout (same evidence) and
//     feeds the cold NEWNYM rung, even though it came back after ~8 s;
//   • a transport failure WITHOUT the flag is still a fast failure;
//   • the flag is ignored when no budget was asked for.
// ---------------------------------------------------------------------------

/** Records the first-byte budget of every probe; answers with [reply]. */
private class FirstByteRecordingRelay(reply: (Int) -> HttpResult) : FakeRelayHttp() {
    val budgets: List<Int> get() = requestsOf("GET").mapNotNull { it.firstByteTimeoutSeconds }
    init { onGet = { r -> r.firstByteTimeoutSeconds?.let(reply) ?: RELAY_DEAD } }
}

class ProbeFirstByteTimeoutTest {

    @Test
    fun theNumber() {
        assertEquals(8, MessageManager.PROBE_FIRST_BYTE_TIMEOUT_SECONDS)
        assertTrue(
            MessageManager.PROBE_FIRST_BYTE_TIMEOUT_SECONDS < MessageManager.HEALTH_HTTP_TIMEOUT_SECONDS,
            "the first-byte budget must cut in BEFORE the overall cold budget",
        )
        assertEquals(8, MessageManager.probeFirstByteTimeoutSeconds(roundTripCompleted = false))
        assertEquals(0, MessageManager.probeFirstByteTimeoutSeconds(roundTripCompleted = true), "warm probes: none")
    }

    @Test
    fun classification_firstByteTimeoutIsAFullBudgetTimeout() {
        assertEquals(
            MessageManager.ProbeAttemptOutcome.TIMEOUT,
            MessageManager.classifyProbeAttempt(
                answered = false, newnymDuringAttempt = false, elapsedMs = 8_100L,
                timeoutSeconds = MessageManager.HEALTH_HTTP_TIMEOUT_SECONDS, firstByteTimedOut = true,
            ),
        )
        assertEquals(
            MessageManager.ProbeAttemptOutcome.FAILED_FAST,
            MessageManager.classifyProbeAttempt(
                answered = false, newnymDuringAttempt = false, elapsedMs = 8_100L,
                timeoutSeconds = MessageManager.HEALTH_HTTP_TIMEOUT_SECONDS, firstByteTimedOut = false,
            ),
            "the same 8 s without the flag is a fast failure",
        )
        // A NEWNYM during the attempt still wins: abandoned, never booked.
        assertEquals(
            MessageManager.ProbeAttemptOutcome.ABANDONED_BY_NEWNYM,
            MessageManager.classifyProbeAttempt(
                answered = false, newnymDuringAttempt = true, elapsedMs = 8_100L,
                timeoutSeconds = MessageManager.HEALTH_HTTP_TIMEOUT_SECONDS, firstByteTimedOut = true,
            ),
        )
    }

    @Test
    fun aColdProbe_passesTheBudget_andItsExpiryFeedsTheColdRung() {
        val relay = FirstByteRecordingRelay { HttpResult(code = -1, body = "Cancelled(no first byte)", isSuccess = false, firstByteTimeout = true) }
        val mgr = MessageManager(InMemoryVault(), "http://relay.test", relay)
        assertFalse(mgr.isRelayReachable())
        assertTrue(relay.budgets.isNotEmpty())
        assertTrue(relay.budgets.all { it == MessageManager.PROBE_FIRST_BYTE_TIMEOUT_SECONDS }, "${relay.budgets}")
        assertTrue(
            mgr.consecutiveFullBudgetProbeTimeouts() >= MessageManager.EARLY_NEWNYM_MIN_TIMEOUTS,
            "every first-byte expiry is full-budget evidence: ${mgr.consecutiveFullBudgetProbeTimeouts()}",
        )
        assertTrue(mgr.earlyNewnymDue(MessageManager.EARLY_NEWNYM_FIRST_MS, 0, 0))
    }

    @Test
    fun aFastFailureWithoutTheFlag_stillBreaksTheRun() {
        val relay = FirstByteRecordingRelay { HttpResult(code = -1, body = "refused", isSuccess = false) }
        val mgr = MessageManager(InMemoryVault(), "http://relay.test", relay)
        assertFalse(mgr.isRelayReachable())
        assertEquals(0, mgr.consecutiveFullBudgetProbeTimeouts())
    }

    @Test
    fun aWarmProbe_passesNoBudget_andAStrayFlagIsIgnored() {
        var answered = false
        val relay = FirstByteRecordingRelay { budget ->
            if (!answered) { answered = true; HttpResult(code = 404, body = "not found", isSuccess = false) }
            else HttpResult(code = -1, body = "", isSuccess = false, firstByteTimeout = budget == 0)
        }
        val mgr = MessageManager(InMemoryVault(), "http://relay.test", relay)
        assertTrue(mgr.isRelayReachable(), "the by-design 404 warms the transport")
        relay.clearRequests()
        assertFalse(mgr.isRelayReachable())
        assertTrue(relay.budgets.all { it == 0 }, "warm: no first-byte budget, ${relay.budgets}")
        assertEquals(0, mgr.consecutiveFullBudgetProbeTimeouts(), "the flag without a budget is not evidence")
    }

    @Test
    fun theFirstByteFlagCarriesNothingFromTheRelay() {
        // The flag is a Boolean on the result; the panel line for it is a fixed
        // phrase with numbers only (see the probe loop).
        val r = HttpResult(code = -1, body = null, isSuccess = false, firstByteTimeout = true)
        assertTrue(r.firstByteTimeout)
        assertTrue(r.headers.isEmpty())
    }
}

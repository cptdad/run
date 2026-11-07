package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// NEWNYM ABORTS THE IN-FLIGHT PROBE (2026-10-08).
//
// Field case (prod, app 1.6.38, connect 1): the warm-up rung fired `SIGNAL
// NEWNYM`; the warm-up's own GET answered 2.5 s later on the fresh circuits, but
// the health probe already in flight sat out its full 20 s budget on a circuit
// Tor had just retired — 17 s lost. Rules pinned here (both platforms run this
// commonMain code; the platform transports only supply the hard abort):
//   • after MessageManager.noteNewCircuitRequested, the probe's stream is
//     aborted (cancelOnNewCircuit) and the attempt re-runs AT ONCE;
//   • the abandoned attempt is booked as NEITHER a timeout nor a success: it
//     does not advance the cold/warm NEWNYM rungs (full-budget run) and does not
//     break their run either (a fast failure would);
//   • even if a transport could NOT abort and the stale result arrives at the
//     full budget, it is still classified ABANDONED, never TIMEOUT;
//   • a NEWNYM nobody has probed yet gets one fast (1–2 s) cycle, even warm;
//   • the batch /peek prime re-sends once instead of failing into the slow path.
// ---------------------------------------------------------------------------

private const val NA_INBOX = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYX"           // 32 chars
private const val NA_CAP = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  // 43 chars

/**
 * Simulates the platform hook: on the first [abortFirst] opted-in GETs it fires
 * the NEWNYM hook mid-flight (as TorManager does on a `250`) and returns what an
 * aborted OkHttp call / cancelled NWConnection returns (`code = -1`); afterwards
 * it answers the relay's by-design 404.
 */
private class NewnymMidFlightRelay(private val abortFirst: Int) : FakeRelayHttp() {
    lateinit var mgr: MessageManager
    val getFlags: List<Boolean> get() = requestsOf("GET").map { it.cancelOnNewCircuit }
    var cancels = 0
    private var aborted = 0
    init {
        onGet = {
            if (aborted < abortFirst) {
                aborted++
                mgr.noteNewCircuitRequested()
                HttpResult(code = -1, body = "Canceled", isSuccess = false)
            } else RELAY_WARM_404
        }
        onCancelNewCircuit = { cancels++; 1 }
    }
}

/** The batch /peek: the first opted-in POST is abandoned by a NEWNYM, then it answers. */
private class NewnymBatchRelay : FakeRelayHttp() {
    lateinit var mgr: MessageManager
    val postFlags: List<Boolean> get() = requestsOf("POST").map { it.cancelOnNewCircuit }
    init {
        onPost = {
            if (requestsOf("POST").size == 1) {
                mgr.noteNewCircuitRequested()
                HttpResult(code = -1, body = "Canceled", isSuccess = false)
            } else HttpResult(code = 200, body = """{"v":1,"results":[{"id":"$NA_INBOX","pending":3}]}""", isSuccess = true)
        }
    }
}

class NewnymProbeAbortTest {

    // --- the pure classification ----------------------------------------

    @Test
    fun abandonedAttempt_isNeverATimeout_evenAtTheFullBudget() {
        val budget = MessageManager.HEALTH_HTTP_TIMEOUT_SECONDS
        // The soft path: a transport that could not abort hands back the stale
        // result at the full budget. Still ABANDONED — never TIMEOUT.
        assertEquals(
            MessageManager.ProbeAttemptOutcome.ABANDONED_BY_NEWNYM,
            MessageManager.classifyProbeAttempt(
                answered = false, newnymDuringAttempt = true,
                elapsedMs = budget * 1_000L, timeoutSeconds = budget,
            ),
        )
        // The hard path: aborted at once. ABANDONED — never FAILED_FAST.
        assertEquals(
            MessageManager.ProbeAttemptOutcome.ABANDONED_BY_NEWNYM,
            MessageManager.classifyProbeAttempt(
                answered = false, newnymDuringAttempt = true, elapsedMs = 15L, timeoutSeconds = budget,
            ),
        )
    }

    @Test
    fun anAnswer_winsAcrossANewnym_andTheOldClassificationIsUnchangedWithoutOne() {
        val budget = MessageManager.HEALTH_HTTP_TIMEOUT_SECONDS
        assertEquals(
            MessageManager.ProbeAttemptOutcome.ANSWERED,
            MessageManager.classifyProbeAttempt(true, newnymDuringAttempt = true, elapsedMs = 30L, timeoutSeconds = budget),
        )
        assertEquals(
            MessageManager.ProbeAttemptOutcome.TIMEOUT,
            MessageManager.classifyProbeAttempt(false, newnymDuringAttempt = false, elapsedMs = budget * 1_000L, timeoutSeconds = budget),
        )
        assertEquals(
            MessageManager.ProbeAttemptOutcome.FAILED_FAST,
            MessageManager.classifyProbeAttempt(false, newnymDuringAttempt = false, elapsedMs = 15L, timeoutSeconds = budget),
        )
    }

    // --- the probe loop --------------------------------------------------

    @Test
    fun newnymMidProbe_abortsAndReprobesAtOnce_withoutSpendingAnAttempt() {
        val relay = NewnymMidFlightRelay(abortFirst = 1)
        val mgr = MessageManager(InMemoryVault(), "http://relay.test", relay)
        relay.mgr = mgr

        assertTrue(mgr.isRelayReachable(), "the re-probe on the fresh circuits answers")
        assertEquals(2, relay.getFlags.size, "abandoned attempt + one immediate re-probe")
        assertTrue(relay.getFlags.all { it }, "every probe GET opts in to the NEWNYM abort")
        assertEquals(1, relay.cancels, "the hook asked the transport to abort in-flight requests")
        assertTrue(mgr.hasCompletedRelayRoundTrip())
        assertEquals(0, mgr.consecutiveFullBudgetProbeTimeouts())
    }

    @Test
    fun abortedProbe_doesNotCountAsATimeout_norBreakTheTimeoutRun() {
        // Every attempt is abandoned by a NEWNYM. With two full-budget timeouts
        // already on record, the abandoned attempts must neither ADD to that run
        // (which would advance the NEWNYM rungs) nor RESET it (which a fast
        // failure does) — they are not evidence about anything.
        val relay = NewnymMidFlightRelay(abortFirst = Int.MAX_VALUE)
        val mgr = MessageManager(InMemoryVault(), "http://relay.test", relay)
        relay.mgr = mgr
        mgr.noteProbeTimedOut(attemptStartedAtMs = 0L)
        mgr.noteProbeTimedOut(attemptStartedAtMs = 20_000L)
        assertEquals(2, mgr.consecutiveFullBudgetProbeTimeouts())

        assertFalse(mgr.isRelayReachable())
        assertEquals(2, mgr.consecutiveFullBudgetProbeTimeouts(), "aborted attempts are neither timeouts nor fast failures")
        // Bounded: the normal attempts plus at most PROBE_NEWNYM_REPROBE_MAX extra.
        assertEquals(
            MessageManager.RELAY_HEALTH_ATTEMPTS + MessageManager.PROBE_NEWNYM_REPROBE_MAX,
            relay.getFlags.size,
        )
        assertFalse(mgr.hasCompletedRelayRoundTrip())
    }

    @Test
    fun unprobedNewnym_getsOneFastCycle_evenOnAWarmTransport() {
        val mgr = MessageManager(InMemoryVault(), "http://relay.test", FakeRelayHttp.warm())
        assertTrue(mgr.isRelayReachable())
        assertTrue(mgr.relayHealthDelayMs() >= MessageManager.RELAY_HEALTH_BASE_MS, "warm → heartbeat")

        mgr.noteNewCircuitRequested()
        assertTrue(mgr.relayHealthDelayMs() <= 2_000L, "fresh circuits unprobed → fast retry")

        assertTrue(mgr.isRelayReachable())
        assertTrue(mgr.relayHealthDelayMs() >= MessageManager.RELAY_HEALTH_BASE_MS, "probed → back to heartbeat")
    }

    @Test
    fun aNewnymOnAColdTransport_doesNotSpendAColdFastRetryCredit() {
        // Cold transport whose probes fail fast (booked, stays cold).
        val mgr = MessageManager(InMemoryVault(), "http://relay.test", FakeRelayHttp.dead())
        mgr.noteNewCircuitRequested()
        assertTrue(mgr.relayHealthDelayMs() <= 2_000L, "the NEWNYM cycle")
        assertFalse(mgr.isRelayReachable())   // books an attempt under the new epoch
        // The NEWNYM-driven cycle was EXTRA: the cold window still holds all of
        // its RELAY_HEALTH_FAST_RETRY_MAX credits, then falls back to heartbeat.
        val fast = (0 until MessageManager.RELAY_HEALTH_FAST_RETRY_MAX).map { mgr.relayHealthDelayMs() }
        assertTrue(fast.all { it <= 2_000L }, "every cold credit still available: $fast")
        assertTrue(mgr.relayHealthDelayMs() >= MessageManager.RELAY_HEALTH_BASE_MS, "credits exhausted → heartbeat")
    }

    // --- the batch /peek --------------------------------------------------

    @Test
    fun batchPeekAbandonedByNewnym_isResentOnce_notFailedIntoTheSlowPath() {
        val relay = NewnymBatchRelay()
        val mgr = MessageManager(InMemoryVault(), "http://relay.test", relay)
        relay.mgr = mgr
        val outcome = mgr.peekInboxesBatch(listOf(MessageManager.PeekRef(NA_INBOX, NA_CAP)))
        val counts = outcome as? MessageManager.BatchPeekOutcome.Counts
        assertTrue(counts != null, "re-sent and answered: $outcome")
        assertEquals(3, counts!!.byInboxId[NA_INBOX])
        assertEquals(listOf(true, true), relay.postFlags, "two opted-in POSTs: abandoned + one resend")
    }
}

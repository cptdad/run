package com.vg.run

import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// MessageManager.isRelayReachable() diagnostics.
//
// The probe's ONLY failure mode in production is a non-throwing one: both
// PlatformHttpClient actuals map a transport error to HttpResult(code = -1, …)
// rather than propagating an exception (Android catches everything; iOS returns
// the bridge's code verbatim). The old implementation logged only from a
// catch block, so that path was UNREACHABLE and every relay/Tor health failure
// went unrecorded — four hour-long e2e runs produced no evidence at this layer.
//
// Rules under test:
//   1. A non-throwing failure logs one WARN per attempt, carrying the code.
//   2. It logs the CODE ONLY. On Android `body` on this path is the raw OkHttp
//      exception message, which can embed the request host ("unexpected end of
//      stream on http://<onion>/…") — writing that into the in-app log buffer
//      would partially deanonymize the relay.
//   3. A reachable relay logs nothing (any code > 0 counts, incl. the relay's
//      by-design 404 on GET /).
// ---------------------------------------------------------------------------

/** The onion-bearing body Android's transport puts in HttpResult on a failure. */
private const val LEAKY_BODY =
    "unexpected end of stream on http://abcdefghijklmnop234567.onion/..."

/** Every request fails the way the real transport fails: no throw, code = -1. */
private class DeadRelay(code: Int = -1) : FakeRelayHttp() {
    init { answerPostPutGet(HttpResult(code = code, body = LEAKY_BODY, isSuccess = false)) }
    val gets: Int get() = requestsOf("GET").size
    val getTimeouts: List<Int> get() = requestsOf("GET").map { it.timeoutSeconds }
}

/** The relay's real answer to GET / — a 404, which still proves it is up. */
private class NotFoundRelay : FakeRelayHttp() {
    val getTimeouts: List<Int> get() = requestsOf("GET").map { it.timeoutSeconds }
}

class RelayProbeDiagnosticsTest {

    private var loggingWasEnabled = false

    @BeforeTest
    fun enableBuffer() {
        loggingWasEnabled = LoggingState.enabled
        LoggingState.enabled = true
        LogBuffer.clear()
    }

    @AfterTest
    fun restoreBuffer() {
        LogBuffer.clear()
        LoggingState.enabled = loggingWasEnabled
    }

    @Test
    fun nonThrowingProbeFailure_isLoggedOncePerAttempt() {
        val relay = DeadRelay()
        val mgr = MessageManager(InMemoryVault(), "http://relay.test", relay)

        assertFalse(mgr.isRelayReachable(), "code = -1 on every attempt must report unreachable")

        val failures = LogBuffer.getAll().filter { it.message.startsWith("relay probe failed") }
        assertTrue(relay.gets >= 1, "the probe must actually hit the transport")
        assertEquals(relay.gets, failures.size, "every failed attempt must be logged (the old catch never fired)")
        assertTrue(failures.all { it.level == "W" }, "probe failures are WARNs")
        assertTrue(failures.all { "code=-1" in it.message }, "the outcome code is the diagnostic: ${failures.map { it.message }}")
    }

    @Test
    fun probeFailureNeverLogsTheResponseBody() {
        val mgr = MessageManager(InMemoryVault(), "http://relay.test", DeadRelay())
        mgr.isRelayReachable()

        val text = LogBuffer.asText()
        assertFalse(".onion" in text, "the failure body can carry the relay host — never log it")
        assertFalse("unexpected end of stream" in text, "no part of the transport's error body may be logged")
    }

    // -----------------------------------------------------------------------
    // The SEND and POLL lines follow the same rule: code only, exception CLASS only.
    // Both used to append up to 80 chars of the result body (on the poll's
    // code = -1 path that is the transport's raw error text) and the send/poll
    // catch blocks logged `e.message` of a thrown transport exception.
    // -----------------------------------------------------------------------

    private fun pairedManager(relay: RelayHttp): MessageManager {
        val vault = InMemoryVault()
        vault.insertContact(ContactRecord("c1", generateSecureRandom(32), 0, "p", 0L))
        vault.insertInboxId(InboxIdRecord("I".repeat(32), "c1", 0L, Long.MAX_VALUE, "inbound", "R".repeat(43)))
        vault.insertInboxId(InboxIdRecord("O".repeat(32), "c1", 0L, Long.MAX_VALUE, "outbound", "W".repeat(43)))
        return MessageManager(vault, "http://relay.test", relay).also { it.sendRetrySleep = {} }
    }

    @Test
    fun sendAndPollFailures_neverLogTheBodyOrTheExceptionMessage() {
        // -1 transport result (poll logs `poll → code=-1`), a real relay error with a
        // body (send logs `send → code=400`), and a thrown transport exception.
        for (relay in listOf<RelayHttp>(DeadRelay(), DeadRelay(code = 400), FakeRelayHttp.throwing(LEAKY_BODY))) {
            LogBuffer.clear()
            val mgr = pairedManager(relay)
            assertFalse(mgr.sendMessage("c1", "hi"), "a failing relay must fail the send")
            mgr.pollMessages("c1")
            val text = LogBuffer.asText()
            assertFalse(".onion" in text, "no relay host in a send/poll log line ($relay): $text")
            assertFalse("unexpected end of stream" in text, "no transport error text ($relay): $text")
        }
        // The diagnostic that IS kept: the code, and the class name of a throw.
        LogBuffer.clear()
        pairedManager(DeadRelay()).pollMessages("c1")
        assertTrue(LogBuffer.getAll().any { it.message.startsWith("poll → code=-1") }, LogBuffer.asText())
        LogBuffer.clear()
        pairedManager(FakeRelayHttp.throwing(LEAKY_BODY)).sendMessage("c1", "hi")
        assertTrue(
            LogBuffer.getAll().any { it.message.startsWith("send threw") && "IllegalStateException" in it.message },
            LogBuffer.asText(),
        )
    }

    @Test
    fun mintAndPeekFailures_neverLogTheBodyOrTheExceptionMessage() {
        // MINT: a terminal relay error with an onion-bearing body (`challenge fetch
        // code=507`), a -1 transport result, and a thrown transport exception (the
        // transient path, whose retry line repeats the MintTransientFailure text).
        // The abort fires on the SECOND poll — after the first attempt, inside the
        // backoff — so the transient paths stop without sleeping out the ladder.
        for (relay in listOf<RelayHttp>(DeadRelay(code = 507), DeadRelay(), FakeRelayHttp.throwing(LEAKY_BODY))) {
            LogBuffer.clear()
            var polls = 0
            val minted = MessageManager(InMemoryVault(), "http://relay.test", relay)
                .mintInbox(abort = PowAbort { ++polls > 1 })
            assertEquals(null, minted, "a failing relay must not mint ($relay)")
            val text = LogBuffer.asText()
            assertTrue(LogBuffer.getAll().any { it.message.startsWith("mintInbox:") }, "the mint must log its failure: $text")
            assertFalse(".onion" in text, "no relay host in a mint log line ($relay): $text")
            assertFalse("unexpected end of stream" in text, "no transport error text ($relay): $text")
        }
        LogBuffer.clear()
        var polls = 0
        MessageManager(InMemoryVault(), "http://relay.test", FakeRelayHttp.throwing(LEAKY_BODY)).mintInbox(abort = PowAbort { ++polls > 1 })
        assertTrue(
            LogBuffer.getAll().any { it.message.startsWith("mintInbox: transient") && "IllegalStateException" in it.message },
            "the exception CLASS is the kept diagnostic: ${LogBuffer.asText()}",
        )

        // PEEK: a thrown transport exception and a -1 result on the unread probe.
        for (relay in listOf<RelayHttp>(DeadRelay(), FakeRelayHttp.throwing(LEAKY_BODY))) {
            LogBuffer.clear()
            assertEquals(null, pairedManager(relay).peekInbox("c1"), "a failing peek is 'unknown' ($relay)")
            val text = LogBuffer.asText()
            assertFalse(".onion" in text, "no relay host in a peek log line ($relay): $text")
            assertFalse("unexpected end of stream" in text, "no transport error text ($relay): $text")
        }
        LogBuffer.clear()
        pairedManager(FakeRelayHttp.throwing(LEAKY_BODY)).peekInbox("c1")
        assertTrue(
            LogBuffer.getAll().any { it.message.startsWith("peek failed") && "IllegalStateException" in it.message },
            LogBuffer.asText(),
        )
    }

    @Test
    fun reachableRelay_logsNothingAndReportsUp() {
        val mgr = MessageManager(InMemoryVault(), "http://relay.test", NotFoundRelay())

        assertTrue(mgr.isRelayReachable(), "any real HTTP response (even the relay's by-design 404) means up")
        assertTrue(
            LogBuffer.getAll().none { it.message.startsWith("relay probe") },
            "a healthy probe must stay silent — the loop runs every 8-12s",
        )
    }

    // -----------------------------------------------------------------------
    // Probe TIMEOUT selection.
    //
    // A cold Tor session reports `Bootstrapped 100%` and publishes a SOCKS port
    // long before the hidden-service descriptor fetch + rendezvous with the
    // relay's onion can succeed, so the first probes legitimately fail. When the
    // probe inherited the 60 s message-transport default, each dead cycle cost
    // RELAY_HEALTH_ATTEMPTS × 60 s = 120 s: the jittered 8-12 s loop collapsed to
    // one probe pair per ~2 minutes, the 3-miss hysteresis could never clear, and
    // the user sat on "Connecting to the relay…". The probe must ask for its own
    // short budget — and must NOT do that by lowering the global default, which
    // real message traffic over Tor still needs.
    //
    // But a flat SHORT budget from the first probe is the opposite failure: every
    // attempt opens a FRESH stream with no carry-over, so if no single attempt is
    // long enough to finish the one-off descriptor fetch + rendezvous, the cold
    // start never completes at all. Hence the two-regime budget below: long until
    // the transport has proven ONE round-trip, tight forever after.
    // -----------------------------------------------------------------------

    @Test
    fun healthProbe_coldTransport_getsARendezvousSizedBudget() {
        val relay = DeadRelay()
        val mgr = MessageManager(InMemoryVault(), "http://relay.test", relay)

        mgr.isRelayReachable()   // latch is false throughout: nothing ever answers

        assertTrue(relay.getTimeouts.isNotEmpty(), "the probe must actually hit the transport")
        assertTrue(
            relay.getTimeouts.all { it == MessageManager.HEALTH_HTTP_TIMEOUT_SECONDS },
            "every cold attempt gets the dedicated health budget: ${relay.getTimeouts}",
        )
        assertTrue(
            relay.getTimeouts.all { it >= MessageManager.WARM_PROBE_TIMEOUT_SECONDS },
            "no cold attempt may be tighter than the mint warm-gate's floor: ${relay.getTimeouts}",
        )
        assertTrue(
            relay.getTimeouts.none { it == DEFAULT_RELAY_HTTP_TIMEOUT_SECONDS },
            "the probe must not inherit the 60 s message-transport default",
        )
    }

    @Test
    fun healthProbe_afterFirstRoundTrip_dropsToTheShortSteadyStateBudget() {
        val relay = FlakyAfterFirstSuccessRelay()
        val mgr = MessageManager(InMemoryVault(), "http://relay.test", relay)

        assertTrue(mgr.isRelayReachable(), "the 404 is a completed round-trip")
        relay.clearRequests()

        relay.dead = true
        assertFalse(mgr.isRelayReachable())
        assertTrue(relay.getTimeouts.isNotEmpty(), "the probe must actually hit the transport")
        assertTrue(
            relay.getTimeouts.all { it == MessageManager.RELAY_HEALTH_TIMEOUT_SECONDS },
            "once a round-trip is proven, every attempt uses the tight budget: ${relay.getTimeouts}",
        )
    }

    @Test
    fun relayProbeTimeoutSeconds_picksTheBudgetFromTheRoundTripLatch() {
        // Cold (nothing has ever answered on this transport): every attempt must be
        // able to outlast a descriptor fetch + rendezvous, because none of them
        // carries progress over to the next.
        assertEquals(
            MessageManager.HEALTH_HTTP_TIMEOUT_SECONDS,
            MessageManager.relayProbeTimeoutSeconds(roundTripCompleted = false),
        )
        // Warm: the rendezvous is done and cached — a slow probe is a dead circuit,
        // and failing fast is what rotates us onto a live one.
        assertEquals(
            MessageManager.RELAY_HEALTH_TIMEOUT_SECONDS,
            MessageManager.relayProbeTimeoutSeconds(roundTripCompleted = true),
        )
    }

    @Test
    fun healthProbe_worstCaseCycleStaysUnderThePollCadence() {
        // The reachability loop re-probes every 8-12 s. A fully dead STEADY-STATE
        // cycle must stay in the same order of magnitude as that cadence (it was 10x
        // it at 120 s), so the loop keeps rotating streams — each attempt opens a
        // fresh one, which is how a dying circuit actually recovers.
        val warmWorstCase = MessageManager.RELAY_HEALTH_TIMEOUT_SECONDS * 2   // RELAY_HEALTH_ATTEMPTS
        assertTrue(
            warmWorstCase <= 30,
            "a dead steady-state probe cycle must not exceed ~30 s (was 120 s): $warmWorstCase",
        )
        // A COLD cycle is deliberately longer (it must be able to COMPLETE), but it
        // is still bounded and still far under the 120 s the 60 s default cost —
        // and it must leave room for a THIRD fresh stream inside the first minute,
        // which is the whole point of the short retry that follows it.
        val coldWorstCase = MessageManager.HEALTH_HTTP_TIMEOUT_SECONDS * 2
        assertTrue(
            coldWorstCase in (warmWorstCase + 1)..45,
            "a dead cold cycle must be longer than the warm one, yet bounded: $coldWorstCase",
        )
        assertTrue(
            MessageManager.HEALTH_HTTP_TIMEOUT_SECONDS < DEFAULT_RELAY_HTTP_TIMEOUT_SECONDS,
            "even the cold budget stays under the message-transport default",
        )
        assertTrue(
            MessageManager.HEALTH_HTTP_TIMEOUT_SECONDS >= MessageManager.WARM_PROBE_TIMEOUT_SECONDS,
            "the cold probe never goes under the mint warm-gate's budget for this same GET",
        )
        assertTrue(
            MessageManager.RELAY_HEALTH_TIMEOUT_SECONDS < DEFAULT_RELAY_HTTP_TIMEOUT_SECONDS,
            "the global default must stay long for real message traffic",
        )
    }

    @Test
    fun globalMessageTransportDefault_isUnchanged() {
        // Guard against "fixing" the probe by lowering the shared default, which
        // would turn slow-but-healthy Tor sends into spurious failures.
        assertEquals(60, DEFAULT_RELAY_HTTP_TIMEOUT_SECONDS)
    }

    // -----------------------------------------------------------------------
    // Onion ROUND-TRIP latch — the honest "we can talk to the relay" signal the
    // UIs gate their "connected" claim on, instead of Tor's `Bootstrapped 100%`.
    // -----------------------------------------------------------------------

    @Test
    fun roundTripLatch_staysFalseUntilTheRelayActuallyAnswers() {
        val mgr = MessageManager(InMemoryVault(), "http://relay.test", DeadRelay())

        assertFalse(mgr.hasCompletedRelayRoundTrip(), "a fresh transport has proven nothing")
        mgr.isRelayReachable()
        assertFalse(
            mgr.hasCompletedRelayRoundTrip(),
            "failed probes are not evidence of an onion round-trip (Tor may well say it bootstrapped)",
        )
    }

    @Test
    fun roundTripLatch_setsOnFirstRealResponseAndDoesNotFlapBack() {
        val relay = FlakyAfterFirstSuccessRelay()
        val mgr = MessageManager(InMemoryVault(), "http://relay.test", relay)

        assertTrue(mgr.isRelayReachable())
        assertTrue(mgr.hasCompletedRelayRoundTrip(), "any real HTTP response (even 404) is a completed round-trip")

        // Later misses flip isRelayReachable (subject to the caller's hysteresis)
        // but must NOT un-prove that the relay was reached on this transport.
        relay.dead = true
        assertFalse(mgr.isRelayReachable())
        assertTrue(mgr.hasCompletedRelayRoundTrip(), "the latch is monotonic for the lifetime of the transport")
    }
}

/** Answers once (404 = up), then goes dark — a circuit dying mid-session. */
private class FlakyAfterFirstSuccessRelay : FakeRelayHttp() {
    var dead = false
    val getTimeouts: List<Int> get() = requestsOf("GET").map { it.timeoutSeconds }
    init {
        onPost = { HttpResult(code = if (dead) -1 else 202, body = "", isSuccess = !dead) }
        onPut = onPost
        onGet = { if (dead) HttpResult(code = -1, body = LEAKY_BODY, isSuccess = false) else RELAY_WARM_404 }
    }
}

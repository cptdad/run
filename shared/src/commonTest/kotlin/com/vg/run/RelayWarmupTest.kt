package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

// ---------------------------------------------------------------------------
// RelayWarmupTest — the pre-unlock rendezvous warm-up (lever 1, 2026-09-11).
//
// What earns a test here:
//
//  * THE REQUEST CARRIES NOTHING. The warm-up runs BEFORE the vault is open, so
//    the one thing that must never drift is that it is a bare `GET /` with an
//    EMPTY header map — no capability, no auth, no custom header. The header map
//    is asserted empty rather than "no read cap", the same rule
//    ConnectTelemetryTest applies to the other unauthenticated endpoint.
//  * ONE REQUEST, and never a write. The fake fails the test loudly on POST /
//    PUT / DELETE: a warm-up that mutated anything on the relay pre-unlock would
//    be a different feature.
//  * THE ADDRESS EXTRACTION IS STRICT. Its output is written into a command on
//    an AUTHENTICATED Tor control socket (`HSFETCH`), so anything carrying
//    CR/LF, a space, a wrong length or a non-base32 character must come back
//    null — that is control-channel command injection, not a failed fetch.
//  * A DEAD TRANSPORT IS NOT AN ERROR. Fire-and-forget: a throw and a
//    transport-level failure both return false without propagating.
//  * THE C5 LADDER (2026-09-15): the 25 s per-attempt budget, and the shared
//    `shouldRotateAndRetry` decision both platforms evaluate before spending one
//    `SIGNAL NEWNYM` out of the SESSION budget the post-unlock cold rung also
//    spends. A fast failure must NOT spend it (NEWNYM cannot fix a broken
//    transport), and the retry is bounded at one.
// ---------------------------------------------------------------------------

private const val WARMUP_BASE = "http://relay.test"

/** GET-only recorder: the warm-up never POSTs, PUTs or DELETEs. */
private fun RecordingWarmupRelay(
    scripted: HttpResult = HttpResult(404, "not found", false),
    throwOnGet: Boolean = false,
) = FakeRelayHttp.getOnly("the rendezvous warm-up") {
    if (throwOnGet) throw RuntimeException("transport down")
    scripted
}

class RelayWarmupTest {

    // -----------------------------------------------------------------------
    // warm — the wire shape
    // -----------------------------------------------------------------------

    @Test
    fun warm_issuesOneBareRootGetWithNoHeadersAtAll() = runTest {
        val http = RecordingWarmupRelay()

        // The relay has no root handler: 404 IS the success signal, exactly as
        // for the health probe.
        assertTrue(RelayWarmup.warm(http, WARMUP_BASE))

        val call = http.requests.single()
        assertEquals("$WARMUP_BASE/", call.url)
        // NO capability, NO auth, NO X-No-Push — nothing at all. This request is
        // issued with no vault open; it must need no secret.
        assertEquals(emptyMap(), call.headers)
        assertEquals(RelayWarmup.HTTP_TIMEOUT_SECONDS, call.timeoutSeconds)
    }

    @Test
    fun warm_skipsSilentlyWithoutATransportOrARelay() = runTest {
        assertFalse(RelayWarmup.warm(null, WARMUP_BASE))

        val http = RecordingWarmupRelay()
        assertFalse(RelayWarmup.warm(http, ""))
        assertTrue(http.requests.isEmpty(), "no relay configured must issue no request")
    }

    @Test
    fun warm_reportsFalseOnATransportFailureAndOnAThrow() = runTest {
        // Both actuals map a transport error to code = -1 rather than throwing.
        assertFalse(RelayWarmup.warm(RecordingWarmupRelay(scripted = HttpResult(-1, null, false)), WARMUP_BASE))
        // …and a throw (an iOS bridge-holder misregistration) is swallowed too.
        assertFalse(RelayWarmup.warm(RecordingWarmupRelay(throwOnGet = true), WARMUP_BASE))
    }

    // -----------------------------------------------------------------------
    // The C5 ladder — budget, attempt timing, and the shared retry decision
    // -----------------------------------------------------------------------

    @Test
    fun theBudgetIsTwentyFiveSecondsPerAttemptWithAtMostOneRetry() {
        // 25 s, NOT the original 60: the budget is the only thing that decides
        // when the cheap self-heal can run, and at 60 s the warm-up reported its
        // failure only after the user had already unlocked into the same wedge.
        assertEquals(25, RelayWarmup.HTTP_TIMEOUT_SECONDS)
        assertEquals(1, RelayWarmup.MAX_RETRIES)
        // …and never below the cold-probe regime: an attempt that cannot finish a
        // cold descriptor fetch + rendezvous would make every launch pay a NEWNYM
        // for work that was about to succeed. The cold health probe's own budget
        // is the reference point (20 s), and the cold send's is 30 s.
        assertTrue(
            RelayWarmup.HTTP_TIMEOUT_SECONDS >= MessageManager.HEALTH_HTTP_TIMEOUT_SECONDS,
            "the warm-up budget must not sit below the cold health probe's",
        )
    }

    @Test
    fun theWarmupRotationCanNeverExhaustTheSessionNewnymBudgetOnItsOwn() {
        // CAP SHARING: the pre-unlock rotation and the post-unlock cold rung
        // spend ONE per-session budget (RunViewModel.earlyNewnymsFired /
        // AppState.earlyNewnymsFired, capped by EARLY_NEWNYM_MAX_FIRES). The
        // warm-up may therefore fire at most one of them, leaving the post-unlock
        // rung at least one — which is what keeps the ladder's shape intact.
        assertEquals(2, MessageManager.EARLY_NEWNYM_MAX_FIRES)
        assertTrue(
            RelayWarmup.MAX_RETRIES < MessageManager.EARLY_NEWNYM_MAX_FIRES,
            "the pre-unlock retry must not be able to spend the whole session NEWNYM budget",
        )
    }

    @Test
    fun warmAttempt_reportsTheAnswerAndTheDuration() = runTest {
        val http = RecordingWarmupRelay()

        val attempt = RelayWarmup.warmAttempt(http, WARMUP_BASE)

        assertTrue(attempt.answered)
        assertTrue(attempt.elapsedMs >= 0L)
        assertEquals(RelayWarmup.HTTP_TIMEOUT_SECONDS, http.requests.single().timeoutSeconds)
    }

    @Test
    fun warmAttempt_reportsZeroElapsedForASkippedAttemptSoNothingRotates() = runTest {
        // Nothing was tried, so there is nothing to rotate away from — and the
        // shared decision must refuse it rather than spend a NEWNYM.
        val skipped = RelayWarmup.warmAttempt(null, WARMUP_BASE)

        assertFalse(skipped.answered)
        assertEquals(0L, skipped.elapsedMs)
        assertFalse(RelayWarmup.shouldRotateAndRetry(skipped.answered, skipped.elapsedMs, retriesUsed = 0))
    }

    @Test
    fun shouldRotateAndRetry_onlyForAFullBudgetFailureAndOnlyOnce() {
        val fullBudgetMs = RelayWarmup.HTTP_TIMEOUT_SECONDS * 1_000L

        // The case it exists for: failed, having burned the whole budget.
        assertTrue(RelayWarmup.shouldRotateAndRetry(answered = false, elapsedMs = fullBudgetMs, retriesUsed = 0))
        // Slack: the transport comes back a hair before its own deadline.
        assertTrue(
            RelayWarmup.shouldRotateAndRetry(
                answered = false,
                elapsedMs = fullBudgetMs - RelayWarmup.FULL_BUDGET_SLACK_MS,
                retriesUsed = 0,
            ),
        )
        assertFalse(
            RelayWarmup.shouldRotateAndRetry(
                answered = false,
                elapsedMs = fullBudgetMs - RelayWarmup.FULL_BUDGET_SLACK_MS - 1L,
                retriesUsed = 0,
            ),
        )
        // A FAST failure is a broken transport (SOCKS refused, no route), which
        // NEWNYM cannot fix — spending the session budget on it would starve the
        // post-unlock rung that can.
        assertFalse(RelayWarmup.shouldRotateAndRetry(answered = false, elapsedMs = 1_200L, retriesUsed = 0))
        assertFalse(RelayWarmup.shouldRotateAndRetry(answered = false, elapsedMs = 0L, retriesUsed = 0))
        // An ANSWERED warm-up never rotates, however long it took.
        assertFalse(RelayWarmup.shouldRotateAndRetry(answered = true, elapsedMs = fullBudgetMs, retriesUsed = 0))
        // Bounded at one retry, and a nonsense counter fails CLOSED.
        assertFalse(RelayWarmup.shouldRotateAndRetry(answered = false, elapsedMs = fullBudgetMs, retriesUsed = 1))
        assertFalse(RelayWarmup.shouldRotateAndRetry(answered = false, elapsedMs = fullBudgetMs, retriesUsed = 7))
        assertFalse(RelayWarmup.shouldRotateAndRetry(answered = false, elapsedMs = fullBudgetMs, retriesUsed = -1))
    }

    @Test
    fun warmAttempt_bracketsItselfWithTheTwoCodedPanelLinesAndNamesNothing() = runTest {
        ConnectionLog.clear()
        try {
            RelayWarmup.warmAttempt(RecordingWarmupRelay(scripted = HttpResult(-1, null, false)), WARMUP_BASE)

            val codes = ConnectionLog.snapshot().mapNotNull { it.code }
            assertEquals(
                listOf(ConnectionLog.Code.WARMUP_STARTED, ConnectionLog.Code.WARMUP_FAILED),
                codes,
                "a failed warm-up must be visible as exactly these two phases",
            )
            // Fixed phrases and numbers only — never the relay host.
            for (line in ConnectionLog.snapshot()) {
                assertFalse(line.text.contains("relay.test"), "the relay host reached a panel line: ${line.text}")
                assertFalse(line.text.contains("http"), "a URL reached a panel line: ${line.text}")
            }
        } finally {
            ConnectionLog.clear()
        }
    }

    @Test
    fun warmAttempt_logsNothingAtAllWhenThereIsNothingToWarm() = runTest {
        ConnectionLog.clear()
        try {
            RelayWarmup.warmAttempt(null, WARMUP_BASE)
            RelayWarmup.warmAttempt(RecordingWarmupRelay(), "")

            assertTrue(ConnectionLog.snapshot().isEmpty(), "a skipped warm-up must not narrate a phase it never ran")
        } finally {
            ConnectionLog.clear()
        }
    }

    @Test
    fun warmUpUrl_isTheRelayRootWithExactlyOneSlash() {
        assertEquals("$WARMUP_BASE/", RelayWarmup.warmUpUrl(WARMUP_BASE))
        assertEquals("$WARMUP_BASE/", RelayWarmup.warmUpUrl("$WARMUP_BASE/"))
    }

    // -----------------------------------------------------------------------
    // v3OnionAddress — strict, because the output reaches the control socket
    // -----------------------------------------------------------------------

    private val validAddress = "a".repeat(50) + "234567"   // 56 base32 chars

    @Test
    fun v3OnionAddress_stripsSchemePortAndPath() {
        assertEquals(validAddress, RelayWarmup.v3OnionAddress("http://$validAddress.onion"))
        assertEquals(validAddress, RelayWarmup.v3OnionAddress("http://$validAddress.onion:8080/inbox/x?y#z"))
        assertEquals(validAddress, RelayWarmup.v3OnionAddress("$validAddress.onion"))
        // A trailing FQDN dot is the same host; uppercase is normalised, since
        // Tor accepts the address only in lowercase base32.
        assertEquals(validAddress, RelayWarmup.v3OnionAddress("http://$validAddress.ONION./"))
    }

    @Test
    fun v3OnionAddress_refusesAnythingThatIsNotAV3Onion() {
        assertNull(RelayWarmup.v3OnionAddress(""))
        assertNull(RelayWarmup.v3OnionAddress("http://relay.test"))
        // v2 (16 chars) and any other length.
        assertNull(RelayWarmup.v3OnionAddress("http://abcdefghij234567.onion"))
        assertNull(RelayWarmup.v3OnionAddress("http://${"a".repeat(55)}.onion"))
        assertNull(RelayWarmup.v3OnionAddress("http://${"a".repeat(57)}.onion"))
        // Base32 excludes 0/1/8/9 and every non-alphanumeric.
        assertNull(RelayWarmup.v3OnionAddress("http://${"a".repeat(55)}0.onion"))
        assertNull(RelayWarmup.v3OnionAddress("http://${"a".repeat(55)}-.onion"))
        // ".onion" in the PATH must not be mistaken for the host.
        assertNull(RelayWarmup.v3OnionAddress("http://relay.test/$validAddress.onion"))
    }

    @Test
    fun v3OnionAddress_refusesControlCommandInjection() {
        // The result is interpolated into "HSFETCH <addr>\r\n" on an
        // AUTHENTICATED control socket. A CR/LF or a space would append a second
        // command; neither can survive the length + charset check, and the
        // authority parse drops anything after a '/' anyway.
        assertNull(RelayWarmup.v3OnionAddress("http://${"a".repeat(50)}23456\r\nSETCONF X=1.onion"))
        assertNull(RelayWarmup.v3OnionAddress("http://${"a".repeat(50)}23456 SIGNAL HALT.onion"))
        assertNull(RelayWarmup.v3OnionAddress("$validAddress.onion\r\nSIGNAL HALT"))
    }
}

package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest

// ---------------------------------------------------------------------------
// ConnectTelemetryTest — the anonymous connect-time report (2026-09-11).
//
// Three things are pinned here and must not drift:
//  1. The BUCKET arithmetic (round UP to 5 s, clamp to [5, 3600]) — the whole
//     privacy argument for sending a number at all is that it is coarse.
//  2. The exact wire body and the exact request shape — no capability, no auth,
//     no extra headers. A regression that started attaching a read capability to
//     an unauthenticated endpoint would be a serious leak, so the header map is
//     asserted EMPTY rather than merely "no read cap".
//  3. The `tor` PHASE SPLIT (lever 5): its own floor of 0 (Tor was already up),
//     omission when unknown, and `tor <= secs` — the relay derives the
//     rendezvous phase as `secs - tor`, so a `tor` above the total would produce
//     a negative phase out of two numbers that share one anchor.
//  4. The `boot` field (2026-09-11): floor 5 like `secs` (NOT 0 like `tor` — a
//     real bootstrap is never 0), omission when unknown, NEVER capped at
//     `secs` (different anchor), and the fixed key order `v, platform, app,
//     secs, tor, boot`.
//  5. The `log` CODED TIMELINE (2026-09-14): the anchor/window rules, the
//     round-UP-to-5 non-decreasing offsets, the reduction ladder, the
//     ≤ 2048-byte body bound — and, above all, that a LINE'S TEXT can never
//     reach the wire (`timelineField_neverCarriesLineTextOnlyTheCodeName`).
//     That last one is the privacy invariant of the whole field: the panel
//     narrates in prose, the report speaks only in a closed vocabulary.
//     `PROBE_TIMEOUT` is pinned NON-SHEDDABLE (2026-09-15): it is the evidence
//     the cold NEWNYM rung fires on, so the reduction ladder must not erase the
//     run that explains a `NEWNYM` in the same timeline.
//  6. The `reveal` field (C4a, 2026-09-15): the same 5 s bucketing as `secs`,
//     FLOORED at `secs` (so `reveal - secs`, the reveal gate, is never
//     negative), omitted when the list had not appeared yet, read from the
//     process latch AFTER the jitter delay — and the timeline window closing at
//     `REVEAL` when one has landed, at `FIRST_ROUNDTRIP` when it has not.
// ---------------------------------------------------------------------------

private const val TELEMETRY_BASE = "http://relay.test"

/** Fixed wall-clock base for the timeline fixtures (a plain epoch-millis value). */
private const val TIMELINE_T0 = 1_757_000_000_000L

/**
 * A [ConnectionLog.Line] built DIRECTLY (not through `append`), so the fixture
 * controls the timestamp and so [text] bypasses `redact()` — that is what lets
 * `timelineField_neverCarriesLineTextOnlyTheCodeName` hand the builder a line
 * whose text is exactly what must never ship.
 */
private fun logLine(
    offsetMs: Long,
    code: ConnectionLog.Code?,
    text: String = "narration",
    kind: ConnectionLog.Kind = ConnectionLog.Kind.TOR,
): ConnectionLog.Line = ConnectionLog.Line(TIMELINE_T0 + offsetMs, kind, text, code)

/** POST-only recorder: connect telemetry never PUTs, GETs or DELETEs. */
private fun RecordingTelemetryRelay(
    scripted: HttpResult = HttpResult(204, null, true),
    throwOnPost: Boolean = false,
) = FakeRelayHttp.postOnly("connect telemetry") {
    if (throwOnPost) throw RuntimeException("transport down")
    scripted
}

class ConnectTelemetryTest {

    // -----------------------------------------------------------------------
    // bucketSeconds — boundaries
    // -----------------------------------------------------------------------

    @Test
    fun bucketSeconds_roundsUpToFiveAndClamps() {
        assertEquals(5, ConnectTelemetry.bucketSeconds(0))
        assertEquals(5, ConnectTelemetry.bucketSeconds(1))
        assertEquals(5, ConnectTelemetry.bucketSeconds(5_000))
        assertEquals(10, ConnectTelemetry.bucketSeconds(5_001))
        assertEquals(3600, ConnectTelemetry.bucketSeconds(3_599_999))
        assertEquals(3600, ConnectTelemetry.bucketSeconds(9_999_999))
    }

    @Test
    fun bucketSeconds_negativeElapsedFloorsAtMinimum() {
        // Two clocks that disagree (a caller subtracting a later anchor) must
        // never produce 0 or a negative on the wire.
        assertEquals(5, ConnectTelemetry.bucketSeconds(-1))
        assertEquals(5, ConnectTelemetry.bucketSeconds(Long.MIN_VALUE))
    }

    @Test
    fun bucketSeconds_hugeElapsedCannotOverflowPastTheCeiling() {
        assertEquals(3600, ConnectTelemetry.bucketSeconds(Long.MAX_VALUE))
        assertEquals(3600, ConnectTelemetry.bucketSeconds(3_600_000))
        assertEquals(3600, ConnectTelemetry.bucketSeconds(3_600_001))
    }

    @Test
    fun bucketSeconds_isAlwaysAMultipleOfFiveInRange() {
        var ms = 0L
        while (ms <= 4_000_000L) {
            val secs = ConnectTelemetry.bucketSeconds(ms)
            assertEquals(0, secs % ConnectTelemetry.BUCKET_SECONDS, "not a 5 s bucket for ms=$ms")
            assertTrue(secs >= ConnectTelemetry.MIN_SECONDS && secs <= ConnectTelemetry.MAX_SECONDS, "out of range for ms=$ms")
            ms += 997L   // prime step, so bucket edges are hit off-phase
        }
    }

    // -----------------------------------------------------------------------
    // bucketTorSeconds — same arithmetic, floor 0 (lever 5)
    // -----------------------------------------------------------------------

    @Test
    fun bucketTorSeconds_roundsUpToFiveButFloorsAtZero() {
        // 0 is MEANINGFUL: Tor was already up when the connect clock started.
        assertEquals(0, ConnectTelemetry.bucketTorSeconds(0))
        assertEquals(0, ConnectTelemetry.bucketTorSeconds(-1))
        assertEquals(0, ConnectTelemetry.bucketTorSeconds(Long.MIN_VALUE))
        // Anything above zero still rounds UP, so a real (tiny) measurement can
        // never be confused with "already up".
        assertEquals(5, ConnectTelemetry.bucketTorSeconds(1))
        assertEquals(5, ConnectTelemetry.bucketTorSeconds(5_000))
        assertEquals(10, ConnectTelemetry.bucketTorSeconds(5_001))
        assertEquals(3600, ConnectTelemetry.bucketTorSeconds(3_599_999))
        assertEquals(3600, ConnectTelemetry.bucketTorSeconds(3_600_000))
        assertEquals(3600, ConnectTelemetry.bucketTorSeconds(3_600_001))
        assertEquals(3600, ConnectTelemetry.bucketTorSeconds(Long.MAX_VALUE))
    }

    @Test
    fun bucketTorSeconds_isAlwaysAMultipleOfFiveInRange() {
        var ms = -5_000L
        while (ms <= 4_000_000L) {
            val secs = ConnectTelemetry.bucketTorSeconds(ms)
            assertEquals(0, secs % ConnectTelemetry.BUCKET_SECONDS, "not a 5 s bucket for ms=$ms")
            assertTrue(
                secs >= ConnectTelemetry.MIN_TOR_SECONDS && secs <= ConnectTelemetry.MAX_SECONDS,
                "out of range for ms=$ms",
            )
            ms += 997L   // prime step, so bucket edges are hit off-phase
        }
    }

    // -----------------------------------------------------------------------
    // bucketBootSeconds — same arithmetic as bucketSeconds, floor 5 (not 0)
    // -----------------------------------------------------------------------

    @Test
    fun bucketBootSeconds_roundsUpToFiveAndFloorsAtFiveNotZero() {
        // Unlike bucketTorSeconds, a real bootstrap is never 0 — the floor is
        // the same MIN_SECONDS as the total.
        assertEquals(5, ConnectTelemetry.bucketBootSeconds(0))
        assertEquals(5, ConnectTelemetry.bucketBootSeconds(1))
        assertEquals(5, ConnectTelemetry.bucketBootSeconds(-1))
        assertEquals(5, ConnectTelemetry.bucketBootSeconds(Long.MIN_VALUE))
        assertEquals(5, ConnectTelemetry.bucketBootSeconds(4_999))
        assertEquals(5, ConnectTelemetry.bucketBootSeconds(5_000))
        assertEquals(10, ConnectTelemetry.bucketBootSeconds(5_001))
        assertEquals(3600, ConnectTelemetry.bucketBootSeconds(3_599_999))
        assertEquals(3600, ConnectTelemetry.bucketBootSeconds(3_600_000))
        assertEquals(3600, ConnectTelemetry.bucketBootSeconds(3_600_001))
        assertEquals(3600, ConnectTelemetry.bucketBootSeconds(Long.MAX_VALUE))
    }

    @Test
    fun bucketBootSeconds_isAlwaysAMultipleOfFiveInRange() {
        var ms = 0L
        while (ms <= 4_000_000L) {
            val secs = ConnectTelemetry.bucketBootSeconds(ms)
            assertEquals(0, secs % ConnectTelemetry.BUCKET_SECONDS, "not a 5 s bucket for ms=$ms")
            assertTrue(secs >= ConnectTelemetry.MIN_BOOT_SECONDS && secs <= ConnectTelemetry.MAX_SECONDS, "out of range for ms=$ms")
            ms += 997L   // prime step, so bucket edges are hit off-phase
        }
    }

    // -----------------------------------------------------------------------
    // payload — exact string, exact key order
    // -----------------------------------------------------------------------

    @Test
    fun payload_isTheExactContractedJson() {
        assertEquals(
            """{"v":1,"platform":"android","app":"1.6.11","secs":45}""",
            ConnectTelemetry.payload(ConnectTelemetry.PLATFORM_ANDROID, "1.6.11", 45),
        )
        assertEquals(
            """{"v":1,"platform":"ios","app":"1.6.11","secs":5}""",
            ConnectTelemetry.payload(ConnectTelemetry.PLATFORM_IOS, "1.6.11", 5),
        )
    }

    @Test
    fun payload_appendsTorLastAndOnlyWhenKnown() {
        assertEquals(
            """{"v":1,"platform":"android","app":"1.6.17","secs":45,"tor":20}""",
            ConnectTelemetry.payload(ConnectTelemetry.PLATFORM_ANDROID, "1.6.17", 45, 20),
        )
        // 0 is a value, not "absent" — it must appear on the wire.
        assertEquals(
            """{"v":1,"platform":"ios","app":"1.6.17","secs":15,"tor":0}""",
            ConnectTelemetry.payload(ConnectTelemetry.PLATFORM_IOS, "1.6.17", 15, 0),
        )
        // Unknown ⇒ the key is OMITTED, never null/-1.
        assertEquals(
            """{"v":1,"platform":"ios","app":"1.6.17","secs":15}""",
            ConnectTelemetry.payload(ConnectTelemetry.PLATFORM_IOS, "1.6.17", 15, null),
        )
    }

    @Test
    fun payload_appendsBootLastAfterTorInTheFixedKeyOrder() {
        // v, platform, app, secs, tor, boot — all three present.
        assertEquals(
            """{"v":1,"platform":"android","app":"1.6.17","secs":45,"tor":20,"boot":38}""",
            ConnectTelemetry.payload(ConnectTelemetry.PLATFORM_ANDROID, "1.6.17", 45, 20, 38),
        )
        // tor omitted, boot present — boot still lands right after secs.
        assertEquals(
            """{"v":1,"platform":"ios","app":"1.6.17","secs":15,"boot":10}""",
            ConnectTelemetry.payload(ConnectTelemetry.PLATFORM_IOS, "1.6.17", 15, null, 10),
        )
        // boot omitted, tor present — unchanged from before boot existed.
        assertEquals(
            """{"v":1,"platform":"ios","app":"1.6.17","secs":15,"tor":0}""",
            ConnectTelemetry.payload(ConnectTelemetry.PLATFORM_IOS, "1.6.17", 15, 0, null),
        )
        // Neither known ⇒ the v1 body, byte-identical to before boot existed.
        assertEquals(
            """{"v":1,"platform":"ios","app":"1.6.17","secs":15}""",
            ConnectTelemetry.payload(ConnectTelemetry.PLATFORM_IOS, "1.6.17", 15, null, null),
        )
    }

    @Test
    fun platformStringsAreTheTwoContractedValues() {
        assertEquals("android", ConnectTelemetry.PLATFORM_ANDROID)
        assertEquals("ios", ConnectTelemetry.PLATFORM_IOS)
        assertEquals("/telemetry/connect", ConnectTelemetry.PATH)
    }

    @Test
    fun sanitizeAppVersion_dropsAnythingButVersionCharactersAndIsBounded() {
        assertEquals("1.6.11", ConnectTelemetry.sanitizeAppVersion("1.6.11"))
        assertEquals("1.6.11-rc1", ConnectTelemetry.sanitizeAppVersion("1.6.11-rc1"))
        // Quotes, backslashes, CR/LF and spaces are dropped outright.
        assertEquals("1.6.11", ConnectTelemetry.sanitizeAppVersion("1.6\"\\.\r\n 11"))
        assertEquals(
            ConnectTelemetry.MAX_APP_CHARS,
            ConnectTelemetry.sanitizeAppVersion("1234567890123456789012345").length,
        )
    }

    // -----------------------------------------------------------------------
    // postReport — the wire shape
    // -----------------------------------------------------------------------

    @Test
    fun postReport_postsToTheTelemetryPathWithNoHeadersAtAll() {
        val http = RecordingTelemetryRelay()

        val sent = ConnectTelemetry.postReport(http, TELEMETRY_BASE, ConnectTelemetry.PLATFORM_ANDROID, "1.6.11", 45)

        assertTrue(sent)
        val call = http.requests.single()
        assertEquals("$TELEMETRY_BASE/telemetry/connect", call.url)
        assertEquals("application/json", call.contentType)
        // NO capability, NO auth, NO X-No-Push — nothing at all.
        assertEquals(emptyMap(), call.headers)
        assertEquals(ConnectTelemetry.HTTP_TIMEOUT_SECONDS, call.timeoutSeconds)
        assertEquals("""{"v":1,"platform":"android","app":"1.6.11","secs":45}""", call.bodyText)
    }

    @Test
    fun postReport_sanitizesTheAppVersionBeforeItReachesTheBody() {
        val http = RecordingTelemetryRelay()

        ConnectTelemetry.postReport(http, TELEMETRY_BASE, ConnectTelemetry.PLATFORM_IOS, """1.6"x""", 10)

        assertEquals("""{"v":1,"platform":"ios","app":"1.6x","secs":10}""", http.requests.single().bodyText)
    }

    @Test
    fun postReport_carriesTheTorPhaseWhenSupplied() {
        val http = RecordingTelemetryRelay()

        ConnectTelemetry.postReport(
            http, TELEMETRY_BASE, ConnectTelemetry.PLATFORM_ANDROID, "1.6.17", 45, 20,
        )

        assertEquals(
            """{"v":1,"platform":"android","app":"1.6.17","secs":45,"tor":20}""",
            http.requests.single().bodyText,
        )
    }

    @Test
    fun postReport_carriesTheBootFieldWhenSupplied() {
        val http = RecordingTelemetryRelay()

        ConnectTelemetry.postReport(
            http, TELEMETRY_BASE, ConnectTelemetry.PLATFORM_ANDROID, "1.6.17", 45, 20, 38,
        )

        assertEquals(
            """{"v":1,"platform":"android","app":"1.6.17","secs":45,"tor":20,"boot":38}""",
            http.requests.single().bodyText,
        )
    }

    // -----------------------------------------------------------------------
    // send — the tor bucket is derived, capped at secs, and omitted when null
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // send — Debug mode consent gate (2026-11-03): nothing leaves a default install
    // -----------------------------------------------------------------------

    @Test
    fun send_sendsNothingWhenDebugModeIsOff() = runTest {
        val http = RecordingTelemetryRelay()

        val sent = ConnectTelemetry.send(
            http = http,
            relayBaseUrl = TELEMETRY_BASE,
            platform = ConnectTelemetry.PLATFORM_ANDROID,
            appVersion = "1.6.17",
            elapsedMs = 42_000L,
            debugModeEnabled = { false },
            torElapsedMs = 20_000L,
            delayMs = 0L,
            revealElapsedMs = { null },
            logLines = { emptyList() },
        )

        assertFalse(sent)
        assertTrue(http.requests.isEmpty(), "a default install must not POST a connect report")
    }

    @Test
    fun send_skipsTheJitterEntirelyWhenDebugModeIsOff() = runTest {
        // The consent is read BEFORE the delay: an opted-out session must not
        // park a coroutine for 2-8 s only to drop the report afterwards.
        val http = RecordingTelemetryRelay()
        val before = testScheduler.currentTime

        ConnectTelemetry.send(
            http = http,
            relayBaseUrl = TELEMETRY_BASE,
            platform = ConnectTelemetry.PLATFORM_ANDROID,
            appVersion = "1.6.17",
            elapsedMs = 42_000L,
            debugModeEnabled = { false },
            delayMs = 5_000L,
            revealElapsedMs = { null },
            logLines = { emptyList() },
        )

        assertEquals(before, testScheduler.currentTime)
        assertTrue(http.requests.isEmpty())
    }

    @Test
    fun send_reReadsTheConsentAFTERTheJitterSoARevokeMidWindowStopsTheReport() = runTest {
        // Consent is not retroactive: on at the first relay answer, switched off
        // while the report sleeps out its jitter ⇒ no POST.
        val http = RecordingTelemetryRelay()
        var on = true
        val revoke = launch {
            delay(1_000L)
            on = false
        }

        val sent = ConnectTelemetry.send(
            http = http,
            relayBaseUrl = TELEMETRY_BASE,
            platform = ConnectTelemetry.PLATFORM_ANDROID,
            appVersion = "1.6.17",
            elapsedMs = 42_000L,
            debugModeEnabled = { on },
            delayMs = 5_000L,
            revealElapsedMs = { null },
            logLines = { emptyList() },
        )
        revoke.join()

        assertFalse(sent)
        assertTrue(http.requests.isEmpty(), "consent revoked during the jitter must drop the report")
    }

    @Test
    fun send_treatsAThrowingConsentProviderAsOff() = runTest {
        // iOS reads the consent from the Keychain, which can throw on a locked
        // keybag; the safe guess is "off" (DebugMode.isEnabled's own rule).
        val http = RecordingTelemetryRelay()

        val sent = ConnectTelemetry.send(
            http = http,
            relayBaseUrl = TELEMETRY_BASE,
            platform = ConnectTelemetry.PLATFORM_IOS,
            appVersion = "1.6.17",
            elapsedMs = 42_000L,
            debugModeEnabled = { throw IllegalStateException("keybag locked") },
            delayMs = 0L,
            revealElapsedMs = { null },
            logLines = { emptyList() },
        )

        assertFalse(sent)
        assertTrue(http.requests.isEmpty())
    }

    @Test
    fun send_reportsExactlyAsBeforeWhenDebugModeIsOn() = runTest {
        // The gate changes WHETHER, never WHAT: with consent on, the body is the
        // pre-2026-11-03 wire format byte for byte.
        val http = RecordingTelemetryRelay()

        val sent = ConnectTelemetry.send(
            http = http,
            relayBaseUrl = TELEMETRY_BASE,
            platform = ConnectTelemetry.PLATFORM_ANDROID,
            appVersion = "1.6.17",
            elapsedMs = 42_000L,
            debugModeEnabled = { true },
            torElapsedMs = 20_000L,
            delayMs = 0L,
            revealElapsedMs = { null },
            logLines = { emptyList() },
        )

        assertTrue(sent)
        assertEquals(
            """{"v":1,"platform":"android","app":"1.6.17","secs":45,"tor":20}""",
            http.requests.single().bodyText,
        )
    }

    @Test
    fun send_bucketsTheTorPhaseAndNeverReportsItAboveTheTotal() = runTest {
        val http = RecordingTelemetryRelay()

        // 42 s total, 20 s of it Tor ⇒ secs 45, tor 20, rendezvous 25.
        ConnectTelemetry.send(
            http = http,
            relayBaseUrl = TELEMETRY_BASE,
            platform = ConnectTelemetry.PLATFORM_ANDROID,
            debugModeEnabled = { true },
            appVersion = "1.6.17",
            elapsedMs = 42_000L,
            torElapsedMs = 20_000L,
            delayMs = 0L,
            // C4a: the `reveal` latch is process-wide, so every body-exact
            // test states its own answer instead of inheriting one.
            revealElapsedMs = { null },
            // The timeline has its own tests below; here the body must stay
            // byte-identical to the pre-2026-09-14 wire format.
            logLines = { emptyList() },
        )

        assertEquals(
            """{"v":1,"platform":"android","app":"1.6.17","secs":45,"tor":20}""",
            http.requests.single().bodyText,
        )
    }

    @Test
    fun send_capsTorAtSecsSoTheDerivedRendezvousIsNeverNegative() = runTest {
        val http = RecordingTelemetryRelay()

        // Nonsense input (a caller handing in a tor phase longer than the whole
        // wait — two clocks that disagree, or a mis-wired anchor): tor is capped
        // at secs, so `secs - tor` is 0 rather than negative. A merely ROUNDED
        // tie (e.g. 6 s total of which 5.6 s Tor, both bucketing to 10) lands on
        // the same rule.
        ConnectTelemetry.send(
            http = http,
            relayBaseUrl = TELEMETRY_BASE,
            platform = ConnectTelemetry.PLATFORM_IOS,
            debugModeEnabled = { true },
            appVersion = "1.6.17",
            elapsedMs = 6_000L,
            torElapsedMs = 9_999_000L,
            delayMs = 0L,
            // C4a: the `reveal` latch is process-wide, so every body-exact
            // test states its own answer instead of inheriting one.
            revealElapsedMs = { null },
            // The timeline has its own tests below; here the body must stay
            // byte-identical to the pre-2026-09-14 wire format.
            logLines = { emptyList() },
        )

        assertEquals(
            """{"v":1,"platform":"ios","app":"1.6.17","secs":10,"tor":10}""",
            http.requests.single().bodyText,
        )
    }

    @Test
    fun send_reportsTorZeroWhenTorWasAlreadyUp() = runTest {
        val http = RecordingTelemetryRelay()

        ConnectTelemetry.send(
            http = http,
            relayBaseUrl = TELEMETRY_BASE,
            platform = ConnectTelemetry.PLATFORM_ANDROID,
            debugModeEnabled = { true },
            appVersion = "1.6.17",
            elapsedMs = 12_000L,
            torElapsedMs = 0L,
            delayMs = 0L,
            // C4a: the `reveal` latch is process-wide, so every body-exact
            // test states its own answer instead of inheriting one.
            revealElapsedMs = { null },
            // The timeline has its own tests below; here the body must stay
            // byte-identical to the pre-2026-09-14 wire format.
            logLines = { emptyList() },
        )

        assertEquals(
            """{"v":1,"platform":"android","app":"1.6.17","secs":15,"tor":0}""",
            http.requests.single().bodyText,
        )
    }

    @Test
    fun send_omitsTorEntirelyWhenTheSessionCannotMeasureIt() = runTest {
        val http = RecordingTelemetryRelay()

        // The debug/direct path has no Tor at all — the v1 body, unchanged.
        ConnectTelemetry.send(
            http = http,
            relayBaseUrl = TELEMETRY_BASE,
            platform = ConnectTelemetry.PLATFORM_ANDROID,
            debugModeEnabled = { true },
            appVersion = "1.6.17",
            elapsedMs = 12_000L,
            torElapsedMs = null,
            delayMs = 0L,
            // C4a: the `reveal` latch is process-wide, so every body-exact
            // test states its own answer instead of inheriting one.
            revealElapsedMs = { null },
            // The timeline has its own tests below; here the body must stay
            // byte-identical to the pre-2026-09-14 wire format.
            logLines = { emptyList() },
        )

        assertEquals(
            """{"v":1,"platform":"android","app":"1.6.17","secs":15}""",
            http.requests.single().bodyText,
        )
    }

    @Test
    fun send_bucketsTheBootFieldAndNeverCapsItAtSecs() = runTest {
        val http = RecordingTelemetryRelay()

        // 12 s total connect wait, but the Tor PROCESS (speculative pre-unlock
        // start) took 90 s to bootstrap — boot legitimately exceeds secs
        // because it shares no anchor with it.
        ConnectTelemetry.send(
            http = http,
            relayBaseUrl = TELEMETRY_BASE,
            platform = ConnectTelemetry.PLATFORM_ANDROID,
            debugModeEnabled = { true },
            appVersion = "1.6.17",
            elapsedMs = 12_000L,
            torElapsedMs = 0L,
            bootElapsedMs = 90_000L,
            delayMs = 0L,
            // C4a: the `reveal` latch is process-wide, so every body-exact
            // test states its own answer instead of inheriting one.
            revealElapsedMs = { null },
            // The timeline has its own tests below; here the body must stay
            // byte-identical to the pre-2026-09-14 wire format.
            logLines = { emptyList() },
        )

        assertEquals(
            """{"v":1,"platform":"android","app":"1.6.17","secs":15,"tor":0,"boot":90}""",
            http.requests.single().bodyText,
        )
    }

    @Test
    fun send_omitsBootEntirelyWhenTheSessionNeverStartedOrConnectedTor() = runTest {
        val http = RecordingTelemetryRelay()

        ConnectTelemetry.send(
            http = http,
            relayBaseUrl = TELEMETRY_BASE,
            platform = ConnectTelemetry.PLATFORM_ANDROID,
            debugModeEnabled = { true },
            appVersion = "1.6.17",
            elapsedMs = 12_000L,
            torElapsedMs = null,
            bootElapsedMs = null,
            delayMs = 0L,
            // C4a: the `reveal` latch is process-wide, so every body-exact
            // test states its own answer instead of inheriting one.
            revealElapsedMs = { null },
            // The timeline has its own tests below; here the body must stay
            // byte-identical to the pre-2026-09-14 wire format.
            logLines = { emptyList() },
        )

        assertEquals(
            """{"v":1,"platform":"android","app":"1.6.17","secs":15}""",
            http.requests.single().bodyText,
        )
    }

    @Test
    fun postReport_swallowsATransportThrow() {
        val http = RecordingTelemetryRelay(throwOnPost = true)

        assertFalse(ConnectTelemetry.postReport(http, TELEMETRY_BASE, ConnectTelemetry.PLATFORM_ANDROID, "1.6.11", 45))
    }

    @Test
    fun postReport_ignoresANonSuccessResponse() {
        // The mock relay used by the emulator/simulator suites answers 404; a
        // deployed relay answers 204. Both are "sent" as far as this client is
        // concerned — nothing downstream may branch on the code.
        val http = RecordingTelemetryRelay(scripted = HttpResult(404, "not found", false))

        assertTrue(ConnectTelemetry.postReport(http, TELEMETRY_BASE, ConnectTelemetry.PLATFORM_IOS, "1.6.11", 15))
    }

    // -----------------------------------------------------------------------
    // The coded timeline (`log`, 2026-09-14) — offsets
    // -----------------------------------------------------------------------

    @Test
    fun offsetSeconds_roundsUpToFiveFloorsAtZeroAndClampsAtTheCeiling() {
        // 0 is the anchor's own offset and must stay 0 (unlike bucketSeconds,
        // whose floor is 5) — otherwise every timeline would open on a 5 s lie.
        assertEquals(0, ConnectTelemetry.offsetSeconds(0L))
        assertEquals(5, ConnectTelemetry.offsetSeconds(1_000L))
        assertEquals(5, ConnectTelemetry.offsetSeconds(5_000L))
        assertEquals(10, ConnectTelemetry.offsetSeconds(6_000L))
        assertEquals(10, ConnectTelemetry.offsetSeconds(10_000L))
        assertEquals(3600, ConnectTelemetry.offsetSeconds(3_600_000L))
        assertEquals(3600, ConnectTelemetry.offsetSeconds(99_999_999L))
        assertEquals(3600, ConnectTelemetry.offsetSeconds(Long.MAX_VALUE))
        // A line stamped before the anchor (clock step) floors at 0 here; the
        // non-decreasing rule in timelineEntries then pins it to its neighbour.
        assertEquals(0, ConnectTelemetry.offsetSeconds(-1L))
        assertEquals(0, ConnectTelemetry.offsetSeconds(Long.MIN_VALUE))
    }

    // -----------------------------------------------------------------------
    // The coded timeline — anchor and window
    // -----------------------------------------------------------------------

    @Test
    fun timelineField_anchorsOnTheFirstTorStartAndRendersTheContractedShape() {
        val field = ConnectTelemetry.timelineField(
            listOf(
                // Pre-Tor narration and a pre-Tor CODED line: both are BEFORE
                // the anchor, so neither may appear.
                logLine(0L, null, text = "waiting for unlock"),
                logLine(1_000L, ConnectionLog.Code.APP_FOREGROUNDED),
                logLine(10_000L, ConnectionLog.Code.TOR_START),
                logLine(15_000L, ConnectionLog.Code.TOR_BOOTSTRAP_TAG),
                logLine(45_000L, ConnectionLog.Code.SOCKS_READY),
                logLine(50_000L, ConnectionLog.Code.HSDESC_REQUESTED),
                logLine(55_000L, ConnectionLog.Code.HSDESC_RECEIVED),
                // Same 5 s bucket as REND_JOINED but a DIFFERENT code, so the
                // dedupe keeps both.
                logLine(70_000L, ConnectionLog.Code.REND_JOINED),
                logLine(70_000L, ConnectionLog.Code.FIRST_ROUNDTRIP),
            ),
        )

        assertEquals(
            ""","log":[[0,"TOR_START"],[5,"TOR_BOOTSTRAP_TAG"],[35,"SOCKS_READY"],""" +
                """[40,"HSDESC_REQUESTED"],[45,"HSDESC_RECEIVED"],[60,"REND_JOINED"],[60,"FIRST_ROUNDTRIP"]]""",
            field,
        )
    }

    @Test
    fun timelineField_anchorsOnTheFirstCodedLineWhenTheBufferHasNoTorStart() {
        // The 300-line ring can evict TOR_START, and the direct/no-Tor path
        // never emits one. Neither case may cost the whole report.
        val field = ConnectTelemetry.timelineField(
            listOf(
                logLine(0L, null, text = "ring evicted the bootstrap lines"),
                logLine(2_000L, ConnectionLog.Code.SOCKS_READY),
                logLine(9_000L, ConnectionLog.Code.PROBE_OK),
            ),
        )

        assertEquals(""","log":[[0,"SOCKS_READY"],[10,"PROBE_OK"]]""", field)
    }

    @Test
    fun timelineField_anchorsAWarmSessionOnTorReusedNotOnALaterRestart() {
        // 2026-10-23: Android's keep-alive adopt clears the ring and logs
        // TOR_REUSED instead of TOR_START. A self-heal restart's LATER
        // TOR_START must not become the anchor and cut the warm session's own
        // opening (and its first answer) off the timeline.
        val field = ConnectTelemetry.timelineField(
            listOf(
                logLine(0L, ConnectionLog.Code.TOR_REUSED),
                logLine(1_000L, ConnectionLog.Code.WARMUP_STARTED),
                logLine(40_000L, ConnectionLog.Code.TOR_RESTART),
                logLine(41_000L, ConnectionLog.Code.TOR_START),
                logLine(70_000L, ConnectionLog.Code.FIRST_ROUNDTRIP),
            ),
        )

        assertEquals(
            ""","log":[[0,"TOR_REUSED"],[5,"WARMUP_STARTED"],[40,"TOR_RESTART"],[45,"TOR_START"],[70,"FIRST_ROUNDTRIP"]]""",
            field,
        )
    }

    @Test
    fun timelineField_carriesTheHsDescReasonSplitCodesByName() {
        val field = ConnectTelemetry.timelineField(
            listOf(
                logLine(0L, ConnectionLog.Code.TOR_START),
                logLine(5_000L, ConnectionLog.Code.HSDESC_NO_HSDIR, text = "descriptor fetch failed: QUERY_NO_HSDIR"),
                logLine(10_000L, ConnectionLog.Code.HSDESC_NOT_FOUND),
                logLine(15_000L, ConnectionLog.Code.HSDESC_BAD_DESC),
                logLine(20_000L, ConnectionLog.Code.HSDESC_RATE_LIMITED),
                logLine(25_000L, ConnectionLog.Code.HSDESC_UNEXPECTED),
                logLine(30_000L, ConnectionLog.Code.HSDESC_FAILED),
                logLine(35_000L, ConnectionLog.Code.FIRST_ROUNDTRIP),
            ),
        )

        assertEquals(
            ""","log":[[0,"TOR_START"],[5,"HSDESC_NO_HSDIR"],[10,"HSDESC_NOT_FOUND"],[15,"HSDESC_BAD_DESC"],""" +
                """[20,"HSDESC_RATE_LIMITED"],[25,"HSDESC_UNEXPECTED"],[30,"HSDESC_FAILED"],[35,"FIRST_ROUNDTRIP"]]""",
            field,
        )
    }

    @Test
    fun timelineField_isOmittedEntirelyWhenNothingIsCoded() {
        assertEquals("", ConnectTelemetry.timelineField(emptyList()))
        assertEquals(
            "",
            ConnectTelemetry.timelineField(
                listOf(
                    logLine(0L, null, text = "connecting"),
                    logLine(5_000L, null, text = "still connecting"),
                ),
            ),
        )
    }

    @Test
    fun timelineField_stopsAtTheFirstRoundTrip() {
        // Everything after the connect completed (self-heal, NEWNYM, later
        // probes, the lock) is none of the relay's business.
        val field = ConnectTelemetry.timelineField(
            listOf(
                logLine(0L, ConnectionLog.Code.TOR_START),
                logLine(20_000L, ConnectionLog.Code.FIRST_ROUNDTRIP),
                logLine(30_000L, ConnectionLog.Code.PROBE_OK),
                logLine(40_000L, ConnectionLog.Code.NEWNYM),
                logLine(50_000L, ConnectionLog.Code.FIRST_ROUNDTRIP),
                logLine(60_000L, ConnectionLog.Code.SESSION_LOCKED),
            ),
        )

        assertEquals(""","log":[[0,"TOR_START"],[20,"FIRST_ROUNDTRIP"]]""", field)
    }

    @Test
    fun timelineField_clampsOffsetsAtTheHourCeiling() {
        val field = ConnectTelemetry.timelineField(
            listOf(
                logLine(0L, ConnectionLog.Code.TOR_START),
                logLine(3_599_000L, ConnectionLog.Code.SOCKS_READY),
                logLine(7_200_000L, ConnectionLog.Code.FIRST_ROUNDTRIP),
            ),
        )

        assertEquals(""","log":[[0,"TOR_START"],[3600,"SOCKS_READY"],[3600,"FIRST_ROUNDTRIP"]]""", field)
    }

    @Test
    fun timelineField_forcesOffsetsNonDecreasingAcrossABackwardsClockStep() {
        // ConnectionLog stamps lines with the WALL clock, and noticing a wrong
        // clock is part of what Tor does at bootstrap — an NTP correction
        // mid-connect must not emit an offset that goes backwards.
        val field = ConnectTelemetry.timelineField(
            listOf(
                logLine(0L, ConnectionLog.Code.TOR_START),
                logLine(30_000L, ConnectionLog.Code.CLOCK_JUMPED),
                logLine(-600_000L, ConnectionLog.Code.SOCKS_READY),   // clock stepped back 10 min
                logLine(-599_000L, ConnectionLog.Code.FIRST_ROUNDTRIP),
            ),
        )

        assertEquals(
            ""","log":[[0,"TOR_START"],[30,"CLOCK_JUMPED"],[30,"SOCKS_READY"],[30,"FIRST_ROUNDTRIP"]]""",
            field,
        )
    }

    // -----------------------------------------------------------------------
    // The coded timeline — the reduction ladder
    // -----------------------------------------------------------------------

    @Test
    fun timelineField_collapsesConsecutiveRepeatsOfTheSameCodeAndBucket() {
        // Tor emits a dozen bootstrap-tag lines inside one 5 s bucket; on the
        // wire they are one indistinguishable repeat. Dedupe is UNCONDITIONAL
        // (not only on overflow) — it lowers the entropy of the report.
        val field = ConnectTelemetry.timelineField(
            listOf(
                logLine(0L, ConnectionLog.Code.TOR_START),
                logLine(1_000L, ConnectionLog.Code.TOR_BOOTSTRAP_TAG),
                logLine(2_000L, ConnectionLog.Code.TOR_BOOTSTRAP_TAG),
                logLine(3_000L, ConnectionLog.Code.TOR_BOOTSTRAP_TAG),
                // Same code, NEXT bucket ⇒ kept (it is new information).
                logLine(7_000L, ConnectionLog.Code.TOR_BOOTSTRAP_TAG),
                // Same bucket, different code ⇒ kept.
                logLine(8_000L, ConnectionLog.Code.SOCKS_READY),
                // A repeat that is NOT consecutive ⇒ kept: A B A stays A B A.
                logLine(9_000L, ConnectionLog.Code.TOR_BOOTSTRAP_TAG),
            ),
        )

        assertEquals(
            ""","log":[[0,"TOR_START"],[5,"TOR_BOOTSTRAP_TAG"],[10,"TOR_BOOTSTRAP_TAG"],""" +
                """[10,"SOCKS_READY"],[10,"TOR_BOOTSTRAP_TAG"]]""",
            field,
        )
    }

    @Test
    fun timelineField_shedsProbeAndStreamEntriesOldestFirstWhenOverTheCap() {
        // 8 over the cap, all sheddable: the OLDEST 8 PROBE_*/STREAM_* entries
        // go and every bootstrap/rendezvous entry survives.
        val lines = mutableListOf(logLine(0L, ConnectionLog.Code.TOR_START))
        var at = 0L
        repeat(20) {
            at += 6_000L
            lines += logLine(at, ConnectionLog.Code.STREAM_FAILED)
        }
        repeat(35) {
            at += 6_000L
            lines += logLine(at, if (it % 2 == 0) ConnectionLog.Code.CIRCUIT_LOST else ConnectionLog.Code.CIRCUIT_OK)
        }

        val entries = ConnectTelemetry.reduceTimeline(ConnectTelemetry.timelineEntries(lines))

        assertEquals(ConnectTelemetry.MAX_LOG_ENTRIES, entries.size)
        // The anchor survived (shedding never touches the head of the list).
        assertEquals(ConnectionLog.Code.TOR_START, entries.first().code)
        assertEquals(0, entries.first().offsetSeconds)
        // 20 stream entries minus the 8 shed = 12 left, all of them the NEWEST.
        assertEquals(12, entries.count { it.code == ConnectionLog.Code.STREAM_FAILED })
        assertEquals(35, entries.count { it.code.name.startsWith("CIRCUIT_") })
        // Oldest-first: the surviving stream entries are the later ones.
        val firstStream = entries.first { it.code == ConnectionLog.Code.STREAM_FAILED }
        assertEquals(ConnectTelemetry.offsetSeconds(9 * 6_000L), firstStream.offsetSeconds)
    }

    @Test
    fun timelineField_dropsTheOldestWhenSheddingIsNotEnough() {
        // 60 non-sheddable entries ⇒ nothing to shed, so the ladder falls
        // through to "drop the oldest" and the NEWEST 48 survive — including
        // the FIRST_ROUNDTRIP that closes the window.
        val lines = mutableListOf(logLine(0L, ConnectionLog.Code.TOR_START))
        var at = 0L
        repeat(58) {
            at += 6_000L
            lines += logLine(at, if (it % 2 == 0) ConnectionLog.Code.CIRCUIT_LOST else ConnectionLog.Code.CIRCUIT_OK)
        }
        at += 6_000L
        lines += logLine(at, ConnectionLog.Code.FIRST_ROUNDTRIP)

        val entries = ConnectTelemetry.reduceTimeline(ConnectTelemetry.timelineEntries(lines))

        assertEquals(ConnectTelemetry.MAX_LOG_ENTRIES, entries.size)
        assertEquals(ConnectionLog.Code.FIRST_ROUNDTRIP, entries.last().code)
        // The anchor was dropped with the rest of the old head, and the
        // survivors keep their TRUE offsets (they are not re-based on 0).
        assertFalse(entries.any { it.code == ConnectionLog.Code.TOR_START })
        assertEquals(ConnectTelemetry.offsetSeconds(12 * 6_000L), entries.first().offsetSeconds)
        // Still non-decreasing after the drop.
        var previous = -1
        for (e in entries) {
            assertTrue(e.offsetSeconds >= previous, "offsets went backwards at $e")
            previous = e.offsetSeconds
        }
    }

    @Test
    fun timelineField_neverEmitsMoreThanTheCapForAPathologicalSession() {
        // A Tor that restarts in a loop for an hour: bounded output, no
        // truncation marker, nothing but codes.
        val lines = mutableListOf<ConnectionLog.Line>()
        var at = 0L
        repeat(400) {
            lines += logLine(at, ConnectionLog.Code.TOR_START)
            at += 3_000L
            lines += logLine(at, ConnectionLog.Code.TOR_BOOTSTRAP_PROBLEM)
            at += 3_000L
            lines += logLine(at, ConnectionLog.Code.TOR_RESTART)
            at += 3_000L
        }

        val field = ConnectTelemetry.timelineField(lines)

        assertEquals(ConnectTelemetry.MAX_LOG_ENTRIES, field.split("],[").size)
        assertFalse(field.contains("…") || field.contains("..."), "no truncation marker may be emitted")
    }

    // -----------------------------------------------------------------------
    // The coded timeline — the privacy invariant
    // -----------------------------------------------------------------------

    @Test
    fun timelineField_neverCarriesLineTextOnlyTheCodeName() {
        // The panel's narration is prose; the report is a closed vocabulary.
        // Hand the builder the worst line imaginable — an onion host and a
        // relay fingerprint, straight into Line.text, bypassing redact() — and
        // assert that NOTHING of it reaches the field.
        val onion = "jtlc2exampleonionaddressthatmustnevershipqwertyuiopasd.onion"
        val fingerprint = "\$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA~Guard1 at 10.1.2.3:9001"
        val lines = listOf(
            logLine(0L, ConnectionLog.Code.TOR_START, text = "starting tor for $onion"),
            logLine(5_000L, ConnectionLog.Code.GUARD_UP, text = fingerprint),
            logLine(9_000L, null, text = "user alias: Alice; inbox $onion"),
            logLine(11_000L, ConnectionLog.Code.FIRST_ROUNDTRIP, text = fingerprint),
        )

        val field = ConnectTelemetry.timelineField(lines)
        val body = ConnectTelemetry.payload(ConnectTelemetry.PLATFORM_ANDROID, "1.6.17", 15, 5, 20, null, field)

        assertEquals(""","log":[[0,"TOR_START"],[5,"GUARD_UP"],[15,"FIRST_ROUNDTRIP"]]""", field)
        for (needle in listOf("onion", "Guard1", "10.1.2.3", "9001", "Alice", "AAAA", "starting", "user")) {
            assertFalse(body.contains(needle), "line text leaked into the body: $needle")
        }
        assertEquals(
            """{"v":1,"platform":"android","app":"1.6.17","secs":15,"tor":5,"boot":20,""" +
                """"log":[[0,"TOR_START"],[5,"GUARD_UP"],[15,"FIRST_ROUNDTRIP"]]}""",
            body,
        )
    }

    // -----------------------------------------------------------------------
    // The coded timeline — the body bound
    // -----------------------------------------------------------------------

    @Test
    fun payload_worstCaseBodyStaysUnderTheRelayCeiling() {
        // Arithmetic bound, derived from the LONGEST name in ConnectionLog.Code
        // rather than from today's enum: adding a very long code name must fail
        // HERE, in the test tier, not at the relay's 2048-byte door. The head is
        // built with EVERY optional number present at its 4-digit ceiling —
        // secs, tor, boot and (since C4a) reveal.
        val longest = ConnectionLog.Code.entries.maxOf { it.name.length }
        // `[3600,"<NAME>"]` = 2 brackets + 4 offset digits + separator comma +
        // 2 quotes + the name.
        val worstEntry = 2 + 4 + 1 + 2 + longest
        val worstLog = ""","log":[""".length + ConnectTelemetry.MAX_LOG_ENTRIES * worstEntry +
            (ConnectTelemetry.MAX_LOG_ENTRIES - 1) + 1
        val worstHead = ConnectTelemetry.payload(
            ConnectTelemetry.PLATFORM_ANDROID,
            "X".repeat(ConnectTelemetry.MAX_APP_CHARS),
            ConnectTelemetry.MAX_SECONDS,
            ConnectTelemetry.MAX_SECONDS,
            ConnectTelemetry.MAX_SECONDS,
            ConnectTelemetry.MAX_SECONDS,
        ).encodeToByteArray().size

        assertTrue(
            worstHead + worstLog <= ConnectTelemetry.MAX_BODY_BYTES,
            "worst-case body ${worstHead + worstLog} B exceeds the relay ceiling ${ConnectTelemetry.MAX_BODY_BYTES} B",
        )
        // Headroom is asserted, not merely implied: `reveal` (C4a) cost 14 B of
        // it, and the next field must be added with the same arithmetic in view.
        assertTrue(
            ConnectTelemetry.MAX_BODY_BYTES - (worstHead + worstLog) >= 256,
            "only ${ConnectTelemetry.MAX_BODY_BYTES - (worstHead + worstLog)} B of headroom left under the relay ceiling",
        )
    }

    @Test
    fun payload_aMaximalRealTimelineFitsTheRelayCeiling() {
        // The same bound, built for real: 48 surviving entries of the two
        // longest code names (alternating, so the dedupe cannot collapse them),
        // all pinned at the 3600 s ceiling, with every optional field present
        // and a max-length app version.
        val longest = ConnectionLog.Code.entries
            .filter { it != ConnectionLog.Code.FIRST_ROUNDTRIP }   // would close the window early
            .sortedByDescending { it.name.length }
        val lines = (0 until ConnectTelemetry.MAX_LOG_ENTRIES).map { i ->
            logLine(7_200_000L + i, longest[i % 2])
        }

        val field = ConnectTelemetry.timelineField(lines)
        val body = ConnectTelemetry.payload(
            ConnectTelemetry.PLATFORM_ANDROID,
            "X".repeat(ConnectTelemetry.MAX_APP_CHARS),
            ConnectTelemetry.MAX_SECONDS,
            ConnectTelemetry.MAX_SECONDS,
            ConnectTelemetry.MAX_SECONDS,
            ConnectTelemetry.MAX_SECONDS,
            field,
        ).encodeToByteArray().size

        assertEquals(ConnectTelemetry.MAX_LOG_ENTRIES, field.split("],[").size)
        assertTrue(
            body in 1_400..ConnectTelemetry.MAX_BODY_BYTES,
            "maximal real body was $body B (expected a full timeline under ${ConnectTelemetry.MAX_BODY_BYTES} B)",
        )
    }

    @Test
    fun payload_dropsTheTimelineRatherThanBustTheCeiling() {
        // Defence in depth over MAX_LOG_ENTRIES: if a future change ever made
        // the fragment enormous, the NUMBERS must still be reported — losing
        // secs/tor/boot to a rejected request is the worse failure.
        val huge = ""","log":[""" + (0 until 500).joinToString(",") { """[3600,"TOR_BOOTSTRAP_PROBLEM"]""" } + "]"

        assertEquals(
            """{"v":1,"platform":"android","app":"1.6.17","secs":45,"tor":20,"boot":38}""",
            ConnectTelemetry.payload(ConnectTelemetry.PLATFORM_ANDROID, "1.6.17", 45, 20, 38, null, huge),
        )
    }

    // -----------------------------------------------------------------------
    // The coded timeline — key order and the send path
    // -----------------------------------------------------------------------

    @Test
    fun payload_appendsTheTimelineLastInTheFixedKeyOrder() {
        val field = ""","log":[[0,"TOR_START"],[35,"SOCKS_READY"]]"""
        // v, platform, app, secs, tor, boot, log — log always last.
        assertEquals(
            """{"v":1,"platform":"android","app":"1.6.17","secs":45,"tor":20,"boot":38,""" +
                """"log":[[0,"TOR_START"],[35,"SOCKS_READY"]]}""",
            ConnectTelemetry.payload(ConnectTelemetry.PLATFORM_ANDROID, "1.6.17", 45, 20, 38, null, field),
        )
        // …including when the optional NUMBERS are absent: log still lands
        // straight after secs, and an empty field changes nothing at all.
        assertEquals(
            """{"v":1,"platform":"ios","app":"1.6.17","secs":15,"log":[[0,"TOR_START"],[35,"SOCKS_READY"]]}""",
            ConnectTelemetry.payload(ConnectTelemetry.PLATFORM_IOS, "1.6.17", 15, null, null, null, field),
        )
        assertEquals(
            """{"v":1,"platform":"ios","app":"1.6.17","secs":15}""",
            ConnectTelemetry.payload(ConnectTelemetry.PLATFORM_IOS, "1.6.17", 15, null, null, null, ""),
        )
    }

    @Test
    fun send_carriesTheTimelineOnEveryConnect() = runTest {
        val http = RecordingTelemetryRelay()

        ConnectTelemetry.send(
            http = http,
            relayBaseUrl = TELEMETRY_BASE,
            platform = ConnectTelemetry.PLATFORM_IOS,
            debugModeEnabled = { true },
            appVersion = "1.6.17",
            elapsedMs = 42_000L,
            torElapsedMs = 20_000L,
            bootElapsedMs = 38_000L,
            delayMs = 0L,
            // C4a: the `reveal` latch is process-wide, so every body-exact
            // test states its own answer instead of inheriting one.
            revealElapsedMs = { null },
            logLines = {
                listOf(
                    logLine(0L, ConnectionLog.Code.TOR_START),
                    logLine(34_000L, ConnectionLog.Code.SOCKS_READY),
                    logLine(41_500L, ConnectionLog.Code.FIRST_ROUNDTRIP),
                )
            },
        )

        assertEquals(
            """{"v":1,"platform":"ios","app":"1.6.17","secs":45,"tor":20,"boot":40,""" +
                """"log":[[0,"TOR_START"],[35,"SOCKS_READY"],[45,"FIRST_ROUNDTRIP"]]}""",
            http.requests.single().bodyText,
        )
    }

    @Test
    fun send_omitsTheLogKeyWhenTheSessionCodedNothing() = runTest {
        val http = RecordingTelemetryRelay()

        ConnectTelemetry.send(
            http = http,
            relayBaseUrl = TELEMETRY_BASE,
            platform = ConnectTelemetry.PLATFORM_ANDROID,
            debugModeEnabled = { true },
            appVersion = "1.6.17",
            elapsedMs = 12_000L,
            delayMs = 0L,
            // C4a: the `reveal` latch is process-wide, so every body-exact
            // test states its own answer instead of inheriting one.
            revealElapsedMs = { null },
            logLines = { listOf(logLine(0L, null, text = "connecting")) },
        )

        assertEquals("""{"v":1,"platform":"android","app":"1.6.17","secs":15}""", http.requests.single().bodyText)
    }

    @Test
    fun send_stillReportsTheNumbersIfTheTimelineSourceThrows() = runTest {
        // Android arms the report in a bare `viewModelScope.launch`: a throw
        // while building the field would crash the app on its first connect.
        // The numbers must survive; the timeline is the expendable part.
        val http = RecordingTelemetryRelay()

        val sent = ConnectTelemetry.send(
            http = http,
            relayBaseUrl = TELEMETRY_BASE,
            platform = ConnectTelemetry.PLATFORM_ANDROID,
            debugModeEnabled = { true },
            appVersion = "1.6.17",
            elapsedMs = 12_000L,
            delayMs = 0L,
            // C4a: the `reveal` latch is process-wide, so every body-exact
            // test states its own answer instead of inheriting one.
            revealElapsedMs = { null },
            logLines = { throw RuntimeException("connection log exploded") },
        )

        assertTrue(sent)
        assertEquals("""{"v":1,"platform":"android","app":"1.6.17","secs":15}""", http.requests.single().bodyText)
    }

    @Test
    fun send_readsTheTimelineAFTERTheJitterNotBeforeIt() = runTest {
        // The lines that close the connect land while this coroutine sleeps out
        // its 2-8 s jitter; reading the snapshot early would systematically
        // truncate the very phase the field exists to show.
        val http = RecordingTelemetryRelay()
        var lines = listOf(logLine(0L, ConnectionLog.Code.TOR_START))
        val late = launch {
            delay(1_000L)
            lines = lines + logLine(20_000L, ConnectionLog.Code.FIRST_ROUNDTRIP)
        }

        ConnectTelemetry.send(
            http = http,
            relayBaseUrl = TELEMETRY_BASE,
            platform = ConnectTelemetry.PLATFORM_ANDROID,
            debugModeEnabled = { true },
            appVersion = "1.6.17",
            elapsedMs = 20_000L,
            delayMs = 5_000L,
            revealElapsedMs = { null },
            logLines = { lines },
        )
        late.join()

        assertEquals(
            """{"v":1,"platform":"android","app":"1.6.17","secs":20,"log":[[0,"TOR_START"],[20,"FIRST_ROUNDTRIP"]]}""",
            http.requests.single().bodyText,
        )
    }

    @Test
    fun send_defaultsToTheLiveConnectionLogWithNoPlatformChange() = runTest {
        // Neither platform passes a timeline: the default provider reads the
        // process-wide ConnectionLog at send time. This is the ONLY test that
        // touches the singleton, so it clears it on both ends.
        ConnectionLog.clear()
        try {
            val http = RecordingTelemetryRelay()
            ConnectionLog.append(ConnectionLog.Kind.TOR, "tor starting", ConnectionLog.Code.TOR_START)
            ConnectionLog.append(ConnectionLog.Kind.RELAY, "relay answered", ConnectionLog.Code.FIRST_ROUNDTRIP)

            ConnectTelemetry.send(
                http = http,
                relayBaseUrl = TELEMETRY_BASE,
                platform = ConnectTelemetry.PLATFORM_ANDROID,
                debugModeEnabled = { true },
                appVersion = "1.6.17",
                elapsedMs = 12_000L,
                delayMs = 0L,
                // C4a: the `reveal` latch is process-wide, so every body-exact
                // test states its own answer instead of inheriting one.
                revealElapsedMs = { null },
            )

            // The two appends are microseconds apart on the REAL clock, so the
            // second offset is 0 or 5 depending on where the millisecond fell —
            // assert the shape, never a race-dependent number.
            val body = http.requests.single().bodyText
            assertTrue(body.contains(""""log":[[0,"TOR_START"],["""), "unexpected body: $body")
            assertTrue(body.contains(""","FIRST_ROUNDTRIP"]]"""), "unexpected body: $body")
            // The "connect time reported" line itself has no code, so it can
            // never appear in the timeline it would follow.
            assertFalse(body.contains("connect time reported"))
        } finally {
            ConnectionLog.clear()
        }
    }

    // -----------------------------------------------------------------------
    // The `reveal` field (C4a, 2026-09-15) — the END of the user's wait
    // -----------------------------------------------------------------------

    @Test
    fun revealSecondsFor_bucketsLikeSecsAndIsNeverBelowTheTotal() {
        // Same 5 s round-UP as `secs` (floor 5, ceiling 3600).
        assertEquals(5, ConnectTelemetry.revealSecondsFor(1L, secs = 5))
        assertEquals(20, ConnectTelemetry.revealSecondsFor(16_000L, secs = 5))
        assertEquals(3600, ConnectTelemetry.revealSecondsFor(Long.MAX_VALUE, secs = 5))
        // FLOORED at this report's own secs — the mirror image of `tor`'s cap:
        // the two share one anchor, and the reveal cannot precede the answer
        // that triggers it, so `reveal - secs` (the reveal gate the relay
        // derives) can never be negative.
        assertEquals(45, ConnectTelemetry.revealSecondsFor(1_000L, secs = 45))
        assertEquals(45, ConnectTelemetry.revealSecondsFor(-9_000L, secs = 45))
        // Unknown ⇒ omitted, never a sentinel.
        assertNull(ConnectTelemetry.revealSecondsFor(null, secs = 45))
    }

    @Test
    fun markRevealed_isSetOnceAndRefusesANegativeMeasurement() {
        ConnectTelemetry.resetRevealForTest()
        try {
            assertNull(ConnectTelemetry.revealedElapsedMs())
            // A caller that cannot measure must not be able to invent a 0 s reveal.
            ConnectTelemetry.markRevealed(-1L)
            assertNull(ConnectTelemetry.revealedElapsedMs())

            ConnectTelemetry.markRevealed(12_000L)
            assertEquals(12_000L, ConnectTelemetry.revealedElapsedMs())
            // Set-once: a later in-process re-auth unlock re-reveals the list,
            // but the report describes the FIRST connect of the process.
            ConnectTelemetry.markRevealed(99_000L)
            assertEquals(12_000L, ConnectTelemetry.revealedElapsedMs())
        } finally {
            ConnectTelemetry.resetRevealForTest()
        }
    }

    @Test
    fun startNewRevealSession_letsAWarmIosSessionLatchItsOwnReveal() {
        // Bounded Tor keep-alive (BackgroundTorKeepAlive, 2026-10-23): a warm
        // return re-arms AppState's anchor + report latch; its report must carry
        // ITS reveal, never the first session's.
        ConnectTelemetry.resetRevealForTest()
        try {
            ConnectTelemetry.markRevealed(40_000L)
            assertEquals(40_000L, ConnectTelemetry.revealedElapsedMs())
            ConnectTelemetry.startNewRevealSession()
            assertNull(ConnectTelemetry.revealedElapsedMs(), "the new session starts unrevealed")
            ConnectTelemetry.markRevealed(3_000L)
            assertEquals(3_000L, ConnectTelemetry.revealedElapsedMs())
            // Still set-once within the new session.
            ConnectTelemetry.markRevealed(9_000L)
            assertEquals(3_000L, ConnectTelemetry.revealedElapsedMs())
        } finally {
            ConnectTelemetry.resetRevealForTest()
        }
    }

    @Test
    fun latchedReveal_isTheSameSetOnceRuleAsTheProcessLatch() {
        assertNull(ConnectTelemetry.latchedReveal(null, -1L), "a caller that cannot measure invents nothing")
        assertEquals(12_000L, ConnectTelemetry.latchedReveal(null, 12_000L))
        assertEquals(0L, ConnectTelemetry.latchedReveal(null, 0L))
        assertEquals(12_000L, ConnectTelemetry.latchedReveal(12_000L, 99_000L), "first measurement wins")
        assertEquals(12_000L, ConnectTelemetry.latchedReveal(12_000L, -5L))
    }

    @Test
    fun send_aSecondSessionReportsItsOwnRevealNotTheProcessLatch() = runTest {
        // THE BUG (fixed 2026-10-23): Android's report and connect anchor are
        // per SESSION (one RunViewModel each), but the reveal came from the
        // process-wide latch — so session 2 in a surviving process (the Tor
        // keep-alive's warm return) shipped session 1's reveal. Session 1 here
        // revealed at 60 s; session 2 answered at 5 s and revealed at 8 s.
        ConnectTelemetry.resetRevealForTest()
        try {
            ConnectTelemetry.markRevealed(60_000L) // the stale first-session value
            val http = RecordingTelemetryRelay()
            var session2Reveal: Long? = null
            session2Reveal = ConnectTelemetry.latchedReveal(session2Reveal, 8_000L)

            ConnectTelemetry.send(
                http = http,
                relayBaseUrl = TELEMETRY_BASE,
                platform = ConnectTelemetry.PLATFORM_ANDROID,
                debugModeEnabled = { true },
                appVersion = "1.6.47",
                elapsedMs = 5_000L,
                torElapsedMs = 0L,
                delayMs = 0L,
                revealElapsedMs = { session2Reveal },
                logLines = { emptyList() },
            )

            assertEquals(
                """{"v":1,"platform":"android","app":"1.6.47","secs":5,"tor":0,"reveal":10}""",
                http.requests.single().bodyText,
            )
        } finally {
            ConnectTelemetry.resetRevealForTest()
        }
    }

    @Test
    fun payload_appendsRevealAfterBootAndBeforeTheTimeline() {
        // v, platform, app, secs, tor, boot, reveal, log.
        assertEquals(
            """{"v":1,"platform":"android","app":"1.6.17","secs":45,"tor":20,"boot":38,"reveal":50}""",
            ConnectTelemetry.payload(ConnectTelemetry.PLATFORM_ANDROID, "1.6.17", 45, 20, 38, 50),
        )
        // Every other optional number absent — reveal still lands right after secs.
        assertEquals(
            """{"v":1,"platform":"ios","app":"1.6.17","secs":15,"reveal":25}""",
            ConnectTelemetry.payload(ConnectTelemetry.PLATFORM_IOS, "1.6.17", 15, null, null, 25),
        )
        // …and the timeline still lands LAST, after reveal.
        assertEquals(
            """{"v":1,"platform":"ios","app":"1.6.17","secs":15,"reveal":25,""" +
                """"log":[[0,"TOR_START"]]}""",
            ConnectTelemetry.payload(
                ConnectTelemetry.PLATFORM_IOS, "1.6.17", 15, null, null, 25,
                ""","log":[[0,"TOR_START"]]""",
            ),
        )
        // Absent ⇒ every pre-C4a body is byte-identical to what it was.
        assertEquals(
            """{"v":1,"platform":"ios","app":"1.6.17","secs":15,"tor":0,"boot":10}""",
            ConnectTelemetry.payload(ConnectTelemetry.PLATFORM_IOS, "1.6.17", 15, 0, 10, null),
        )
    }

    @Test
    fun send_carriesTheRevealFromTheProcessLatchWithNoPlatformChange() = runTest {
        // Neither platform passes the reveal: the default provider reads the
        // markRevealed latch at send time, exactly like the timeline reads
        // ConnectionLog — which is why this field needed no Android or iOS
        // plumbing through the call site.
        ConnectTelemetry.resetRevealForTest()
        try {
            val http = RecordingTelemetryRelay()
            ConnectTelemetry.markRevealed(31_000L)

            ConnectTelemetry.send(
                http = http,
                relayBaseUrl = TELEMETRY_BASE,
                platform = ConnectTelemetry.PLATFORM_ANDROID,
                debugModeEnabled = { true },
                appVersion = "1.6.17",
                elapsedMs = 12_000L,
                torElapsedMs = 0L,
                delayMs = 0L,
                logLines = { emptyList() },
            )

            assertEquals(
                """{"v":1,"platform":"android","app":"1.6.17","secs":15,"tor":0,"reveal":35}""",
                http.requests.single().bodyText,
            )
        } finally {
            ConnectTelemetry.resetRevealForTest()
        }
    }

    @Test
    fun send_readsTheRevealAFTERTheJitterSoALateRevealStillCounts() = runTest {
        // The reveal lands AFTER the first relay answer that armed the report —
        // usually inside the 2-8 s jitter window. Reading it at the call site
        // would omit the field on almost every connect.
        ConnectTelemetry.resetRevealForTest()
        try {
            val http = RecordingTelemetryRelay()
            val late = launch {
                delay(1_000L)
                ConnectTelemetry.markRevealed(21_000L)
            }

            ConnectTelemetry.send(
                http = http,
                relayBaseUrl = TELEMETRY_BASE,
                platform = ConnectTelemetry.PLATFORM_ANDROID,
                debugModeEnabled = { true },
                appVersion = "1.6.17",
                elapsedMs = 20_000L,
                delayMs = 5_000L,
                logLines = { emptyList() },
            )
            late.join()

            assertEquals(
                """{"v":1,"platform":"android","app":"1.6.17","secs":20,"reveal":25}""",
                http.requests.single().bodyText,
            )
        } finally {
            ConnectTelemetry.resetRevealForTest()
        }
    }

    @Test
    fun send_omitsRevealEntirelyWhenTheListHasNotAppearedYet() = runTest {
        // A reveal that outlives the report omits the key rather than delaying
        // the report — and its ABSENCE is itself the honest statement that the
        // reveal gate outlasted the jitter.
        ConnectTelemetry.resetRevealForTest()
        try {
            val http = RecordingTelemetryRelay()

            ConnectTelemetry.send(
                http = http,
                relayBaseUrl = TELEMETRY_BASE,
                platform = ConnectTelemetry.PLATFORM_IOS,
                debugModeEnabled = { true },
                appVersion = "1.6.17",
                elapsedMs = 12_000L,
                delayMs = 0L,
                logLines = { emptyList() },
            )

            assertEquals("""{"v":1,"platform":"ios","app":"1.6.17","secs":15}""", http.requests.single().bodyText)
        } finally {
            ConnectTelemetry.resetRevealForTest()
        }
    }

    @Test
    fun send_neverReportsARevealBelowTheTotalSoTheDerivedGateIsNeverNegative() = runTest {
        val http = RecordingTelemetryRelay()

        // Nonsense input (a reveal measured as EARLIER than the answer it
        // follows): floored at secs, so `reveal - secs` is 0, never negative.
        ConnectTelemetry.send(
            http = http,
            relayBaseUrl = TELEMETRY_BASE,
            platform = ConnectTelemetry.PLATFORM_ANDROID,
            debugModeEnabled = { true },
            appVersion = "1.6.17",
            elapsedMs = 42_000L,
            delayMs = 0L,
            revealElapsedMs = { 1_000L },
            logLines = { emptyList() },
        )

        assertEquals(
            """{"v":1,"platform":"android","app":"1.6.17","secs":45,"reveal":45}""",
            http.requests.single().bodyText,
        )
    }

    @Test
    fun send_stillReportsTheNumbersIfTheRevealSourceThrows() = runTest {
        val http = RecordingTelemetryRelay()

        val sent = ConnectTelemetry.send(
            http = http,
            relayBaseUrl = TELEMETRY_BASE,
            platform = ConnectTelemetry.PLATFORM_ANDROID,
            debugModeEnabled = { true },
            appVersion = "1.6.17",
            elapsedMs = 12_000L,
            delayMs = 0L,
            revealElapsedMs = { throw RuntimeException("reveal clock exploded") },
            logLines = { emptyList() },
        )

        assertTrue(sent)
        assertEquals("""{"v":1,"platform":"android","app":"1.6.17","secs":15}""", http.requests.single().bodyText)
    }

    // -----------------------------------------------------------------------
    // The coded timeline — the window now closes at the REVEAL (C4a)
    // -----------------------------------------------------------------------

    @Test
    fun timelineField_extendsTheWindowToTheRevealWhenItHasAlreadyLanded() {
        // The user's wait ends when the CONTACT LIST appears, not when the relay
        // answers: everything between the two (the unread prime, its cap) is the
        // phase C4a exists to make visible.
        val field = ConnectTelemetry.timelineField(
            listOf(
                logLine(0L, ConnectionLog.Code.TOR_START),
                logLine(20_000L, ConnectionLog.Code.FIRST_ROUNDTRIP),
                logLine(22_000L, ConnectionLog.Code.PRIME_PASS),
                logLine(30_000L, ConnectionLog.Code.PRIME_CAP),
                logLine(30_500L, ConnectionLog.Code.REVEAL),
                // …and everything after the reveal is out of scope again.
                logLine(40_000L, ConnectionLog.Code.PROBE_OK),
                logLine(60_000L, ConnectionLog.Code.SESSION_LOCKED),
            ),
        )

        assertEquals(
            ""","log":[[0,"TOR_START"],[20,"FIRST_ROUNDTRIP"],[25,"PRIME_PASS"],""" +
                """[30,"PRIME_CAP"],[35,"REVEAL"]]""",
            field,
        )
    }

    @Test
    fun timelineField_closesAtTheRoundTripWhenTheRevealHasNotLandedYet() {
        // Unchanged pre-C4a behaviour, and deliberately so: the window is never
        // WAITED for. A report assembled before the list appeared simply carries
        // no REVEAL — which is the honest reading.
        val field = ConnectTelemetry.timelineField(
            listOf(
                logLine(0L, ConnectionLog.Code.TOR_START),
                logLine(20_000L, ConnectionLog.Code.FIRST_ROUNDTRIP),
                logLine(22_000L, ConnectionLog.Code.PRIME_PASS),
            ),
        )

        assertEquals(""","log":[[0,"TOR_START"],[20,"FIRST_ROUNDTRIP"]]""", field)
    }

    @Test
    fun timelineField_takesTheFirstRevealAfterTheRoundTripNotALaterSessionsOne() {
        // An in-process re-auth unlock re-reveals the list, so the buffer can
        // hold a SECOND connect's lines. The window must close on THIS connect's
        // reveal and never swallow the next connect.
        val field = ConnectTelemetry.timelineField(
            listOf(
                logLine(0L, ConnectionLog.Code.TOR_START),
                logLine(20_000L, ConnectionLog.Code.FIRST_ROUNDTRIP),
                logLine(25_000L, ConnectionLog.Code.REVEAL),
                logLine(120_000L, ConnectionLog.Code.SESSION_LOCKED),
                logLine(130_000L, ConnectionLog.Code.FIRST_ROUNDTRIP),
                logLine(135_000L, ConnectionLog.Code.REVEAL),
            ),
        )

        assertEquals(
            ""","log":[[0,"TOR_START"],[20,"FIRST_ROUNDTRIP"],[25,"REVEAL"]]""",
            field,
        )
    }

    // -----------------------------------------------------------------------
    // The reduction ladder — PROBE_TIMEOUT is evidence, not volume
    // -----------------------------------------------------------------------

    @Test
    fun reduceTimeline_shedsStreamsFirstAndKeepsEveryProbeTimeout() {
        // 55 entries, 7 over the cap: the OLDEST 7 STREAM_* go and nothing else
        // is touched — the probe run that explains the connect survives intact.
        val lines = mutableListOf(logLine(0L, ConnectionLog.Code.TOR_START))
        var at = 0L
        repeat(10) { at += 6_000L; lines += logLine(at, ConnectionLog.Code.STREAM_FAILED) }
        repeat(12) { at += 6_000L; lines += logLine(at, ConnectionLog.Code.PROBE_OK) }
        repeat(2) { at += 6_000L; lines += logLine(at, ConnectionLog.Code.PROBE_TIMEOUT) }
        repeat(30) {
            at += 6_000L
            lines += logLine(at, if (it % 2 == 0) ConnectionLog.Code.CIRCUIT_LOST else ConnectionLog.Code.CIRCUIT_OK)
        }

        val entries = ConnectTelemetry.reduceTimeline(ConnectTelemetry.timelineEntries(lines))

        assertEquals(ConnectTelemetry.MAX_LOG_ENTRIES, entries.size)
        assertEquals(3, entries.count { it.code == ConnectionLog.Code.STREAM_FAILED })
        assertEquals(12, entries.count { it.code == ConnectionLog.Code.PROBE_OK })
        assertEquals(2, entries.count { it.code == ConnectionLog.Code.PROBE_TIMEOUT })
        assertEquals(ConnectionLog.Code.TOR_START, entries.first().code)
    }

    @Test
    fun reduceTimeline_shedsTheNEWESTOtherProbesAndNeverAProbeTimeout() {
        // Streams alone are not enough (2 of a 10-entry overflow), so the ladder
        // reaches the PROBE_* family — which must give up its NEWEST members
        // (the ones nearest the answer, i.e. the least surprising) and NEVER a
        // PROBE_TIMEOUT, the evidence the cold NEWNYM rung fires on.
        val lines = mutableListOf(logLine(0L, ConnectionLog.Code.TOR_START))
        var at = 0L
        repeat(2) { at += 6_000L; lines += logLine(at, ConnectionLog.Code.STREAM_FAILED) }
        val probeOkOffsets = mutableListOf<Int>()
        repeat(12) {
            at += 6_000L
            probeOkOffsets += ConnectTelemetry.offsetSeconds(at)
            lines += logLine(at, ConnectionLog.Code.PROBE_OK)
        }
        repeat(3) { at += 6_000L; lines += logLine(at, ConnectionLog.Code.PROBE_TIMEOUT) }
        repeat(40) {
            at += 6_000L
            lines += logLine(at, if (it % 2 == 0) ConnectionLog.Code.CIRCUIT_LOST else ConnectionLog.Code.CIRCUIT_OK)
        }

        val entries = ConnectTelemetry.reduceTimeline(ConnectTelemetry.timelineEntries(lines))

        assertEquals(ConnectTelemetry.MAX_LOG_ENTRIES, entries.size)
        assertEquals(0, entries.count { it.code == ConnectionLog.Code.STREAM_FAILED }, "streams are shed first")
        assertEquals(3, entries.count { it.code == ConnectionLog.Code.PROBE_TIMEOUT }, "PROBE_TIMEOUT is never shed")
        // 12 PROBE_OK minus the 8 remaining overflow = the OLDEST 4 survive.
        val survivingOk = entries.filter { it.code == ConnectionLog.Code.PROBE_OK }.map { it.offsetSeconds }
        assertEquals(probeOkOffsets.take(4), survivingOk)
        assertEquals(40, entries.count { it.code.name.startsWith("CIRCUIT_") })
        assertEquals(ConnectionLog.Code.TOR_START, entries.first().code)
    }

    @Test
    fun isSheddableProbeCode_excludesTheTimeoutAndNothingElse() {
        assertFalse(ConnectTelemetry.isSheddableProbeCode(ConnectionLog.Code.PROBE_TIMEOUT))
        assertTrue(ConnectTelemetry.isSheddableProbeCode(ConnectionLog.Code.PROBE_OK))
        assertTrue(ConnectTelemetry.isSheddableProbeCode(ConnectionLog.Code.PROBE_ERROR))
        assertFalse(ConnectTelemetry.isSheddableProbeCode(ConnectionLog.Code.STREAM_FAILED))
        assertTrue(ConnectTelemetry.isSheddableStreamCode(ConnectionLog.Code.STREAM_FAILED))
        assertTrue(ConnectTelemetry.isSheddableStreamCode(ConnectionLog.Code.STREAM_OK))
        assertFalse(ConnectTelemetry.isSheddableStreamCode(ConnectionLog.Code.PROBE_OK))
        // The reveal pair is never sheddable by family: they are the phase C4a
        // measures, and there are at most one of each per connect.
        assertFalse(ConnectTelemetry.isSheddableProbeCode(ConnectionLog.Code.REVEAL))
        assertFalse(ConnectTelemetry.isSheddableStreamCode(ConnectionLog.Code.PRIME_CAP))
        // C2d: the FAST probe failure joined the sheddable family — a broken
        // stream repeated twenty times says what the first two said, while a
        // FULL-BUDGET timeout stays evidence and stays non-sheddable.
        assertTrue(ConnectTelemetry.isSheddableProbeCode(ConnectionLog.Code.PROBE_FAILED))
        assertFalse(ConnectTelemetry.isSheddableStreamCode(ConnectionLog.Code.PROBE_FAILED))
    }

    // -----------------------------------------------------------------------
    // The vocabulary's size bound (C2, 2026-09-15)
    // -----------------------------------------------------------------------

    @Test
    fun codeNames_stayWithinTheNameLengthTheCeilingWasSizedFor() {
        // The worst-case body scales with the LONGEST name times
        // MAX_LOG_ENTRIES, so a new code costs 48 bytes per character it adds
        // beyond the longest one already there — this is the one property that
        // makes "add a code" a cheap change. C2 added 15 codes and not one
        // character to this number.
        val longest = ConnectionLog.Code.entries.maxBy { it.name.length }
        assertEquals(
            "TOR_BOOTSTRAP_PROBLEM",
            longest.name,
            "a longer code name shrinks the payload headroom by 48 B per character",
        )
        // Every C2 phase code is a fixed name, never a Tor token echoed into
        // one: the mapping is a lookup with a catch-all.
        for (code in ConnectionLog.Code.entries) {
            assertTrue(
                code.name.all { it in 'A'..'Z' || it == '_' },
                "a code name outside [A-Z_] breaks the relay's entry regex: ${code.name}",
            )
        }
    }

    // -----------------------------------------------------------------------
    // jitterDelayMs
    // -----------------------------------------------------------------------

    @Test
    fun jitterDelayMs_staysInTheContractedWindow() {
        repeat(200) {
            val d = ConnectTelemetry.jitterDelayMs()
            assertTrue(
                d >= ConnectTelemetry.MIN_DELAY_MS && d <= ConnectTelemetry.MAX_DELAY_MS,
                "jitter out of the 2-8 s window: $d",
            )
        }
    }
}

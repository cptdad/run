package com.vg.run

// ---------------------------------------------------------------------------
// PlatformHttpClient — platform-agnostic HTTP client abstraction.
// ---------------------------------------------------------------------------

data class HttpResult(
    val code: Int,
    val body: String?,
    val isSuccess: Boolean,
    /**
     * A small, ALLOWLISTED, platform-filtered subset of the relay's response
     * headers — never the relay's full header set. Each platform actual reads
     * only its own single relay header (Android: `android-version`; iOS:
     * `ios-version`), and only when present AND no longer than
     * [MAX_APP_VERSION_HEADER_CHARS] stores it under the single common key
     * [APP_VERSION_HEADER_KEY]; otherwise this stays empty. Values here must
     * NEVER be logged — a hostile relay controls them.
     */
    val headers: Map<String, String> = emptyMap(),
    /**
     * The request's stream CONNECTED through Tor's SOCKS port but
     * no response byte arrived within the caller's first-byte budget (see
     * [RelayHttp.get]'s five-argument form), so the transport gave up early.
     * Only ever true when a first-byte budget was passed. On Android it may also
     * mean the SOCKS CONNECT itself outlived that budget (Java's SOCKS client can
     * honour the socket read timeout) — the same stalled-stream evidence.
     * Carries no data from the relay.
     */
    val firstByteTimeout: Boolean = false,
)

/**
 * Cap on the response body read into memory — bounds a hostile relay's OOM
 * vector. 16 MiB >> any legitimate inbox drain. Single-sourced for both Kotlin
 * actuals (one declaration, not per-actuals copies); SwiftTorHttp keeps its
 * own Swift `maxResponseBytes` mirror, documented against this value.
 */
internal const val MAX_RESPONSE_BYTES: Long = 16L * 1024 * 1024

/**
 * Update-nudge: the single common key under which the platform
 * actuals store the relay's advertised app-store version in
 * [HttpResult.headers], regardless of which platform-specific relay header
 * (`android-version` / `ios-version`) supplied it. See [HttpResult.headers].
 */
const val APP_VERSION_HEADER_KEY: String = "app-version"

/**
 * Update-nudge: cap on the app-version header value length. The
 * wire grammar is `MAJOR.MINOR.PATCH`, each component 1-4 ASCII digits, total
 * <= 14 chars. A hostile relay must not be able
 * to park an oversized string under [APP_VERSION_HEADER_KEY]; anything longer
 * is dropped outright (never truncated).
 */
const val MAX_APP_VERSION_HEADER_CHARS: Int = 14

/**
 * The ONE allowlist step both actuals run on the platform-filtered relay
 * version header: the value (already the platform's own `ios-version` /
 * `android-version`) is kept only under [APP_VERSION_HEADER_KEY] and only when
 * it fits [MAX_APP_VERSION_HEADER_CHARS] — a hostile relay cannot park a large
 * string in [HttpResult.headers] on every response. Pure stdlib, so it lives
 * here rather than as two "keep in sync" copies (unit-tested once).
 */
internal fun appVersionHeaderMap(rawValue: String?): Map<String, String> =
    rawValue?.takeIf { it.length <= MAX_APP_VERSION_HEADER_CHARS }
        ?.let { mapOf(APP_VERSION_HEADER_KEY to it) }
        ?: emptyMap()

/**
 * The ONE per-request transport log line, identical on both platforms (fix 2a,
 * 2026-09-16): `GET /inbox/… → 200`.
 *
 * Before this, iOS wrote THREE lines per relay request — a `HttpClient` pre-flight
 * line, a `TorHttp` request-start line and a `TorHttp: ← code=NNN` response line —
 * plus the control-port tap's two stream lines, so >90 % of a debug-mode upload was
 * per-request plumbing and the 500-line / 64 KiB batch caps were being spent on it.
 * Android already wrote exactly this one line; iOS now writes the same one, and the
 * platforms can no longer drift because the text is built here.
 *
 * NO SOCKS PORT. The `(socks:58450)` / `socksPort=58450` suffix both platforms used
 * to carry is a per-PROCESS constant with no diagnostic value — the same number on
 * every line of a session, and one more thing the redactor would have to think about.
 *
 * [path] is the host-free request path: never the URL, so no onion
 * host prefix reaches [LogBuffer] or a bug report.
 */
internal fun httpLogLine(method: String, path: String, code: Int): String = "$method $path → $code"

/**
 * The DNS-leak transport guard, shared by both actuals. The
 * DIRECT path (OkHttp-no-proxy / NSURLSession) resolves DNS locally, so it must
 * refuse `.onion` (a direct .onion lookup leaks the relay to the DNS
 * resolver); the SOCKS5h path must refuse non-`.onion` (misroute). Returns a
 * refusal [HttpResult] when the url/transport pairing is wrong, else null.
 */
internal fun onionTransportGuard(url: String, viaSocks: Boolean): HttpResult? {
    if (!viaSocks && hostIsOnion(url)) {
        platformLogError("HttpClient", "BLOCKED .onion on direct path (would leak DNS)")
        return HttpResult(-1, "refused: .onion via direct HTTP", false)
    }
    if (viaSocks && !hostIsOnion(url)) {
        platformLogError("HttpClient", "BLOCKED non-onion on SOCKS path (misroute)")
        return HttpResult(-1, "refused: non-onion via SOCKS", false)
    }
    return null
}

/**
 * Default per-request transport budget (seconds) for relay HTTP — used by
 * message send/poll/rotation. The inbox MINT overrides it with a shorter value
 * (see [MessageManager.MINT_HTTP_TIMEOUT_SECONDS]): a mint round-trip is tiny,
 * so a mint that hasn't answered in far less than this is on a cold/half-open
 * Tor circuit and is better cancelled + retried (letting Tor attach the next
 * attempt's fresh stream to a different circuit) than left to block the full
 * budget. iOS already treats this as an overall cancel deadline (SwiftTorHttp);
 * Android applies it as OkHttp's per-call callTimeout.
 */
const val DEFAULT_RELAY_HTTP_TIMEOUT_SECONDS: Int = 60

/**
 * The slim relay-HTTP surface MessageManager talks to. PlatformHttpClient
 * implements it implicitly via [asRelayHttp]; tests inject a fake. Keeping
 * this as a commonMain interface lets commonTest exercise MessageManager
 * without needing access to the expect class's platform actuals.
 */
interface RelayHttp {
    fun post(url: String, body: ByteArray, contentType: String, headers: Map<String, String> = emptyMap(), timeoutSeconds: Int = DEFAULT_RELAY_HTTP_TIMEOUT_SECONDS): HttpResult

    /**
     * [post] with the transport's own PER-REQUEST LOG OPT-OUT. `suppressLog =
     * true` means: write no `POST <path> → <code>` line (and no transport-error
     * line) for THIS request — neither to [LogBuffer] nor to any platform sink.
     *
     * ONE caller: [DebugLogUploader.postBatch]. Without it the uploader's own
     * POST is logged, that log line is new since the cursor, so the next tick
     * ships it — which logs another line. An idle app uploaded at 1 Hz forever
     * (seen live on the dev relay: 21 batches in 31 s of an idle session). This
     * kills the loop AT THE SOURCE, which is why no text-matching filter is
     * needed downstream: nothing is written, so nothing has to be recognised
     * and dropped later.
     *
     * A DEFAULTED member (like [delete], unlike post/put/get) so the many
     * existing RelayHttp test doubles need no new override. The default simply
     * forwards to [post] and logs — for a fake that is harmless, and for a real
     * transport the overriding actual is what matters.
     */
    fun post(
        url: String,
        body: ByteArray,
        contentType: String,
        headers: Map<String, String>,
        timeoutSeconds: Int,
        suppressLog: Boolean,
    ): HttpResult = post(url, body, contentType, headers, timeoutSeconds)
    fun put(url: String, body: ByteArray, contentType: String, headers: Map<String, String> = emptyMap(), timeoutSeconds: Int = DEFAULT_RELAY_HTTP_TIMEOUT_SECONDS): HttpResult
    fun get(url: String, headers: Map<String, String> = emptyMap(), timeoutSeconds: Int = DEFAULT_RELAY_HTTP_TIMEOUT_SECONDS): HttpResult
    // DELETE /inbox/{id}/push (push opt-out / vault wipe).
    // Defaulted (unlike post/put/get) so the many existing RelayHttp test
    // doubles that predate Phase-3 push don't all need a stub override —
    // this fails closed (isSuccess=false) exactly like a real transport
    // error would, so a fake that doesn't override it can't be mistaken for
    // a successful unregister.
    fun delete(url: String, headers: Map<String, String> = emptyMap(), timeoutSeconds: Int = DEFAULT_RELAY_HTTP_TIMEOUT_SECONDS): HttpResult =
        HttpResult(code = -1, body = "delete not implemented by this RelayHttp", isSuccess = false)

    // -----------------------------------------------------------------------
    // NEWNYM ABORT (2026-10-08). A request opted in with `cancelOnNewCircuit =
    // true` is one the transport may abort the moment the app has fired a
    // `SIGNAL NEWNYM` ([cancelNewCircuitSensitive]): its stream rides a circuit
    // Tor has just retired, and the fresh circuits answer in ~2–3 s (field
    // 2026-10-08, the warm-up's GET answered 2.5 s after a NEWNYM while the
    // health probe sat out its full 20 s). Only READ-ONLY, idempotent requests
    // opt in — the health probe `GET /` and the unread prime's batch `POST
    // /peek`; never a send, a mint, a cap rotation or a push registration.
    //
    // DEFAULTED (like [delete] and the suppressLog overload) so every existing
    // test double compiles unchanged: a fake that does not override them simply
    // never aborts, and MessageManager's epoch check then ignores the stale
    // result instead (the soft half of the same behaviour).
    // -----------------------------------------------------------------------

    /** [get] that [cancelNewCircuitSensitive] may abort. */
    fun get(url: String, headers: Map<String, String>, timeoutSeconds: Int, cancelOnNewCircuit: Boolean): HttpResult =
        get(url, headers, timeoutSeconds)

    /**
     * [get] with a FIRST-BYTE budget (C3, 2026-10-09): once the stream has
     * connected through Tor, a response byte must arrive within
     * [firstByteTimeoutSeconds] (> 0) or the request is abandoned and returned
     * with [HttpResult.firstByteTimeout] = true. 0 = no such budget. Only the
     * COLD health probe passes one (device-run iOS cycle 8: stream connected in
     * 0.35 s, then no answer for the whole 20 s budget). DEFAULTED like the
     * other abort forms, so a test double that does not override it simply
     * ignores the budget.
     */
    fun get(url: String, headers: Map<String, String>, timeoutSeconds: Int, cancelOnNewCircuit: Boolean, firstByteTimeoutSeconds: Int): HttpResult =
        get(url, headers, timeoutSeconds, cancelOnNewCircuit)

    /** [post] that [cancelNewCircuitSensitive] may abort. */
    fun post(
        url: String,
        body: ByteArray,
        contentType: String,
        headers: Map<String, String>,
        timeoutSeconds: Int,
        suppressLog: Boolean,
        cancelOnNewCircuit: Boolean,
    ): HttpResult = post(url, body, contentType, headers, timeoutSeconds, suppressLog)

    /**
     * Aborts every in-flight request that opted in with `cancelOnNewCircuit`.
     * Non-blocking; an aborted request returns a transport failure (`code = -1`)
     * to its caller promptly. Returns how many were aborted (0 if the transport
     * cannot abort — then only the caller-side epoch check applies).
     */
    fun cancelNewCircuitSensitive(): Int = 0

    // -----------------------------------------------------------------------
    // SOCKS ISOLATION (2026-10-25, [RendezvousHedge]). DEFAULTED like the abort
    // forms: a test double (or the direct / external-proxy transports) cannot
    // isolate, says so, and the five-argument get below then ignores the
    // credential — which is why MessageManager never fires a hedge unless
    // [supportsSocksIsolation] is true.
    // -----------------------------------------------------------------------

    /** True only for a transport through the EMBEDDED Tor's SOCKS port, which can
     *  send a SOCKS5 username/password per request ([SocksIsolation]). */
    val supportsSocksIsolation: Boolean get() = false

    /**
     * [get] (five-argument form) whose stream goes into the SOCKS isolation class
     * of [socksIsolation] (a [SocksIsolation.newCredential] value; NEVER logged)
     * instead of the session's. Only the rendezvous hedge passes one.
     */
    fun get(
        url: String,
        headers: Map<String, String>,
        timeoutSeconds: Int,
        cancelOnNewCircuit: Boolean,
        firstByteTimeoutSeconds: Int,
        socksIsolation: String,
    ): HttpResult = get(url, headers, timeoutSeconds, cancelOnNewCircuit, firstByteTimeoutSeconds)
}

/** Adapts a [PlatformHttpClient] (an expect/actual class) to [RelayHttp]. */
fun PlatformHttpClient.asRelayHttp(): RelayHttp {
    val self = this
    return object : RelayHttp {
        override fun post(url: String, body: ByteArray, contentType: String, headers: Map<String, String>, timeoutSeconds: Int): HttpResult =
            self.post(url, body, contentType, headers, timeoutSeconds)
        override fun post(url: String, body: ByteArray, contentType: String, headers: Map<String, String>, timeoutSeconds: Int, suppressLog: Boolean): HttpResult =
            self.post(url, body, contentType, headers, timeoutSeconds, suppressLog)
        override fun put(url: String, body: ByteArray, contentType: String, headers: Map<String, String>, timeoutSeconds: Int): HttpResult =
            self.put(url, body, contentType, headers, timeoutSeconds)
        override fun get(url: String, headers: Map<String, String>, timeoutSeconds: Int): HttpResult =
            self.get(url, headers, timeoutSeconds)
        override fun delete(url: String, headers: Map<String, String>, timeoutSeconds: Int): HttpResult =
            self.delete(url, headers, timeoutSeconds)
        override fun get(url: String, headers: Map<String, String>, timeoutSeconds: Int, cancelOnNewCircuit: Boolean): HttpResult =
            self.get(url, headers, timeoutSeconds, cancelOnNewCircuit)
        override fun get(url: String, headers: Map<String, String>, timeoutSeconds: Int, cancelOnNewCircuit: Boolean, firstByteTimeoutSeconds: Int): HttpResult =
            self.get(url, headers, timeoutSeconds, cancelOnNewCircuit, firstByteTimeoutSeconds)
        override fun post(url: String, body: ByteArray, contentType: String, headers: Map<String, String>, timeoutSeconds: Int, suppressLog: Boolean, cancelOnNewCircuit: Boolean): HttpResult =
            self.post(url, body, contentType, headers, timeoutSeconds, suppressLog, cancelOnNewCircuit)
        override fun cancelNewCircuitSensitive(): Int = self.cancelNewCircuitSensitive()
        override val supportsSocksIsolation: Boolean get() = self.supportsSocksIsolation
        override fun get(url: String, headers: Map<String, String>, timeoutSeconds: Int, cancelOnNewCircuit: Boolean, firstByteTimeoutSeconds: Int, socksIsolation: String): HttpResult =
            self.getIsolated(url, headers, timeoutSeconds, cancelOnNewCircuit, firstByteTimeoutSeconds, socksIsolation)
    }
}

expect class PlatformHttpClient {
    // [suppressLog]: see RelayHttp.post's six-argument overload — the
    // per-request log opt-out the debug-log uploader uses so its own POST does
    // not become the next batch. Both actuals must honour it by writing NO log
    // line for the request. Since fix 2a that is ONE line on both platforms —
    // [httpLogLine]'s `$method $path → $code` — plus, on iOS, SwiftTorHttp's
    // remaining transport-level lines, which the HttpBridge `suppressLog` flag
    // already gates.
    //
    // [cancelOnNewCircuit]: see RelayHttp's NEWNYM ABORT block — the request is
    // registered so [cancelNewCircuitSensitive] can abort it (Android: OkHttp
    // `Call.cancel()`; iOS: SwiftTorHttp cancels the NWConnection).
    fun post(url: String, body: ByteArray, contentType: String, headers: Map<String, String> = emptyMap(), timeoutSeconds: Int = DEFAULT_RELAY_HTTP_TIMEOUT_SECONDS, suppressLog: Boolean = false, cancelOnNewCircuit: Boolean = false): HttpResult
    fun put(url: String, body: ByteArray, contentType: String, headers: Map<String, String> = emptyMap(), timeoutSeconds: Int = DEFAULT_RELAY_HTTP_TIMEOUT_SECONDS): HttpResult
    // [firstByteTimeoutSeconds]: see RelayHttp's five-argument get (C3). 0 = none.
    fun get(url: String, headers: Map<String, String> = emptyMap(), timeoutSeconds: Int = DEFAULT_RELAY_HTTP_TIMEOUT_SECONDS, cancelOnNewCircuit: Boolean = false, firstByteTimeoutSeconds: Int = 0): HttpResult
    fun delete(url: String, headers: Map<String, String> = emptyMap(), timeoutSeconds: Int = DEFAULT_RELAY_HTTP_TIMEOUT_SECONDS): HttpResult
    /** Aborts every in-flight request registered with `cancelOnNewCircuit`; returns how many. */
    fun cancelNewCircuitSensitive(): Int

    // SOCKS ISOLATION ([RendezvousHedge], [SocksIsolation]): true only for the
    // embedded-Tor SOCKS client (Android `torProxy`, iOS `PlatformHttpClient(socksPort)`
    // outside external-proxy mode). Such a client sends every request under the
    // process's [SocksIsolation.current] class (null = no SOCKS auth, today's
    // handshake); [getIsolated] overrides that class for ONE request.
    val supportsSocksIsolation: Boolean
    // A non-isolating client ignores [socksIsolation] and behaves like [get].
    fun getIsolated(url: String, headers: Map<String, String>, timeoutSeconds: Int, cancelOnNewCircuit: Boolean, firstByteTimeoutSeconds: Int, socksIsolation: String): HttpResult
}

/**
 * True if [url]'s authority host is a `.onion` address. Host-level — it
 * parses scheme://[user@]host[:port]/… and tests the host, NOT a loose
 * `url.contains(".onion")`, so a path/query containing ".onion" cannot
 * fool it. Used by both transports as a DNS-leak guard: the direct
 * (NSURLSession/OkHttp-no-proxy) path resolves DNS locally and must refuse
 * `.onion`; the SOCKS5h path must refuse non-`.onion` (misroute). The
 * transport decision normally derives from the same URL via
 * [RelayConfig.isTorRequired], so this is belt-and-braces enforcement at
 * the layer that actually performs (or tunnels) resolution.
 */
internal fun hostIsOnion(url: String): Boolean {
    // Parse the authority host robustly:
    //  • scheme-less inputs ("host:port/…") are still parsed — previously they
    //    yielded an empty authority, mis-classifying a .onion as non-onion and
    //    disabling both the Tor requirement and the direct-path guard;
    //  • strip path/query/fragment, userinfo and port;
    //  • trim a trailing FQDN dot ("abc.onion." is the same host as "abc.onion"
    //    but used to bypass endsWith(".onion") onto the direct path).
    val afterScheme = if (url.contains("://")) url.substringAfter("://") else url
    val authority = afterScheme
        .substringBefore("/").substringBefore("?").substringBefore("#")
    val host = authority.substringAfterLast("@").substringBefore(":").trimEnd('.')
    return host.endsWith(".onion", ignoreCase = true)
}

@file:OptIn(kotlinx.cinterop.BetaInteropApi::class)

package com.vg.run

import platform.Foundation.*

// MAX_RESPONSE_BYTES is single-sourced in commonMain PlatformHttpClient.kt
// (SwiftTorHttp keeps its own Swift mirror, documented against that value).

// The ROUTE SHAPE of a request for a log line — never the onion host and never
// the rest of the path (`/inbox/<id>` carries the full inbox id, and LogBuffer
// lines reach the Debug-mode upload): the first path segment only, query
// dropped. Android twin: `httpLogRoute` in PlatformHttpClient.android.kt.
private fun logPath(url: String): String {
    val afterScheme = url.substringAfter("://", url)
    val slash = afterScheme.indexOf('/')
    if (slash < 0) return "/"
    val first = afterScheme.substring(slash).substringBefore('?').trimStart('/').substringBefore('/')
    return when {
        first.isEmpty() -> "/"
        first.length <= 16 && first.all { it in 'a'..'z' || it == '-' } -> "/$first"
        else -> "/[path]"
    }
}

// One Swift transport result as the shared [HttpResult] (the four bridge verbs).
// [firstByteTimeout] is the caller's decision (GET only).
private fun HttpBridgeResult.toHttpResult(firstByteTimeout: Boolean = false): HttpResult =
    HttpResult(code, body, isSuccess, headers = appVersionHeaderMap(appVersionHeader), firstByteTimeout = firstByteTimeout)

// ---------------------------------------------------------------------------
// PlatformHttpClient — iOS actual implementation.
//
// Two modes:
//   1. Direct HTTP (no proxy) — NSURLSession, used when Tor is not required.
//   2. SOCKS5 proxy — delegates to HttpBridge (NWConnection-based Swift
//      implementation) which properly tunnels DNS through the SOCKS5 proxy.
//      NSURLSession's SOCKS5 support does NOT tunnel DNS, so .onion
//      addresses fail with NSURLErrorBadURL. The HttpBridge uses
//      Network.framework's NWConnection which handles SOCKS5h (remote DNS).
//
// Every verb blocks the calling thread (called from KMP background threads).
// ---------------------------------------------------------------------------

actual class PlatformHttpClient {

    private val session: NSURLSession?
    private val socksPort: Int

    /**
     * SOCKS ISOLATION ([RendezvousHedge], [SocksIsolation]): true only for the
     * EMBEDDED Tor's client — never the direct session, never external-proxy mode
     * (IosAppController passes `!externalProxyMode`; SwiftTorHttp additionally
     * ignores any credential while the process is in external mode).
     */
    private val isolationCapable: Boolean

    actual val supportsSocksIsolation: Boolean get() = isolationCapable

    /** The SOCKS5 username for a request: [explicit] (a hedge), else the
     *  process's adopted class, else "" (no auth — today's handshake). NEVER log. */
    private fun socksAuthFor(explicit: String? = null): String {
        if (!isolationCapable) return ""
        val c = explicit ?: SocksIsolation.current() ?: return ""
        return if (SocksIsolation.isValidCredential(c)) c else ""
    }

    /** Creates a direct (no-proxy) HTTP client. */
    constructor() {
        val config = NSURLSessionConfiguration.ephemeralSessionConfiguration
        config.setURLCache(null)
        // Known limitation: NSURLSession auto-follows
        // server redirects (Android's OkHttp disables this). Suppressing them
        // needs a session delegate. This DIRECT path is reached only on the
        // dev/simulator clearnet override — a RELEASE build refuses a clearnet
        // relay (RunViewModel / AppState) and production traffic uses the
        // SOCKS5h NWConnection path (HttpBridge), which does not follow
        // redirects — so the production risk is nil.
        session = NSURLSession.sessionWithConfiguration(
            configuration = config,
            delegate = null,
            delegateQueue = NSOperationQueue()
        )
        socksPort = 0
        isolationCapable = false
    }

    /**
     * Creates an HTTP client that routes all traffic through a local
     * SOCKS5 proxy (Tor). Delegates to HttpBridge for NWConnection-based
     * transport with proper remote DNS support.
     */
    constructor(socksPort: Int) : this(socksPort, socksIsolationCapable = true)

    /** [socksIsolationCapable] = false for the external-proxy transport. */
    constructor(socksPort: Int, socksIsolationCapable: Boolean) {
        session = null
        this.socksPort = socksPort
        this.isolationCapable = socksIsolationCapable
    }

    /**
     * DNS-leak guard. The direct path (NSURLSession) resolves
     * DNS locally, so it must never carry a `.onion` request; the SOCKS5h
     * path must only carry `.onion`. Returns a refusal HttpResult if the
     * url/transport pairing is wrong, else null.
     */
    // Delegates to the shared commonMain guard. session != null ⇒ direct
    // (NSURLSession) path; otherwise the SOCKS5h NWConnection path.
    /**
     * The registered Swift transport. Hard-fails, matching the crypto/Keychain
     * bridge holders (which use `?: error(...)`), rather than silently returning a
     * -1 "transport error". A null bridge here is an INIT-ORDER violation —
     * `AppState.registerBridges()` must register every *BridgeHolder before
     * `IosAppController()` is constructed — never a runtime network failure.
     * Degrading it to a generic transport result let a misregistration masquerade
     * as "the relay is unreachable", hiding a serious bug; failing loud surfaces
     * it. The invariant holds in correct code, so this never throws in practice.
     */
    private fun requireBridge(): HttpBridge = HttpBridgeHolder.bridge
        ?: error("HttpBridge not registered — register all bridge holders before IosAppController()")

    private fun transportGuard(url: String): HttpResult? =
        onionTransportGuard(url, viaSocks = session == null)

    /**
     * The ONE log line this transport writes per request (fix 2a) — same text on
     * both platforms via commonMain's [httpLogLine], written AFTER the call so it
     * carries the status, and never the SOCKS port (a per-process constant).
     * WARN only on a TRANSPORT failure (code <= 0); a 4xx/5xx is a valid answer
     * and the caller decides whether it is a problem. [suppress] is the
     * uploader's per-request opt-out.
     */
    private fun logHttp(method: String, url: String, r: HttpResult, suppress: Boolean = false) {
        if (suppress) return
        // The status code only — never the relay's (or SwiftTorHttp's) body text.
        val line = httpLogLine(method, logPath(url), r.code)
        if (r.code <= 0) platformLogWarn("HttpClient", line) else platformLog("HttpClient", line)
    }

    // [suppressLog]: the per-request log opt-out (see RelayHttp.post's
    // six-argument overload and HttpBridge.post's own flag). It gates this
    // request's WHOLE footprint — the one [logHttp] line written here and every
    // `TorHttp:` line SwiftTorHttp writes on the bridge side — because
    // DebugLogUploader's own POST must leave nothing behind for the next tick
    // to ship (a 1 Hz self-feeding loop otherwise).
    //
    // FIX 2a (2026-09-16): ONE line per request, written AFTER the call and
    // carrying the status, exactly as the Android actual has always done (the
    // text is single-sourced in commonMain's [httpLogLine]). The old pre-flight
    // `POST /path (socks:58450, 123b)` line and SwiftTorHttp's two per-request
    // lines are gone: a per-process constant SOCKS port carries no diagnostic
    // value, and three lines per request were >90 % of a debug-mode upload.
    // The stuck-request diagnosis they were worth is preserved where it belongs
    // — ConnectionLog's stream pairing always ships a slow or failed stream
    // together with its start line (fix 2b).
    actual fun post(
        url: String,
        body: ByteArray,
        contentType: String,
        headers: Map<String, String>,
        timeoutSeconds: Int,
        suppressLog: Boolean,
        cancelOnNewCircuit: Boolean,
    ): HttpResult {
        transportGuard(url)?.let { return it }
        if (session != null) {
            val r = executeUrlSession(buildRequest(url, "POST", body, contentType, headers, timeoutSeconds.toDouble()))
            logHttp("POST", url, r, suppressLog)
            return r
        }
        val bridge = requireBridge()
        val result = bridge.post(url, body.toNSData(), contentType, headers, SocksPortRedirect.resolve(socksPort), timeoutSeconds, suppressLog = suppressLog, cancelOnNewCircuit = cancelOnNewCircuit, socksAuth = socksAuthFor())
        val out = result.toHttpResult()
        logHttp("POST", url, out, suppressLog)
        return out
    }

    actual fun put(
        url: String,
        body: ByteArray,
        contentType: String,
        headers: Map<String, String>,
        timeoutSeconds: Int
    ): HttpResult {
        transportGuard(url)?.let { return it }
        if (session != null) {
            // Thread the caller's timeout (was always the 60s default).
            val r = executeUrlSession(buildRequest(url, "PUT", body, contentType, headers, timeoutSeconds.toDouble()))
            logHttp("PUT", url, r)
            return r
        }
        val bridge = requireBridge()
        val result = bridge.put(url, body.toNSData(), contentType, headers, SocksPortRedirect.resolve(socksPort), timeoutSeconds, suppressLog = false, socksAuth = socksAuthFor())
        val out = result.toHttpResult()
        logHttp("PUT", url, out)
        return out
    }

    actual fun get(url: String, headers: Map<String, String>, timeoutSeconds: Int, cancelOnNewCircuit: Boolean, firstByteTimeoutSeconds: Int): HttpResult =
        getWith(url, headers, timeoutSeconds, cancelOnNewCircuit, firstByteTimeoutSeconds, null)

    // The rendezvous hedge's GET: this ONE request under [socksIsolation]'s class.
    actual fun getIsolated(url: String, headers: Map<String, String>, timeoutSeconds: Int, cancelOnNewCircuit: Boolean, firstByteTimeoutSeconds: Int, socksIsolation: String): HttpResult =
        getWith(url, headers, timeoutSeconds, cancelOnNewCircuit, firstByteTimeoutSeconds, socksIsolation)

    private fun getWith(url: String, headers: Map<String, String>, timeoutSeconds: Int, cancelOnNewCircuit: Boolean, firstByteTimeoutSeconds: Int, isolationOverride: String?): HttpResult {
        transportGuard(url)?.let { return it }
        if (session != null) {
            val r = executeUrlSession(buildRequest(url, "GET", null, null, headers, timeoutSeconds.toDouble()))
            logHttp("GET", url, r)
            return r
        }
        val bridge = requireBridge()
        // Honor the caller's timeout on the SOCKS/bridge path too (was
        // hardcoded 60). Over Tor every GET takes this path, so a hardcoded 60
        // silently defeated the shorter warm-probe budget the caller passes.
        // [firstByteTimeoutSeconds] > 0 arms SwiftTorHttp's first-byte timer
        // once the SOCKS5 CONNECT has succeeded (RelayHttp's five-argument get).
        val result = bridge.get(url, headers, SocksPortRedirect.resolve(socksPort), timeoutSeconds, suppressLog = false, cancelOnNewCircuit = cancelOnNewCircuit, firstByteTimeoutSeconds = firstByteTimeoutSeconds, socksAuth = socksAuthFor(isolationOverride))
        val out = result.toHttpResult(firstByteTimeout = firstByteTimeoutSeconds > 0 && result.firstByteTimeout)
        logHttp("GET", url, out)
        return out
    }

    // docs/RELAY_SPEC.md (push): DELETE /inbox/{id}/push (push opt-out / vault wipe).
    actual fun delete(url: String, headers: Map<String, String>, timeoutSeconds: Int): HttpResult {
        transportGuard(url)?.let { return it }
        if (session != null) {
            val r = executeUrlSession(buildRequest(url, "DELETE", null, null, headers, timeoutSeconds.toDouble()))
            logHttp("DELETE", url, r)
            return r
        }
        val bridge = requireBridge()
        val result = bridge.delete(url, headers, SocksPortRedirect.resolve(socksPort), timeoutSeconds, suppressLog = false, socksAuth = socksAuthFor())
        val out = result.toHttpResult()
        logHttp("DELETE", url, out)
        return out
    }

    /**
     * NEWNYM ABORT (RelayHttp): the SOCKS/NWConnection path cancels its
     * registered connections in SwiftTorHttp. The direct NSURLSession path
     * (simulator / debug clearnet only — no Tor, so no NEWNYM ever fires) has
     * nothing to abort and reports 0.
     */
    actual fun cancelNewCircuitSensitive(): Int {
        if (session != null) return 0
        return HttpBridgeHolder.bridge?.cancelNewCircuitSensitive() ?: 0
    }

    // -----------------------------------------------------------------------
    // NSURLSession path (direct HTTP, no proxy)
    // -----------------------------------------------------------------------

    private fun buildRequest(
        url: String,
        method: String,
        body: ByteArray?,
        contentType: String?,
        headers: Map<String, String>,
        timeoutSeconds: Double = 60.0,
    ): NSMutableURLRequest? {
        val urlObj = NSURL.URLWithString(url) ?: return null
        val request = NSMutableURLRequest.requestWithURL(urlObj) as NSMutableURLRequest
        request.setHTTPMethod(method)
        if (body != null) request.setHTTPBody(body.toNSData())
        if (contentType != null) request.setValue(contentType, forHTTPHeaderField = "Content-Type")
        headers.forEach { (k, v) ->
            // Defense-in-depth parity with the SOCKS/SwiftTorHttp path:
            // reject control chars in header keys/values so a relay-
            // controlled cap/token can never inject a header. NSURLSession
            // already rejects CRLF and caps are validated upstream — belt-and-
            // braces. A bad header fails the whole request closed (returns null).
            if (k.any { it.code < 0x20 || it.code == 0x7F } ||
                v.any { it.code < 0x20 || it.code == 0x7F }
            ) {
                return null
            }
            request.setValue(v, forHTTPHeaderField = k)
        }
        // Anti-fingerprinting parity with the Android/Tor paths:
        // NSURLSession otherwise adds a platform-revealing default
        // User-Agent (e.g. "Run/x CFNetwork/y Darwin/z") and Accept-Encoding.
        // Neutralize them so the relay can't fingerprint iOS on the direct path.
        request.setValue("", forHTTPHeaderField = "User-Agent")
        request.setValue("identity", forHTTPHeaderField = "Accept-Encoding")
        request.setTimeoutInterval(timeoutSeconds)
        return request
    }

    private fun executeUrlSession(request: NSMutableURLRequest?): HttpResult {
        if (request == null) return HttpResult(-1, "Invalid URL", false)
        val sess = session ?: return HttpResult(-1, "No session", false)
        var result = HttpResult(-1, null, false)
        val condition = NSCondition()
        var done = false

        condition.lock()

        sess.dataTaskWithRequest(request) { data, response, error ->
            val http = response as? NSHTTPURLResponse
            val code = http?.statusCode?.toInt() ?: -1
            val body = data?.let {
                // #15: the SOCKS/Tor path (SwiftTorHttp) enforces a hard read
                // cap during accumulation; this direct path is dev/non-Tor only
                // and NSURLSession has already buffered `data`, so this is a
                // parse-stage guard that rejects an over-cap body rather than
                // feeding a giant string downstream.
                if (it.length.toLong() > MAX_RESPONSE_BYTES) "response too large"
                else NSString.create(it, NSUTF8StringEncoding)?.toString()
                    ?: error?.localizedDescription
            } ?: error?.localizedDescription
            // An over-cap body must fail closed (isSuccess=false),
            // for parity with the Android + SwiftTorHttp paths which return -1.
            // (This direct client is DEBUG+simulator-only — production uses the
            // SOCKS/HttpBridge path — so this is a parity nit, not a live risk.)
            val oversize = body == "response too large"
            // Update-nudge: this NSURLSession path is what the iOS
            // SIMULATOR takes (RelayConfig.ios.kt -> localhost -> direct, not
            // SOCKS5h) — without reading the header here the sim e2e can never
            // see it. valueForHTTPHeaderField is a case-insensitive lookup;
            // deliberately NOT allHeaderFields (never expose the full set).
            val versionHeader = http?.valueForHTTPHeaderField("ios-version")
            result = HttpResult(code = if (oversize) -1 else code, body = body,
                                isSuccess = !oversize && code in 200..299,
                                headers = appVersionHeaderMap(versionHeader))

            condition.lock()
            done = true
            condition.signal()
            condition.unlock()
        }.resume()

        while (!done) condition.wait()
        condition.unlock()

        return result
    }
}

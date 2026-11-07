package com.vg.run

import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.net.InetSocketAddress
import java.net.Proxy
import java.util.concurrent.TimeUnit

/**
 * Adds the APP-supplied [headers] (capability / PoW) in key-sorted order.
 * `toSortedMap()` uses natural String ordering (lexicographic over the ASCII
 * header names), matching the iOS transport's `headers.sorted { $0.key < $1.key }`,
 * so the app headers are emitted in the identical sequence on both platforms and
 * their ordering can't fingerprint the client.
 *
 * NOTE: this unifies only the app headers. The FULL on-wire request still
 * differs by HTTP stack — OkHttp positions Host/Content-Type/Content-Length on
 * its own, whereas the iOS hand-rolled request interleaves Content-* into the
 * sorted block and prepends Host/Connection — so platform is still distinguishable
 * from the overall header layout (and from Tor circuit timing). This reduces, not
 * eliminates, header-order fingerprinting.
 */
private fun Request.Builder.addSortedHeaders(headers: Map<String, String>): Request.Builder =
    apply { headers.toSortedMap().forEach { (k, v) -> addHeader(k, v) } }

// The ROUTE SHAPE of a request path for a log line: its first segment only
// (`/inbox/<id>/push` → `/inbox`, `/` → `/`). Every relay route starts with a
// fixed word, so this never carries an inbox id, a capability or a query; a
// first segment that is not a short lowercase word is logged as `/[path]`.
// iOS twin: `httpLogRoute` in PlatformHttpClient.ios.kt (one-liner; a shared
// commonMain home next to [httpLogLine] is a follow-up).
internal fun httpLogRoute(encodedPath: String): String {
    val first = encodedPath.trimStart('/').substringBefore('/')
    return when {
        first.isEmpty() -> "/"
        first.length <= 16 && first.all { it in 'a'..'z' || it == '-' } -> "/$first"
        else -> "/[path]"
    }
}

actual class PlatformHttpClient(
    // Default follows no redirects — see baseBuilder()/direct()/torProxy().
    private val client: OkHttpClient = OkHttpClient.Builder()
        .followRedirects(false).followSslRedirects(false).build(),
    // True for the Tor SOCKS client. Drives the DNS-leak guard in execute():
    // a direct (no-proxy) client resolves DNS locally so it must refuse
    // .onion; the SOCKS client must refuse non-.onion (misroute).
    private val viaSocks: Boolean = false,
    // External SOCKS proxy mode ([socksProxy]): the proxy address is the USER'S
    // (possibly a LAN IP), and OkHttp/JDK exception messages embed it
    // ("Failed to connect to /192.168.1.20:9050"). When true, a transport error
    // is logged and returned as the exception CLASS name only — never its
    // message — so the configured address can never reach LogBuffer, a bug
    // report or a Debug-mode upload.
    private val redactTransportErrors: Boolean = false,
    // SOCKS ISOLATION ([RendezvousHedge]): the EMBEDDED Tor's SOCKS port this
    // client was built for ([torProxy] only), or null. Non-null = requests may be
    // sent under a SOCKS5 username/password — the process's [SocksIsolation]
    // class, or a hedge's own credential — through [Socks5IsolatedSocket]. Never
    // set for the external proxy ([socksProxy]) or the direct client.
    private val isolationSocksPort: Int? = null,
) {

    actual val supportsSocksIsolation: Boolean get() = isolationSocksPort != null

    /**
     * In-flight calls opted in with `cancelOnNewCircuit` (RelayHttp's NEWNYM
     * ABORT block): [cancelNewCircuitSensitive] cancels exactly these. OkHttp's
     * `Call.cancel()` is thread-safe and makes the blocked `execute()` throw
     * `IOException("Canceled")` at once, which [execute]'s catch maps to the
     * usual `code = -1` transport failure. A call cancelled before it started
     * executing throws the same way, so the add-then-execute order is race-free.
     */
    private val newCircuitSensitiveCalls: MutableSet<okhttp3.Call> =
        java.util.concurrent.ConcurrentHashMap.newKeySet()

    actual fun cancelNewCircuitSensitive(): Int {
        var n = 0
        for (call in newCircuitSensitiveCalls.toList()) {
            if (!call.isCanceled()) { call.cancel(); n++ }
        }
        return n
    }

    actual fun post(url: String, body: ByteArray, contentType: String, headers: Map<String, String>, timeoutSeconds: Int, suppressLog: Boolean, cancelOnNewCircuit: Boolean): HttpResult {
        val builder = Request.Builder().url(url).post(body.toRequestBody(contentType.toMediaType()))
        // Add headers in a fixed (key-sorted) order so the on-wire header
        // sequence is deterministic and identical to the iOS transport (which
        // sorts the same map the same way) — header order is a client
        // fingerprint, so an unstable order would distinguish clients to the relay.
        builder.addSortedHeaders(headers)
        return execute(builder.build(), timeoutSeconds, suppressLog, cancelOnNewCircuit)
    }

    actual fun put(url: String, body: ByteArray, contentType: String, headers: Map<String, String>, timeoutSeconds: Int): HttpResult {
        val builder = Request.Builder().url(url).put(body.toRequestBody(contentType.toMediaType()))
        builder.addSortedHeaders(headers)
        // Honor the caller's timeout (parity with get/post) instead of
        // leaving only the per-phase timeouts as the bound.
        return execute(builder.build(), timeoutSeconds)
    }

    actual fun get(url: String, headers: Map<String, String>, timeoutSeconds: Int, cancelOnNewCircuit: Boolean, firstByteTimeoutSeconds: Int): HttpResult {
        val builder = Request.Builder().url(url).get()
        builder.addSortedHeaders(headers)
        return execute(builder.build(), timeoutSeconds, cancelOnNewCircuit = cancelOnNewCircuit, firstByteTimeoutSeconds = firstByteTimeoutSeconds)
    }

    // The rendezvous hedge's GET ([RendezvousHedge]): this ONE request under
    // [socksIsolation]'s class. A non-isolating client ignores it (plain [get]).
    actual fun getIsolated(url: String, headers: Map<String, String>, timeoutSeconds: Int, cancelOnNewCircuit: Boolean, firstByteTimeoutSeconds: Int, socksIsolation: String): HttpResult {
        val builder = Request.Builder().url(url).get()
        builder.addSortedHeaders(headers)
        val cred = socksIsolation.takeIf { isolationSocksPort != null && SocksIsolation.isValidCredential(it) }
        return execute(builder.build(), timeoutSeconds, cancelOnNewCircuit = cancelOnNewCircuit, firstByteTimeoutSeconds = firstByteTimeoutSeconds, isolationOverride = cred)
    }

    // LIVE on Android (comment previously claimed "never actually called on
    // this platform" — false since the notification tiers landed): Android
    // registers FCM and UnifiedPush, and PushRegistration.unregister issues
    // `DELETE /inbox/{id}/push` through here on the settings opt-out, the
    // enable-failure revert and the wipe (docs/RELAY_SPEC.md (push); over Tor these can
    // absorb the full call timeout, which is why the opt-out path retries and
    // persists a pending flag — PushRegistrationCoordinator.unregisterPushInBackground).
    // MessageManager's relay inbox purge (`DELETE /inbox/{id}`) rides this
    // verb too.
    actual fun delete(url: String, headers: Map<String, String>, timeoutSeconds: Int): HttpResult {
        val builder = Request.Builder().url(url).delete()
        builder.addSortedHeaders(headers)
        return execute(builder.build(), timeoutSeconds)
    }

    // [timeoutSeconds] > 0 sets an overall per-call cap (OkHttp callTimeout); 0
    // leaves the client's per-phase connect/read/write timeouts as the only
    // bound. All three verbs (post/get/put) thread a budget so the inbox mint
    // can abandon a cold Tor circuit early (MessageManager.MINT_HTTP_TIMEOUT_
    // SECONDS) instead of blocking the full DEFAULT_RELAY_HTTP_TIMEOUT_SECONDS —
    // parity with iOS, whose SwiftTorHttp already applies it as a cancel deadline.
    //
    // [suppressLog] = this request writes NO log line at all — not the success
    // line, not the oversize/transport-error lines. Only DebugLogUploader's own
    // POST passes it (see RelayHttp.post's six-argument overload): a line
    // written here would be new since the uploader's cursor, so the next tick
    // would ship it and log another one — a 1 Hz self-feeding loop. The error
    // lines are gated for the same reason (a FAILING upload would otherwise
    // feed itself just as reliably as a succeeding one). Mirror of the iOS
    // HttpBridge/SwiftTorHttp `suppressLog` flag.
    private fun execute(
        request: Request,
        timeoutSeconds: Int = 0,
        suppressLog: Boolean = false,
        cancelOnNewCircuit: Boolean = false,
        firstByteTimeoutSeconds: Int = 0,
        isolationOverride: String? = null,
    ): HttpResult {
        val method = request.method
        // Log only the ROUTE SHAPE ([httpLogRoute]: the first path segment), never
        // the host and never the rest of the path — `/inbox/<id>` carries the
        // full inbox id, and LogBuffer lines reach the Debug-mode upload.
        val path = httpLogRoute(request.url.encodedPath)

        // DNS-leak guard — shared with iOS via commonMain.
        // OkHttp resolves DNS locally on the direct path (refuse .onion there);
        // the SOCKS5h path defers resolution to the proxy (must only carry .onion).
        val url = request.url.toString()
        onionTransportGuard(url, viaSocks)?.let { return it }

        var sensitiveCall: okhttp3.Call? = null
        // C3 first-byte budget (RelayHttp's five-argument get): a per-call client
        // sharing this one's pool/dispatcher, whose READ timeout is the budget —
        // OkHttp arms it on the socket, so the wait for the first response byte
        // after the request was written is bounded by it. [connectStarted] tells a
        // stalled stream (the budget expiring once the socket to Tor's SOCKS port
        // exists) from anything else; the overall call timeout above still
        // bounds the whole request. Never applied when the budget is 0.
        val connectStarted = java.util.concurrent.atomic.AtomicBoolean(false)
        // SOCKS ISOLATION: the class this request goes into — the hedge's own
        // credential, else the process's adopted one, else none (null = the
        // unchanged java.net SOCKS route below, byte-for-byte today's handshake).
        // Read per request, like SocksPortRedirect, so an adoption re-classes every
        // existing torProxy client without a rebuild. NEVER logged.
        val isolation = isolationSocksPort?.let { port ->
            (isolationOverride ?: SocksIsolation.current())?.let { port to it }
        }
        // OPTIMISTIC DATA ([isOptimisticEligible]): only the embedded-Tor client,
        // only an un-isolated request (an isolated one keeps its own handshake
        // route), only the two read-only reveal-path requests.
        val optimistic = isolation == null && isolationSocksPort != null &&
            isOptimisticEligible(method, request.url.encodedPath)
        val baseClient = when {
            isolation != null -> isolatedClient(isolation.first, isolation.second)
            optimistic -> optimisticClient(0)
            else -> client
        }
        val firstByteListener = object : okhttp3.EventListener() {
            override fun connectStart(call: okhttp3.Call, inetSocketAddress: InetSocketAddress, proxy: Proxy) {
                connectStarted.set(true)
            }
        }
        val callClient = if (firstByteTimeoutSeconds > 0 && optimistic) {
            // The optimistic socket reads the CONNECT reply INSIDE the first
            // response read, where OkHttp's read timeout (okio's watchdog included)
            // would cover Tor's descriptor/intro/rendezvous phase too. So the
            // budget does NOT go into OkHttp's read timeout here: the socket arms
            // it itself once the reply is consumed (see [Socks5OptimisticSocket]).
            optimisticClient(firstByteTimeoutSeconds * 1000)
                .newBuilder()
                .eventListener(firstByteListener)
                .build()
        } else if (firstByteTimeoutSeconds > 0) {
            baseClient.newBuilder()
                .readTimeout(firstByteTimeoutSeconds.toLong(), TimeUnit.SECONDS)
                .eventListener(firstByteListener)
                .build()
        } else baseClient
        return try {
            val call = callClient.newCall(request)
            if (timeoutSeconds > 0) call.timeout().timeout(timeoutSeconds.toLong(), TimeUnit.SECONDS)
            if (cancelOnNewCircuit) { sensitiveCall = call; newCircuitSensitiveCalls.add(call) }
            call.execute().use { response ->
                // Bound the body AND FAIL CLOSED on
                // oversize — never parse a TRUNCATED prefix. iOS rejects responses
                // over its cap, so Android must too; otherwise a hostile relay
                // could get Android to accept a truncation iOS refuses (platform
                // inconsistency). A declared Content-Length past the cap is
                // rejected outright; for chunked/unknown length we peek ONE byte
                // past the cap and reject if the body actually exceeds it. Memory
                // stays bounded either way (16 MiB is far above any legitimate
                // inbox drain — a max message blob is ~175 KB base64).
                // OkHttp 5 made Response.body non-null (it was `ResponseBody?`
                // in 4.x), so the old `?.contentLength() ?: -1L` is now a
                // redundant safe call. Behaviour is unchanged: OkHttp still
                // reports -1 for an absent/unknown Content-Length, which is the
                // value the old elvis produced for a null body.
                val declared = response.body.contentLength()
                if (declared > MAX_RESPONSE_BYTES) {
                    if (!suppressLog) platformLogError("HttpClient", "$method $path response too large (declared ${declared}B > cap) — rejected")
                    return@use HttpResult(-1, "response exceeds size cap", false)
                }
                val raw = response.peekBody(MAX_RESPONSE_BYTES + 1).bytes()
                if (raw.size > MAX_RESPONSE_BYTES) {
                    if (!suppressLog) platformLogError("HttpClient", "$method $path response exceeds ${MAX_RESPONSE_BYTES}B cap — rejected (fail closed)")
                    return@use HttpResult(-1, "response exceeds size cap", false)
                }
                // Update-nudge: OkHttp's Response.header(name) is a
                // single-value, case-insensitive, LAST-WINS lookup — never
                // headers.values()/toMultimap(), which would expose every
                // relay header (and any duplicates) instead of the one
                // allowlisted key. Cap-check + map-building lives in the
                // extracted pure appVersionHeaderMap() below (unit-tested).
                val result = HttpResult(
                    code = response.code,
                    body = raw.decodeToString(),
                    isSuccess = response.isSuccessful,
                    headers = appVersionHeaderMap(response.header("android-version"))
                )
                // WARN only on transport failure (code <= 0, which only
                // happens in the catch below). A 4xx/5xx is a valid server
                // response — the caller decides whether it's a problem.
                // The relay's GET / returns 404 by design (no root handler),
                // and probing it for reachability was producing noise.
                // ONE line per request, shape single-sourced in commonMain
                // (httpLogLine) so iOS cannot drift from it — fix 2a.
                // The status code only — never the relay's body text.
                if (!suppressLog) platformLog("HttpClient", httpLogLine(method, path, result.code))
                result
            }
        } catch (e: Exception) {
            // The isolated route's exception messages can name the onion (OkHttp's
            // "Failed to connect to <host>/…" on a DIRECT route): class name only.
            // Same for the optimistic route (also NO_PROXY + OnionLoopbackDns).
            val redact = redactTransportErrors || isolation != null || optimistic
            // The LOG line is the class name on every route (the message can carry
            // a host or a path); [redact] still decides the returned body below.
            if (!suppressLog) platformLogError("HttpClient", "$method $path failed: ${e.javaClass.simpleName}")
            // A socket READ timeout (SocketTimeoutException — the call timeout and a
            // NEWNYM cancel throw plain InterruptedIOException / IOException instead)
            // on a request that had reached Tor's SOCKS port = the stream stalled.
            val firstByte = firstByteTimeoutSeconds > 0 &&
                connectStarted.get() &&
                e is java.net.SocketTimeoutException
            HttpResult(
                code = -1,
                body = if (redact) e.javaClass.simpleName else e.message,
                isSuccess = false,
                firstByteTimeout = firstByte,
            )
        } finally {
            sensitiveCall?.let { newCircuitSensitiveCalls.remove(it) }
        }
    }

    /**
     * The per-request client for SOCKS isolation class [username] through the
     * embedded Tor at [socksPort] (resolved through [SocksPortRedirect] at each
     * connection, like the default route). Same pool/dispatcher/timeouts/
     * interceptors as [client]; only the route differs:
     *  - `Proxy.NO_PROXY` + [OnionLoopbackDns] + [Socks5IsolatedSocketFactory]:
     *    java.net's SOCKS client can only take credentials from the process-global
     *    `java.net.Authenticator` (no per-request credential, global state), so the
     *    SOCKS5 + RFC 1929 handshake is done by [Socks5IsolatedSocket] itself;
     *  - the onion still reaches Tor UNRESOLVED (ATYP DOMAINNAME): the DNS stub
     *    never resolves anything — it refuses every non-onion name and maps an
     *    onion to a loopback placeholder that CARRIES the name, which the socket
     *    reads back (`InetSocketAddress.getHostString`, no lookup) and hands to Tor.
     */
    private fun isolatedClient(socksPort: Int, username: String): OkHttpClient =
        client.newBuilder()
            .proxy(Proxy.NO_PROXY)
            .dns(OnionLoopbackDns)
            .socketFactory(Socks5IsolatedSocketFactory(socksPort, username, SocksIsolation.PASSWORD))
            .build()

    /** The no-budget optimistic client, built once (the socket factory is
     *  stateless; the SOCKS port is still resolved at every connect). */
    private val optimisticDefault: OkHttpClient by lazy { buildOptimisticClient(0) }

    /**
     * The OPTIMISTIC-DATA client ([isOptimisticEligible]) for the embedded Tor at
     * [isolationSocksPort]: same pool/dispatcher/protocols/timeouts/interceptors as
     * [client] (so the same no-redirect, no-UA base), only the route differs —
     * `Proxy.NO_PROXY` + [OnionLoopbackDns] (the onion is never resolved locally,
     * exactly as on the isolated route) + [Socks5OptimisticSocketFactory], whose
     * socket returns from `connect()` right after WRITING the CONNECT, so OkHttp's
     * request bytes follow it before Tor's reply. [firstByteBudgetMs] > 0 = the C3
     * budget, armed by the socket after the reply (never by OkHttp — see execute).
     * Only called when [isolationSocksPort] is non-null.
     */
    private fun optimisticClient(firstByteBudgetMs: Int): OkHttpClient =
        if (firstByteBudgetMs <= 0) optimisticDefault else buildOptimisticClient(firstByteBudgetMs)

    private fun buildOptimisticClient(firstByteBudgetMs: Int): OkHttpClient =
        client.newBuilder()
            .proxy(Proxy.NO_PROXY)
            .dns(OnionLoopbackDns)
            .socketFactory(Socks5OptimisticSocketFactory(requireNotNull(isolationSocksPort), firstByteBudgetMs))
            .build()

    companion object {
        // MAX_RESPONSE_BYTES is single-sourced in commonMain PlatformHttpClient.kt.

        // A hostile/compromised relay must not be able to redirect us elsewhere:
        // OkHttp follows 3xx by default and the DNS-leak/SOCKS guard only checks
        // the ORIGINAL url, not the redirect target — so a 302 could exfiltrate
        // the request (capability headers) to an attacker-controlled .onion or
        // leak DNS on the direct path. The relay protocol never legitimately
        // redirects, so disable redirect-following on every client.
        private fun baseBuilder(): OkHttpClient.Builder =
            OkHttpClient.Builder()
                .followRedirects(false)
                .followSslRedirects(false)
                // Strip OkHttp's default User-Agent ("okhttp/x.y.z") and
                // Accept-Encoding so the untrusted relay can't fingerprint the
                // client as Android vs iOS (the iOS SwiftTorHttp path sends
                // neither). A network interceptor runs AFTER OkHttp's
                // BridgeInterceptor adds these defaults, so removeHeader here
                // actually drops them from the wire.
                .addNetworkInterceptor { chain ->
                    chain.proceed(
                        chain.request().newBuilder()
                            .removeHeader("User-Agent")
                            .removeHeader("Accept-Encoding")
                            .build()
                    )
                }

        fun direct(): PlatformHttpClient = PlatformHttpClient(client = baseBuilder().build())

        /**
         * The SOCKS transport tail shared by [torProxy] and [socksProxy]: no idle
         * connection pool, HTTP/1.1 only, 60 s connect/read/write. The caller adds
         * the route (selector or fixed proxy).
         */
        private fun socksTransportBuilder(): OkHttpClient.Builder = baseBuilder()
            .connectionPool(okhttp3.ConnectionPool(0, 1, TimeUnit.MILLISECONDS))
            .protocols(listOf(okhttp3.Protocol.HTTP_1_1))
            .connectTimeout(60, TimeUnit.SECONDS)
            .readTimeout(60, TimeUnit.SECONDS)
            .writeTimeout(60, TimeUnit.SECONDS)

        // The SOCKS port is resolved through [SocksPortRedirect]
        // at EVERY connection (see [SocksRedirectProxySelector]), so the guard-
        // channel kick's listener move re-points this client without rebuilding it.
        fun torProxy(socksPort: Int): PlatformHttpClient = PlatformHttpClient(
            client = socksTransportBuilder()
                .proxySelector(SocksRedirectProxySelector(socksPort))
                .build(),
            viaSocks = true,
            isolationSocksPort = socksPort,
        )

        /**
         * EXTERNAL SOCKS PROXY MODE (ExternalTorProxy.kt): the relay client for a
         * SOCKS5 proxy the USER runs (Orbot, a LAN tor, a logging proxy), built
         * exactly like [torProxy] — same no-redirect/no-fingerprint base, same
         * HTTP/1.1-only, pool-less, 60 s timeouts, same `viaSocks` onion guard —
         * with two differences:
         *  - the proxy is FIXED at [host]:[port] (`OkHttpClient.Builder.proxy`,
         *    which OkHttp uses as the ONLY route — no selector, no direct
         *    fallback) and is NOT subject to [SocksPortRedirect], which describes
         *    the embedded Tor's listener and has nothing to say about this one;
         *  - the proxy address is built from the literal's raw bytes
         *    (`InetAddress.getByAddress`), so there is no name lookup of the proxy
         *    host either. The relay's onion still goes to the proxy UNRESOLVED
         *    (SOCKS5 ATYP DOMAINNAME — OkHttp's SOCKS route, pinned by
         *    PlatformHttpClientSocksDnsTest / PlatformHttpClientExternalSocksTest).
         *
         * [host] must already be a valid [ExternalTorProxy] literal (callers build
         * it from a parsed [ExternalTorProxyConfig]); anything else throws rather
         * than producing a client that could route somewhere unintended.
         */
        fun socksProxy(host: String, port: Int): PlatformHttpClient {
            val address = requireNotNull(ExternalTorProxy.addressBytes(host)) {
                "external proxy host is not a loopback/LAN IP literal"
            }
            require(port in 1..65535) { "external proxy port out of range" }
            val proxyAddress = InetSocketAddress(java.net.InetAddress.getByAddress(address), port)
            return PlatformHttpClient(
                client = socksTransportBuilder()
                    .proxy(Proxy(Proxy.Type.SOCKS, proxyAddress))
                    .build(),
                viaSocks = true,
                redactTransportErrors = true,
            )
        }

        /**
         * External proxy mode's reachability check: a plain TCP connect to the
         * proxy's listener, closed immediately — no SOCKS handshake, no request,
         * nothing sent, and certainly no clearnet probe. Built from the literal's
         * raw bytes like [socksProxy], so no name lookup. False for an invalid
         * host, a refused/timed-out connect, or any other error; never throws and
         * never logs (the caller writes the one address-free status line).
         */
        fun socksProxyReachable(host: String, port: Int, timeoutMs: Int): Boolean {
            val address = ExternalTorProxy.addressBytes(host) ?: return false
            if (port !in 1..65535) return false
            return try {
                java.net.Socket(Proxy.NO_PROXY).use { socket ->
                    socket.connect(
                        InetSocketAddress(java.net.InetAddress.getByAddress(address), port),
                        timeoutMs.coerceAtLeast(1),
                    )
                    true
                }
            } catch (_: Exception) {
                false
            }
        }
    }
}

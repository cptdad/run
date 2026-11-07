package com.vg.run

import java.net.InetSocketAddress
import java.net.Proxy

// ---------------------------------------------------------------------------
// The SOCKS5 socket layer of the embedded-Tor client (moved verbatim out of
// PlatformHttpClient.android.kt): the redirecting proxy selector, the onion-only
// loopback DNS, the ISOLATED route (RFC 1929 credentials = a Tor isolation
// class) and the OPTIMISTIC DATA route. PlatformHttpClient builds its OkHttp
// clients from these; nothing here logs a host, a port of an external proxy, or
// a credential.
//
// Network-API guard (scripts/check-network-api-usage.sh): this file is on the
// allowlist because it opens `java.net.Socket`s itself. It enforces the host
// guard on its own: [OnionLoopbackDns] refuses every non-onion name, and every
// socket factory refuses the host-resolving `createSocket` forms.
// ---------------------------------------------------------------------------

/**
 * The Tor client's proxy: ALWAYS exactly one SOCKS proxy on 127.0.0.1, at the
 * port [SocksPortRedirect.resolve] names for [socksPort] right now — the
 * original port, the port a guard-channel kick moved it to, or
 * [SocksPortRedirect.BLOCKED_PORT] while that move is unconfirmed.
 *
 * NEVER an empty list and never `Proxy.NO_PROXY`: OkHttp falls back to a DIRECT
 * connection on an empty selection, which for an onion URL would mean a local
 * DNS lookup. A failed connection is not "retried elsewhere" either
 * ([connectFailed] is a no-op): the only alternative would be direct.
 */
internal class SocksRedirectProxySelector(private val socksPort: Int) : java.net.ProxySelector() {
    override fun select(uri: java.net.URI?): List<Proxy> =
        listOf(Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", SocksPortRedirect.resolve(socksPort))))

    override fun connectFailed(uri: java.net.URI?, sa: java.net.SocketAddress?, ioe: java.io.IOException?) {
        // Deliberately nothing — see the class comment.
    }
}

// ---------------------------------------------------------------------------
// SOCKS ISOLATION route ([RendezvousHedge], [SocksIsolation]) — used ONLY when a
// request carries an isolation credential; every other Tor request keeps the
// java.net SOCKS route above.
// ---------------------------------------------------------------------------

private val LOOPBACK_V4 = byteArrayOf(127, 0, 0, 1)

/**
 * The isolated route's DNS: resolves NOTHING. An onion name becomes a loopback
 * placeholder address that carries the name (`InetAddress.getByAddress(host, …)`
 * performs no lookup); anything else is refused. [Socks5IsolatedSocket] ignores
 * the placeholder's bytes and sends the NAME to Tor — so even a mis-wired client
 * could only ever dial the local loopback, never resolve or reach a clearnet host.
 */
internal object OnionLoopbackDns : okhttp3.Dns {
    override fun lookup(hostname: String): List<java.net.InetAddress> {
        if (!hostIsOnion("http://$hostname/")) throw java.net.UnknownHostException("refused: non-onion via SOCKS")
        return listOf(java.net.InetAddress.getByAddress(hostname, LOOPBACK_V4))
    }
}

/** Hands OkHttp one [Socks5IsolatedSocket] per connection. Only the no-argument
 *  form is used by OkHttp; the connecting forms are refused (they would bypass
 *  the handshake). */
internal class Socks5IsolatedSocketFactory(
    private val socksPort: Int,
    private val username: String,
    private val password: String,
) : javax.net.SocketFactory() {
    override fun createSocket(): java.net.Socket = Socks5IsolatedSocket(socksPort, username, password)
    override fun createSocket(host: String?, port: Int): java.net.Socket = refuse()
    override fun createSocket(host: String?, port: Int, localHost: java.net.InetAddress?, localPort: Int): java.net.Socket = refuse()
    override fun createSocket(host: java.net.InetAddress?, port: Int): java.net.Socket = refuse()
    override fun createSocket(address: java.net.InetAddress?, port: Int, localAddress: java.net.InetAddress?, localPort: Int): java.net.Socket = refuse()
    private fun refuse(): Nothing = throw java.io.IOException("SOCKS5 isolated socket: unsupported connect form")
}

/**
 * A plain TCP socket to the embedded Tor's SOCKS listener (127.0.0.1, port via
 * [SocksPortRedirect.resolve] at each connect) that performs SOCKS5 with
 * username/password auth (RFC 1928 + 1929) for the requested `host:port`, so the
 * stream lands in Tor's isolation class for that credential (IsolateSOCKSAuth).
 * Offers ONLY method 0x02 — a server answering anything else fails the connect
 * rather than silently dropping the isolation. Exception messages carry fixed
 * text and the SOCKS reply code only: never the host, never the credential.
 *
 * Handshake reads are bounded by the socket's read timeout as OkHttp set it
 * before connecting (the C3 first-byte budget when one applies — the same "a
 * CONNECT that outlives the budget is the stalled-stream signal" behaviour the
 * java.net route has), capped by the connect timeout.
 */
internal class Socks5IsolatedSocket(
    private val socksPort: Int,
    private val username: String,
    private val password: String,
) : java.net.Socket(Proxy.NO_PROXY) {

    override fun connect(endpoint: java.net.SocketAddress?) = connect(endpoint, 0)

    override fun connect(endpoint: java.net.SocketAddress?, timeout: Int) {
        val target = endpoint as? InetSocketAddress ?: throw java.io.IOException("SOCKS5: unsupported address")
        // getHostString never resolves: the name OnionLoopbackDns attached.
        val host = target.hostString
        if (!hostIsOnion("http://$host/")) throw java.io.IOException("refused: non-onion via SOCKS")
        val port = SocksPortRedirect.resolve(socksPort)
        super.connect(InetSocketAddress(java.net.InetAddress.getByAddress(LOOPBACK_V4), port), timeout)
        // The handshake spans Tor's descriptor/intro/rendezvous phase (the CONNECT
        // reply comes only after the rendezvous joins), so it runs under the CONNECT
        // deadline, never the shorter read timeout OkHttp set before calling us — the
        // C3 first-byte budget must not cover that phase (MessageManager C3 note),
        // same as the java.net SOCKS route. Restored for the HTTP exchange after.
        val saved = soTimeout
        soTimeout = timeout
        try {
            socks5UserPassHandshake(getInputStream(), getOutputStream(), host, target.port, username, password)
        } catch (e: Exception) {
            try { close() } catch (_: Exception) {}
            throw e
        }
        soTimeout = saved
    }
}

/**
 * The client side of SOCKS5 + RFC 1929 over blocking streams: greeting `05 01 02`,
 * `01 ULEN U PLEN P`, then CONNECT by DOMAINNAME; drains the reply exactly so the
 * stream carries only HTTP afterwards. Throws [java.io.IOException] (fixed text +
 * reply code) on any refusal. Pure over its streams → unit-tested with a fake
 * server (PlatformHttpClientSocksIsolationTest).
 */
internal fun socks5UserPassHandshake(
    input: java.io.InputStream,
    output: java.io.OutputStream,
    host: String,
    port: Int,
    username: String,
    password: String,
) {
    val din = java.io.DataInputStream(input)
    output.write(Socks5Wire.greetingUserPass())
    output.flush()
    val ver = din.readUnsignedByte()
    val method = din.readUnsignedByte()
    if (ver != Socks5Wire.VERSION || method != Socks5Wire.METHOD_USER_PASS) {
        throw java.io.IOException("SOCKS5 auth method rejected ($method)")
    }
    output.write(Socks5Wire.userPassRequest(username, password))
    output.flush()
    din.readUnsignedByte() // auth sub-negotiation version
    val status = din.readUnsignedByte()
    if (status != 0) throw java.io.IOException("SOCKS5 auth refused ($status)")
    output.write(Socks5Wire.connectDomain(host, port))
    output.flush()
    readSocks5ConnectReply(din)
}

/**
 * Consumes ONE SOCKS5 CONNECT reply exactly — the 4-byte head, then the BND tail
 * whose length ATYP decides (IPv4 4+2, IPv6 16+2, domain 1+len+2) — and nothing
 * past it, so the stream carries only HTTP afterwards (DataInputStream does not
 * buffer). Throws [java.io.IOException] with fixed text + the reply code on a
 * refusal. Shared by the isolated handshake and the optimistic route's gate.
 */
internal fun readSocks5ConnectReply(din: java.io.DataInputStream) {
    val head = ByteArray(4)
    din.readFully(head)
    if ((head[0].toInt() and 0xff) != Socks5Wire.VERSION) throw java.io.IOException("SOCKS5 bad reply")
    val rep = head[1].toInt() and 0xff
    if (rep != 0) throw java.io.IOException("SOCKS5 connect rejected (rep=$rep)")
    val tail = when (val n = Socks5Wire.replyTailLength(head[3].toInt() and 0xff)) {
        -1 -> din.readUnsignedByte() + 2
        -2 -> throw java.io.IOException("SOCKS5 bad reply address type")
        else -> n
    }
    din.readFully(ByteArray(tail))
}

// ---------------------------------------------------------------------------
// OPTIMISTIC DATA route (2026-10-26) — the request bytes go out right behind the
// SOCKS5 CONNECT instead of after Tor's CONNECT reply, so a request on an already
// joined rendezvous circuit costs ONE circuit round trip, not two (stream open,
// then request/response). Tor buffers bytes that arrive before the stream is
// connected and sends them as optimistic data on C_REND_JOINED circuits (else it
// holds them until RELAY_CONNECTED) — never slower than the wait-for-reply path.
// iOS sibling: SwiftTorHttp.swift (`isOptimisticEligible`, `socks5Connect`).
// ---------------------------------------------------------------------------

/**
 * Which requests may ride the optimistic route: EXACTLY `GET /` (health probe +
 * pre-unlock warm-up probe) and `POST /peek` (batch unread prime). Exact method,
 * exact PATH — the query is not part of [path] (callers pass OkHttp's
 * `encodedPath`), so `GET /?x=1` is the same read-only root GET and is eligible;
 * `/peek/` or `/PEEK` are not. iOS compares the same percent-encoded path.
 *
 * WHY so narrow: Tor RE-SENDS optimistic data when it retries a stream on another
 * circuit (stream detach/re-attach after a timeout or an END on the first one), so
 * the relay can receive the request TWICE. Harmless for these two read-only,
 * idempotent requests; a send, a mint, a PUT/DELETE — and above all the
 * `GET /inbox/{id}` drain (a leasing GET hides blobs for the lease; the move transfer inbox's plain GET deletes at request-handling time) —
 * could execute twice. Everything else keeps the wait-for-reply route.
 */
internal fun isOptimisticEligible(method: String, path: String): Boolean =
    (method == "GET" && path == "/") || (method == "POST" && path == "/peek")

/** One [Socks5OptimisticSocket] per connection; connecting forms refused (they
 *  would bypass the handshake), like [Socks5IsolatedSocketFactory]. */
internal class Socks5OptimisticSocketFactory(
    private val socksPort: Int,
    private val firstByteBudgetMs: Int,
) : javax.net.SocketFactory() {
    override fun createSocket(): java.net.Socket = Socks5OptimisticSocket(socksPort, firstByteBudgetMs)
    override fun createSocket(host: String?, port: Int): java.net.Socket = refuse()
    override fun createSocket(host: String?, port: Int, localHost: java.net.InetAddress?, localPort: Int): java.net.Socket = refuse()
    override fun createSocket(host: java.net.InetAddress?, port: Int): java.net.Socket = refuse()
    override fun createSocket(address: java.net.InetAddress?, port: Int, localAddress: java.net.InetAddress?, localPort: Int): java.net.Socket = refuse()
    private fun refuse(): Nothing = throw java.io.IOException("SOCKS5 optimistic socket: unsupported connect form")
}

/**
 * A plain TCP socket to the embedded Tor's SOCKS listener (127.0.0.1, port via
 * [SocksPortRedirect.resolve] at each connect, like every Tor route) whose
 * `connect()` performs the LOCAL part of SOCKS5 ([socks5OptimisticOpen]: greeting,
 * method reply, java.net's auth step, CONNECT by DOMAINNAME — sub-millisecond on
 * loopback) and returns WITHOUT reading the CONNECT reply. OkHttp then writes the
 * request; [getInputStream]'s gate consumes the reply on the first read.
 *
 * Timeouts (C3, see Socks5IsolatedSocket.connect): the CONNECT reply spans Tor's
 * descriptor/intro/rendezvous + stream attach, so it is read under the CONNECT
 * timeout this socket was given, never the C3 first-byte budget; after the reply
 * the socket's read timeout is [firstByteBudgetMs] (> 0) or what OkHttp set.
 * Exception messages carry fixed text + the SOCKS reply code only, never the host.
 */
internal class Socks5OptimisticSocket(
    private val socksPort: Int,
    private val firstByteBudgetMs: Int,
) : java.net.Socket(Proxy.NO_PROXY) {

    private var connectTimeoutMs = 0
    private var connectSentAtNs = 0L
    private var gate: Socks5ReplyGateInputStream? = null

    override fun connect(endpoint: java.net.SocketAddress?) = connect(endpoint, 0)

    override fun connect(endpoint: java.net.SocketAddress?, timeout: Int) {
        val target = endpoint as? InetSocketAddress ?: throw java.io.IOException("SOCKS5: unsupported address")
        // getHostString never resolves: the name OnionLoopbackDns attached.
        val host = target.hostString
        if (!hostIsOnion("http://$host/")) throw java.io.IOException("refused: non-onion via SOCKS")
        val port = SocksPortRedirect.resolve(socksPort)
        super.connect(InetSocketAddress(java.net.InetAddress.getByAddress(LOOPBACK_V4), port), timeout)
        connectTimeoutMs = timeout
        // The request follows the CONNECT in its own write(s): no Nagle hold-back
        // waiting for the CONNECT segment's ACK.
        tcpNoDelay = true
        val saved = soTimeout
        soTimeout = timeout
        try {
            socks5OptimisticOpen(super.getInputStream(), super.getOutputStream(), host, target.port)
        } catch (e: Exception) {
            try { close() } catch (_: Exception) {}
            throw e
        }
        soTimeout = saved
        connectSentAtNs = System.nanoTime()
    }

    @Synchronized
    override fun getInputStream(): java.io.InputStream {
        gate?.let { return it }
        return Socks5ReplyGateInputStream(
            super.getInputStream(),
            aroundReply = { readReply ->
                val saved = soTimeout
                soTimeout = connectTimeoutMs
                try {
                    readReply()
                } finally {
                    // The socket may already be closed (cancel, refusal): best effort.
                    try { soTimeout = if (firstByteBudgetMs > 0) firstByteBudgetMs else saved } catch (_: Exception) {}
                }
            },
            startedAtNs = connectSentAtNs,
        ).also { gate = it }
    }
}

/**
 * The optimistic route's read side: the FIRST read (or skip) consumes the SOCKS5
 * CONNECT reply exactly ([readSocks5ConnectReply], run inside [aroundReply] so the
 * socket can swap timeouts around it) and only then passes HTTP bytes through
 * untouched. A refused reply fails that read and every later one. Writes never
 * touch it — the request is already on its way while the reply is pending.
 *
 * Writes ONE debug line per stream at the first HTTP byte (numbers only — no host,
 * no path, no identifier; LogBuffer is itself debug-mode gated):
 * `optimistic stream: socks reply +N ms, first byte +M ms`, both measured from the
 * CONNECT write ([startedAtNs]; 0 = no line, e.g. in a unit test of the gate).
 * Eligible requests are never `suppressLog` (that is DebugLogUploader's own POST).
 */
internal class Socks5ReplyGateInputStream(
    raw: java.io.InputStream,
    private val aroundReply: (readReply: () -> Unit) -> Unit = { it() },
    private val startedAtNs: Long = 0L,
) : java.io.FilterInputStream(raw) {

    private var replyConsumed = false
    private var refusal: java.io.IOException? = null
    private var replyAtNs = 0L
    private var firstByteLogged = false

    @Synchronized
    private fun ensureReply() {
        refusal?.let { throw java.io.IOException(it.message) }
        if (replyConsumed) return
        try {
            aroundReply { readSocks5ConnectReply(java.io.DataInputStream(`in`)) }
        } catch (e: java.io.IOException) {
            refusal = e
            throw e
        }
        replyConsumed = true
        replyAtNs = System.nanoTime()
    }

    private fun noteBytes(n: Int) {
        if (n <= 0 || firstByteLogged) return
        firstByteLogged = true
        if (startedAtNs == 0L) return
        val now = System.nanoTime()
        platformLog(
            "HttpClient",
            "optimistic stream: socks reply +${(replyAtNs - startedAtNs) / 1_000_000} ms, " +
                "first byte +${(now - startedAtNs) / 1_000_000} ms",
        )
    }

    override fun read(): Int {
        ensureReply()
        return `in`.read().also { if (it >= 0) noteBytes(1) }
    }

    override fun read(b: ByteArray, off: Int, len: Int): Int {
        ensureReply()
        if (len == 0) return 0
        return `in`.read(b, off, len).also { noteBytes(it) }
    }

    override fun skip(n: Long): Long {
        ensureReply()
        return `in`.skip(n)
    }

    /** Nothing is "available" while the reply is still unread: those bytes are SOCKS, not HTTP. */
    override fun available(): Int = if (replyConsumed) `in`.available() else 0

    override fun markSupported(): Boolean = false
}

/**
 * The LOCAL half of the optimistic route's SOCKS5 exchange: everything up to and
 * including WRITING the CONNECT by DOMAINNAME (SOCKS5h — Tor resolves the onion),
 * never reading its reply ([Socks5ReplyGateInputStream] does, after the request
 * went out).
 *
 * The greeting + auth step REPEAT java.net's SOCKS client byte for byte (the
 * default route, [SocksRedirectProxySelector]): offer `00` AND `02`; on a `02` pick
 * (Tor's default preference) authenticate as the `user.name` system property with
 * an EMPTY password, exactly as `SocksSocketImpl` does with no Authenticator (Rún
 * installs none). That is load-bearing: Tor isolates streams by SOCKS credential
 * (IsolateSOCKSAuth), so a no-auth-only greeting would put these streams in a
 * DIFFERENT class from every drain/send — a fresh rendezvous circuit for the
 * probe, and none of the saving. Pinned by PlatformHttpClientSocksOptimisticTest
 * (both routes against one fake server → identical handshake bytes). Throws
 * [java.io.IOException] with fixed text on a refusal — never the host.
 */
internal fun socks5OptimisticOpen(
    input: java.io.InputStream,
    output: java.io.OutputStream,
    host: String,
    port: Int,
    userName: String? = System.getProperty("user.name"),
) {
    val din = java.io.DataInputStream(input)
    output.write(Socks5Wire.greetingJavaNet())
    output.flush()
    val ver = din.readUnsignedByte()
    val method = din.readUnsignedByte()
    if (ver != Socks5Wire.VERSION) throw java.io.IOException("SOCKS5 bad reply")
    when (method) {
        Socks5Wire.METHOD_NO_AUTH -> {}
        Socks5Wire.METHOD_USER_PASS -> {
            // java.net gives up (no connection) without a user.name; so do we.
            val user = userName ?: throw java.io.IOException("SOCKS5 auth method rejected ($method)")
            output.write(javaNetSocksUserPassRequest(user))
            output.flush()
            din.readUnsignedByte() // auth sub-negotiation version
            val status = din.readUnsignedByte()
            if (status != 0) throw java.io.IOException("SOCKS5 auth refused ($status)")
        }
        else -> throw java.io.IOException("SOCKS5 auth method rejected ($method)")
    }
    output.write(Socks5Wire.connectDomain(host, port))
    output.flush()
}

/**
 * RFC 1929 request exactly as java.net's `SocksSocketImpl.authenticate` builds it
 * with no Authenticator: `01`, `user.length()` as one byte, the name in
 * ISO-8859-1, then `00` (no password). Quirks included on purpose — the point is
 * the SAME isolation class as the default route, not a "correct" request.
 */
internal fun javaNetSocksUserPassRequest(userName: String): ByteArray =
    byteArrayOf(Socks5Wire.AUTH_VERSION.toByte(), userName.length.toByte()) +
        userName.toByteArray(Charsets.ISO_8859_1) +
        byteArrayOf(0)

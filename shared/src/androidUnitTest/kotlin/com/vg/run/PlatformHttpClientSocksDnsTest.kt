package com.vg.run

import java.io.DataInputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.ServerSocket
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * THE remote-DNS regression test for the Android relay transport.
 *
 * Rún's single most important transport invariant: a request to a `.onion` must
 * never have its hostname resolved by this device. A local lookup of the relay's
 * onion address is a DNS leak that names the relay to the network — the exact
 * thing Tor exists to prevent — and it happens silently, with the request still
 * succeeding, so nothing else would notice.
 *
 * WHY THIS TEST EXISTS AT ALL (2026-09-16, OkHttp 4.12.0 → 5.5.0): the invariant
 * is NOT implemented by anything in this repo. There is no custom [okhttp3.Dns]
 * on the Tor client; `PlatformHttpClient.torProxy` only sets a
 * `Proxy(Proxy.Type.SOCKS, 127.0.0.1:port)`, and the no-local-resolution
 * behaviour is a property OkHttp itself provides: `RouteSelector.nextRoutes`
 * short-circuits `Proxy.Type.SOCKS` to a Route built from
 * `InetSocketAddress.createUnresolved(host, port)` and returns BEFORE its
 * `dnsLookup(...)` branch, so the JDK's SOCKS client sends the hostname to the
 * proxy as a SOCKS5 DOMAINNAME (ATYP 0x03) and Tor resolves it. That is a
 * third-party implementation detail we depend on, across a major version — so it
 * is pinned here behaviourally rather than trusted.
 *
 * The other two layers of the same defense are tested elsewhere and are NOT what
 * this file covers: `onionTransportGuard` (OnionTransportGuardTest) refuses a
 * `.onion` on the direct client and a non-onion on the SOCKS client, and
 * scripts/check-network-api-usage.sh refuses a DNS-capable networking API
 * outside the approved transport files.
 *
 * Loopback only — no network, no device, no Tor.
 */
class PlatformHttpClientSocksDnsTest {

    private companion object {
        /** SOCKS5 ATYP values (RFC 1928 §4). 0x03 == the hostname went out UNRESOLVED. */
        const val ATYP_IPV4 = 0x01
        const val ATYP_DOMAINNAME = 0x03
        const val ATYP_IPV6 = 0x04

        /**
         * A syntactically well-formed v3 onion. It resolves nowhere, which is
         * the point: if OkHttp ever resolved locally, the connection would die
         * with UnknownHostException and the fake proxy below would record
         * nothing at all.
         */
        const val ONION_HOST =
            "exampleonionaddressfortestsonlyaaaaaaaaaaaaaaaaaaaaaaaaa.onion"
    }

    /** What the fake SOCKS5 proxy saw in the client's CONNECT request. */
    private data class SocksConnect(val atyp: Int, val host: String, val port: Int)

    /**
     * A minimal SOCKS5 server on 127.0.0.1 that completes the method
     * negotiation, records ONE CONNECT request, and then drops the connection
     * (so the HTTP call fails fast instead of waiting out a timeout — the HTTP
     * exchange is irrelevant here, only the address handed to the proxy is).
     */
    private class FakeSocks5Proxy : AutoCloseable {
        private val server = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))
        private val seen = ArrayBlockingQueue<SocksConnect>(1)

        val port: Int get() = server.localPort

        init {
            thread(isDaemon = true, name = "fake-socks5") {
                try {
                    server.accept().use { socket ->
                        val input = DataInputStream(socket.getInputStream())
                        val output = socket.getOutputStream()

                        // --- greeting: VER, NMETHODS, METHODS[NMETHODS] ---
                        val version = input.readUnsignedByte()
                        val methodCount = input.readUnsignedByte()
                        repeat(methodCount) { input.readUnsignedByte() }
                        // Answer "SOCKS5, no authentication".
                        output.write(byteArrayOf(version.toByte(), 0x00))
                        output.flush()

                        // --- request: VER, CMD, RSV, ATYP, ADDR, PORT ---
                        input.readUnsignedByte()          // VER
                        input.readUnsignedByte()          // CMD (0x01 CONNECT)
                        input.readUnsignedByte()          // RSV
                        val atyp = input.readUnsignedByte()
                        val host = when (atyp) {
                            ATYP_DOMAINNAME -> {
                                val len = input.readUnsignedByte()
                                val bytes = ByteArray(len)
                                input.readFully(bytes)
                                String(bytes, Charsets.ISO_8859_1)
                            }
                            ATYP_IPV4 -> ByteArray(4)
                                .also { input.readFully(it) }
                                .joinToString(".") { (it.toInt() and 0xff).toString() }
                            ATYP_IPV6 -> ByteArray(16)
                                .also { input.readFully(it) }
                                .joinToString(":") { (it.toInt() and 0xff).toString(16) }
                            else -> ""
                        }
                        val destPort = (input.readUnsignedByte() shl 8) or input.readUnsignedByte()
                        seen.offer(SocksConnect(atyp, host, destPort))
                    }
                } catch (_: Exception) {
                    // Client gave up, or the socket closed mid-handshake: the
                    // assertions below turn an empty queue into a clear failure.
                }
            }
        }

        fun awaitConnect(): SocksConnect? = seen.poll(30, TimeUnit.SECONDS)

        override fun close() {
            try { server.close() } catch (_: Exception) { /* best-effort */ }
        }
    }

    @Test
    fun torProxyClient_sendsTheOnionHostnameToTheProxyUNRESOLVED() {
        FakeSocks5Proxy().use { proxy ->
            val client = PlatformHttpClient.torProxy(proxy.port)

            // The HTTP exchange cannot complete (the fake proxy hangs up after
            // the CONNECT), so this returns a transport failure by design. What
            // matters is what reached the proxy on the way.
            val result = client.get("http://$ONION_HOST/inbox/probe", emptyMap(), 20)
            assertFalse(result.isSuccess, "fake proxy never serves a response")

            val connect = proxy.awaitConnect()
            assertNotNull(
                connect,
                "the SOCKS proxy received no CONNECT at all — OkHttp resolved (or " +
                    "refused) the onion locally instead of handing it to the proxy",
            )
            assertEquals(
                ATYP_DOMAINNAME,
                connect.atyp,
                "SOCKS5 ATYP must be DOMAINNAME (0x03): an IP address here means " +
                    "this device resolved the onion itself — a DNS leak",
            )
            assertEquals(
                ONION_HOST,
                connect.host,
                "the proxy must receive the onion hostname verbatim",
            )
            assertEquals(80, connect.port, "default HTTP port must survive the SOCKS hop")
        }
    }

    @Test
    fun torProxyClient_carriesASocksProxyOnLoopbackAndThe60sTimeouts() {
        val socksPort = 9150
        val okHttp = okHttpClientOf(PlatformHttpClient.torProxy(socksPort))

        // The proxy is chosen per connection by a selector that
        // follows SocksPortRedirect — it must always yield exactly ONE SOCKS proxy
        // on loopback, never an empty list (OkHttp would go DIRECT).
        assertTrue(okHttp.proxy == null, "the port is resolved per connection, not pinned")
        SocksPortRedirect.reset()
        try {
            fun selected(): Proxy {
                val list = okHttp.proxySelector.select(java.net.URI("http://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion/"))
                assertEquals(1, list.size, "exactly one proxy, never empty (= direct)")
                val proxy = list.single()
                assertEquals(Proxy.Type.SOCKS, proxy.type(), "must be SOCKS, never HTTP or DIRECT")
                assertEquals("127.0.0.1", (proxy.address() as InetSocketAddress).address.hostAddress)
                return proxy
            }
            assertEquals(socksPort, (selected().address() as InetSocketAddress).port)
            SocksPortRedirect.beginMove(socksPort)
            assertEquals(SocksPortRedirect.BLOCKED_PORT, (selected().address() as InetSocketAddress).port, "gap: blocked, still SOCKS")
            SocksPortRedirect.completeMove(socksPort, 45678)
            assertEquals(45678, (selected().address() as InetSocketAddress).port, "the moved listener")
        } finally {
            SocksPortRedirect.reset()
        }

        // Unchanged across the 4.x → 5.x bump (a cold Tor circuit needs them).
        assertEquals(60_000, okHttp.connectTimeoutMillis)
        assertEquals(60_000, okHttp.readTimeoutMillis)
        assertEquals(60_000, okHttp.writeTimeoutMillis)

        // A hostile relay must not be able to redirect the capability headers
        // anywhere: the guard only inspects the ORIGINAL url.
        assertFalse(okHttp.followRedirects)
        assertFalse(okHttp.followSslRedirects)
    }

    @Test
    fun directClient_carriesNoProxyAtAll() {
        val okHttp = okHttpClientOf(PlatformHttpClient.direct())
        assertTrue(
            okHttp.proxy == null,
            "the direct (debug/emulator) client must never carry a proxy — its " +
                "onion refusal comes from onionTransportGuard",
        )
        assertFalse(okHttp.followRedirects)
    }

    /**
     * Reads the private `client` backing field. Deliberately reflective: the
     * OkHttpClient is an implementation detail of [PlatformHttpClient] and must
     * stay private to production callers, but the proxy/timeout wiring is a
     * security property worth asserting. A rename fails here loudly rather than
     * silently skipping the assertions.
     */
    private fun okHttpClientOf(platformClient: PlatformHttpClient): okhttp3.OkHttpClient {
        val field = PlatformHttpClient::class.java.getDeclaredField("client")
        field.isAccessible = true
        return field.get(platformClient) as okhttp3.OkHttpClient
    }
}

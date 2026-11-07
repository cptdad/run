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
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * External SOCKS proxy mode — the Android transport half
 * ([PlatformHttpClient.socksProxy] / [PlatformHttpClient.socksProxyReachable]).
 *
 * The mode's whole promise is "every relay request goes to YOUR proxy, the
 * onion goes there unresolved, and nothing else is used". These tests pin:
 *  - the onion reaches the configured proxy as a SOCKS5 DOMAINNAME (no local DNS);
 *  - the client is pinned to exactly that proxy (never a selector, never direct);
 *  - a transport error never carries the user's proxy address back out;
 *  - the reachability check is a bare TCP connect that refuses invalid hosts.
 * Loopback only — no network, no device, no Tor.
 */
class PlatformHttpClientExternalSocksTest {

    private companion object {
        const val ATYP_DOMAINNAME = 0x03
        const val ONION_HOST =
            "exampleonionaddressfortestsonlyaaaaaaaaaaaaaaaaaaaaaaaaa.onion"
    }

    private data class SocksConnect(val atyp: Int, val host: String, val port: Int)

    /** Minimal SOCKS5 listener: negotiates, records ONE CONNECT, hangs up. */
    private class FakeSocks5Proxy : AutoCloseable {
        private val server = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))
        private val seen = ArrayBlockingQueue<SocksConnect>(1)
        val port: Int get() = server.localPort

        init {
            thread(isDaemon = true, name = "fake-ext-socks5") {
                try {
                    server.accept().use { socket ->
                        val input = DataInputStream(socket.getInputStream())
                        val output = socket.getOutputStream()
                        val version = input.readUnsignedByte()
                        repeat(input.readUnsignedByte()) { input.readUnsignedByte() }
                        output.write(byteArrayOf(version.toByte(), 0x00))
                        output.flush()
                        input.readUnsignedByte(); input.readUnsignedByte(); input.readUnsignedByte()
                        val atyp = input.readUnsignedByte()
                        val host = if (atyp == ATYP_DOMAINNAME) {
                            val bytes = ByteArray(input.readUnsignedByte())
                            input.readFully(bytes)
                            String(bytes, Charsets.ISO_8859_1)
                        } else ""
                        val destPort = (input.readUnsignedByte() shl 8) or input.readUnsignedByte()
                        seen.offer(SocksConnect(atyp, host, destPort))
                    }
                } catch (_: Exception) { /* assertions below turn silence into a failure */ }
            }
        }

        fun awaitConnect(): SocksConnect? = seen.poll(30, TimeUnit.SECONDS)
        override fun close() { try { server.close() } catch (_: Exception) {} }
    }

    @Test
    fun socksProxyClient_sendsTheOnionToTheConfiguredProxyUNRESOLVED() {
        FakeSocks5Proxy().use { proxy ->
            val client = PlatformHttpClient.socksProxy("127.0.0.1", proxy.port)
            val result = client.get("http://$ONION_HOST/inbox/probe", emptyMap(), 20)
            assertFalse(result.isSuccess, "fake proxy never serves a response")

            val connect = proxy.awaitConnect()
            assertNotNull(connect, "the configured proxy received no CONNECT — the onion was resolved or refused locally")
            assertEquals(ATYP_DOMAINNAME, connect.atyp, "ATYP must be DOMAINNAME: anything else is a local DNS resolution")
            assertEquals(ONION_HOST, connect.host)
            assertEquals(80, connect.port)
        }
    }

    @Test
    fun socksProxyClient_isPinnedToExactlyTheGivenProxy() {
        val okHttp = okHttpClientOf(PlatformHttpClient.socksProxy("192.168.1.20", 9150))
        val proxy = okHttp.proxy
        assertNotNull(proxy, "a FIXED proxy — OkHttp then never consults a selector or goes direct")
        assertEquals(Proxy.Type.SOCKS, proxy.type())
        val address = proxy.address() as InetSocketAddress
        assertFalse(address.isUnresolved, "built from the literal's bytes — nothing left to resolve")
        assertEquals("192.168.1.20", address.address.hostAddress)
        assertEquals(9150, address.port)
        assertEquals(60_000, okHttp.connectTimeoutMillis)
        assertEquals(60_000, okHttp.readTimeoutMillis)
        assertEquals(60_000, okHttp.writeTimeoutMillis)
        assertFalse(okHttp.followRedirects)
        assertFalse(okHttp.followSslRedirects)
    }

    @Test
    fun socksProxyClient_ipv6Loopback() {
        val proxy = okHttpClientOf(PlatformHttpClient.socksProxy("::1", 9050)).proxy
        assertNotNull(proxy)
        val address = proxy.address() as InetSocketAddress
        assertTrue(address.address.isLoopbackAddress)
        assertEquals(9050, address.port)
    }

    @Test
    fun socksProxyClient_refusesAnythingButAValidLiteral() {
        for (h in listOf("localhost", "proxy.lan", "8.8.8.8", "0127.0.0.1", "", "[::1]")) {
            assertFailsWith<IllegalArgumentException>(h) { PlatformHttpClient.socksProxy(h, 9050) }
        }
        assertFailsWith<IllegalArgumentException> { PlatformHttpClient.socksProxy("127.0.0.1", 0) }
        assertFailsWith<IllegalArgumentException> { PlatformHttpClient.socksProxy("127.0.0.1", 65536) }
    }

    @Test
    fun socksProxyClient_keepsTheOnionGuard_refusingNonOnionUrls() {
        val result = PlatformHttpClient.socksProxy("127.0.0.1", 9).get("http://example.com/", emptyMap(), 5)
        assertFalse(result.isSuccess)
        assertEquals("refused: non-onion via SOCKS", result.body)
    }

    @Test
    fun socksProxyClient_transportErrorNeverCarriesTheProxyAddress() {
        // A closed loopback port: the connect to the proxy is refused, and the
        // JDK's message for that names the address it dialed.
        val closedPort = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1")).use { it.localPort }
        val result = PlatformHttpClient.socksProxy("127.0.0.1", closedPort)
            .get("http://$ONION_HOST/", emptyMap(), 5)
        assertFalse(result.isSuccess)
        val body = result.body ?: ""
        assertFalse(body.contains("127.0.0.1"), "proxy address leaked into the result: $body")
        assertFalse(body.contains(closedPort.toString()), "proxy port leaked into the result: $body")
        assertFalse(body.contains(".onion"), "relay onion leaked into the result: $body")
    }

    @Test
    fun socksProxyReachable_trueForAListener_falseOtherwise() {
        ServerSocket(0, 1, InetAddress.getByName("127.0.0.1")).use { server ->
            assertTrue(PlatformHttpClient.socksProxyReachable("127.0.0.1", server.localPort, 2_000))
        }
        val closedPort = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1")).use { it.localPort }
        assertFalse(PlatformHttpClient.socksProxyReachable("127.0.0.1", closedPort, 2_000))
        // Invalid hosts are refused BEFORE any socket exists — no lookup, no connect.
        assertFalse(PlatformHttpClient.socksProxyReachable("localhost", 9050, 2_000))
        assertFalse(PlatformHttpClient.socksProxyReachable("8.8.8.8", 53, 2_000))
        assertFalse(PlatformHttpClient.socksProxyReachable("127.0.0.1", 0, 2_000))
    }

    private fun okHttpClientOf(platformClient: PlatformHttpClient): okhttp3.OkHttpClient {
        val field = PlatformHttpClient::class.java.getDeclaredField("client")
        field.isAccessible = true
        return field.get(platformClient) as okhttp3.OkHttpClient
    }
}

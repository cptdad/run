package com.vg.run

import java.io.DataInputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * SOCKS ISOLATION route of the Android Tor client (RendezvousHedge, 2026-10-25).
 *
 * A request carrying an isolation credential (the rendezvous hedge's GET, or any
 * request once a hedge won and [SocksIsolation] adopted its class) does NOT use
 * java.net's SOCKS client — that one can only take credentials from the
 * process-global Authenticator — but `Proxy.NO_PROXY` + [OnionLoopbackDns] +
 * [Socks5IsolatedSocket]. Pinned here behaviourally, against a fake SOCKS5 server:
 *  - the greeting offers ONLY method 0x02 (never 0x00: a "no auth" pick would
 *    silently drop the isolation);
 *  - RFC 1929 carries exactly the credential and [SocksIsolation.PASSWORD];
 *  - the onion still goes out UNRESOLVED as ATYP DOMAINNAME (the remote-DNS
 *    invariant PlatformHttpClientSocksDnsTest pins for the default route);
 *  - with no credential the default route is untouched (no auth sub-negotiation);
 *  - the external-proxy client never sends a credential;
 *  - the isolated route's failure text never carries the onion or the credential.
 * Loopback only — no network, no device, no Tor.
 */
class PlatformHttpClientSocksIsolationTest {

    private companion object {
        const val ONION_HOST = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion"
        const val ATYP_DOMAINNAME = 0x03
    }

    /** What the fake server saw. [username] null = no auth sub-negotiation. */
    private data class Seen(val methods: List<Int>, val username: String?, val password: String?, val atyp: Int, val host: String, val port: Int)

    /** Accepts ONE client, picks 0x02 if offered (Tor's default preference), else
     *  0x00, records the handshake, answers the CONNECT with success and then a
     *  minimal HTTP 404, so the request completes. */
    private class FakeTorSocks : AutoCloseable {
        private val server = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))
        private val seen = ArrayBlockingQueue<Seen>(1)
        val port: Int get() = server.localPort

        init {
            thread(isDaemon = true, name = "fake-tor-socks") {
                try {
                    server.accept().use { s ->
                        val input = DataInputStream(s.getInputStream())
                        val out = s.getOutputStream()
                        input.readUnsignedByte()
                        val n = input.readUnsignedByte()
                        val methods = (0 until n).map { input.readUnsignedByte() }
                        val pick = if (0x02 in methods) 0x02 else 0x00
                        out.write(byteArrayOf(0x05, pick.toByte())); out.flush()
                        var user: String? = null
                        var pass: String? = null
                        if (pick == 0x02) {
                            input.readUnsignedByte()
                            user = ByteArray(input.readUnsignedByte()).also { input.readFully(it) }.decodeToString()
                            pass = ByteArray(input.readUnsignedByte()).also { input.readFully(it) }.decodeToString()
                            out.write(byteArrayOf(0x01, 0x00)); out.flush()
                        }
                        input.readUnsignedByte(); input.readUnsignedByte(); input.readUnsignedByte()
                        val atyp = input.readUnsignedByte()
                        val host = if (atyp == ATYP_DOMAINNAME) {
                            ByteArray(input.readUnsignedByte()).also { input.readFully(it) }.decodeToString()
                        } else ""
                        val port = (input.readUnsignedByte() shl 8) or input.readUnsignedByte()
                        seen.offer(Seen(methods, user, pass, atyp, host, port))
                        out.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0)); out.flush()
                        // Drain the request head, then answer like the relay's GET /.
                        val buf = ByteArray(4096)
                        input.read(buf)
                        out.write("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".toByteArray())
                        out.flush()
                    }
                } catch (_: Exception) {
                }
            }
        }

        fun await(): Seen? = seen.poll(30, TimeUnit.SECONDS)
        override fun close() { try { server.close() } catch (_: Exception) {} }
    }

    @BeforeTest
    fun setUp() { SocksIsolation.reset(); SocksPortRedirect.reset() }

    @AfterTest
    fun tearDown() { SocksIsolation.reset(); SocksPortRedirect.reset() }

    @Test
    fun hedgeGet_authenticatesWithItsOwnCredential_andKeepsTheOnionUnresolved() {
        FakeTorSocks().use { tor ->
            val client = PlatformHttpClient.torProxy(tor.port)
            assertTrue(client.supportsSocksIsolation)
            val cred = SocksIsolation.newCredential()
            val r = client.getIsolated("http://$ONION_HOST/", emptyMap(), 20, false, 0, cred)
            assertEquals(404, r.code, "the isolated route completes a real HTTP exchange")
            val seen = assertNotNull(tor.await())
            assertEquals(listOf(0x02), seen.methods, "ONLY username/password is offered")
            assertEquals(cred, seen.username)
            assertEquals(SocksIsolation.PASSWORD, seen.password)
            assertEquals(ATYP_DOMAINNAME, seen.atyp, "the onion must reach Tor unresolved")
            assertEquals(ONION_HOST, seen.host)
            assertEquals(80, seen.port)
            assertEquals(null, SocksIsolation.current(), "a hedge GET alone never adopts a class")
        }
    }

    @Test
    fun adoptedClass_isUsedByEveryRequestOfAnExistingTorClient() {
        FakeTorSocks().use { tor ->
            val client = PlatformHttpClient.torProxy(tor.port)   // built BEFORE the adoption
            val cred = SocksIsolation.newCredential()
            assertTrue(SocksIsolation.adopt(cred, SocksIsolation.generation()))
            val r = client.post("http://$ONION_HOST/peek", ByteArray(2), "application/json", emptyMap(), 20)
            assertEquals(404, r.code)
            val seen = assertNotNull(tor.await())
            assertEquals(cred, seen.username, "the session's adopted class rides every request")
        }
    }

    @Test
    fun noCredential_keepsTheDefaultRoute() {
        FakeTorSocks().use { tor ->
            val client = PlatformHttpClient.torProxy(tor.port)
            // Not `GET /`: that one rides the optimistic route since 2026-10-26
            // (PlatformHttpClientSocksOptimisticTest); this pins the java.net route.
            client.get("http://$ONION_HOST/status", emptyMap(), 20)
            val seen = assertNotNull(tor.await())
            // java.net's client offers 0x00 AND 0x02 (and, if 0x02 is picked, sends
            // the JVM's user.name with an empty password): one fixed class per
            // process, never a SocksIsolation credential.
            assertTrue(0x00 in seen.methods, "the default java.net route still offers no-auth")
            assertTrue(seen.username == null || !SocksIsolation.isValidCredential(seen.username) || seen.password.isNullOrEmpty())
            assertEquals(ATYP_DOMAINNAME, seen.atyp)
        }
    }

    @Test
    fun externalProxyClient_neverIsolates() {
        FakeTorSocks().use { proxy ->
            val client = PlatformHttpClient.socksProxy("127.0.0.1", proxy.port)
            assertFalse(client.supportsSocksIsolation)
            assertTrue(SocksIsolation.adopt(SocksIsolation.newCredential(), SocksIsolation.generation()))
            client.getIsolated("http://$ONION_HOST/", emptyMap(), 20, false, 0, SocksIsolation.newCredential())
            val seen = assertNotNull(proxy.await())
            assertTrue(seen.username == null || seen.username != SocksIsolation.current(),
                "the user's proxy never receives an isolation credential")
        }
    }

    @Test
    fun isolatedRouteFailure_namesNeitherTheOnionNorTheCredential() {
        // Nothing listens on the blocked port: connection refused on the isolated route.
        SocksPortRedirect.beginMove(9)   // 9 → BLOCKED_PORT (1): nothing can listen there
        val client = PlatformHttpClient.torProxy(9)
        val cred = SocksIsolation.newCredential()
        val r = client.getIsolated("http://$ONION_HOST/", emptyMap(), 5, false, 0, cred)
        assertEquals(-1, r.code)
        val body = r.body ?: ""
        assertFalse(body.contains("onion"), "no host in the failure text")
        assertFalse(body.contains(cred), "no credential in the failure text")
    }

    @Test
    fun handshake_rejectsAServerThatPicksNoAuth() {
        val serverSays = java.io.ByteArrayInputStream(byteArrayOf(0x05, 0x00))
        val sent = java.io.ByteArrayOutputStream()
        val e = runCatching {
            socks5UserPassHandshake(serverSays, sent, ONION_HOST, 80, SocksIsolation.newCredential(), SocksIsolation.PASSWORD)
        }.exceptionOrNull()
        assertTrue(e is java.io.IOException, "a no-auth pick must fail, never silently drop the isolation")
        assertTrue(sent.toByteArray().contentEquals(byteArrayOf(0x05, 0x01, 0x02)), "nothing but the greeting went out")
    }

    @Test
    fun onionLoopbackDns_resolvesNothing() {
        val a = OnionLoopbackDns.lookup(ONION_HOST).single()
        assertEquals(ONION_HOST, a.hostName, "the name travels with the placeholder, unresolved")
        assertEquals("127.0.0.1", a.hostAddress)
        assertTrue(runCatching { OnionLoopbackDns.lookup("example.com") }.exceptionOrNull() is java.net.UnknownHostException)
    }
}

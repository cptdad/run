package com.vg.run

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.IOException
import java.net.InetAddress
import java.net.ServerSocket
import java.net.SocketTimeoutException
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
 * OPTIMISTIC DATA route of the Android Tor client (2026-10-26): `GET /` and
 * `POST /peek` write their HTTP request right behind the SOCKS5 CONNECT instead of
 * after Tor's CONNECT reply ([Socks5OptimisticSocket] + [Socks5ReplyGateInputStream]).
 * Pinned against a fake SOCKS5 server on loopback (no network, no Tor):
 *  - the request bytes reach the server BEFORE it sends the CONNECT reply, and a
 *    non-eligible request (the destructive drain) still waits for the reply;
 *  - the reply tail is drained exactly for ATYP 1/3/4 and the HTTP response comes
 *    through intact;
 *  - rep != 0 fails the first read with fixed text (no onion in the failure);
 *  - the handshake is byte-identical to java.net's (same Tor isolation class as
 *    the default route, so the same joined rendezvous circuit);
 *  - the first-byte budget does not cover the CONNECT-reply phase, but still
 *    catches a stream that connected and then never answered;
 *  - the eligibility predicate.
 */
class PlatformHttpClientSocksOptimisticTest {

    private companion object {
        const val ONION_HOST = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion"
        const val OK_RESPONSE = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"
    }

    /** What the fake server saw. */
    private data class Seen(
        val methods: List<Int>,
        val username: String?,
        val password: String?,
        val host: String,
        /** The HTTP head (+ any body bytes in the same reads) that arrived BEFORE
         *  the CONNECT reply was sent; empty = nothing arrived early. */
        val earlyRequest: String,
        /** Everything of the request the server read in total. */
        val request: String,
    )

    /**
     * Accepts ONE client. Picks 0x02 if offered and [preferUserPass] (Tor's default),
     * else 0x00; then, before replying to the CONNECT, waits up to [earlyWaitMs] for
     * request bytes (recording what came), sleeps [replyDelayMs], answers with
     * [rep] / [atyp], then (on success) [response] — or nothing at all when null.
     */
    private class FakeTorSocks(
        private val atyp: Int = 0x01,
        private val rep: Int = 0x00,
        private val earlyWaitMs: Int = 3000,
        private val replyDelayMs: Long = 0,
        private val response: String? = OK_RESPONSE,
        private val preferUserPass: Boolean = true,
    ) : AutoCloseable {
        private val server = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))
        private val seen = ArrayBlockingQueue<Seen>(1)
        val port: Int get() = server.localPort

        init {
            thread(isDaemon = true, name = "fake-tor-socks-optimistic") {
                try {
                    server.accept().use { s ->
                        val input = DataInputStream(s.getInputStream())
                        val out = s.getOutputStream()
                        input.readUnsignedByte()
                        val n = input.readUnsignedByte()
                        val methods = (0 until n).map { input.readUnsignedByte() }
                        val pick = if (preferUserPass && 0x02 in methods) 0x02 else 0x00
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
                        input.readUnsignedByte() // ATYP (DOMAINNAME; pinned by the DNS tests)
                        val host = ByteArray(input.readUnsignedByte()).also { input.readFully(it) }.decodeToString()
                        input.readUnsignedByte(); input.readUnsignedByte()

                        // Phase 1: anything the client sends BEFORE our CONNECT reply.
                        val early = ByteArrayOutputStream()
                        s.soTimeout = earlyWaitMs
                        val buf = ByteArray(4096)
                        try {
                            while (!early.toString(Charsets.ISO_8859_1).contains("\r\n\r\n")) {
                                val r = input.read(buf)
                                if (r < 0) break
                                early.write(buf, 0, r)
                            }
                        } catch (_: SocketTimeoutException) {
                        }
                        if (replyDelayMs > 0) Thread.sleep(replyDelayMs)

                        // The CONNECT reply with the requested BND form.
                        val tail = when (atyp) {
                            0x01 -> byteArrayOf(10, 0, 0, 1, 0x1f, 0x40)
                            0x04 -> ByteArray(16) { it.toByte() } + byteArrayOf(0x1f, 0x40)
                            else -> byteArrayOf(9) + "relay.bnd".toByteArray() + byteArrayOf(0x1f, 0x40)
                        }
                        out.write(byteArrayOf(0x05, rep.toByte(), 0x00, atyp.toByte()) + tail); out.flush()

                        // Phase 2: the rest of the request (the wait-for-reply path
                        // sends it only now).
                        val all = ByteArrayOutputStream().apply { write(early.toByteArray()) }
                        s.soTimeout = 3000
                        try {
                            while (!all.toString(Charsets.ISO_8859_1).contains("\r\n\r\n")) {
                                val r = input.read(buf)
                                if (r < 0) break
                                all.write(buf, 0, r)
                            }
                        } catch (_: SocketTimeoutException) {
                        }
                        seen.offer(Seen(methods, user, pass, host, early.toString(Charsets.ISO_8859_1), all.toString(Charsets.ISO_8859_1)))
                        if (rep == 0 && response != null) {
                            out.write(response.toByteArray()); out.flush()
                        } else if (rep == 0) {
                            Thread.sleep(10_000) // connected, never answers
                        }
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

    // ---- (1) request before reply ------------------------------------------------

    @Test
    fun healthProbe_requestArrivesBeforeTheConnectReply() {
        FakeTorSocks().use { tor ->
            val r = PlatformHttpClient.torProxy(tor.port).get("http://$ONION_HOST/", emptyMap(), 20)
            assertEquals(200, r.code)
            assertEquals("hello", r.body)
            val seen = assertNotNull(tor.await())
            assertTrue(seen.earlyRequest.startsWith("GET / HTTP/1.1\r\n"), "the GET went out behind the CONNECT: <${seen.earlyRequest}>")
            assertEquals(ONION_HOST, seen.host, "the onion still reaches Tor unresolved")
        }
    }

    @Test
    fun batchPeek_requestAndBodyArriveBeforeTheConnectReply() {
        FakeTorSocks().use { tor ->
            val r = PlatformHttpClient.torProxy(tor.port)
                .post("http://$ONION_HOST/peek", "{}".toByteArray(), "application/json", emptyMap(), 20)
            assertEquals(200, r.code)
            val seen = assertNotNull(tor.await())
            assertTrue(seen.earlyRequest.startsWith("POST /peek HTTP/1.1\r\n"), "the POST went out behind the CONNECT")
        }
    }

    @Test
    fun drain_isNotOptimistic_itStillWaitsForTheReply() {
        FakeTorSocks(earlyWaitMs = 500).use { tor ->
            val r = PlatformHttpClient.torProxy(tor.port).get("http://$ONION_HOST/inbox/abc", emptyMap(), 20)
            assertEquals(200, r.code)
            val seen = assertNotNull(tor.await())
            assertEquals("", seen.earlyRequest, "a destructive drain must never ride ahead of the CONNECT reply")
            assertTrue(seen.request.startsWith("GET /inbox/abc HTTP/1.1\r\n"))
        }
    }

    @Test
    fun isolatedRequest_isNotOptimistic() {
        FakeTorSocks(earlyWaitMs = 500).use { tor ->
            val client = PlatformHttpClient.torProxy(tor.port)
            val r = client.getIsolated("http://$ONION_HOST/", emptyMap(), 20, false, 0, SocksIsolation.newCredential())
            assertEquals(200, r.code)
            assertEquals("", assertNotNull(tor.await()).earlyRequest)
        }
    }

    @Test
    fun externalProxy_isNotOptimistic() {
        FakeTorSocks(earlyWaitMs = 500).use { proxy ->
            val r = PlatformHttpClient.socksProxy("127.0.0.1", proxy.port).get("http://$ONION_HOST/", emptyMap(), 20)
            assertEquals(200, r.code)
            assertEquals("", assertNotNull(proxy.await()).earlyRequest, "the user's own proxy keeps the classic order")
        }
    }

    // ---- (2) exact reply drain per ATYP ------------------------------------------

    @Test
    fun replyTail_isDrainedExactly_forEveryAtyp() {
        for (atyp in listOf(0x01, 0x03, 0x04)) {
            FakeTorSocks(atyp = atyp).use { tor ->
                val r = PlatformHttpClient.torProxy(tor.port).get("http://$ONION_HOST/", emptyMap(), 20)
                assertEquals(200, r.code, "ATYP $atyp")
                assertEquals("hello", r.body, "ATYP $atyp: no SOCKS byte leaks into, and no HTTP byte is lost from, the response")
            }
        }
    }

    @Test
    fun gate_passesHttpBytesThroughUntouched_afterAnExactDrain() {
        val http = "HTTP/1.1 404 Not Found\r\n\r\n".toByteArray()
        val replies = listOf(
            byteArrayOf(0x05, 0, 0, 0x01, 1, 2, 3, 4, 0, 80),
            byteArrayOf(0x05, 0, 0, 0x04) + ByteArray(16) + byteArrayOf(0, 80),
            byteArrayOf(0x05, 0, 0, 0x03, 3) + "abc".toByteArray() + byteArrayOf(0, 80),
        )
        for (reply in replies) {
            val gate = Socks5ReplyGateInputStream(ByteArrayInputStream(reply + http))
            assertEquals(0, gate.available(), "SOCKS bytes are never reported as available HTTP")
            assertTrue(http.contentEquals(gate.readBytes()))
        }
    }

    // ---- (3) rep != 0 ------------------------------------------------------------

    @Test
    fun gate_refusedReply_failsTheFirstReadAndEveryLaterOne() {
        val gate = Socks5ReplyGateInputStream(ByteArrayInputStream(byteArrayOf(0x05, 0x04, 0, 0x01, 0, 0, 0, 0, 0, 0)))
        val first = runCatching { gate.read(ByteArray(16)) }.exceptionOrNull()
        assertTrue(first is IOException)
        assertEquals("SOCKS5 connect rejected (rep=4)", first.message)
        assertTrue(runCatching { gate.read() }.exceptionOrNull() is IOException)
    }

    @Test
    fun refusedReply_isATransportFailure_namingNeitherTheOnion() {
        FakeTorSocks(rep = 0x04).use { tor ->
            val r = PlatformHttpClient.torProxy(tor.port).get("http://$ONION_HOST/", emptyMap(), 20)
            assertEquals(-1, r.code)
            assertFalse((r.body ?: "").contains("onion"), "no host in the failure text")
        }
    }

    // ---- same isolation class as the default route -------------------------------

    @Test
    fun handshake_isByteIdenticalToTheJavaNetRoute() {
        for (preferUserPass in listOf(true, false)) {
            val plain = FakeTorSocks(earlyWaitMs = 200, preferUserPass = preferUserPass).use { tor ->
                PlatformHttpClient.torProxy(tor.port).get("http://$ONION_HOST/status", emptyMap(), 20)
                assertNotNull(tor.await())
            }
            val optimistic = FakeTorSocks(preferUserPass = preferUserPass).use { tor ->
                PlatformHttpClient.torProxy(tor.port).get("http://$ONION_HOST/", emptyMap(), 20)
                assertNotNull(tor.await())
            }
            assertTrue(optimistic.earlyRequest.isNotEmpty(), "sanity: the second one was optimistic")
            assertEquals(plain.methods, optimistic.methods, "same greeting")
            assertEquals(plain.username, optimistic.username, "same SOCKS username → same Tor isolation class")
            assertEquals(plain.password, optimistic.password, "same SOCKS password → same Tor isolation class")
        }
    }

    @Test
    fun open_writesExactlyJavaNetsBytes_andNeverReadsTheConnectReply() {
        // Server: picks 02, accepts the auth — and nothing else is readable, so a
        // read of the CONNECT reply here would throw EOF.
        val sent = ByteArrayOutputStream()
        socks5OptimisticOpen(ByteArrayInputStream(byteArrayOf(0x05, 0x02, 0x01, 0x00)), sent, "ab.onion", 80, userName = "u0_a7")
        val expected = byteArrayOf(0x05, 0x02, 0x00, 0x02) +
            byteArrayOf(0x01, 5) + "u0_a7".toByteArray() + byteArrayOf(0) +
            byteArrayOf(0x05, 0x01, 0x00, 0x03, 8) + "ab.onion".toByteArray() + byteArrayOf(0, 80)
        assertTrue(expected.contentEquals(sent.toByteArray()))
    }

    // ---- first-byte budget ----------------------------------------------------

    @Test
    fun firstByteBudget_doesNotCoverTheConnectReplyPhase() {
        // The reply takes 2.5 s (Tor's descriptor/intro/rendezvous), the budget is 1 s.
        FakeTorSocks(replyDelayMs = 2500).use { tor ->
            val r = PlatformHttpClient.torProxy(tor.port).get("http://$ONION_HOST/", emptyMap(), 20, false, 1)
            assertEquals(200, r.code, "the budget starts at the CONNECT reply, not before it")
        }
    }

    @Test
    fun firstByteBudget_stillCatchesAConnectedStreamThatNeverAnswers() {
        FakeTorSocks(response = null).use { tor ->
            val started = System.nanoTime()
            val r = PlatformHttpClient.torProxy(tor.port).get("http://$ONION_HOST/", emptyMap(), 20, false, 1)
            val secs = (System.nanoTime() - started) / 1e9
            assertEquals(-1, r.code)
            assertTrue(r.firstByteTimeout, "booked as the first-byte stalled-stream signal")
            assertTrue(secs < 10, "abandoned at the budget, not the call timeout ($secs s)")
        }
    }

    // ---- (4) eligibility ---------------------------------------------------------

    @Test
    fun eligibility_isExactlyGetRootAndPostPeek() {
        assertTrue(isOptimisticEligible("GET", "/"))
        assertTrue(isOptimisticEligible("POST", "/peek"))
        assertFalse(isOptimisticEligible("GET", "/peek"))
        assertFalse(isOptimisticEligible("GET", "/inbox/x"), "the destructive drain")
        assertFalse(isOptimisticEligible("PUT", "/x"))
        assertFalse(isOptimisticEligible("POST", "/telemetry/connect"))
        assertFalse(isOptimisticEligible("POST", "/"))
        assertFalse(isOptimisticEligible("DELETE", "/"))
        assertFalse(isOptimisticEligible("get", "/"), "method compare is exact")
        assertFalse(isOptimisticEligible("POST", "/peek/"))
        assertFalse(isOptimisticEligible("POST", "/PEEK"))
    }

    @Test
    fun eligibility_comparesThePathOnly_theQueryIsNotPartOfIt() {
        // Decision: `GET /?x=1` is the same read-only root GET → eligible. The
        // transport hands the predicate OkHttp's encodedPath, which excludes the query.
        FakeTorSocks().use { tor ->
            val r = PlatformHttpClient.torProxy(tor.port).get("http://$ONION_HOST/?x=1", emptyMap(), 20)
            assertEquals(200, r.code)
            assertTrue(assertNotNull(tor.await()).earlyRequest.startsWith("GET /?x=1 HTTP/1.1\r\n"))
        }
    }
}

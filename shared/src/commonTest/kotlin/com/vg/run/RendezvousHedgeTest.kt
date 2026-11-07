package com.vg.run

import kotlin.concurrent.Volatile
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource

// ---------------------------------------------------------------------------
// RENDEZVOUS HEDGE (2026-10-25) — the shared decision, the session isolation
// class, the SOCKS5/RFC 1929 bytes, and MessageManager's one-hedge-per-transport
// wiring. Both platforms run this code; the transports only carry the credential.
// ---------------------------------------------------------------------------

private const val RH_URL = "http://relay.test"

/**
 * The transport for the wiring tests. [mainMode] decides the normal probe GET:
 *  - ANSWER: 404 at once (the first rendezvous was fast);
 *  - BLOCK:  parked on the "slow rendezvous" until [cancelNewCircuitSensitive]
 *            (what OkHttp `Call.cancel()` / NWConnection.cancel() do), max 5 s;
 *  - FAIL:   transport failure at once.
 * The isolated (hedge) GET answers 404 at once and records its credential.
 */
private class HedgeRelay(
    private val mainMode: Mode,
    private val isolating: Boolean = true,
) : RelayHttp {
    enum class Mode { ANSWER, BLOCK, BLOCK_SHORT, FAIL }

    @Volatile var cancelled = false
    @Volatile var mainCalls = 0
    val isolatedCredentials = mutableListOf<String>()

    override val supportsSocksIsolation: Boolean get() = isolating

    override fun post(url: String, body: ByteArray, contentType: String, headers: Map<String, String>, timeoutSeconds: Int) =
        HttpResult(code = 202, body = "", isSuccess = true)
    override fun put(url: String, body: ByteArray, contentType: String, headers: Map<String, String>, timeoutSeconds: Int) =
        HttpResult(code = 202, body = "", isSuccess = true)
    override fun get(url: String, headers: Map<String, String>, timeoutSeconds: Int): HttpResult =
        get(url, headers, timeoutSeconds, false, 0)
    override fun get(url: String, headers: Map<String, String>, timeoutSeconds: Int, cancelOnNewCircuit: Boolean, firstByteTimeoutSeconds: Int): HttpResult {
        mainCalls++
        return when (mainMode) {
            Mode.ANSWER -> HttpResult(code = 404, body = "not found", isSuccess = false)
            Mode.FAIL -> HttpResult(code = -1, body = "refused", isSuccess = false)
            Mode.BLOCK, Mode.BLOCK_SHORT -> {
                val cap = if (mainMode == Mode.BLOCK) 5.seconds else 0.3.seconds
                val mark = TimeSource.Monotonic.markNow()
                while (!cancelled && mark.elapsedNow() < cap) { /* parked on the slow rendezvous */ }
                HttpResult(code = -1, body = "Canceled", isSuccess = false)
            }
        }
    }
    override fun get(url: String, headers: Map<String, String>, timeoutSeconds: Int, cancelOnNewCircuit: Boolean, firstByteTimeoutSeconds: Int, socksIsolation: String): HttpResult {
        synchronizedAdd(socksIsolation)
        return HttpResult(code = 404, body = "not found", isSuccess = false)
    }
    override fun cancelNewCircuitSensitive(): Int { cancelled = true; return 1 }

    private val lock = SyncLock()
    private fun synchronizedAdd(c: String) = lock.withLock { isolatedCredentials += c }
    fun credentials(): List<String> = lock.withLock { isolatedCredentials.toList() }
}

/** Waits (spinning, bounded) for [cond]; the hedge runs on Dispatchers.Default. */
private fun eventually(cond: () -> Boolean): Boolean {
    val mark = TimeSource.Monotonic.markNow()
    while (mark.elapsedNow() < 5.seconds) { if (cond()) return true }
    return cond()
}

class RendezvousHedgeTest {

    @BeforeTest
    fun setUp() {
        SocksIsolation.reset()
        ConnectionLog.clear()
        RendezvousHedge.setNoHedgeControl(false)
    }

    @AfterTest
    fun tearDown() {
        SocksIsolation.reset()
        RendezvousHedge.setNoHedgeControl(false)
    }

    // --- the pure decision -----------------------------------------------

    private fun decide(
        now: Long, inFlight: Boolean = true, coldStart: Long? = 0L, desc: Long? = 0L,
        warm: Boolean = false, newnym: Boolean = false, spent: Boolean = false, iso: Boolean = true,
    ) = RendezvousHedge.decide(now, inFlight, coldStart, desc, warm, newnym, spent, iso)

    @Test
    fun firesHedgeDelayAfterTheLaterOfProbeStartAndDescriptor() {
        val h = RendezvousHedge.HEDGE_DELAY_MS
        // Descriptor 10 s before the probe (warm-up fetched it): measured from the probe.
        assertEquals(RendezvousHedge.Action.WAIT, decide(now = 10_000 + h - 1, coldStart = 10_000, desc = 0).action)
        assertEquals(RendezvousHedge.Action.FIRE, decide(now = 10_000 + h, coldStart = 10_000, desc = 0).action)
        // Descriptor 4 s AFTER the probe started: measured from the descriptor.
        assertEquals(RendezvousHedge.Action.WAIT, decide(now = 4_000 + h - 1, coldStart = 0, desc = 4_000).action)
        assertEquals(RendezvousHedge.Action.FIRE, decide(now = 4_000 + h, coldStart = 0, desc = 4_000).action)
    }

    @Test
    fun waitNeverExceedsThePollStep_andUnknownDescriptorKeepsWaiting() {
        val s = decide(now = 0, coldStart = 0, desc = 0)
        assertEquals(RendezvousHedge.Action.WAIT, s.action)
        assertTrue(s.recheckInMs in 1..RendezvousHedge.POLL_MS)
        val unknown = decide(now = 60_000, desc = null)
        assertEquals(RendezvousHedge.Action.WAIT, unknown.action, "no descriptor = a hedge would queue on the same fetch")
        assertEquals(RendezvousHedge.POLL_MS, unknown.recheckInMs)
    }

    @Test
    fun hedgeNeverFires_afterWarm_afterNewnym_onceSpent_orWithoutIsolation() {
        val late = 60_000L
        assertEquals(RendezvousHedge.Action.NEVER, decide(late, warm = true).action, "never after the first answer")
        assertEquals(RendezvousHedge.Action.NEVER, decide(late, newnym = true).action, "never once a NEWNYM rung fired")
        assertEquals(RendezvousHedge.Action.NEVER, decide(late, spent = true).action, "one per transport")
        assertEquals(RendezvousHedge.Action.NEVER, decide(late, iso = false).action, "external proxy / direct")
    }

    @Test
    fun hedgePausesWithoutALiveProbeOrColdStart() {
        val late = 60_000L
        assertEquals(RendezvousHedge.Action.PAUSE, decide(late, inFlight = false).action, "no timer without a live probe")
        assertEquals(RendezvousHedge.Action.PAUSE, decide(late, coldStart = null).action)
    }

    // --- the isolation class ----------------------------------------------

    @Test
    fun credentials_areFreshValidAndShort() {
        val a = SocksIsolation.newCredential()
        val b = SocksIsolation.newCredential()
        assertEquals(32, a.length)
        assertTrue(SocksIsolation.isValidCredential(a))
        assertNotEquals(a, b, "per hedge, never reused")
        assertFalse(SocksIsolation.isValidCredential(""))
        assertFalse(SocksIsolation.isValidCredential("a b"))
        assertFalse(SocksIsolation.isValidCredential("x".repeat(256)))
    }

    @Test
    fun adoption_isRefusedAcrossATorRestart_andResetReturnsToTheDefaultClass() {
        assertNull(SocksIsolation.current(), "default class = today's handshake")
        val gen = SocksIsolation.generation()
        val c = SocksIsolation.newCredential()
        SocksIsolation.reset()   // a new Tor process between fire and answer
        assertFalse(SocksIsolation.adopt(c, gen))
        assertNull(SocksIsolation.current())
        assertTrue(SocksIsolation.adopt(c, SocksIsolation.generation()))
        assertEquals(c, SocksIsolation.current())
        SocksIsolation.reset()
        assertNull(SocksIsolation.current())
    }

    // --- the bytes ----------------------------------------------------------

    @Test
    fun socks5Bytes_matchRfc1928And1929() {
        assertTrue(Socks5Wire.greetingUserPass().contentEquals(byteArrayOf(5, 1, 2)), "ONLY method 0x02")
        val auth = Socks5Wire.userPassRequest("ab", "r")
        assertTrue(auth.contentEquals(byteArrayOf(1, 2, 'a'.code.toByte(), 'b'.code.toByte(), 1, 'r'.code.toByte())))
        val conn = Socks5Wire.connectDomain("x.onion", 80)
        assertTrue(conn.contentEquals(byteArrayOf(5, 1, 0, 3, 7) + "x.onion".encodeToByteArray() + byteArrayOf(0, 80)), "ATYP DOMAINNAME (SOCKS5h)")
        assertEquals(6, Socks5Wire.replyTailLength(0x01))
        assertEquals(18, Socks5Wire.replyTailLength(0x04))
        assertEquals(-1, Socks5Wire.replyTailLength(0x03))
        assertEquals(-2, Socks5Wire.replyTailLength(0x7f))
    }

    // --- MessageManager wiring ------------------------------------------------

    private fun manager(relay: HedgeRelay, clock: () -> Long): MessageManager =
        MessageManager(InMemoryVault(), RH_URL, relay).apply {
            rendHedgeDescriptorAtMs = { 0L }
            rendHedgeNowMs = clock
        }

    /** A clock that jumps 5 s per read: the hedge is due on the watcher's first tick. */
    private fun jumpingClock(): () -> Long {
        val lock = SyncLock()
        var t = 0L
        return { lock.withLock { t += 5_000; t } }
    }

    @Test
    fun hedgeWins_probeBooksItsAnswer_andTheSessionAdoptsItsClass() {
        val relay = HedgeRelay(HedgeRelay.Mode.BLOCK)
        val mgr = manager(relay, jumpingClock())

        assertTrue(mgr.isRelayReachable(), "the hedge's real answer ends the blocked probe")
        assertTrue(mgr.hasCompletedRelayRoundTrip())
        assertTrue(relay.cancelled, "the slow default-class probe was aborted")
        val creds = relay.credentials()
        assertEquals(1, creds.size, "exactly one hedge")
        assertEquals(creds.single(), SocksIsolation.current(), "the winner's class becomes the session's")
        assertEquals(1, relay.mainCalls, "no extra probe after the hedge answered")

        val lines = ConnectionLog.snapshot()
        val probeLine = lines.single { it.code == ConnectionLog.Code.PROBE_OK }
        assertTrue(probeLine.text.endsWith("(rendezvous hedge)"))
        assertTrue(lines.any { it.text.startsWith("rendezvous hedge won in ") && it.code == null }, "uncoded: not in the telemetry")
        assertTrue(lines.any { it.text == RendezvousHedge.FIRED_PHRASE && it.code == null })
        assertTrue(lines.none { creds.single() in it.text }, "the credential never reaches a line")
    }

    @Test
    fun fastFirstRendezvous_neverHedges() {
        val relay = HedgeRelay(HedgeRelay.Mode.ANSWER)
        val mgr = manager(relay) { 0L }   // frozen clock: the hedge is never due
        assertTrue(mgr.isRelayReachable())
        assertTrue(mgr.isRelayReachable(), "warm probes never arm it either")
        assertTrue(relay.credentials().isEmpty())
        assertNull(SocksIsolation.current(), "the default class stays")
        assertTrue(ConnectionLog.snapshot().none { it.text.startsWith("rendezvous hedge") })
    }

    @Test
    fun noHedgeAfterANewnym_orOnANonIsolatingTransport() {
        val afterNewnym = HedgeRelay(HedgeRelay.Mode.FAIL)
        val m1 = manager(afterNewnym, jumpingClock())
        m1.noteNewCircuitRequested()
        assertFalse(m1.isRelayReachable())

        val external = HedgeRelay(HedgeRelay.Mode.FAIL, isolating = false)
        val m2 = manager(external, jumpingClock())
        assertFalse(m2.isRelayReachable())

        assertTrue(afterNewnym.credentials().isEmpty(), "the NEWNYM rungs own recovery")
        assertTrue(external.credentials().isEmpty(), "external proxy / direct never hedge")
        assertNull(SocksIsolation.current())
    }

    @Test
    fun controlArm_spendsTheHedgeWithoutSendingIt() {
        if (!RendezvousHedge.setNoHedgeControl(true)) return   // release-flavoured test binary: arm refused
        // Each attempt parks 0.3 s: long enough for the watcher's first tick.
        val relay = HedgeRelay(HedgeRelay.Mode.BLOCK_SHORT)
        val mgr = manager(relay, jumpingClock())
        assertFalse(mgr.isRelayReachable(), "no hedge = the slow rendezvous is all there is")
        assertTrue(eventually { ConnectionLog.snapshot().any { it.text == RendezvousHedge.CONTROL_PHRASE } })
        assertTrue(relay.credentials().isEmpty())
        assertNull(SocksIsolation.current())
    }
}

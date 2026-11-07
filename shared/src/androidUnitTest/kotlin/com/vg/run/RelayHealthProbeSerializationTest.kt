package com.vg.run

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// ONE health GET in flight per transport — needs REAL threads (same reason
// CapRotationRaceTest / ContactEditCounterRaceTest live here rather than in
// commonTest).
//
// Since the cold cadence dropped to ~1-2 s, two callers can genuinely overlap:
// the manual "Reconnect" fires its own immediate probe (iOS
// AppState.reconnectRelay), and a relayCheckJob/relayCheckTask that was
// cancelled and replaced cannot interrupt the blocking transport call the old
// one already made. A second GET would learn nothing — Tor attaches both to the
// same rendezvous work — while doubling the load on exactly the cold circuit we
// are trying to establish.
//
// The contract:
//   1. a caller that loses the race opens NO second stream;
//   2. it gets the last verdict a probe actually COMPLETED with — never a
//      fabricated one, in either direction;
//   3. the in-flight flag is released even when the transport throws, so one
//      bad probe cannot wedge reachability for the life of the session.
// ---------------------------------------------------------------------------

/** Blocks inside the FIRST get() until released; later gets answer immediately. */
private class GatedRelay(private val code: Int) : RelayHttp {
    val gets = AtomicInteger(0)
    val entered = CountDownLatch(1)
    val release = CountDownLatch(1)
    override fun post(url: String, body: ByteArray, contentType: String, headers: Map<String, String>, timeoutSeconds: Int) =
        HttpResult(code = code, body = "", isSuccess = false)
    override fun put(url: String, body: ByteArray, contentType: String, headers: Map<String, String>, timeoutSeconds: Int) =
        HttpResult(code = code, body = "", isSuccess = false)
    override fun get(url: String, headers: Map<String, String>, timeoutSeconds: Int): HttpResult {
        if (gets.incrementAndGet() == 1) {
            entered.countDown()
            release.await(10, TimeUnit.SECONDS)
        }
        return HttpResult(code = code, body = "", isSuccess = code in 200..299)
    }
}

/** Answers 404 (up) until [gate] is armed, then blocks the next get(). */
private class WarmThenGatedRelay : RelayHttp {
    val gate = AtomicBoolean(false)
    val entered = CountDownLatch(1)
    val release = CountDownLatch(1)
    val gets = AtomicInteger(0)
    override fun post(url: String, body: ByteArray, contentType: String, headers: Map<String, String>, timeoutSeconds: Int) =
        HttpResult(code = 202, body = "", isSuccess = true)
    override fun put(url: String, body: ByteArray, contentType: String, headers: Map<String, String>, timeoutSeconds: Int) =
        HttpResult(code = 202, body = "", isSuccess = true)
    override fun get(url: String, headers: Map<String, String>, timeoutSeconds: Int): HttpResult {
        gets.incrementAndGet()
        if (gate.get()) {
            entered.countDown()
            release.await(10, TimeUnit.SECONDS)
            return HttpResult(code = -1, body = "", isSuccess = false)
        }
        return HttpResult(code = 404, body = "not found", isSuccess = false)
    }
}

class RelayHealthProbeSerializationTest {

    @Test
    fun aSecondProbeDoesNotOpenASecondStream() {
        val relay = GatedRelay(code = -1)
        val mgr = MessageManager(InMemoryVault(), "http://relay.test", relay)

        val winner = Thread { mgr.isRelayReachable() }
        winner.start()
        assertTrue(relay.entered.await(10, TimeUnit.SECONDS), "the first probe must reach the transport")
        assertEquals(1, relay.gets.get(), "exactly one GET is in flight")

        // The loser must return WITHOUT touching the transport.
        val loser = mgr.isRelayReachable()
        assertEquals(1, relay.gets.get(), "a concurrent probe must not open a second onion stream")
        assertFalse(loser, "nothing has completed yet — the honest answer is the last verdict (false)")

        relay.release.countDown()
        winner.join(10_000)
        assertFalse(winner.isAlive, "the winner must finish")
    }

    @Test
    fun theLoserGetsTheLastCOMPLETEDVerdict_notAFabricatedOne() {
        val relay = WarmThenGatedRelay()
        val mgr = MessageManager(InMemoryVault(), "http://relay.test", relay)

        // A completed probe says the relay is up.
        assertTrue(mgr.isRelayReachable())

        // Now a probe is in flight and will eventually fail. A caller that loses
        // the race reports the last COMPLETED verdict (true) rather than inventing
        // a miss — which is exactly the "hold the last value" direction both
        // platform loops' consecutive-miss hysteresis already applies.
        relay.gate.set(true)
        val t = Thread { mgr.isRelayReachable() }
        t.start()
        assertTrue(relay.entered.await(10, TimeUnit.SECONDS))
        val before = relay.gets.get()
        assertTrue(mgr.isRelayReachable(), "the loser reports the last completed verdict")
        assertEquals(before, relay.gets.get(), "…and issues no request of its own")

        relay.release.countDown()
        t.join(10_000)
        assertFalse(t.isAlive)

        // That probe completed with a MISS, so the verdict a later loser would see
        // has moved with it — the value is only ever written by a probe that ran.
        relay.gate.set(false)
        assertTrue(mgr.isRelayReachable(), "a completed probe on a live relay reports up again")
    }

    @Test
    fun aThrowingTransportStillReleasesTheGate() {
        val relay = object : RelayHttp {
            val gets = AtomicInteger(0)
            override fun post(url: String, body: ByteArray, contentType: String, headers: Map<String, String>, timeoutSeconds: Int) =
                HttpResult(code = -1, body = "", isSuccess = false)
            override fun put(url: String, body: ByteArray, contentType: String, headers: Map<String, String>, timeoutSeconds: Int) =
                HttpResult(code = -1, body = "", isSuccess = false)
            override fun get(url: String, headers: Map<String, String>, timeoutSeconds: Int): HttpResult {
                gets.incrementAndGet()
                throw IllegalStateException("bridge holder not registered")
            }
        }
        val mgr = MessageManager(InMemoryVault(), "http://relay.test", relay)

        assertFalse(mgr.isRelayReachable())
        val afterFirst = relay.gets.get()
        assertTrue(afterFirst > 0, "the probe must have hit the transport")
        // If the gate leaked, this call would short-circuit and issue no GET.
        assertFalse(mgr.isRelayReachable())
        assertTrue(relay.gets.get() > afterFirst, "the in-flight gate must be released on the throwing path")
    }
}

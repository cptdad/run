package com.vg.run

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// The push-deregistration pass runs its DELETEs IN PARALLEL (2026-10-25,
// chain:push Case A: three sequential 60 s waits made one ladder pass ~192 s).
// Real threads: every DELETE blocks until all three are in flight at once, which
// a sequential pass can never reach (the latch would time out instead). Plus the
// per-request budget: each DELETE simulates the transport honouring its own
// timeout, so a pass of three dead circuits ends in ~one budget, not three.
// ---------------------------------------------------------------------------

private const val PP_URL = "http://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion"
private const val PP_CAP = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
private val PP_REFS = listOf("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC", "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD")
    .map { InboundInboxRef(it, PP_CAP) }

private abstract class DeleteOnly : RelayHttp {
    override fun post(url: String, body: ByteArray, contentType: String, headers: Map<String, String>, timeoutSeconds: Int): HttpResult =
        throw AssertionError("no POST")
    override fun put(url: String, body: ByteArray, contentType: String, headers: Map<String, String>, timeoutSeconds: Int): HttpResult =
        throw AssertionError("no PUT")
    override fun get(url: String, headers: Map<String, String>, timeoutSeconds: Int): HttpResult =
        throw AssertionError("no GET")
}

class PushDeregParallelismTest {

    @Test
    fun allDeletesAreInFlightAtOnce() {
        val allIn = CountDownLatch(PP_REFS.size)
        val maxConcurrent = AtomicInteger(0)
        val now = AtomicInteger(0)
        val http = object : DeleteOnly() {
            override fun delete(url: String, headers: Map<String, String>, timeoutSeconds: Int): HttpResult {
                maxConcurrent.accumulateAndGet(now.incrementAndGet(), ::maxOf)
                allIn.countDown()
                // A sequential pass would sit here alone until the 5 s bound.
                val together = allIn.await(5, TimeUnit.SECONDS)
                now.decrementAndGet()
                return if (together) HttpResult(200, null, true) else HttpResult(-1, "sequential", false)
            }
        }
        val failed = kotlinx.coroutines.runBlocking {
            PushRegistration.unregisterAllParallelReturningFailures(http, PP_URL, PP_REFS, race = null)
        }
        assertTrue(failed.isEmpty(), "a DELETE ran alone: the pass is not parallel")
        assertEquals(PP_REFS.size, maxConcurrent.get())
    }

    @Test
    fun deadCircuits_passEndsInOneBudget_notThree() {
        // Each DELETE "hangs" for its own budget (scaled: 1 s per budget second
        // would make the test slow, so 25 s is modelled as 250 ms) then fails.
        val http = object : DeleteOnly() {
            override fun delete(url: String, headers: Map<String, String>, timeoutSeconds: Int): HttpResult {
                Thread.sleep(timeoutSeconds * 10L)
                return HttpResult(-1, "timeout", false)
            }
        }
        val t0 = System.nanoTime()
        val failed = kotlinx.coroutines.runBlocking {
            PushRegistration.unregisterAllParallelReturningFailures(http, PP_URL, PP_REFS, race = null)
        }
        val elapsedMs = (System.nanoTime() - t0) / 1_000_000
        assertEquals(PP_REFS, failed)
        // One budget = 250 ms; sequential would be 750 ms.
        assertTrue(elapsedMs < 600, "pass took $elapsedMs ms — DELETEs were not parallel")
    }

    @Test
    fun parallelism_isBounded() {
        val refs = (0 until 10).map { i -> InboundInboxRef(('A' + i).toString().repeat(32), PP_CAP) }
        val now = AtomicInteger(0)
        val maxConcurrent = AtomicInteger(0)
        val http = object : DeleteOnly() {
            override fun delete(url: String, headers: Map<String, String>, timeoutSeconds: Int): HttpResult {
                maxConcurrent.accumulateAndGet(now.incrementAndGet(), ::maxOf)
                Thread.sleep(30)
                now.decrementAndGet()
                return HttpResult(200, null, true)
            }
        }
        val failed = kotlinx.coroutines.runBlocking {
            PushRegistration.unregisterAllParallelReturningFailures(http, PP_URL, refs, race = null)
        }
        assertTrue(failed.isEmpty())
        assertTrue(maxConcurrent.get() <= PushRegistration.DEREG_PARALLELISM, "max in flight ${maxConcurrent.get()}")
    }
}

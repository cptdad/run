package com.vg.run

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * [terminateTorChild] — the SIGTERM / SIGKILL step of `TorManager.stop()`.
 *
 * Its contract is what lets `stop()` ALWAYS drop the process handle and publish
 * Idle: it never throws, and it reports "confirmed gone" only when the child
 * really is (so `stop()` purges the session ephemera only then). The old stop()
 * ran the termination inside one try with the Idle write, so an
 * InterruptedException from `waitFor` skipped Idle and left the session owner
 * seeing a live Tor.
 *
 * `java.lang.Process` is abstract, so a fake drives every branch without a
 * daemon; `waitFor(timeout)` returns at once.
 */
class TorChildTerminationTest {

    /**
     * [diesOnTerm] / [diesOnKill]: whether the child exits after destroy() /
     * destroyForcibly(). [waitThrows] / [destroyThrows]: the failure to inject.
     */
    private class FakeProcess(
        private val diesOnTerm: Boolean = true,
        private val diesOnKill: Boolean = true,
        private val waitThrows: Exception? = null,
        private val destroyThrows: RuntimeException? = null,
    ) : Process() {
        var alive = true
        var destroyCalls = 0
        var destroyForciblyCalls = 0

        override fun getOutputStream(): OutputStream = ByteArrayOutputStream()
        override fun getInputStream(): InputStream = ByteArrayInputStream(ByteArray(0))
        override fun getErrorStream(): InputStream = ByteArrayInputStream(ByteArray(0))
        override fun waitFor(): Int {
            waitThrows?.let { throw it }
            return 0
        }
        override fun waitFor(timeout: Long, unit: TimeUnit): Boolean {
            waitThrows?.let { throw it }
            return !alive
        }
        override fun exitValue(): Int = if (alive) throw IllegalThreadStateException() else 0
        override fun isAlive(): Boolean = alive
        override fun destroy() {
            destroyCalls++
            destroyThrows?.let { throw it }
            if (diesOnTerm) alive = false
        }
        override fun destroyForcibly(): Process {
            destroyForciblyCalls++
            if (diesOnKill) alive = false
            return this
        }
    }

    @Test
    fun exitsOnSigterm_isConfirmedGone_withoutSigkill() {
        val p = FakeProcess(diesOnTerm = true)
        assertTrue(terminateTorChild(p))
        assertEquals(1, p.destroyCalls)
        assertEquals(0, p.destroyForciblyCalls, "a child that exits on SIGTERM must never be SIGKILLed")
    }

    @Test
    fun ignoresSigterm_isKilledOnce_andConfirmedGoneWhenItDies() {
        val p = FakeProcess(diesOnTerm = false, diesOnKill = true)
        assertTrue(terminateTorChild(p))
        assertEquals(1, p.destroyForciblyCalls)
    }

    @Test
    fun neverDies_isNotConfirmed() {
        val p = FakeProcess(diesOnTerm = false, diesOnKill = false)
        assertFalse(terminateTorChild(p), "a child still alive after SIGKILL must not be reported gone")
        assertEquals(1, p.destroyForciblyCalls)
    }

    @Test
    fun interruptedWait_returnsFalse_neverThrows_andReassertsTheInterrupt() {
        val p = FakeProcess(diesOnTerm = false, waitThrows = InterruptedException("test"))
        try {
            assertFalse(terminateTorChild(p))
            assertTrue(Thread.interrupted(), "the interrupt must be re-asserted on the thread")
        } finally {
            Thread.interrupted() // never leak the flag into the next test
        }
        assertTrue(p.destroyForciblyCalls >= 1, "an interrupted wait still SIGKILLs the child")
    }

    @Test
    fun throwingDestroy_returnsFalse_neverThrows() {
        val p = FakeProcess(destroyThrows = IllegalStateException("test"))
        assertFalse(terminateTorChild(p))
        assertFalse(Thread.currentThread().isInterrupted)
    }

    @Test
    fun noChild_isConfirmedGone() {
        assertTrue(terminateTorChild(null))
    }
}

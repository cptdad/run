package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

// The export needs a FRESH credential verification. These pin the
// token (single-use, time-boxed), the verification policy (mirrors change-PIN:
// record-before-check, cap => WIPE, outage/biometric failure => DEFERRED) and that
// MoveManager refuses to freeze anything without a token.
/** Test-only gate that is always pre-granted (re-usable across retries within one test). */
internal class TestGrantedGate : MoveExportAuthGate() {
    override fun consume(): Boolean = true
}

class MoveExportAuthTest {

    @Test
    fun gate_isSingleUse() {
        var now = 0L
        val gate = MoveExportAuthGate { now }
        assertFalse(gate.consume(), "no grant, no token")
        gate.grant()
        assertTrue(gate.consume())
        assertFalse(gate.consume(), "a token is spent by its first use")
    }

    @Test
    fun aGrantOlderThanTheFreshWindow_authorisesNothing_butOneAtTheEdgeStillDoes() {
        var now = 1_000L
        val gate = MoveExportAuthGate { now }
        gate.grant()
        now += MoveExportAuthGate.FRESH_WINDOW_MS + 1
        assertFalse(gate.consume(), "a stale verification must not authorise an export")
        gate.grant()
        now += MoveExportAuthGate.FRESH_WINDOW_MS
        assertTrue(gate.consume())
    }

    @Test
    fun evaluate_recordsBeforeVerifying_andWrongCounts() {
        val ops = mutableListOf<String>()
        val out = MoveExportAuth.evaluate(
            recordAttempt = { ops += "record"; false },
            verify = { ops += "verify"; false },
            strongAuthRequired = { ops += "strongReq"; true },
            strongAuth = { ops += "strong"; true },
        )
        assertEquals(MoveExportAuth.Outcome.WRONG, out)
        assertEquals(listOf("record", "verify"), ops)
    }

    @Test
    fun evaluate_capWipesWithoutVerifying() {
        var verified = false
        val out = MoveExportAuth.evaluate(
            recordAttempt = { true },
            verify = { verified = true; true },
            strongAuthRequired = { false },
            strongAuth = { true },
        )
        assertEquals(MoveExportAuth.Outcome.WIPE, out)
        assertFalse(verified)
    }

    @Test
    fun evaluate_transientOutageDefers_neverWipes() {
        val out = MoveExportAuth.evaluate(
            recordAttempt = { throw KeyUnavailableException("locked keybag") },
            verify = { true },
            strongAuthRequired = { false },
            strongAuth = { true },
        )
        assertEquals(MoveExportAuth.Outcome.DEFERRED, out)
    }

    @Test
    fun evaluate_leverB_needsTheBiometricToo() {
        fun run(bio: Boolean) = MoveExportAuth.evaluate(
            recordAttempt = { false }, verify = { true },
            strongAuthRequired = { true }, strongAuth = { bio },
        )
        assertEquals(MoveExportAuth.Outcome.OK, run(true))
        assertEquals(MoveExportAuth.Outcome.DEFERRED, run(false))
    }

    @Test
    fun evaluate_nonLeverB_skipsTheBiometric() {
        var prompted = false
        val out = MoveExportAuth.evaluate(
            recordAttempt = { false }, verify = { true },
            strongAuthRequired = { false }, strongAuth = { prompted = true; true },
        )
        assertEquals(MoveExportAuth.Outcome.OK, out)
        assertFalse(prompted)
    }
}

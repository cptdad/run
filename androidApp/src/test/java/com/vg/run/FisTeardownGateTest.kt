package com.vg.run

import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.FixMethodOrder
import org.junit.Test
import org.junit.runners.MethodSorters

/**
 * The state machine behind the 2026-09-17 FIS-lockout fix, tested off-device —
 * which is why [FisTeardownGate] is a separate object with no Android or
 * Play-Services surface at all, exactly like [VendorPushIdentityEpoch].
 *
 * What it guards, measured on a Samsung A20e (API 30, Play Services 26.33,
 * firebase-bom 34.19.0 / firebase-installations 19.1.2) and confirmed against
 * the SDK's bytecode: the teardown's own `FirebaseMessaging.deleteToken()`
 * re-reads `PersistedInstallation.<key>.json` a few hundred ms in, on the FIS
 * network executor. Deleting that file in between makes the SDK read the
 * absent-file default (`ATTEMPT_MIGRATION`, no fid, no auth token) and, because
 * `doNetworkCallIfNecessary` re-registers only for `isErrored() ||
 * isUnregistered()`, fall through to `authTokens:generate` for a NULL fid. FIS
 * answers 400 INVALID_ARGUMENT, `RequestLimiter` treats any non-2xx/401/404 as a
 * non-retryable configuration error and blocks EVERY later FIS request for 24
 * hours, so `currentToken()` returns null and re-enabling notifications fails
 * for the rest of the process.
 *
 * The three properties below are what make the gate safe: it can only ever
 * DELAY a delete, never cancel one, and it is unarmed in a fresh process —
 * the state in which the sweep deletes everything.
 *
 * NAME_ASCENDING because the object is a process-wide singleton and exactly one
 * property — the initial value of its counter — is only observable before
 * anything has touched it.
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
class FisTeardownGateTest {

    @After
    fun tearDown() {
        FisTeardownGate.resetForTest()
    }

    /**
     * A fresh process must start UNARMED: that is the state in which
     * `sweepLocalArtifacts` removes the Installations state file, so anything
     * that defaulted the other way would suppress the deletion of a live bearer
     * credential (Fid + AuthToken + RefreshToken) forever.
     */
    @Test
    fun t1_startsUnarmed() {
        assertFalse("a fresh process must not defer any deletion", FisTeardownGate.isPending())
    }

    @Test
    fun t2_armDefersUntilReleased() {
        FisTeardownGate.arm()
        assertTrue("an in-flight teardown must defer the state-file deletion", FisTeardownGate.isPending())
        FisTeardownGate.release()
        assertFalse("a settled teardown must stop deferring", FisTeardownGate.isPending())
    }

    /**
     * Two teardowns can overlap — the wipe path and the opt-out path both call
     * `destroyLocalPushIdentity`, and the enable-failure branch can fire while an
     * earlier chain is still in flight. The FIRST settle must not un-defer the
     * SECOND chain, or the file is deleted under a chain that is still reading
     * it, which is the whole failure this gate exists for.
     */
    @Test
    fun t3_overlappingTeardownsAreCounted() {
        FisTeardownGate.arm()
        FisTeardownGate.arm()
        FisTeardownGate.release()
        assertTrue(
            "the second teardown's chain is still in flight — the state file must stay deferred",
            FisTeardownGate.isPending(),
        )
        FisTeardownGate.release()
        assertFalse(FisTeardownGate.isPending())
    }

    /**
     * The gate can only ever DELAY a delete. A stray/duplicate release (the
     * settle arriving after the cap already released, a caller that got its
     * pairing wrong) must never drive the counter negative, because a negative
     * counter would read as "not pending" for the NEXT teardown too — and that
     * one would then delete the file mid-chain.
     */
    @Test
    fun t4_releaseNeverGoesNegative() {
        FisTeardownGate.release()
        FisTeardownGate.release()
        assertFalse(FisTeardownGate.isPending())

        FisTeardownGate.arm()
        assertTrue(
            "an over-released counter must not swallow the next teardown's deferral",
            FisTeardownGate.isPending(),
        )
        FisTeardownGate.release()
        assertFalse(FisTeardownGate.isPending())
    }
}

package com.vg.run

import kotlin.time.TimeSource

// ---------------------------------------------------------------------------
// MoveExportAuth — the fresh-credential gate in front of "Move to new device".
//
// The export used to need only an OPEN vault, so
// anyone holding an unlocked session could ship the whole vault (and every
// future message) to a phone of their own, defeating MAXIMUM's forced re-auth.
// The export now requires the user to re-enter the current credential — and, on
// a Lever B (auth-bound DB key) vault, to pass the strong biometric again.
//
// Two pieces, deliberately split:
//  * [MoveExportAuthGate] — a short-lived, single-use token held by MoveManager.
//    MoveManager.runExport refuses unless it can consume a fresh token, so a UI
//    that skips the prompt cannot start an export (lowest sensible layer).
//  * [MoveExportAuth.evaluate] — the verification policy, a MIRROR of the
//    change-PIN flow: the wrong guess is recorded against the SAME daily
//    change-PIN abuse budget ([ChangePinAttemptStore]) BEFORE the check, the cap
//    triggers the caller's emergency wipe, and a transient key outage DEFERS
//    (never counts toward a wipe, never grants).
// ---------------------------------------------------------------------------

private val monoOrigin = TimeSource.Monotonic.markNow()
private fun defaultMonoMs(): Long = monoOrigin.elapsedNow().inWholeMilliseconds

/**
 * Single-use, time-boxed proof that the credential was just re-verified.
 * Monotonic clock, so a wall-clock jump can neither extend nor shorten it.
 * Not synchronised: a lost race can at worst consume a token one call early,
 * which fails closed (the user re-enters the credential).
 */
open class MoveExportAuthGate(private val monoMs: () -> Long = ::defaultMonoMs) {
    private var grantedAtMs: Long? = null

    /** Record a successful verification. Call ONLY after [MoveExportAuth.evaluate] returned OK. */
    fun grant() {
        grantedAtMs = monoMs()
    }

    /** True (and the token is spent) iff a verification landed within [FRESH_WINDOW_MS]. */
    open fun consume(): Boolean {
        val at = grantedAtMs ?: return false
        grantedAtMs = null
        val age = monoMs() - at
        return age in 0..FRESH_WINDOW_MS
    }

    fun clear() {
        grantedAtMs = null
    }

    companion object {
        /**
         * Generous enough for the Android bounded transport wait that sits between
         * the prompt and `beginExport` (~150 s worst case), short enough that a
         * token cannot outlive the screen that earned it.
         */
        const val FRESH_WINDOW_MS = 300_000L
    }
}

object MoveExportAuth {

    enum class Outcome {
        /** Credential (and, on Lever B, the biometric) verified — the gate may be granted. */
        OK,
        /** Wrong credential. Already counted against the daily budget. */
        WRONG,
        /** The daily cap was reached: the CALLER must run its emergency wipe. */
        WIPE,
        /** Transient outage or a cancelled/failed biometric: nothing granted, nothing wiped; retry. */
        DEFERRED,
    }

    /**
     * Pure policy (unit-tested). Blocking and heavy (KDF + possible biometric
     * prompt) — call OFF the main thread.
     *
     * @param recordAttempt  records one change-PIN abuse attempt and returns true at
     *   the cap; throws [KeyUnavailableException] on a transient store failure.
     * @param verify  the credential check (the same one change-PIN uses).
     * @param strongAuthRequired  true on a Lever B (auth-bound DB key) vault.
     * @param strongAuth  the strong-biometric unwrap round trip; false on cancel/failure.
     */
    fun evaluate(
        recordAttempt: () -> Boolean,
        verify: () -> Boolean,
        strongAuthRequired: () -> Boolean,
        strongAuth: () -> Boolean,
    ): Outcome {
        val atCap = try {
            recordAttempt()
        } catch (_: KeyUnavailableException) {
            return Outcome.DEFERRED
        }
        if (atCap) return Outcome.WIPE
        if (!verify()) return Outcome.WRONG
        if (strongAuthRequired() && !strongAuth()) return Outcome.DEFERRED
        return Outcome.OK
    }

    /**
     * Production wiring: verify [credential] and, on OK, grant [gate]. The WIPE
     * outcome is returned for the platform to act on (it owns the wipe routine).
     */
    fun verifyAndGrant(
        credential: String,
        selector: VaultSelector,
        attempts: ChangePinAttemptStore,
        gate: MoveExportAuthGate,
    ): Outcome {
        val outcome = evaluate(
            recordAttempt = { attempts.recordAttemptAndCheckLimit() },
            verify = { selector.verifyCredential(credential) },
            strongAuthRequired = { selector.isDbKeyAuthBound() },
            strongAuth = { selector.verifyStrongAuth() },
        )
        if (outcome == Outcome.OK) gate.grant() else gate.clear()
        return outcome
    }
}

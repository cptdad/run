package com.vg.run

/**
 * The ViewModel's own evaluator for the two foreground lock deadlines: the
 * periodic re-auth at MAXIMUM and Lever C (idle auto-lock, release only).
 *
 * WHY it exists (security review iteration 3, S2 F1): MainActivity's Runnable used
 * to be the ONLY evaluator of both deadlines. onPause removes it, and the next
 * Activity instance re-posted it from onResume with the full 10 s coarse delay. An
 * attacker holding an unlocked phone could rotate it (or flip the dark-theme tile)
 * every few seconds: each configuration change recreated the Activity, the Runnable
 * never ran, and neither the forced re-auth nor the idle lock ever fired.
 * MainActivity now evaluates immediately on resume, and this backstop runs in
 * `viewModelScope`, which survives Activity recreation. So the deadlines hold even
 * when no Activity is attached.
 *
 * The Activity stays the PRIMARY: it renders the countdown overlay inside the
 * warning window, and its Lever-C path is the full `finishAndRemoveTask` teardown.
 * The backstop fires the re-auth exactly at the deadline. `lockForReauth` is a
 * no-op once the vault is closed, so a double fire is harmless. It fires Lever C
 * only [ACTIVITY_GRACE_MS] AFTER the deadline, so an attached Activity always gets
 * there first and the ordinary path is unchanged. Pure, so the decision is
 * unit-testable without an Activity or a ViewModel.
 */
internal object LockPolicyBackstop {

    /** How long after the Lever-C deadline the backstop waits for the Activity's own lock. */
    const val ACTIVITY_GRACE_MS: Long = 2_000L

    /** Longest sleep between two evaluations (the Activity's coarse cadence). */
    const val MAX_CHECK_INTERVAL_MS: Long = 10_000L

    /** Shortest sleep, so a deadline a few ms away never spins the loop. */
    const val MIN_CHECK_INTERVAL_MS: Long = 250L

    enum class Action { NONE, REAUTH_LOCK, IDLE_LOCK }

    data class Decision(val action: Action, val nextCheckInMs: Long)

    /**
     * @param vaultOpen no vault = nothing to lock (the deadlines are only armed
     *   while a vault is open, and are cleared by every lock and wipe).
     * @param reauthDeadlineElapsedMs the periodic re-auth deadline, or null when
     *   it is not armed.
     * @param idleTimeoutMs Lever C's timeout for this session, or null when Lever C
     *   does not apply (debug builds).
     */
    fun decide(
        nowElapsedMs: Long,
        vaultOpen: Boolean,
        reauthDeadlineElapsedMs: Long?,
        idleTimeoutMs: Long?,
        lastInteractionElapsedMs: Long,
    ): Decision {
        if (!vaultOpen) return Decision(Action.NONE, MAX_CHECK_INTERVAL_MS)
        val reauthRemaining = reauthDeadlineElapsedMs?.let { it - nowElapsedMs } ?: Long.MAX_VALUE
        if (reauthRemaining <= 0) return Decision(Action.REAUTH_LOCK, MAX_CHECK_INTERVAL_MS)
        val idleRemaining = idleTimeoutMs?.let {
            it + ACTIVITY_GRACE_MS - (nowElapsedMs - lastInteractionElapsedMs)
        } ?: Long.MAX_VALUE
        if (idleRemaining <= 0) return Decision(Action.IDLE_LOCK, MAX_CHECK_INTERVAL_MS)
        val next = minOf(reauthRemaining, idleRemaining, MAX_CHECK_INTERVAL_MS)
            .coerceAtLeast(MIN_CHECK_INTERVAL_MS)
        return Decision(Action.NONE, next)
    }
}

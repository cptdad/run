package com.vg.run

/**
 * Budget ledger for the WARM-transport NEWNYM rung
 * ([MessageManager.shouldFireWarmNewnym]) — the two caps that rung is allowed to
 * spend: [MessageManager.WARM_NEWNYM_MAX_PER_RUN] per DARK RUN (one stall, from
 * the first full-budget probe timeout to the next probe that answers) and
 * [MessageManager.WARM_NEWNYM_MAX_PER_WINDOW] per rolling
 * [MessageManager.WARM_NEWNYM_WINDOW_MS] across all runs (the long-session cap —
 * see "ANONYMITY COST" in MessageManager's companion).
 *
 * Owned by the platform SESSION, not by a MessageManager, because a transport
 * re-wire builds a new manager and the hourly budget must survive it: Android
 * `RunViewModel.warmNewnymLedger`, iOS `IosAppController.warmNewnymLedger`. One
 * class for both so the accounting cannot drift between platforms.
 *
 * Every timestamp is on [MessageManager.warmRungNowMs] (process-wide
 * monotonic). Not thread-safe by design: each platform touches it only from its
 * single health-loop context (Android the relay-check coroutine on Main, iOS the
 * main actor).
 */
class WarmNewnymLedger {
    /** Dark-run key ([MessageManager]'s dark-run start) the per-run counters
     *  belong to; null before any run was seen. */
    private var runKey: Long? = null

    /** Warm fires spent in the CURRENT dark run. */
    var firesThisRun: Int = 0
        private set

    private var lastFireThisRunAtMs: Long? = null

    /** Fire times inside the rolling window; never more than
     *  [MessageManager.WARM_NEWNYM_MAX_PER_WINDOW] entries are kept useful, and
     *  the list is pruned on every read. */
    private val fireTimesMs = ArrayList<Long>()

    /** A different dark-run start than the one the counters belong to = a new
     *  run: the per-run budget re-arms (the window budget does not). */
    internal fun syncRun(darkRunStartedAtMs: Long) {
        if (runKey == darkRunStartedAtMs) return
        runKey = darkRunStartedAtMs
        firesThisRun = 0
        lastFireThisRunAtMs = null
    }

    /** ms since this run's previous fire; 0 when there was none (the predicate
     *  ignores it for the first fire). */
    internal fun msSinceLastFireThisRun(nowMs: Long): Long =
        lastFireThisRunAtMs?.let { nowMs - it } ?: 0L

    /**
     * Fires within the last [MessageManager.WARM_NEWNYM_WINDOW_MS]. An entry
     * from the FUTURE (cannot happen on a monotonic clock) keeps counting —
     * fail closed — until the clock passes it.
     */
    internal fun firesInWindow(nowMs: Long): Int {
        fireTimesMs.removeAll { nowMs - it >= MessageManager.WARM_NEWNYM_WINDOW_MS }
        return fireTimesMs.size
    }

    internal fun noteFired(nowMs: Long) {
        firesThisRun++
        lastFireThisRunAtMs = nowMs
        fireTimesMs.add(nowMs)
    }

    /**
     * The control channel refused the NEWNYM (down): stop asking for the rest
     * of THIS run — the heavy ladders own it (Android escalates to a Tor
     * restart, iOS to `.stalled` / relaunch). Spends no window budget: nothing
     * reached Tor. Same spirit as the cold rung latching its counter at the cap.
     */
    fun retireRun() {
        firesThisRun = MessageManager.WARM_NEWNYM_MAX_PER_RUN
    }
}

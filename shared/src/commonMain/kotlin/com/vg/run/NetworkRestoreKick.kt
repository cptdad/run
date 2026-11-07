package com.vg.run

import kotlin.time.TimeSource

/**
 * NETWORK-RESTORE KICK (2026-10-25) — the shared DECISION half of "the phone's
 * network came back: tell the embedded Tor at once". The platform owners feed it
 * default-network observations (Android: `ConnectivityManager`
 * default-network callback in `RunViewModel`; iOS: `NWPathMonitor` in
 * `AppState`) and act when [due] says FIRE: one `SETCONF DisableNetwork=1` /
 * `=0` toggle on the command channel (`TorManager.kickForNetworkRestore`, both
 * platforms), the in-flight relay requests aborted, the stall watch re-armed and
 * the push opt-out ladder's backoff ended early.
 *
 * WHY (chain:push Case A, the device run of 2026-10-25, Pixel 7): the network was
 * restored at ~05:00:25 UTC but Tor reported its first guard back up only at
 * 05:10:21 (GUARD_UP), and the relay logged the opt-out's DELETE at 05:10:35 —
 * past the test's 600 s budget. While offline, every guard connection failed, so
 * Tor marked its guards unreachable and only retried them on its own ~10-minute
 * schedule. Nothing in the app told Tor the network was back; the toggle makes
 * it reopen every OR connection now (guards, consensus, descriptors and
 * identity are kept).
 *
 * RULES (all here, unit-tested — NetworkRestoreKickTest):
 *  - The FIRST observation is the BASELINE, never a restore — the callback a
 *    registration delivers for the network that is already up does nothing.
 *    A baseline of "no network" counts as an observed loss.
 *  - A restore is a usable network after an OBSERVED LOSS, or a switch to a
 *    DIFFERENT default network. The same network re-reported (capability
 *    churn) is not one.
 *  - DEBOUNCED: [due] fires only once the network has stayed usable for
 *    [debounceMs] since the latest restore event; a loss inside the window
 *    cancels it, a further restore restarts it.
 *  - RATE-LIMITED: never two fires within [minIntervalMs]; a restore inside that
 *    interval is DEFERRED to its end, never dropped (a flapping network's last
 *    restore is the one that matters).
 *  - NOTHING happens on a loss: no `DisableNetwork=1` — Tor notices by itself.
 *
 * The network KEY is an opaque per-network handle (Android's network handle,
 * iOS's preferred interface) used for equality only — it never reaches a log
 * line, the connection log or the wire. Thread-safe (lock-guarded): Android's
 * callbacks arrive on the ConnectivityManager thread.
 */
class NetworkRestoreKick(
    private val debounceMs: Long = DEBOUNCE_MS,
    private val minIntervalMs: Long = MIN_INTERVAL_MS,
) {
    private val lock = SyncLock()
    private var baselineSeen = false
    /** The current default network's key; null = none usable. */
    private var currentKey: String? = null
    private var lossObserved = false
    /** When the latest restore event arrived; null = no restore pending. */
    private var pendingSinceMs: Long? = null
    private var lastFireAtMs: Long? = null

    /** One [due] verdict: FIRE now, or re-check after [waitMs] (>= 0), or
     *  nothing pending ([waitMs] == [NO_RECHECK]). [rateLimited] = the wait is
     *  the rate limit's, not the debounce's (the owner logs that once). */
    class Decision internal constructor(val fire: Boolean, val waitMs: Long, val rateLimited: Boolean = false) {
        override fun toString(): String = "Decision(fire=$fire, waitMs=$waitMs, rateLimited=$rateLimited)"
    }

    /** [observeAt] on the class's own monotonic clock. */
    fun observe(networkKey: String?): Long = observeAt(networkKey, nowMs())

    /**
     * Feed one default-network observation: [networkKey] is the usable default
     * network's opaque key, or null when there is none (lost / unsatisfied).
     * Returns how long until [due] should be asked, or [NO_RECHECK].
     */
    internal fun observeAt(networkKey: String?, nowMs: Long): Long = lock.withLock {
        if (!baselineSeen) {
            baselineSeen = true
            currentKey = networkKey
            lossObserved = networkKey == null
            return@withLock NO_RECHECK
        }
        if (networkKey == null) {
            lossObserved = true
            currentKey = null
            pendingSinceMs = null
            return@withLock NO_RECHECK
        }
        val switched = networkKey != currentKey
        currentKey = networkKey
        if (!lossObserved && !switched) return@withLock NO_RECHECK
        lossObserved = false
        pendingSinceMs = nowMs
        debounceMs
    }

    /** [observeLostAt] on the class's own monotonic clock. */
    fun observeLost(networkKey: String): Long = observeLostAt(networkKey, nowMs())

    /**
     * Android's `onLost(network)`: a loss only if it is the CURRENT default
     * network (a lost non-default network changes nothing). iOS reports an
     * unsatisfied path as `observe(null)` instead.
     */
    internal fun observeLostAt(networkKey: String, nowMs: Long): Long {
        val isCurrent = lock.withLock { baselineSeen && currentKey == networkKey }
        return if (isCurrent) observeAt(null, nowMs) else NO_RECHECK
    }

    /** True while a usable network is known and no loss is outstanding. */
    fun isNetworkUp(): Boolean = lock.withLock { baselineSeen && currentKey != null }

    /** [dueAt] on the class's own monotonic clock. */
    fun due(): Decision = dueAt(nowMs())

    /**
     * Is the pending restore due? A FIRE has already been booked (the rate-limit
     * clock starts) and cleared the pending restore, so a repeated call can never
     * fire twice for one restore.
     */
    internal fun dueAt(nowMs: Long): Decision = lock.withLock {
        val since = pendingSinceMs ?: return@withLock Decision(false, NO_RECHECK)
        if (currentKey == null) {
            pendingSinceMs = null
            return@withLock Decision(false, NO_RECHECK)
        }
        val settled = nowMs - since
        if (settled < debounceMs) return@withLock Decision(false, debounceMs - settled)
        val last = lastFireAtMs
        if (last != null && nowMs - last < minIntervalMs) {
            return@withLock Decision(false, minIntervalMs - (nowMs - last), rateLimited = true)
        }
        pendingSinceMs = null
        lastFireAtMs = nowMs
        Decision(true, NO_RECHECK)
    }

    /** Why a due kick did not reach Tor. Closed vocabulary — the [text] is the
     *  only thing ever logged. */
    enum class SkipReason(val text: String) {
        NOT_EMBEDDED_TOR("not embedded Tor"),
        TOR_NOT_RUNNING("Tor not running"),
        TOR_RETRYING("Tor internal retry in flight"),
        RELAUNCH_REQUIRED("Tor needs an app relaunch"),
        CONTROL_DOWN("control channel down"),
        PORT_HANDOUT("SOCKS port hand-out in progress"),
        REFUSED("Tor refused the network toggle"),
    }

    companion object {
        /** The network must stay up this long before the kick (a re-associating
         *  Wi-Fi often reports available → lost → available within a second). */
        const val DEBOUNCE_MS: Long = 2_000L
        /** The kick's own minimum spacing — independent of every other rung's. */
        const val MIN_INTERVAL_MS: Long = 15_000L
        const val NO_RECHECK: Long = -1L

        // Fixed phrases — identical on both platforms (they call these helpers).
        // No code: the connect-telemetry vocabulary is unchanged, so these lines
        // stay in the panel / debug log and never travel.
        const val KICK_SENT_PHRASE = "network restored: tor kick sent"
        const val LOST_PHRASE = "network lost: waiting for it to return"
        const val SKIP_PREFIX = "network restore: skipped"

        fun skipLine(reason: SkipReason): String = "$SKIP_PREFIX (${reason.text})"
        fun deferredLine(waitMs: Long): String =
            "network restore: kick deferred ${(waitMs + 999) / 1000} s (rate limit)"

        fun logKickSent() = log(KICK_SENT_PHRASE)
        fun logLost() = log(LOST_PHRASE)
        fun logSkip(reason: SkipReason) = log(skipLine(reason))
        fun logDeferred(waitMs: Long) = log(deferredLine(waitMs))

        private fun log(line: String) {
            platformLog("NetRestore", line)
            ConnectionLog.append(ConnectionLog.Kind.STALL, line)
        }

        private val CLOCK_ORIGIN = TimeSource.Monotonic.markNow()
        private fun nowMs(): Long = CLOCK_ORIGIN.elapsedNow().inWholeMilliseconds
    }
}

package com.vg.run

// ---------------------------------------------------------------------------
// BOUNDED TOR KEEP-ALIVE (Android only, 2026-10-12).
//
// Backgrounding Rún is a WHOLE-SESSION teardown (MainActivity.onStop →
// finishAndRemoveTask → RunViewModel.onCleared → lockSession(stopTor = true)):
// vault closed, Tink keyset wiped, MessageManager / transport scrubbed. All of
// that is UNCHANGED. The one thing this file changes is the last step: instead
// of `TorManager.stop()`, the live Tor child is handed to a keeper that stops
// it [KEEP_ALIVE_MS] after backgrounding unless the NEXT session reclaims it
// first. A quick return then skips the Tor bootstrap AND keeps Tor's in-RAM
// onion-descriptor cache (a v3 descriptor is never cached on disk), so the
// first relay request goes straight to intro/rendezvous.
//
// What is kept: the Tor CHILD PROCESS only (guards, consensus, descriptor
// cache, circuits — all of which already survive on disk or are pure network
// state). What is NOT kept: the vault, any key, any MessageManager, any
// capability. A parked Tor has no session hooks bound ([TorSessionHooks]
// falls back to inert answers) and nothing in the app talks through it until
// a new session has been unlocked.
//
// iOS sibling: commonMain `BackgroundTorKeepAlive` + AppState's
// "Bounded Tor keep-alive" — iOS-shaped: tor_main is once per process, so the
// whole PROCESS stays alive (vault locked) for the background-task budget the
// OS grants instead of a parked child, and exits at its end. Same gates in
// spirit, same reuse phrase + TOR_REUSED code.
//
// Everything decision-shaped lives here, pure Kotlin with an injected
// scheduler, so the state machine is unit-tested without an Android framework
// (TorKeepAliveTest). The Android glue (Handler, foreground service) lives in
// TorKeepAliveHolder / TorKeepAliveService.
// ---------------------------------------------------------------------------

/**
 * The keeper's state machine. Generic over the kept object so tests can use a
 * fake; production instantiates it with [TorManager].
 *
 * States: IDLE → (arm) ARMED → (park) PARKED → (reclaim | expire | discard) IDLE.
 * The expiry timer is started at [arm] — i.e. at BACKGROUNDING, which is what
 * the 2-minute promise is measured from — and runs through PARKED.
 *
 * NOT thread-safe by design: every caller runs on the Android main thread
 * (Activity/ViewModel lifecycle callbacks, the main-Looper expiry timer and the
 * service callbacks), which also serialises a stop of the parked child against
 * the next session's speculative start (two Tor children on one DataDirectory
 * would trip Tor's lock file and fall into the corrupt-state discard path).
 *
 * @param schedule posts [action] after [delayMs]; returns a canceller.
 * @param stopTor ordinary teardown of a kept instance (working dirs PRESERVED —
 *   `TorManager.stop()`), used on expiry and on a dead instance at reclaim.
 * @param discardTor wipe-path teardown (`TorManager.stopAndDiscardState()`).
 * @param releaseService drops the foreground service that keeps the process
 *   alive; called exactly once per arm, whichever way the keep-alive ends.
 * @param nowMs a SLEEP-INCLUSIVE clock (`SystemClock.elapsedRealtime` in
 *   production). [reclaim] refuses a keeper older than [keepAliveMs] on it, so
 *   the bound holds in wall time even if [schedule]'s uptime-based timer was
 *   stretched by deep sleep (review 2026-11-06, S2 F4).
 */
class TorKeepAlive<T : Any>(
    private val schedule: (delayMs: Long, action: () -> Unit) -> (() -> Unit),
    private val stopTor: (T) -> Unit,
    private val discardTor: (T) -> Unit,
    private val releaseService: () -> Unit,
    private val keepAliveMs: Long = KEEP_ALIVE_MS,
    private val nowMs: () -> Long = { System.nanoTime() / 1_000_000L },
) {

    enum class State { IDLE, ARMED, PARKED }

    /** What [reclaim] found. */
    sealed class Reclaim<out T> {
        /** A healthy parked instance — the new session adopts it. */
        data class Warm<T>(val tor: T) : Reclaim<T>()
        /** A keep-alive ended without reuse since the last reclaim (timer, OS
         *  timeout, or the parked child was no longer usable). Start cold. */
        data object Expired : Reclaim<Nothing>()
        /** Nothing was kept (first launch of the process, gate refused, …). */
        data object Cold : Reclaim<Nothing>()
    }

    var state: State = State.IDLE
        private set

    private var parked: T? = null
    private var cancelTimer: (() -> Unit)? = null
    /** [nowMs] at the current [arm]; meaningful only while not IDLE. */
    private var armedAtMs: Long = 0L

    /** Latched when a keep-alive ends WITHOUT reuse; consumed by [reclaim] so
     *  the next session's panel can say why it is starting cold. */
    private var expiredSinceReclaim = false

    /**
     * Backgrounding: the gates already passed ([shouldKeepAlive]) and the
     * foreground service has been requested. Starts the expiry clock. Returns
     * false (and changes nothing) unless IDLE — a second arm without an
     * intervening reclaim/expiry is a lifecycle the app does not produce, and
     * refusing is the conservative answer (the caller stops Tor as before).
     */
    fun arm(): Boolean {
        if (state != State.IDLE) return false
        state = State.ARMED
        armedAtMs = nowMs()
        cancelTimer = schedule(keepAliveMs) { expire() }
        return true
    }

    /**
     * The session teardown hands [tor] over. Accepted only while ARMED and only
     * when [connected] (a bootstrapping / failed instance is not worth keeping);
     * otherwise the arm is dropped (timer cancelled, service released) and the
     * caller stops Tor exactly as it always did. Returns whether the keeper now
     * OWNS [tor].
     */
    fun park(tor: T, connected: Boolean): Boolean {
        if (state != State.ARMED || !connected) {
            if (state == State.ARMED) endArm()
            return false
        }
        parked = tor
        state = State.PARKED
        return true
    }

    /**
     * A new session begins. Always leaves the keeper IDLE with no timer and no
     * service. [isUsable] is re-checked HERE (the child can die while parked);
     * an unusable one is stopped before returning so the caller's cold start
     * never races it for the DataDirectory. So is an OVER-AGE one: past
     * [keepAliveMs] since [arm] on the sleep-inclusive clock, the timer should
     * already have stopped it, and a late timer must not turn into reuse.
     */
    fun reclaim(isUsable: (T) -> Boolean): Reclaim<T> {
        val tor = parked
        val wasArmed = state != State.IDLE
        val overAge = wasArmed && nowMs() - armedAtMs > keepAliveMs
        if (wasArmed) endArm()
        if (tor != null) {
            if (!overAge && isUsable(tor)) {
                expiredSinceReclaim = false
                return Reclaim.Warm(tor)
            }
            stopTor(tor)
            expiredSinceReclaim = false
            return Reclaim.Expired
        }
        if (expiredSinceReclaim) {
            expiredSinceReclaim = false
            return Reclaim.Expired
        }
        return Reclaim.Cold
    }

    /**
     * The keep-alive window is over (main-Looper timer) or the OS ended the
     * service (`Service.onTimeout`, `onDestroy`). Stops the parked child the
     * ordinary way — working dirs preserved, exactly like the old teardown.
     * Idempotent.
     */
    fun expire() {
        if (state == State.IDLE) return
        val tor = parked
        endArm()
        expiredSinceReclaim = true
        if (tor != null) stopTor(tor)
    }

    /**
     * Any WIPE. The parked child (if any) dies through the discard path, never
     * the preserving one, and nothing is left latched for the next session.
     * Idempotent; safe in every state.
     */
    fun discard() {
        val tor = parked
        if (state != State.IDLE) endArm()
        expiredSinceReclaim = false
        if (tor != null) discardTor(tor)
    }

    private fun endArm() {
        cancelTimer?.invoke()
        cancelTimer = null
        parked = null
        state = State.IDLE
        releaseService()
    }

    companion object {
        /** THE keep-alive window, measured from backgrounding. One constant. */
        const val KEEP_ALIVE_MS: Long = 120_000L

        /**
         * Connection-log panel phrases (fixed text, no identifier, deliberately
         * UNCODED — the relay's telemetry allowlist is not widened for them).
         * Read by both the producer (RunViewModel) and the tests.
         */
        const val PHRASE_REUSED = "reused warm Tor from the previous session"
        const val PHRASE_EXPIRED = "warm Tor expired - starting cold"

        /**
         * The gate, evaluated at BACKGROUNDING. Keep Tor alive only when ALL hold:
         *  - this is not a wipe teardown ([isWipe]) — every wipe stops and
         *    DISCARDS Tor at once, as before;
         *  - Tor is Connected and not inside its own corrupt-state retry
         *    ([torConnected]) — nothing else is worth keeping;
         *  - [notKnownWedged]: an UNLOCKED session that never got a relay answer
         *    over this Tor refuses — backgrounding and returning is the user's
         *    "restart the app" remedy for a stuck connect, and it must keep
         *    yielding a FRESH daemon, not the same wedged one. Pre-unlock (no
         *    session evidence either way) passes;
         *  - the protection tier is provably below MAXIMUM.
         *
         * The tier: [liveTier] is read at backgrounding. `Present(CASUAL|PRIVATE)`
         * and `Absent` (legacy, never chosen) allow; `Present(MAXIMUM)` and
         * `Damaged` refuse (MAXIMUM's whole point is the shortest residue window;
         * a damaged blob already fails secure to MAXIMUM elsewhere). `Unreadable`
         * (the device key is momentarily out — on Android the master key is
         * unlocked-device-required, so a power-button lock racing onStop reads
         * this) falls back to [sessionTierAllowed], the same decision taken from
         * an authenticated read at this session's unlock; null (no unlock this
         * session) refuses.
         */
        fun shouldKeepAlive(
            isWipe: Boolean,
            torConnected: Boolean,
            notKnownWedged: Boolean,
            liveTier: ProtectionLevelRead,
            sessionTierAllowed: Boolean?,
        ): Boolean {
            if (isWipe || !torConnected || !notKnownWedged) return false
            return when (liveTier) {
                is ProtectionLevelRead.Unreadable -> sessionTierAllowed == true
                else -> tierAllowsKeepAlive(liveTier)
            }
        }

        /** The tier half of [shouldKeepAlive] for an AUTHENTICATED read. */
        fun tierAllowsKeepAlive(read: ProtectionLevelRead): Boolean = when (read) {
            is ProtectionLevelRead.Present -> read.level != ProtectionLevel.MAXIMUM
            is ProtectionLevelRead.Absent -> true
            else -> false
        }
    }
}

/**
 * The three session callbacks a [TorManager] calls back into (the session's
 * descriptor hedge, NEWNYM-accepted hook, hung-circuit gate), made REBINDABLE.
 *
 * A TorManager takes its hooks at construction. Before the keep-alive that was
 * fine — the instance died with the ViewModel that built it. A kept instance
 * outlives that ViewModel, so its hooks must (a) stop pointing at the cleared
 * ViewModel the moment it is cleared (no leak, no stale "relay answered"
 * latch) and (b) point at the NEW session's ViewModel once that one adopts
 * the instance. Every TorManager is therefore built with these forwarding
 * functions, and the owning ViewModel binds/unbinds itself.
 *
 * Unbound answers are INERT, never eager: no descriptor hedge, nothing to
 * abort on NEWNYM, and "already answered" so the hung-circuit rung closes
 * nothing while no session exists.
 */
class TorSessionHooks {
    private class Bound(
        val owner: Any,
        val descriptorHedge: () -> DescriptorHedge?,
        val onNewCircuitAccepted: () -> Unit,
        val hsCircuitAnswered: () -> Boolean,
        val onDescriptorStageStalled: () -> Unit,
    )

    @Volatile private var bound: Bound? = null

    fun bind(
        owner: Any,
        descriptorHedge: () -> DescriptorHedge?,
        onNewCircuitAccepted: () -> Unit,
        hsCircuitAnswered: () -> Boolean,
        onDescriptorStageStalled: () -> Unit = {},
    ) {
        bound = Bound(owner, descriptorHedge, onNewCircuitAccepted, hsCircuitAnswered, onDescriptorStageStalled)
    }

    /** Unbinds only if [owner] is still the bound one — a newer session that
     *  bound first must not be unbound by an older one's late teardown. */
    fun unbind(owner: Any) {
        if (bound?.owner === owner) bound = null
    }

    val isBound: Boolean get() = bound != null

    /** The bound session's [DescriptorHedge] (per-SESSION budget), or null = inert. */
    fun descriptorHedge(): DescriptorHedge? = bound?.descriptorHedge?.invoke()

    fun onNewCircuitAccepted() {
        bound?.onNewCircuitAccepted?.invoke()
    }

    fun hsCircuitAnswered(): Boolean = bound?.hsCircuitAnswered?.invoke() ?: true

    /** The bound session spends a NEWNYM on a stalled descriptor stage through
     *  its shared early-NEWNYM gate; unbound = nothing (inert). */
    fun onDescriptorStageStalled() {
        bound?.onDescriptorStageStalled?.invoke()
    }
}

package com.vg.run

// ---------------------------------------------------------------------------
// BOUNDED TOR KEEP-ALIVE AFTER BACKGROUNDING — the iOS shape (2026-10-23).
//
// Until now iOS recycled the process on EVERY `.background`: the vault locked,
// `TorManager.stop()` latched `relaunchRequired`, and ContentView `exit(0)`ed
// while invisible, so every open paid a cold Tor (fresh descriptor fetch, fresh
// intro/rendezvous circuits — prod 1.6.47: almost all connect time is AFTER
// bootstrap). It also produced the "crashes every other launch" report: the
// `exit(0)` landed 1.3-1.5 s after the app went NotVisible, and a user who
// re-tapped the icon inside that window foregrounded the process that was
// about to exit — it vanished (RBSProcessExitContext "voluntary", no crash
// report), and the next tap got a fresh process.
//
// What changes: on `.background` the vault still locks and wipes its key
// material EXACTLY as before. Only the Tor teardown + `exit(0)` move: they run
// when the iOS background-task budget is (nearly) used up — never while the app
// is in the foreground. A return inside that window REUSES the running Tor
// (tor_main is once per process, so it is the only Tor this process can ever
// have) — no bootstrap, and Tor's in-RAM onion descriptor and circuits survive.
//
// Android's sibling is `androidApp/.../TorKeepAlive.kt` (a parked child process
// + foreground service, 120 s). The GATES are the same in spirit (never on a
// wipe, never a non-Connected Tor, never a session that is known wedged, never
// at MAXIMUM); the WINDOW is iOS-shaped: it is the background-task budget the OS
// actually grants, read when the task starts (see [windowSeconds]).
//
// Everything decision-shaped lives here, pure Kotlin with no clock and no timer,
// so it is unit-tested on the JVM (BackgroundTorKeepAliveTest). The Swift glue
// (UIApplication background task, the main-queue deadline, the expiration
// handler, the device-lock observer) lives in AppState's "Bounded Tor
// keep-alive" section. Every method is called on the MAIN ACTOR only; that
// serialisation is what closes the exit race (see [deadline]).
// ---------------------------------------------------------------------------

/**
 * The single state flag the exit decision is taken against.
 *
 * States: IDLE → (arm) KEEPING → (foreground) IDLE, or → (deadline while still
 * backgrounded) TORN_DOWN. TORN_DOWN is terminal for the process: Tor has been
 * stopped (tor_main cannot run again), so nothing may re-arm it.
 *
 * Each [arm] issues a new TOKEN; every deadline source (the budget timer, the
 * background task's expiration handler, the device-lock notification) carries
 * the token it was armed with. [foreground] bumps the token, so a deadline that
 * was already queued on the main queue when the user came back is STALE and
 * refused — even if it is delivered after the foreground transition began.
 *
 * NOT thread-safe by design — every caller is on the main actor.
 */
class BackgroundTorKeepAlive {

    enum class Phase { IDLE, KEEPING, TORN_DOWN }

    var phase: Phase = Phase.IDLE
        private set

    private var token: Long = 0L

    val isKeeping: Boolean get() = phase == Phase.KEEPING

    /**
     * Backgrounding, gates already passed ([shouldKeepAlive]) and a background
     * task granted. Returns the token every deadline source must carry, or
     * [NO_TOKEN] once TORN_DOWN (the caller then takes the old immediate path).
     *
     * Re-arming while KEEPING (a background → inactive → background bounce that
     * never reached `.active`) is allowed: the old token dies with the new one.
     */
    fun arm(): Long {
        if (phase == Phase.TORN_DOWN) return NO_TOKEN
        token += 1
        phase = Phase.KEEPING
        return token
    }

    /**
     * The scene became ACTIVE. Returns true exactly when Tor was being kept —
     * i.e. this is a WARM RETURN and the caller must reuse the running Tor.
     * Invalidates every outstanding deadline token.
     */
    fun foreground(): Boolean {
        if (phase == Phase.TORN_DOWN) {
            // The teardown already began (TorManager.stop() blocks the main thread
            // for up to 2 s, so this `.active` was queued behind it). Not a warm
            // return — Tor is gone — but it VETOES the pending exit: see
            // [exitStillAllowed].
            foregroundedSinceTeardown = true
            return false
        }
        if (phase != Phase.KEEPING) return false
        token += 1
        phase = Phase.IDLE
        return true
    }

    /** Set by a [foreground] that arrived after the teardown began. */
    private var foregroundedSinceTeardown = false

    /**
     * The LAST check before `exit(0)`, taken one main-runloop turn after the
     * (blocking) `TorManager.stop()` so a foreground return queued during it has
     * been delivered: true only while TORN_DOWN, no [foreground] came in since,
     * and the app is [stillInBackground] at THIS moment. False = do not exit
     * (Tor is stopped; relaunchRequired drives the close-and-reopen hint and the
     * next `.background` recycles at once).
     */
    fun exitStillAllowed(stillInBackground: Boolean): Boolean =
        phase == Phase.TORN_DOWN && !foregroundedSinceTeardown && stillInBackground

    /**
     * The arm could not be backed by the OS (`beginBackgroundTask` returned
     * `.invalid` — no budget at all): back to IDLE, every token dead, and the
     * caller takes the old immediate teardown. No-op unless KEEPING.
     */
    fun disarm() {
        if (phase != Phase.KEEPING) return
        token += 1
        phase = Phase.IDLE
    }

    /**
     * A deadline source fired. Returns true — and moves to TORN_DOWN — ONLY when
     * all three hold: Tor is still being kept, [deadlineToken] is the CURRENT
     * arm's (not one a foreground transition already invalidated), and the app
     * is [stillInBackground] at THIS moment (read on the main actor by the
     * caller, `UIApplication.applicationState == .background` — `.inactive`
     * means the user is coming back, so it is NOT background). On true the
     * caller stops Tor and exits; on false it must not.
     *
     * A refused deadline leaves the phase unchanged: a KEEPING keeper whose
     * deadline landed during a foreground transition is settled by the
     * [foreground] that follows (warm return).
     */
    fun deadline(deadlineToken: Long, stillInBackground: Boolean): Boolean {
        if (phase != Phase.KEEPING) return false
        if (deadlineToken != token) return false
        if (!stillInBackground) return false
        phase = Phase.TORN_DOWN
        return true
    }

    companion object {
        /** Returned by [arm] once the process is TORN_DOWN. Never a live token. */
        const val NO_TOKEN: Long = -1L

        /**
         * Seconds left in the background-task budget that the teardown keeps in
         * hand: Tor's HALT + guard-state flush (`TorManager.stop`, bounded at 2 s)
         * must finish before iOS would kill the process for overrunning its task.
         */
        const val SAFETY_MARGIN_SEC: Double = 3.0

        /** Never schedule the teardown sooner than this after backgrounding. The
         *  expiration handler stays the hard backstop if the OS granted less. */
        const val MIN_WINDOW_SEC: Double = 5.0

        /**
         * Never keep Tor longer than this in ONE background stretch, whatever the
         * OS grants. Today iOS grants ~30 s; this bounds a single window should a
         * future OS grant minutes. The PER-PROCESS bound is [RESIDUE_CAP_SEC].
         */
        const val MAX_WINDOW_SEC: Double = 170.0

        /**
         * The ABSOLUTE residue cap (security review F1, 2026-10-23): a process
         * that held an UNLOCKED session is kept alive INVISIBLE (backgrounded)
         * only until this many seconds of wall clock after that session's lock(),
         * across every background stretch. (Visible time at the PIN screen after
         * a warm return is not a keep-alive; the clock keeps running through it.)
         * Without it the per-stretch window re-armed on every `.background` after
         * a warm return, so tapping back inside each window kept the freed-heap
         * residue of the unlocked session alive indefinitely. Measured from the
         * lock() that ended the LAST unlocked session (a new unlock restarts it on
         * its own lock). Same 170 s as [MAX_WINDOW_SEC]: one maximal window, never
         * more, per unlocked session.
         */
        const val RESIDUE_CAP_SEC: Double = 170.0

        /**
         * Seconds of residue budget left when a keep-alive is armed, or null when
         * there is nothing to bound (no unlocked session has existed in this
         * process). [unlockedNow]: the session is being locked by THIS
         * backgrounding (the gate runs just before the lock) — the full cap.
         * Otherwise [RESIDUE_CAP_SEC] minus the time since the last unlocked
         * session's lock ([sinceLastUnlockedLockSec], negative clamps to 0; NaN
         * fails secure to 0 left).
         */
        fun residueLeftSeconds(sinceLastUnlockedLockSec: Double?, unlockedNow: Boolean): Double? = when {
            unlockedNow -> RESIDUE_CAP_SEC
            sinceLastUnlockedLockSec == null -> null
            sinceLastUnlockedLockSec.isNaN() -> 0.0
            else -> (RESIDUE_CAP_SEC - sinceLastUnlockedLockSec.coerceAtLeast(0.0)).coerceAtLeast(0.0)
        }

        /** Whether [residueLeftSec] still admits a keep-alive: more than the
         *  [MIN_WINDOW_SEC] floor left (or nothing to bound). At or below the
         *  floor the caller takes today's immediate stop() + exit(0). */
        fun residueAllowsKeepAlive(residueLeftSec: Double?): Boolean =
            residueLeftSec == null || residueLeftSec > MIN_WINDOW_SEC

        /**
         * The window actually scheduled: the budget-derived [budgetWindowSec]
         * ([windowSeconds], or [MAX_WINDOW_SEC] when the budget stayed unknown)
         * capped by the residue left NOW ([residueLeftNowSec], null = no cap).
         * Never negative and never NaN (a deadline already due fires at once).
         */
        fun composeWindow(budgetWindowSec: Double, residueLeftNowSec: Double?): Double {
            val budget = if (budgetWindowSec.isNaN()) 0.0 else budgetWindowSec.coerceAtLeast(0.0)
            if (residueLeftNowSec == null) return budget
            val residue = if (residueLeftNowSec.isNaN()) 0.0 else residueLeftNowSec.coerceAtLeast(0.0)
            return minOf(budget, residue)
        }

        /**
         * `backgroundTimeRemaining` above this is not a budget: UIKit reports
         * `DBL_MAX` ("suitably large") while it still considers the app
         * foreground. The caller re-reads a moment later.
         */
        const val UNKNOWN_BUDGET_ABOVE_SEC: Double = 100_000.0

        /**
         * The keep-alive window for a background task with [backgroundTimeRemainingSec]
         * left: the budget minus [SAFETY_MARGIN_SEC], clamped into
         * [[MIN_WINDOW_SEC], [MAX_WINDOW_SEC]]. Null when the value is not a
         * budget yet (NaN, infinite, or above [UNKNOWN_BUDGET_ABOVE_SEC]) — the
         * caller re-reads; negative/zero budgets clamp up to the floor (the
         * expiration handler then ends it).
         */
        fun windowSeconds(backgroundTimeRemainingSec: Double): Double? {
            if (backgroundTimeRemainingSec.isNaN() || backgroundTimeRemainingSec.isInfinite()) return null
            if (backgroundTimeRemainingSec > UNKNOWN_BUDGET_ABOVE_SEC) return null
            return (backgroundTimeRemainingSec - SAFETY_MARGIN_SEC).coerceIn(MIN_WINDOW_SEC, MAX_WINDOW_SEC)
        }

        /**
         * The gate, evaluated at `.background` BEFORE the vault locks (the tier
         * read needs the device key the lock wipes). Keep Tor only when ALL hold:
         *  - not a wipe ([isWipe]) — every wipe stops and DISCARDS Tor at once;
         *  - Tor is not [relaunchRequired] (dead / terminally failed / stopped:
         *    nothing to keep, and the recycle is the cure);
         *  - not [externalProxy] mode (no embedded Tor exists; a changed proxy
         *    setting must take effect on the next open);
         *  - Tor is [torConnected] — a bootstrapping or failed daemon is not worth
         *    keeping, and a stuck bootstrap's cure is a fresh process;
         *  - [notKnownWedged]: an UNLOCKED session that never got a relay answer
         *    over this Tor refuses — "leave and come back" is the user's restart
         *    remedy for a stuck connect and must keep yielding a FRESH Tor.
         *    Pre-unlock (no evidence either way) passes;
         *  - the device is not [deviceLocking] (`protectedDataWillBecomeUnavailable`
         *    seen with no did-become-available since — it can arrive BEFORE the
         *    scene's `.background` on a power-button lock): the Tor dir is
         *    NSFileProtectionComplete, and a seized LOCKED phone is the threat
         *    model's moment to hold the least;
         *  - [residueAllows]: the ABSOLUTE residue cap still has more than the
         *    floor left ([residueAllowsKeepAlive] of [residueLeftSeconds]);
         *  - [tierAllowed] (see [tierAllows]).
         */
        fun shouldKeepAlive(
            isWipe: Boolean,
            relaunchRequired: Boolean,
            externalProxy: Boolean,
            torConnected: Boolean,
            notKnownWedged: Boolean,
            deviceLocking: Boolean,
            residueAllows: Boolean,
            tierAllowed: Boolean,
        ): Boolean =
            !isWipe && !relaunchRequired && !externalProxy && torConnected && notKnownWedged &&
                !deviceLocking && residueAllows && tierAllowed

        /**
         * The tier half. MAXIMUM refuses — its whole point is the shortest
         * residue window — and so does a DAMAGED read (fails secure to MAXIMUM
         * everywhere else). CASUAL / PRIVATE and a legacy ABSENT level allow.
         * UNREADABLE (a transient device-key outage) falls back to
         * [sessionTierAllowed], this session's decision from an authenticated
         * read at unlock (false when there was no unlock). Android sibling:
         * `TorKeepAlive.shouldKeepAlive`'s tier branch.
         */
        fun tierAllows(live: ProtectionLevelRead, sessionTierAllowed: Boolean): Boolean = when (live) {
            is ProtectionLevelRead.Present -> live.level != ProtectionLevel.MAXIMUM
            is ProtectionLevelRead.Absent -> true
            is ProtectionLevelRead.Damaged -> false
            is ProtectionLevelRead.Unreadable -> sessionTierAllowed
        }

        /** [tierAllows] for an AUTHENTICATED read at unlock (Unreadable refuses). */
        fun tierAllowsAuthenticated(read: ProtectionLevelRead): Boolean = tierAllows(read, sessionTierAllowed = false)

        /**
         * Connection-log panel phrases — fixed text plus numbers, no identifier.
         * [PHRASE_REUSED] is WORD FOR WORD Android's `TorKeepAlive.PHRASE_REUSED`
         * and carries `ConnectionLog.Code.TOR_REUSED` on both platforms; the
         * window line is UNCODED (the relay's telemetry allowlist is not widened
         * for it — it never reaches the wire).
         */
        const val PHRASE_REUSED: String = "reused warm Tor from the previous session"

        /**
         * "tor keep-alive window N s (background budget M s)" — N = the scheduled
         * window, M = what the OS granted, both whole seconds (truncated); an
         * unknown budget (UIKit still reporting "suitably large" after the
         * re-reads) renders as "unknown" instead of a number.
         */
        fun windowPhrase(windowSec: Double, budgetSec: Double?): String {
            val budget = budgetSec?.takeIf { !it.isNaN() && !it.isInfinite() && it <= UNKNOWN_BUDGET_ABOVE_SEC }
            val budgetText = if (budget == null) "unknown" else "${budget.coerceAtLeast(0.0).toLong()} s"
            return "tor keep-alive window ${windowSec.toLong()} s (background budget $budgetText)"
        }
    }
}

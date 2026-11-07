package com.vg.run

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.os.PowerManager
import android.os.SystemClock

/**
 * Application-scoped home of the bounded Tor keep-alive (see TorKeepAlive.kt
 * for the design). Survives Activity finish + ViewModel clear because it is a
 * process-lifetime object; the process itself survives because
 * [TorKeepAliveService] holds a foreground service for the window.
 *
 * Lifecycle, all on the MAIN thread:
 *  1. `MainActivity.onStop` → `RunViewModel.armTorKeepAliveOnBackground` →
 *     [armOnBackground]: gates passed, start the foreground service, start the
 *     [TorKeepAlive.KEEP_ALIVE_MS] clock. Done at onStop (not later in
 *     onCleared) because a foreground service may only be started while the app
 *     is still in its visible→background transition.
 *  2. `RunViewModel.lockSession(stopTor = true)` (from onCleared) →
 *     [parkOnTeardown]: hands the live TorManager over instead of stopping it,
 *     AFTER the vault, keys and session managers are gone.
 *  3. Next `RunViewModel.init` → [reclaimForNewSession]: Warm (adopt), Expired
 *     or Cold. Always ends the keep-alive (timer + service).
 *  4. Timer / `Service.onTimeout` / `Service.onDestroy` → `TorManager.stop()`
 *     (working dirs preserved, exactly the old teardown).
 *  5. Any wipe (`WipeRoutine.wipePersistentState`) → [discardForWipe]:
 *     `TorManager.stopAndDiscardState()`.
 */
object TorKeepAliveHolder {

    /** The session callbacks every TorManager is built with (rebindable). */
    val hooks = TorSessionHooks()

    private val main: Handler by lazy { Handler(Looper.getMainLooper()) }

    /**
     * Held for the keep-alive window so the CPU cannot deep-sleep inside it
     * (review 2026-11-06, S2 F4). The expiry timer is a main-Looper post on the
     * uptime clock, which stops while the device sleeps: with the screen off, a
     * "2 minute" keep-alive lasted 2 minutes of AWAKE time, so a parked Tor child
     * could run on for hours of wall time. Acquired once per arm with a timeout
     * equal to the window (never re-acquired, never extended), released however
     * the keep-alive ends. Not reference-counted, so a release is always final.
     */
    private var wakeLock: PowerManager.WakeLock? = null

    private fun acquireWakeLock(app: Context) {
        try {
            val pm = app.getSystemService(PowerManager::class.java) ?: return
            val wl = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "run:keepalive")
            wl.setReferenceCounted(false)
            wl.acquire(TorKeepAlive.KEEP_ALIVE_MS)
            wakeLock = wl
        } catch (_: Exception) {
            // Best-effort: without it the over-age check in reclaim still holds
            // the reuse bound, and the service's own stop paths still run.
        }
    }

    private fun releaseWakeLock() {
        val wl = wakeLock ?: return
        wakeLock = null
        try { if (wl.isHeld) wl.release() } catch (_: Exception) { /* already timed out */ }
    }

    /**
     * Bumped on every successful [armOnBackground]. A service instance records
     * the generation it serves, so a late `onDestroy` of a service released for
     * an OLDER arm can never end a newer one.
     */
    @Volatile var generation: Int = 0
        private set

    private val keeper = TorKeepAlive<TorManager>(
        schedule = { delayMs, action ->
            val r = Runnable(action)
            main.postDelayed(r, delayMs)
            val cancel: () -> Unit = { main.removeCallbacks(r) }
            cancel
        },
        stopTor = { tor ->
            LogBuffer.append("D", "TorKeepAlive", "keep-alive ended without reuse — stopping the kept Tor")
            tor.stop()
            // The lines the parked daemon appended AFTER the lock's clear (CIRC /
            // STREAM / GUARD narration, no identifiers) must not outlive the
            // keep-alive: the ring's rule is "cleared on lock", and this bounds the
            // post-lock residue to the keep-alive window.
            ConnectionLog.clear()
        },
        discardTor = { tor ->
            tor.stopAndDiscardState()
            ConnectionLog.clear()
        },
        releaseService = {
            releaseWakeLock()
            TorKeepAliveService.release()
        },
        nowMs = { SystemClock.elapsedRealtime() },
    )

    /** Whether a keep-alive is armed or holding a Tor right now. */
    val isKeeping: Boolean get() = keeper.state != TorKeepAlive.State.IDLE

    /**
     * Step 1. The caller has ALREADY evaluated [TorKeepAlive.shouldKeepAlive];
     * this only starts the service and the clock. Returns false (nothing armed,
     * the teardown stops Tor as before) when the OS refuses the foreground
     * service or a keep-alive is already in flight.
     */
    fun armOnBackground(context: Context): Boolean {
        val app = context.applicationContext
        if (keeper.state != TorKeepAlive.State.IDLE) return false
        if (!TorKeepAliveService.start(app)) {
            LogBuffer.append("W", "TorKeepAlive", "foreground service refused — Tor stops with the session as before")
            return false
        }
        generation++
        if (!keeper.arm()) {
            TorKeepAliveService.release()
            return false
        }
        acquireWakeLock(app)
        LogBuffer.append("D", "TorKeepAlive", "armed for ${TorKeepAlive.KEEP_ALIVE_MS / 1000}s")
        return true
    }

    /** Step 2. True = the keeper owns [tor] now; false = the caller stops it. */
    fun parkOnTeardown(tor: TorManager, connected: Boolean): Boolean {
        val kept = keeper.park(tor, connected)
        if (kept) LogBuffer.append("D", "TorKeepAlive", "session torn down — Tor kept warm")
        return kept
    }

    /** Step 3. Usable = still Connected and not inside its own corrupt-state retry. */
    fun reclaimForNewSession(): TorKeepAlive.Reclaim<TorManager> =
        keeper.reclaim { tor ->
            tor.state.value is TorManager.ConnectionState.Connected && !tor.isMidInternalRetry
        }

    /** Step 4 (OS side): the short service hit its system limit or was destroyed
     *  while still serving [servedGeneration]. */
    fun onServiceEnded(servedGeneration: Int) {
        onMain {
            if (servedGeneration == generation) keeper.expire()
        }
    }

    /** Step 5. Every wipe entry point reaches this via WipeRoutine. */
    fun discardForWipe() {
        onMain { keeper.discard() }
    }

    private fun onMain(block: () -> Unit) {
        if (Looper.myLooper() == Looper.getMainLooper()) block() else main.post(block)
    }
}

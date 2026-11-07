package com.vg.run

import android.app.Application
import android.net.ConnectivityManager
import android.net.Network
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * The network-restore hook (iOS sibling: AppState startNetworkRestoreMonitor):
 * the default-network callback, the one debounce timer and the rate-limit
 * deferral latch. The decision (baseline, debounce, rate limit) is the shared
 * [NetworkRestoreKick]; the ACTION stays with the owner as [onRestore]
 * (RunViewModel.performNetworkRestoreKick reads the Tor manager, the vault, the
 * move freeze and the connect phase).
 *
 * PROCESS-scoped for its owner: [register] once at construction, [unregister] in
 * onCleared. A lock must NOT stop it, or the opt-out ladder's network-restore
 * wake dies with the first re-auth lock. Nothing happens on a loss beyond
 * dropping a pending kick. The network handle is an equality key only, never
 * logged. Main thread for every state change ([scope] is the owner's
 * viewModelScope).
 */
internal class NetworkRestoreMonitor(
    private val app: Application,
    private val scope: CoroutineScope,
    private val onRestore: suspend () -> Unit,
) {
    private val networkRestoreKick = NetworkRestoreKick()
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var networkRestoreCheckJob: Job? = null
    /** Rate-limit deferral already logged for the pending restore. */
    private var networkRestoreDeferralLogged = false

    fun register() {
        val cm = app.getSystemService(ConnectivityManager::class.java) ?: return
        // BASELINE first: the network that is up now (or none). The callback the
        // registration delivers for that same network is then a no-op, and with
        // none up the first onAvailable is a genuine restore.
        val active = try { cm.activeNetwork } catch (_: Exception) { null }
        networkRestoreKick.observe(active?.networkHandle?.toString())
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                val key = network.networkHandle.toString()
                scope.launch { scheduleNetworkRestoreCheck(networkRestoreKick.observe(key)) }
            }

            override fun onLost(network: Network) {
                val key = network.networkHandle.toString()
                scope.launch {
                    val wasUp = networkRestoreKick.isNetworkUp()
                    networkRestoreKick.observeLost(key)
                    if (wasUp && !networkRestoreKick.isNetworkUp()) {
                        networkRestoreCheckJob?.cancel()
                        NetworkRestoreKick.logLost()
                    }
                }
            }
        }
        try {
            cm.registerDefaultNetworkCallback(cb)
            networkCallback = cb
        } catch (e: Exception) {
            // Never fatal: without the hook Tor recovers on its own schedule, as before.
            LogBuffer.append("W", "NetRestore", "network callback unavailable (${e.javaClass.simpleName})")
        }
    }

    fun unregister() {
        networkRestoreCheckJob?.cancel()
        val cb = networkCallback ?: return
        networkCallback = null
        try {
            app.getSystemService(ConnectivityManager::class.java)?.unregisterNetworkCallback(cb)
        } catch (_: Exception) {}
    }

    /** One timer, replaced on every restore event (that IS the debounce). */
    private fun scheduleNetworkRestoreCheck(waitMs: Long) {
        if (waitMs < 0) return
        networkRestoreCheckJob?.cancel()
        networkRestoreCheckJob = scope.launch {
            var wait = waitMs
            while (true) {
                delay(wait)
                val d = networkRestoreKick.due()
                if (d.fire) {
                    networkRestoreDeferralLogged = false
                    // NonCancellable: a newer restore event replaces this job, and
                    // cancelling the kick between its SOCKS-port block and the
                    // readback would leave the port blocked. Bounded by the control
                    // socket's own read timeout.
                    withContext(NonCancellable) { onRestore() }
                    return@launch
                }
                if (d.waitMs < 0) return@launch
                if (d.rateLimited && !networkRestoreDeferralLogged) {
                    networkRestoreDeferralLogged = true
                    NetworkRestoreKick.logDeferred(d.waitMs)
                }
                wait = d.waitMs
            }
        }
    }
}

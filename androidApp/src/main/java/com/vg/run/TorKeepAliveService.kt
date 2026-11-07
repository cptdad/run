package com.vg.run

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder

/**
 * Foreground service that keeps the app PROCESS (and with it the embedded Tor
 * child) alive for the bounded keep-alive window after backgrounding — see
 * TorKeepAlive.kt / [TorKeepAliveHolder]. It owns no state and does no work:
 * Tor runs as it already was; this only stops the OS from caching/freezing or
 * killing the process while the keeper holds it.
 *
 * Type: `shortService` on API 34+ (≤ ~3 min, no type-specific permission —
 * there is no FOREGROUND_SERVICE_SHORT_SERVICE permission; only the generic
 * FOREGROUND_SERVICE). The keep-alive window (2 min) ends well inside the
 * system limit; if the OS times it out anyway, [onTimeout] stops Tor and the
 * service. API 30–33 have no such type: the same service runs typeless
 * (FOREGROUND_SERVICE_TYPE_NONE) with the same 2-min self-stop.
 *
 * Notification: LOW importance (silent, no heads-up, no badge, no vibration),
 * VISIBILITY_SECRET (nothing on the lock screen), fixed generic text — never
 * message content, never a contact or group name, never the word "Tor".
 *
 * NOT exported. Started only by [start] from MainActivity.onStop's path.
 */
class TorKeepAliveService : Service() {

    /** The keep-alive generation this instance was started for (see
     *  [TorKeepAliveHolder.generation]); -1 = serving nothing. */
    private var servedGeneration = -1

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // ALWAYS answer a startForegroundService() with startForeground() first —
        // stopping a service that never called it crashes the app on API 26+.
        // Only then decide whether there is still anything to keep.
        startInForeground()
        if (TorKeepAliveHolder.isKeeping) {
            servedGeneration = TorKeepAliveHolder.generation
            current = this
        } else {
            // Released (a new session reclaimed, or the arm was dropped) before
            // the service got here.
            stopNow()
        }
        return START_NOT_STICKY
    }

    /** API 34 shortService limit reached (system-enforced). */
    override fun onTimeout(startId: Int) {
        endFromSystem()
    }

    /** API 35+ variant of the same callback. */
    override fun onTimeout(startId: Int, fgsType: Int) {
        endFromSystem()
    }

    override fun onDestroy() {
        if (current === this) current = null
        // Destroyed while still serving the live keep-alive (OS kill path, the
        // FGS task manager): the process may be cached/frozen next, so stop Tor
        // now rather than leave it to a timer that may never fire. A service
        // released for an OLDER generation is ignored by the holder.
        val gen = servedGeneration
        servedGeneration = -1
        if (gen >= 0) TorKeepAliveHolder.onServiceEnded(gen)
        // Wipe hygiene (M9 class): WipeRoutine's own channel delete is refused
        // while this service is still foreground — repeat it now that it is not.
        if (ProcessWipeLatch.wipedThisProcess) deleteChannel(this)
        super.onDestroy()
    }

    private fun endFromSystem() {
        val gen = servedGeneration
        servedGeneration = -1
        if (gen >= 0) TorKeepAliveHolder.onServiceEnded(gen)
        stopNow()
    }

    private fun stopNow() {
        try {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } catch (_: Exception) { /* best-effort */ }
        stopSelf()
    }

    private fun startInForeground() {
        ensureChannel(this)
        val tap = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val notification = Notification.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentTitle(getString(R.string.tor_keepalive_notification_title))
            .setContentIntent(tap)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setShowWhen(false)
            .setCategory(Notification.CATEGORY_SERVICE)
            .setVisibility(Notification.VISIBILITY_SECRET)
            .build()
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SHORT_SERVICE)
            } else {
                @Suppress("DEPRECATION")
                startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_NONE)
            }
        } catch (e: Exception) {
            // Refused by the OS (background-start restriction, quota): end the
            // keep-alive now — Tor stops exactly as it did before this feature.
            LogBuffer.append("W", "TorKeepAlive", "startForeground refused (${e.javaClass.simpleName}) — ending keep-alive")
            servedGeneration = TorKeepAliveHolder.generation
            endFromSystem()
        }
    }

    companion object {
        /** Own channel: never shares the message channel's sound/badge settings. */
        const val CHANNEL_ID = "run_standby_v1"
        /** Distinct from NotificationHelper's message notification id (1001). */
        const val NOTIFICATION_ID = 1201

        @Volatile private var current: TorKeepAliveService? = null

        /** Requests the foreground service. False when the OS refuses. */
        fun start(context: Context): Boolean = try {
            context.startForegroundService(Intent(context, TorKeepAliveService::class.java))
            true
        } catch (e: Exception) {
            // ForegroundServiceStartNotAllowedException (API 31+) / SecurityException.
            false
        }

        /**
         * Ends the service if it is running. If it has not reached
         * [onStartCommand] yet, that call sees [TorKeepAliveHolder.isKeeping]
         * false and stops itself right after the mandatory startForeground().
         */
        fun release() {
            current?.let {
                current = null
                it.servedGeneration = -1
                it.stopNow()
            }
        }

        private fun ensureChannel(context: Context) {
            val nm = context.getSystemService(NotificationManager::class.java) ?: return
            val channel = NotificationChannel(
                CHANNEL_ID,
                context.getString(R.string.tor_keepalive_channel_name),
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                setShowBadge(false)
                enableVibration(false)
                enableLights(false)
                setSound(null, null)
                lockscreenVisibility = Notification.VISIBILITY_SECRET
            }
            nm.createNotificationChannel(channel)
        }

        /** Wipe hygiene: removes the live channel. Android still keeps the deleted
         *  record ("N categories deleted"), a known trace — see
         *  NotificationHelper.deleteChannel. */
        fun deleteChannel(context: Context) {
            try {
                context.getSystemService(NotificationManager::class.java)?.deleteNotificationChannel(CHANNEL_ID)
            } catch (_: Exception) { /* best-effort */ }
        }
    }
}

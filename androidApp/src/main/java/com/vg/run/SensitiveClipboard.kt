package com.vg.run

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import android.os.SystemClock
import java.security.MessageDigest

/**
 * The one way Rún puts text on the system clipboard: flagged sensitive, and
 * optionally cleared again after a delay. Used by the pairing-code copy
 * (AddContactScreen), the transfer-handle copy (MoveToNewDeviceScreen), the
 * donation address (DonateModal, cleared on dismiss) and the debug log copy
 * (LogViewerScreen, never cleared).
 *
 * `EXTRA_IS_SENSITIVE` is set on EVERY API level. The platform honours it from
 * API 33 (no clipboard preview overlay; clipboard-history managers skip it), but
 * the extra is just a string key in the clip description, so below 33 it costs
 * nothing and keyboards that read it on their own (Gboard's clipboard history
 * does) still skip the clip. Gating it on API 33 left the transfer handle in IME
 * clipboard histories on API 30-32 (review 2026-11-06, S5).
 *
 * The clear rule: when the delay runs out, the clip is cleared if it is still ours
 * OR if the clipboard cannot be read. Android makes it unreadable whenever Rún is
 * in the background, so a clip copied from another app in the meantime may be
 * overwritten too: forensic safety (no code left on the clipboard) wins over
 * preserving someone else's clip. The delays therefore match the iOS ones (pairing
 * code 20 s, transfer handle 60 s), long enough to switch apps and paste.
 *
 * Two timers carry the clear (review 2026-11-06, S2 F3). The in-process Handler
 * only runs while this process is alive, unfrozen and awake, and leaving Rún to
 * paste finishes the task, which makes the process the first one the OS kills or
 * freezes. So an AlarmManager alarm ([ClipboardClearReceiver], not exported) backs
 * it: it fires after process death and through Doze, possibly some minutes late
 * (setAndAllowWhileIdle is inexact). The alarm carries only a SHA-256 fingerprint
 * of the copied text, never the text.
 */
object SensitiveClipboard {

    /** Extra on the alarm intent: hex SHA-256 of the copied text. */
    internal const val EXTRA_FINGERPRINT = "com.vg.run.clip_fingerprint"

    // One pending alarm at a time: a newer copy replaces the older one's alarm,
    // and the newer clip has replaced the older one on the clipboard anyway.
    private const val ALARM_REQUEST_CODE = 0x0C11

    /**
     * Copies [text] under [label], flagged sensitive. With [clearAfterMs] set, the
     * clip is cleared after that delay by the in-process timer and, as a backstop
     * that survives process death, by an alarm. Uses the application context, so
     * the delayed clear neither leaks an Activity nor depends on one.
     */
    fun copy(context: Context, label: String, text: String, clearAfterMs: Long?) {
        val clipboard = clipboardOf(context)
        val clip = ClipData.newPlainText(label, text)
        clip.description.extras = PersistableBundle().apply {
            putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
        }
        clipboard.setPrimaryClip(clip)
        if (clearAfterMs != null) {
            val app = context.applicationContext
            val fingerprint = fingerprint(text)
            scheduleAlarmClear(app, fingerprint, clearAfterMs)
            Handler(Looper.getMainLooper()).postDelayed({
                clearIfFingerprintOrUnreadable(clipboard, fingerprint)
                cancelAlarmClear(app)
            }, clearAfterMs)
        }
    }

    /** Clears the clipboard if it still holds [text], or if it cannot be read. */
    fun clearIfOursOrUnreadable(context: Context, text: String) =
        clearIfFingerprintOrUnreadable(clipboardOf(context), fingerprint(text))

    /** The alarm path: same rule, matched by fingerprint. */
    internal fun clearIfFingerprintOrUnreadable(context: Context, fingerprint: String) =
        clearIfFingerprintOrUnreadable(clipboardOf(context), fingerprint)

    private fun clearIfFingerprintOrUnreadable(clipboard: ClipboardManager, fingerprint: String) {
        try {
            // Since Android 10, getPrimaryClip() returns null to an app without
            // input focus, i.e. whenever Rún is in the background (and always in
            // a process the alarm started).
            val current = try { clipboard.primaryClip } catch (_: Exception) { null }
            val currentText = current?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.text?.toString()
            if (shouldClearFingerprint(readable = current != null, currentText = currentText, oursFingerprint = fingerprint)) {
                // An empty replacement as well as clearPrimaryClip(), for vendor ROMs
                // that ignore the latter. Both are writes, which work without focus.
                clipboard.setPrimaryClip(ClipData.newPlainText("", ""))
                clipboard.clearPrimaryClip()
            }
        } catch (_: Exception) { /* clipboard race; nothing to do */ }
    }

    /**
     * Whether the delayed clear should fire. A readable clip is cleared only when
     * it is still ours, so a clip the user copied elsewhere since is left alone.
     */
    internal fun shouldClear(readable: Boolean, currentText: String?, ours: String): Boolean =
        shouldClearFingerprint(readable, currentText, fingerprint(ours))

    /** [shouldClear] against a fingerprint, which is all the alarm path holds. */
    internal fun shouldClearFingerprint(readable: Boolean, currentText: String?, oursFingerprint: String): Boolean {
        // WHY clear an UNREADABLE clipboard: unreadable means we cannot tell whether
        // our text is still there, and Android makes it unreadable exactly when Rún
        // is backgrounded, which is when the user has gone to paste the code. Leaving
        // a pairing code / transfer handle on the clipboard is the worse failure than
        // overwriting a clip copied from another app. To revert to "only if provably
        // ours", change this line to `if (!readable) return false`.
        if (!readable) return true
        if (currentText == null) return false
        return MessageDigest.isEqual(
            fingerprint(currentText).toByteArray(Charsets.US_ASCII),
            oursFingerprint.toByteArray(Charsets.US_ASCII),
        )
    }

    /** Hex SHA-256 of [text]. The copied values carry >= 160 bits of entropy, so
     *  the fingerprint in the alarm intent reveals nothing about them. */
    internal fun fingerprint(text: String): String =
        MessageDigest.getInstance("SHA-256").digest(text.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }

    private fun alarmIntent(context: Context, fingerprint: String?): PendingIntent? {
        val intent = Intent(context, ClipboardClearReceiver::class.java)
        if (fingerprint != null) intent.putExtra(EXTRA_FINGERPRINT, fingerprint)
        val flags = PendingIntent.FLAG_IMMUTABLE or
            (if (fingerprint != null) PendingIntent.FLAG_UPDATE_CURRENT else PendingIntent.FLAG_NO_CREATE)
        return PendingIntent.getBroadcast(context, ALARM_REQUEST_CODE, intent, flags)
    }

    private fun scheduleAlarmClear(context: Context, fingerprint: String, delayMs: Long) {
        try {
            val am = context.getSystemService(AlarmManager::class.java) ?: return
            val pi = alarmIntent(context, fingerprint) ?: return
            // Inexact, allowed in Doze, no exact-alarm permission needed. On the
            // sleep-inclusive clock, so deep sleep does not stretch the delay.
            am.setAndAllowWhileIdle(AlarmManager.ELAPSED_REALTIME_WAKEUP, SystemClock.elapsedRealtime() + delayMs, pi)
        } catch (_: Exception) { /* best-effort backstop; the in-process timer still runs */ }
    }

    private fun cancelAlarmClear(context: Context) {
        try {
            val pi = alarmIntent(context, null) ?: return
            context.getSystemService(AlarmManager::class.java)?.cancel(pi)
            pi.cancel()
        } catch (_: Exception) { /* nothing pending */ }
    }

    private fun clipboardOf(context: Context): ClipboardManager =
        context.applicationContext.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
}

/**
 * Fires [SensitiveClipboard]'s delayed clear from an alarm, including in a process
 * the alarm itself started after Rún was killed. Declared `exported="false"`: only
 * the app's own PendingIntent can reach it. It touches the clipboard and nothing
 * else (no vault, no Tor, no prefs); RunApplication.onCreate on that path runs the
 * same steps a push-wake process runs.
 */
class ClipboardClearReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val fingerprint = intent.getStringExtra(SensitiveClipboard.EXTRA_FINGERPRINT) ?: return
        SensitiveClipboard.clearIfFingerprintOrUnreadable(context, fingerprint)
    }
}

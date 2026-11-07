package com.vg.run

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.media.AudioAttributes
import android.net.Uri
import android.provider.Settings

// ---------------------------------------------------------------------------
// NotificationHelper — the single, CONTENTLESS local notification.
//
// Content discipline: one fixed string, "Notification".
// No sender alias, no body, no per-contact or total count — a count leaks
// active-conversation graph size on the lock screen, and the OS notification
// LOG (dumpsys notification --noredact) persists text outside the vault, so
// the text must be generic forever. That invariant is what lets the rest of
// this behave like an ordinary messenger (product decision 2026-08-05, see
// ensureChannel): it ALERTS (sound, vibration, heads-up) and it SHOWS on the
// lock screen — but only ever as "Notification". Both are first-run defaults
// the user owns from system settings; the app never re-imposes them.
// Tapping opens MainActivity, which lands on the PIN gate — never deep-links
// past unlock.
//
// Launcher badge (2026-08-20 design decision): the channel now allows a
// BOOLEAN launcher badge — "something is waiting" — never a count. See
// [ensureChannel] and [showNewMessages] for how that stays count-free.
// ---------------------------------------------------------------------------

object NotificationHelper {

    /**
     * v3 because a channel's importance/badge behaviour can only ever be
     * LOWERED/DISABLED by the app on an existing channel (see
     * [ensureChannel]) — every install that already carries an older channel
     * with `setShowBadge(false)` would otherwise never see a launcher badge,
     * code change or not. A NEW id is the only way the platform lets an app
     * raise its own default (same reasoning that minted v2 from v1). Must
     * stay byte-for-byte equal to the
     * `com.google.firebase.messaging.default_notification_channel_id`
     * meta-data in AndroidManifest.xml.
     */
    private const val CHANNEL_ID = "run_new_messages_v3"

    /** Superseded channels — deleted on sight so they can't linger in system
     *  settings as extra, confusing "Messages" entries. Both retired ids are
     *  kept (not just the immediately-prior one): a device can skip versions
     *  between launches, so v1 must still be cleaned up even after v2 exists. */
    private val LEGACY_CHANNEL_IDS = listOf("run_new_messages", "run_new_messages_v2")

    private const val NOTIFICATION_ID = 1001

    private fun manager(context: Context): NotificationManager =
        context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

    /**
     * ALERTING BY DEFAULT — IMPORTANCE_HIGH, system notification sound,
     * vibration: an inbound message should feel like any other messenger
     * (product decision 2026-08-05). This deliberately reverses an earlier
     * silencing (and its VISIBILITY_SECRET sibling), so state
     * the cost plainly rather than let a future reader assume it was
     * overlooked: a chime/buzz announces the ARRIVAL EVENT, and a lock-screen
     * entry additionally attributes it to Rún, for anyone holding a locked,
     * seized phone. Those timestamps correlate one-to-one against relay-side
     * observation — a traffic-analysis oracle the silent, hidden channel did
     * not give away. Trade-off: a messenger nobody notices messages
     * on is not a messenger, the leak is presence + timing only (never
     * content, sender or count — invariant I4 is untouched), and the
     * mitigation is now one tap away and USER-OWNED rather than hardcoded.
     *
     * THE USER OWNS THIS SETTING, not the app. Per
     * NotificationManager.createNotificationChannel, on an EXISTING channel
     * "the importance will only be changed if the new importance is LOWER than
     * the current value AND the user has not altered any settings on this
     * channel", and all other fields are ignored. Two consequences, both
     * intended:
     *  - this call raises nothing after creation, so a user who sets Silent
     *    (or turns the channel off) in system settings KEEPS that choice, on
     *    every later notification, forever;
     *  - the values below are therefore a first-run DEFAULT, not a policy the
     *    app re-imposes. [openChannelSettings] takes the user straight there.
     * The v3 id is what lets this new default reach installs that already
     * carry an older channel — see [CHANNEL_ID].
     */
    private fun ensureChannel(context: Context) {
        val nm = manager(context)
        // Retire every superseded channel. Safe unconditionally: deleting a
        // channel that was never created is a no-op.
        for (id in LEGACY_CHANNEL_IDS) {
            try { nm.deleteNotificationChannel(id) } catch (_: Exception) { /* best-effort */ }
        }

        val channel = NotificationChannel(
            CHANNEL_ID,
            // Channel name shows in system settings — keep it as generic as
            // the notification itself. Localized (l10n plumbing): the string
            // itself is still generic ("Messages") in every language, only the
            // wording changes with the app's language.
            context.getString(R.string.notification_channel_name),
            NotificationManager.IMPORTANCE_HIGH
        ).apply {
            // ADVISORY ONLY — verified on-device (NotificationChannelShapeTest):
            // the platform STRIPS an app-set channel visibility and stores
            // VISIBILITY_NO_OVERRIDE, i.e. "follow the user's own lock-screen
            // setting". Kept because it states intent and costs nothing, but the
            // lock screen is governed by the per-notification visibility in
            // [showNewMessages] plus the user's system settings — never by this
            // line. (The pre-2026-08-05 code set SECRET here and believed it was
            // load-bearing; it was not.)
            lockscreenVisibility = Notification.VISIBILITY_PUBLIC
            // Launcher dot = boolean "something is waiting", never a count
            // (design decision 2026-08-20). We deliberately never call
            // setNumber anywhere in this file, so no count ever reaches the
            // launcher — with the single fixed NOTIFICATION_ID below, at most
            // one notification can ever be posted at a time, so an OEM
            // launcher that renders counts shows "1", never a real total.
            // Opt-in gating is inherited for free: this notification only
            // ever posts when NotificationLevel is VENDOR_PUSH/UNIFIED_PUSH.
            setShowBadge(true)
            enableVibration(true)
            setSound(
                Settings.System.DEFAULT_NOTIFICATION_URI,
                AudioAttributes.Builder()
                    .setUsage(AudioAttributes.USAGE_NOTIFICATION)
                    .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION)
                    .build()
            )
        }
        nm.createNotificationChannel(channel)
    }

    /**
     * Localization: re-apply the channel NAME (only) to whatever language is
     * now active, for a device that changed its language while a channel from
     * an earlier language already exists — `createNotificationChannel` on an
     * EXISTING id updates the name for free (see [ensureChannel]'s own kdoc:
     * everything else about an existing channel is user-owned and untouched
     * by a repeat call).
     *
     * NEVER creates a channel that is absent — checked explicitly rather than
     * delegating to [ensureChannel], because a channel's mere existence is
     * itself evidence the user opted into push;
     * manufacturing one here on a never-notified install would
     * create exactly that evidence for someone who never asked for it.
     */
    fun refreshChannelNameIfExists(context: Context) {
        val nm = manager(context)
        if (nm.getNotificationChannel(CHANNEL_ID) == null) return
        val channel = NotificationChannel(
            CHANNEL_ID,
            context.getString(R.string.notification_channel_name),
            NotificationManager.IMPORTANCE_HIGH
        )
        nm.createNotificationChannel(channel)
    }

    /**
     * Opens the OS's own settings page for [CHANNEL_ID] — sound, vibration,
     * importance, pop-on-screen, or off entirely — so alerting is tunable on
     * the phone rather than only in code. Falls back to the app-level
     * notification page, then to app details, since OEM builds vary in which
     * of these they honour. Requires the channel to exist, so [ensureChannel]
     * runs first: deep-linking to a channel the OS has never heard of lands on
     * a blank page.
     */
    fun openChannelSettings(context: Context) {
        ensureChannel(context)
        val intents = listOf(
            Intent(Settings.ACTION_CHANNEL_NOTIFICATION_SETTINGS)
                .putExtra(Settings.EXTRA_APP_PACKAGE, context.packageName)
                .putExtra(Settings.EXTRA_CHANNEL_ID, CHANNEL_ID),
            Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS)
                .putExtra(Settings.EXTRA_APP_PACKAGE, context.packageName),
            Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS)
                .setData(Uri.fromParts("package", context.packageName, null)),
        )
        for (intent in intents) {
            try {
                context.startActivity(intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                return
            } catch (_: Exception) { /* try the next fallback */ }
        }
    }

    /**
     * Raises THE contentless notification. One fixed id: repeated raises
     * collapse into a single entry rather than stacking a visible count.
     * No-op when the user denied POST_NOTIFICATIONS (graceful degradation) or notifications are disabled system-wide.
     */
    fun showNewMessages(context: Context) {
        val nm = manager(context)
        if (!nm.areNotificationsEnabled()) return
        ensureChannel(context)

        val tapIntent = PendingIntent.getActivity(
            context,
            0,
            Intent(context, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val notification = Notification.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentTitle(context.getString(R.string.notification_title))
            .setContentIntent(tapIntent)
            .setAutoCancel(true)
            // CATEGORY_MESSAGE so Do-Not-Disturb / Priority-conversation rules
            // can classify this the way the user already classifies messengers.
            // It carries no content — the category is a type tag, not text.
            .setCategory(Notification.CATEGORY_MESSAGE)
            // Must match the channel's lockscreenVisibility: a SECRET here
            // would hide the entry on the lock screen no matter what the
            // channel (or the user) says, which is exactly the override we are
            // removing. The text is the fixed generic string either way.
            .setVisibility(Notification.VISIBILITY_PUBLIC)
            // Small-icon badge for launchers that render a long-press preview
            // of the badged notification — still no number (never setNumber).
            .setBadgeIconType(Notification.BADGE_ICON_SMALL)
            .build()

        try {
            nm.notify(NOTIFICATION_ID, notification)
        } catch (_: SecurityException) {
            // Permission revoked between the check and the notify — degrade
            // silently (fail-soft, never crash a background worker).
        }
    }

    /**
     * Wipe hygiene remove any delivered/pending notification.
     * Also called on every successful vault unlock ([RunViewModel.onVaultOpened])
     * — once the vault is open, the in-app unread dots take over, and the
     * system notification (and the launcher badge it drives) must not linger
     * for a user who entered via the launcher rather than by tapping it.
     */
    fun cancelAll(context: Context) {
        try {
            manager(context).cancelAll()
        } catch (_: Exception) { /* best-effort */ }
    }

    /**
     * Wipe hygiene: delete the notification CHANNEL itself, not just posted
     * notifications. [cancelAll] only clears what's currently shown/pending; the
     * live channel (name, importance, lockscreen visibility) survives that.
     *
     * This does NOT erase the fact that the app posted notifications: Android
     * keeps a deleted channel on record (it is restored if the same id is
     * re-created) and the app's notification settings page then shows
     * "N categories deleted". No app API purges that record, so it is a known
     * trace (SECURITY_OVERVIEW "Traces left on the device"; review 2026-11-06,
     * S1 F2). Safe to call unconditionally: [ensureChannel] recreates the
     * channel the next time a notification is actually due, and a
     * never-notified install (channel never created) is a harmless no-op.
     */
    fun deleteChannel(context: Context) {
        // ALL ids, current + every legacy one: an install that notified
        // before a version switch carries an older channel too, and leaving
        // it live would keep its settings visible as an active category.
        for (id in listOf(CHANNEL_ID) + LEGACY_CHANNEL_IDS) {
            try {
                manager(context).deleteNotificationChannel(id)
            } catch (_: Exception) { /* best-effort */ }
        }
    }
}

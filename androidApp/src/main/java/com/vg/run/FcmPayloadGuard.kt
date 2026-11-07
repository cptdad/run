package com.vg.run

// ---------------------------------------------------------------------------
// The Firebase SDK decides that an FCM
// payload is a DISPLAY notification purely from its intent extras —
// `NotificationParams.isNotification` checks `gcm.n.e` (or the legacy
// `gcm.notification.e`) — and, for a backgrounded app, renders the sender's
// `gcm.n.title` / `gcm.n.body` as ITS OWN system notification and returns
// WITHOUT ever calling onMessageReceived. That let anyone who can send to the
// device's token (the relay, by design; or its credentials) put arbitrary
// text on the lock screen attributed to Rún — also after a wipe — while the
// opt-in copy promises the push "carries nothing".
//
// RunFcmService overrides handleIntent and strips every such key BEFORE the
// SDK sees the intent, so the message is always data-only and the ONLY thing
// this app can ever show is NotificationHelper's fixed generic string on the
// level-gated path. This object holds the pure key classification so it can
// be unit-tested on the JVM without Android classes.
// ---------------------------------------------------------------------------
internal object FcmPayloadGuard {
    private const val NOTIFICATION_PREFIX = "gcm.n."
    private const val LEGACY_NOTIFICATION_PREFIX = "gcm.notification."

    /** True for an extra the FCM SDK reads as part of a display-type payload. */
    fun isNotificationExtraKey(key: String): Boolean =
        key.startsWith(NOTIFICATION_PREFIX) || key.startsWith(LEGACY_NOTIFICATION_PREFIX)

    /** The subset of [keys] that must be removed before the SDK dispatches the message. */
    fun keysToStrip(keys: Iterable<String>): List<String> = keys.filter(::isNotificationExtraKey)
}

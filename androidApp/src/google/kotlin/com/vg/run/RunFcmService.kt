package com.vg.run

import android.content.Intent
import android.os.Bundle
import java.security.MessageDigest
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage

// ---------------------------------------------------------------------------
// RunFcmService — the Vendor-push (FCM) wake entry point. In every build since the 2026-08-04
// flavor collapse; inert on devices without Play Services (FCM never
// delivers there — UnifiedPush/RunPushService is that path).
//
// Contentless invariant: FCM only ever carries a data-only "type":"wake"
// message (no inbox id/sender/count — the relay's FcmSender mints it that
// way), and the relay sends it ONLY when a message is appended to a registered
// inbox. So the push itself IS the "new messages" signal: onMessageReceived
// does NOT peek, fetch, decrypt, or open Tor — it just posts the generic
// "Notification" notification (NotificationHelper.showNewMessages) and returns.
// The user opens Rún to fetch the messages over Tor. (The former WorkManager
// background poll — a blind timer with no per-message signal, so it had to
// peek-then-notify — has been removed entirely and is not coming back.)
// FCM is no longer the ONLY push transport: Google-free devices use
// UnifiedPush (RunPushService). The two are
// mutually exclusive per device, selected by the persisted NotificationLevel —
// which is exactly what the gate in onMessageReceived checks.
//
// THIS SERVICE NEVER REACHES THE RELAY. It reads two plaintext values (the
// persisted NotificationLevel and PushWakeFreshness's last-sweep stamp, which
// drops a late-delivered wake's banner) and posts a local notification. Nothing here
// touches the vault, a capability, Tor, or the network — see onNewToken for
// why that is now true of the token-rotation callback as well.
//
// The gate below reads NotificationLevelStore
// (`notification_level_prefs`, key `notif_level`) — the SAME single source
// of truth RunViewModel.isBackgroundNotificationsEnabled() reads, and the
// SAME store RunViewModel.setBackgroundNotificationsEnabledAwaiting writes
// at TOGGLE time (before/independent of whether registration itself has
// completed). This gate is also the only LOCAL backstop if the relay-side
// inbox DELETE and VendorPush.destroyLocalPushIdentity's deleteToken() both
// fail during a wipe: it must read false in every state the user has opted
// out, not just the states registration succeeded in. See RunViewModel's
// unregisterPushInBackground/clearLevel-ordering comments for why the
// level is always removed (not merely raced) before any relay-side effort.
// ---------------------------------------------------------------------------

class RunFcmService : FirebaseMessagingService() {

    /**
     * ENFORCE the contentless invariant
     * client-side instead of trusting the sender.
     *
     * NOTE: `handleIntent` is the SDK's sole entry point only while Firebase's
     * notification-DELEGATION feature is off. That feature
     * (`ProxyNotificationInitializer`, bytecode-verified against
     * firebase-messaging 25.1.2) authorises `com.google.android.gms` to call
     * `NotificationManager.setNotificationDelegate` and render a display-type
     * FCM payload itself, via `notifyAsPackage` — a path that does not start
     * this app's process AT ALL, so `handleIntent` (this method) never runs,
     * `FcmPayloadGuard.keysToStrip` never sees the extras, and the
     * level-gated `onMessageReceived` below is never consulted either. That
     * bypass is now closed at both layers (`AndroidManifest.xml`'s
     * `firebase_messaging_notification_delegation_enabled=false` +
     * `VendorPush.disableNotificationDelegation`'s runtime revocation at
     * process start / every wipe / every push opt-out) — with delegation off,
     * `handleIntent` really is this app's sole entry point for an FCM message,
     * which is the precondition every claim below actually depends on.
     *
     * `handleIntent` → `handleMessageIntent` → `passMessageIntentToSdk` →
     * `dispatchMessage` (verified against firebase-messaging 25.1.2 bytecode),
     * and `dispatchMessage` decides "display notification vs. data message"
     * from the intent extras (`NotificationParams.isNotification`: `gcm.n.e` /
     * `gcm.notification.e`). For a backgrounded app — i.e. essentially always,
     * given MainActivity.onStop's finishAndRemoveTask — a display payload
     * that reaches this method is rendered by the SDK with the SENDER's
     * title/body and onMessageReceived is never called. Stripping every
     * `gcm.n.*` / `gcm.notification.*` extra here, before delegating, turns
     * any such payload into a data-only message, so the only notification
     * this device can ever post is NotificationHelper's fixed generic string
     * on the level-gated path below. Nothing here reads the vault, a
     * capability, Tor or the network; the strip is pure Bundle work.
     */
    override fun handleIntent(intent: Intent) {
        val extras = intent.extras
        if (extras != null) {
            val strip = FcmPayloadGuard.keysToStrip(extras.keySet())
            if (strip.isNotEmpty()) {
                val cleaned = Bundle(extras)
                for (k in strip) cleaned.remove(k)
                intent.replaceExtras(cleaned)
                // Inert in release (LoggingState.enabled == BuildConfig.DEBUG); the
                // enforcement above is the defense, this line only aids e2e triage.
                LogBuffer.append(
                    "W", "RunFcmService",
                    "handleIntent: stripped a display-type FCM payload (${strip.size} keys) — " +
                        "contentless invariant enforced client-side (D-1)"
                )
            }
        }
        super.handleIntent(intent)
    }

    override fun onMessageReceived(message: RemoteMessage) {
        super.onMessageReceived(message)
        // Contentless-invariant detector (made release-live and
        // non-fatal). After handleIntent's strip this cannot be
        // non-null — it is kept as a belt on that braces: if it ever fires, the SDK
        // changed its key scheme and FcmPayloadGuard needs updating. Never crashes
        // a shipped build; LogBuffer is inert in release, so the line is free.
        if (message.notification != null) {
            LogBuffer.append(
                "E", "RunFcmService",
                "onMessageReceived: notification-type FCM payload reached the app — " +
                    "FcmPayloadGuard's key list is stale (D-1)"
            )
        }
        // The relay sends this contentless wake ONLY because a message was just
        // appended to a registered inbox — so the push itself IS the "new
        // messages" signal. Do NOT peek, fetch, decrypt, or open Tor here; just
        // post the generic notification. The user opens Rún to fetch over Tor.
        val levelStore = KeyValueStore(applicationContext, RunViewModel.NOTIFICATION_LEVEL_PREFS_NAME)
        if (NotificationLevelStore.getLevel(levelStore) == NotificationLevel.VENDOR_PUSH) {
            // Late-delivered wake: FCM stores a wake it could not
            // deliver and hands it over when the push socket returns from doze —
            // possibly long after the unlocked app already showed that message.
            // Drop the banner only when FCM's sentTime predates the last COMPLETE
            // inbox sweep by more than the skew margin; every doubt shows it.
            // Reads one more plaintext value from the same outside-vault store —
            // still no vault, Tor, capability or network here.
            if (PushWakeFreshness.isStaleWake(levelStore, message.sentTime, System.currentTimeMillis())) {
                // Inert in release; no identifier, no timestamp.
                LogBuffer.append(
                    "D", "RunFcmService",
                    "onMessageReceived: wake predates the last inbox sweep — banner suppressed",
                )
                return
            }
            // The same one-banner-per-10-s guard as UnifiedPush (PushReplayGuard
            // kdoc). Keyed by FCM's message id, so an FCM redelivery of the same
            // message is an exact repeat; a stream of distinct wakes hits the rate
            // limit. Genuine bursts inside 10 s already collapse into the one
            // notification id, so nothing a user would hear is lost.
            if (!PushReplayGuard.processWide.shouldShowBanner(fcmWakeKey(message), System.currentTimeMillis())) {
                LogBuffer.append("D", "RunFcmService", "onMessageReceived: wake suppressed by replay/rate-limit guard")
                return
            }
            // AppLocale.wrap: applicationContext does not follow a per-app
            // language override below API 33 (only an attachBaseContext-wrapped
            // Activity does) — wrap explicitly so a wake that never touches
            // MainActivity still localizes the channel/title. Identity on 33+.
            NotificationHelper.showNewMessages(AppLocale.wrap(applicationContext))
        }
    }

    /**
     * A new/rotated FCM registration token. **Deliberately a no-op**.
     *
     * It used to re-register the rotated token against a device-key-encrypted
     * (inboxId, readCap) manifest, because a Service has no ViewModel/vault
     * access. That manifest is REMOVED: the relay read capability is the inbox
     * OWNER capability (drain / delete-inbox / rotate BOTH capabilities), and
     * keeping a copy outside the vault — necessarily under a key usable while
     * the device is locked — handed an AFU forensic image exactly that authority
     * per inbound inbox. See NotificationPollStore's kdoc for the full bound.
     *
     * With no mirror there is nothing to register against: this callback cannot
     * know which inboxes exist without opening the vault, and it must not.
     *
     * TRADE-OFF, do not re-engineer around it: after a token rotation, push
     * wakes LAPSE until the next unlock. `RunViewModel.refreshVendorPushRegistration`
     * then re-registers every inbound text inbox — unconditionally, because its
     * "already registered" set and cached token are plain ViewModel fields, i.e.
     * RAM-only: on a fresh process the token is null, so the diff runs against an
     * EMPTY set and returns every inbox, and `PushRegistration.register` is an
     * idempotent relay upsert. There is no persisted value that could go stale and
     * suppress it, which is why deferring here DELAYS push rather than breaking
     * it. It runs on unlock and again on every control-poll cycle (the unlock-time
     * attempt is usually a no-op because Tor is still bootstrapping, and the cycle
     * catches it ~25-45 s later; a session where Tor never connects registers
     * nothing). The canonical rotation causes — reinstall, clear-app-data,
     * restore-to-new-device — destroyed the manifest too, so this path was
     * already a no-op for them; what is genuinely lost is FCM's own
     * server-initiated refresh on an otherwise intact install, and reading the
     * messages requires opening the app either way.
     *
     * No local nudge notification is posted here on purpose: a notification that
     * fires without the user having received anything is a use-artifact on a
     * device that may have been wiped, and it would leak "this app is installed
     * and configured" onto the lock screen of a seized phone.
     */
    override fun onNewToken(token: String) {
        super.onNewToken(token)
        // LogBuffer is compiled-in but inert in release (LoggingState.enabled is
        // BuildConfig.DEBUG), and the line carries no token material.
        LogBuffer.append(
            "D", "RunFcmService",
            "onNewToken: FCM token rotated — re-registration deferred to the next unlock"
        )
    }

    /** The replay-guard key of an FCM wake: a digest of FCM's own message id
     *  (no payload byte, no identifier of ours). Null id = one shared key, so
     *  such wakes are rate-limited together. */
    private fun fcmWakeKey(message: RemoteMessage): String =
        MessageDigest.getInstance("SHA-256")
            .digest((message.messageId ?: "").toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }

}

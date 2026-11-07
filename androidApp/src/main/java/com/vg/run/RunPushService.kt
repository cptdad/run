package com.vg.run

import android.content.Context
import org.unifiedpush.android.connector.FailedReason
import org.unifiedpush.android.connector.PushService
import org.unifiedpush.android.connector.data.PushEndpoint
import org.unifiedpush.android.connector.data.PushMessage
import java.security.MessageDigest

// ---------------------------------------------------------------------------
// RunPushService — the UnifiedPush wake entry point (connector: pure
// Apache-2.0, no Google transitives). This is the transport for devices
// WITHOUT Play Services: no Play Services means no FCM, and this is the only
// real-time wake path that exists on a de-Googled device.
//
// This file is a deliberate copy of RunFcmService.kt's discipline (see its
// header — it is the template). Read that first; the
// invariants are identical and the reasoning is not repeated in full here.
//
// THIS SERVICE NEVER REACHES THE RELAY, THE VAULT, A CAPABILITY, OR TOR.
// It reads one plaintext value (the persisted NotificationLevel) and posts one
// fixed, contentless local notification. It performs NO network I/O of any
// kind — the relay PUT that registers an endpoint happens in RunViewModel, with
// an OPEN VAULT, and never here (a service has no vault, so any registration
// it could perform would require a capability mirror outside the vault, which is
// exactly the artifact that was deleted).
//
// CONTENTLESS INVARIANT. The relay's WebPush sender mints one fixed payload,
// `{"type":"wake"}`, and sends it ONLY because a message was appended to a
// registered inbox — so the push itself IS the "new messages" signal.
// [onMessage] therefore NEVER PARSES, INSPECTS, OR LOGS `message.content` —
// the one exception is hashing the raw bytes for the
// replay/rate-limit guard, which never reads, branches on, or logs what the
// bytes MEAN. It checks the forgery gate, the level, and the replay guard,
// posts the generic banner, and returns. The user opens Rún and fetches over
// Tor. Never interpreting the bytes is what keeps this true even if a future
// relay (or a hostile distributor) started stuffing data into the payload.
//
// NO ENDPOINT URL OR KEY MATERIAL IS EVER LOGGED. The endpoint names the user's
// distributor and push-server host; on a self-hosted server it effectively
// names the user. Every LogBuffer line below is a bare state transition. (
// LogBuffer is inert in release anyway — LoggingState.enabled is
// BuildConfig.DEBUG — but the discipline holds regardless, because debug builds
// are what e2e and beta testers run.)
// ---------------------------------------------------------------------------

class RunPushService : PushService() {

    companion object {
        /**
         * Drop any wake the connector could not decrypt. Named, not inlined,
         * because it is a security gate rather than a tunable.
         *
         * The connector performs the RFC 8291 decryption locally with the
         * private half of the subscription (kept in ITS store, sealed under the
         * AndroidKeyStore alias `UnifiedPush` — never in ours), and reports the
         * outcome as [PushMessage.decrypted]. `false` means the payload was NOT
         * authenticated to our subscription: a distributor bug, a truncated
         * message, or — the case that matters — a forged POST to an endpoint URL
         * someone learned. This one check is what stops an attacker who knows
         * the endpoint from spraying "you have messages" banners at a target (a
         * cheap user-behaviour oracle, and a nuisance vector).
         *
         * WHAT THE GATE ACTUALLY DEPENDS ON — worth stating exactly, because
         * getting it wrong is what justified storing the inputs in cleartext
         * until 2026-08-11. Encrypting to this subscription needs `p256dh` AND
         * `auth`, and `auth` is a 16-octet SHARED SECRET (RFC 8291 §3.2), not a
         * public half. So "an authenticated wake can only have come from the
         * relay" holds only while `auth` stays secret. It is therefore sealed at
         * rest ([UnifiedPushStateStore.KEYSTORE_ALIAS]) and crypto-erased by
         * `UnifiedPushSupport.eraseKeySurface` on every teardown path. Do not
         * relax this constant, and do not let either value be persisted or
         * logged in the clear.
         *
         * Fail-CLOSED: an undecryptable wake is dropped silently, never
         * "shown just in case".
         */
        private const val REQUIRE_ENCRYPTED_PUSH = true

        /**
         * Process-wide, not per-`RunPushService`
         * instance — the framework may construct a new `Service` object per
         * dispatch, but the ring/rate-limit state must survive across calls
         * within the same live process (see [PushReplayGuard]'s kdoc for the
         * RAM-only scope and why that is a known limitation).
         */
        private val replayGuard = PushReplayGuard.processWide

        /** No endpoint/key material ever crosses this boundary — see [onMessage]. */
        private fun sha256Hex(bytes: ByteArray): String =
            MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
    }

    /**
     * A (new or rotated) WebPush endpoint from the distributor.
     *
     * Persist it and raise the in-process signal. Explicitly NO relay call here
     * — see the file header. RunViewModel does the relay PUT on the next
     * pass with an open vault; the toggle-ON handshake is woken by the signal
     * so the user's spinner resolves promptly instead of waiting for a poll.
     *
     * The write is refused (and the signal not raised) when the endpoint is
     * implausible, the distributor supplied no WebPush keys, or those keys
     * could not be SEALED — see [UnifiedPushStateStore.saveSubscription]. A
     * keyless endpoint is unusable by design: the relay must be able to RFC
     * 8291-encrypt, and [REQUIRE_ENCRYPTED_PUSH] would drop everything it
     * delivered anyway. A seal failure (Keystore momentarily unavailable)
     * refuses the whole save rather than degrading to cleartext; the toggle
     * reports "no endpoint yet" and a retry re-asks the distributor.
     *
     * GATED ON THE PERSISTED LEVEL, exactly as [onMessage] and [onUnregistered]
     * are, and for the write-after-delete reason rather than a UX one. This is a
     * WRITE that MINTS `unifiedpush_state_prefs.xml`, it arrives asynchronously
     * from another app, and the in-session teardowns (settings opt-out, failed
     * enable) set no [ProcessWipeLatch] — so `saveSubscription`'s latch check
     * does not cover them. The failed-enable case is the sharp one: the toggle
     * gives up on the handshake after a timeout and sweeps, and the
     * distributor's NEW_ENDPOINT broadcast can land seconds LATER, re-creating a
     * prefs file that carries the endpoint URL (which names the user's push
     * server) with nothing left to ever remove it again — the modal's
     * `applyLevel` dispatches no disable, and the control-poll dispatcher keys
     * off the level that branch just cleared. Every teardown path clears the
     * level FIRST, so a level that no longer reads UNIFIED_PUSH is precisely the
     * "nobody is waiting for this endpoint" signal. The enable path writes the
     * level at toggle time, BEFORE `UnifiedPush.register` is ever called
     * (`RunViewModel.setBackgroundNotificationsEnabledAwaiting`), so no
     * legitimate endpoint is ever refused by this.
     */
    override fun onNewEndpoint(endpoint: PushEndpoint, instance: String) {
        val levelStore = KeyValueStore(applicationContext, RunViewModel.NOTIFICATION_LEVEL_PREFS_NAME)
        val level = NotificationLevelStore.getLevel(levelStore)
        if (level != NotificationLevel.UNIFIED_PUSH) {
            LogBuffer.append(
                "D", "RunPushService",
                "onNewEndpoint: not opted into UnifiedPush — endpoint discarded, nothing written",
            )
            return
        }
        val keys = endpoint.pubKeySet
        val stored = UnifiedPushStateStore(applicationContext)
            .saveSubscription(endpoint.url, keys?.pubKey, keys?.auth)
        if (stored) {
            UnifiedPushEndpointSignal.emit(PushEndpointEvent.NewEndpoint)
        }
        // No URL, no key material, no instance id — a bare state transition.
        LogBuffer.append(
            "D", "RunPushService",
            if (stored) "onNewEndpoint: endpoint stored, relay registration deferred to the ViewModel"
            else "onNewEndpoint: endpoint rejected (implausible URL or no WebPush keys)"
        )
    }

    /**
     * A contentless wake. The ONLY thing this does is post the generic banner.
     *
     * Three gates, in order:
     *  1. [REQUIRE_ENCRYPTED_PUSH] — drop anything the connector could not
     *     authenticate to our subscription (see the constant's kdoc).
     *  2. The persisted [NotificationLevel] must be exactly
     *     [NotificationLevel.UNIFIED_PUSH]. Reading the SAME
     *     `notification_level_prefs` / `notif_level` value that
     *     `RunViewModel.isBackgroundNotificationsEnabled` reads and
     *     `setBackgroundNotificationsEnabledAwaiting` writes at TOGGLE time is
     *     what makes this the local backstop when the relay-side DELETE and the
     *     distributor-side unregister both fail during opt-out or a wipe: the
     *     level is removed FIRST on every one of those paths, so this reads
     *     "off" the instant the user opts out. Requiring UNIFIED_PUSH
     *     specifically (not merely "not OFF") additionally means a device that
     *     switched to VENDOR_PUSH cannot be woken through a stale UnifiedPush
     *     registration.
     *  3. [replayGuard] — [REQUIRE_ENCRYPTED_PUSH]
     *     is freshness-blind (an RFC 8291 record is replayable forever by
     *     whoever holds the push server, by construction), so the push
     *     server itself can re-deliver an old wake and re-fire the banner on
     *     demand. This bounds that to at most one banner per
     *     [PushReplayGuard.RATE_LIMIT_MS] — see that class's kdoc for why a
     *     literal content-hash dedupe is not realizable here (the connector
     *     never exposes pre-decrypt ciphertext or a message id to this
     *     callback, and the decrypted content is a FIXED plaintext for every
     *     wake, genuine or replayed).
     *
     * `message.content` bytes are hashed for the replay guard ONLY — never
     * parsed, inspected, or logged, and the hash identifies no endpoint or key
     * material.
     */
    override fun onMessage(message: PushMessage, instance: String) {
        if (REQUIRE_ENCRYPTED_PUSH && !message.decrypted) {
            LogBuffer.append("W", "RunPushService", "onMessage: undecryptable wake dropped")
            return
        }
        val ctx: Context = applicationContext
        val levelStore = KeyValueStore(ctx, RunViewModel.NOTIFICATION_LEVEL_PREFS_NAME)
        if (NotificationLevelStore.getLevel(levelStore) != NotificationLevel.UNIFIED_PUSH) return
        val contentHash = sha256Hex(message.content)
        if (!replayGuard.shouldShowBanner(contentHash, System.currentTimeMillis())) {
            LogBuffer.append("D", "RunPushService", "onMessage: wake suppressed by replay/rate-limit guard")
            return
        }
        // AppLocale.wrap: applicationContext does not follow a per-app
        // language override below API 33 (only an attachBaseContext-wrapped
        // Activity does) — wrap explicitly so a wake that never touches
        // MainActivity still localizes the channel/title. Identity on 33+.
        NotificationHelper.showNewMessages(AppLocale.wrap(ctx))
    }

    /**
     * The distributor dropped our registration (its app was uninstalled, the
     * user revoked us, or it reset its own state).
     *
     * Local teardown only. Clear the store, REMOVE the persisted level (never
     * write OFF — [NotificationLevelStore.clearLevel]'s absence-not-artifact
     * rule), and leave a one-shot marker the settings modal surfaces once.
     *
     * NO relay DELETE: there is no vault here, so there is no capability to
     * authenticate one with — and none is needed. A stale relay row is inert:
     * the relay would POST to an endpoint the distributor no longer honours,
     * and even if it were somehow delivered this device's level now reads OFF,
     * so [onMessage] drops it.
     *
     * Order matters: level first. It is the gate every wake path consults, so
     * it must go before the best-effort store cleanup — if the process dies
     * between the two, the device is silent rather than woken by a
     * registration it no longer has.
     *
     * THE NOTICE IS CONDITIONAL, and that condition is load-bearing in two
     * ways. The connector broadcasts UNREGISTERED back into this callback for a
     * DELIBERATE local unregister too, not only for a distributor that dropped
     * us — so both the settings opt-out and [WipeRoutine] land here. Every one
     * of those paths clears the persisted level BEFORE touching the
     * distributor, so a level that still reads UNIFIED_PUSH is exactly the
     * signal "the user did not ask for this".
     *  1. UX: without the check, turning notifications off would immediately
     *     arm a "your distributor stopped delivering" line for the next time
     *     settings opens.
     *  2. Residue, which is the real reason: opt-out runs
     *     destroyLocalPushIdentity → sweepLocalArtifacts, and this callback can
     *     arrive AFTER that sweep. An unconditional marker write would then
     *     RE-CREATE unifiedpush_state_prefs.xml — the write-after-delete race
     *     the Firebase teardown also has to avoid. (The wipe path is additionally covered by
     *     [ProcessWipeLatch], which refuses the write outright; opt-out sets no
     *     latch, so this check is its only defense.)
     */
    override fun onUnregistered(instance: String) {
        val ctx: Context = applicationContext
        val levelStore = KeyValueStore(ctx, RunViewModel.NOTIFICATION_LEVEL_PREFS_NAME)
        val wasOptedIn = NotificationLevelStore.getLevel(levelStore) == NotificationLevel.UNIFIED_PUSH
        // Clear the level ONLY when it is ours. The level is SHARED across
        // transports, so an unconditional clear lets this transport's teardown
        // wipe someone else's VENDOR_PUSH opt-in — and the distributor, which
        // this transport does not trust, is the party that triggers it. A device
        // that later gained Play Services switches to VENDOR_PUSH without tearing
        // the connector registration down, so a distributor UNREGISTERED
        // broadcast (user action, distributor reset, or malice) would silently
        // kill every FCM banner: RunFcmService gates on level == VENDOR_PUSH, and
        // the unlock-time re-registration is gated on
        // isBackgroundNotificationsEnabled(), so nothing recovers it and the
        // switch still LOOKS on until the modal is reopened.
        // UnifiedPushSupport's own teardown already does exactly this and says so.
        // No vault in this process, so the epoch cannot be advanced
        // here — the removal still lands and the invalidation happens at the
        // next vault-open read of an absent proof (NotificationLevel.kt).
        if (wasOptedIn) NotificationLevelStore.clearLevel(levelStore, CryptoProvider(ctx), vault = null)
        val store = UnifiedPushStateStore(ctx)
        store.clear()
        if (wasOptedIn) store.markUnregisteredNoticePending()
        UnifiedPushEndpointSignal.emit(PushEndpointEvent.Unregistered)
        LogBuffer.append(
            "D", "RunPushService",
            "onUnregistered: local push state cleared (userVisibleNotice=$wasOptedIn)"
        )
    }

    /**
     * Registration was refused. Signal only — NO store writes.
     *
     * Deliberately does not clear anything: a transient refusal (a distributor
     * restarting, a push server briefly down) must not destroy a working
     * subscription. The toggle-ON handshake in RunViewModel is what acts on
     * this, and only for the attempt it is currently awaiting.
     *
     * Only the connector's own enum NAME crosses the signal — a closed
     * vocabulary, never text from another app.
     */
    override fun onRegistrationFailed(reason: FailedReason, instance: String) {
        UnifiedPushEndpointSignal.emit(PushEndpointEvent.Failed(reason.name))
        LogBuffer.append("W", "RunPushService", "onRegistrationFailed: ${reason.name}")
    }

    /**
     * The distributor is momentarily unavailable. Signal only; persisted state
     * is untouched — this is explicitly a "try again later", not a revocation.
     */
    override fun onTempUnavailable(instance: String) {
        UnifiedPushEndpointSignal.emit(PushEndpointEvent.TempUnavailable)
        LogBuffer.append("D", "RunPushService", "onTempUnavailable: distributor unavailable, state kept")
    }

    /**
     * Test seam, and nothing else. Widens [android.content.ContextWrapper]'s
     * protected `attachBaseContext` so an instrumented test can construct this
     * service directly and drive the callbacks above without a real distributor
     * app installed — which is what locks the show-only / no-vault invariants
     * (`RunPushServiceCallbackTest`) into CI.
     *
     * Behaviourally identical to the inherited method (it only calls `super`);
     * the framework's own single call at service creation is unaffected.
     */
    public override fun attachBaseContext(base: Context?) {
        super.attachBaseContext(base)
    }
}

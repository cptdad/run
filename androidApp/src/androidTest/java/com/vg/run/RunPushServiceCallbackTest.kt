package com.vg.run

import android.app.NotificationManager
import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.unifiedpush.android.connector.FailedReason
import org.unifiedpush.android.connector.data.PublicKeySet
import org.unifiedpush.android.connector.data.PushEndpoint
import org.unifiedpush.android.connector.data.PushMessage
import java.io.File

/**
 * Locks the show-only invariants of [RunPushService] into CI **without a
 * real distributor app installed**.
 *
 * The service is driven DIRECTLY: constructed here and handed the framework's
 * base context through the widened `attachBaseContext` seam, then its callbacks
 * are invoked by hand. That is the only way to exercise this class in CI — a
 * genuine wake requires a distributor app, a push server and a relay round
 * trip, none of which exist on a build machine, and "we'll catch it in manual
 * on-device testing" is exactly how the deleted capability mirror survived as
 * long as it did.
 *
 * What each test defends, in order:
 *  - an undecryptable wake shows NOTHING (the forgery gate: anyone who learns
 *    the endpoint URL could otherwise spray "you have messages" at a target);
 *  - a wake at the wrong level shows NOTHING (the local backstop when the relay
 *    DELETE and the distributor unregister both fail during opt-out or a wipe);
 *  - `onNewEndpoint` performs NO NETWORK I/O and stores NO relay authority;
 *  - `onNewEndpoint` writes NOTHING once the level no longer says UNIFIED_PUSH,
 *    so a late endpoint cannot re-create the prefs file an in-session teardown
 *    just swept (the in-session paths arm no ProcessWipeLatch);
 *  - `onUnregistered` clears the level FIRST and leaves a one-shot notice.
 *
 * Transport-agnostic — the connector ships in every build.
 *
 * Run with: ./gradlew connectedAndroidTest --tests "*.RunPushServiceCallbackTest"
 * (or `am instrument` with `-e class` against an already-provisioned device).
 */
class RunPushServiceCallbackTest {

    private val ctx: Context get() = ApplicationProvider.getApplicationContext()

    private fun service(): RunPushService =
        RunPushService().apply { attachBaseContext(ctx) }

    private fun levelStore() = KeyValueStore(ctx, RunViewModel.NOTIFICATION_LEVEL_PREFS_NAME)

    // The persisted opt-in is TWO slots now — the
    // PLAINTEXT wake gate these service callbacks read, plus a device-key AEAD
    // consent proof whose freshness epoch lives in the OPEN VAULT. These tests
    // are about the wake gate and have no vault, so they seed the plaintext slot
    // directly; `NotificationLevelStore.setLevel` deliberately refuses (and
    // writes nothing) without a vault, because a proof sealed against an epoch
    // it cannot read is one no later read could validate.
    private fun seedLevel(level: NotificationLevel) =
        levelStore().putString(NotificationLevelStore.KEY, level.storageValue)

    private fun notificationManager(): NotificationManager =
        ctx.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

    private val storePrefsFile: File
        get() = File(ctx.dataDir, "shared_prefs/${UnifiedPushStateStore.PREFS_NAME}.xml")

    private val endpoint = "https://ntfy.example/UP?up=1&i=abcdef0123456789"
    private val keys = PublicKeySet("B" + "A".repeat(86), "C".repeat(22))

    /** A wake the connector authenticated (`decrypted = true`) — content bytes
     *  deliberately garbage, because the service must never read them. */
    private fun wake(decrypted: Boolean) =
        PushMessage("this must never be parsed".encodeToByteArray(), decrypted)

    @Before
    fun setUp() {
        ProcessWipeLatch.resetForTest()
        try {
            InstrumentationRegistry.getInstrumentation().uiAutomation
                .grantRuntimePermission(ctx.packageName, android.Manifest.permission.POST_NOTIFICATIONS)
        } catch (_: Exception) { /* pre-33 device, or already granted */ }
        NotificationHelper.cancelAll(ctx)
        ctx.deleteSharedPreferences(UnifiedPushStateStore.PREFS_NAME)
        NotificationLevelStore.clearLevel(levelStore(), CryptoProvider(ctx), vault = null)
    }

    @After
    fun tearDown() {
        NotificationHelper.cancelAll(ctx)
        ctx.deleteSharedPreferences(UnifiedPushStateStore.PREFS_NAME)
        NotificationLevelStore.clearLevel(levelStore(), CryptoProvider(ctx), vault = null)
        ProcessWipeLatch.resetForTest()
    }

    // -----------------------------------------------------------------------
    // onMessage
    // -----------------------------------------------------------------------

    /**
     * THE forgery gate. `decrypted == false` means the payload was not
     * authenticated to this device's subscription, so it did not come from the
     * relay — and the endpoint URL is not a secret (it transits the distributor
     * and its push server). Showing such a wake would hand anyone who learned
     * the URL a free "is this person using Rún right now" oracle and a nuisance
     * vector. Fail-CLOSED: dropped silently, never "shown just in case".
     */
    @Test
    fun onMessage_undecryptedWake_postsNothing_evenAtTheCorrectLevel() {
        seedLevel(NotificationLevel.UNIFIED_PUSH)

        service().onMessage(wake(decrypted = false), "default")

        assertTrue(
            "an undecryptable wake must post NOTHING — REQUIRE_ENCRYPTED_PUSH is a " +
                "security gate, not a tunable",
            notificationManager().activeNotifications.isEmpty(),
        )
    }

    /**
     * The local wake gate. Every opt-out and wipe path REMOVES the persisted
     * level before it does anything best-effort, precisely so this check reads
     * "off" the instant the user disables — independent of whether the relay
     * DELETE or the distributor unregister ever land. VENDOR_PUSH is included
     * because a device that switched transports must not be woken through a
     * stale UnifiedPush registration.
     */
    @Test
    fun onMessage_wrongOrAbsentLevel_postsNothing() {
        for (level in listOf(null, NotificationLevel.OFF, NotificationLevel.VENDOR_PUSH, NotificationLevel.POLL)) {
            NotificationHelper.cancelAll(ctx)
            if (level == null) NotificationLevelStore.clearLevel(levelStore(), CryptoProvider(ctx), vault = null)
            else seedLevel(level)

            service().onMessage(wake(decrypted = true), "default")

            assertTrue(
                "a decrypted wake must post nothing at level=$level — only UNIFIED_PUSH " +
                    "may wake through this transport",
                notificationManager().activeNotifications.isEmpty(),
            )
        }
    }

    /**
     * The positive control — without it every assertion above could pass
     * vacuously on an environment that never posts notifications at all.
     */
    @Test
    fun onMessage_decryptedWakeAtUnifiedPushLevel_postsTheContentlessBanner() {
        seedLevel(NotificationLevel.UNIFIED_PUSH)
        val nm = notificationManager()
        assumeTrue(
            "notifications are not deliverable in this environment — skipping rather " +
                "than asserting on an untestable environment",
            nm.areNotificationsEnabled(),
        )

        service().onMessage(wake(decrypted = true), "default")

        assertTrue(
            "a decrypted wake at UNIFIED_PUSH must post the generic banner",
            nm.activeNotifications.isNotEmpty(),
        )
    }

    // -----------------------------------------------------------------------
    // onNewEndpoint
    // -----------------------------------------------------------------------

    /**
     * The wake handler must never reach the relay. It has no vault, so any
     * registration it could perform would need a capability mirror outside the
     * vault — the artifact that was removed.
     *
     * Enforced structurally rather than by inspection: the callback is invoked
     * on the MAIN LOOPER, where Android's default thread policy turns any
     * socket operation into a `NetworkOnMainThreadException`. So this test fails
     * loudly the day someone adds a relay PUT here, instead of quietly passing.
     */
    @Test
    fun onNewEndpoint_performsNoNetworkIo() {
        // The level is the callback's opt-in gate (see
        // onNewEndpoint_afterAnInSessionTeardown_writesNothingAndRecreatesNoFile);
        // without it this test would assert on a discarded endpoint.
        seedLevel(NotificationLevel.UNIFIED_PUSH)
        val thrown = arrayOfNulls<Throwable>(1)
        InstrumentationRegistry.getInstrumentation().runOnMainSync {
            try {
                service().onNewEndpoint(PushEndpoint(endpoint, keys, false), "default")
            } catch (t: Throwable) {
                thrown[0] = t
            }
        }
        assertNull(
            "onNewEndpoint must perform NO network I/O — running it on the main " +
                "looper turns any socket call into NetworkOnMainThreadException. Got: ${thrown[0]}",
            thrown[0],
        )
        assertEquals(endpoint, UnifiedPushStateStore(ctx).readSubscription()?.endpoint)
    }

    /**
     * The endpoint store must stay the receiving-address analogue of the FCM
     * token: an address plus the SEALED RFC 8291 key pair, and nothing that
     * grants any relay authority. Asserted on the whole key set so it fails on
     * ANY new key.
     *
     * `up_auth` is deliberately absent from this set: `auth` is a shared secret
     * (RFC 8291 §3.2), not a public half, so since 2026-08-11 it lives only
     * inside `up_keys_enc`, sealed under an AndroidKeyStore key. The cleartext
     * assertions live in [UnifiedPushStateStoreTest].
     */
    @Test
    fun onNewEndpoint_storesNoInboxIdOrCapability() {
        seedLevel(NotificationLevel.UNIFIED_PUSH)
        service().onNewEndpoint(PushEndpoint(endpoint, keys, false), "default")

        val stored = ctx.getSharedPreferences(UnifiedPushStateStore.PREFS_NAME, Context.MODE_PRIVATE).all
        assertEquals(
            "the wake handler must persist ONLY the WebPush receiving address. Found: $stored",
            setOf("up_endpoint", "up_keys_enc"),
            stored.keys,
        )
        assertFalse(
            "and the wake handler must never write the RFC 8291 auth secret in cleartext",
            storePrefsFile.readText().contains(keys.auth),
        )
    }

    /**
     * A distributor that supplies no WebPush keys cannot be encrypted to, so the
     * relay could only ever send wakes this device drops. Refuse it at the door
     * rather than storing an endpoint that guarantees silent failure.
     */
    @Test
    fun onNewEndpoint_keylessOrImplausibleEndpoint_storesNothing() {
        // At the OPT-IN level, so neither assertion can pass merely because the
        // level gate discarded the endpoint before the content checks ran.
        seedLevel(NotificationLevel.UNIFIED_PUSH)

        service().onNewEndpoint(PushEndpoint(endpoint, null, false), "default")
        assertFalse("a keyless endpoint must not be stored", storePrefsFile.exists())

        service().onNewEndpoint(PushEndpoint("http://ntfy.example/UP?i=abcdef0123456789", keys, false), "default")
        assertFalse("an http:// endpoint must not be stored", storePrefsFile.exists())
    }

    /**
     * The `onNewEndpoint` sibling of
     * [onUnregistered_afterADeliberateOptOut_writesNothingAndRecreatesNoFile],
     * and — until this fix — the ONE callback of the four with no level gate at
     * all (`onMessage` and `onUnregistered` both had one).
     *
     * Its only guard was the [ProcessWipeLatch] inside
     * `UnifiedPushStateStore.saveSubscription`, and that latch is armed ONLY by
     * [WipeRoutine]. The two IN-SESSION teardowns — the settings opt-out branch
     * and the enable-FAILURE branch of
     * `RunViewModel.setBackgroundNotificationsEnabledAwaiting` — arm nothing, so
     * a NEW_ENDPOINT landing after either of them MINTED
     * `unifiedpush_state_prefs.xml` again, carrying the endpoint URL that names
     * the user's push server, with nothing left to ever remove it (the modal's
     * `applyLevel` dispatches no disable, and the control-poll dispatcher keys
     * off the level that branch just cleared).
     *
     * The window is not theoretical and is widest exactly where it hurts: the
     * failed-enable path gives up on the distributor handshake after a TIMEOUT
     * and tears down while the distributor's answer is still in flight. The
     * connector's own `MessagingReceiver.onReceive` does drop a broadcast whose
     * token no longer resolves to a registration (verified in connector-3.3.5's
     * sources — it returns early on `registrations.getInstance(token) == null`),
     * but that receiver runs on its own background executor via `goAsync()`, so
     * it can resolve the token BEFORE the teardown deletes the row and deliver
     * AFTER the sweep. It is also best-effort: every step of
     * `UnifiedPushSupport.destroyLocalPushIdentity` swallows exceptions, so a
     * failed unregister leaves the token resolvable. The level gate removes the
     * need to reason about any of that.
     */
    @Test
    fun onNewEndpoint_afterAnInSessionTeardown_writesNothingAndRecreatesNoFile() {
        // Exactly the state opt-out / a failed enable leaves behind: level
        // already cleared, prefs already swept, NO ProcessWipeLatch armed.
        NotificationLevelStore.clearLevel(levelStore(), CryptoProvider(ctx), vault = null)
        ctx.deleteSharedPreferences(UnifiedPushStateStore.PREFS_NAME)
        assertFalse("precondition: the swept file must be absent", storePrefsFile.exists())
        assertFalse(
            "precondition: an in-session teardown arms NO wipe latch — that is why the " +
                "latch inside saveSubscription cannot be this callback's only guard",
            ProcessWipeLatch.wipedThisProcess,
        )

        service().onNewEndpoint(PushEndpoint(endpoint, keys, false), "default")

        assertFalse(
            "a NEW_ENDPOINT arriving after an in-session teardown must not RE-CREATE " +
                "${storePrefsFile.name} — it carries the endpoint URL, which names the " +
                "user's push server, and nothing would ever remove it again",
            storePrefsFile.exists(),
        )
        assertNull(
            "and nothing may be readable back from the store",
            UnifiedPushStateStore(ctx).readSubscription(),
        )
    }

    /**
     * The complement of the guard above: a level that names the OTHER transport
     * must not be able to persist a UnifiedPush endpoint either. Same rule
     * `onMessage` already applies (UNIFIED_PUSH exactly, not merely "not OFF"),
     * so a `google` device that switched to FCM cannot accumulate a stale
     * UnifiedPush address it can never be woken through.
     */
    @Test
    fun onNewEndpoint_atAnotherTransportsLevel_storesNothing() {
        for (level in listOf(NotificationLevel.OFF, NotificationLevel.VENDOR_PUSH, NotificationLevel.POLL)) {
            ctx.deleteSharedPreferences(UnifiedPushStateStore.PREFS_NAME)
            seedLevel(level)

            service().onNewEndpoint(PushEndpoint(endpoint, keys, false), "default")

            assertFalse(
                "an endpoint must not be persisted at level=$level — only UNIFIED_PUSH " +
                    "opted into this transport",
                storePrefsFile.exists(),
            )
        }
    }

    // -----------------------------------------------------------------------
    // onUnregistered / onRegistrationFailed
    // -----------------------------------------------------------------------

    /**
     * The distributor dropped us. Local teardown only: no relay DELETE is
     * possible (no vault, no capability) and none is needed — a stale relay row
     * POSTs to an endpoint the distributor no longer honours, and the level this
     * clears would drop it anyway.
     */
    @Test
    fun onUnregistered_clearsLevelAndStore_andArmsTheOneShotNotice() {
        seedLevel(NotificationLevel.UNIFIED_PUSH)
        UnifiedPushStateStore(ctx).saveSubscription(endpoint, keys.pubKey, keys.auth)

        service().onUnregistered("default")

        assertEquals(
            "the local wake gate must read OFF immediately",
            NotificationLevel.OFF, NotificationLevelStore.getLevel(levelStore()),
        )
        assertNull("the subscription must be gone", UnifiedPushStateStore(ctx).readSubscription())
        assertTrue(
            "the settings modal must be able to tell the user once",
            UnifiedPushStateStore(ctx).consumeUnregisteredNotice(),
        )
    }

    /**
     * The other half of the notice rule, and the one that is about RESIDUE
     * rather than UX.
     *
     * The connector broadcasts UNREGISTERED into this callback for a DELIBERATE
     * local unregister too — so opt-out and [WipeRoutine] both land here, and
     * this callback can arrive AFTER `sweepLocalArtifacts` already deleted the
     * prefs file. An unconditional marker write would then RE-CREATE
     * `unifiedpush_state_prefs.xml`: the write-after-delete race the Firebase teardown hit with
     * Firebase, reproduced here in a form no full wipe (and therefore no
     * [ProcessWipeLatch]) would catch, because the settings opt-out sets no
     * latch.
     *
     * The level having been cleared first is the "the user did not ask for
     * this" signal every deliberate teardown path establishes.
     */
    @Test
    fun onUnregistered_afterADeliberateOptOut_writesNothingAndRecreatesNoFile() {
        // Exactly the state opt-out leaves behind: level already cleared, store
        // already swept.
        NotificationLevelStore.clearLevel(levelStore(), CryptoProvider(ctx), vault = null)
        ctx.deleteSharedPreferences(UnifiedPushStateStore.PREFS_NAME)
        assertFalse("precondition: the swept file must be absent", storePrefsFile.exists())

        service().onUnregistered("default")

        assertFalse(
            "a deliberate opt-out's UNREGISTERED callback must not RE-CREATE " +
                "${storePrefsFile.name} after the sweep already removed it",
            storePrefsFile.exists(),
        )
        assertFalse(
            "and it must not arm a 'your distributor dropped you' notice the user " +
                "would see after deliberately turning notifications off",
            UnifiedPushStateStore(ctx).consumeUnregisteredNotice(),
        )
    }

    /**
     * A refusal must NOT destroy a working subscription — a distributor
     * restarting or a push server briefly down is transient, and the toggle-ON
     * handshake is the only thing that should act on it.
     */
    @Test
    fun onRegistrationFailed_leavesPersistedStateUntouched() {
        seedLevel(NotificationLevel.UNIFIED_PUSH)
        UnifiedPushStateStore(ctx).saveSubscription(endpoint, keys.pubKey, keys.auth)

        service().onRegistrationFailed(FailedReason.NETWORK, "default")
        service().onTempUnavailable("default")

        assertEquals(NotificationLevel.UNIFIED_PUSH, NotificationLevelStore.getLevel(levelStore()))
        assertEquals(endpoint, UnifiedPushStateStore(ctx).readSubscription()?.endpoint)
    }

    /**
     * The reason vocabulary the toggle branches on. `VAPID_REQUIRED` gets its
     * own error copy (a different distributor is the fix, not a retry), so the
     * constant the ViewModel compares against must match the connector's own
     * enum name — a typo there would silently downgrade it to the generic error.
     */
    @Test
    fun vapidRequiredReasonName_matchesTheConnectorEnum() {
        assertEquals(
            UnifiedPushEndpointSignal.REASON_VAPID_REQUIRED,
            FailedReason.VAPID_REQUIRED.name,
        )
    }
}

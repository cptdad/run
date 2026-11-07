package com.vg.run

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File
import java.security.KeyStore

/**
 * [UnifiedPushStateStore] — the ONE new on-disk artifact of the UnifiedPush
 * notification tier, so its contract is worth pinning precisely.
 *
 * Instrumented rather than plain-JVM because the store is backed by real
 * SharedPreferences AND a real AndroidKeyStore key (this module has no
 * Robolectric), and because several of the properties under test are about the
 * FILE — that clearing removes keys instead of writing blanks, that a clear on
 * a never-written store does not MINT the file, and that the RFC 8291 `auth`
 * SHARED SECRET never reaches it in cleartext.
 *
 * Nothing here is Google-specific.
 *
 * Run with: ./gradlew connectedAndroidTest --tests "*.UnifiedPushStateStoreTest"
 * (or `am instrument` with `-e class` against an already-provisioned device —
 * connectedAndroidTest uninstalls the app and destroys seeded state).
 */
class UnifiedPushStateStoreTest {

    private val ctx: Context get() = ApplicationProvider.getApplicationContext()

    private val prefsFile: File
        get() = File(ctx.dataDir, "shared_prefs/${UnifiedPushStateStore.PREFS_NAME}.xml")

    private val endpoint = "https://ntfy.example/UP?up=1&i=abcdef0123456789"
    private val p256dh = "B" + "A".repeat(86)
    private val auth = "C".repeat(22)

    @Before
    fun setUp() {
        // Instrumented tests share one process, and the latch is one-way in
        // production — a wipe test running earlier would otherwise silently
        // turn every write below into a no-op and make this class pass
        // vacuously.
        ProcessWipeLatch.resetForTest()
        ctx.deleteSharedPreferences(UnifiedPushStateStore.PREFS_NAME)
        // The Keystore alias outlives a prefs deletion, and its PRESENCE is a
        // live input (it is what makes the legacy-cleartext path refuse). A
        // fresh install has neither, so start every test from that state or the
        // migration tests would pass/fail on whichever test ran before them.
        deleteStateAlias()
    }

    @After
    fun tearDown() {
        ProcessWipeLatch.resetForTest()
        ctx.deleteSharedPreferences(UnifiedPushStateStore.PREFS_NAME)
        deleteStateAlias()
    }

    private fun rawPrefs() =
        ctx.getSharedPreferences(UnifiedPushStateStore.PREFS_NAME, Context.MODE_PRIVATE)

    private fun deleteStateAlias() {
        try {
            KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
                .deleteEntry(UnifiedPushStateStore.KEYSTORE_ALIAS)
        } catch (_: Exception) { /* absent or unavailable */ }
    }

    private fun stateAliasExists(): Boolean = try {
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            .containsAlias(UnifiedPushStateStore.KEYSTORE_ALIAS)
    } catch (_: Exception) {
        false
    }

    /** Exactly what a pre-2026-08-11 build left on disk. */
    private fun seedLegacyCleartext() {
        rawPrefs().edit()
            .putString("up_endpoint", endpoint)
            .putString("up_p256dh", p256dh)
            .putString("up_auth", auth)
            .commit()
    }

    @Test
    fun saveThenRead_roundTrips() {
        val store = UnifiedPushStateStore(ctx)

        assertTrue("a well-formed subscription must be stored", store.saveSubscription(endpoint, p256dh, auth))

        val read = UnifiedPushStateStore(ctx).readSubscription()
        assertEquals(endpoint, read?.endpoint)
        assertEquals(p256dh, read?.p256dh)
        assertEquals(auth, read?.auth)
    }

    /**
     * Android's (inboxId, readCap) mirror was deleted because the relay READ capability is the inbox OWNER
     * capability, so ANY copy of it outside the vault hands an AFU forensic
     * image the ability to drain and destroy every inbound inbox.
     *
     * This store is the receiving-address analogue of the FCM token and must
     * NEVER grow a field carrying relay authority. Asserted against the raw XML
     * — a key-set assertion, not a "we didn't call putString(inboxId)" one — so
     * it fails on ANY new key rather than only on the ones this test imagined.
     */
    @Test
    fun storedFile_containsOnlyTheAddressFields_neverAnInboxIdOrCapability() {
        UnifiedPushStateStore(ctx).saveSubscription(endpoint, p256dh, auth)

        val keys = rawPrefs().all.keys
        assertEquals(
            "unifiedpush_state_prefs must hold ONLY the WebPush receiving address " +
                "(no inbox id, no capability, ever). Found: $keys",
            setOf("up_endpoint", "up_keys_enc"),
            keys,
        )
    }

    /**
     * THE finding this file's storage model was rebuilt for (2026-08-11).
     *
     * `auth` is not a public half: RFC 8291 §3.2 makes it a 16-octet SHARED
     * secret, and (`p256dh`, `auth`) is exactly what an RFC 8291 sender needs.
     * An AFU image of the cleartext file therefore let anyone encrypt a record,
     * POST it to the endpoint, and make the handset raise the "Notification"
     * banner on demand — past `RunPushService.REQUIRE_ENCRYPTED_PUSH`, whose
     * entire argument is that only the relay can produce an authenticated wake.
     *
     * Asserted against the raw FILE BYTES, not the key set, so it fails for any
     * route that puts the material back on disk (a new key, a debug dump, a
     * value appended to the endpoint).
     *
     * The endpoint is deliberately still cleartext — see the store's kdoc — and
     * that is asserted too, so a later change that seals it has to come here and
     * state its reasoning rather than silently flipping a deliberate trade-off.
     */
    @Test
    fun storedFile_holdsNoCleartextRfc8291KeyMaterial() {
        assertTrue(UnifiedPushStateStore(ctx).saveSubscription(endpoint, p256dh, auth))

        val onDisk = prefsFile.readText()
        assertFalse(
            "the RFC 8291 `auth` SHARED SECRET must never be at rest in cleartext — with " +
                "p256dh it forges a wake this device will display. File was:\n$onDisk",
            onDisk.contains(auth),
        )
        assertFalse(
            "p256dh rides in the same seal (forging needs both). File was:\n$onDisk",
            onDisk.contains(p256dh),
        )
        assertTrue(
            "the endpoint stays cleartext ON PURPOSE (it must be readable without the " +
                "Keystore, the distributor app stores it anyway, and alone it cannot forge a " +
                "wake). File was:\n$onDisk",
            onDisk.contains("up_endpoint"),
        )
        assertTrue("the sealed pair must be present", rawPrefs().contains("up_keys_enc"))
    }

    /**
     * Migration, the half that must never regress: an install that opted in
     * before the seal existed carries `up_p256dh`/`up_auth` in cleartext, and it
     * MUST keep working. Read-old-write-new was chosen over discard precisely
     * because nothing would re-ask the distributor for an endpoint — a discard
     * would silently kill push for every existing opt-in.
     *
     * Pins both halves: the values still read back, and the cleartext is gone
     * afterwards (lazy migrate-on-read, write-before-delete).
     */
    @Test
    fun legacyCleartextSubscription_stillReads_andIsMigratedToTheSealedForm() {
        seedLegacyCleartext()
        assertFalse("precondition: a legacy install has no seal key", stateAliasExists())

        val read = UnifiedPushStateStore(ctx).readSubscription()

        assertEquals("a legacy opt-in must never be bricked by the format change", endpoint, read?.endpoint)
        assertEquals(p256dh, read?.p256dh)
        assertEquals(auth, read?.auth)

        val keys = rawPrefs().all.keys
        assertEquals(
            "the read must have migrated the pair into the sealed key and dropped the " +
                "cleartext. Found: $keys",
            setOf("up_endpoint", "up_keys_enc"),
            keys,
        )
        assertFalse(
            "and the cleartext must be gone from the FILE, not merely from the key set",
            prefsFile.readText().contains(auth),
        )

        // …and the migrated form still opens on a later, independent read.
        val again = UnifiedPushStateStore(ctx).readSubscription()
        assertEquals(auth, again?.auth)
        assertEquals(p256dh, again?.p256dh)
    }

    /**
     * The migration is a WRITE, so it obeys the same [ProcessWipeLatch] rule as
     * every other write here: after a wipe it must not touch the file. The READ
     * itself is still allowed (reads create nothing), so this also pins that the
     * latch never turns a legacy subscription into a brick — it just defers.
     */
    @Test
    fun legacyMigration_isRefusedAfterAWipeInThisProcess() {
        seedLegacyCleartext()
        ProcessWipeLatch.latch()

        assertNotNull(
            "a read is not a write: the latch must not make a legacy subscription unreadable",
            UnifiedPushStateStore(ctx).readSubscription(),
        )
        assertFalse(
            "no post-wipe write: the sealed key must not have been created",
            rawPrefs().contains("up_keys_enc"),
        )
    }

    /**
     * The legacy path is one-shot and self-tightening. Once this install has
     * sealed at least once, planted cleartext keys are ignored outright — an
     * app-data restore can write `shared_prefs`, but it cannot write the
     * Keystore, so the alias's existence is the one signal a file-level attacker
     * cannot forge.
     *
     * Without this the fix would be cosmetic: an attacker could drop
     * `up_keys_enc` and plant a subscription whose private key THEY hold, and
     * forge wakes exactly as before.
     */
    @Test
    fun plantedCleartextKeys_areIgnoredOnceThisInstallHasSealed() {
        assertTrue(UnifiedPushStateStore(ctx).saveSubscription(endpoint, p256dh, auth))
        assertTrue("precondition: sealing must have minted the alias", stateAliasExists())

        // Exactly what a malicious app-data restore can do: drop the blob it
        // cannot produce, plant a pair it controls.
        rawPrefs().edit()
            .remove("up_keys_enc")
            .putString("up_p256dh", p256dh)
            .putString("up_auth", auth)
            .commit()

        assertNull(
            "cleartext key material must not be honoured on an install that has already " +
                "sealed — that is the downgrade route back to the original vulnerability",
            UnifiedPushStateStore(ctx).readSubscription(),
        )
    }

    /**
     * Fail-CLOSED on a damaged seal. A blob that will not open must read as "no
     * subscription" and must NEVER fall back to anything — the next registration
     * pass then asks the distributor for a fresh subscription.
     */
    @Test
    fun tamperedSealedKeys_readBackAsNoSubscription() {
        UnifiedPushStateStore(ctx).saveSubscription(endpoint, p256dh, auth)
        val sealed = rawPrefs().getString("up_keys_enc", null)!!
        // Flip one base64 character inside the ciphertext body.
        val damaged = sealed.dropLast(1) + (if (sealed.last() == 'A') 'B' else 'A')
        rawPrefs().edit().putString("up_keys_enc", damaged).commit()

        assertNull(UnifiedPushStateStore(ctx).readSubscription())
    }

    /**
     * The endpoint is cleartext but NOT unprotected: it is bound into the seal
     * as AEAD associated data, so substituting an attacker-controlled push
     * server — which [isPlausibleUnifiedPushEndpoint] alone cannot catch, since
     * any `https://` URL passes it — makes the keys fail to open and the whole
     * subscription read back as absent.
     *
     * This is the property that lets the endpoint stay readable without the
     * Keystore while still being tamper-evident.
     */
    @Test
    fun swappedButPlausibleEndpoint_readsBackAsNoSubscription() {
        UnifiedPushStateStore(ctx).saveSubscription(endpoint, p256dh, auth)
        val swapped = "https://attacker.example/UP?up=1&i=abcdef0123456789"
        assertTrue("precondition: the swap must pass the shape check", isPlausibleUnifiedPushEndpoint(swapped))

        rawPrefs().edit().putString("up_endpoint", swapped).commit()

        assertNull(
            "the endpoint is AEAD-bound to the sealed keys: swapping it must invalidate them",
            UnifiedPushStateStore(ctx).readSubscription(),
        )
    }

    /**
     * Crypto-erase means what it says: after `UnifiedPushSupport.eraseKeySurface`
     * has destroyed the alias, the surviving ciphertext yields nothing — and the
     * read must degrade to "no subscription" rather than throwing out of a
     * service callback that has no error path.
     *
     * (The wipe/opt-out paths delete the prefs file too; this pins the ORDER's
     * guarantee — the erase alone is already sufficient, so an interrupted
     * teardown is safe.)
     */
    @Test
    fun erasedKeySurface_readsBackAsNoSubscription_andDoesNotThrow() {
        UnifiedPushStateStore(ctx).saveSubscription(endpoint, p256dh, auth)
        assertNotNull("precondition", UnifiedPushStateStore(ctx).readSubscription())

        UnifiedPushSupport.eraseKeySurface(ctx)

        assertFalse("the alias must be gone", stateAliasExists())
        assertNull(
            "an interrupted teardown leaves ciphertext with no key — that must read as " +
                "absent, not throw",
            UnifiedPushStateStore(ctx).readSubscription(),
        )
    }

    @Test
    fun clear_removesKeys_doesNotWriteBlanks() {
        val store = UnifiedPushStateStore(ctx)
        store.saveSubscription(endpoint, p256dh, auth)
        store.markUnregisteredNoticePending()
        assertTrue("seed must exist", prefsFile.exists())

        store.clear()

        assertNull("the subscription must read back as absent", UnifiedPushStateStore(ctx).readSubscription())
        val prefs = ctx.getSharedPreferences(UnifiedPushStateStore.PREFS_NAME, Context.MODE_PRIVATE)
        assertTrue(
            "clear() must REMOVE keys, never write empty/sentinel values — a written " +
                "falsy value is itself proof the app was configured, an absent key is not " +
                "(NotificationLevelStore.clearLevel's absence-not-artifact rule). Found: ${prefs.all}",
            prefs.all.isEmpty(),
        )
    }

    /**
     * `edit().remove(k)` on a key the map does not hold makes NO change, and
     * SharedPreferencesImpl only skips the disk write for a no-change commit
     * WHEN THE FILE ALREADY EXISTS — so an unguarded clear on a fresh install
     * MINTS the prefs file, manufacturing the very "this app was configured"
     * artifact the wipe exists to remove. [KeyValueStore.remove]'s `contains()`
     * guard is what prevents it; this is the regression test for that coupling.
     */
    @Test
    fun clear_onNeverWrittenStore_doesNotCreateTheFile() {
        assertFalse("precondition: the file must be absent", prefsFile.exists())

        UnifiedPushStateStore(ctx).clear()

        assertFalse(
            "clearing a store that was never written must not MINT ${prefsFile.name}",
            prefsFile.exists(),
        )
    }

    @Test
    fun unregisteredNotice_isOneShot() {
        val store = UnifiedPushStateStore(ctx)
        assertFalse("nothing pending on a fresh store", store.consumeUnregisteredNotice())

        store.markUnregisteredNoticePending()

        assertTrue("first read consumes it", UnifiedPushStateStore(ctx).consumeUnregisteredNotice())
        assertFalse("second read must be false — the notice shows once", UnifiedPushStateStore(ctx).consumeUnregisteredNotice())
    }

    @Test
    fun implausibleEndpointOrMissingKeys_refused() {
        val store = UnifiedPushStateStore(ctx)

        assertFalse("http:// is refused — the relay's Tor CONNECT tunnel cannot reach it",
            store.saveSubscription("http://ntfy.example/UP?i=abcdef0123456789", p256dh, auth))
        assertFalse(store.saveSubscription("https://x", p256dh, auth))
        assertFalse("a keyless endpoint is unusable: the relay must be able to RFC 8291-encrypt",
            store.saveSubscription(endpoint, null, auth))
        assertFalse(store.saveSubscription(endpoint, p256dh, null))
        assertFalse("nothing may have been persisted by a refused save", prefsFile.exists())
    }

    /**
     * Fail-closed on tamper. This is a plaintext, non-integrity-protected file:
     * an examiner or a malicious data restore can edit it, and its endpoint ends
     * up in an HTTP body the relay acts on. A stored value that no longer passes
     * [isPlausibleUnifiedPushEndpoint] must read back as "no subscription", so
     * the next registration pass asks the distributor for a fresh one instead of
     * forwarding attacker-chosen bytes.
     */
    @Test
    fun tamperedEndpointOnDisk_readsBackAsNoSubscription() {
        UnifiedPushStateStore(ctx).saveSubscription(endpoint, p256dh, auth)
        ctx.getSharedPreferences(UnifiedPushStateStore.PREFS_NAME, Context.MODE_PRIVATE)
            .edit().putString("up_endpoint", "http://attacker.example/UP?i=abcdef0123456789").commit()

        assertNull(UnifiedPushStateStore(ctx).readSubscription())
    }

    /**
     * [ProcessWipeLatch]'s rule for a new consumer. The wake path is
     * asynchronous and out-of-process, so after a wipe the distributor can still
     * deliver a NEW_ENDPOINT broadcast; an ungated write would re-create
     * `unifiedpush_state_prefs.xml` carrying the push-server URL, dated AFTER
     * the erasure.
     */
    @Test
    fun writesAreRefusedAfterAWipeInThisProcess() {
        ProcessWipeLatch.latch()

        assertFalse(UnifiedPushStateStore(ctx).saveSubscription(endpoint, p256dh, auth))
        UnifiedPushStateStore(ctx).markUnregisteredNoticePending()

        assertFalse(
            "a post-wipe write must never re-create ${prefsFile.name}",
            prefsFile.exists(),
        )
    }
}

package com.vg.run

import android.content.Context
import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Guards the daily change-PIN abuse cap (auto-wipe after MAX_PER_DAY change-PIN
 * attempts in a rolling 24h window). The change-PIN flow is exempt from the
 * unlock-screen 5-attempt wipe, so without this cap it is a penalty-free channel
 * for probing the other vault's PIN.
 *
 * Run with: ./gradlew connectedAndroidTest
 */
@RunWith(AndroidJUnit4::class)
class ChangePinAttemptStoreTest {

    companion object {
        private const val ATTEMPTS_PREFS = "pin_attempts_prefs"
        private const val ANCHOR_PREFS = "change_pin_anchor_test_prefs"
        private val STORAGE_KEY = ChangePinAttemptStore.STORAGE_KEY
        private val MAX = ChangePinAttemptStore.MAX_PER_DAY
        private val CTX = "change-pin-attempts".toByteArray()
        private const val MINUTE = 60_000L
        private const val HOUR = 60 * MINUTE
        private const val WRAP_KEY = "vlt_c" // VAULT_DBKEY_STORAGE_KEY
    }

    private lateinit var context: Context

    @Before
    fun setUp() {
        context = InstrumentationRegistry.getInstrumentation().targetContext
        context.deleteSharedPreferences(ATTEMPTS_PREFS)
        context.deleteSharedPreferences(ANCHOR_PREFS)
    }

    @After
    fun tearDown() {
        context.deleteSharedPreferences(ATTEMPTS_PREFS)
        context.deleteSharedPreferences(ANCHOR_PREFS)
    }

    private fun newStore() =
        ChangePinAttemptStore(KeyValueStore(context, ATTEMPTS_PREFS), CryptoProvider(context))

    /** Attempts 1..MAX-1 do not wipe; the MAX-th does. */
    @Test
    fun limitReachedOnMaxthAttempt() {
        val store = newStore()
        for (i in 1 until MAX) {
            assertFalse("attempt $i must not trigger wipe", store.recordAttemptAndCheckLimit())
        }
        assertTrue("attempt $MAX must trigger wipe", store.recordAttemptAndCheckLimit())
    }

    /** The count is durable across (simulated) process restarts. */
    @Test
    fun countPersistsAcrossInstances() {
        val half = MAX / 2
        val s1 = newStore()
        repeat(half) { assertFalse(s1.recordAttemptAndCheckLimit()) }

        // Fresh instance over the same prefs file = a process restart.
        val s2 = newStore()
        for (i in half + 1 until MAX) {
            assertFalse("attempt $i after restart must not wipe", s2.recordAttemptAndCheckLimit())
        }
        assertTrue("MAX-th attempt after restart must wipe", s2.recordAttemptAndCheckLimit())
    }

    /** A tampered / undecryptable counter is treated as adversarial → wipe. */
    @Test
    fun tamperedCiphertext_triggersWipe() {
        newStore().recordAttemptAndCheckLimit()
        context.getSharedPreferences(ATTEMPTS_PREFS, Context.MODE_PRIVATE)
            .edit().putString(STORAGE_KEY, "not-valid-ciphertext").commit()
        assertTrue("tampered counter must trigger wipe", newStore().recordAttemptAndCheckLimit())
    }

    /** reset() returns the counter to the start of a fresh window. */
    @Test
    fun reset_clearsCounter() {
        val s = newStore()
        repeat(MAX - 1) { s.recordAttemptAndCheckLimit() }
        s.reset()
        // Next attempt is #1 of a new window, not the MAX-th.
        assertFalse("after reset the count must restart", newStore().recordAttemptAndCheckLimit())
    }

    /** An emergency wipe (prefs-file deletion) restarts the counter. */
    @Test
    fun deletingPrefs_resetsCounter() {
        val s = newStore()
        repeat(MAX - 1) { s.recordAttemptAndCheckLimit() }
        context.deleteSharedPreferences(ATTEMPTS_PREFS)
        assertFalse("wiped counter must restart", newStore().recordAttemptAndCheckLimit())
    }

    /**
     * A counter from an EXPIRED window rolls over: even a near-max stored count
     * does not wipe, because the new attempt starts a fresh 24h window at 1.
     * This is the "during one day" semantics — abuse must be concentrated.
     */
    @Test
    fun expiredWindow_rollsOverAndDoesNotWipe() {
        val expiredStart = System.currentTimeMillis() - ChangePinAttemptStore.WINDOW_MS - 60_000L
        seedState(windowStart = expiredStart, count = MAX - 1)

        // Despite a stored count of MAX-1, the window is stale → reset to 1.
        assertFalse("expired window must reset, not wipe", newStore().recordAttemptAndCheckLimit())
    }

    /** Within the window, a near-max stored count DOES wipe on the next attempt. */
    @Test
    fun freshWindowNearMax_wipesOnNextAttempt() {
        seedState(windowStart = System.currentTimeMillis(), count = MAX - 1)
        assertTrue("MAX-th attempt in-window must wipe", newStore().recordAttemptAndCheckLimit())
    }

    /**
     * A window whose start is in the FUTURE — i.e. the device
     * clock was rolled BACKWARD between guesses — must NOT reset the count. Seed
     * count=MAX-1 at a future windowStart; the next attempt must still trip the
     * cap. Pre-fix the `now < windowStart` term zeroed the count (returned false).
     */
    @Test
    fun backwardClock_doesNotResetCount() {
        seedState(windowStart = System.currentTimeMillis() + 60 * 60 * 1000L, count = MAX - 1)
        assertTrue("a backward clock must keep the count, not reset it",
            newStore().recordAttemptAndCheckLimit())
    }

    // ---- forward-clock defense ----

    /**
     * A FORWARD wall-clock jump past 24h must NOT reset the 100/day cap when a
     * monotonic anchor proves little real time elapsed — this cap is the change-
     * PIN flow's only numeric bound.
     */
    @Test
    fun forwardClockJump_withMonotonicAnchor_doesNotReset() {
        val boot = 7L
        seedStateWithMono(
            windowStart = System.currentTimeMillis() - ChangePinAttemptStore.WINDOW_MS - HOUR,
            count = MAX - 1, elapsed = 10 * HOUR, bootId = boot,
        )
        val store = ChangePinAttemptStore(
            KeyValueStore(context, ATTEMPTS_PREFS), CryptoProvider(context),
            monotonicNow = { MonotonicSample(10 * HOUR + 5 * MINUTE, boot) },
        )
        assertTrue("forward wall jump must not reset the change-PIN cap → MAX-th wipes",
            store.recordAttemptAndCheckLimit())
    }

    /** Backward compatibility: a legacy 20-byte blob (no anchor) still decodes. */
    @Test
    fun legacy20ByteBlob_stillReadsAndRecords() {
        seedState(windowStart = System.currentTimeMillis(), count = MAX - 1)
        val store = ChangePinAttemptStore(
            KeyValueStore(context, ATTEMPTS_PREFS), CryptoProvider(context),
            monotonicNow = { MonotonicSample(HOUR, 7L) },
        )
        assertTrue("legacy in-window near-max blob still trips the cap",
            store.recordAttemptAndCheckLimit())
    }

    // ---- Brick-safe deletion defense ----

    /**
     * BRICK FIX (#9): a pre-existing / pre-anchor vault's FIRST-ever change-PIN —
     * DB-key wrap present but NO counter and NO marker — must ESTABLISH, not wipe.
     * (iOS never re-establishes outside provision, so round 1 emergency-wiped these
     * on the first change-PIN.)
     */
    @Test
    fun firstChangePin_preExistingVault_establishesNotWipe() {
        val anchor = KeyValueStore(context, ANCHOR_PREFS)
        anchor.putStringSync(WRAP_KEY, "wrapped-db-key-blob") // provisioned vault, no counter/marker
        val store = ChangePinAttemptStore(
            KeyValueStore(context, ATTEMPTS_PREFS), CryptoProvider(context),
            anchorStore = anchor, vaultWrapKeyInAnchorStore = WRAP_KEY,
        )
        assertFalse("first-ever change-PIN on a pre-anchor vault must establish, not wipe",
            store.recordAttemptAndCheckLimit())
        assertTrue("establish-on-read must arm the change-PIN marker in the fate-shared store",
            context.getSharedPreferences(ANCHOR_PREFS, Context.MODE_PRIVATE)
                .contains(ChangePinAttemptStore.ESTABLISHED_KEY))
    }

    /**
     * After establishment, deleting ONLY the counter blob while the marker and the
     * DB-key wrap survive is the deletion signature → wipe.
     */
    @Test
    fun counterDeletedAfterEstablishment_withMarkerAndWrap_wipes() {
        val anchor = KeyValueStore(context, ANCHOR_PREFS)
        anchor.putStringSync(WRAP_KEY, "wrapped-db-key-blob")
        ChangePinAttemptStore(
            KeyValueStore(context, ATTEMPTS_PREFS), CryptoProvider(context),
            anchorStore = anchor, vaultWrapKeyInAnchorStore = WRAP_KEY,
        ).recordAttemptAndCheckLimit()                  // establishes counter (ATTEMPTS) + marker (ANCHOR)
        context.deleteSharedPreferences(ATTEMPTS_PREFS) // delete counter only; marker + wrap survive
        assertTrue("counter deleted after establishment (marker + wrap survive) must wipe",
            ChangePinAttemptStore(
                KeyValueStore(context, ATTEMPTS_PREFS), CryptoProvider(context),
                anchorStore = KeyValueStore(context, ANCHOR_PREFS), vaultWrapKeyInAnchorStore = WRAP_KEY,
            ).recordAttemptAndCheckLimit())
    }

    /**
     * Known limitation: deleting BOTH the counter and the (iOS per-item-deletable)
     * marker while the wrap survives re-establishes (reset), not wipe — a bounded
     * reset mitigated in depth by the Argon2id KDF cost.
     */
    @Test
    fun counterAndMarkerBothDeleted_isKnownLimitationReset() {
        val anchor = KeyValueStore(context, ANCHOR_PREFS)
        anchor.putStringSync(WRAP_KEY, "wrapped-db-key-blob")
        ChangePinAttemptStore(
            KeyValueStore(context, ATTEMPTS_PREFS), CryptoProvider(context),
            anchorStore = anchor, vaultWrapKeyInAnchorStore = WRAP_KEY,
        ).recordAttemptAndCheckLimit()
        context.deleteSharedPreferences(ATTEMPTS_PREFS) // counter gone
        context.getSharedPreferences(ANCHOR_PREFS, Context.MODE_PRIVATE)
            .edit().remove(ChangePinAttemptStore.ESTABLISHED_KEY).commit() // marker gone, wrap kept
        assertFalse("delete-both is a known limitation → re-establish, not wipe",
            ChangePinAttemptStore(
                KeyValueStore(context, ATTEMPTS_PREFS), CryptoProvider(context),
                anchorStore = KeyValueStore(context, ANCHOR_PREFS), vaultWrapKeyInAnchorStore = WRAP_KEY,
            ).recordAttemptAndCheckLimit())
    }

    /** Opt-in wrap anchor but nothing provisioned → a genuine first change-PIN
     *  must NOT wipe (starts a fresh window). */
    @Test
    fun firstChangePin_wrapKeyOptInButNotProvisioned_doesNotWipe() {
        val store = ChangePinAttemptStore(
            KeyValueStore(context, ATTEMPTS_PREFS), CryptoProvider(context),
            anchorStore = KeyValueStore(context, ANCHOR_PREFS), vaultWrapKeyInAnchorStore = WRAP_KEY,
        )
        assertFalse("first change-PIN on a store with no wrap present must start a fresh window",
            store.recordAttemptAndCheckLimit())
    }

    // Writes a crafted {windowStart, count} state in the same on-disk format
    // ChangePinAttemptStore uses: windowStart(8 BE) ‖ count(4 BE) ‖ pad(8).
    private fun seedState(windowStart: Long, count: Int) {
        val payload = ByteArray(20)
        for (i in 0 until 8) payload[i] = (windowStart ushr (56 - i * 8)).toByte()
        for (i in 0 until 4) payload[8 + i] = (count ushr (24 - i * 8)).toByte()
        // last 8 bytes (pad) left zero — value is irrelevant
        writeBlob(payload)
    }

    // 36-byte forward-clock-defense format: windowStart(8) ‖ count(4) ‖ monoElapsed(8) ‖ bootId(8) ‖ pad(8).
    private fun seedStateWithMono(windowStart: Long, count: Int, elapsed: Long, bootId: Long) {
        val payload = ByteArray(36)
        for (i in 0 until 8) payload[i] = (windowStart ushr (56 - i * 8)).toByte()
        for (i in 0 until 4) payload[8 + i] = (count ushr (24 - i * 8)).toByte()
        for (i in 0 until 8) payload[12 + i] = (elapsed ushr (56 - i * 8)).toByte()
        for (i in 0 until 8) payload[20 + i] = (bootId ushr (56 - i * 8)).toByte()
        writeBlob(payload)
    }

    private fun writeBlob(payload: ByteArray) {
        val b64 = Base64.encodeToString(CryptoProvider(context).encrypt(payload, CTX), Base64.NO_WRAP)
        context.getSharedPreferences(ATTEMPTS_PREFS, Context.MODE_PRIVATE)
            .edit().putString(STORAGE_KEY, b64).commit()
    }
}

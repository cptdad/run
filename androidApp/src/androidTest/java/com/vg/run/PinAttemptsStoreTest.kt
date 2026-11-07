package com.vg.run

import android.content.Context
import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Regression guard: the wrong-PIN counter must be (a) durable
 * across process death, (b) stored in its OWN prefs file separate from the
 * credential hashes, and (c) destroyed by an emergency wipe.
 *
 * These three invariants are what make the "persist before evaluating the
 * PIN" fix safe: a counter-only file can be force-quit-resurrected harmlessly
 * (it can never bring credential hashes back, which was the 2026-05-11
 * regression), and a stale count >= MAX is self-healing because the launch
 * path re-triggers the wipe.
 *
 * Run with: ./gradlew connectedAndroidTest
 */
@RunWith(AndroidJUnit4::class)
class PinAttemptsStoreTest {

    companion object {
        private const val ATTEMPTS_PREFS = "pin_attempts_prefs"
        private const val SELECTOR_PREFS = "vault_selector_prefs"
        private const val STORAGE_KEY    = "pin_failed_attempts_v2"
        private const val MINUTE = 60_000L
        private const val HOUR = 60 * MINUTE
    }

    private lateinit var context: Context

    @Before
    fun setUp() {
        context = InstrumentationRegistry.getInstrumentation().targetContext
        context.deleteSharedPreferences(ATTEMPTS_PREFS)
        context.deleteSharedPreferences(SELECTOR_PREFS)
    }

    @After
    fun tearDown() {
        context.deleteSharedPreferences(ATTEMPTS_PREFS)
        context.deleteSharedPreferences(SELECTOR_PREFS)
    }

    private fun newStore() =
        PinAttemptsStore(KeyValueStore(context, ATTEMPTS_PREFS), CryptoProvider(context))

    /** write() must be durable before it returns (synchronous commit). */
    @Test
    fun counter_survivesAcrossFreshStoreInstances() {
        newStore().write(3)

        // A brand-new instance over the same prefs file simulates a process
        // restart. With an async apply() a force-quit here would lose the 3.
        assertEquals("counter must persist durably", 3, newStore().read())
    }

    @Test
    fun reset_clearsCounter() {
        newStore().write(4)
        newStore().reset()
        assertEquals(0, newStore().read())
    }

    /**
     * The counter must NOT live in vault_selector_prefs — that shared file
     * was the root cause of the 2026-05-11 wipe-resurrection race.
     */
    @Test
    fun counter_isolatedFromCredentialPrefsFile() {
        newStore().write(2)

        val attemptsPrefs = context.getSharedPreferences(ATTEMPTS_PREFS, Context.MODE_PRIVATE)
        val selectorPrefs = context.getSharedPreferences(SELECTOR_PREFS, Context.MODE_PRIVATE)

        assertTrue("counter must be in its own prefs file",
            attemptsPrefs.contains(STORAGE_KEY))
        assertFalse("counter must NOT be in the credential prefs file",
            selectorPrefs.contains(STORAGE_KEY))
    }

    /** Emergency-wipe deletes the counter file → reads back as 0. */
    @Test
    fun deletingAttemptsPrefs_resetsCounter() {
        newStore().write(5)
        context.deleteSharedPreferences(ATTEMPTS_PREFS)
        assertEquals("wiped counter file must read as fresh", 0, newStore().read())
    }

    /** Tampering with the ciphertext is detected (adversarial → wipe path). */
    @Test
    fun tamperedCiphertext_throwsTamperException() {
        newStore().write(1)
        context.getSharedPreferences(ATTEMPTS_PREFS, Context.MODE_PRIVATE)
            .edit().putString(STORAGE_KEY, "not-valid-base64-ciphertext").commit()

        try {
            newStore().read()
            throw AssertionError("expected TamperException")
        } catch (_: PinAttemptsStore.TamperException) {
            // expected
        }
    }

    // ---- AND-SEC-1: rolling-window cumulative wrong-PIN cap ----
    // A successful unlock resets the 5-consecutive counter, so a party who
    // knows the PIN could reset-and-retry indefinitely. This
    // window counter is the backstop: NOT reset by any unlock,
    // only by the daily roll or an emergency wipe.

    @Test
    fun window_wipesOnMaxthWrongAttempt() {
        val store = newStore()
        for (i in 1 until PinAttemptsStore.MAX_WRONG_PER_DAY) {
            assertFalse("wrong attempt $i must not wipe",
                store.recordWrongAttemptInWindowAndCheckLimit())
        }
        assertTrue("the MAX_WRONG_PER_DAY-th wrong attempt must wipe",
            store.recordWrongAttemptInWindowAndCheckLimit())
    }

    @Test
    fun window_countPersistsAcrossInstances() {
        val half = PinAttemptsStore.MAX_WRONG_PER_DAY / 2
        repeat(half) { newStore().recordWrongAttemptInWindowAndCheckLimit() }
        for (i in half + 1 until PinAttemptsStore.MAX_WRONG_PER_DAY) {
            assertFalse("attempt $i after restart must not wipe",
                newStore().recordWrongAttemptInWindowAndCheckLimit())
        }
        assertTrue("window count must persist across restarts → MAX-th wipes",
            newStore().recordWrongAttemptInWindowAndCheckLimit())
    }

    /**
     * THE AND-SEC-1 invariant: reset() (called on every successful unlock)
     * must clear ONLY the consecutive counter, never the
     * rolling-window count — otherwise a successful unlock zeroes the brute-force
     * budget and the cap is defeated.
     */
    @Test
    fun window_survivesUnlockReset() {
        val s = newStore()
        repeat(PinAttemptsStore.MAX_WRONG_PER_DAY - 1) { s.recordWrongAttemptInWindowAndCheckLimit() }
        s.reset() // simulates a successful unlock
        assertEquals("reset() must clear the consecutive counter", 0, newStore().read())
        assertTrue("window count must SURVIVE reset() → next wrong attempt wipes",
            newStore().recordWrongAttemptInWindowAndCheckLimit())
    }

    @Test
    fun window_tamperedCiphertext_failsOpenWithoutWipe() {
        // The window cap is SECONDARY: the consecutive counter is the tamper
        // authority. A corrupt/undecryptable window blob must NOT wipe — it
        // fails open (resets to a fresh window) so it never crashes or wipes
        // (esp. important on the iOS main actor, where a throw would SIGABRT).
        newStore().recordWrongAttemptInWindowAndCheckLimit()
        context.getSharedPreferences(ATTEMPTS_PREFS, Context.MODE_PRIVATE)
            .edit().putString(PinAttemptsStore.WINDOW_STORAGE_KEY, "not-valid-ciphertext").commit()
        assertFalse("tampered window counter must NOT wipe",
            newStore().recordWrongAttemptInWindowAndCheckLimit())
        // Self-healed: the next wrong attempt is counted in a fresh window.
        assertFalse("after self-heal the counter resumes from a fresh window",
            newStore().recordWrongAttemptInWindowAndCheckLimit())
    }

    @Test
    fun window_expiredWindow_rollsOverAndDoesNotWipe() {
        val expiredStart = System.currentTimeMillis() - PinAttemptsStore.WINDOW_MS - 60_000L
        seedWindowState(expiredStart, PinAttemptsStore.MAX_WRONG_PER_DAY - 1)
        assertFalse("expired window must reset, not wipe",
            newStore().recordWrongAttemptInWindowAndCheckLimit())
    }

    @Test
    fun window_freshNearMax_wipesOnNextWrongAttempt() {
        seedWindowState(System.currentTimeMillis(), PinAttemptsStore.MAX_WRONG_PER_DAY - 1)
        assertTrue("MAX-th wrong attempt in-window must wipe",
            newStore().recordWrongAttemptInWindowAndCheckLimit())
    }

    @Test
    fun window_deletingPrefs_resetsCounter() {
        seedWindowState(System.currentTimeMillis(), PinAttemptsStore.MAX_WRONG_PER_DAY - 1)
        context.deleteSharedPreferences(ATTEMPTS_PREFS)
        assertFalse("wiped window counter must restart",
            newStore().recordWrongAttemptInWindowAndCheckLimit())
    }

    @Test
    fun window_backwardClock_doesNotResetCount() {
        // PINW-2: a windowStart in the FUTURE (device clock rolled back) must
        // NOT reset the count — the start is clamped down to now but the count
        // keeps accumulating, so rolling the clock back between guesses cannot
        // neuter the cap. Seed a near-max count with a future windowStart.
        seedWindowState(System.currentTimeMillis() + 60 * 60_000L, PinAttemptsStore.MAX_WRONG_PER_DAY - 1)
        assertTrue("backward clock must keep the count → the MAX-th still wipes",
            newStore().recordWrongAttemptInWindowAndCheckLimit())
    }

    // ---- forward-clock defense end-to-end (real AEAD blob) ----

    /**
     * The forward-clock attack: a FORWARD wall-clock jump past 24h
     * makes the wall roll predicate true and zeroed the count. With a monotonic
     * anchor showing only minutes of real uptime, the window must NOT reset, so a
     * near-max count still trips the cap.
     */
    @Test
    fun window_forwardClockJump_withMonotonicAnchor_doesNotReset() {
        val boot = 7L
        // windowStart 25h in the wall-clock past (wall says "expired") but the
        // anchor proves only ~5 min of real uptime will have elapsed.
        seedWindowStateWithMono(
            windowStart = System.currentTimeMillis() - PinAttemptsStore.WINDOW_MS - HOUR,
            count = PinAttemptsStore.MAX_WRONG_PER_DAY - 1,
            elapsed = 10 * HOUR, bootId = boot,
        )
        val store = PinAttemptsStore(
            KeyValueStore(context, ATTEMPTS_PREFS), CryptoProvider(context),
            monotonicNow = { MonotonicSample(10 * HOUR + 5 * MINUTE, boot) },
        )
        assertTrue("forward wall jump must not reset the window → MAX-th wipes",
            store.recordWrongAttemptInWindowAndCheckLimit())
    }

    /** A genuine 24h+ elapse (monotonic-proven) DOES roll, even if the wall clock
     *  still reads in-window — real elapsed governs the roll. */
    @Test
    fun window_realElapsedPastWindow_rollsAndDoesNotWipe() {
        val boot = 7L
        seedWindowStateWithMono(
            windowStart = System.currentTimeMillis(),   // wall clock: in-window
            count = PinAttemptsStore.MAX_WRONG_PER_DAY - 1,
            elapsed = 0L, bootId = boot,
        )
        val store = PinAttemptsStore(
            KeyValueStore(context, ATTEMPTS_PREFS), CryptoProvider(context),
            monotonicNow = { MonotonicSample(25 * HOUR, boot) },
        )
        assertFalse("24h+ of real uptime rolls the window → no wipe",
            store.recordWrongAttemptInWindowAndCheckLimit())
    }

    /** Backward compatibility: a legacy 20-byte window blob (no anchor) still
     *  decodes and records; the next write migrates it to the 36-byte shape. */
    @Test
    fun window_legacy20ByteBlob_stillReadsAndRecords() {
        seedWindowState(System.currentTimeMillis(), PinAttemptsStore.MAX_WRONG_PER_DAY - 1)
        val store = PinAttemptsStore(
            KeyValueStore(context, ATTEMPTS_PREFS), CryptoProvider(context),
            monotonicNow = { MonotonicSample(HOUR, 7L) }, // sample present, stored anchor absent → wall path
        )
        assertTrue("legacy in-window near-max blob still trips the cap",
            store.recordWrongAttemptInWindowAndCheckLimit())
    }

    // windowStart(8 BE) ‖ count(4 BE) ‖ pad(8), AEAD-encrypted under the
    // "pin-attempts-window" context — the on-disk format PinAttemptsStore uses.
    private fun seedWindowState(windowStart: Long, count: Int) {
        val payload = ByteArray(20)
        for (i in 0 until 8) payload[i] = (windowStart ushr (56 - i * 8)).toByte()
        for (i in 0 until 4) payload[8 + i] = (count ushr (24 - i * 8)).toByte()
        writeWindowBlob(payload)
    }

    // 36-byte forward-clock-defense format: windowStart(8) ‖ count(4) ‖ monoElapsed(8) ‖ bootId(8) ‖ pad(8).
    private fun seedWindowStateWithMono(windowStart: Long, count: Int, elapsed: Long, bootId: Long) {
        val payload = ByteArray(36)
        for (i in 0 until 8) payload[i] = (windowStart ushr (56 - i * 8)).toByte()
        for (i in 0 until 4) payload[8 + i] = (count ushr (24 - i * 8)).toByte()
        for (i in 0 until 8) payload[12 + i] = (elapsed ushr (56 - i * 8)).toByte()
        for (i in 0 until 8) payload[20 + i] = (bootId ushr (56 - i * 8)).toByte()
        writeWindowBlob(payload)
    }

    private fun writeWindowBlob(payload: ByteArray) {
        val ctx = "pin-attempts-window".toByteArray()
        val b64 = Base64.encodeToString(CryptoProvider(context).encrypt(payload, ctx), Base64.NO_WRAP)
        context.getSharedPreferences(ATTEMPTS_PREFS, Context.MODE_PRIVATE)
            .edit().putString(PinAttemptsStore.WINDOW_STORAGE_KEY, b64).commit()
    }
}

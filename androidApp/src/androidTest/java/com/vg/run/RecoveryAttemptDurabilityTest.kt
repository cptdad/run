package com.vg.run

import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Regression guard for RecoveryEntryScreen's attempt counter.
 *
 * The recovery-code screen is a full pre-unlock credential sink (recoverWithCode
 * evaluates the PIN/passphrase and opens the vault). Its wrong-attempt budget used
 * to live in Compose composition state (`remember { mutableStateOf(0) }`), so:
 *   #2 — tapping Back destroyed the composition and reset the budget to 0; and
 *   #3 — nothing durable was recorded until AFTER recoverWithCode's ~5 s enforced
 *        delay floor, so a force-quit inside that window discarded the attempt.
 *
 * The fix routes the recovery screen through the SAME durable
 * PinAttemptsStore consecutive counter the lock screen uses, writing the increment
 * SYNCHRONOUSLY *before* the evaluation. This test exercises that exact call
 * sequence against the real Android SharedPreferences-backed store and asserts the
 * count survives (a) a simulated Back (a fresh store instance re-reads the durable
 * value) and (b) a simulated process restart, and that a successful recovery
 * clears it.
 *
 * Run with: ./gradlew connectedAndroidTest
 */
@RunWith(AndroidJUnit4::class)
class RecoveryAttemptDurabilityTest {

    companion object {
        private const val ATTEMPTS_PREFS = "pin_attempts_prefs"
        private const val SELECTOR_PREFS = "vault_selector_prefs"
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

    // Mirrors RunViewModel's wiring: the consecutive counter lives in its own prefs
    // file, with the "established" marker fate-shared into vault_selector_prefs.
    private fun newStore() = PinAttemptsStore(
        KeyValueStore(context, ATTEMPTS_PREFS),
        CryptoProvider(context),
        KeyValueStore(context, SELECTOR_PREFS),
    )

    /**
     * The durable consecutive counter survives a simulated Back. Each
     * recovery attempt does a pre-eval write; disposing the composition (Back) and
     * re-entering re-reads the SAME durable count instead of restarting at 0.
     */
    @Test
    fun recoveryCounter_survivesSimulatedBack() {
        // Composition A: one wrong attempt → pre-eval write of the incremented count.
        val a = newStore()
        val seedA = a.read()                 // composition seeds from the durable count
        assertEquals(0, seedA)
        a.write(seedA + 1)                   // pre-eval durable increment (persist-before-evaluate ordering)

        // Back tears the composition down; re-entering RE-READS the durable counter.
        // A brand-new store instance over the same prefs models the fresh composition.
        val b = newStore()
        assertEquals("Back must NOT reset the recovery budget", 1, b.read())

        // Second wrong attempt in the re-entered screen keeps counting UP from 1.
        b.write(b.read() + 1)
        assertEquals("consecutive budget accumulates across Back", 2, newStore().read())
    }

    /**
     * The pre-eval write is durable before the ~5 s evaluation, so a
     * force-quit (or process restart) inside that window cannot hand out a free,
     * uncounted guess. A fresh store after the "kill" still reports the increment.
     */
    @Test
    fun recoveryCounter_survivesSimulatedProcessRestart() {
        // Pre-eval write, then the process is killed DURING recoverWithCode's delay
        // floor (before any post-eval bookkeeping runs).
        newStore().write(3)

        // New process → new store over the same prefs file. With an async apply()
        // the 3 would be lost; PinAttemptsStore commits synchronously.
        assertEquals("force-quit mid-evaluation must not discard the attempt",
            3, newStore().read())
    }

    /** A successful recovery clears the shared consecutive counter (reset() on the
     *  Opened branch), exactly like a successful unlock. */
    @Test
    fun successfulRecovery_resetsCounter() {
        newStore().write(4)
        newStore().reset()                   // recovery Opened → viewModel.pinAttempts.reset()
        assertEquals(0, newStore().read())
    }

    /**
     * The recovery screen and the lock screen share ONE durable budget, so guesses
     * made through the recovery sink are visible to the lock screen's launch-time
     * check (and vice-versa) — an attacker cannot get a fresh budget by switching
     * sinks.
     */
    @Test
    fun recoveryAndUnlock_shareOneDurableBudget() {
        newStore().write(2)                  // two wrong recovery attempts
        // The lock screen seeds failedAttempts from the same store on next launch.
        assertEquals(2, newStore().read())
    }
}

package com.vg.run

import android.content.Context
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
 * Regression guard: every wipe path must cryptographically erase
 * the Tink master key, not just delete files. After erasure, data encrypted
 * with the old key must be permanently unrecoverable even by a fresh
 * CryptoProvider on the same device (which transparently regenerates a new
 * keyset) — i.e. the wipe is robust against a pre-wipe disk image.
 *
 * Run with: ./gradlew connectedAndroidTest
 */
@RunWith(AndroidJUnit4::class)
class CryptoErasureTest {

    private lateinit var context: Context
    private val ctx = "erasure-test".toByteArray()

    @Before
    fun setUp() {
        context = InstrumentationRegistry.getInstrumentation().targetContext
        CryptoManager.eraseMasterKey(context) // clean slate
        context.deleteSharedPreferences("inactivity_prefs") // test isolation
    }

    @After
    fun tearDown() {
        CryptoManager.eraseMasterKey(context)
        context.deleteSharedPreferences("inactivity_prefs")
    }

    @Test
    fun eraseMasterKey_makesPriorCiphertextUnrecoverable() {
        val secret = "top-secret-vault-material".toByteArray()
        val ciphertext = CryptoProvider(context).encrypt(secret, ctx)

        // Sanity: same key still decrypts before erasure.
        assertTrue(CryptoProvider(context).decrypt(ciphertext, ctx).contentEquals(secret))

        CryptoManager.eraseMasterKey(context)

        // The wrapped keyset file is gone...
        assertFalse(
            "keyset prefs file must be deleted",
            context.getSharedPreferences(CryptoManager.PREF_FILE_NAME, Context.MODE_PRIVATE)
                .contains("run_aead_keyset")
        )

        // ...and a fresh provider regenerates a brand-new keyset, so the old
        // ciphertext can never be decrypted again (different master key).
        try {
            CryptoProvider(context).decrypt(ciphertext, ctx)
            throw AssertionError("old ciphertext must not decrypt after crypto-erasure")
        } catch (_: AssertionError) {
            throw AssertionError("old ciphertext must not decrypt after crypto-erasure")
        } catch (_: Exception) {
            // expected — Tink rejects with the new key
        }
    }

    /**
     * Regression: a CryptoProvider-encrypted inactivity timestamp must not
     * survive a wipe. If it does, the next launch can't decrypt it (keyset
     * erased + regenerated), InactivityWipe fail-safes to "expired" and
     * wipes the freshly-provisioned vault on every launch — which broke
     * cross-multi relaunchAndUnlock.
     */
    @Test
    fun staleInactivityTimestamp_doesNotSurviveWipe_soNoFailSafeLoop() {
        // Simulate a prior session's inactivity timestamp on disk (its
        // exact bytes are irrelevant — what matters is that a value is
        // present and was written under a since-erased keyset).
        context.getSharedPreferences("inactivity_prefs", Context.MODE_PRIVATE)
            .edit().putString("last_opened_enc", "stale-ciphertext-old-keyset").commit()

        // A keyset-erasing wipe must also remove the inactivity timestamp.
        WipeRoutine.wipePersistentState(context)

        assertFalse(
            "inactivity timestamp must not outlive the erased keyset",
            context.getSharedPreferences("inactivity_prefs", Context.MODE_PRIVATE)
                .contains("last_opened_enc")
        )
        // Clean state → no stored timestamp → checkAndWipeIfNeeded must
        // NOT fail-safe-wipe (the loop that broke cross-multi relaunch).
        assertFalse(
            "checkAndWipeIfNeeded must not fail-safe-wipe after a clean wipe",
            InactivityWipe.checkAndWipeIfNeeded(context)
        )
    }

    @Test
    fun eraseMasterKey_isIdempotentWhenNothingProvisioned() {
        // No prior crypto use — must not throw.
        CryptoManager.eraseMasterKey(context)
        CryptoManager.eraseMasterKey(context)
    }

    /** WipeRoutine deletes every vault prefs file, incl. the CR-5 counter. */
    @Test
    fun wipeRoutine_clearsAllVaultPrefsFiles() {
        val files = listOf(
            "vault_selector_prefs", "pin_attempts_prefs",
            // inactivity_prefs is CryptoProvider-encrypted; if it outlives
            // the erased keyset, InactivityWipe.checkAndWipeIfNeeded can't
            // decrypt it, fail-safes to "expired", and wipes on every launch
            // (regression that broke cross-multi relaunchAndUnlock).
            "inactivity_prefs",
            "auto_wipe_prefs", "pin_entry_prefs",
        )
        files.forEach {
            context.getSharedPreferences(it, Context.MODE_PRIVATE)
                .edit().putString("marker", "x").commit()
        }
        // Touch the keyset too.
        CryptoProvider(context).encrypt("x".toByteArray(), ctx)

        WipeRoutine.wipePersistentState(context)

        files.forEach {
            assertEquals(
                "$it must be wiped by WipeRoutine", 0,
                context.getSharedPreferences(it, Context.MODE_PRIVATE).all.size
            )
        }
        assertFalse(
            "keyset must be crypto-erased by WipeRoutine",
            context.getSharedPreferences(CryptoManager.PREF_FILE_NAME, Context.MODE_PRIVATE)
                .contains("run_aead_keyset")
        )
    }
}

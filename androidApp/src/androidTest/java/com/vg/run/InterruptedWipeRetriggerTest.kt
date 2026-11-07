package com.vg.run

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
 * The LAUNCH-TIME interrupted-wipe re-trigger, end-to-end through a real
 * SharedPreferences store and the real device-key AEAD (regression 2026-07-30).
 *
 * All four pre-unlock credential screens compare the ALREADY-ACCUMULATED durable
 * counter against a threshold at COMPOSITION time, before the user enters
 * anything, to finish a wipe that was interrupted mid-flight. The stricter unauthenticated-level handling made the
 * NEW-attempt budget shrink retroactively (unauthenticated or damaged `vlt_lvl`
 * ⇒ MAXIMUM's 5), so pointing that check at the new budget destroyed a genuine
 * pre-sealed-level legacy-cleartext CASUAL vault carrying 5–9 stranded failures — possible
 * precisely because its budget WAS 10 and only a successful unlock clears the
 * counter — on its first launch after the upgrade.
 *
 * `maxConsecutiveAttemptsForInterruptedWipe()` is the launch-only threshold; the
 * new-attempt budget is unchanged and still tightens. The pure rule is pinned in
 * commonTest InterruptedWipeThresholdTest; this covers the real reads.
 *
 * Run with: ./gradlew connectedAndroidTest --tests "*.InterruptedWipeRetriggerTest"
 */
@RunWith(AndroidJUnit4::class)
class InterruptedWipeRetriggerTest {

    private lateinit var context: android.content.Context
    private lateinit var vaultSelector: VaultSelector

    companion object {
        private const val SELECTOR_PREFS = "vault_selector_prefs"
        private const val K_LEVEL = "vlt_lvl"
    }

    private fun newSelector() = VaultSelector(
        store = KeyValueStore(context, SELECTOR_PREFS),
        crypto = CryptoProvider(context),
        vaultFactory = androidVaultFactory(context),
    )

    @Before
    fun setUp() {
        context = InstrumentationRegistry.getInstrumentation().targetContext
        context.deleteSharedPreferences(SELECTOR_PREFS)
        vaultSelector = newSelector()
    }

    @After
    fun tearDown() {
        context.deleteSharedPreferences(SELECTOR_PREFS)
    }

    /** The new-attempt budget, i.e. what the stricter level handling tightened. */
    private fun newAttemptBudget() =
        CredentialPolicy.maxConsecutiveAttempts(vaultSelector.protectionLevelForEnforcement())

    // -- The regression --------------------------------------------------------

    @Test
    fun legacyCleartextCasual_isNotWipedAtLaunchWithAStrandedCounter() {
        // Exactly what a pre-sealed-level install has on disk: the tier as plain ASCII.
        KeyValueStore(context, SELECTOR_PREFS).putString(K_LEVEL, ProtectionLevel.CASUAL.storageValue)

        // The unauthenticated-level rule still holds: an unauthenticated value cannot LOOSEN a new attempt.
        assertEquals(
            "the fail-secure rule must stay in force for new attempts",
            ProtectionLevel.MAXIMUM.maxConsecutiveAttempts, newAttemptBudget(),
        )

        // …but the launch-time re-trigger must use the most lenient budget, so the
        // 5–9 stranded failures this vault legitimately accumulated under CASUAL's
        // 10 do not destroy it the moment the app opens.
        val launch = vaultSelector.maxConsecutiveAttemptsForInterruptedWipe()
        assertEquals(ProtectionLevel.MOST_LENIENT_MAX_ATTEMPTS, launch)
        for (stranded in 5..9) {
            assertFalse(
                "a legacy CASUAL vault stranded at $stranded failures must not be wiped" +
                    " at composition time — no wrong credential was entered",
                stranded >= launch,
            )
        }
    }

    @Test
    fun damagedLevelBlob_doesNotRetroactivelyCondemnAnExistingCounter() {
        // Blob-shaped but fails AEAD under a WORKING device key: the positive
        // tamper evidence. It still buys MAXIMUM's tight budget for new attempts…
        KeyValueStore(context, SELECTOR_PREFS)
            .putString(K_LEVEL, encodeBase64(ByteArray(40) { it.toByte() }))
        assertEquals(
            "M1 must stay in force for new attempts",
            ProtectionLevel.MAXIMUM.maxConsecutiveAttempts, newAttemptBudget(),
        )
        // …but must not turn an existing counter into an immediate wipe, which
        // would make one flipped byte a data-destruction primitive.
        assertEquals(
            ProtectionLevel.MOST_LENIENT_MAX_ATTEMPTS,
            vaultSelector.maxConsecutiveAttemptsForInterruptedWipe(),
        )
    }

    // -- …while a genuinely interrupted wipe still completes at launch ---------

    @Test
    fun authenticatedTier_retriggersAtItsOwnBudget() {
        for (level in ProtectionLevel.entries) {
            assertTrue("setProtectionLevel($level)", vaultSelector.setProtectionLevel(level))
            val launch = vaultSelector.maxConsecutiveAttemptsForInterruptedWipe()
            assertEquals(
                "an authenticated $level must keep its own budget as the launch threshold",
                level.maxConsecutiveAttempts, launch,
            )
            assertEquals(
                "the new-attempt budget must be unchanged for an authenticated tier",
                level.maxConsecutiveAttempts, newAttemptBudget(),
            )
            // A wipe interrupted at this tier's budget still fires at composition.
            assertTrue(
                "an interrupted wipe on an authenticated $level vault must still complete",
                level.maxConsecutiveAttempts >= launch,
            )
        }
    }

    @Test
    fun absentTier_keepsTheLegacyPreSliderDefault() {
        // Nothing stored at all: the budget has always been the legacy default, so
        // it cannot have shrunk and gets no leniency.
        assertEquals(
            CredentialPolicy.MAX_CONSECUTIVE_ATTEMPTS,
            vaultSelector.maxConsecutiveAttemptsForInterruptedWipe(),
        )
        assertEquals(CredentialPolicy.MAX_CONSECUTIVE_ATTEMPTS, newAttemptBudget())
    }

    // -- Invariants ------------------------------------------------------------

    /**
     * The two properties that make this change safe, asserted on whatever is
     * currently planted in the store:
     *  - never TIGHTER than the new-attempt budget — that is precisely what
     *    destroys a legitimate vault whose counter predates the tightening;
     *  - never LOOSER than the most lenient tier ever offered — so the delay a
     *    force-quit-mid-wipe attacker can buy stays bounded.
     */
    private fun assertLaunchThresholdInvariants(name: String) {
        val launch = vaultSelector.maxConsecutiveAttemptsForInterruptedWipe()
        val budget = newAttemptBudget()
        assertTrue(
            "$name: launch threshold $launch must not be tighter than the new-attempt budget $budget",
            launch >= budget,
        )
        assertTrue(
            "$name: launch threshold $launch must stay bounded by the most lenient budget",
            launch <= ProtectionLevel.MOST_LENIENT_MAX_ATTEMPTS,
        )
    }

    @Test
    fun launchThresholdInvariantsHoldForEveryStoredState() {
        val prefs = KeyValueStore(context, SELECTOR_PREFS)

        assertLaunchThresholdInvariants("absent")

        for (level in ProtectionLevel.entries) {
            vaultSelector.setProtectionLevel(level)
            assertLaunchThresholdInvariants("authenticated ${level.storageValue}")

            prefs.putString(K_LEVEL, level.storageValue)
            assertLaunchThresholdInvariants("legacy cleartext ${level.storageValue}")
        }

        prefs.putString(K_LEVEL, "zzz")
        assertLaunchThresholdInvariants("unrecognized cleartext token")

        prefs.putString(K_LEVEL, encodeBase64(ByteArray(40) { it.toByte() }))
        assertLaunchThresholdInvariants("damaged blob")
    }
}

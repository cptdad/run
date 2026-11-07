package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// The LAUNCH-TIME interrupted-wipe re-trigger (regression, 2026-07-30).
//
// All four pre-unlock credential screens (PinEntryScreen / PinEntryView and the
// two recovery screens) compare the ALREADY-ACCUMULATED durable consecutive
// counter against a budget the moment they compose — before the user has entered
// anything. That check exists to finish a wipe that was interrupted mid-flight.
//
// Two earlier fixes made the NEW-attempt budget shrink retroactively:
// an unauthenticated (legacy-cleartext) vlt_lvl and a damaged blob both now
// enforce MAXIMUM's 5 instead of CASUAL's 10 / the most lenient 10. Pointing the
// launch check at that budget wiped a genuine pre-tier legacy CASUAL vault carrying
// 5–9 stranded failures (possible precisely because its budget WAS 10 and only a
// successful unlock clears the counter) on its first launch after the upgrade,
// with no wrong credential entered.
//
// SelectorMetaPolicy.interruptedWipeAttemptThreshold is the fix: the launch check uses
// the tier budget only where the read proves the budget cannot have shrunk under
// the counter, and the most lenient tier's budget everywhere else. CryptoProvider
// and KeyValueStore are expect classes with no common fake seam, so this pins the
// extracted decision (the end-to-end wiring through a real store + real AEAD is
// covered by the instrumented androidApp InterruptedWipeRetriggerTest).
// ---------------------------------------------------------------------------

class InterruptedWipeThresholdTest {

    /** The launch-time threshold for a stored value with the given provenance. */
    private fun threshold(level: ProtectionLevel?, present: Boolean, authenticated: Boolean) =
        SelectorMetaPolicy.interruptedWipeAttemptThreshold(level, present, authenticated)

    // -- The regression: a retroactively shrunk budget must not fire a wipe -----

    @Test
    fun legacyCleartextTier_neverRetriggersOnACounterStrandedUnderItsOldBudget() {
        // A pre-tier install stores the tier as plain ASCII, so the read is
        // unauthenticated — the selector guard routes it to Present(MAXIMUM), budget 5. The
        // counter it carries, however, was accumulated under CASUAL's 10.
        for (level in ProtectionLevel.entries) {
            val launch = threshold(level, present = true, authenticated = false)
            assertEquals(
                ProtectionLevel.MOST_LENIENT_MAX_ATTEMPTS, launch,
                "unauthenticated '${level.storageValue}' must fall back to the most lenient budget",
            )
            // The whole range that used to be destroyed on first launch. An
            // unauthenticated value carries no proof of WHICH tier wrote it, so a
            // vault that really was MAXIMUM takes the same lenient bound here —
            // its interrupted wipe is delayed to the next wrong entry, never
            // cancelled (see everyInterruptedWipeCompletesAtLaunchOrOnTheNextWrongEntry).
            for (stranded in ProtectionLevel.MAXIMUM.maxConsecutiveAttempts until
                ProtectionLevel.MOST_LENIENT_MAX_ATTEMPTS) {
                assertFalse(
                    stranded >= launch,
                    "a legacy '${level.storageValue}' vault stranded at $stranded failures must" +
                        " NOT be wiped at composition time — nothing wrong was entered",
                )
            }
        }
    }

    @Test
    fun authenticatedButUnparseableTier_alsoFallsBackToTheMostLenientBudget() {
        // The blob decrypts but the token is a NEWER binary's tier, whose
        // budget this build cannot know. Enforcement fails secure to MAXIMUM's 5
        // for new attempts; the launch check must not apply that 5 to a counter
        // the newer binary may have allowed to reach 10.
        assertEquals(
            ProtectionLevel.MOST_LENIENT_MAX_ATTEMPTS,
            threshold(null, present = true, authenticated = true),
        )
    }

    @Test
    fun damagedAndOutageReadsGetTheMostLenientBudgetToo() {
        // Both are produced by the accessor's catch, which returns exactly this
        // constant. Pin that it really is no tighter than the budget those two
        // states hand a NEW attempt, so the catch can never fire a wipe early.
        assertTrue(
            CredentialPolicy.maxConsecutiveAttempts(ProtectionLevelRead.Damaged) <=
                ProtectionLevel.MOST_LENIENT_MAX_ATTEMPTS,
        )
        assertTrue(
            CredentialPolicy.maxConsecutiveAttempts(ProtectionLevelRead.Unreadable) <=
                ProtectionLevel.MOST_LENIENT_MAX_ATTEMPTS,
        )
    }

    // -- …while a genuinely interrupted wipe still completes --------------------

    @Test
    fun authenticatedTier_retriggersAtItsOwnBudget() {
        // A tier change only happens while UNLOCKED, and a successful unlock
        // resets the counter to 0 — so an authenticated tier can never be tighter
        // than the budget the stranded failures were counted under. Its own
        // budget is therefore the correct, precise threshold, and an interrupted
        // wipe on a MAXIMUM vault still fires at composition time.
        for (level in ProtectionLevel.entries) {
            val launch = threshold(level, present = true, authenticated = true)
            assertEquals(level.maxConsecutiveAttempts, launch)
            assertTrue(
                level.maxConsecutiveAttempts >= launch,
                "a wipe interrupted at $level's budget must still re-fire at launch",
            )
        }
    }

    @Test
    fun absentTier_keepsTheLegacyPreSliderDefault() {
        // Nothing was ever stored: the budget has ALWAYS been the legacy default,
        // so it cannot have shrunk and needs no leniency.
        val launch = threshold(null, present = false, authenticated = false)
        assertEquals(CredentialPolicy.MAX_CONSECUTIVE_ATTEMPTS, launch)
        assertTrue(
            CredentialPolicy.maxConsecutiveAttempts(ProtectionLevelRead.Absent) >= launch,
            "a pre-slider vault's interrupted wipe must still re-fire at launch",
        )
    }

    @Test
    fun everyInterruptedWipeCompletesAtLaunchOrOnTheNextWrongEntry() {
        // Model both screens: at composition they wipe iff persisted >= launch
        // threshold; otherwise the next entry writes attempt = persisted + 1 and
        // the Denied branch wipes iff attempt >= the NEW-attempt budget. A counter
        // that genuinely reached the budget in force must always end in a wipe.
        for (scenario in scenarios()) {
            for (persisted in scenario.newAttemptBudget..(ProtectionLevel.MOST_LENIENT_MAX_ATTEMPTS + 2)) {
                val wipesAtLaunch = persisted >= scenario.launchThreshold
                val wipesOnNextWrongEntry = persisted + 1 >= scenario.newAttemptBudget
                assertTrue(
                    wipesAtLaunch || wipesOnNextWrongEntry,
                    "${scenario.name}: counter $persisted is at/over the budget in force," +
                        " so the interrupted wipe must still complete",
                )
                // Where the read PROVES the budget did not shrink, no delay at
                // all is tolerated — the wipe must finish at composition time,
                // exactly as before this fix.
                if (scenario.budgetProvablyUnshrunk) {
                    assertTrue(
                        wipesAtLaunch,
                        "${scenario.name}: counter $persisted must re-fire the interrupted" +
                            " wipe at composition time, not one entry later",
                    )
                }
            }
        }
    }

    // -- Bounds that keep the relaxation from becoming a hole ------------------

    @Test
    fun launchThresholdIsNeverBelowTheNewAttemptBudget() {
        // Never firing EARLIER than the budget for a new attempt is exactly the
        // property that makes this change incapable of destroying data that the
        // the earlier code would have kept.
        for (scenario in scenarios()) {
            assertTrue(
                scenario.launchThreshold >= scenario.newAttemptBudget,
                "${scenario.name}: launch threshold ${scenario.launchThreshold} must not be" +
                    " tighter than the new-attempt budget ${scenario.newAttemptBudget}",
            )
        }
    }

    @Test
    fun launchThresholdIsNeverAboveTheMostLenientBudget() {
        // …and the delay is bounded: a force-quit-mid-wipe attacker can never buy
        // more slack than the largest budget any tier ever offered.
        for (scenario in scenarios()) {
            assertTrue(
                scenario.launchThreshold <= ProtectionLevel.MOST_LENIENT_MAX_ATTEMPTS,
                "${scenario.name}: launch threshold must stay bounded by the most lenient budget",
            )
        }
    }

    /** Launch threshold vs new-attempt budget for every reachable read state. */
    private class Scenario(
        val name: String,
        val launchThreshold: Int,
        val newAttemptBudget: Int,
        /** True when the read proves the budget cannot have shrunk under the counter. */
        val budgetProvablyUnshrunk: Boolean,
    )

    private fun scenarios(): List<Scenario> = buildList {
        add(
            Scenario(
                "absent (pre-slider)",
                threshold(null, present = false, authenticated = false),
                CredentialPolicy.maxConsecutiveAttempts(ProtectionLevelRead.Absent),
                budgetProvablyUnshrunk = true,
            )
        )
        for (level in ProtectionLevel.entries) {
            add(
                Scenario(
                    "authenticated ${level.storageValue}",
                    threshold(level, present = true, authenticated = true),
                    CredentialPolicy.maxConsecutiveAttempts(ProtectionLevelRead.Present(level)),
                    budgetProvablyUnshrunk = true,
                )
            )
            add(
                Scenario(
                    "legacy cleartext ${level.storageValue}",
                    threshold(level, present = true, authenticated = false),
                    // The fail-secure destination for any unauthenticated value.
                    CredentialPolicy.maxConsecutiveAttempts(
                        ProtectionLevelRead.Present(ProtectionLevel.MAXIMUM)
                    ),
                    budgetProvablyUnshrunk = false,
                )
            )
        }
        add(
            Scenario(
                "authenticated but unparseable token",
                threshold(null, present = true, authenticated = true),
                CredentialPolicy.maxConsecutiveAttempts(
                    ProtectionLevelRead.Present(ProtectionLevel.MAXIMUM)
                ),
                budgetProvablyUnshrunk = false,
            )
        )
        // The two states the accessor's catch produces.
        add(
            Scenario(
                "damaged blob",
                ProtectionLevel.MOST_LENIENT_MAX_ATTEMPTS,
                CredentialPolicy.maxConsecutiveAttempts(ProtectionLevelRead.Damaged),
                budgetProvablyUnshrunk = false,
            )
        )
        add(
            Scenario(
                "device-key outage",
                ProtectionLevel.MOST_LENIENT_MAX_ATTEMPTS,
                CredentialPolicy.maxConsecutiveAttempts(ProtectionLevelRead.Unreadable),
                budgetProvablyUnshrunk = false,
            )
        )
    }
}

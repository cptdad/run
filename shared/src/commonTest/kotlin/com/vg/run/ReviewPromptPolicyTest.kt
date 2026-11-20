package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

private const val NOW = 1_000_000_000_000L
private const val ONE_DAY_MS = 1L * 24 * 60 * 60 * 1000

/** Every gate satisfied — the shared "eligible" baseline the boundary tests mutate ONE field of. */
private fun eligibleArgs(
    now: Long = NOW,
    firstUnlockAt: Long? = NOW - ONE_DAY_MS,
    unlockCount: Int = 3,
    contactCount: Int = 1,
    alreadyPrompted: Boolean = false,
    isDebugBuild: Boolean = false,
) = ReviewPromptPolicy.shouldPrompt(
    now = now,
    firstUnlockAt = firstUnlockAt,
    unlockCount = unlockCount,
    contactCount = contactCount,
    alreadyPrompted = alreadyPrompted,
    isDebugBuild = isDebugBuild,
)

class ReviewPromptPolicyTest {

    // -------------------------------------------------------------------
    // The eligible baseline itself
    // -------------------------------------------------------------------

    @Test
    fun everyGateSatisfied_isEligible() {
        assertTrue(eligibleArgs())
    }

    // -------------------------------------------------------------------
    // Unlock-count boundary (>= 3)
    // -------------------------------------------------------------------

    @Test
    fun exactlyThreeUnlocks_isEligible() {
        assertTrue(eligibleArgs(unlockCount = 3))
    }

    @Test
    fun twoUnlocks_isNotEligible() {
        assertFalse(eligibleArgs(unlockCount = 2))
    }

    @Test
    fun manyUnlocks_staysEligible() {
        assertTrue(eligibleArgs(unlockCount = 500))
    }

    // -------------------------------------------------------------------
    // Age boundary (>= 1 day since firstUnlockAt)
    // -------------------------------------------------------------------

    @Test
    fun exactlyOneDayElapsed_isEligible() {
        assertTrue(eligibleArgs(firstUnlockAt = NOW - ONE_DAY_MS))
    }

    @Test
    fun oneMillisecondShortOfOneDay_isNotEligible() {
        assertFalse(eligibleArgs(firstUnlockAt = NOW - ONE_DAY_MS + 1))
    }

    @Test
    fun wellPastOneDay_staysEligible() {
        assertTrue(eligibleArgs(firstUnlockAt = NOW - ONE_DAY_MS * 10))
    }

    @Test
    fun nullFirstUnlockAt_isNotEligible() {
        // Fail direction: never ask before a first-unlock timestamp exists at all.
        assertFalse(eligibleArgs(firstUnlockAt = null))
    }

    // -------------------------------------------------------------------
    // Contact-count gate (>= 1)
    // -------------------------------------------------------------------

    @Test
    fun zeroContacts_isNotEligible() {
        assertFalse(eligibleArgs(contactCount = 0))
    }

    @Test
    fun oneContact_isEligible() {
        assertTrue(eligibleArgs(contactCount = 1))
    }

    // -------------------------------------------------------------------
    // Debug gate — ALWAYS false, regardless of every other input
    // -------------------------------------------------------------------

    @Test
    fun debugBuild_isNeverEligible_evenWithEveryOtherGateWideOpen() {
        assertFalse(
            eligibleArgs(
                isDebugBuild = true,
                unlockCount = 1_000,
                contactCount = 1_000,
                firstUnlockAt = 0L,
                now = Long.MAX_VALUE,
            )
        )
    }

    @Test
    fun releaseBuildOtherwiseIdentical_isEligible() {
        assertTrue(eligibleArgs(isDebugBuild = false))
    }

    // -------------------------------------------------------------------
    // Prompted-once latch — a strict one-shot
    // -------------------------------------------------------------------

    @Test
    fun alreadyPrompted_isNeverEligibleAgain() {
        assertFalse(eligibleArgs(alreadyPrompted = true))
    }

    @Test
    fun alreadyPrompted_staysBlockedNoMatterHowEligibleOtherwise() {
        assertFalse(
            eligibleArgs(
                alreadyPrompted = true,
                unlockCount = 1_000,
                contactCount = 1_000,
                firstUnlockAt = 0L,
            )
        )
    }

    // -------------------------------------------------------------------
    // afterUnlock — the counters helper
    // -------------------------------------------------------------------

    @Test
    fun afterUnlock_firstCallLatchesFirstUnlockAtToNow() {
        val result = ReviewPromptPolicy.afterUnlock(now = NOW, firstUnlockAt = null, unlockCount = 0)
        assertEquals(NOW, result.firstUnlockAt)
        assertEquals(1, result.unlockCount)
    }

    @Test
    fun afterUnlock_laterCallsNeverMoveAnAlreadySetFirstUnlockAt() {
        val firstEver = NOW - ONE_DAY_MS
        val result = ReviewPromptPolicy.afterUnlock(now = NOW, firstUnlockAt = firstEver, unlockCount = 4)
        assertEquals(firstEver, result.firstUnlockAt)
        assertEquals(5, result.unlockCount)
    }

    @Test
    fun afterUnlock_countAlwaysIncrementsByExactlyOne() {
        var firstUnlockAt: Long? = null
        var unlockCount = 0
        repeat(6) {
            val result = ReviewPromptPolicy.afterUnlock(now = NOW, firstUnlockAt = firstUnlockAt, unlockCount = unlockCount)
            assertEquals(unlockCount + 1, result.unlockCount)
            firstUnlockAt = result.firstUnlockAt
            unlockCount = result.unlockCount
        }
        assertEquals(6, unlockCount)
        assertEquals(NOW, firstUnlockAt)
    }

    // --- debug gate (2026-11-20: REVIEW_PROMPT_TEST=1 opens it on debug builds) ---

    @Test
    fun debugGate_blocksAnOrdinaryDebugBuild() {
        assertTrue(ReviewPromptPolicy.debugGateBlocks(isDebugBuild = true, testKnob = false))
    }

    @Test
    fun debugGate_letsADebugBuildWithTheTestKnobThrough() {
        assertFalse(ReviewPromptPolicy.debugGateBlocks(isDebugBuild = true, testKnob = true))
    }

    @Test
    fun debugGate_neverBlocksAReleaseBuild() {
        assertFalse(ReviewPromptPolicy.debugGateBlocks(isDebugBuild = false, testKnob = false))
        assertFalse(ReviewPromptPolicy.debugGateBlocks(isDebugBuild = false, testKnob = true))
    }

    @Test
    fun shippingBuildsCarryNoTestKnob() {
        // The unit-test compilation never sets REVIEW_PROMPT_TEST, like every shipping path.
        assertFalse(REVIEW_PROMPT_TEST_THRESHOLDS)
    }
}

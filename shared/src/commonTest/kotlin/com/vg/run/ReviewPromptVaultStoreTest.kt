package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** A vault whose `_meta` accessors fail (locked/closed mid-session) — same
 *  shape as UpdateNudgeThrottleTest's double, rolled per-file per that file's own
 *  convention. */
private class ReviewPromptThrowingVault : InMemoryVault() {
    override fun getMeta(key: String): String? = throw IllegalStateException("vault unavailable")
    override fun putMeta(key: String, value: String): Unit = throw IllegalStateException("vault unavailable")
}

/** A vault whose `getMeta` succeeds but whose `putMeta` fails — isolates the
 *  "read ok, write refused" case (e.g. a locked iOS keybag mid-write). */
private class ReviewPromptWriteThrowingVault : InMemoryVault() {
    override fun putMeta(key: String, value: String): Unit = throw IllegalStateException("write refused")
}

/**
 * The review-prompt counters are now a
 * vault `_meta` singleton (`review_prompt_v1`), exactly the [UpdateNudge]
 * shape — pack/unpack, never-throws in both directions, and a platform-
 * supplied legacy fallback that seeds (never restarts) an upgrading install's
 * history exactly once.
 */
class ReviewPromptVaultStoreTest {

    private val now = 1_700_000_000_000L

    // ---- readReviewPromptState ---------------------------------------

    @Test
    fun noKeyStored_readsFreshInstallDefaults() {
        val vault = InMemoryVault()
        val state = readReviewPromptState(vault)
        assertEquals(ReviewPromptVaultState(null, 0, false), state)
    }

    @Test
    fun aWrittenRow_roundTripsExactly() {
        val vault = InMemoryVault()
        assertTrue(recordReviewPromptUnlock(vault, now))
        val state = readReviewPromptState(vault)
        assertEquals(now, state.firstUnlockAt)
        assertEquals(1, state.unlockCount)
        assertFalse(state.alreadyPrompted)
    }

    @Test
    fun garbageStoredValue_readsAsFreshInstallDefaults() {
        for (junk in listOf(
            "", "|", "||", "garbage", "1000", "1000|1", "1000|1|2", "1000|x|0",
            "x|1|0", "1000|1|", "1000||0", "1000|1|0|0", "1000 |1|0",
        )) {
            val vault = InMemoryVault()
            vault.putMeta(REVIEW_PROMPT_META_KEY, junk)
            assertEquals(
                ReviewPromptVaultState(null, 0, false),
                readReviewPromptState(vault),
                "unparseable stored value (\"$junk\") must read exactly like no key",
            )
        }
    }

    @Test
    fun aThrowingVault_readNeverThrowsAndReadsDefaults() {
        val vault = ReviewPromptThrowingVault()
        assertEquals(ReviewPromptVaultState(null, 0, false), readReviewPromptState(vault))
    }

    // ---- recordReviewPromptUnlock --------------------------------------

    @Test
    fun firstCall_latchesFirstUnlockAtAndSetsCountToOne() {
        val vault = InMemoryVault()
        assertTrue(recordReviewPromptUnlock(vault, now))
        assertEquals("$now|1|0", vault.getMeta(REVIEW_PROMPT_META_KEY))
    }

    @Test
    fun laterCalls_neverMoveFirstUnlockAtAndAlwaysIncrementCountByOne() {
        val vault = InMemoryVault()
        assertTrue(recordReviewPromptUnlock(vault, now))
        assertTrue(recordReviewPromptUnlock(vault, now + 1_000))
        assertTrue(recordReviewPromptUnlock(vault, now + 2_000))
        val state = readReviewPromptState(vault)
        assertEquals(now, state.firstUnlockAt)
        assertEquals(3, state.unlockCount)
    }

    @Test
    fun recordUnlock_neverClearsAnAlreadySetPromptedLatch() {
        val vault = InMemoryVault()
        recordReviewPromptUnlock(vault, now)
        markReviewPromptShown(vault)
        assertTrue(readReviewPromptState(vault).alreadyPrompted)

        recordReviewPromptUnlock(vault, now + 1_000)

        assertTrue(readReviewPromptState(vault).alreadyPrompted, "recording another unlock must not un-latch the one-shot flag")
    }

    @Test
    fun legacyFallback_isUsedOnlyWhenNoVaultRowExistsYet() {
        val vault = InMemoryVault()
        val legacy = ReviewPromptVaultState(firstUnlockAt = now - 5_000_000L, unlockCount = 9, alreadyPrompted = false)

        assertTrue(recordReviewPromptUnlock(vault, now, legacyFallback = legacy))

        val state = readReviewPromptState(vault)
        assertEquals(legacy.firstUnlockAt, state.firstUnlockAt, "the migrated first-unlock timestamp must be preserved, not restarted")
        assertEquals(10, state.unlockCount, "this call's own unlock must still increment on top of the migrated count")
    }

    @Test
    fun legacyFallback_isIgnoredOnceAVaultRowAlreadyExists() {
        val vault = InMemoryVault()
        recordReviewPromptUnlock(vault, now)
        val legacy = ReviewPromptVaultState(firstUnlockAt = 1L, unlockCount = 999, alreadyPrompted = true)

        recordReviewPromptUnlock(vault, now + 1_000, legacyFallback = legacy)

        val state = readReviewPromptState(vault)
        assertEquals(now, state.firstUnlockAt, "an existing vault row must win over the legacy fallback")
        assertEquals(2, state.unlockCount)
    }

    @Test
    fun aThrowingVault_recordNeverThrowsAndReportsFailure() {
        val vault = ReviewPromptThrowingVault()
        assertFalse(recordReviewPromptUnlock(vault, now))
    }

    @Test
    fun aReadOkWriteThrowingVault_recordReportsFailureAndWritesNothing() {
        val vault = ReviewPromptWriteThrowingVault()
        assertFalse(recordReviewPromptUnlock(vault, now))
        assertNull(vault.getMeta(REVIEW_PROMPT_META_KEY), "a failed write must leave no partial row behind")
    }

    // ---- markReviewPromptShown ------------------------------------------

    @Test
    fun markShown_setsTheLatchAndPreservesCounters() {
        val vault = InMemoryVault()
        recordReviewPromptUnlock(vault, now)
        recordReviewPromptUnlock(vault, now + 1_000)

        markReviewPromptShown(vault)

        val state = readReviewPromptState(vault)
        assertTrue(state.alreadyPrompted)
        assertEquals(now, state.firstUnlockAt)
        assertEquals(2, state.unlockCount)
    }

    @Test
    fun markShown_onAFreshVault_stillLatchesWithDefaultCounters() {
        val vault = InMemoryVault()
        markReviewPromptShown(vault)
        val state = readReviewPromptState(vault)
        assertTrue(state.alreadyPrompted)
        assertEquals(null, state.firstUnlockAt)
        assertEquals(0, state.unlockCount)
    }

    @Test
    fun aThrowingVault_markShownNeverThrows() {
        val vault = ReviewPromptThrowingVault()
        markReviewPromptShown(vault) // must not throw
    }

    // ---- scoping / no cross-talk with other _meta rows -------------------

    @Test
    fun theStoreIsScopedToItsOwnKey() {
        val vault = InMemoryVault()
        vault.putMeta("onboard_push_prompt_v1", "1")
        vault.putMeta("seeded", "x")

        recordReviewPromptUnlock(vault, now)
        markReviewPromptShown(vault)

        assertEquals("1", vault.getMeta("onboard_push_prompt_v1"))
        assertEquals("x", vault.getMeta("seeded"))
        assertEquals(3, vault.metaKeys().size)
    }

    @Test
    fun theKeyIsTheDocumentedSingleton() {
        assertEquals("review_prompt_v1", REVIEW_PROMPT_META_KEY)
    }
}

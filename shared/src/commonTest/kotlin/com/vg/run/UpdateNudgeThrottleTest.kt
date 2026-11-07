package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** A vault whose `_meta` accessors fail (locked/closed mid-session). */
private class ThrowingMetaVault : InMemoryVault() {
    override fun getMeta(key: String): String? = throw IllegalStateException("vault unavailable")
    override fun putMeta(key: String, value: String): Unit = throw IllegalStateException("vault unavailable")
}

/**
 * The per-vault throttle: once per day per advertised version, monotonic in the
 * version, and never-throwing in both directions.
 */
class UpdateNudgeThrottleTest {

    private val today = 20_000L
    private val v = AppVersion(0, 8, 185)

    @Test
    fun noKeyStored_shows() {
        val vault = InMemoryVault()
        assertTrue(shouldShowUpdateNudge(vault, v, today))
    }

    @Test
    fun sameVersionSameDay_suppresses() {
        val vault = InMemoryVault()
        markUpdateNudgeShown(vault, v, today)
        assertFalse(shouldShowUpdateNudge(vault, v, today))
    }

    @Test
    fun sameVersionNextDay_shows() {
        val vault = InMemoryVault()
        markUpdateNudgeShown(vault, v, today)
        assertTrue(shouldShowUpdateNudge(vault, v, today + 1))
        // …and a clock that goes BACKWARD is also "a different day" — re-arming is
        // always the safe direction (at most one extra nudge, never suppression).
        assertTrue(shouldShowUpdateNudge(vault, v, today - 1))
    }

    @Test
    fun higherVersionSameDay_shows() {
        val vault = InMemoryVault()
        markUpdateNudgeShown(vault, v, today)
        assertTrue(shouldShowUpdateNudge(vault, AppVersion(0, 8, 186), today))
        assertTrue(shouldShowUpdateNudge(vault, AppVersion(1, 0, 0), today))
    }

    @Test
    fun lowerOrEqualVersionSameDay_suppresses() {
        // The monotonic bound: a relay cannot flip-flop between two
        // versions to re-nag — it has to keep climbing.
        val vault = InMemoryVault()
        markUpdateNudgeShown(vault, v, today)
        assertFalse(shouldShowUpdateNudge(vault, AppVersion(0, 8, 184), today))
        assertFalse(shouldShowUpdateNudge(vault, AppVersion(0, 0, 0), today))
        assertFalse(shouldShowUpdateNudge(vault, v, today))
    }

    @Test
    fun garbageStoredValue_isTreatedAsNoKey() {
        for (junk in listOf(
            "", "|", "garbage", "9.9.9", "20000", "9.9.9|", "|20000",
            "v9.9.9|20000", "9.9.9|today", "9.9.9|-1", "9.9.9|20000|20000",
            "9.9.9 |20000", "99999.0.0|20000",
        )) {
            val vault = InMemoryVault()
            vault.putMeta(UPDATE_NUDGE_META_KEY, junk)
            assertTrue(shouldShowUpdateNudge(vault, v, today),
                "an unparseable stored value (\"$junk\") must behave exactly like no key")
        }
    }

    @Test
    fun garbageStoredValue_isOverwrittenOnTheNextShow() {
        val vault = InMemoryVault()
        vault.putMeta(UPDATE_NUDGE_META_KEY, "garbage")
        assertTrue(shouldShowUpdateNudge(vault, v, today))
        markUpdateNudgeShown(vault, v, today)
        assertEquals("0.8.185|20000", vault.getMeta(UPDATE_NUDGE_META_KEY))
        assertFalse(shouldShowUpdateNudge(vault, v, today))
    }

    @Test
    fun storedValueCarriesTheRenderedTriple_neverARawHeader() {
        // The persisted relay-chosen state is bounded by the AppVersion
        // grammar — it is rebuilt from the parsed integers.
        val vault = InMemoryVault()
        markUpdateNudgeShown(vault, AppVersion(12, 34, 5678), 1L)
        assertEquals("12.34.5678|1", vault.getMeta(UPDATE_NUDGE_META_KEY))
        val stored = vault.getMeta(UPDATE_NUDGE_META_KEY)!!
        assertNotNull(parseAppVersion(stored.substringBefore('|')))
    }

    @Test
    fun aThrowingVault_neverThrowsAndNeverShows() {
        val vault = ThrowingMetaVault()
        assertFalse(shouldShowUpdateNudge(vault, v, today),
            "an unreadable vault must fail toward NO nudge")
        // …and the write is a silent no-op rather than a crash on the UI path.
        markUpdateNudgeShown(vault, v, today)
    }

    @Test
    fun theKeyIsTheDocumentedSingleton() {
        assertEquals("update_nudge_v1", UPDATE_NUDGE_META_KEY)
    }

    @Test
    fun epochDayNow_isTheUtcDayNumber() {
        val before = currentTimeMillis() / 86_400_000L
        val day = epochDayNow()
        val after = currentTimeMillis() / 86_400_000L
        // Sanity band: 2020-01-01 (18262) .. 2100-01-01 (47482). Pins the divisor
        // (a seconds/millis mix-up would land far outside).
        assertTrue(day in 18_262L..47_482L, "epochDayNow() returned $day")
        assertTrue(day == before || day == after, "epochDayNow() must be today's UTC day number")
    }

    @Test
    fun theThrottleIsScopedToItsOwnKey() {
        // It must not disturb — or be disturbed by — any other `_meta` row.
        val vault = InMemoryVault()
        vault.putMeta("onboard_push_prompt_v1", "1")
        vault.putMeta("seeded", "x")
        markUpdateNudgeShown(vault, v, today)
        assertEquals("1", vault.getMeta("onboard_push_prompt_v1"))
        assertEquals("x", vault.getMeta("seeded"))
        assertEquals(3, vault.metaKeys().size)
    }
}

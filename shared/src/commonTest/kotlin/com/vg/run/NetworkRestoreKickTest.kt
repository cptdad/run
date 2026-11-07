package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// NetworkRestoreKick (2026-10-25, chain:push Case A): the shared decision behind
// both platforms' network-restore kick. Explicit clock (the *At forms); the keys
// are synthetic opaque handles.
// ---------------------------------------------------------------------------

private const val WIFI = "wifi-handle"
private const val CELL = "cell-handle"

class NetworkRestoreKickTest {

    private fun kick() = NetworkRestoreKick(debounceMs = 2_000, minIntervalMs = 15_000)

    // ---- the initial callback is never a restore -------------------------------

    @Test
    fun baseline_networkUp_isNotARestore() {
        val k = kick()
        assertEquals(NetworkRestoreKick.NO_RECHECK, k.observeAt(WIFI, 0))
        assertFalse(k.dueAt(10_000).fire)
    }

    @Test
    fun registrationsInitialCallback_forTheBaselineNetwork_isIgnored() {
        // Android: the owner seeds the baseline from activeNetwork, then the
        // registration delivers onAvailable for that same network.
        val k = kick()
        k.observeAt(WIFI, 0)
        assertEquals(NetworkRestoreKick.NO_RECHECK, k.observeAt(WIFI, 50))
        assertFalse(k.dueAt(10_000).fire)
    }

    @Test
    fun baseline_noNetwork_thenAvailable_isARestore() {
        // Launched offline: no initial callback arrives; the first network IS a restore.
        val k = kick()
        k.observeAt(null, 0)
        assertEquals(2_000L, k.observeAt(WIFI, 1_000))
        assertTrue(k.dueAt(3_000).fire)
    }

    // ---- what counts as a restore ------------------------------------------------

    @Test
    fun lossThenSameNetwork_isARestore() {
        val k = kick()
        k.observeAt(WIFI, 0)
        k.observeLostAt(WIFI, 1_000)
        assertFalse(k.isNetworkUp())
        assertEquals(2_000L, k.observeAt(WIFI, 5_000))
        assertTrue(k.dueAt(7_000).fire)
    }

    @Test
    fun switchToADifferentNetwork_isARestore_withoutALoss() {
        val k = kick()
        k.observeAt(WIFI, 0)
        assertEquals(2_000L, k.observeAt(CELL, 1_000))
        assertTrue(k.dueAt(3_000).fire)
    }

    @Test
    fun lostNonDefaultNetwork_isIgnored() {
        val k = kick()
        k.observeAt(WIFI, 0)
        assertEquals(NetworkRestoreKick.NO_RECHECK, k.observeLostAt(CELL, 1_000))
        assertTrue(k.isNetworkUp())
        assertEquals(NetworkRestoreKick.NO_RECHECK, k.observeAt(WIFI, 2_000))
    }

    @Test
    fun lossAlone_neverFires() {
        val k = kick()
        k.observeAt(WIFI, 0)
        k.observeAt(null, 1_000)
        assertFalse(k.dueAt(60_000).fire)
        assertEquals(NetworkRestoreKick.NO_RECHECK, k.dueAt(60_000).waitMs)
    }

    // ---- debounce ------------------------------------------------------------------

    @Test
    fun debounce_notBeforeTheWindow_thenOnce() {
        val k = kick()
        k.observeAt(null, 0)
        k.observeAt(WIFI, 10_000)
        val early = k.dueAt(11_500)
        assertFalse(early.fire)
        assertEquals(500L, early.waitMs)
        assertFalse(early.rateLimited)
        assertTrue(k.dueAt(12_000).fire)
        // One restore, one fire.
        assertFalse(k.dueAt(12_001).fire)
        assertEquals(NetworkRestoreKick.NO_RECHECK, k.dueAt(12_001).waitMs)
    }

    @Test
    fun debounce_aLossInsideTheWindowCancels() {
        val k = kick()
        k.observeAt(null, 0)
        k.observeAt(WIFI, 1_000)
        k.observeAt(null, 2_000)
        assertFalse(k.dueAt(5_000).fire)
        assertEquals(NetworkRestoreKick.NO_RECHECK, k.dueAt(5_000).waitMs)
    }

    @Test
    fun debounce_aFlapRestartsTheWindowFromTheLatestRestore() {
        val k = kick()
        k.observeAt(null, 0)
        k.observeAt(WIFI, 1_000)
        k.observeAt(null, 1_500)
        k.observeAt(WIFI, 2_500)
        assertFalse(k.dueAt(3_500).fire)        // 2 s from the FIRST restore, not the latest
        assertTrue(k.dueAt(4_500).fire)
    }

    // ---- rate limit ----------------------------------------------------------------

    @Test
    fun rateLimit_aSecondRestoreInsideTheIntervalIsDeferredNotDropped() {
        val k = kick()
        k.observeAt(null, 0)
        k.observeAt(WIFI, 0)
        assertTrue(k.dueAt(2_000).fire)          // kick #1 at t=2 s
        k.observeAt(null, 4_000)
        k.observeAt(WIFI, 5_000)
        val d = k.dueAt(7_000)                    // debounced, but only 5 s since #1
        assertFalse(d.fire)
        assertTrue(d.rateLimited)
        assertEquals(10_000L, d.waitMs)           // until t = 17 s
        assertTrue(k.dueAt(17_000).fire)          // kick #2 exactly at the interval
    }

    @Test
    fun rateLimit_deferredRestoreIsCancelledByALoss() {
        val k = kick()
        k.observeAt(null, 0)
        k.observeAt(WIFI, 0)
        assertTrue(k.dueAt(2_000).fire)
        k.observeAt(null, 3_000)
        k.observeAt(CELL, 4_000)
        assertTrue(k.dueAt(6_000).rateLimited)
        k.observeAt(null, 8_000)
        assertFalse(k.dueAt(17_000).fire)
    }

    @Test
    fun rateLimit_isTheKicksOwn_spacedRestoresAllFire() {
        val k = kick()
        k.observeAt(null, 0)
        var t = 0L
        repeat(3) {
            k.observeAt(WIFI, t)
            assertTrue(k.dueAt(t + 2_000).fire)
            k.observeAt(null, t + 5_000)
            t += 20_000
        }
    }

    // ---- phrases: fixed text, nothing variable but a number ----------------------

    @Test
    fun phrases_areFixed_andCarryNoKey() {
        assertEquals("network restored: tor kick sent", NetworkRestoreKick.KICK_SENT_PHRASE)
        assertEquals(
            "network restore: skipped (not embedded Tor)",
            NetworkRestoreKick.skipLine(NetworkRestoreKick.SkipReason.NOT_EMBEDDED_TOR),
        )
        for (r in NetworkRestoreKick.SkipReason.entries) {
            val line = NetworkRestoreKick.skipLine(r)
            assertTrue(line.startsWith("network restore: skipped ("), line)
            assertFalse(line.contains(WIFI) || line.contains(CELL), line)
        }
        assertEquals("network restore: kick deferred 10 s (rate limit)", NetworkRestoreKick.deferredLine(9_001))
    }
}

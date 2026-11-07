package com.vg.run

import kotlin.math.abs
import kotlin.random.Random
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// ReauthPolicy — periodic random re-authentication at MAXIMUM
// (docs/periodic-reauth-design.md). Pins the interval bound, the distribution,
// the tier gate (and its agreement with CredentialPolicy's fail direction),
// the debug/e2e escape hatch, and the phase boundaries shared by Android
// (MainActivity/RunViewModel) and iOS (ContentView/IosAppController).
// ---------------------------------------------------------------------------

class ReauthPolicyTest {

    // setTestIntervalOverrideMs/nextIntervalMs touch shared object state — reset
    // it after every test so this class can't leak an override into another
    // (same technique as RelayProbeDiagnosticsTest's LoggingState save/restore).
    @AfterTest
    fun clearOverride() {
        ReauthPolicy.clearTestIntervalOverrideForTest()
    }

    private fun draw(seed: Int): Long = ReauthPolicy.intervalFromRandom(Random(seed).nextBytes(8))

    // -- Constants ------------------------------------------------------------

    @Test
    fun constants_matchDesign() {
        assertEquals(3L * 60 * 1000, ReauthPolicy.MIN_INTERVAL_MS)
        assertEquals(10L * 60 * 1000, ReauthPolicy.MAX_INTERVAL_MS)
    }

    @Test
    fun floor_isAboveMaximumAndPrivateLeverC() {
        assertTrue(ReauthPolicy.MIN_INTERVAL_MS > ProtectionLevel.MAXIMUM.autoLockTimeoutMs)
        assertTrue(ReauthPolicy.MIN_INTERVAL_MS > ProtectionLevel.PRIVATE.autoLockTimeoutMs)
    }

    @Test
    fun warning_isAtMostHalfTheFloor() {
        assertTrue(ReauthPolicy.WARNING_MS <= ReauthPolicy.MIN_INTERVAL_MS / 2)
    }

    // -- Distribution -----------------------------------------------------------

    @Test
    fun tenThousandDraws_stayWithinBounds() {
        repeat(10_000) { i ->
            val ms = draw(i)
            assertTrue(
                ms in ReauthPolicy.MIN_INTERVAL_MS..ReauthPolicy.MAX_INTERVAL_MS,
                "draw $i out of bounds: $ms",
            )
        }
    }

    @Test
    fun distribution_meanNearMidpoint_bothHalvesPopulated() {
        val n = 10_000
        var sum = 0.0
        var lowerHalf = 0
        var upperHalf = 0
        val mid = (ReauthPolicy.MIN_INTERVAL_MS + ReauthPolicy.MAX_INTERVAL_MS) / 2.0
        repeat(n) { i ->
            val ms = draw(i)
            sum += ms
            if (ms <= mid) lowerHalf++ else upperHalf++
        }
        val mean = sum / n
        val tolerance = (ReauthPolicy.MAX_INTERVAL_MS - ReauthPolicy.MIN_INTERVAL_MS) * 0.05
        assertTrue(abs(mean - mid) <= tolerance, "mean $mean not within 5% of midpoint $mid")
        assertTrue(lowerHalf > 0 && upperHalf > 0, "one half of the range never drawn ($lowerHalf/$upperHalf)")
    }

    @Test
    fun twoDraws_canDiffer() {
        assertNotEquals(draw(1), draw(2))
    }

    @Test
    fun intervalFromRandom_rejectsFewerThan8Bytes() {
        var threw = false
        try {
            ReauthPolicy.intervalFromRandom(ByteArray(7))
        } catch (_: IllegalArgumentException) {
            threw = true
        }
        assertTrue(threw, "intervalFromRandom must require >= 8 bytes")
    }

    // -- Tier gate --------------------------------------------------------------

    @Test
    fun tierGate_maximumDamagedUnreadable_true() {
        assertTrue(ReauthPolicy.appliesTo(ProtectionLevelRead.Present(ProtectionLevel.MAXIMUM)))
        assertTrue(ReauthPolicy.appliesTo(ProtectionLevelRead.Damaged))
        assertTrue(ReauthPolicy.appliesTo(ProtectionLevelRead.Unreadable))
    }

    @Test
    fun tierGate_casualPrivateAbsent_false() {
        assertFalse(ReauthPolicy.appliesTo(ProtectionLevelRead.Present(ProtectionLevel.CASUAL)))
        assertFalse(ReauthPolicy.appliesTo(ProtectionLevelRead.Present(ProtectionLevel.PRIVATE)))
        assertFalse(ReauthPolicy.appliesTo(ProtectionLevelRead.Absent))
    }

    @Test
    fun tierGate_agreesWithCredentialPolicyFailDirection() {
        // Both decisions must fail toward the STRICTEST behaviour for
        // Damaged/Unreadable: CredentialPolicy picks the SHORTEST auto-lock
        // timeout of any tier for both, and ReauthPolicy must likewise enable
        // (not skip) the periodic re-auth for both.
        val shortestTimeout = ProtectionLevel.entries.minOf { it.autoLockTimeoutMs }
        assertEquals(shortestTimeout, CredentialPolicy.autoLockTimeoutMs(ProtectionLevelRead.Damaged))
        assertEquals(shortestTimeout, CredentialPolicy.autoLockTimeoutMs(ProtectionLevelRead.Unreadable))
        assertTrue(ReauthPolicy.appliesTo(ProtectionLevelRead.Damaged))
        assertTrue(ReauthPolicy.appliesTo(ProtectionLevelRead.Unreadable))
    }

    // -- Flavour gate (debug/e2e escape hatch) -----------------------------------

    @Test
    fun flavourGate_debugNoOverride_disabled() {
        assertFalse(
            ReauthPolicy.isEnabled(
                ProtectionLevelRead.Present(ProtectionLevel.MAXIMUM), debugBuild = true, override = null,
            ),
        )
    }

    @Test
    fun flavourGate_release_alwaysEnabledAtMaximum() {
        assertTrue(
            ReauthPolicy.isEnabled(
                ProtectionLevelRead.Present(ProtectionLevel.MAXIMUM), debugBuild = false, override = null,
            ),
        )
    }

    @Test
    fun flavourGate_debugWithOverride_enabled() {
        assertTrue(
            ReauthPolicy.isEnabled(
                ProtectionLevelRead.Present(ProtectionLevel.MAXIMUM), debugBuild = true, override = 5_000L,
            ),
        )
    }

    @Test
    fun flavourGate_offTierIgnoresOverride() {
        assertFalse(
            ReauthPolicy.isEnabled(
                ProtectionLevelRead.Present(ProtectionLevel.CASUAL), debugBuild = true, override = 5_000L,
            ),
        )
    }

    @Test
    fun overrideSetter_clampsBelowFloor() {
        assertTrue(ReauthPolicy.setTestIntervalOverrideMs(1L))
        assertEquals(1000L, ReauthPolicy.nextIntervalMs())
    }

    @Test
    fun overrideSetter_isConstantAcrossDraws() {
        ReauthPolicy.setTestIntervalOverrideMs(42_000L)
        assertEquals(42_000L, ReauthPolicy.nextIntervalMs())
        assertEquals(42_000L, ReauthPolicy.nextIntervalMs())
    }

    @Test
    fun noOverride_nextIntervalMs_staysWithinBounds() {
        // isDebugBuild is true in this test binary and no override is armed
        // (cleared after every test), so this exercises the production CSPRNG
        // path exactly like a release build would.
        repeat(100) {
            val ms = ReauthPolicy.nextIntervalMs()
            assertTrue(ms in ReauthPolicy.MIN_INTERVAL_MS..ReauthPolicy.MAX_INTERVAL_MS)
        }
    }

    // Note: "the setter refuses in release" is exercised through the pure
    // isEnabled(debugBuild=false, …) parameter above rather than by flipping
    // the real isDebugBuild flag, which is fixed for the whole test binary —
    // setTestIntervalOverrideMs is itself gated on that SAME flag
    // (BuildFlags.kt), so a release binary's behaviour is proven by
    // assertKdfBuildIntegrity's own guarantee that isDebugBuild is false there.

    // -- phase() boundaries -------------------------------------------------------

    @Test
    fun phaseIsFireAtOrBelowZero_warnInsideTheWarningWindow_idleBeyondIt() {
        assertEquals(ReauthPolicy.Phase.Fire, ReauthPolicy.phase(0L))
        assertEquals(ReauthPolicy.Phase.Fire, ReauthPolicy.phase(-1L))
        assertEquals(ReauthPolicy.Phase.Warn(1), ReauthPolicy.phase(1L))
        assertEquals(ReauthPolicy.Phase.Warn(5), ReauthPolicy.phase(ReauthPolicy.WARNING_MS))
        assertEquals(ReauthPolicy.Phase.Idle, ReauthPolicy.phase(ReauthPolicy.WARNING_MS + 1))
    }

    @Test
    fun remainingMs_isDeadlineMinusNow() {
        assertEquals(500L, ReauthPolicy.remainingMs(deadlineElapsedMs = 1500L, nowElapsedMs = 1000L))
        assertEquals(-500L, ReauthPolicy.remainingMs(deadlineElapsedMs = 1000L, nowElapsedMs = 1500L))
    }
}

package com.vg.run

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// Forward-clock defense for the rolling wrong-PIN / change-PIN caps.
//
// [windowRolled] is the pure roll decision both counters share; the stores are
// expect classes with no common fake seam, so the decision is pinned here (same
// pattern as PinAttemptsStoreAbsentCounterDecisionTest).
// Before the fix the code judged the window roll from the attacker-controlled wall
// clock, so advancing it past 24h zeroed the accumulated count. windowRolled
// judges from an un-rollable monotonic sample when one is available.
//
// kotlin.test asserts are (actual, message) — the Boolean comes first.
// ---------------------------------------------------------------------------

class PinAttemptsWindowRollTest {

    private val window = PinAttemptsStore.WINDOW_MS      // 24h
    private val minute = 60_000L
    private val hour = 60 * minute

    // ---- (b) a forward wall-clock jump must NOT reset the window ----

    @Test
    fun forwardWallJump_sameBoot_doesNotRoll() {
        // Attacker rolls the wall clock forward 25h between guesses (windowStart
        // now reads 25h in the past), but only ~5 min of real uptime elapsed.
        val stored = MonotonicSample(elapsedRealtimeMs = 10 * hour, bootId = 7L)
        val now = MonotonicSample(elapsedRealtimeMs = 10 * hour + 5 * minute, bootId = 7L)
        assertFalse(
            windowRolled(
                windowStartWall = 0L,          // wall says the window started at epoch...
                nowWall = 25 * hour,           // ...and 25h have "passed" → wall would roll
                windowMs = window,
                storedMono = stored,
                nowMono = now,
            ),
            "a forward wall jump with little real elapsed time must NOT roll the window",
        )
    }

    // ---- (c) a genuine window expiry after real elapsed time still resets ----

    @Test
    fun realElapsedPastWindow_sameBoot_rolls() {
        val stored = MonotonicSample(elapsedRealtimeMs = 0L, bootId = 7L)
        val now = MonotonicSample(elapsedRealtimeMs = 25 * hour, bootId = 7L)
        assertTrue(
            windowRolled(0L, 25 * hour, window, stored, now),
            "24h+ of real monotonic uptime must roll the window",
        )
    }

    @Test
    fun realElapsedExactlyWindow_rolls() {
        val stored = MonotonicSample(elapsedRealtimeMs = 1000L, bootId = 7L)
        val now = MonotonicSample(elapsedRealtimeMs = 1000L + window, bootId = 7L)
        assertTrue(
            windowRolled(0L, window, window, stored, now),
            "exactly WINDOW_MS of real uptime rolls (>= semantics)",
        )
    }

    // ---- (d) a legitimate reboot is not mistaken for tampering ----
    // A reboot resets elapsedRealtime, so the stored anchor can no longer measure
    // elapsed-since-start; the roll falls back to the wall clock. This must NOT
    // spuriously wipe (it behaves exactly like the historical wall-clock rule)
    // and must NOT hold the count forever (which could false-wipe a reboot-heavy
    // user who legitimately accumulates a few mistyped PINs).

    @Test
    fun reboot_fallsBackToWallClock_withinWindow_doesNotRoll() {
        // bootId changed → reboot. Wall clock shows only 1h → not rolled.
        val stored = MonotonicSample(elapsedRealtimeMs = 20 * hour, bootId = 7L)
        val now = MonotonicSample(elapsedRealtimeMs = 1 * hour, bootId = 8L)
        assertFalse(
            windowRolled(windowStartWall = 5 * hour, nowWall = 6 * hour, windowMs = window, storedMono = stored, nowMono = now),
            "a reboot within the wall-clock window must not roll",
        )
    }

    @Test
    fun reboot_fallsBackToWallClock_pastWindow_rolls_noFalseHold() {
        // Same reboot, but the wall clock genuinely shows 25h — a legit user gone
        // a day across a reboot rolls normally (not held/false-wiped forever).
        val stored = MonotonicSample(elapsedRealtimeMs = 20 * hour, bootId = 7L)
        val now = MonotonicSample(elapsedRealtimeMs = 2 * hour, bootId = 8L)
        assertTrue(
            windowRolled(windowStartWall = 0L, nowWall = 25 * hour, windowMs = window, storedMono = stored, nowMono = now),
            "a reboot with 24h+ of wall-clock elapse rolls (no forever-hold)",
        )
    }

    @Test
    fun uptimeWentBackwards_fallsBackToWallClock() {
        // Anomalous / reboot: elapsedRealtime decreased → cannot trust the
        // monotonic delta, fall back to the wall clock (here within-window → false).
        val stored = MonotonicSample(elapsedRealtimeMs = 10 * hour, bootId = 7L)
        val now = MonotonicSample(elapsedRealtimeMs = 2 * hour, bootId = 7L)
        assertFalse(windowRolled(windowStartWall = 1 * hour, nowWall = 2 * hour, windowMs = window, storedMono = stored, nowMono = now))
    }

    // ---- BOOT_COUNT spoof no longer forces the wall-clock fallback ----
    // The monotonic delta was once trusted only when storedMono.bootId ==
    // nowMono.bootId; Android sourced bootId from the shell-writable BOOT_COUNT, so
    // an examiner could `adb shell settings put global boot_count N` (no root, no
    // reboot) to forge a bootId mismatch, force the wall-clock branch, then advance
    // the wall clock +25h to reset the window. windowRolled no longer consults
    // bootId — a FORWARD uptime delta is trusted regardless — so the spoof is inert.

    @Test
    fun forgedBootIdMismatch_forwardUptime_stillTrustsMonotonic_doesNotRoll() {
        // Forged "reboot" (mismatched bootId) but uptime still moving FORWARD and
        // little real time elapsed: must NOT roll, despite a +25h wall jump.
        val stored = MonotonicSample(elapsedRealtimeMs = 10 * hour, bootId = 7L)
        val now = MonotonicSample(elapsedRealtimeMs = 10 * hour + 5 * minute, bootId = 999L)
        assertFalse(
            windowRolled(
                windowStartWall = 0L,
                nowWall = 25 * hour,
                windowMs = window,
                storedMono = stored,
                nowMono = now,
            ),
            "a forged bootId mismatch with forward uptime must NOT force the wall-clock roll",
        )
    }

    // ---- backward-compat: no monotonic reference → historical wall-clock rule ----

    @Test
    fun noMonotonicReference_fallsBackToWallClock() {
        // Neither injected (unwired platform) nor stored (legacy blob): the roll
        // is the pre-fix wall-clock rule — unchanged behavior, just undefended.
        assertTrue(
            windowRolled(windowStartWall = 0L, nowWall = 25 * hour, windowMs = window, storedMono = null, nowMono = null),
            "wall fallback: past the window rolls",
        )
        assertFalse(
            windowRolled(windowStartWall = 1000L, nowWall = 1000L + hour, windowMs = window, storedMono = null, nowMono = null),
            "wall fallback: within the window does not roll",
        )
    }

    @Test
    fun legacyStoredBlob_withCurrentSample_stillFallsBackToWall() {
        // A blob from before the monotonic anchor has no anchor (storedMono == null); even with a fresh
        // sample we can't measure elapsed-since-start, so we fall back to wall for
        // this decision and migrate on the next write.
        val now = MonotonicSample(elapsedRealtimeMs = 5 * minute, bootId = 7L)
        assertTrue(windowRolled(0L, 25 * hour, window, storedMono = null, nowMono = now))
    }

    @Test
    fun backwardWallClock_wallFallback_doesNotRoll() {
        // now < windowStart (clock wound back), no monotonic ref: not rolled, so
        // the caller's minOf(windowStart, now) clamp keeps the count.
        assertFalse(
            windowRolled(windowStartWall = 50 * hour, nowWall = 1 * hour, windowMs = window, storedMono = null, nowMono = null),
        )
    }

    // ---- (a) deletion of the counter blob while the vault is configured ----
    // The tamper decision now requires POSITIVE establishment evidence
    // (the surviving marker) AND the vault configured; vlt_c-presence alone is no
    // longer a trigger (reading it as a trigger would brick a real vault). "Configured" is derived by
    // readAbsentCounter from EITHER the iOS probe OR the DB-key wrap in the
    // fate-shared anchorStore.

    @Test
    fun deletionAfterEstablishment_whileConfigured_failsClosed() {
        assertTrue(
            PinAttemptsStore.absentCounterIsTamper(established = true, vaultConfigured = true),
            "counter deleted while the marker survives on a configured vault must fail closed",
        )
    }

    @Test
    fun configuredButNoMarker_establishes_neverWipes() {
        // The legacy / interrupted-provision case round 1 wrongly wiped: no marker,
        // vault configured → establish-on-read, NOT tamper.
        assertFalse(
            PinAttemptsStore.absentCounterIsTamper(established = false, vaultConfigured = true),
            "an absent counter with no marker on a configured vault must NOT wipe",
        )
        assertTrue(
            PinAttemptsStore.absentCounterShouldEstablish(established = false, vaultConfigured = true),
            "an absent counter with no marker on a configured vault must establish",
        )
    }

    @Test
    fun freshInstall_notConfigured_isNotTamper() {
        assertFalse(
            PinAttemptsStore.absentCounterIsTamper(established = false, vaultConfigured = false),
            "a genuine fresh install (nothing configured) must read as 0, never wipe",
        )
    }
}

package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

// InactivityPolicy — the shared dead-man's-switch decision. Both Android and iOS
// now route through this, so this ONE test pins the rule for both platforms.
class InactivityPolicyTest {

    private val t = InactivityPolicy.THRESHOLD_MS
    private val minute = 60L * 1000
    private val hour = 60L * minute
    private val day = 24L * hour
    private val noUptime = InactivityPolicy.NO_UPTIME

    @Test
    fun thresholdIsSevenDays() {
        assertEquals(7L * 24 * 60 * 60 * 1000, InactivityPolicy.THRESHOLD_MS)
    }

    @Test
    fun freshlyOpened_notExpired() {
        assertFalse(InactivityPolicy.isExpired(lastOpenedMs = 1_000_000L, nowMs = 1_000_000L + t / 2, thresholdMs = t))
    }

    @Test
    fun justBeforeThreshold_notExpired() {
        assertFalse(InactivityPolicy.isExpired(lastOpenedMs = 0L, nowMs = t - 1, thresholdMs = t))
    }

    @Test
    fun exactlyThreshold_expired() {   // `>=` boundary
        assertTrue(InactivityPolicy.isExpired(lastOpenedMs = 0L, nowMs = t, thresholdMs = t))
    }

    @Test
    fun pastThreshold_expired() {
        assertTrue(InactivityPolicy.isExpired(lastOpenedMs = 1_000_000L, nowMs = 1_000_000L + t + 1, thresholdMs = t))
    }

    // -- The backward branch needs a tolerance ----------
    //
    // This REPLACES the old `clockRolledBack_expired`, which asserted the
    // ZERO-tolerance rule verbatim:
    //
    //     assertTrue(isExpired(lastOpenedMs = 2_000_000L, nowMs = 1_000_000L, thresholdMs = t))
    //     assertTrue(isExpired(lastOpenedMs = 5L,         nowMs = 4L,         thresholdMs = t))
    //
    // The second row is a ONE-MILLISECOND backward step, and "expired" here is not
    // a warning — the callers turn it straight into an unconfirmed, irreversible
    // crypto-erase that takes the recovery blob with it. `lastOpened` is re-stamped
    // on every unlock, so it is typically MINUTES old: an ordinary NTP/NITZ
    // correction after RTC drift (these users run offline, on Tor), or a user
    // fixing a mis-set date, destroyed a healthy vault. Both old rows are far
    // inside CLOCK_BACK_TOLERANCE_MS and must NOT expire now; the deliberate
    // multi-day back-set the branch actually exists for is asserted below, and the
    // evasion the branch never caught anyway (set the clock FORWARD of lastOpened,
    // or step it back incrementally) is what the monotonic term now closes.

    @Test
    fun smallClockRollback_doesNotExpire_theOldZeroToleranceRows() {
        assertFalse(InactivityPolicy.isExpired(lastOpenedMs = 2_000_000L, nowMs = 1_000_000L, thresholdMs = t))
        assertFalse(InactivityPolicy.isExpired(lastOpenedMs = 5L, nowMs = 4L, thresholdMs = t))
        // A realistic correction: an hour of accumulated RTC drift, snapped back by
        // NTP moments after an unlock.
        val base = 1_700_000_000_000L
        assertFalse(InactivityPolicy.isExpired(
            lastOpenedMs = base, nowMs = base - hour, thresholdMs = t))
    }

    @Test
    fun clockRollbackBeyondTolerance_stillExpires() {
        // The branch keeps its teeth for the move it exists for: a deliberate
        // multi-day back-set to freeze the dead-man's switch.
        val base = 1_700_000_000_000L
        assertTrue(InactivityPolicy.isExpired(
            lastOpenedMs = base, nowMs = base - 3 * day, thresholdMs = t))
        assertTrue(InactivityPolicy.isExpired(
            lastOpenedMs = base, nowMs = base - 365 * day, thresholdMs = t))
    }

    @Test
    fun clockRollbackTolerance_isExclusiveAtTheBoundary() {
        val base = 1_700_000_000_000L
        val tol = InactivityPolicy.CLOCK_BACK_TOLERANCE_MS
        // Exactly the tolerance is still noise; one ms past it is tamper.
        assertFalse(InactivityPolicy.isExpired(lastOpenedMs = base, nowMs = base - tol, thresholdMs = t))
        assertTrue(InactivityPolicy.isExpired(lastOpenedMs = base, nowMs = base - tol - 1, thresholdMs = t))
        // And the tolerance is big enough to be worth having: at least a few hours.
        assertTrue(tol >= 3 * hour)
    }

    // -- Per-level threshold decision --------------------
    // Both enforcement sites (Android InactivityWipe, iOS via
    // IosAppController.inactivityThresholdMs) consume THIS mapping, so these
    // rows pin the fail-safe for both platforms.

    @Test
    fun storedLevel_yieldsItsOwnWindow() {
        for (level in ProtectionLevel.entries) {
            assertEquals(
                level.inactivityWipeMs,
                InactivityPolicy.thresholdMsOrNull(ProtectionLevelRead.Present(level)),
            )
        }
    }

    @Test
    fun absentLevel_keepsTheLegacyDefault() {
        assertEquals(t, InactivityPolicy.thresholdMsOrNull(ProtectionLevelRead.Absent))
        // Android passes its (test-overridable) current default through unchanged.
        assertEquals(123L, InactivityPolicy.thresholdMsOrNull(ProtectionLevelRead.Absent, defaultMs = 123L))
    }

    @Test
    fun unreadableLevel_skipsTheCheck_neverAShorterWindow() {
        // The regression: an UNREADABLE stored level (transient DEVICE-KEY outage)
        // must yield null (skip this launch) — falling back to the 7-day default
        // would crypto-erase a CASUAL (180-day) vault ~173 days early.
        assertNull(InactivityPolicy.thresholdMsOrNull(ProtectionLevelRead.Unreadable))
        assertNull(InactivityPolicy.thresholdMsOrNull(ProtectionLevelRead.Unreadable, defaultMs = 123L))
    }

    // -- a DAMAGED blob must not disarm the switch --------

    @Test
    fun damagedLevel_getsTheMaximumWindow_neverSkipsForever() {
        // The bug: flipping one byte INSIDE the base64 leaves the value
        // blob-shaped but AEAD-invalid, which used to collapse to Unreadable →
        // null → "skip this launch" on EVERY launch, so the 7-day MAXIMUM
        // self-wipe never fired while an examiner held the device. A damaged blob
        // is positive tamper evidence (the device key WORKS), so it now selects
        // the strictest tier's window.
        assertEquals(
            ProtectionLevel.MAXIMUM.inactivityWipeMs,
            InactivityPolicy.thresholdMsOrNull(ProtectionLevelRead.Damaged),
        )
        // …and the caller's own default cannot loosen it (Android passes its
        // current, possibly already-widened thresholdMs in as defaultMs).
        assertEquals(
            ProtectionLevel.MAXIMUM.inactivityWipeMs,
            InactivityPolicy.thresholdMsOrNull(
                ProtectionLevelRead.Damaged, defaultMs = 180L * 24 * 60 * 60 * 1000),
        )
    }

    @Test
    fun damagedAndUnreadable_areNotConflated() {
        // The whole point of the split: a transient device-key outage still
        // DEFERS (null), only a provably-corrupt blob fails secure. Conflating
        // them in either direction reopens one of the two bugs.
        assertNull(InactivityPolicy.thresholdMsOrNull(ProtectionLevelRead.Unreadable))
        assertNotNull(InactivityPolicy.thresholdMsOrNull(ProtectionLevelRead.Damaged))
    }

    @Test
    fun damagedLevel_isAWindowNotAWipe() {
        // BRICK-SAFETY: Damaged only picks the window; the expiry decision still
        // requires a real last-active timestamp that is genuinely past it. A
        // freshly-used vault with a damaged level blob must NOT read as expired.
        val threshold = InactivityPolicy.thresholdMsOrNull(ProtectionLevelRead.Damaged)!!
        val now = 1_700_000_000_000L
        assertFalse(InactivityPolicy.isExpired(
            lastOpenedMs = now - 1000L, nowMs = now, thresholdMs = threshold))
        // Absence of the level keeps establish-on-read (the legacy default), so an
        // examiner DELETING the value gains nothing either.
        assertEquals(t, InactivityPolicy.thresholdMsOrNull(ProtectionLevelRead.Absent))
    }

    // -- The monotonic anchor ---------------------------
    // The bug: the predicate was pure wall clock, so disabling automatic time
    // and pinning the date to the seizure day kept the elapsed term small FOREVER
    // and permanently disarmed the 7/90/180-day self-destruct. The old backward
    // branch never caught it — the examiner sets the clock FORWARD of lastOpened
    // (which the prefs/plist mtime leaks approximately), not backward.

    @Test
    fun frozenWallClock_stillExpiresOnTheMonotonicTerm() {
        val base = 1_700_000_000_000L
        val bootAt = 3 * hour   // uptime when the vault was last unlocked
        // The examiner's frozen clock: `now` never moves more than a minute past
        // the stamp, whatever the real elapsed time.
        assertFalse(InactivityPolicy.isExpired(
            lastOpenedMs = base, nowMs = base + minute, thresholdMs = t,
            storedUptimeMs = bootAt, nowUptimeMs = bootAt + 6 * day))
        assertTrue(InactivityPolicy.isExpired(
            lastOpenedMs = base, nowMs = base + minute, thresholdMs = t,
            storedUptimeMs = bootAt, nowUptimeMs = bootAt + t))
        // …and the boundary is `>=`, like the wall-clock term.
        assertFalse(InactivityPolicy.isExpired(
            lastOpenedMs = base, nowMs = base + minute, thresholdMs = t,
            storedUptimeMs = bootAt, nowUptimeMs = bootAt + t - 1))
    }

    @Test
    fun uptimeWentBackwards_fallsBackToTheWallClock() {
        // A reboot resets uptime, destroying the anchor. That is the ONLY way out of
        // the monotonic term — and it drops the device to BFU, so the examiner pays
        // for each evasion. On this path every wall-clock rule is live again.
        val base = 1_700_000_000_000L
        val stored = 10 * hour
        val afterReboot = 2 * minute
        assertTrue(InactivityPolicy.isExpired(
            lastOpenedMs = base, nowMs = base + t, thresholdMs = t,
            storedUptimeMs = stored, nowUptimeMs = afterReboot))
        assertFalse(InactivityPolicy.isExpired(
            lastOpenedMs = base, nowMs = base + minute, thresholdMs = t,
            storedUptimeMs = stored, nowUptimeMs = afterReboot))
        // Including the (tolerance-gated) backward branch, which the monotonic
        // veto below would otherwise suppress.
        assertTrue(InactivityPolicy.isExpired(
            lastOpenedMs = base, nowMs = base - 3 * day, thresholdMs = t,
            storedUptimeMs = stored, nowUptimeMs = afterReboot))
    }

    @Test
    fun monotonicTerm_neverVetoesTheWallClockTerm() {
        // PERMANENT-DISARM GUARD. The monotonic delta can UNDERSTATE real elapsed
        // time: here the anchor (1 h) is from a previous boot and the device has
        // been up 5 h, so uptime has NOT "gone backwards" and the delta reads 4 h —
        // while the wall clock correctly says 8 days. If the terms were anything
        // but a disjunction, this device would never self-destruct. (iOS's
        // systemUptime, which does not advance in deep sleep, understates the same
        // way, which is why this is the shape of the rule and not an edge case.)
        val base = 1_700_000_000_000L
        assertTrue(InactivityPolicy.isExpired(
            lastOpenedMs = base, nowMs = base + 8 * day, thresholdMs = t,
            storedUptimeMs = hour, nowUptimeMs = 5 * hour))
    }

    @Test
    fun sameBootAnchor_vouchesForABackwardStep_butOnlyUntilTheTermMatures() {
        // BRICK-SAFETY: a usable same-boot anchor is positive evidence that only
        // minutes of real time have passed, so a backward wall step is a clock
        // CORRECTION (a user fixing a badly mis-set date), not a stale vault.
        val base = 1_700_000_000_000L
        assertFalse(InactivityPolicy.isExpired(
            lastOpenedMs = base, nowMs = base - 60 * day, thresholdMs = t,
            storedUptimeMs = hour, nowUptimeMs = hour + minute))
        // Nothing is lost by not wiping twice as fast: if the device really is
        // being sat on, the monotonic term fires on its own at the true threshold.
        assertTrue(InactivityPolicy.isExpired(
            lastOpenedMs = base, nowMs = base - 60 * day, thresholdMs = t,
            storedUptimeMs = hour, nowUptimeMs = hour + t))
    }

    @Test
    fun healthyDeviceWithACorrectClock_neverExpires_atAnyTier() {
        // The combined predicate must not fire more readily than the old one on a
        // device that is simply being used. Wall clock and uptime advance together;
        // the user unlocks well inside every tier's window.
        val base = 1_700_000_000_000L
        for (level in ProtectionLevel.entries) {
            val window = level.inactivityWipeMs
            for (elapsed in listOf(0L, 1L, minute, hour, day, window - 1)) {
                assertFalse(
                    InactivityPolicy.isExpired(
                        lastOpenedMs = base, nowMs = base + elapsed, thresholdMs = window,
                        storedUptimeMs = 7 * hour, nowUptimeMs = 7 * hour + elapsed),
                    "healthy $level vault must not expire after ${elapsed}ms",
                )
                // Same instant, but this vault predates the anchor (legacy blob).
                assertFalse(
                    InactivityPolicy.isExpired(
                        lastOpenedMs = base, nowMs = base + elapsed, thresholdMs = window,
                        storedUptimeMs = noUptime, nowUptimeMs = 7 * hour + elapsed),
                    "healthy legacy $level vault must not expire after ${elapsed}ms",
                )
            }
        }
    }

    // -- Stamp format: legacy records must keep reading (migrate-on-write) ------

    @Test
    fun legacyBareDecimalStamp_stillParses_andIsJudgedOnTheWallClock() {
        // Every vault provisioned before the anchor stored a bare decimal. It must
        // parse, must carry NO_UPTIME, and must behave exactly like the old
        // wall-clock-only rule — the platforms rewrite it with an anchor on the
        // next unlock (recordUnlock / touch), never eagerly.
        val stamp = assertNotNull(InactivityPolicy.parseStamp("1700000000000"))
        assertEquals(1_700_000_000_000L, stamp.timestampMs)
        assertEquals(noUptime, stamp.uptimeMs)
        assertTrue(InactivityPolicy.isStampExpired(
            stamp, nowMs = 1_700_000_000_000L + t, nowUptimeMs = 5 * hour, thresholdMs = t))
        assertFalse(InactivityPolicy.isStampExpired(
            stamp, nowMs = 1_700_000_000_000L + minute, nowUptimeMs = 5 * hour, thresholdMs = t))
        // A present `now` uptime with an ABSENT stored anchor must not be mistaken
        // for a usable term (it would read as "up for 5 h since the stamp").
        assertFalse(InactivityPolicy.isStampExpired(
            stamp, nowMs = 1_700_000_000_000L + minute, nowUptimeMs = 400 * day, thresholdMs = t))
    }

    @Test
    fun stampRoundTrips_andTheLegacyShapeIsByteIdentical() {
        assertEquals("1700000000000", InactivityPolicy.formatStamp(1_700_000_000_000L, noUptime))
        assertEquals("1700000000000|3600000", InactivityPolicy.formatStamp(1_700_000_000_000L, hour))
        val round = assertNotNull(InactivityPolicy.parseStamp(InactivityPolicy.formatStamp(42L, 7L)))
        assertEquals(42L, round.timestampMs)
        assertEquals(7L, round.uptimeMs)
    }

    @Test
    fun malformedStamps_failTowardTheSafeSide() {
        // A damaged UPTIME field degrades to "no anchor" (the anchor is an
        // optimisation — failing the whole parse would hand the callers their
        // tamper verdict over a cosmetic defect).
        val degraded = assertNotNull(InactivityPolicy.parseStamp("1700000000000|not-a-number"))
        assertEquals(1_700_000_000_000L, degraded.timestampMs)
        assertEquals(noUptime, degraded.uptimeMs)
        assertEquals(noUptime, InactivityPolicy.parseStamp("1700000000000|-9")!!.uptimeMs)
        // A damaged WALL-CLOCK field is the case the callers have always treated as
        // a malformed timestamp; keep saying so rather than inventing a value.
        assertNull(InactivityPolicy.parseStamp("not-a-number"))
        assertNull(InactivityPolicy.parseStamp(""))
        assertNull(InactivityPolicy.parseStamp("|3600000"))
    }

    @Test
    fun failSafeEpochStamp_isStillExpired() {
        // Android's undecryptable-blob branch substitutes InactivityStamp(0, NO_UPTIME)
        // where it used to pass a bare 0L lastOpened. That must stay "expired" for
        // every real threshold and any uptime.
        for (level in ProtectionLevel.entries) {
            assertTrue(InactivityPolicy.isStampExpired(
                InactivityStamp(0L, noUptime),
                nowMs = 1_700_000_000_000L, nowUptimeMs = 5 * minute,
                thresholdMs = level.inactivityWipeMs))
        }
    }
}

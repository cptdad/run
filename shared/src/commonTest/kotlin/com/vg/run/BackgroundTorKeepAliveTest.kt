package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The iOS bounded Tor keep-alive's decisions (BackgroundTorKeepAlive.kt) —
 * hermetic, no clock, no UIKit. The Swift glue (AppState's "Bounded Tor
 * keep-alive" section + ContentView's `.background` branch) is pinned by
 * `IosTorKeepAliveSourceTest` (androidApp JVM suite).
 *
 * Pinned here:
 *  • no exit while foreground — a deadline is refused whenever the app is not
 *    in the background at that moment, and every token a foreground return
 *    outlived is stale;
 *  • exit only after the window, in the background, and exactly once;
 *  • the exceptions (wipe, relaunch-required, external proxy, not connected,
 *    known-wedged, device locking, MAXIMUM) refuse the keep-alive → today's
 *    immediate exit;
 *  • the window = OS budget − 3 s, clamped to [5 s, 170 s]; "not a budget yet"
 *    is null.
 */
class BackgroundTorKeepAliveTest {

    // ---------------------------------------------------------- the exit race

    @Test
    fun deadlineInTheBackground_afterArm_tearsDownOnce() {
        val k = BackgroundTorKeepAlive()
        val t = k.arm()
        assertTrue(k.isKeeping)
        assertTrue(k.deadline(t, stillInBackground = true), "window over, still invisible: stop Tor + exit")
        assertEquals(BackgroundTorKeepAlive.Phase.TORN_DOWN, k.phase)
        // The second source (expiration handler after the timer) must not tear down twice.
        assertFalse(k.deadline(t, stillInBackground = true))
    }

    @Test
    fun noExitWhileForeground_evenWithTheCurrentToken() {
        val k = BackgroundTorKeepAlive()
        val t = k.arm()
        // `.inactive` (the user is coming back) is NOT background.
        assertFalse(k.deadline(t, stillInBackground = false))
        assertTrue(k.isKeeping, "a refused deadline leaves the keeper for the foreground to settle")
        assertTrue(k.foreground(), "warm return")
        assertEquals(BackgroundTorKeepAlive.Phase.IDLE, k.phase)
    }

    @Test
    fun aDeadlineQueuedBeforeTheForegroundReturn_isStale() {
        val k = BackgroundTorKeepAlive()
        val t = k.arm()
        assertTrue(k.foreground())
        // Delivered late, and even if the app is backgrounded AGAIN by then.
        assertFalse(k.deadline(t, stillInBackground = true), "a foregrounded keep-alive never exits on an old token")
        assertEquals(BackgroundTorKeepAlive.Phase.IDLE, k.phase)
    }

    @Test
    fun reArming_killsTheOldToken() {
        val k = BackgroundTorKeepAlive()
        val first = k.arm()
        assertTrue(k.foreground())
        val second = k.arm()
        assertFalse(first == second)
        assertFalse(k.deadline(first, stillInBackground = true), "the first background's timer is dead")
        assertTrue(k.isKeeping)
        assertTrue(k.deadline(second, stillInBackground = true))
    }

    @Test
    fun reArmingWhileKeeping_withoutAForegroundInBetween_alsoKillsTheOldToken() {
        val k = BackgroundTorKeepAlive()
        val first = k.arm()
        val second = k.arm()
        assertFalse(k.deadline(first, stillInBackground = true))
        assertTrue(k.deadline(second, stillInBackground = true))
    }

    @Test
    fun foreground_withoutAKeepAlive_isNotAWarmReturn() {
        val k = BackgroundTorKeepAlive()
        assertFalse(k.foreground(), "a Face ID .inactive → .active bounce reuses nothing")
        assertEquals(BackgroundTorKeepAlive.Phase.IDLE, k.phase)
    }

    @Test
    fun tornDown_isTerminal() {
        val k = BackgroundTorKeepAlive()
        assertTrue(k.deadline(k.arm(), stillInBackground = true))
        assertEquals(BackgroundTorKeepAlive.NO_TOKEN, k.arm(), "tor_main is gone: never keep again")
        assertFalse(k.foreground(), "a return after teardown is not warm")
        assertFalse(k.isKeeping)
        assertEquals(BackgroundTorKeepAlive.Phase.TORN_DOWN, k.phase)
    }

    @Test
    fun disarm_whenTheOsGrantsNoTask_killsTheTokenAndIsNotAWarmReturn() {
        val k = BackgroundTorKeepAlive()
        val t = k.arm()
        k.disarm()
        assertFalse(k.isKeeping)
        assertFalse(k.deadline(t, stillInBackground = true), "the caller already took the immediate path")
        assertFalse(k.foreground(), "nothing was kept")
        k.disarm()   // idempotent
        assertEquals(BackgroundTorKeepAlive.Phase.IDLE, k.phase)
    }

    // ---------------------------------------------------------- exit veto

    @Test
    fun aForegroundQueuedBehindTheBlockingStop_vetoesTheExit() {
        val k = BackgroundTorKeepAlive()
        assertTrue(k.deadline(k.arm(), stillInBackground = true))
        // stop() blocked the main thread; the `.active` it hid is delivered now.
        assertFalse(k.foreground(), "not a warm return — Tor is gone")
        assertFalse(k.exitStillAllowed(stillInBackground = true),
            "even if UIKit still reads .background on that turn, the foreground vetoes the exit")
    }

    @Test
    fun exitStillAllowed_onlyWhenTornDownAndStillInvisible() {
        val k = BackgroundTorKeepAlive()
        assertFalse(k.exitStillAllowed(stillInBackground = true), "nothing torn down")
        val t = k.arm()
        assertFalse(k.exitStillAllowed(stillInBackground = true), "still keeping")
        assertTrue(k.deadline(t, stillInBackground = true))
        assertFalse(k.exitStillAllowed(stillInBackground = false), "the app is coming forward on this turn")
        assertTrue(k.exitStillAllowed(stillInBackground = true))
    }

    // ---------------------------------------------------------- residue cap

    @Test
    fun residueLeft_isMeasuredFromTheLastUnlockedLock_notPerStretch() {
        val cap = BackgroundTorKeepAlive.RESIDUE_CAP_SEC
        assertEquals(cap, BackgroundTorKeepAlive.residueLeftSeconds(sinceLastUnlockedLockSec = 900.0, unlockedNow = true),
            "this backgrounding locks the session now: the full cap")
        assertNull(BackgroundTorKeepAlive.residueLeftSeconds(null, unlockedNow = false), "never unlocked: nothing to bound")
        assertEquals(cap - 30.0, BackgroundTorKeepAlive.residueLeftSeconds(30.0, unlockedNow = false))
        assertEquals(0.0, BackgroundTorKeepAlive.residueLeftSeconds(cap + 50.0, unlockedNow = false), "spent")
        assertEquals(cap, BackgroundTorKeepAlive.residueLeftSeconds(-3.0, unlockedNow = false), "clock oddity clamps")
        assertEquals(0.0, BackgroundTorKeepAlive.residueLeftSeconds(Double.NaN, unlockedNow = false), "NaN fails secure")
    }

    @Test
    fun residueCap_bindsAcrossRepeatedWarmReturns() {
        // lock at t=0; warm returns + re-backgrounds at 27, 54, 81, 108, 135, 162 s:
        // each stretch would get a fresh ~27 s budget window, but the TOTAL is capped.
        val budgetWindow = BackgroundTorKeepAlive.windowSeconds(30.0)!!
        var t = 0.0
        var stretches = 0
        while (true) {
            val left = BackgroundTorKeepAlive.residueLeftSeconds(t, unlockedNow = false)
            if (!BackgroundTorKeepAlive.residueAllowsKeepAlive(left)) break
            val w = BackgroundTorKeepAlive.composeWindow(budgetWindow, left)
            assertTrue(t + w <= BackgroundTorKeepAlive.RESIDUE_CAP_SEC + 1e-9, "stretch at $t overruns the cap")
            t += w
            stretches++
            assertTrue(stretches < 100, "must terminate")
        }
        assertTrue(t <= BackgroundTorKeepAlive.RESIDUE_CAP_SEC)
        assertTrue(BackgroundTorKeepAlive.RESIDUE_CAP_SEC - t <= BackgroundTorKeepAlive.MIN_WINDOW_SEC,
            "keeps going only while more than the floor is left")
    }

    @Test
    fun residueAllows_onlyAboveTheFloor() {
        assertTrue(BackgroundTorKeepAlive.residueAllowsKeepAlive(null))
        assertTrue(BackgroundTorKeepAlive.residueAllowsKeepAlive(5.5))
        assertFalse(BackgroundTorKeepAlive.residueAllowsKeepAlive(BackgroundTorKeepAlive.MIN_WINDOW_SEC), "≤ floor ⇒ immediate path")
        assertFalse(BackgroundTorKeepAlive.residueAllowsKeepAlive(0.0))
    }

    @Test
    fun composeWindow_isTheMinOfBudgetAndResidue() {
        assertEquals(27.0, BackgroundTorKeepAlive.composeWindow(27.0, null), "no unlocked session: budget only")
        assertEquals(27.0, BackgroundTorKeepAlive.composeWindow(27.0, 170.0))
        assertEquals(12.0, BackgroundTorKeepAlive.composeWindow(27.0, 12.0), "residue binds")
        assertEquals(0.0, BackgroundTorKeepAlive.composeWindow(27.0, -4.0), "already due ⇒ fires at once")
        assertEquals(0.0, BackgroundTorKeepAlive.composeWindow(27.0, Double.NaN))
        assertEquals(0.0, BackgroundTorKeepAlive.composeWindow(Double.NaN, null))
        assertEquals(BackgroundTorKeepAlive.MAX_WINDOW_SEC,
            BackgroundTorKeepAlive.composeWindow(BackgroundTorKeepAlive.MAX_WINDOW_SEC, BackgroundTorKeepAlive.RESIDUE_CAP_SEC),
            "an unknown budget (cap fallback) still obeys the residue cap")
    }

    @Test
    fun deadlineWithoutAnyArm_isRefused() {
        val k = BackgroundTorKeepAlive()
        assertFalse(k.deadline(0L, stillInBackground = true))
        assertFalse(k.deadline(BackgroundTorKeepAlive.NO_TOKEN, stillInBackground = true))
    }

    // ---------------------------------------------------------- the window

    @Test
    fun window_isTheBudgetMinusTheMargin_clamped() {
        assertEquals(27.0, BackgroundTorKeepAlive.windowSeconds(30.0))
        assertEquals(26.5, BackgroundTorKeepAlive.windowSeconds(29.5))
        assertEquals(BackgroundTorKeepAlive.MIN_WINDOW_SEC, BackgroundTorKeepAlive.windowSeconds(6.0), "floor")
        assertEquals(BackgroundTorKeepAlive.MIN_WINDOW_SEC, BackgroundTorKeepAlive.windowSeconds(0.0))
        assertEquals(BackgroundTorKeepAlive.MIN_WINDOW_SEC, BackgroundTorKeepAlive.windowSeconds(-4.0))
        assertEquals(BackgroundTorKeepAlive.MAX_WINDOW_SEC, BackgroundTorKeepAlive.windowSeconds(600.0), "cap")
        assertEquals(170.0, BackgroundTorKeepAlive.windowSeconds(173.0))
    }

    @Test
    fun window_isUnknownWhileUiKitStillReportsForeground() {
        // UIKit's "suitably large" DBL_MAX, infinities and NaN are not budgets.
        assertNull(BackgroundTorKeepAlive.windowSeconds(Double.MAX_VALUE))
        assertNull(BackgroundTorKeepAlive.windowSeconds(Double.POSITIVE_INFINITY))
        assertNull(BackgroundTorKeepAlive.windowSeconds(Double.NaN))
        assertNull(BackgroundTorKeepAlive.windowSeconds(BackgroundTorKeepAlive.UNKNOWN_BUDGET_ABOVE_SEC + 1))
    }

    @Test
    fun window_constantsAreSane() {
        assertTrue(BackgroundTorKeepAlive.MIN_WINDOW_SEC > 0)
        assertTrue(BackgroundTorKeepAlive.MIN_WINDOW_SEC < BackgroundTorKeepAlive.MAX_WINDOW_SEC)
        // The margin must cover TorManager.stop()'s 2 s bounded HALT + flush.
        assertTrue(BackgroundTorKeepAlive.SAFETY_MARGIN_SEC >= 2.5)
        assertTrue(BackgroundTorKeepAlive.MAX_WINDOW_SEC <= 180.0, "residue window bound (doc: iOS bounded Tor keep-alive)")
    }

    // ---------------------------------------------------------- the gate

    private fun gate(
        isWipe: Boolean = false,
        relaunchRequired: Boolean = false,
        externalProxy: Boolean = false,
        torConnected: Boolean = true,
        notKnownWedged: Boolean = true,
        deviceLocking: Boolean = false,
        residueAllows: Boolean = true,
        tierAllowed: Boolean = true,
    ) = BackgroundTorKeepAlive.shouldKeepAlive(
        isWipe, relaunchRequired, externalProxy, torConnected, notKnownWedged, deviceLocking, residueAllows, tierAllowed,
    )

    @Test
    fun gate_keepsAHealthyConnectedTor() {
        assertTrue(gate())
    }

    @Test
    fun gate_everyExceptionKeepsTheImmediateExit() {
        assertFalse(gate(isWipe = true), "wipe")
        assertFalse(gate(relaunchRequired = true), "dead / terminal / stopped Tor")
        assertFalse(gate(externalProxy = true), "external SOCKS proxy mode")
        assertFalse(gate(torConnected = false), "bootstrapping / never started")
        assertFalse(gate(notKnownWedged = false), "unlocked session that never reached the relay")
        assertFalse(gate(deviceLocking = true), "device lock under way (Class-A keys about to go)")
        assertFalse(gate(residueAllows = false), "absolute residue cap spent")
        assertFalse(gate(tierAllowed = false), "MAXIMUM / damaged tier")
    }

    @Test
    fun tier_maximumAndDamagedRefuse_othersAllow() {
        val allow = { r: ProtectionLevelRead -> BackgroundTorKeepAlive.tierAllows(r, sessionTierAllowed = true) }
        assertTrue(allow(ProtectionLevelRead.Present(ProtectionLevel.CASUAL)))
        assertTrue(allow(ProtectionLevelRead.Present(ProtectionLevel.PRIVATE)))
        assertFalse(allow(ProtectionLevelRead.Present(ProtectionLevel.MAXIMUM)), "MAXIMUM: shortest residue window")
        assertTrue(allow(ProtectionLevelRead.Absent), "legacy, never chosen")
        assertFalse(allow(ProtectionLevelRead.Damaged), "fails secure to MAXIMUM")
    }

    @Test
    fun tier_unreadableFallsBackToTheSessionDecision() {
        assertTrue(BackgroundTorKeepAlive.tierAllows(ProtectionLevelRead.Unreadable, sessionTierAllowed = true))
        assertFalse(BackgroundTorKeepAlive.tierAllows(ProtectionLevelRead.Unreadable, sessionTierAllowed = false))
        assertFalse(BackgroundTorKeepAlive.tierAllowsAuthenticated(ProtectionLevelRead.Unreadable), "no session to fall back on")
        assertTrue(BackgroundTorKeepAlive.tierAllowsAuthenticated(ProtectionLevelRead.Present(ProtectionLevel.CASUAL)))
        assertFalse(BackgroundTorKeepAlive.tierAllowsAuthenticated(ProtectionLevelRead.Present(ProtectionLevel.MAXIMUM)))
    }

    // ---------------------------------------------------------- the phrases

    @Test
    fun phrases_areFixedTextAndNumbers() {
        // Word for word Android's TorKeepAlive.PHRASE_REUSED (both panels read alike).
        assertEquals("reused warm Tor from the previous session", BackgroundTorKeepAlive.PHRASE_REUSED)
        assertEquals("tor keep-alive window 27 s (background budget 30 s)", BackgroundTorKeepAlive.windowPhrase(27.9, 30.4))
        assertEquals("tor keep-alive window 170 s (background budget unknown)", BackgroundTorKeepAlive.windowPhrase(170.0, null))
        assertEquals("tor keep-alive window 170 s (background budget unknown)", BackgroundTorKeepAlive.windowPhrase(170.0, Double.MAX_VALUE))
        assertEquals("tor keep-alive window 5 s (background budget 0 s)", BackgroundTorKeepAlive.windowPhrase(5.0, -1.0))
        // Only the two numbers ever vary: strip them and the text is fixed.
        val skeleton = BackgroundTorKeepAlive.windowPhrase(27.0, 30.0).replace(Regex("[0-9]+"), "#")
        assertEquals("tor keep-alive window # s (background budget # s)", skeleton)
    }
}

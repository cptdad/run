package com.vg.run

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Source guard for the iOS bounded Tor keep-alive after backgrounding
 * (2026-10-23). The decisions are shared commonMain code
 * (`BackgroundTorKeepAlive`, pinned by `BackgroundTorKeepAliveTest`); what the
 * Swift compiler cannot check is the GLUE, and every rule below is one whose
 * regression reintroduces a bug we have seen or a security property we promise:
 *
 *  - no exit while foreground: every exit(0) on the background path is gated on
 *    the keeper, the deadline is decided against `applicationState ==
 *    .background` read at THAT moment, and re-read after the bounded stop();
 *  - exit only after the window, in the background: the old immediate exit is
 *    skipped exactly when Tor is kept, and nothing else stops a kept Tor;
 *  - the exceptions keep the immediate exit (the gate short-circuits on them);
 *  - the vault lock + key wipe on `.background` are unchanged and unconditional;
 *  - `.background`-gated, never `.inactive` (the Lever-B lesson);
 *  - TOR_REUSED on a warm return, with Android's phrase word for word;
 *  - a single tor_main: the warm return starts nothing;
 *  - one connect report per SESSION with honest phases (anchor + latch re-armed,
 *    `boot` omitted, reveal latch re-armed).
 * Bodies are scanned with comments stripped.
 */
class IosTorKeepAliveSourceTest {

    private val appState: String by lazy {
        stripComments(iosAppStateSources())
    }
    private val contentView: String by lazy {
        stripComments(File(repoRoot(), "iosApp/iosApp/ContentView.swift").readText())
    }
    private val torManager: String by lazy {
        stripComments(File(repoRoot(), "iosApp/iosApp/TorManager.swift").readText())
    }

    /** The `.onChange(of: scenePhase)` handler of ContentView. */
    private val scenePhaseHandler: String by lazy {
        val start = contentView.indexOf(".onChange(of: scenePhase)")
        assertTrue("ContentView scenePhase handler not found", start >= 0)
        braceBody(contentView, contentView.indexOf('{', start), includeBraces = false)
    }

    /**
     * The `.background` branch: the handler dispatches `.background` (and ONLY
     * `.background`) to `handleSceneEnteredBackground()`, whose body is the branch.
     */
    private val backgroundBranch: String by lazy {
        sceneBranch("if phase == .background { handleSceneEnteredBackground() }",
            "handleSceneEnteredBackground", "private func handleSceneEnteredBackground()")
    }

    /** The `.active` branch, dispatched the same way to `handleSceneBecameActive()`. */
    private val activeBranch: String by lazy {
        sceneBranch("if phase == .active { handleSceneBecameActive() }",
            "handleSceneBecameActive", "private func handleSceneBecameActive()")
    }

    /**
     * The handler must dispatch [phase] to [name] with exactly [dispatch], and
     * [name] must have no other caller (declaration + that one call), so its body
     * runs only for that phase — never `.inactive`.
     */
    private fun sceneBranch(dispatch: String, name: String, signature: String): String {
        assertTrue("the scenePhase handler must dispatch with `$dispatch`", scenePhaseHandler.contains(dispatch))
        assertEquals("`$name` must be declared once and called only from the scenePhase handler",
            2, Regex(Regex.escape(name) + """\(""").findAll(contentView).count())
        return functionBody(contentView, signature, includeBraces = false)
    }

    // ------------------------------------------------------------ ContentView

    @Test
    fun theKeepAliveIsDecidedFirst_beforeTheLock() {
        val decide = backgroundBranch.indexOf("let keepingTor = appState.armTorKeepAliveOnBackground()")
        val lock = backgroundBranch.indexOf("lockAndResetNavigation()")
        assertTrue("the `.background` branch must ask the keep-alive", decide >= 0)
        assertTrue("the background lock must stay", lock >= 0)
        assertTrue("decided BEFORE the lock (the tier read needs the device key the lock wipes)", decide < lock)
    }

    @Test
    fun theVaultLockAndPreUnlockScrubsAreUnconditional() {
        // The keep-alive defers ONLY the Tor teardown and the exit.
        assertTrue(Regex("""if appState\.isUnlocked \{\s*lockAndResetNavigation\(\)""").containsMatchIn(backgroundBranch))
        assertTrue("delivered-notification sweep must stay", backgroundBranch.contains("appState.sweepDeliveredNotificationsWhileLocked()"))
        assertTrue("scanned-handle clear must stay", backgroundBranch.contains("appState.pendingMoveHandle = nil"))
        assertFalse("the scrubs must not be gated on the keep-alive",
            Regex("""if !?keepingTor \{[^}]*(sweepDelivered|pendingMoveHandle|lockAndResetNavigation)""").containsMatchIn(backgroundBranch))
    }

    @Test
    fun aKeptTorIsNeverStoppedOrExitedOnTheBackgroundPath() {
        assertTrue("pre-unlock stop must be skipped when kept",
            backgroundBranch.contains("if !keepingTor { TorManager.shared.stop() }"))
        assertTrue("the old immediate exit must be skipped when kept",
            Regex("""if !keepingTor,\s*TorManager\.shared\.relaunchRequired \|\| ExternalProxyMode\.shared\.isExternalThisProcess \{""")
                .containsMatchIn(backgroundBranch))
        assertEquals("exactly one exit(0) on the background path", 1, Regex("""exit\(0\)""").findAll(backgroundBranch).count())
        // lock() must not stop the kept daemon either.
        val lock = functionBody(appState, "func lock()", includeBraces = false)
        assertTrue(lock.contains("if leavingForeground && !torKeepAlive.isKeeping {"))
        // …and the `.background` lock is the plain one: not-`.active` still stops Tor.
        assertTrue(lock.contains("let leavingForeground = !lockStaysInForegroundScene && UIApplication.shared.applicationState != .active"))
        assertFalse("the `.background` branch must never take the in-scene lock",
            backgroundBranch.contains("inForegroundScene") || backgroundBranch.contains("lockInForegroundScene"))
    }

    /**
     * An overdue periodic re-auth fired while `.inactive` (Control Center, app
     * switcher) locks the vault but must NOT stop Tor — the scene never left the
     * screen, and a stopped `tor_main` cannot restart in-process, so the PIN-screen
     * re-unlock would need a relaunch. The lock goes through
     * `AppState.lockInForegroundScene`, whose flag makes lock()'s ONE Tor-stop gate
     * false. At ANY tier, MAXIMUM included (re-auth runs only at MAXIMUM, and the
     * `.active` re-auth lock has always kept Tor): MAXIMUM's "no keep-alive" rule
     * is enforced on the `.background` that follows, via the locked branch's
     * keep-alive decision — pinned below.
     *
     * Non-vacuousness: routing lockIfDeadlinePassed back through a bare
     * `lockAndResetNavigation()`, or dropping the flag from lock()'s gate, fails this.
     */
    @Test
    fun anInactiveReauthLock_keepsTor_andMaximumStillStopsItOnTheFollowingBackground() {
        val check = functionBody(contentView, "private func lockIfDeadlinePassed(includeIdle: Bool) -> Bool", includeBraces = false)
        assertEquals("both out-of-tick locks are in-scene",
            2, Regex(Regex.escape("lockAndResetNavigation(inForegroundScene: true)")).findAll(check).count())
        assertFalse("no plain (Tor-stopping) lock in the out-of-tick check",
            check.contains("lockAndResetNavigation()"))
        assertTrue("the out-of-tick check stays the `.inactive` tick's lock",
            functionBody(contentView, "private func onAutoLockTick()", includeBraces = false)
                .contains("lockIfDeadlinePassed(includeIdle: false)"))

        val helper = functionBody(contentView, "private func lockAndResetNavigation(inForegroundScene: Bool = false)", includeBraces = false)
        assertTrue(Regex("""if inForegroundScene \{\s*appState\.lockInForegroundScene\(\)\s*\} else \{\s*appState\.lock\(\)\s*\}""")
            .containsMatchIn(helper))
        assertEquals("lockInForegroundScene is driven only from lockAndResetNavigation",
            1, Regex("""lockInForegroundScene\(""").findAll(contentView).count())

        val inScene = functionBody(appState, "func lockInForegroundScene()", includeBraces = false)
        val set = inScene.indexOf("lockStaysInForegroundScene = true")
        val reset = inScene.indexOf("defer { lockStaysInForegroundScene = false }")
        val call = inScene.indexOf("lock()")
        assertTrue("flag set, reset deferred, then lock()", set in 0 until reset && reset < call)
        assertFalse("the in-scene lock must not stop Tor itself", inScene.contains("TorManager.shared.stop"))

        val lock = functionBody(appState, "func lock()", includeBraces = false)
        assertEquals("lock() keeps ONE Tor stop, behind the foreground gate",
            1, Regex(Regex.escape("TorManager.shared.stop(")).findAll(lock).count())
        val gate = lock.indexOf("let leavingForeground = !lockStaysInForegroundScene && UIApplication.shared.applicationState != .active")
        val stopGate = lock.indexOf("if leavingForeground && !torKeepAlive.isKeeping {")
        assertTrue("the gate is computed before the stop", gate in 0 until stopGate)
        assertTrue("the one stop sits inside that gate",
            Regex("""if leavingForeground && !torKeepAlive\.isKeeping \{\s*TorManager\.shared\.stop\(\)\s*\}""").containsMatchIn(lock))
        assertTrue("the Debug-mode flush wait reads the same gate (no main-actor block on `.inactive`)",
            lock.contains("let waitForLockFlush = leavingForeground"))

        // MAXIMUM: a locked `.background` after the in-scene lock decides Tor through
        // the tier-gated keep-alive, and a refusal stops it + recycles.
        val decide = backgroundBranch.indexOf("let keepingTor = appState.armTorKeepAliveOnBackground()")
        val lockedStop = backgroundBranch.indexOf("if !keepingTor { TorManager.shared.stop() }")
        assertTrue(decide in 0 until lockedStop)
        val begin = functionBody(appState, "func armTorKeepAliveOnBackground()", includeBraces = false)
        assertTrue(begin.contains("controller.torKeepAliveTierAllows(sessionTierAllowed: sessionTierAllowsKeepAlive)"))
    }

    @Test
    fun aWarmReturnIsHandledOnActive_neverOnInactive() {
        assertTrue(activeBranch.contains("appState.endTorKeepAliveOnForeground()"))
        assertFalse("never `.inactive` (Lever-B lesson)", scenePhaseHandler.contains(".inactive"))
        assertFalse("never `.inactive` in the `.active` handler", activeBranch.contains(".inactive"))
        assertFalse("never `.inactive` in the `.background` handler", backgroundBranch.contains(".inactive"))
        assertEquals(1, Regex("""armTorKeepAliveOnBackground\(\)""").findAll(contentView).count())
        assertEquals(1, Regex("""endTorKeepAliveOnForeground\(\)""").findAll(contentView).count())
    }

    // ------------------------------------------------------------ the exit race

    @Test
    fun theDeadline_isDecidedByTheKeeper_againstTheBackgroundStateAtThatMoment() {
        val deadline = functionBody(appState, "private func torKeepAliveDeadline(", includeBraces = false)
        assertTrue(deadline.contains("let inBackground = UIApplication.shared.applicationState == .background"))
        assertTrue(deadline.contains("guard torKeepAlive.deadline(deadlineToken: token, stillInBackground: inBackground) else {"))
        // A refused expiration must still end its task (or iOS kills the process).
        assertTrue(Regex("""if cause == \.expired \{ endTorKeepAliveBackgroundTask\(\) \}""").containsMatchIn(deadline))
        // stop() blocks the main thread, so the exit is decided one runloop
        // turn LATER — never inline in the deadline.
        val stop = deadline.indexOf("TorManager.shared.stop()")
        val hop = deadline.indexOf("hopToMain {")
        val finishCall = deadline.indexOf("self?.finishTorKeepAliveTeardown()")
        assertTrue("stop() first", stop >= 0)
        assertTrue("then a main-runloop hop", hop > stop)
        assertTrue("which runs the exit decision", finishCall > hop)
        // …and hopToMain IS a plain one-runloop-turn main-queue hop (no delay, no
        // inline run when already on main).
        val hopToMain = functionBody(appState, "func hopToMain(_ body: @escaping @MainActor () -> Void)", includeBraces = false)
        assertEquals("hopToMain must be exactly a DispatchQueue.main.async hop",
            "DispatchQueue.main.async { MainActor.assumeIsolated(body) }", hopToMain.trim())
        assertFalse("no inline exit in the deadline", deadline.contains("exit(0)"))
        val finish = functionBody(appState, "private func finishTorKeepAliveTeardown()", includeBraces = false)
        assertTrue(finish.contains("let inBackground = UIApplication.shared.applicationState == .background"))
        val veto = finish.indexOf("guard torKeepAlive.exitStillAllowed(stillInBackground: inBackground) else {")
        assertTrue("the keeper (foreground since teardown) + the state at THIS turn decide", veto >= 0)
        assertTrue(veto < finish.indexOf("exit(0)"))
        assertEquals("one exit", 1, Regex("""exit\(0\)""").findAll(finish).count())
    }

    // ------------------------------------------------------------ residue cap

    @Test
    fun theAbsoluteResidueCap_isMeasuredFromTheLastUnlockedSessionsLock() {
        val lock = functionBody(appState, "func lock()", includeBraces = false)
        val stamp = lock.indexOf("if isUnlocked { lastUnlockedSessionLockUptime = ProcessInfo.processInfo.systemUptime }")
        assertTrue("lock() stamps the end of an UNLOCKED session", stamp >= 0)
        assertTrue("before isUnlocked is cleared", stamp < lock.indexOf("isUnlocked = false"))
        val begin = functionBody(appState, "func armTorKeepAliveOnBackground()", includeBraces = false)
        assertTrue(begin.contains("BackgroundTorKeepAlive.companion.residueLeftSeconds("))
        assertTrue(begin.contains("unlockedNow: isUnlocked"))
        assertTrue("a spent cap takes the immediate path", begin.contains("!deviceLocking, residueAllows else {"))
        assertTrue(begin.contains("torKeepAliveResidueDeadlineUptime = residueLeft.map { now + $0 }"))
        val schedule = functionBody(appState, "private func scheduleTorKeepAliveDeadline(", includeBraces = false)
        assertTrue("window = min(budget window, residue left now)",
            schedule.contains("BackgroundTorKeepAlive.companion.composeWindow("))
    }

    // ------------------------------------------------------------ LEAD: background unlock

    @Test
    fun anUnlockFinishingInTheBackground_isLockedAtOnce() {
        val relock = functionBody(appState, "private func relockIfUnlockedInBackground(", includeBraces = false)
        assertTrue(relock.contains("guard isUnlocked, UIApplication.shared.applicationState == .background else { return false }"))
        assertTrue(relock.contains("lock()"))
        assertFalse("never `.inactive` (Lever B: Face ID drives .inactive mid-unlock)", relock.contains(".inactive"))
        // unlock()'s `.opened` branch is didOpenVault(), run on the main actor
        // BEFORE the completion; the relock is its last step, after the
        // vault-opening work.
        val unlock = functionBody(appState, "func unlock(pin: String", includeBraces = false)
        val opened = unlock.indexOf("if outcome == .opened {\n                    self.didOpenVault()")
        assertTrue("unlock's `.opened` branch must run didOpenVault()", opened >= 0)
        assertTrue("didOpenVault (with its relock) runs before completion",
            opened < unlock.indexOf("completion(outcome)"))
        val didOpen = functionBody(appState, "private func didOpenVault()", includeBraces = false)
        assertTrue(didOpen.contains("self.relockIfUnlockedInBackground(site: \"unlock\")"))
        assertTrue("after the vault-opening work",
            didOpen.indexOf("self.relockIfUnlockedInBackground(site: \"unlock\")") > didOpen.indexOf("self.startTorOrDirect()"))
        assertTrue("startTorOrDirect must still be in didOpenVault", didOpen.indexOf("self.startTorOrDirect()") >= 0)
        val recover = functionBody(appState, "func recoverWithCode(", includeBraces = false)
        assertTrue(recover.contains("self.relockIfUnlockedInBackground(site: \"recovery\")"))
    }

    @Test
    fun theKeepAliveLocksAnUnlockedVault_beforeAnythingElse() {
        val foreground = functionBody(appState, "func endTorKeepAliveOnForeground()", includeBraces = false)
        val warm = foreground.indexOf("guard torKeepAlive.foreground() else { return }")
        val lock = foreground.indexOf("lock()")
        val adopt = foreground.indexOf("adoptKeptTor()")
        assertTrue("only on a WARM return (never a Face ID bounce)", warm in 0 until lock)
        assertTrue(foreground.contains("if isUnlocked {"))
        assertTrue("locked before the adoption", lock < adopt)
        val deadline = functionBody(appState, "private func torKeepAliveDeadline(", includeBraces = false)
        val relock = deadline.indexOf("if inBackground { relockIfUnlockedInBackground(site: \"keep-alive deadline\") }")
        assertTrue("the deadline re-locks first, background-gated", relock >= 0)
        assertTrue(relock < deadline.indexOf("guard torKeepAlive.deadline("))
    }

    @Test
    fun allThreeDeadlineSourcesCarryTheirArmsToken() {
        val begin = functionBody(appState, "func armTorKeepAliveOnBackground()", includeBraces = false)
        assertTrue(begin.contains("self?.torKeepAliveDeadline(token: token, cause: .expired)"))
        assertTrue(begin.contains("torKeepAliveToken = token"))
        // Device lock: PERMANENT observers (a power-button lock can post
        // will-become-unavailable before `.background`), installed from init.
        val lockObs = functionBody(appState, "private func observeDeviceLockForTorKeepAlive()", includeBraces = false)
        assertTrue(lockObs.contains("UIApplication.protectedDataWillBecomeUnavailableNotification"))
        assertTrue(lockObs.contains("self.torKeepAliveDeadline(token: self.torKeepAliveToken, cause: .deviceLocked)"))
        assertTrue(lockObs.contains("UIApplication.protectedDataDidBecomeAvailableNotification"))
        assertTrue(functionBody(appState, "    init() {", includeBraces = false).contains("observeDeviceLockForTorKeepAlive()"))
        assertTrue("a lock under way refuses the keep-alive", begin.contains("!deviceLocking, residueAllows else {"))
        val schedule = functionBody(appState, "private func scheduleTorKeepAliveDeadline(", includeBraces = false)
        assertTrue(schedule.contains("self?.torKeepAliveDeadline(token: token, cause: .window)"))
        // The window is the OS budget, re-read — never a hard-coded constant.
        assertTrue(schedule.contains("UIApplication.shared.backgroundTimeRemaining"))
        assertTrue(schedule.contains("BackgroundTorKeepAlive.companion.windowSeconds(backgroundTimeRemainingSec: remaining)"))
        // No invalid task ⇒ immediate path.
        assertTrue(begin.contains("guard task != .invalid else {"))
        assertTrue(begin.contains("torKeepAlive.disarm()"))
    }

    @Test
    fun theGateShortCircuitsOnEveryException_beforeTheTierRead() {
        val begin = functionBody(appState, "func armTorKeepAliveOnBackground()", includeBraces = false)
        val shortCircuit = begin.indexOf("guard !isWipe, !relaunch, !external, torConnected, notKnownWedged, !deviceLocking, residueAllows else {")
        val tierRead = begin.indexOf("controller.torKeepAliveTierAllows(sessionTierAllowed: sessionTierAllowsKeepAlive)")
        assertTrue(shortCircuit >= 0)
        assertTrue(tierRead > shortCircuit)
        assertTrue(begin.contains("let isWipe = wipedThisSession"))
        assertTrue(begin.contains("let relaunch = tor.relaunchRequired"))
        assertTrue(begin.contains("let external = ExternalProxyMode.shared.isExternalThisProcess"))
        assertTrue(begin.contains("BackgroundTorKeepAlive.companion.shouldKeepAlive("))
    }

    // ------------------------------------------------------------ warm return

    @Test
    fun warmReturn_emitsTorReused_withAndroidsPhrase() {
        val adopt = functionBody(appState, "private func adoptKeptTor()", includeBraces = false)
        assertTrue(Regex("""text: BackgroundTorKeepAlive\.companion\.PHRASE_REUSED,\s*code: ConnectionLog\.Code\.torReused""")
            .containsMatchIn(adopt))
        val clear = adopt.indexOf("ConnectionLog.shared.clear()")
        val reused = adopt.indexOf("PHRASE_REUSED")
        assertTrue("the ring is cleared first so TOR_REUSED anchors the timeline", clear in 0 until reused)
        // Word for word the Android panel line.
        assertEquals(TorKeepAlive.PHRASE_REUSED, BackgroundTorKeepAlive.PHRASE_REUSED)
        assertEquals(ConnectionLog.Code.TOR_REUSED, ConnectionLog.Code.valueOf("TOR_REUSED"))
    }

    @Test
    fun warmReturn_startsNoSecondTorMain() {
        val adopt = functionBody(appState, "private func adoptKeptTor()", includeBraces = false)
        val foreground = functionBody(appState, "func endTorKeepAliveOnForeground()", includeBraces = false)
        for (body in listOf(adopt, foreground)) {
            assertFalse("a warm return must never start Tor", body.contains(".start()"))
            assertFalse(body.contains("startSpeculativeTor"))
            assertFalse(body.contains("speculativeTorStarted = false"))
        }
        // TorManager.start() refuses on `started` BEFORE the once-per-process latch,
        // so the unlock-time start() of a warm session is a quiet no-op, not a
        // relaunch latch.
        val start = functionBody(torManager, "func start()", includeBraces = false)
        val startedGuard = start.indexOf("guard !started else {")
        val everGuard = start.indexOf("guard !threadEverCreated else {")
        assertTrue(startedGuard in 0 until everGuard)
    }

    @Test
    fun warmReturn_keepsADecidedRace_andRerunsAnUndecidedOne() {
        val adopt = functionBody(appState, "private func adoptKeptTor()", includeBraces = false)
        assertTrue(adopt.contains("tor.rerunUndecidedRelayAddressRace()"))
        assertFalse("the hedge must not be reset on a warm return", adopt.contains("descriptorHedge"))
        val rerun = functionBody(torManager, "func rerunUndecidedRelayAddressRace()", includeBraces = false)
        assertTrue(rerun.contains("!race.decidedThisState()"))
        assertTrue(rerun.indexOf("race.noteTorHsStateReset()") in 0 until rerun.indexOf("return startRelayAddressRace()"))
    }

    @Test
    fun warmReturn_reArmsTheSessionsTelemetry() {
        val warm = functionBody(appState, "private func beginWarmTorSession()", includeBraces = false)
        for (line in listOf(
            "connectStartUptime = nil",
            "connectTelemetrySent = false",
            "torConnectedUptime = ProcessInfo.processInfo.systemUptime",
            "warmTorSession = true",
            "ConnectTelemetry.shared.startNewRevealSession()",
            "relayAnsweredThisSession = false",
            "controller.resetEarlyNewnyms()",
        )) assertTrue("beginWarmTorSession must do: $line", warm.contains(line))
        assertTrue("a warm session omits boot",
            appState.contains("let bootStartedAt = warmTorSession ? 0 : TorManager.shared.startedAtUptime"))
        // The pre-unlock warm-up runs again for the new session.
        val adopt = functionBody(appState, "private func adoptKeptTor()", includeBraces = false)
        assertTrue(adopt.indexOf("rendezvousWarmupFired = false") in 0 until adopt.indexOf("warmRendezvousIfPreUnlock()"))
    }

    @Test
    fun theWindowLine_isUncoded() {
        val schedule = functionBody(appState, "private func scheduleTorKeepAliveDeadline(", includeBraces = false)
        assertTrue(schedule.contains("ConnectionLog.shared.append(kind: ConnectionLog.Kind.system, text: line)"))
        assertFalse("no new telemetry code for the window", schedule.contains("code:"))
    }

    // ------------------------------------------------------------ DEBUG measurement mode

    @Test
    fun theUnboundedMeasurementMode_isCompiledOutOfRelease() {
        // The switch itself only exists in DEBUG, and the accessor is false in release.
        assertTrue(Regex("""#if DEBUG[^#]*static var testUnboundedTorKeepAlive = false""").containsMatchIn(appState))
        assertTrue(Regex("""#if DEBUG\s+return AppState\.testUnboundedTorKeepAlive\s+#else\s+return false\s+#endif""")
            .containsMatchIn(appState))
        // The launch argument is read inside RunApp's DEBUG block
        // (scripts/verify-release-clean.sh walks the preprocessor depth too).
        val runApp = File(repoRoot(), "iosApp/iosApp/RunApp.swift").readText()
        val arg = runApp.indexOf("\"--test-tor-keepalive-unbounded\"")
        assertTrue(arg >= 0)
        val lastIf = runApp.lastIndexOf("#if DEBUG", arg)
        val lastEnd = runApp.lastIndexOf("#endif", arg)
        assertTrue("the argument read must sit inside an open #if DEBUG", lastIf > lastEnd)
        // The probe element exists only in DEBUG.
        val probeEl = contentView.indexOf(".accessibilityIdentifier(\"tor_suspend_probe\")")
        assertTrue(probeEl >= 0)
        assertTrue(contentView.lastIndexOf("#if DEBUG", probeEl) > contentView.lastIndexOf("#endif", probeEl))
    }

    @Test
    fun theUnboundedMode_stillTearsDownOnDeviceLock_andOnlySkipsTheTimedDeadlines() {
        val deadline = functionBody(appState, "private func torKeepAliveDeadline(", includeBraces = false)
        val skip = deadline.indexOf("if torKeepAliveUnbounded && cause != .deviceLocked {")
        assertTrue("device lock must still tear down in measurement mode", skip >= 0)
        assertTrue("the relock still runs first", deadline.indexOf("relockIfUnlockedInBackground") < skip)
        val begin = functionBody(appState, "func armTorKeepAliveOnBackground()", includeBraces = false)
        assertTrue("wipe / relaunch / external / connected / wedged / device-lock gates are NOT bypassed",
            begin.contains("guard !isWipe, !relaunch, !external, torConnected, notKnownWedged, !deviceLocking, residueAllows else {"))
        assertTrue(begin.contains("let residueAllows = unbounded || "))
        assertTrue(begin.contains("let tierAllowed = unbounded || "))
    }

    @Test
    fun theProbe_runsOnWarmReturns_andItsLinesCarryNumbersOnly() {
        val foreground = functionBody(appState, "func endTorKeepAliveOnForeground()", includeBraces = false)
        assertTrue(foreground.indexOf("if torKeepAliveUnbounded { runTorSuspendProbe() }") > foreground.indexOf("adoptKeptTor()"))
        val raw = iosAppStateSources()
        val phrases = Regex("""torSuspendProbeLine\(([^\n]*)\)""").findAll(raw).map { it.groupValues[1] }.toList()
        assertTrue(phrases.size >= 5)
        val allowed = setOf("bgSec", "ms", "probe.answerSec ?? -1", "probe.answerAfterUnlockSec ?? -1")
        for (p in phrases) {
            for (m in Regex("""\\\(([^)]*\)?)\)""").findAll(p)) {
                assertTrue("probe line interpolates a non-number: $p", m.groupValues[1] in allowed)
            }
            assertFalse(p.contains("port", ignoreCase = false) && p.contains("\\(port"))
        }
    }
}

package com.vg.run

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Guards the IN-PROCESS periodic re-auth lock (docs/periodic-reauth-design.md).
 *
 * Until this feature landed, "lock" on Android meant `finishAndRemoveTask()` —
 * a process/Activity boundary that cleared session state by DESTROYING the
 * ViewModel. `lockForReauth` is the first lock that keeps both the Activity and
 * the ViewModel alive, so every "the teardown is implicit in the object dying"
 * assumption in `RunViewModel` and `MainActivity` has to be made EXPLICIT. Each
 * property below is one such assumption that stopped holding, and each failure
 * is a real defect rather than a style rule:
 *
 *  - the ONE watchdog that drives both Lever C and the re-auth `return`s after
 *    it fires, and only `onResume` re-posts it. A re-auth lock does not leave
 *    the foreground, so `onResume` never runs: without an explicit re-post, ONE
 *    re-auth permanently disarms BOTH watchdogs for the rest of the session —
 *    the "at least once every ten minutes" bound silently degrades to
 *    once-ever, and the Lever-C idle auto-lock stops existing;
 *  - the push session bookkeeping and the relay-reachability latches are
 *    documented as SESSION-scoped, which was true only while a lock destroyed
 *    the ViewModel that holds them. Left behind, the raw inbox ids and the
 *    UnifiedPush endpoint URL stay resident in a locked-but-alive process, and
 *    the next session inherits a stale "we have talked to the relay" claim;
 *  - `lockForReauth` must close the vault and wipe the key BEFORE it raises the
 *    flag MainActivity navigates on, or the PIN screen renders over a live
 *    vault;
 *  - on iOS, `AppState.lock()` is reachable WITHOUT going through
 *    `ContentView.lockAndResetNavigation()` (the `onVaultSessionRetired`
 *    callback, and `emergencyWipe`), so the re-auth deadline has to be cleared
 *    on the lock TRANSITION rather than in that one helper.
 *
 * SOURCE-LEVEL, for the reason this file's siblings state: `RunViewModel` is an
 * `AndroidViewModel` needing a real `Application`, `MainActivity`'s watchdog is
 * a `Handler` Runnable, and this module's unit-test tier has no Robolectric and
 * no mocking framework. Same technique as [SpeculativeTorAdoptionSourceTest] /
 * [PushSessionBookkeepingRaceSourceTest]; bodies are scanned with comments
 * STRIPPED so prose that merely names a call can neither satisfy nor trip a
 * guard. The RUNTIME companion is the instrumented
 * `RunViewModelLockSessionTest`.
 */
class PeriodicReauthLockSourceTest {

    private val viewModel: String by lazy {
        SourcePins.stripped(SourcePins.RUN_VIEW_MODEL)
    }
    private val activity: String by lazy {
        SourcePins.stripped(SourcePins.MAIN_ACTIVITY)
    }
    private val contentView: String by lazy {
        stripComments(File(repoRoot(), "iosApp/iosApp/ContentView.swift").readText())
    }

    // -----------------------------------------------------------------------
    // 1. The watchdog must survive its own re-auth fire
    // -----------------------------------------------------------------------

    /**
     * The sharpest regression this feature can produce, and a SILENT one: the
     * app keeps working, it just stops locking.
     *
     * `autoLockCheck` re-posts itself at the bottom of every ordinary tick and
     * `return`s early once a deadline fires. That early return is correct for
     * Lever C — `finishAndRemoveTask()` is destroying the Activity, and
     * `onResume` will re-post on the next launch — but the re-auth branch keeps
     * the Activity RESUMED, so nothing else ever posts it again.
     *
     * Non-vacuousness: deleting the `postDelayed` line from the re-auth branch
     * fails this.
     */
    @Test
    fun reauthFire_rePostsTheSharedWatchdog_soOneReauthDoesNotDisarmBoth() {
        val fired = activity.functionBody("            if (remainingMs <= 0) {")

        val reauthAt = fired.indexOf("vm.lockForReauth()")
        val repostAt = fired.indexOf("autoLockHandler.postDelayed(this,")
        assertTrue("precondition: the fired branch must call vm.lockForReauth()", reauthAt >= 0)
        assertTrue(
            "the re-auth branch must RE-POST the watchdog — it is an IN-PROCESS lock, so " +
                "onResume (the only other poster) never runs, and returning without a re-post " +
                "disarms BOTH the periodic re-auth and Lever C for the rest of the foreground " +
                "session. Fired branch was:\n$fired",
            repostAt >= 0,
        )
        assertTrue(
            "the re-post must follow the lock, inside the re-auth arm — not the Lever-C arm, " +
                "which is finishing the Activity",
            repostAt > reauthAt,
        )
        assertTrue(
            "the Lever-C arm must still tear the whole session down",
            fired.contains("finishAndRemoveTask()"),
        )
        assertTrue(
            "…and the Lever-C arm must NOT re-post: the Activity is going away, and onResume " +
                "posts a fresh one on the next launch",
            fired.indexOf("finishAndRemoveTask()") > repostAt,
        )
    }

    /**
     * The re-post is safe only because a locked session is a cheap tick: both
     * inputs the Runnable reads are nulled by [RunViewModel.lockSession], so
     * every tick between the lock and the re-unlock short-circuits.
     */
    @Test
    fun aLockedSessionMakesEveryTickANoOp() {
        val session = viewModel.functionBody("    private fun lockSession(stopTor: Boolean) {")
        assertTrue(
            "lockSession must null the vault — the Lever-C branch of the watchdog is gated on it",
            session.contains("vault = null"),
        )
        assertTrue(
            "lockSession must clear the re-auth deadline — the re-auth branch is gated on it, " +
                "and a stale deadline would re-fire the lock on the very next tick",
            session.contains("reauthDeadlineElapsedMs = null"),
        )
        val run = activity.functionBody("        override fun run() {")
        assertTrue(
            "the Lever-C branch must stay gated on an OPEN vault",
            run.contains("vm.vault != null"),
        )
        assertTrue(
            "the re-auth branch must stay gated on a non-null deadline",
            run.contains("val reauthDeadline = vm.reauthDeadlineElapsedMs"),
        )
    }

    // -----------------------------------------------------------------------
    // 2. lockSession must explicitly clear what ViewModel death used to clear
    // -----------------------------------------------------------------------

    /**
     * `vendorPushRegisteredIds` / `unifiedPushRegisteredIds` hold RAW INBOX IDS
     * and `unifiedPushLastEndpoint` holds the URL of the user's push server —
     * the same class of identifier `clearInMemoryIdentifierMaps()` already
     * scrubs on lock. They are documented as session-scoped RAM, which held
     * only while every lock destroyed this ViewModel.
     *
     * Through the shared helper, never inline: the helper bumps
     * `pushTeardownEpoch` FIRST, which is what makes a registration pass
     * straddling this lock discard its own bookkeeping instead of re-planting
     * inbox ids behind us.
     *
     * Non-vacuousness: removing the call (or replacing it with inline
     * `.clear()`s — which [PushSessionBookkeepingRaceSourceTest] independently
     * forbids) fails this.
     */
    @Test
    fun lockSession_dropsThePushSessionBookkeepingThroughTheSharedHelper() {
        val session = viewModel.functionBody("    private fun lockSession(stopTor: Boolean) {")
        assertTrue(
            "lockSession must call clearPushSessionBookkeeping() — an in-process lock leaves " +
                "raw inbox ids + the UnifiedPush endpoint URL strongly reachable in a " +
                "locked-but-alive process, and carries them into the next session's " +
                "already-registered diff. Body was:\n$session",
            session.contains("clearPushSessionBookkeeping()"),
        )
        for (field in listOf(
            "vendorPushRegisteredIds", "vendorPushToken",
            "unifiedPushRegisteredIds", "unifiedPushLastEndpoint",
        )) {
            assertFalse(
                "lockSession must not touch `$field` directly — an inline clear skips the " +
                    "epoch bump that invalidates an in-flight registration pass",
                session.contains(field),
            )
        }
    }

    /**
     * [RunViewModel.relayHandshakeComplete]'s kdoc states the rule: reset only
     * when the transport itself is torn down — Tor restart / lock / wipe. The
     * lock half held vacuously while a lock destroyed the ViewModel. Carrying a
     * true latch into the next session paints the contact list CONNECTED before
     * a single round-trip has been made on the rebuilt transport, which is the
     * dishonest claim the latch exists to prevent.
     */
    @Test
    fun lockSession_resetsTheRelayReachabilityAndHandshakeLatches() {
        val session = viewModel.functionBody("    private fun lockSession(stopTor: Boolean) {")
        assertTrue(
            "lockSession must drop the reachability flag with the transport",
            session.contains("_isRelayReachable.value = false"),
        )
        assertTrue(
            "lockSession must drop the honest-connected latch with the transport — its own " +
                "kdoc names `lock` as one of the three resets",
            session.contains("_relayHandshakeComplete.value = false"),
        )
        // Both siblings already do it; keep them pinned so the three cannot drift.
        assertTrue(
            "performEmergencyWipe must keep resetting both",
            viewModel.functionBody("    fun performEmergencyWipe(deniable: Boolean = true) {")
                .let {
                    it.contains("_isRelayReachable.value = false") &&
                        it.contains("_relayHandshakeComplete.value = false")
                },
        )
        assertTrue(
            "restartTor must keep resetting both",
            viewModel.functionBody("    private fun restartTor() {").let {
                it.contains("_isRelayReachable.value = false") &&
                    it.contains("_relayHandshakeComplete.value = false")
            },
        )
    }

    /**
     * Every tracked Job must die with the session. `lockSession` is the ONLY
     * thing standing between a pre-lock coroutine and the next session now that
     * the scope (`viewModelScope`) outlives the lock — `onCleared` used to
     * cancel the whole scope for free.
     */
    @Test
    fun lockSession_cancelsEveryTrackedJob() {
        val session = viewModel.functionBody("    private fun lockSession(stopTor: Boolean) {")
        for (job in listOf(
            "torMonitorJob", "torStartJob", "relayCheckJob", "controlPollJob",
            "unreadPrimeJob", "relayStallJob", "torStallJob",
        )) {
            assertTrue(
                "lockSession must cancel `$job` — viewModelScope survives an in-process lock, " +
                    "so nothing else stops it racing the next session. Body was:\n$session",
                sessionJobCancelIndex(viewModel, session, job) >= 0,
            )
        }
    }

    // -----------------------------------------------------------------------
    // 3. The PIN screen may never render over a live vault
    // -----------------------------------------------------------------------

    /**
     * MainActivity navigates to `"pin"` off `reauthLocked`. If that flag were
     * raised before the teardown, the credential prompt would be composed while
     * the vault handle is still open and the Tink keyset still unwrapped —
     * precisely the AFU-window RAM the full-lock decision (design doc §2) exists
     * to remove.
     */
    @Test
    fun lockForReauth_closesTheVaultAndWipesTheKeyBeforeRaisingTheFlag() {
        val fn = viewModel.functionBody("    fun lockForReauth() {")
        val lockAt = fn.indexOf("lockSession(stopTor = false)")
        val flagAt = fn.indexOf("_reauthLocked.value = true")
        assertTrue("lockForReauth must run the shared teardown", lockAt >= 0)
        assertTrue("lockForReauth must raise the navigation flag", flagAt >= 0)
        assertTrue(
            "the teardown must come FIRST — MainActivity navigates to the PIN screen off this " +
                "flag, and it must never compose over a live vault / unwrapped keyset",
            lockAt < flagAt,
        )
        assertTrue(
            "Tor must stay UP for an in-process lock, so the re-unlock's connectViaTor ADOPTS " +
                "it — stopTor = false is the whole reason lockSession takes a parameter",
            fn.contains("lockSession(stopTor = false)"),
        )
        val session = viewModel.functionBody("    private fun lockSession(stopTor: Boolean) {")
        val closeAt = session.indexOf("vault?.close()")
        val wipeAt = session.indexOf("cryptoProvider.wipeKey()")
        assertTrue("lockSession must close the vault handle", closeAt >= 0)
        assertTrue("lockSession must wipe the Tink keyset from RAM", wipeAt >= 0)
        assertTrue(
            "the Tor teardown must stay gated on stopTor, so lockForReauth keeps the instance",
            session.contains("if (stopTor) {"),
        )
    }

    // -----------------------------------------------------------------------
    // 4. iOS: the deadline is cleared on the lock TRANSITION, not in one helper
    // -----------------------------------------------------------------------

    /**
     * `lockAndResetNavigation()` is not the only way the iOS vault locks:
     * `AppState.lock()` is also called straight from the
     * `controller.onVaultSessionRetired` callback (a re-key that did not
     * verifiably commit), and `emergencyWipe()` sets `isUnlocked = false`
     * itself. Neither goes through ContentView, so clearing the deadline only
     * in that helper leaves an already-PAST deadline in `@State`. The
     * `.onReceive` guard covers the locked stretch but NOT the window between
     * the next unlock's `isUnlocked = true` and this handler's re-arm, and
     * SwiftUI orders a main-run-loop Timer delivery against a view update by no
     * contract at all.
     *
     * Non-vacuousness: deleting the `if !unlocked { reauthDeadlineUptime = nil }`
     * block fails this.
     */
    @Test
    fun ios_clearsTheReauthDeadlineOnEveryLockTransition() {
        assertTrue(
            "the isUnlocked handler must route every transition to onUnlockedChanged",
            contentView.contains(".onChange(of: appState.isUnlocked) { unlocked in onUnlockedChanged(unlocked) }"),
        )
        val fn = contentView.functionBody("    private func onUnlockedChanged(_ unlocked: Bool) {")
        val clearAt = fn.indexOf("reauthDeadlineUptime = nil")
        val armAt = fn.indexOf("reauthDeadlineUptime = appState.controller.reauthEnabled()")
        assertTrue(
            "the isUnlocked handler must clear the deadline on the lock transition — " +
                "AppState.lock() is reachable without ContentView.lockAndResetNavigation(). " +
                "Body was:\n$fn",
            clearAt >= 0,
        )
        assertTrue(
            "…guarded on `if !unlocked`, so it cannot also clear the deadline it just armed",
            fn.contains("if !unlocked {"),
        )
        assertTrue("the unlock arm must still re-arm the deadline", armAt >= 0)
        assertTrue(
            "the clear must come BEFORE the re-arm in source order, or an unlock would land " +
                "on a nil deadline",
            clearAt < armAt,
        )
        // The helper keeps its own clear: it is the path every ContentView-driven
        // lock takes, and it also resets the presentation state.
        assertTrue(
            "lockAndResetNavigation must keep clearing the deadline too (belt and braces — it " +
                "runs synchronously with the lock, ahead of any view update)",
            contentView.functionBody("    private func lockAndResetNavigation(inForegroundScene: Bool = false) {")
                .contains("reauthDeadlineUptime = nil"),
        )
    }

    /**
     * Both platforms must keep the deadline gated behind an OPEN vault: the
     * Android field is nulled by `lockSession`, and the iOS timer body refuses
     * to act while locked or in `.background`. While `.inactive` (Control Center,
     * app switcher — the scene is still on screen behind the privacy cover) ONLY an
     * overdue re-auth may fire, so holding the scene `.inactive` cannot keep the
     * vault open without bound; Lever C stays `.active`-only.
     */
    @Test
    fun ios_theTimerNeverActsWhileLockedOrBackgrounded_andAnOverdueReauthFiresWhileInactive() {
        assertTrue(
            "every auto-lock timer tick must route to onAutoLockTick",
            contentView.contains(".onReceive(autoLockTimer) { _ in onAutoLockTick() }"),
        )
        val tick = contentView.functionBody("    private func onAutoLockTick() {")
        val inactiveAt = tick.indexOf("if scenePhase == .inactive {")
        val guardAt = tick.indexOf("guard scenePhase == .active, appState.isUnlocked else {")
        assertTrue(
            "the shared guard must cover BOTH Lever C and the countdown: neither may run in " +
                "`.background` or pre-unlock",
            guardAt >= 0,
        )
        assertTrue("the `.inactive` branch must come before the `.active` guard", inactiveAt in 0 until guardAt)
        val inactiveBranch = tick.substring(inactiveAt, guardAt)
        assertTrue(
            "`.inactive` may only fire an OVERDUE re-auth (no Lever C: no touch can reach the app)",
            inactiveBranch.contains("lockIfDeadlinePassed(includeIdle: false)") &&
                !inactiveBranch.contains("includeIdle: true") &&
                !inactiveBranch.contains("lockAndResetNavigation()"),
        )
        assertTrue(
            "the re-auth deadline must be read as an Optional, so a cleared one is inert",
            tick.contains("if let deadline = reauthDeadlineUptime {"),
        )
        val check = contentView.functionBody("    private func lockIfDeadlinePassed(includeIdle: Bool) -> Bool {")
        val unlockedGuard = check.indexOf("guard appState.isUnlocked else { return false }")
        val reauthAt = check.indexOf("if let deadline = reauthDeadlineUptime, ProcessInfo.processInfo.systemUptime >= deadline {")
        assertTrue("the out-of-tick check must refuse pre-unlock, first", unlockedGuard >= 0 && unlockedGuard < reauthAt)
        assertTrue("the out-of-tick check fires only a PAST-DUE deadline", reauthAt >= 0)
        assertTrue(
            "the out-of-tick Lever-C half stays compiled out of DEBUG, like the tick's",
            Regex("""#if !DEBUG\s*if includeIdle \{""").containsMatchIn(check),
        )
        // An `.inactive`-fired re-auth must lock IN-SCENE (Tor kept for the
        // PIN-screen re-unlock); the plain lock() would stop Tor on `.inactive` and
        // force a relaunch. Pinned in full by IosTorKeepAliveSourceTest.
        assertTrue(
            "the out-of-tick re-auth must lock in-scene, never through the Tor-stopping plain lock",
            check.contains("lockAndResetNavigation(inForegroundScene: true)") &&
                !check.contains("lockAndResetNavigation()"),
        )
    }

    /**
     * iOS: on the way back to `.active` the overdue check runs FIRST, synchronously,
     * before the privacy cover (`privacyCovered()`: shown while scenePhase != .active)
     * lifts — otherwise a past-due re-auth leaves the content readable until the next
     * timer tick.
     */
    @Test
    fun ios_returningToActiveChecksTheDeadlinesBeforeTheCoverLifts() {
        val active = contentView.functionBody("    private func handleSceneBecameActive() {")
        val firstStatement = active.substringAfter("{").trim().lineSequence().first().trim()
        assertTrue(
            "handleSceneBecameActive must open with lockIfDeadlinePassed(includeIdle: true); " +
                "first statement was `$firstStatement`",
            firstStatement == "lockIfDeadlinePassed(includeIdle: true)",
        )
    }

    // -----------------------------------------------------------------------
    // 5. Android-only: performEmergencyWipe must
    //    not leave a stale re-auth deadline armed, lockForReauth must refuse
    //    to fire once the vault is already gone, and the deniable wipe cover
    //    must be a top-level NavHost-gating branch (not a per-screen local a
    //    BACK press can pop past). iOS already has the correct root-level
    //    pattern (`ContentView`'s `wipedThisSession` branch) — Android-only.
    // -----------------------------------------------------------------------

    /**
     * `performEmergencyWipe` is the ONE other function besides `lockSession`
     * that nulls `vault` — before this fix it never cleared the re-auth
     * deadline, so a watchdog tick racing a deniable wipe (the change-PIN
     * abuse cap) could fire `lockForReauth()` against an already-wiped
     * session and replacing the black wipe cover with an interactive PIN screen.
     *
     * Non-vacuousness: deleting the `reauthDeadlineElapsedMs = null` line from
     * `performEmergencyWipe` fails this.
     */
    @Test
    fun performEmergencyWipe_clearsTheReauthDeadline() {
        val fn = viewModel.functionBody("    fun performEmergencyWipe(deniable: Boolean = true) {")
        assertTrue(
            "precondition: performEmergencyWipe must null the vault",
            fn.contains("vault = null"),
        )
        assertTrue(
            "performEmergencyWipe must clear the re-auth deadline — the ONE other function " +
                "that nulls `vault` besides `lockSession`, and the watchdog's re-auth branch " +
                "is gated on this field being non-null. Body was:\n$fn",
            fn.contains("reauthDeadlineElapsedMs = null"),
        )
    }

    /**
     * `wipedThisSession` is the reactive Compose twin of `ProcessWipeCover.armed`
     * ([ProcessWipeCoverTest] pins the latter) — must be armed on the exact
     * same `deniable` gate, or the two flags could disagree about whether the
     * current process is covered.
     */
    @Test
    fun performEmergencyWipe_armsWipedThisSessionOnlyWhenDeniable() {
        val fn = viewModel.functionBody("    fun performEmergencyWipe(deniable: Boolean = true) {")
        assertTrue(
            "performEmergencyWipe must arm _wipedThisSession, gated on `deniable` exactly " +
                "like ProcessWipeCover.arm() above it. Body was:\n$fn",
            fn.contains("if (deniable) _wipedThisSession.value = true"),
        )
    }

    /**
     * The vault-null guard closes 1A-2 at a second layer even if something
     * else ever left a stale deadline armed: a lock with no open vault must be
     * a no-op rather than tearing down / navigating a wiped session.
     *
     * Non-vacuousness: deleting the `if (vault == null) return` line fails this.
     */
    @Test
    fun lockForReauth_refusesToFireWithoutAnOpenVault() {
        val fn = viewModel.functionBody("    fun lockForReauth() {")
        val guardAt = fn.indexOf("if (vault == null) return")
        assertTrue("lockForReauth must guard on a null vault. Body was:\n$fn", guardAt >= 0)
        assertTrue(
            "the null-vault guard must come BEFORE the teardown",
            guardAt < fn.indexOf("lockSession(stopTor = false)"),
        )
    }

    /**
     * MainActivity's watchdog re-auth branch must ALSO gate on an open vault
     * (belt-and-braces alongside the ViewModel-side fixes above): the old
     * comment here claimed "reauthDeadlineElapsedMs is null whenever no vault
     * is open" — exactly the invariant `performEmergencyWipe` used to violate.
     */
    @Test
    fun androidWatchdog_reauthBranchAlsoGatesOnAnOpenVault() {
        val run = activity.functionBody("        override fun run() {")
        val deadlineReadAt = run.indexOf("val reauthDeadline = vm.reauthDeadlineElapsedMs")
        assertTrue("precondition: the re-auth branch must exist", deadlineReadAt >= 0)
        val afterDeadlineRead = run.substring(deadlineReadAt)
        assertTrue(
            "the re-auth branch's own `if` must check vm.vault != null alongside the " +
                "deadline — not rely solely on the deadline being cleared elsewhere. Body " +
                "from the deadline read was:\n$afterDeadlineRead",
            Regex("""if\s*\(reauthDeadline != null && vm\.vault != null\)""")
                .containsMatchIn(afterDeadlineRead),
        )
    }

    /**
     * The deniable wipe cover must be a TOP-LEVEL branch that skips the whole
     * NavHost (removing the back stack entirely), not a per-screen local a
     * BACK press could pop past (the ChangePinScreen / RecoveryEntryScreen
     * pattern this replaces as the sole cover). Also pins that a BackHandler
     * consumes BACK while the cover renders, and that the reauthLocked
     * collector (which navigates the NavHost) refuses to do so while the
     * cover is up.
     */
    @Test
    fun mainActivity_deniableWipeCoverIsATopLevelNavHostGate() {
        val coverAt = activity.indexOf("if (wipedThisSession || ProcessWipeCover.armed) {")
        assertTrue("MainActivity must gate on the LIVE flag OR the process-lifetime one", coverAt >= 0)
        val navHostAt = activity.indexOf("NavHost(")
        assertTrue("precondition: the NavHost must exist", navHostAt >= 0)
        assertTrue(
            "the cover check must be composed BEFORE the NavHost, so a wiped session never " +
                "builds a back stack for BACK to pop into",
            coverAt < navHostAt,
        )

        val coverBranch = activity.functionBody("                if (wipedThisSession || ProcessWipeCover.armed) {")
        assertTrue(
            "the cover branch must install a BackHandler that swallows BACK. Body was:\n$coverBranch",
            coverBranch.contains("BackHandler(enabled = true)"),
        )
        assertTrue(
            "the cover branch must return@RunTheme, skipping the NavHost entirely",
            coverBranch.contains("return@RunTheme"),
        )

        val reauthCollectAt = activity.indexOf("viewModel.reauthLocked.collect")
        assertTrue("precondition: the reauthLocked collector must exist", reauthCollectAt >= 0)
        assertTrue(
            "the cover check must be composed ahead of the reauthLocked collector too",
            coverAt < reauthCollectAt,
        )
        val collectorBody = activity.functionBody("                LaunchedEffect(Unit) {")
        assertTrue(
            "the reauthLocked collector must not navigate the NavHost while the wipe cover " +
                "is up — belt-and-braces alongside lockForReauth's own vault==null guard. " +
                "Body was:\n$collectorBody",
            collectorBody.contains("if (!viewModel.wipedThisSession.value && !ProcessWipeCover.armed) {"),
        )
    }

    // -----------------------------------------------------------------------

    /** See [SpeculativeTorAdoptionSourceTest] — same walk, same fail-loud contract. */
    private fun String.functionBody(signature: String): String {
        val start = indexOf(signature)
        assertTrue("precondition: `$signature` must exist", start >= 0)
        val indent = signature.takeWhile { it == ' ' }
        val closer = "\n$indent}"
        val end = indexOf(closer, start)
        assertTrue("precondition: `$signature` must be closed", end > start)
        return substring(start, end)
    }
}

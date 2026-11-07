package com.vg.run

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Tor's working dirs are PRESERVED across an ordinary stop/start on BOTH
 * platforms (2026-08-01, deliberate tradeoff), and destroyed by every WIPE path
 * on both. This guards the two-sided contract at the source level.
 *
 * WHY THIS TIER. The behaviour itself needs either a live Tor daemon (Android:
 * `TorManager.start()` spawns `libtor.so`; iOS: `tor_main` runs once per process)
 * or a real `Context`, so neither platform's teardown is reachable from this
 * module's plain-JVM `test` source set. The instrumented
 * `TorDataDirPreservationTest` covers Android's real stop-preserves /
 * discard-deletes behaviour against a real Context, and the iOS half is verified
 * by build + e2e — but a SwiftUI/daemon-lifecycle change has no unit tier at all,
 * so a source guard is the only thing that can catch the regression that matters:
 * a future edit "cleaning up" the Tor dir on the ordinary path again, silently
 * restoring the cold bootstrap on every relaunch — or, worse, the mirror image, a
 * wipe path that stops preserving nothing.
 *
 * Same technique and same justification as [ProcessWipeCoverTest].
 */
class TorDataDirPreservationSourceTest {

    private val androidTor: String by lazy {
        File(repoRoot(), "shared/src/androidMain/kotlin/com/vg/run/TorManager.kt").readText()
    }
    private val iosTor: String by lazy {
        File(repoRoot(), "iosApp/iosApp/TorManager.swift").readText()
    }

    /**
     * iOS `start()` together with the working-dir preparation it delegates to
     * (`prepareWorkingDir`), so the positive AND negative `start()` checks below keep
     * covering that block. The ordering guard [iosStart_preparesTheWorkingDirBeforeTorWrites]
     * pins that start() runs it before anything writes into the dir.
     */
    private val iosStartWithWorkingDirPrep: String by lazy {
        iosTor.functionBody("    func start() {") + "\n" +
            iosTor.functionBody("    private func prepareWorkingDir(_ torDir: String) -> String {")
    }
    /** The Tor child's spawn / termination, split out of TorManager.kt. */
    private val androidTorProcess: String by lazy {
        File(repoRoot(), "shared/src/androidMain/kotlin/com/vg/run/TorProcess.kt").readText()
    }

    // -----------------------------------------------------------------------
    // Ordinary stop/start must PRESERVE
    // -----------------------------------------------------------------------

    /**
     * Android: `stop()` must not delete anything. The old implementation called
     * `wipeWorkingDirs()` twice from `stop()` — once eagerly, once after the
     * waitFor — which is exactly what made every relaunch a cold bootstrap.
     */
    @Test
    fun androidStop_deletesNothing() {
        val stop = androidTor.functionBody("    fun stop() {")
        assertFalse(
            "TorManager.stop() is the ORDINARY teardown (background, lock, onCleared) and must " +
                "preserve Tor's guard + consensus state. Wipe paths call stopAndDiscardState().",
            stop.contains("wipeWorkingDirs()") || stop.contains("deleteRecursively()"),
        )
        // The termination stop() delegates to deletes nothing either.
        val terminate = androidTorProcess.functionBody("internal fun terminateTorChild(p: Process?): Boolean {")
        assertFalse(
            "terminateTorChild (stop()'s SIGTERM/SIGKILL step) must delete nothing",
            terminate.contains("wipeWorkingDirs()") || terminate.contains("deleteRecursively()"),
        )
    }

    /**
     * Android: whatever the child termination does — even an interrupt or a throw
     * — stop() still drops the process handle and publishes Idle, and it purges the
     * session ephemera only once the child is confirmed dead (a dying daemon must
     * not re-create the notice log behind the purge). Behaviour pinned by
     * TorChildTerminationTest; this pins stop()'s use of it.
     */
    @Test
    fun androidStop_publishesIdleInFinally_andPurgesOnlyAfterConfirmedDeath() {
        val stop = androidTor.functionBody("    fun stop() {")
        val terminateAt = stop.indexOf("terminateTorChild(")
        val finallyAt = stop.indexOf("finally {")
        val idleAt = stop.indexOf("_state.value = ConnectionState.Idle")
        val nullAt = stop.indexOf("torProcess = null")
        val purgeAt = stop.indexOf("purgeSessionEphemera(dataDir)")
        assertTrue("stop() must terminate the child through terminateTorChild", terminateAt >= 0)
        assertTrue("stop() must publish Idle in a finally after the termination", terminateAt in 0 until finallyAt && finallyAt < idleAt)
        assertTrue("stop() must drop the process handle in that finally", nullAt > finallyAt)
        assertTrue("stop() must still purge the session ephemera, after the termination", purgeAt > terminateAt)
        assertTrue(
            "the purge must be guarded by the child's confirmed death",
            stop.contains("if (childGone) purgeSessionEphemera(dataDir)"),
        )
    }

    /**
     * Android: `start()` must not delete the data dir either — only the two
     * per-session files, via the pure helper the unit tier pins.
     */
    @Test
    fun androidStart_reusesTheDataDirAndOnlyClearsEphemera() {
        val start = androidTor.functionBody("    private suspend fun startAttempt(): Int {")
        // The working-dir phase of startAttempt() is prepareWorkingDirs().
        assertTrue("startAttempt() must ready the working dirs through prepareWorkingDirs()", start.contains("prepareWorkingDirs()"))
        val prepare = androidTor.functionBody("    private fun prepareWorkingDirs(): TorSessionFiles {")
        assertTrue(
            "startAttempt() must clear only the per-session files (torrc + tor.log — a stale " +
                "notice log would hand this run the PREVIOUS run's SOCKS port)",
            prepare.contains("purgeSessionEphemera(dataDir)"),
        )
        for ((name, body) in listOf("startAttempt" to start, "prepareWorkingDirs" to prepare)) {
            assertFalse(
                "$name() must NOT delete the preserved working dirs — that is the whole " +
                    "regression this change removes",
                body.contains("dataDir.deleteRecursively()") || body.contains("cacheDir.deleteRecursively()"),
            )
        }
    }

    /**
     * iOS: `stop(discardingState:)` must DEFAULT to preserving, so a new call site
     * fails toward the ordinary behaviour, and `start()` must not unconditionally
     * remove the dir.
     */
    @Test
    fun iosStopDefaultsToPreserving_andStartDoesNotWipeUnconditionally() {
        assertTrue(
            "iOS stop() must take a discardingState flag defaulting to FALSE (preserve)",
            iosTor.contains("func stop(discardingState: Bool = false)"),
        )
        val start = iosStartWithWorkingDirPrep
        assertTrue(
            "iOS start() may only remove the working dir where it is never reusable (the " +
                "pid-suffixed simulator path) — the device path must be preserved",
            start.contains("if !TorManager.preservesStateAcrossLaunches {"),
        )
    }

    // -----------------------------------------------------------------------
    // Every WIPE path must DESTROY
    // -----------------------------------------------------------------------

    /**
     * The shared Android wipe routine — reached by the emergency wipe, the
     * inactivity dead-man's switch, the launch-time orphan self-heal and the debug
     * test hook — is now the ONLY routine deletion of the Tor trees, so it is
     * load-bearing rather than belt-and-braces.
     */
    @Test
    fun androidWipeRoutine_stillDeletesBothTorTrees() {
        val src = SourcePins.text(SourcePins.WIPE_ROUTINE)
        assertTrue(
            "WipeRoutine must delete filesDir/tor_direct",
            src.contains("""java.io.File(context.filesDir, "tor_direct").deleteRecursively()"""),
        )
        assertTrue(
            "WipeRoutine must delete cacheDir/tor_direct",
            src.contains("""java.io.File(context.cacheDir, "tor_direct").deleteRecursively()"""),
        )
    }

    /**
     * The in-session panic wipe stops a LIVE Tor, so it needs the discarding
     * variant: `WipeRoutine` deleted the trees while that child was still running.
     */
    @Test
    fun androidEmergencyWipe_usesTheDiscardingTeardown() {
        val src = SourcePins.text(SourcePins.RUN_VIEW_MODEL)
        val fn = src.functionBody("    fun performEmergencyWipe(deniable: Boolean = true) {")
        assertTrue(
            "performEmergencyWipe must call torManager.stopAndDiscardState() — a plain stop() " +
                "preserves the working dirs now",
            fn.contains("torManager?.stopAndDiscardState()"),
        )
    }

    /** iOS sibling of the assertion above. */
    @Test
    fun iosEmergencyWipe_usesTheDiscardingTeardown() {
        val src = iosAppStateSources()
        val fn = src.functionBody("    func emergencyWipe(deniable: Bool = true) {")
        assertTrue(
            "AppState.emergencyWipe must call TorManager.shared.stop(discardingState: true)",
            fn.contains("TorManager.shared.stop(discardingState: true)"),
        )
    }

    /**
     * The DEBUG e2e wipe is a wipe path too, and the one most likely to be
     * forgotten: it hand-rolls its deletions instead of routing through
     * `IosAppController.emergencyWipe`. Before preservation it got the Tor dir for
     * free because `start()` wiped; now it must delete it itself, or a "fresh
     * install" test inherits the previous run's guards.
     */
    @Test
    fun iosTestWipe_deletesTheTorDir() {
        val src = File(repoRoot(), "iosApp/iosApp/RunApp.swift").readText()
        val fn = src.functionBody("fileprivate func wipeAllPersistentStateForTest() {")
        assertTrue(
            "wipeAllPersistentStateForTest must remove TorManager.workingDirPath()",
            fn.contains("removeItem(atPath: TorManager.workingDirPath())"),
        )
    }

    /** The Kotlin-side wipe that every iOS launch-time wipe goes through. */
    @Test
    fun iosControllerWipe_stillDeletesTheTorDir() {
        val src = File(repoRoot(), "shared/src/iosMain/kotlin/com/vg/run/IosAppController.kt").readText()
        val fn = src.functionBody("    fun emergencyWipe() {")
        assertTrue(
            "IosAppController.emergencyWipe must still call deleteTorData() — it is the only " +
                "Tor cleanup on the three launch-time wipe paths (reinstall-over-Keychain, " +
                "orphaned credentials, 7-day inactivity), none of which stop a daemon",
            fn.contains("deleteTorData()"),
        )
    }

    // -----------------------------------------------------------------------
    // Hardening of what now persists
    // -----------------------------------------------------------------------

    /**
     * iOS: preserved state must be unreadable at rest — same protection
     * `IosVaultDatabase` gives the vault files.
     */
    @Test
    fun iosPreservedState_isFileProtectedAndBackupExcluded() {
        assertTrue(
            "the Tor working dir must carry NSFileProtectionComplete",
            iosTor.contains("FileProtectionType.complete"),
        )
        assertTrue(
            "the Tor working dir must be excluded from backup",
            iosTor.contains("isExcludedFromBackup = true"),
        )
        assertTrue(
            "protection must be applied in start(), before Tor writes anything (new files " +
                "inherit their directory's class)",
            iosStartWithWorkingDirPrep.contains("applyDataProtection(to: torDir)"),
        )
    }

    /** The prep (incl. applyDataProtection) must run before the torrc write and the Tor thread. */
    @Test
    fun iosStart_preparesTheWorkingDirBeforeTorWrites() {
        val start = iosTor.functionBody("    func start() {")
        val prep = start.indexOf("prepareWorkingDir(torDir)")
        assertTrue("iOS start() must call prepareWorkingDir(torDir)", prep >= 0)
        val config = start.indexOf("makeTorConfiguration(")
        val thread = start.indexOf("TorThread(configuration:")
        assertTrue(
            "prepareWorkingDir must run before the torrc is written and before the Tor thread starts",
            config > prep && thread > prep,
        )
    }

    /**
     * iOS: the atexit backstop must NOT be armed from `start()`. It deletes the
     * working dir as the process's last act, and the exit(0) self-recycle is the
     * single most common relaunch — arming it unconditionally would silently undo
     * preservation on exactly the path it is meant to help.
     */
    @Test
    fun iosExitWipe_isArmedOnlyByDiscardingTeardowns() {
        assertFalse(
            "armExitWipe() must not be armed from start() — the exit(0) self-recycle would " +
                "then wipe the preserved dir on every ordinary relaunch",
            iosStartWithWorkingDirPrep.contains("armExitWipe()"),
        )
        assertTrue(
            "armExitWipe() must still be armed on the discarding teardown, where an un-halted " +
                "tor_main can rewrite the dir after the delete",
            iosTor.functionBody("    func stop(discardingState: Bool = false) {")
                .contains("TorManager.armExitWipe()"),
        )
    }

    // -----------------------------------------------------------------------

    /**
     * The body of the function starting at [signature], up to the first line that
     * closes it at the same indentation. Fails loudly if the signature is gone, so
     * a rename can never turn these guards into vacuous passes.
     */
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

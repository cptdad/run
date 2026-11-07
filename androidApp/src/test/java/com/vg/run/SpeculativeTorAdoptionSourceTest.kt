package com.vg.run

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Guards the Android speculative-Tor-start package: Tor bootstraps CONCURRENTLY
 * with credential entry, and the unlock ADOPTS that live instance instead of
 * destroying it.
 *
 * WHY THIS TIER. Every moving part needs either a real `Context`
 * (`AndroidViewModel`, `TorManager(application)`) or a live Tor daemon
 * (`start()` spawns `libtor.so`), so none of it is reachable from this module's
 * plain-JVM `test` source set and there is no Robolectric here. The properties
 * below are nonetheless the ones a future edit is most likely to break silently,
 * and each of them is a real defect rather than a style rule:
 *
 *  - the speculative start doing anything VAULT-DEPENDENT before there is a
 *    vault (MessageManager, relay checks, control poll, push registration);
 *  - `restartTor` losing `forceFresh`, which would make the ~100 s self-heal AND
 *    the manual Reconnect silently adopt the very session they exist to throw
 *    away — i.e. become no-ops;
 *  - the adopt path re-entering `TorManager.start()` or calling `stop()`, either
 *    of which puts two Tor children on one DataDirectory;
 *  - the pre-unlock window losing its teardown coverage — the whole safety
 *    argument is that the speculative start writes the SAME `torManager` /
 *    `torStartJob` fields `onCleared` and `performEmergencyWipe` already tear
 *    down unconditionally;
 *  - `TorManager`'s internal corrupt-state retry becoming invisible or
 *    non-volatile again, which is what lets the external 100 s timer cancel the
 *    internal recovery just as it starts.
 *
 * Same technique and same justification as [TorDataDirPreservationSourceTest]
 * and [VendorPushOptOutTeardownSourceTest]; bodies are scanned with comments
 * STRIPPED so prose that merely names a call can neither satisfy nor trip a
 * shape guard.
 */
class SpeculativeTorAdoptionSourceTest {

    private val viewModel: String by lazy {
        SourcePins.stripped(SourcePins.RUN_VIEW_MODEL)
    }
    private val torManager: String by lazy {
        stripComments(
            File(repoRoot(), "shared/src/androidMain/kotlin/com/vg/run/TorManager.kt").readText()
        )
    }

    // -----------------------------------------------------------------------
    // 1. The speculative start is ViewModel-scoped and vault-free
    // -----------------------------------------------------------------------

    /**
     * The trigger must be the ViewModel's `init`, never a Composable. The PIN
     * screen recomposes freely, so a `LaunchedEffect`/`remember`-scoped trigger
     * could double-fire and spawn a second Tor child against the same
     * DataDirectory.
     */
    @Test
    fun speculativeStart_firesFromTheViewModelInit_andFromNowhereElse() {
        assertTrue(
            "RunViewModel.init must call startSpeculativeTor()",
            viewModel.functionBody("    init {").contains("startSpeculativeTor()"),
        )
        for (screen in listOf(
            "PinEntryScreen.kt", "MainActivity.kt", "PinSetupScreen.kt", "RecoveryEntryScreen.kt",
            "ContactListScreen.kt", "AddContactScreen.kt",
        )) {
            val src = File(repoRoot(), "androidApp/src/main/java/com/vg/run/$screen").readText()
            assertFalse(
                "$screen must not trigger the speculative Tor start — it is ViewModel-scoped " +
                    "on purpose; a composable-scoped trigger can double-fire on recomposition",
                src.contains("startSpeculativeTor"),
            )
        }
    }

    /**
     * Pre-unlock there is no vault, so nothing vault-dependent may exist. This is
     * the one place in the app that runs before `onVaultOpened`, and every item
     * below would either NPE or leak state that outlives the credential check.
     */
    @Test
    fun speculativeStart_startsTorAndNothingElse() {
        val fn = viewModel.functionBody("    private fun startSpeculativeTor() {")
        for (forbidden in listOf(
            "MessageManager(",
            "startRelayCheck()",
            "startControlPoll()",
            "startUnreadPrime()",
            "refreshPushRegistration",
            "createSessionManagers(",
            "vaultSelector",
        )) {
            assertFalse(
                "startSpeculativeTor must not touch `$forbidden` — it runs BEFORE any vault " +
                    "exists",
                fn.contains(forbidden),
            )
        }
        for (forbidden in listOf("armTorBootstrapWatchdog()", "startRelayStallWatch()")) {
            assertFalse(
                "startSpeculativeTor must not arm `$forbidden` pre-unlock: the stall hint is " +
                    "never rendered on the PIN screen and the self-heal (restartTor) needs the " +
                    "vault. TorManager's own 90s timeout + one-shot retry govern this window.",
                fn.contains(forbidden),
            )
        }
    }

    /**
     * Gated on a build-time predicate (no vault), one-shot, and writing the SAME
     * two fields the unlock path owns — the last of which is the entire reason
     * the existing teardowns cover the new window unchanged.
     */
    @Test
    fun speculativeStart_isGuardedAndWritesTheSharedTorFields() {
        val fn = viewModel.functionBody("    private fun startSpeculativeTor() {")
        assertTrue(
            "the speculative start must be gated on RelayConfig.isTorRequired — a clearnet " +
                "dev/emulator relay must start no Tor at all",
            fn.contains("if (!RelayConfig.isTorRequired) return"),
        )
        assertTrue(
            "it must be one-shot AND must refuse once an unlock already owns torManager",
            fn.contains("if (speculativeTorStarted || torManager != null) return"),
        )
        assertTrue(
            "it must publish into the SHARED torManager field (this is what makes onCleared / " +
                "performEmergencyWipe cover the pre-unlock window with zero changes)",
            fn.contains("torManager = tor"),
        )
        assertTrue(
            "…and into the SHARED torStartJob field, for the same reason",
            fn.contains("torStartJob = viewModelScope.launch"),
        )
    }

    // -----------------------------------------------------------------------
    // 2. Adopt, don't recreate
    // -----------------------------------------------------------------------

    /**
     * The marquee property. The adopt branch may attach a monitor and arm the
     * watchdog; it must NOT stop the instance, construct another one, or call
     * `start()` a second time (TorManager.start is not re-entrant — a second call
     * spawns a second Tor child against the same DataDirectory).
     */
    @Test
    fun adoptBranch_neitherStopsNorRestartsTheLiveInstance() {
        val branch = viewModel.functionBody(
            "        if (!forceFresh && existing != null && torInstanceIsLive(existing)) {"
        )
        assertTrue(
            "the adopt branch must re-anchor the monitor onto the EXISTING instance",
            branch.contains("startTorMonitor(openedVault, existing)"),
        )
        for (forbidden in listOf("stop()", "stopAndDiscardState()", "TorManager(", ".start()")) {
            assertFalse(
                "the adopt branch must not call `$forbidden` — adopting means keeping the live " +
                    "instance and its in-flight start exactly as they are",
                branch.contains(forbidden),
            )
        }
        assertTrue(
            "the adopt branch must return before the fresh-instance path",
            branch.contains("return"),
        )
    }

    /**
     * `Failed` is never adopted, and the internal corrupt-state retry IS — that
     * path publishes `Failed` then `Idle` on its way into its second attempt, so
     * a naive state read would tear the recovery down.
     */
    @Test
    fun liveness_excludesFailed_andIncludesTheInternalRetry() {
        val fn = viewModel.functionBody("    private fun torInstanceIsLive(tor: TorManager): Boolean {")
        assertTrue(
            "an instance inside its own discard-and-retry is LIVE regardless of its last " +
                "published state",
            fn.contains("if (tor.isMidInternalRetry) return true"),
        )
        assertTrue(
            "a Failed instance must never be adopted",
            fn.contains("is TorManager.ConnectionState.Failed -> false"),
        )
        assertTrue(
            "Idle is ambiguous (pre-start vs stopped) and must be resolved by the start job",
            fn.contains("torStartJob?.isActive == true"),
        )
    }

    /**
     * `restartTor` EXISTS to throw the current Tor session away (the ~100 s
     * self-heal and the manual Reconnect). Without `forceFresh` it would take the
     * adopt path and become a silent no-op the moment adoption landed — the
     * sharpest regression this package can produce.
     */
    @Test
    fun restartTor_neverAdopts() {
        val fn = viewModel.functionBody("    private fun restartTor() {")
        assertTrue(
            "restartTor must force a FRESH Tor instance — adopting here would turn both the " +
                "auto self-heal and the manual Reconnect into no-ops",
            fn.contains("connectViaTor(v, forceFresh = true)"),
        )
        assertTrue(
            "connectViaTor's forceFresh must default to false, so the ordinary unlock adopts",
            viewModel.contains(
                "private fun connectViaTor(openedVault: VaultDatabase, forceFresh: Boolean = false)"
            ),
        )
    }

    // -----------------------------------------------------------------------
    // 3. Watchdog re-anchoring
    // -----------------------------------------------------------------------

    /**
     * The re-anchor must be ZERO once Tor is Connected. Without that clause a
     * long, SUCCESSFUL pre-unlock bootstrap would collapse the relay self-heal to
     * its floor and restart a perfectly healthy Tor seconds after unlock — and a
     * much later reachability flap would do the same.
     */
    @Test
    fun reanchoring_onlyCompensatesAnUnfinishedBootstrap() {
        val fn = viewModel.functionBody("    private fun torBootstrapElapsedMs(): Long {")
        assertTrue(
            "a CONNECTED Tor must contribute zero elapsed time — the remaining window is about " +
                "the relay handshake, which only starts when the transport is wired at unlock",
            fn.contains("if (tor.state.value is TorManager.ConnectionState.Connected) return 0L"),
        )
        assertTrue(
            "an instance that has not started yet must contribute zero, so the fresh-instance " +
                "path keeps its full window",
            fn.contains("if (startedAt <= 0L) return 0L"),
        )
        assertTrue(
            "the re-anchored delay must be floored, never zero",
            viewModel.contains("coerceAtLeast(MIN_REANCHORED_WATCHDOG_MS)"),
        )
        assertTrue(
            "the pre-connect bootstrap watchdog must be re-anchored",
            viewModel.functionBody("    private fun armTorBootstrapWatchdog() {")
                .contains("reanchoredDelayMs(TOR_BOOTSTRAP_STALL_MS)"),
        )
        assertTrue(
            "the relay stall watch's restart step must be re-anchored",
            viewModel.functionBody("    private fun startRelayStallWatch() {")
                .contains("reanchoredDelayMs(RELAY_SELF_HEAL_RESTART_MS)"),
        )
    }

    /** The re-anchor is a monotonic clock, never a wall clock a user can move. */
    @Test
    fun reanchoring_usesTheMonotonicClock() {
        assertTrue(
            "TorManager must stamp its start with SystemClock.elapsedRealtime()",
            torManager.functionBody("    suspend fun start(): Int {")
                .contains("startedAtElapsedMs = SystemClock.elapsedRealtime()"),
        )
        assertTrue(
            "the ViewModel must measure elapsed bootstrap against the same monotonic clock",
            viewModel.functionBody("    private fun torBootstrapElapsedMs(): Long {")
                .contains("SystemClock.elapsedRealtime()"),
        )
    }

    // -----------------------------------------------------------------------
    // 4/5. The internal retry is visible, volatile, and deferred to
    // -----------------------------------------------------------------------

    /**
     * P6b. The retry latch is now read from the MAIN thread, so the old
     * "IO-dispatcher only, needs no @Volatile" reasoning no longer holds.
     */
    @Test
    fun internalRetryState_isVolatileAndReadable() {
        assertTrue(
            "purgedForRetry is now externally observable through isMidInternalRetry and must " +
                "be @Volatile",
            torManager.contains("@Volatile private var purgedForRetry = false"),
        )
        assertTrue(
            "the in-flight flag must be @Volatile — it is written on the IO dispatcher and read " +
                "on Main",
            torManager.contains("@Volatile private var midInternalRetry = false"),
        )
        assertTrue(
            "the read-only accessor must exist",
            torManager.contains("val isMidInternalRetry: Boolean get() = midInternalRetry"),
        )
        assertTrue(
            "the start stamp must be @Volatile and externally read-only",
            torManager.contains("var startedAtElapsedMs: Long = 0L") &&
                torManager.contains("private set"),
        )
    }

    /**
     * The flag must cover the DISCARD too — an external restart landing between
     * `stopAndDiscardState()` and the second attempt destroys the working dirs
     * the retry is in the middle of rebuilding — and must be cleared however the
     * attempt resolves, or the self-heal stays disarmed for the session.
     */
    @Test
    fun internalRetryFlag_spansTheDiscardAndAlwaysClears() {
        val fn = torManager.functionBody("    suspend fun start(): Int {")
        val raised = fn.indexOf("midInternalRetry = true")
        val discard = fn.indexOf("stopAndDiscardState()")
        val cleared = fn.indexOf("midInternalRetry = false")
        assertTrue("start() must raise the in-flight retry flag", raised >= 0)
        assertTrue("start() must still discard the corrupt working dirs", discard >= 0)
        assertTrue(
            "the flag must be raised BEFORE the discard — the discard is part of the retry, and " +
                "an external restart landing inside it destroys what the retry is rebuilding",
            raised < discard,
        )
        assertTrue(
            "the flag must be cleared in a `finally`, so a failure or a cancellation cannot " +
                "leave the external self-heal permanently disarmed",
            cleared > discard && fn.contains("finally {"),
        )
    }

    /**
     * P6c. Both external restart paths must stand down while the internal retry
     * is in flight — and must RESCHEDULE rather than drop the intent.
     */
    @Test
    fun externalRestartPaths_deferToTheInternalRetry() {
        val watch = viewModel.functionBody("    private fun startRelayStallWatch() {")
        assertTrue(
            "the ~100s self-heal must not fire while TorManager is already retrying internally",
            watch.contains("if (torManager?.isMidInternalRetry != true) break"),
        )
        assertTrue(
            "…and must RESCHEDULE a full window rather than silently dropping the restart",
            watch.contains("waitMs = RELAY_SELF_HEAL_RESTART_MS"),
        )
        val restart = viewModel.functionBody("    private fun restartTor() {")
        val guard = restart.indexOf("if (torManager?.isMidInternalRetry == true)")
        val teardown = restart.indexOf("messageManager = null")
        assertTrue("restartTor must carry the same guard (backstop for manual Reconnect)", guard >= 0)
        assertTrue("restartTor must still tear the transport down on the non-deferred path", teardown >= 0)
        assertTrue(
            "the deferral must come BEFORE any teardown — a partial teardown that then returns " +
                "would leave the session with no MessageManager and nothing to rebuild it",
            guard < teardown,
        )
    }

    // -----------------------------------------------------------------------
    // 6. The pre-unlock window inherits the existing teardowns
    // -----------------------------------------------------------------------

    /**
     * The entire brick/leak-safety argument for starting Tor before the vault
     * opens: both teardown paths act UNCONDITIONALLY on the two shared fields, so
     * abandoning the PIN screen (onCleared) or exhausting the wrong-credential
     * budget mid-bootstrap (performEmergencyWipe) stops the speculative Tor with
     * no new code.
     *
     * docs/periodic-reauth-design.md §3.4 extracted onCleared's body into
     * `lockSession(stopTor: Boolean)` — the ONE teardown body onCleared
     * (`stopTor = true`) and the new in-process periodic-re-auth lock
     * (`lockForReauth`, `stopTor = false`) now share — so this guard follows the
     * delegation down into `lockSession` rather than reading `onCleared`'s (now
     * one-line) body directly.
     */
    @Test
    fun bothTeardowns_stillCoverTheSharedTorFieldsUnconditionally() {
        val cleared = viewModel.functionBody("    override fun onCleared() {")
        assertTrue(
            "onCleared must delegate to lockSession(stopTor = true) — ONE teardown body — so " +
                "it and lockForReauth's stopTor=false call cannot drift",
            cleared.contains("lockSession(stopTor = true)"),
        )
        val session = viewModel.functionBody("    private fun lockSession(stopTor: Boolean) {")
        assertTrue(
            "lockSession must cancel the in-flight start — it may be the SPECULATIVE one now",
            sessionJobCancelIndex(viewModel, session, "torStartJob") >= 0,
        )
        // Bounded Tor keep-alive (TorKeepAlive.kt, 2026-10-12): the stopTor branch
        // now HANDS a Connected instance to the keeper when MainActivity.onStop
        // armed it, and stops it otherwise. A speculative instance still mid-
        // bootstrap is never Connected, so it is still stopped right here — the
        // keeper refuses it (TorKeepAliveTest.aNotConnectedInstanceIsNeverKept).
        assertTrue(
            "lockSession must stop the Tor instance on the stopTor branch unless the bounded " +
                "keep-alive took it — it may be the SPECULATIVE one now",
            session.contains("if (!TorKeepAliveHolder.parkOnTeardown(tor, connected)) tor.stop()") &&
                session.contains("tor.state.value is TorManager.ConnectionState.Connected"),
        )
        val wipe = viewModel.functionBody("    fun performEmergencyWipe(deniable: Boolean = true) {")
        assertTrue(
            "the emergency wipe must cancel the in-flight start (possibly the speculative one) " +
                "before discarding Tor's state",
            sessionJobCancelIndex(viewModel, wipe, "torStartJob") >= 0,
        )
        assertTrue(
            "the emergency wipe must use the DISCARDING teardown, after the child is confirmed " +
                "dead — a wrong-credential wipe can now land mid speculative bootstrap",
            wipe.contains("torManager?.stopAndDiscardState()"),
        )
        assertFalse(
            "neither teardown may become conditional on a vault being open — the pre-unlock " +
                "window has no vault",
            session.contains("vault ?: return") || wipe.contains("vault ?: return"),
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

package com.vg.run

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Network-restore kick (2026-10-25) — the Android WIRING. The decision itself
 * (baseline, debounce, rate limit) is pinned behaviourally in commonTest
 * (NetworkRestoreKickTest); `RunViewModel` is an `AndroidViewModel`, not
 * constructible at this plain-JVM tier, so its wiring is pinned at source level
 * (comments stripped, same technique as [BackTapLatencySourceTest]):
 *
 *  - the state the callback touches is declared ABOVE `init` (Kotlin runs
 *    property initializers and init blocks in textual order — a field declared
 *    below would still be null when `init` registers the callback);
 *  - the BASELINE is seeded from `activeNetwork` before the callback is
 *    registered (the registration's own initial callback must not kick);
 *  - `onCleared` unregisters it;
 *  - the action is embedded-Tor-only and runs the kick non-cancellably;
 *  - the sweep stands down while an opt-out ladder is active.
 */
class NetworkRestoreHookSourceTest {

    private val vm: String by lazy { read(SourcePins.RUN_VIEW_MODEL) }
    /** The hook (callback, timer, deferral latch) moved here out of RunViewModel (R4). */
    private val monitor: String by lazy { read("androidApp/src/main/java/com/vg/run/NetworkRestoreMonitor.kt") }
    /** The opt-out ladder and the dereg sweep moved here out of RunViewModel. */
    private val pushCoordinator: String by lazy { read(SourcePins.PUSH_REGISTRATION_COORDINATOR) }

    @Test
    fun hookState_isDeclaredAboveInit_andInitRegistersIt() {
        val initAt = vm.indexOf("\n    init {")
        assertTrue("init block must exist", initAt >= 0)
        for (decl in listOf(
            "private val networkRestoreEpoch = MutableStateFlow(0L)",
            "private val networkRestore = NetworkRestoreMonitor(",
        )) {
            val at = vm.indexOf(decl)
            assertTrue("`$decl` must exist", at >= 0)
            assertTrue("`$decl` must be declared ABOVE init (textual init order)", at < initAt)
        }
        // The monitor's own state is constructor-time (class property initializers
        // run before register() can be called).
        for (decl in listOf(
            "private val networkRestoreKick = NetworkRestoreKick()",
            "private var networkCallback:",
            "private var networkRestoreCheckJob:",
        )) {
            assertTrue("NetworkRestoreMonitor must declare `$decl`", monitor.contains(decl))
        }
        val init = vm.functionBody("    init {")
        assertTrue("init must register the hook", init.contains("networkRestore.register()"))
        assertFalse(
            "the hook moved to NetworkRestoreMonitor — no stale copy in RunViewModel",
            vm.contains("registerDefaultNetworkCallback("),
        )
    }

    @Test
    fun baselineIsSeeded_beforeTheCallbackIsRegistered() {
        val body = monitor.functionBody("    fun register() {")
        val seed = body.indexOf("networkRestoreKick.observe(active?.networkHandle?.toString())")
        val reg = body.indexOf("cm.registerDefaultNetworkCallback(cb)")
        assertTrue("baseline seed from activeNetwork must exist. Body:\n$body", seed >= 0)
        assertTrue("registerDefaultNetworkCallback must exist", reg >= 0)
        assertTrue("the baseline must be seeded BEFORE registration", seed < reg)
        assertTrue("onLost must route through observeLost (current network only)", body.contains("networkRestoreKick.observeLost(key)"))
    }

    @Test
    fun onCleared_unregistersTheHook() {
        val body = vm.functionBody("    override fun onCleared() {")
        assertTrue("onCleared must unregister the network callback", body.contains("networkRestore.unregister()"))
        val unreg = monitor.functionBody("    fun unregister() {")
        assertTrue(unreg.contains("unregisterNetworkCallback(cb)"))
    }

    @Test
    fun action_isEmbeddedTorOnly_andTheKickIsNonCancellable() {
        val body = vm.functionBody("    private suspend fun performNetworkRestoreKick() {")
        val scope = body.indexOf("if (externalProxyMode || !RelayConfig.isTorRequired)")
        val kick = body.indexOf("tor.kickForNetworkRestore()")
        assertTrue("scope gate must exist. Body:\n$body", scope >= 0)
        assertTrue("the kick must exist", kick >= 0)
        assertTrue("the scope gate must run BEFORE the kick", scope < kick)
        assertTrue("the ladder wake must be bumped", body.contains("networkRestoreEpoch.update { it + 1 }"))
        val schedule = monitor.functionBody("    private fun scheduleNetworkRestoreCheck(waitMs: Long) {")
        assertTrue(
            "the kick must run NonCancellable (a replaced timer must not cut a SOCKS-port move short)",
            schedule.contains("withContext(NonCancellable) { onRestore() }"),
        )
        assertTrue(
            "the monitor's onRestore must be the ViewModel's performNetworkRestoreKick",
            Regex("""private val networkRestore = NetworkRestoreMonitor\([^)]*\)\s*\{\s*performNetworkRestoreKick\(\)\s*\}""")
                .containsMatchIn(vm),
        )
    }

    @Test
    fun sweep_standsDownWhileAnOptOutLadderIsActive() {
        val body = pushCoordinator.functionBody("    private suspend fun sweepPendingPushDeregistration() {")
        assertFalse(
            "the sweep moved to PushRegistrationCoordinator — no stale copy in RunViewModel",
            vm.contains("fun sweepPendingPushDeregistration("),
        )
        val guard = body.indexOf("if (pushDeregLaddersActive.get() > 0)")
        val pass = body.indexOf("unregisterAllParallelReturningFailures(")
        assertTrue("ladder guard must exist. Body:\n$body", guard >= 0)
        assertTrue("the sweep's pass must be the fail-fast one", pass >= 0)
        assertTrue("the guard must precede the pass", guard < pass)
    }

    // -----------------------------------------------------------------------

    private fun read(relativePath: String): String =
        stripComments(File(repoRoot(), relativePath).readText())

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

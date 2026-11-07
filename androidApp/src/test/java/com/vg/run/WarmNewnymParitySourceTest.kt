package com.vg.run

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Cross-platform guard for the WARM-TRANSPORT NEWNYM rung (2026-10-07). The
 * decision and the budgets are shared commonMain code (pinned by
 * `WarmNewnymRungTest`); what can still drift is the platform glue, which
 * neither a JVM test nor the Swift compiler checks against the other side:
 *  - both ladders must ASK the shared seam (never re-derive the rule),
 *  - both must ask it on the failed-probe path, next to the cold rung,
 *  - both must emit the IDENTICAL connection-log phrase under Code NEWNYM,
 *  - both must spend / retire the shared ledger exactly as the other does,
 *  - the heavy backstops must stay where they were.
 * Bodies are scanned with comments stripped, same technique as
 * [TorNewNymSelfHealSourceTest].
 */
class WarmNewnymParitySourceTest {

    private val viewModel: String by lazy {
        SourcePins.stripped(SourcePins.RUN_VIEW_MODEL)
    }
    private val appState: String by lazy {
        stripComments(iosAppStateSources())
    }

    @Test
    fun bothLaddersAskTheSharedSeam() {
        assertTrue("Android must ask MessageManager.warmNewnymDue with the session ledger",
            viewModel.contains("mgr.warmNewnymDue(warmNewnymLedger)"))
        assertTrue("Android must spend the ledger through the seam after a fire",
            viewModel.contains("mgr.noteWarmNewnymFired(warmNewnymLedger)"))
        assertTrue("Android must retire the run when NEWNYM is unavailable",
            viewModel.contains("warmNewnymLedger.retireRun()"))
        assertTrue("iOS must ask IosAppController.warmNewnymDue",
            appState.contains("controller.warmNewnymDue()"))
        assertTrue("iOS must spend the ledger through the seam after a fire",
            appState.contains("controller.noteWarmNewnymFired()"))
        assertTrue("iOS must retire the run when NEWNYM is unavailable",
            appState.contains("controller.retireWarmNewnymRun()"))
    }

    @Test
    fun bothLaddersEvaluateItOnTheFailedProbePathNextToTheColdRung() {
        assertTrue(viewModel.contains("if (!probe && mgr != null) maybeFireWarmNewnym(mgr)"))
        val iosCall = Regex("""maybeFireEarlyNewnym\(\)\s+maybeFireWarmNewnym\(\)""")
        assertTrue("iOS must call the warm rung right after the cold rung", iosCall.containsMatchIn(appState))
    }

    @Test
    fun theConnectionLogPhraseIsIdenticalOnBothPlatforms() {
        val ktPhrase = "\"relay unreachable - requesting fresh circuits (NEWNYM \$n/\${MessageManager.WARM_NEWNYM_MAX_PER_RUN}, warm)\""
        val swiftPhrase = "\"relay unreachable - requesting fresh circuits (NEWNYM \\(n)/\\(maxFires), warm)\""
        val kt = Regex(Regex.escape(ktPhrase) + """,\s*ConnectionLog\.Code\.NEWNYM""")
        val swift = Regex(Regex.escape(swiftPhrase) + """,\s*code: ConnectionLog\.Code\.newnym""")
        assertTrue("Android phrase/code drifted", kt.containsMatchIn(viewModel))
        assertTrue("iOS phrase/code drifted", swift.containsMatchIn(appState))
        // Same words once the interpolations are normalised.
        val norm = { p: String -> p.replace("\$n", "N").replace("\\(n)", "N")
            .replace("\${MessageManager.WARM_NEWNYM_MAX_PER_RUN}", "M").replace("\\(maxFires)", "M") }
        assertEquals(norm(ktPhrase), norm(swiftPhrase))
        assertTrue("iOS maxFires must be the shared per-run cap",
            appState.contains("let maxFires = Int(controller.warmNewnymMaxPerRun())"))
    }

    @Test
    fun theHeavyBackstopsAreUnchanged() {
        assertTrue(viewModel.contains("private const val RELAY_SELF_HEAL_RESTART_MS = 100_000L"))
        assertTrue(viewModel.contains("private const val RELAY_NEWNYM_MAX_TRIES = 2"))
        assertTrue(appState.contains("private static let stalledStreakThreshold = 24"))
        assertTrue("the stalled backstop must still fire on the unreachable streak while connecting",
            appState.contains("if relayUnreachableStreak >= AppState.stalledStreakThreshold && relayConnectPhase == .connecting {"))
        assertTrue(appState.contains("private static let newnymAfterUnreachableMs: Double = 64_000"))
        assertEquals(2, MessageManager.WARM_NEWNYM_MAX_PER_RUN)
    }
}

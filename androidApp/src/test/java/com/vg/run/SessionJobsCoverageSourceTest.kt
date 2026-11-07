package com.vg.run

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Every coroutine whose lifetime is ONE unlocked session must die with it, on
 * BOTH teardown paths: `lockSession` (the in-process re-auth lock keeps the
 * ViewModel — and `viewModelScope` — alive, so nothing else stops a pre-lock job
 * racing the next session) and `performEmergencyWipe` (the deniable wipe keeps
 * the process alive behind the black cover).
 *
 * The two cancel lists are hand-kept, and they have drifted before:
 * `transportRedriveJob` was on neither (a pending wait survived lockForReauth and
 * fired against the next session's first relay answer and manager), and before
 * that the two move jobs were on neither. This guard makes the drift a test
 * failure:
 *
 *  1. every `Job?` field of RunViewModel and ConnectTelemetryRecorder is
 *     classified as exactly one of SESSION or PROCESS — a new field fails until
 *     someone decides which it is;
 *  2. every SESSION job of RunViewModel is a [SessionJobs] slot
 *     (`by sessionJobs.slot()`), and both teardown paths call
 *     `sessionJobs.cancelAll()` (the recorder's four through its two cancel
 *     helpers), plus the in-flight sends. The SESSION list still names every job
 *     the two old hand lists cancelled, so none can silently drop out;
 *  3. ALL of those cancels, including the Tor monitor/start, the in-flight sends
 *     and the prime cap, run BEFORE the vault is dropped (owner-approved after
 *     the iteration-3 review, R5 section 2 items 1 and 2).
 *
 * PROCESS-scoped: `networkRestoreCheckJob` belongs to the network callback that
 * `init` registers and `onCleared` unregisters — a lock must NOT cancel it, or
 * the opt-out ladder's network-restore wake dies with the first re-auth lock.
 * `lockPolicyBackstopJob` evaluates the lock deadlines for the ViewModel's whole
 * life; a lock that cancelled it would leave the NEXT session without its
 * Activity-independent re-auth / idle backstop.
 *
 * Not a field, deliberately untracked: the push opt-out DELETE ladder holds no
 * Job ("nothing cancels A") — its persisted flag hands any cut-short ladder to the
 * next session's sweep.
 *
 * Comment-stripped source, so prose naming a cancel can neither satisfy nor trip
 * the guard.
 */
class SessionJobsCoverageSourceTest {

    private val viewModel: String by lazy { read("RunViewModel.kt") }
    private val recorder: String by lazy { read("ConnectTelemetryRecorder.kt") }
    /** Owns the process-scoped network-restore timer since the R4 extraction. */
    private val networkMonitor: String by lazy { read("NetworkRestoreMonitor.kt") }

    @Test
    fun everyJobField_isClassifiedExactlyOnce() {
        val declared = (JOB_FIELD.findAll(viewModel) + JOB_FIELD.findAll(recorder) + JOB_FIELD.findAll(networkMonitor))
            .map { it.groupValues[1] }.toList()
        assertEquals("a Job field is declared twice: $declared", declared.size, declared.toSet().size)
        val classified = VM_SESSION_JOBS + RECORDER_SESSION_JOBS + PROCESS_SCOPED_JOBS
        for (job in declared) {
            assertTrue(
                "`$job` is a new Job field: classify it as a SESSION job (and cancel it in " +
                    "lockSession AND performEmergencyWipe) or as PROCESS-scoped, in this test",
                job in classified,
            )
        }
        for (job in classified) {
            assertTrue("`$job` is classified but no longer declared — drop it from the list", job in declared)
        }
    }

    @Test
    fun theRecordersJobsLiveInTheRecorder_andItsCancelHelpersCoverAllFour() {
        for (job in RECORDER_SESSION_JOBS) {
            assertTrue("`$job` must be declared in ConnectTelemetryRecorder", recorder.contains("private var $job: Job?"))
            assertFalse("`$job` must not be re-declared in RunViewModel", viewModel.contains("var $job: Job?"))
        }
        val connect = recorder.functionBody("    fun cancelConnectJobs() {")
        for (job in listOf("connectTelemetryJob", "revealMarkJob", "debugLogConnectJob")) {
            assertTrue("cancelConnectJobs must cancel `$job`. Body was:\n$connect", connect.contains("$job?.cancel()"))
        }
        val boot = recorder.functionBody("    fun cancelBootStamp() {")
        assertTrue("cancelBootStamp must cancel bootStampJob. Body was:\n$boot", boot.contains("bootStampJob?.cancel()"))
    }

    @Test
    fun everyVmSessionJob_isARegistrySlot_andProcessJobsAreNot() {
        for (job in VM_SESSION_JOBS) {
            assertTrue(
                "`$job` must be declared `private var $job: Job? by sessionJobs.slot()` so " +
                    "sessionJobs.cancelAll() reaches it",
                viewModel.contains("private var $job: Job? by sessionJobs.slot()"),
            )
        }
        for (job in PROCESS_SCOPED_JOBS) {
            assertFalse(
                "the process-scoped `$job` must NOT be a session slot — cancelAll() would kill it on every lock",
                viewModel.contains("var $job: Job? by sessionJobs.slot()"),
            )
        }
        val slots = Regex("""var\s+(\w+)\s*:\s*Job\?\s+by\s+sessionJobs\.slot\(\)""")
            .findAll(viewModel).map { it.groupValues[1] }.toSet()
        assertEquals("every registry slot is a classified SESSION job", VM_SESSION_JOBS, slots)
        // The old hand lists, verbatim: none of these may stop being a session job.
        assertTrue(
            "every job the two hand-kept cancel lists named must still be a session slot",
            VM_SESSION_JOBS.containsAll(HAND_LIST_JOBS),
        )
    }

    @Test
    fun bothTeardownPaths_cancelEverySessionJob() {
        for ((name, signature) in TEARDOWNS) {
            val body = viewModel.functionBody(signature)
            for (call in listOf(
                "sessionJobs.cancelAll()",
                "telemetry.cancelConnectJobs()",
                "telemetry.cancelBootStamp()",
                "cancelInFlightSends()",
            )) {
                assertTrue("$name must call `$call`", body.contains(call))
            }
            for (job in PROCESS_SCOPED_JOBS) {
                assertFalse(
                    "$name must NOT cancel the process-scoped `$job`",
                    body.contains("$job?.cancel()"),
                )
            }
        }
    }

    /**
     * Every session cancel runs before the vault handle goes away, so nothing the
     * session started can act on a closing (or erasing) vault. In the wipe that
     * now includes the Tor monitor/start (one O(1) cancel; the start's cancel only
     * destroys a bootstrapping child before WipeRoutine deletes the Tor dirs), the
     * in-flight sends (no backoff retry against an erasing vault) and the prime
     * cap (Main-confined) — owner-approved after the iteration-3 review.
     */
    @Test
    fun everySessionCancel_precedesTheVaultTeardown() {
        for ((name, signature, vaultGone) in listOf(
            Triple("lockSession", TEARDOWNS[0].second, "vault = null"),
            Triple("performEmergencyWipe", TEARDOWNS[1].second, "vault?.close()"),
        )) {
            val body = viewModel.functionBody(signature)
            val goneAt = body.indexOf(vaultGone)
            assertTrue("precondition: $name must contain `$vaultGone`", goneAt >= 0)
            for (call in listOf(
                "sessionJobs.cancelAll()",
                "telemetry.cancelConnectJobs()",
                "telemetry.cancelBootStamp()",
            )) {
                val at = body.indexOf(call)
                assertTrue("$name must call `$call` BEFORE `$vaultGone`", at in 0 until goneAt)
            }
            for (job in VM_SESSION_JOBS) {
                assertFalse(
                    "$name must not cancel `$job` by name any more — a hand-placed cancel is " +
                        "the drift the registry removes (and could sit after the vault close)",
                    body.contains("$job?.cancel()"),
                )
            }
        }
        val wipe = viewModel.functionBody(TEARDOWNS[1].second)
        val sendsAt = wipe.indexOf("cancelInFlightSends()")
        assertTrue(
            "performEmergencyWipe must cancel the in-flight sends BEFORE vault?.close()",
            sendsAt in 0 until wipe.indexOf("vault?.close()"),
        )
        assertTrue(
            "…and therefore before the crypto-erase",
            sendsAt < wipe.indexOf("WipeRoutine.wipePersistentState(app)"),
        )
    }

    /** The registry's own declaration order: declared before any slot property. */
    @Test
    fun theRegistryIsDeclaredBeforeItsFirstSlot() {
        val decl = viewModel.indexOf("private val sessionJobs = SessionJobs()")
        val firstSlot = viewModel.indexOf("by sessionJobs.slot()")
        assertTrue("RunViewModel must declare `private val sessionJobs = SessionJobs()`", decl >= 0)
        assertTrue("…before the first slot (delegates are created at initialization)", decl < firstSlot)
    }

    // -----------------------------------------------------------------------

    private fun read(name: String): String =
        stripComments(File(repoRoot(), "androidApp/src/main/java/com/vg/run/$name").readText())

    private fun String.functionBody(signature: String): String {
        val start = indexOf(signature)
        assertTrue("precondition: `$signature` must exist", start >= 0)
        val open = indexOf('{', start)
        var depth = 0
        var i = open
        while (i < length) {
            when (this[i]) {
                '{' -> depth++
                '}' -> { depth--; if (depth == 0) break }
            }
            i++
        }
        assertTrue("`$signature` must be brace-balanced", depth == 0)
        return substring(open, i + 1)
    }

    private companion object {
        val JOB_FIELD = Regex("""(?:private\s+)?var\s+(\w+)\s*:\s*(?:kotlinx\.coroutines\.)?Job\?""")

        /** The 15 jobs the two hand-kept cancel lists named before the registry. */
        val HAND_LIST_JOBS = setOf(
            "torMonitorJob", "torStartJob", "relayCheckJob", "debugLogPeriodicJob",
            "controlPollJob", "unreadPrimeJob", "relayStallJob", "pushPromptJob",
            "relayWarmupJob", "extProxyConnectJob", "torStallJob", "moveOpJob",
            "movePollJob", "unreadPrimeCapJob", "transportRedriveJob",
        )

        /** RunViewModel's session jobs: registry slots, stopped by `sessionJobs.cancelAll()`. */
        val VM_SESSION_JOBS = HAND_LIST_JOBS + setOf("contactListJob", "consentTickJob")

        /** ConnectTelemetryRecorder's session jobs: cancelled through its two helpers. */
        val RECORDER_SESSION_JOBS = setOf(
            "connectTelemetryJob", "revealMarkJob", "debugLogConnectJob", "bootStampJob",
        )

        /**
         * `networkRestoreCheckJob` lives in NetworkRestoreMonitor (registered in
         * init, unregistered in onCleared); `lockPolicyBackstopJob` in RunViewModel.
         */
        val PROCESS_SCOPED_JOBS = setOf("networkRestoreCheckJob", "lockPolicyBackstopJob")

        val TEARDOWNS = listOf(
            "lockSession" to "    private fun lockSession(stopTor: Boolean) {",
            "performEmergencyWipe" to "    fun performEmergencyWipe(deniable: Boolean = true) {",
        )
    }
}

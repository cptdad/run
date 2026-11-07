package com.vg.run

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * MoveWiringTest — the Android side of "Move to new device" (docs/device-move.md).
 *
 * Two halves:
 *  1. the routing decisions, which are pure functions precisely so they can be
 *     tested without an Activity or a NavController;
 *  2. source-level guards on the [MoveSessionControl] body in RunViewModel,
 *     whose properties are ORDERING and OMISSION ("stops the polls, does NOT
 *     stop Tor") — invisible to a compiler and untestable without a device, but
 *     exactly the kind of thing a later refactor quietly breaks. Same shape as
 *     PushSessionBookkeepingRaceSourceTest / SpeculativeTorAdoptionSourceTest.
 */
class MoveWiringTest {

    // -------------------------------------------------------------------
    // 1. Routing
    // -------------------------------------------------------------------

    @Test
    fun postSetupRoute_sendsAFailedOpenToThePinScreen() {
        // Unchanged pre-move behaviour: the provision guard refused (a vault
        // already exists), so unlock — never setup again, never the import.
        assertEquals("pin", postSetupRoute(openedRealVault = false, hasPendingMoveHandle = false))
        assertEquals("pin", postSetupRoute(openedRealVault = false, hasPendingMoveHandle = true))
    }

    @Test
    fun postSetupRoute_runsTheImportWhenAHandleWasScanned() {
        assertEquals("move_import", postSetupRoute(openedRealVault = true, hasPendingMoveHandle = true))
        assertEquals("contacts", postSetupRoute(openedRealVault = true, hasPendingMoveHandle = false))
    }

    @Test
    fun postUnlock_frozenOutranksEverythingElse() {
        // A frozen vault is the OLD phone of a move: it must not reach the
        // contact list, and not the tier screens either — the only decisions
        // left on it are finish / cancel / wipe.
        for (base in listOf("contacts", "protection_setup", "protection_forced")) {
            assertEquals(
                "a frozen vault must route to the move screen, not $base",
                "move_frozen",
                moveAwarePostUnlockRoute(base, moveFrozen = true, pendingMoveImport = false),
            )
            assertEquals(
                "frozen must win over a pending import too (they cannot both be real)",
                "move_frozen",
                moveAwarePostUnlockRoute(base, moveFrozen = true, pendingMoveImport = true),
            )
        }
    }

    @Test
    fun postUnlock_pendingImportBeatsTheOrdinaryRouteButNotTheTierScreens_whenNeitherApplies() {
        assertEquals(
            "move_import",
            moveAwarePostUnlockRoute("contacts", moveFrozen = false, pendingMoveImport = true),
        )
        // No move in play: the pre-existing route is passed through untouched.
        for (base in listOf("contacts", "protection_setup", "protection_forced")) {
            assertEquals(base, moveAwarePostUnlockRoute(base, moveFrozen = false, pendingMoveImport = false))
        }
    }

    // -------------------------------------------------------------------
    // 2. Session-control guards
    // -------------------------------------------------------------------

    /**
     * The contract MoveManager.takeTransport documents from the other side:
     * quiesce stops the CONTACT-facing loops and leaves Tor + the MessageManager
     * alone, because the transfer inbox still has to be uploaded, peeked,
     * deleted and possibly re-issued over the same SOCKS client.
     */
    @Test
    fun quiesce_stopsEveryPollLoopAndNeverStopsTor() {
        val fn = viewModel.functionBody("    internal suspend fun moveQuiesceSession() {")
        for (job in listOf("controlPollJob", "unreadPrimeJob", "relayCheckJob", "relayStallJob", "torStallJob")) {
            assertTrue(
                "moveQuiesceSession must cancel $job — a single control poll RECEIVES, which " +
                    "advances the Double Ratchet and orphans the new phone's chain. Body was:\n$fn",
                fn.contains("$job?.cancel()"),
            )
        }
        for (forbidden in listOf("torManager?.stop()", "stopAndDiscardState()", "vault?.close()", "messageManager = null")) {
            assertFalse(
                "moveQuiesceSession must NOT `$forbidden`: the export still needs the transport " +
                    "(mint, upload, the 10s peek, the cancel DELETE). Body was:\n$fn",
                fn.contains(forbidden),
            )
        }
    }

    /**
     * The guard has to live in the loop STARTERS, not only at the call site that
     * quiesced: a Tor restart re-enters startTorMonitor's Connected branch, which
     * recreates the MessageManager (the move needs it) and would restart every
     * loop with it.
     */
    @Test
    fun everyPollLoopStarterRefusesWhileTheMoveIsQuiesced() {
        for (starter in listOf(
            "    private fun startControlPoll() {",
            "    private fun startUnreadPrime() {",
            "    private fun startRelayCheck() {",
            "    private fun startRelayStallWatch() {",
        )) {
            val fn = viewModel.functionBody(starter)
            // Either the bare `if (moveQuiesced) return` or a guarded block that
            // returns (startUnreadPrime settles the reveal gate first — 6d997ef3).
            assertTrue(
                "`$starter` must return early while moveQuiesced. Body was:\n$fn",
                Regex("""if \(moveQuiesced\) (return\b|\{[^}]*\breturn\b)""").containsMatchIn(fn),
            )
        }
    }

    /** A frozen session must not re-register the push rows the export deleted. */
    @Test
    fun unlockDoesNotRegisterPushWhileFrozen() {
        val fn = viewModel.functionBody("    fun onVaultOpened(")
        // The freeze decision moved into onVaultOpened's applySessionPolicy() (R5 it3),
        // which runs before the managers and the push registration below.
        val policy = viewModel.functionBody("    private fun applySessionPolicy() {")
        assertTrue(
            "onVaultOpened must come up quiesced for a frozen (old-phone-of-a-move) vault — " +
                "and must ASSIGN the flag, so an unlock after a cancelled move clears it",
            fn.contains("applySessionPolicy()") &&
                policy.contains("val frozenForMove = moveManagerImpl.isFrozen()") &&
                policy.contains("moveQuiesced = frozenForMove"),
        )
        assertTrue(
            "the freeze must be decided BEFORE the unlock-time push registration",
            fn.indexOf("applySessionPolicy()") < fn.indexOf("if (isBackgroundNotificationsEnabled() && !moveQuiesced)"),
        )
        assertTrue(
            "the unlock-time push registration must be gated on the move freeze",
            fn.contains("if (isBackgroundNotificationsEnabled() && !moveQuiesced)"),
        )
    }

    /** Tor Connected + an open vault, or nothing: the clearnet fail-closed rule
     *  applies to the transfer inbox exactly as it does to message traffic. */
    @Test
    fun transport_requiresAnOpenVaultAndAConnectedTor() {
        val fn = viewModel.functionBody("    internal fun moveTransport(): MoveTransport? {")
        assertTrue(fn.contains("if (vault == null) return null"))
        assertTrue(fn.contains("val mm = messageManager ?: return null"))
        assertTrue(
            "a release build with an .onion relay must never hand out a transport without Tor",
            fn.contains("(RelayConfig.isTorRequired || externalProxyMode) && _torState.value !is TorManager.ConnectionState.Connected"),
        )
    }

    /**
     * The 30 s budget MoveManager wraps around the push unregistration can only
     * cut at a suspension point. The work therefore has to run in viewModelScope
     * (NOT as a child of the caller) with a `join()` as the single suspension
     * point — so a timeout abandons the WAIT and the DELETEs still finish.
     */
    @Test
    fun pushUnregisterIsAwaitableAndAbandonable() {
        // The push logic moved into PushRegistrationCoordinator.unregisterForMoveAwaiting
        // (R5 it3 R2); the VM keeps a one-line delegate. The coordinator's `scope` IS
        // the ViewModel's viewModelScope (constructor argument).
        assertTrue(
            "the VM delegate must hand the step to the coordinator",
            viewModel.source.contains("internal suspend fun moveUnregisterPushAwaiting() = push.unregisterForMoveAwaiting()"),
        )
        assertTrue(
            "the coordinator's scope must be viewModelScope",
            viewModel.source.contains("scope = viewModelScope,"),
        )
        val fn = stripComments(java.io.File(repoRoot(), SourcePins.PUSH_REGISTRATION_COORDINATOR).readText())
            .let { src ->
                val start = src.indexOf("    suspend fun unregisterForMoveAwaiting() {")
                assertTrue("precondition: unregisterForMoveAwaiting must exist", start >= 0)
                src.substring(start, src.indexOf("\n    }", start))
            }
        assertTrue(
            "the DELETEs must run in viewModelScope, not as a child of the timed-out caller. " +
                "Body was:\n$fn",
            fn.contains("scope.launch(Dispatchers.IO)"),
        )
        assertTrue("…and the caller must wait on it at a cancellable suspension point", fn.contains("job.join()"))
        assertTrue(
            "the dereg surface must be allPushableInboxes — the same surface registration uses",
            fn.contains("allPushableInboxes(db)"),
        )
        assertTrue(
            "session bookkeeping must go through the shared helper (it bumps the teardown epoch)",
            fn.contains("clearPushSessionBookkeeping()"),
        )
    }

    /**
     * RunViewModel.kt must not contain the token PushSessionBookkeepingRaceSourceTest
     * forbids — which is why the MoveSessionControl implementation lives in its own
     * file. This states the coupling so the next person does not "simplify" it back.
     */
    @Test
    fun theSessionControlOverrideLivesOutsideRunViewModel() {
        assertFalse(
            "RunViewModel.kt must not declare a `suspend fun unregisterPushBestEffort(` — " +
                "PushSessionBookkeepingRaceSourceTest pins that file's unregister as non-suspend " +
                "for the crypto-erase-first wipe path. The MoveSessionControl override belongs " +
                "in MoveSessionControlAndroid.kt.",
            viewModel.source.contains("suspend fun unregisterPushBestEffort("),
        )
        // The wipe-path unregister itself now lives in PushRegistrationCoordinator;
        // the same rule holds there.
        val coordinator = SourcePins.text(SourcePins.PUSH_REGISTRATION_COORDINATOR)
        assertFalse(
            "PushRegistrationCoordinator.kt must not declare a `suspend fun unregisterPushBestEffort(` " +
                "either — the wipe path calls it synchronously",
            coordinator.contains("suspend fun unregisterPushBestEffort("),
        )
        val impl = File(repoRoot(), "androidApp/src/main/java/com/vg/run/MoveSessionControlAndroid.kt").readText()
        for (delegate in listOf(
            "override suspend fun unregisterPushBestEffort() = vm.moveUnregisterPushAwaiting()",
            "override suspend fun quiesce() = vm.moveQuiesceSession()",
            "override suspend fun resume() = vm.moveResumeSession()",
            "override fun transport(): MoveTransport? = vm.moveTransport()",
        )) {
            assertTrue("AndroidMoveSessionControl must delegate: `$delegate`", impl.contains(delegate))
        }
    }

    /** The handle carries a read capability AND the one-time code: RAM only. */
    @Test
    fun theScannedHandleIsNeverPersisted() {
        val src = viewModel.source
        assertTrue(
            "pendingMoveHandle must be a plain RAM field on the ViewModel",
            Regex("""var pendingMoveHandle: MoveHandle\? = null""").containsMatchIn(src),
        )
        for (store in listOf("SecurePrefs.", "putMeta(", "KeyValueStore(")) {
            val esc = Regex.escape(store)
            assertFalse(
                "the pending move handle must never reach `$store`",
                Regex("$esc[^\n]*pendingMoveHandle").containsMatchIn(src) ||
                    Regex("pendingMoveHandle[^\n]*$esc").containsMatchIn(src),
            )
        }
        for (teardown in listOf("    private fun lockSession(", "    fun performEmergencyWipe(")) {
            assertTrue(
                "`$teardown` must drop the RAM-only move secrets",
                viewModel.functionBody(teardown).contains("pendingMoveHandle = null"),
            )
        }
    }

    // -------------------------------------------------------------------

    private class Source(val source: String) {
        /** Brace-walks from [signature] to its matching close (braces included). Fails loudly. */
        fun functionBody(signature: String): String = com.vg.run.functionBody(source, signature)
    }

    private val viewModel: Source by lazy {
        Source(SourcePins.text(SourcePins.RUN_VIEW_MODEL))
    }
}

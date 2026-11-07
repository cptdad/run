package com.vg.run

import kotlinx.coroutines.launch

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// Push deregistration FAIL-FAST (2026-10-25, chain:push Case A): every DELETE
// carries its own 25 s budget, the pass reports exactly the refs that failed, in
// order, and it is not cut short by the caller's cancellation. The concurrency
// itself (all DELETEs in flight at once) is pinned on the JVM —
// androidUnitTest PushDeregParallelismTest.
// Plus the ladder's backoff-or-wake (virtual time).
// ---------------------------------------------------------------------------

private val FF_URL = "http://${"a".repeat(56)}.onion"
private const val FF_CAP = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
private val FF_REFS = listOf("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC", "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD")
    .map { InboundInboxRef(it, FF_CAP) }

/** DELETE-only recorder: [fail] names inbox ids that fail (returned -1) and
 *  [throwFor] ones whose transport throws. */
private fun DeleteRecorder(
    fail: Set<String> = emptySet(),
    throwFor: Set<String> = emptySet(),
    onDelete: () -> Unit = {},
) = FakeRelayHttp.deleteOnly("push deregistration") { r ->
    onDelete()
    val inbox = r.url.substringAfter("/inbox/").substringBefore("/")
    if (inbox in throwFor) throw IllegalStateException("socket closed")
    if (inbox in fail) HttpResult(-1, "timeout", false) else HttpResult(200, null, true)
}

class PushDeregFailFastTest {

    @Test
    fun everyDelete_carriesThe25sBudget() = kotlinx.coroutines.test.runTest {
        val http = DeleteRecorder()
        val failed = PushRegistration.unregisterAllParallelReturningFailures(
            http, FF_URL, FF_REFS, race = null, dispatcher = kotlinx.coroutines.Dispatchers.Default,
        )
        assertTrue(failed.isEmpty())
        assertEquals(3, http.requests.size)
        assertTrue(http.requests.all { it.timeoutSeconds == PushRegistration.DEREG_TIMEOUT_SECONDS })
        assertEquals(25, PushRegistration.DEREG_TIMEOUT_SECONDS)
    }

    @Test
    fun failures_areExactlyTheFailedRefs_inOrder_andAThrowIsAFailure() = kotlinx.coroutines.test.runTest {
        val http = DeleteRecorder(fail = setOf(FF_REFS[2].inboxId), throwFor = setOf(FF_REFS[0].inboxId))
        val failed = PushRegistration.unregisterAllParallelReturningFailures(
            http, FF_URL, FF_REFS, race = null, dispatcher = kotlinx.coroutines.Dispatchers.Default,
        )
        assertEquals(listOf(FF_REFS[0], FF_REFS[2]), failed)
    }

    @Test
    fun emptyRefs_sendNothing() = kotlinx.coroutines.test.runTest {
        val http = DeleteRecorder()
        assertTrue(PushRegistration.unregisterAllParallelReturningFailures(http, FF_URL, emptyList(), race = null).isEmpty())
        assertTrue(http.requests.isEmpty())
    }

    @Test
    fun aCancelledCaller_doesNotCancelThePass() = kotlinx.coroutines.test.runTest {
        // The dd1123a5 lesson: the fan-out must not observe the caller's
        // cancellation. The caller is cancelled from INSIDE the first DELETE
        // (the settings modal closing mid-pass); every DELETE still goes out.
        var callerRef: kotlinx.coroutines.Job? = null
        val http = DeleteRecorder(onDelete = { callerRef?.cancel() })
        val caller = launch(kotlinx.coroutines.Dispatchers.Default, start = kotlinx.coroutines.CoroutineStart.LAZY) {
            PushRegistration.unregisterAllParallelReturningFailures(
                http, FF_URL, FF_REFS, race = null, dispatcher = kotlinx.coroutines.Dispatchers.Default,
            )
        }
        callerRef = caller
        caller.start()
        caller.join()
        assertTrue(caller.isCancelled)
        assertEquals(3, http.requests.size)
    }

    @Test
    fun legacySequentialForm_keepsTheTransportDefault() {
        // Unchanged for its remaining callers/tests: 60 s default budget.
        val http = DeleteRecorder()
        PushRegistration.unregisterAllReturningFailures(http, FF_URL, FF_REFS.take(1), race = null, raceWaitMaxMs = 0)
        assertEquals(DEFAULT_RELAY_HTTP_TIMEOUT_SECONDS, http.requests.single().timeoutSeconds)
    }

    // ---- the ladder's backoff-or-wake ---------------------------------------------

    @Test
    fun backoff_noRestore_sleepsTheFullBackoff() = kotlinx.coroutines.test.runTest {
        val epoch = kotlinx.coroutines.flow.MutableStateFlow(0L)
        assertFalse(PushRegistration.awaitBackoffOrWake(45_000, 0L, epoch))
        assertEquals(45_000L, testScheduler.currentTime)
    }

    @Test
    fun backoff_aRestoreMidBackoff_endsItAtOnce() = kotlinx.coroutines.test.runTest {
        val epoch = kotlinx.coroutines.flow.MutableStateFlow(0L)
        launch {
            kotlinx.coroutines.delay(7_000)
            epoch.value = 1L
        }
        assertTrue(PushRegistration.awaitBackoffOrWake(45_000, 0L, epoch))
        assertEquals(7_000L, testScheduler.currentTime)
    }

    @Test
    fun backoff_aRestoreDuringThePrecedingPass_wakesImmediately() = kotlinx.coroutines.test.runTest {
        // Epoch captured before the pass (0); the restore landed while it ran (1).
        val epoch = kotlinx.coroutines.flow.MutableStateFlow(1L)
        assertTrue(PushRegistration.awaitBackoffOrWake(45_000, 0L, epoch))
        assertEquals(0L, testScheduler.currentTime)
    }

    // ---- the after-restore extension ------------------------------------------------

    @Test
    fun ladder_normalPassesAlwaysRun() {
        assertTrue(PushRegistration.continueDeregLadder(1, 4, 0L, null))
        assertTrue(PushRegistration.continueDeregLadder(3, 4, 0L, null))
    }

    @Test
    fun ladder_noRestore_stopsAfterTheNormalPasses() {
        assertFalse(PushRegistration.continueDeregLadder(4, 4, 1_000_000L, null))
    }

    @Test
    fun ladder_afterARestore_keepsGoingWithinTheGrace() {
        val restore = 100_000L
        assertTrue(PushRegistration.continueDeregLadder(4, 4, restore + 130_000L, restore))
        assertTrue(PushRegistration.continueDeregLadder(6, 4, restore + PushRegistration.DEREG_RESTORE_GRACE_MS - 1, restore))
        assertFalse(PushRegistration.continueDeregLadder(6, 4, restore + PushRegistration.DEREG_RESTORE_GRACE_MS, restore))
    }

    @Test
    fun ladder_neverPastTheHardCap() {
        assertFalse(PushRegistration.continueDeregLadder(PushRegistration.DEREG_MAX_PASSES, 4, 1L, 0L))
    }
}

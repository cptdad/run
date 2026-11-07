package com.vg.run

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for the pure halves of the UnifiedPush toggle-ON handshake
 * (2026-08-11, extracted from `RunViewModel.enableUnifiedPushAwaiting`, now `PushRegistrationCoordinator.enableUnifiedPushAwaiting`, after a
 * hardware run in which the enable failed differently on every attempt):
 *
 *  - [answersHandshakeAttempt] — the attempt-scoping filter that lets the
 *    signal flow carry replay(1) (so a distributor answer landing before the
 *    collector attaches is no longer LOST) without a replayed stale event ever
 *    resolving a LATER attempt with a previous attempt's outcome — the exact
 *    hazard the old `replay = 0` traded the lost-signal bug for;
 *  - [decideUnifiedPushHandshake] — the truth table at the end of the await
 *    (answer × stored-subscription backstop → proceed / which
 *    [PushEnableFailure]).
 *
 * These decide whether the user sees an honest error, a real registration
 * pass, or — the worst outcome, which attempt 2 of the hardware run produced —
 * a success nothing is backing. Keeping them pure and pinned here is the
 * repo's standard answer to logic that otherwise lives untestably inside a
 * device-only coroutine.
 */
class UnifiedPushHandshakeDecisionTest {

    private fun stamped(seq: Long, event: PushEndpointEvent) = StampedPushEndpointEvent(seq, event)

    // -- answersHandshakeAttempt ------------------------------------------

    @Test
    fun freshEventsAfterTheBaseline_answer() {
        assertTrue(answersHandshakeAttempt(stamped(6, PushEndpointEvent.NewEndpoint), baselineSeq = 5))
        assertTrue(answersHandshakeAttempt(stamped(6, PushEndpointEvent.Failed("NETWORK")), baselineSeq = 5))
        assertTrue(answersHandshakeAttempt(stamped(6, PushEndpointEvent.Unregistered), baselineSeq = 5))
    }

    @Test
    fun replayedEventsAtOrBeforeTheBaseline_neverAnswer() {
        // The reason replay used to be 0: a stale replayed outcome must not
        // resolve a later attempt's await. Now the filter enforces it instead.
        assertFalse(answersHandshakeAttempt(stamped(5, PushEndpointEvent.NewEndpoint), baselineSeq = 5))
        assertFalse(answersHandshakeAttempt(stamped(4, PushEndpointEvent.Failed("NETWORK")), baselineSeq = 5))
        assertFalse(answersHandshakeAttempt(stamped(1, PushEndpointEvent.Unregistered), baselineSeq = 5))
    }

    @Test
    fun tempUnavailable_neverAnswers_evenWhenFresh() {
        // "Ask again later" is a non-event; consuming it would end the wait on
        // nothing.
        assertFalse(answersHandshakeAttempt(stamped(6, PushEndpointEvent.TempUnavailable), baselineSeq = 5))
    }

    // -- decideUnifiedPushHandshake ---------------------------------------

    @Test
    fun newEndpointWithStoredSubscription_proceeds() {
        assertEquals(
            UnifiedPushHandshakeOutcome.Proceed,
            decideUnifiedPushHandshake(PushEndpointEvent.NewEndpoint, hasStoredSubscription = true),
        )
    }

    @Test
    fun timeoutWithStoredSubscription_proceeds() {
        // "A timeout is not automatically a failure": the save always precedes
        // the emit, so a stored subscription means the answer landed — just
        // past the deadline, or as an event the baseline filter refused.
        assertEquals(
            UnifiedPushHandshakeOutcome.Proceed,
            decideUnifiedPushHandshake(answer = null, hasStoredSubscription = true),
        )
    }

    @Test
    fun timeoutWithNothingStored_isNoEndpoint() {
        assertEquals(
            UnifiedPushHandshakeOutcome.Fail(PushEnableFailure.NO_ENDPOINT),
            decideUnifiedPushHandshake(answer = null, hasStoredSubscription = false),
        )
    }

    @Test
    fun newEndpointButNothingStored_isNoEndpoint() {
        // The event fired but the save was refused (implausible endpoint,
        // keyless subscription, seal failure) or a teardown raced it: the
        // store is the source of truth, so this must not proceed.
        assertEquals(
            UnifiedPushHandshakeOutcome.Fail(PushEnableFailure.NO_ENDPOINT),
            decideUnifiedPushHandshake(PushEndpointEvent.NewEndpoint, hasStoredSubscription = false),
        )
    }

    @Test
    fun vapidRequired_isItsOwnFailure() {
        // Distinct copy: the fix is a different distributor, not a retry.
        assertEquals(
            UnifiedPushHandshakeOutcome.Fail(PushEnableFailure.VAPID_UNSUPPORTED),
            decideUnifiedPushHandshake(
                PushEndpointEvent.Failed(UnifiedPushEndpointSignal.REASON_VAPID_REQUIRED),
                hasStoredSubscription = false,
            ),
        )
    }

    @Test
    fun otherRefusals_areDistributorRefused() {
        for (reason in listOf("INTERNAL_ERROR", "NETWORK", "ACTION_REQUIRED")) {
            assertEquals(
                UnifiedPushHandshakeOutcome.Fail(PushEnableFailure.DISTRIBUTOR_REFUSED),
                decideUnifiedPushHandshake(PushEndpointEvent.Failed(reason), hasStoredSubscription = false),
            )
        }
    }

    @Test
    fun refusals_failEvenWhenAnOlderSubscriptionIsStored() {
        // The user just watched this enable get refused; success on the back
        // of stale stored state would hide the refusal.
        assertEquals(
            UnifiedPushHandshakeOutcome.Fail(PushEnableFailure.DISTRIBUTOR_REFUSED),
            decideUnifiedPushHandshake(PushEndpointEvent.Failed("NETWORK"), hasStoredSubscription = true),
        )
        assertEquals(
            UnifiedPushHandshakeOutcome.Fail(PushEnableFailure.DISTRIBUTOR_REFUSED),
            decideUnifiedPushHandshake(PushEndpointEvent.Unregistered, hasStoredSubscription = true),
        )
        assertEquals(
            UnifiedPushHandshakeOutcome.Fail(PushEnableFailure.VAPID_UNSUPPORTED),
            decideUnifiedPushHandshake(
                PushEndpointEvent.Failed(UnifiedPushEndpointSignal.REASON_VAPID_REQUIRED),
                hasStoredSubscription = true,
            ),
        )
    }

    @Test
    fun unregistered_isDistributorRefused() {
        assertEquals(
            UnifiedPushHandshakeOutcome.Fail(PushEnableFailure.DISTRIBUTOR_REFUSED),
            decideUnifiedPushHandshake(PushEndpointEvent.Unregistered, hasStoredSubscription = false),
        )
    }

    // -- the signal's not-losable property --------------------------------

    /**
     * The mechanism fix itself: an event emitted with NO collector attached
     * must be retained (replay 1) and stamped past the pre-emission baseline —
     * i.e. a late-attaching collector both SEES it and is ALLOWED to act on
     * it. With the old replay(0) flow the replay cache stayed empty and the
     * event was simply gone, which is what left a toggle attempt waiting out
     * its full timeout for an answer that had already arrived.
     *
     * Uses the process-lifetime singleton, so assertions are RELATIVE to the
     * captured baseline, never absolute.
     */
    @Test
    fun anEventEmittedBeforeTheCollectorAttaches_isReplayedAndAnswerable() {
        val baseline = UnifiedPushEndpointSignal.latestSeq
        UnifiedPushEndpointSignal.emit(PushEndpointEvent.NewEndpoint)

        val replayed = UnifiedPushEndpointSignal.events.replayCache
        assertEquals("replay(1) must retain the un-collected event", 1, replayed.size)
        assertEquals(PushEndpointEvent.NewEndpoint, replayed.single().event)
        assertTrue(
            "the retained event must be stamped past the pre-emission baseline, so the " +
                "attempt that captured that baseline may act on it",
            answersHandshakeAttempt(replayed.single(), baseline),
        )
        assertEquals("latestSeq must advance with the emission", baseline + 1, UnifiedPushEndpointSignal.latestSeq)

        // And an attempt that begins AFTER the emission must refuse the same
        // replayed event — the no-stale-resolution half of the property.
        val laterBaseline = UnifiedPushEndpointSignal.latestSeq
        assertFalse(
            "a later attempt's baseline must exclude the replayed event",
            answersHandshakeAttempt(replayed.single(), laterBaseline),
        )
    }
}

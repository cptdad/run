package com.vg.run

import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow

// ---------------------------------------------------------------------------
// UnifiedPushEndpointSignal — the in-process bridge from RunPushService (an
// Android Service, no ViewModel/vault access) to RunViewModel's toggle-ON
// handshake.
//
// WHY A PROCESS-LIFETIME SINGLETON. UnifiedPush registration is asynchronous
// and out-of-process: `UnifiedPush.register(...)` broadcasts to the distributor
// app, which answers minutes-or-milliseconds later by starting OUR service with
// NEW_ENDPOINT / REGISTRATION_FAILED / TEMP_UNAVAILABLE / UNREGISTERED. The
// service instance that receives it is created by the framework, so there is no
// object graph connecting it to the ViewModel that is sitting on a spinner.
// Same shape as [ProcessWipeLatch]: a plain object, RAM only.
//
// RAM ONLY, DELIBERATELY. Nothing here is persisted — a queued "your push
// registration failed" event surviving on disk would be one more dated artifact
// (and a stale one). The subscription itself lands in [UnifiedPushStateStore];
// this carries only the transient "something happened, look again" edge.
//
// NOTHING SECURITY-BEARING TRAVELS ON IT. [PushEndpointEvent.NewEndpoint] is
// intentionally a bare marker with no payload: the ViewModel re-reads the
// subscription from the store (the single source of truth, which re-validates)
// rather than trusting a value handed across a flow. So an event can at worst
// cause a redundant registration pass.
// ---------------------------------------------------------------------------

/** What the distributor last told us, as observed by [RunPushService]. */
sealed class PushEndpointEvent {
    /** A (new or rotated) endpoint has been persisted to [UnifiedPushStateStore]. */
    object NewEndpoint : PushEndpointEvent()

    /**
     * Registration was refused. [reason] is the connector's own enum name
     * (`INTERNAL_ERROR` / `NETWORK` / `ACTION_REQUIRED` / `VAPID_REQUIRED`) —
     * a bounded vocabulary, never free-form text from another app.
     */
    data class Failed(val reason: String) : PushEndpointEvent()

    /** The distributor is temporarily unable to serve; existing state stands. */
    object TempUnavailable : PushEndpointEvent()

    /** The distributor dropped the registration entirely. */
    object Unregistered : PushEndpointEvent()
}

/**
 * A [PushEndpointEvent] plus its position in the process-lifetime emission
 * order. The sequence number is what lets a toggle attempt keep the flow's
 * replayed value (see the replay note on [UnifiedPushEndpointSignal]) without
 * ever mistaking a PREVIOUS attempt's outcome for its own answer: the attempt
 * captures [UnifiedPushEndpointSignal.latestSeq] as a baseline before it
 * registers, and only an event stamped AFTER that baseline counts.
 */
data class StampedPushEndpointEvent(val seq: Long, val event: PushEndpointEvent)

object UnifiedPushEndpointSignal {

    /** `VAPID_REQUIRED`, as [PushEndpointEvent.Failed.reason] — the one reason
     *  the UI treats specially (this distributor's push server needs VAPID,
     *  which the relay does not mint in v1). */
    const val REASON_VAPID_REQUIRED = "VAPID_REQUIRED"

    private val seq = AtomicLong(0L)

    /**
     * The stamp of the most recently emitted event (0 before the first one).
     * A toggle attempt reads this as its baseline BEFORE calling
     * `UnifiedPush.register`, then accepts only events stamped later — see
     * [answersHandshakeAttempt].
     */
    val latestSeq: Long get() = seq.get()

    // extraBufferCapacity so emitting from the service's main thread never
    // suspends and never drops: tryEmit must succeed even when the ViewModel
    // is not currently collecting (the common case — the app may not even be
    // in the foreground when the distributor answers).
    //
    // replay = 1 (2026-08-11, changed from 0): a distributor's answer is
    // asynchronous and out-of-process, so it CAN land in the gap after a toggle
    // attempt has begun (the persisted level is written, so onNewEndpoint
    // stores the endpoint) but before the attempt's collector attaches. With
    // replay 0 that event was simply GONE — the attempt then sat out its whole
    // timeout waiting for a signal that had already fired, and could only
    // recover through the store-read backstop. The reason replay used to be 0
    // — "a stale event replayed into a LATER toggle attempt would resolve that
    // attempt's await with the previous attempt's outcome" — is real, and is
    // now enforced by the SEQUENCE FILTER instead: every event is stamped
    // ([StampedPushEndpointEvent]), and a collector ignores anything at or
    // before the baseline it captured at attempt start
    // ([answersHandshakeAttempt]), which a replayed stale event by definition
    // is. Losable signal traded for a filtered replay — strictly better.
    private val _events = MutableSharedFlow<StampedPushEndpointEvent>(
        replay = 1,
        extraBufferCapacity = 8,
    )

    val events: SharedFlow<StampedPushEndpointEvent> = _events.asSharedFlow()

    /** Fire-and-forget from any thread; never throws, never blocks. */
    fun emit(event: PushEndpointEvent) {
        _events.tryEmit(StampedPushEndpointEvent(seq.incrementAndGet(), event))
    }
}

/**
 * Whether [stamped] is an answer the toggle-ON handshake that captured
 * [baselineSeq] may act on:
 *  - it must have been emitted AFTER the baseline — a replayed event from
 *    before this attempt (the previous attempt's late answer or failure) must
 *    never resolve this attempt's await;
 *  - [PushEndpointEvent.TempUnavailable] never answers — it explicitly means
 *    "ask again later", so consuming it would end the wait on a non-event.
 *
 * Pure, so the JVM unit tier pins it ([UnifiedPushHandshakeDecisionTest])
 * instead of it living untestably inside the ViewModel's collector lambda.
 */
fun answersHandshakeAttempt(stamped: StampedPushEndpointEvent, baselineSeq: Long): Boolean =
    stamped.seq > baselineSeq && stamped.event !is PushEndpointEvent.TempUnavailable

/**
 * How a completed (or timed-out) toggle-ON handshake await resolves. See
 * [decideUnifiedPushHandshake].
 */
sealed class UnifiedPushHandshakeOutcome {
    /** An endpoint is stored — run the relay registration pass on it. */
    object Proceed : UnifiedPushHandshakeOutcome()

    /** The enable failed before the relay leg; [failure] picks the error copy. */
    data class Fail(val failure: PushEnableFailure) : UnifiedPushHandshakeOutcome()
}

/**
 * The pure decision at the end of the UnifiedPush toggle-ON handshake —
 * extracted from `RunViewModel.enableUnifiedPushAwaiting` so the JVM unit tier
 * can pin every arm ([UnifiedPushHandshakeDecisionTest]) rather than the truth
 * table living only inside a coroutine that needs a device to run.
 *
 * [answer] is the first attempt-scoped event ([answersHandshakeAttempt]) the
 * await saw, or null when it timed out. [hasStoredSubscription] is the
 * store-read backstop, sampled AFTER the await: `UnifiedPushStateStore` is the
 * single source of truth the signal's own kdoc names, and the save always
 * precedes the emit — so a timeout with a stored subscription means the answer
 * arrived (this attempt's own, landed just past the deadline — or one the
 * replay filter deliberately refused) and the registration pass can proceed on
 * what was stored. Only "no answer AND nothing stored" is a failure.
 *
 * A distributor REFUSAL fails the attempt even when an older subscription is
 * still stored: the user just watched this enable get refused, so reporting
 * success on the back of stale state would hide the refusal the distributor
 * wants acted on.
 */
fun decideUnifiedPushHandshake(
    answer: PushEndpointEvent?,
    hasStoredSubscription: Boolean,
): UnifiedPushHandshakeOutcome = when (answer) {
    is PushEndpointEvent.Failed -> UnifiedPushHandshakeOutcome.Fail(
        if (answer.reason == UnifiedPushEndpointSignal.REASON_VAPID_REQUIRED) {
            // The distributor's push server demands a VAPID-signed request. The
            // relay does not mint VAPID keys in v1, so this distributor genuinely
            // cannot be used yet — a distinct, actionable error, not "check your
            // connection".
            PushEnableFailure.VAPID_UNSUPPORTED
        } else {
            PushEnableFailure.DISTRIBUTOR_REFUSED
        }
    )
    PushEndpointEvent.Unregistered ->
        UnifiedPushHandshakeOutcome.Fail(PushEnableFailure.DISTRIBUTOR_REFUSED)
    // NewEndpoint, a timeout (null), or — unreachable through the await, which
    // filters it, but kept total — TempUnavailable: the store decides.
    PushEndpointEvent.NewEndpoint, PushEndpointEvent.TempUnavailable, null ->
        if (hasStoredSubscription) UnifiedPushHandshakeOutcome.Proceed
        else UnifiedPushHandshakeOutcome.Fail(PushEnableFailure.NO_ENDPOINT)
}

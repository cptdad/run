package com.vg.run

import kotlin.concurrent.Volatile
import kotlin.time.TimeSource

/**
 * EARLIER BOUNDED HSDIR HEDGE (2026-10-12, replaces the 4 s descriptor-fetch
 * watchdog + its per-NEWNYM `DescriptorRefetchLedger`). THE decision, shared by
 * both platforms; the platform TorManagers (Android `TorManager.kt`
 * `checkDescriptorHedge`, iOS `TorManager.swift` `checkDescriptorHedge`) own only
 * the single timer and the `HSFETCH` on the COMMAND connection.
 *
 * WHAT IT DOES. The first `HS_DESC REQUESTED` for the relay's onion with no
 * `RECEIVED` yet (a descriptor cache miss) opens an EPISODE. [HSDESC_HEDGE_MS]
 * (1 s) later, if the descriptor still has not arrived, ONE bare
 * `HSFETCH <onion>` (no `SERVER=`) overlaps the still-pending fetch: Tor's
 * control-port path launches a second fetch despite the pending one, and the
 * bare form keeps Tor's own responsible-HSDir selection AND its
 * recently-requested filter (`hs_pick_hsdir` skips HSDirs asked in the last
 * 15 min), so it lands on a different HSDir. An explicit `SERVER=` would bypass
 * that filter — which is why the 1 s hedge is always bare. [HSDESC_SECOND_HEDGE_MS]
 * (4 s) after the first hedge a SECOND re-request may go out; that one keeps the
 * [HsDirLedger] pin (`SERVER=$<last good HSDir>`) exactly where the old 4 s
 * watchdog used it. Measured basis (prod 2026-10-08): a healthy fetch lands in
 * 0.5–1.8 s on device; a stalled one never completes by itself — so the old
 * 4 s wait was pure cost on every stall, and a 1 s overlap costs one extra
 * directory request on a merely-slow fetch, nothing else.
 *
 * BOUNDS (research report 2026-10-11, practice-to-avoid #3 "a renewable bound is
 * not a bound"):
 *  - ≤ [HSDESC_MAX_IN_FLIGHT] (2) fetches in flight. Counted from Tor's own
 *    `HS_DESC REQUESTED`-without-outcome events — never from commands sent —
 *    plus hedges sent less than [HSDESC_HEDGE_CONFIRM_MS] ago whose REQUESTED has
 *    not shown yet. A `250` only acknowledges the command; a hedge Tor never
 *    started stops counting once that window passes (and is logged
 *    [NOT_STARTED_PHRASE]).
 *  - ONE budget of [HSDESC_FETCH_BUDGET] (4) hedge `HSFETCH`es per SESSION — this
 *    object's lifetime, owned by the session owner (Android `RunViewModel`: a new
 *    session = a new instance; iOS `IosAppController`: one per PROCESS, so a
 *    warm-Tor session in a surviving process keeps the spent budget —
 *    `AppState.beginWarmTorSession`; which rule is intended is open, review P7).
 *    Charged for EVERY
 *    hedge command handed to the control channel (including the plain retry after
 *    a rejected pin, and including one Tor then never started). NEVER replenished:
 *    not by an accepted NEWNYM ([noteNewnym]), not by a Tor restart inside the
 *    session ([resetForNewTorProcess]).
 *  - A request with no outcome older than [HSDESC_PRESUMED_DEAD_MS] (4 s) is
 *    presumed dead and stops counting toward that cap, so the 4 s re-request
 *    always fires when the budget allows (physical-phone A/B 2026-10-13).
 *  - Only before the session's first relay answer (`relayAnswered` on [due]).
 *
 * DESCRIPTOR-STAGE EARLY RECOVERY. An episode still open
 * [HSDESC_STAGE_DEADLINE_MS] (10 s) after its first request, with the budget spent
 * or ≥ 2 requests made and none answered, sets [Decision.stageStalled] once per
 * episode; the platform hands it to the session owner, which spends a NEWNYM
 * through the SAME shared gate as the warm-up rotation
 * ([MessageManager.shouldFireWarmupNewnym]: no relay answer yet, the session's
 * shared cap of [MessageManager.EARLY_NEWNYM_MAX_FIRES]) and logs
 * [STAGE_STALLED_PHRASE]. It REPLACES the warm-up's 25 s-evidence NEWNYM for
 * the same stall ([stageNewnymFiredThisSession] → the warm-up retries its GET
 * without a second NEWNYM). The NEWNYM restarts the episode; the budget is not
 * replenished.
 *
 * LATE LOSERS. Once one fetch is `RECEIVED`, later `RECEIVED` / `FAILED` events
 * of the overlapping fetch only decrement the in-flight count: nothing is
 * scheduled, nothing fires, and no rung anywhere reacts to an `HS_DESC FAILED`
 * (it is a panel line only) — so a late loser can never NEWNYM away the winner's
 * circuits or the cached descriptor. A REQUESTED that matches a hedge we sent is
 * that hedge starting, never a fresh cache miss.
 *
 * NO-HEDGE CONTROL for the physical-phone A/B: [setNoHedgeControl] (debug builds only —
 * refused in release) makes [due] send nothing and log [CONTROL_PHRASE] once per
 * session. Android: `--ez TEST_DESCRIPTOR_HEDGE_OFF true` on the TEST_WIPE launch
 * (persisted by the debug TestHooks until the next TEST_WIPE); iOS:
 * `--test-descriptor-hedge-off` (launch args re-apply on every activateApp
 * relaunch of the session). The connect:cycle harness passes both when
 * `WDIO_DESCRIPTOR_HEDGE=off`.
 *
 * IDENTIFIERS: none. The input is an [RelayDescriptorEvent.Action] (the HSDir
 * fingerprint stays in [HsDirLedger]); every phrase is fixed text plus counts.
 *
 * THREAD-SAFE (Android feeds it from the event reader and decides on an IO
 * coroutine; iOS on the main actor).
 */
class DescriptorHedge {

    enum class Stage {
        /** The 1 s hedge: a bare `HSFETCH <onion>`. */
        FIRST,
        /** The re-request 4 s after the first hedge: pinned via [HsDirLedger] when
         *  a good HSDir is known (the old watchdog's fire sequence), else bare. */
        SECOND,
    }

    /**
     * What one [due] call decided. [stage] null = send nothing. [stageStalled] =
     * ask the session owner for a NEWNYM through the shared early-NEWNYM gate
     * (the descriptor-stage early recovery). The other fields only drive the
     * fixed log phrases.
     */
    class Decision internal constructor(
        val stage: Stage?,
        /** Hedges whose REQUESTED never followed within [HSDESC_HEDGE_CONFIRM_MS]. */
        val notStartedCount: Int,
        /** The budget refused a due hedge for the first time this session. */
        val budgetSpentNow: Boolean,
        /** The no-hedge control arm suppressed a due hedge for the first time this session. */
        val controlArmNow: Boolean,
        /** Hedge `HSFETCH`es charged this session, including any [stage] just decided. */
        val spent: Int,
        /** The descriptor episode is still open [HSDESC_STAGE_DEADLINE_MS] after its
         *  first request with the budget spent or ≥ 2 requests outcome-less: the
         *  session owner should request fresh circuits (once per episode). */
        val stageStalled: Boolean,
    ) {
        override fun toString(): String = "Decision($stage, spent=$spent, stageStalled=$stageStalled)"
    }

    private val lock = SyncLock()

    // --- session-scoped: never reset ------------------------------------
    private var spent = 0
    private var budgetSpentLogged = false
    private var controlArmLogged = false
    private var stageNewnymFired = false

    // --- Tor-HS-state-scoped: reset by NEWNYM and by a new Tor process ---
    private var received = false
    /** Times of Tor's `REQUESTED` events with no outcome yet, oldest first. An
     *  entry older than [HSDESC_PRESUMED_DEAD_MS] stays here (it is still a
     *  request "made with no outcome" for the stage deadline) but no longer
     *  counts toward the in-flight cap. */
    private val openRequestedAtMs = ArrayDeque<Long>()
    /** Send times of hedges whose `REQUESTED` has not shown yet, oldest first. */
    private val unconfirmedSentAtMs = ArrayDeque<Long>()
    private var notStartedUnreported = 0
    private var episodeActive = false
    private var episodeStartMs = 0L
    private var stageStallFired = false
    private var hedgesThisEpisode = 0
    private var nextHedgeAtMs: Long? = null

    /** Hedge `HSFETCH`es charged this session (for logs / tests). */
    val spentThisSession: Int get() = lock.withLock { spent }

    /** A descriptor-stage NEWNYM was accepted this session ([noteStageNewnymFired]).
     *  The warm-up rotation reads it: that NEWNYM REPLACES the warm-up's own
     *  25 s-evidence NEWNYM for the same stall, it does not add one. */
    val stageNewnymFiredThisSession: Boolean get() = lock.withLock { stageNewnymFired }

    /** Fetches counted in flight right now: Tor's REQUESTEDs without outcome that
     *  are younger than [HSDESC_PRESUMED_DEAD_MS], plus young unconfirmed hedges. */
    fun inFlight(nowMs: Long): Int = lock.withLock {
        expireUnconfirmed(nowMs)
        liveOpen(nowMs) + unconfirmedSentAtMs.size
    }

    /** Feed EVERY `HS_DESC` REQUESTED / RECEIVED / FAILED of the relay's onion
     *  ([RelayDescriptorWatchdog.parseEvent]), in Tor's order. */
    fun observe(action: RelayDescriptorEvent.Action, nowMs: Long) {
        lock.withLock {
            expireUnconfirmed(nowMs)
            when (action) {
                RelayDescriptorEvent.Action.REQUESTED -> {
                    val liveBefore = liveOpen(nowMs)
                    openRequestedAtMs.addLast(nowMs)
                    if (unconfirmedSentAtMs.isNotEmpty()) {
                        // One of OUR hedges started: it is now counted by its
                        // REQUESTED, and it is never a fresh cache miss.
                        unconfirmedSentAtMs.removeFirst()
                        return
                    }
                    if (received) {
                        // Tor's OWN re-fetch after a RECEIVED (e.g. every intro
                        // point of the cached descriptor failed): a new miss.
                        received = false
                        episodeActive = false
                    }
                    val exhaustedAndIdle = episodeActive && nextHedgeAtMs == null && liveBefore == 0
                    if (!episodeActive || exhaustedAndIdle) startEpisode(nowMs)
                }
                RelayDescriptorEvent.Action.RECEIVED -> {
                    openRequestedAtMs.removeFirstOrNull()
                    // The winner. Anything still in flight is a late loser.
                    received = true
                    episodeActive = false
                    nextHedgeAtMs = null
                }
                RelayDescriptorEvent.Action.FAILED -> {
                    // Which fetch failed is unknown here (the HSDir stays in
                    // HsDirLedger); the YOUNGEST is dropped — a fast FAILED
                    // (NOT_FOUND) is the common case, and the old hung ones are
                    // what the age rule already discounts. A late loser after
                    // RECEIVED changes nothing but the count; before RECEIVED the
                    // episode keeps its schedule (a slot just freed up).
                    openRequestedAtMs.removeLastOrNull()
                }
            }
        }
    }

    /**
     * The timer fired (or an event may have unblocked a deferred hedge). Charges
     * the budget for the [Decision.stage] it returns — the caller MUST then hand
     * that `HSFETCH` to the control channel — and, when [Decision.stageStalled],
     * the caller asks the session owner for a NEWNYM.
     *
     * @param relayAnswered the session's set-once "relay answered" latch OR the
     *   current transport's round-trip latch. Once true nothing ever fires.
     * @param hedgeEnabled false = the no-hedge control arm ([isHedgeEnabled]):
     *   no hedge AND no descriptor-stage NEWNYM (the control has no descriptor-side
     *   intervention at all).
     */
    fun due(nowMs: Long, relayAnswered: Boolean, hedgeEnabled: Boolean): Decision = lock.withLock {
        expireUnconfirmed(nowMs)
        val notStarted = notStartedUnreported
        notStartedUnreported = 0
        var budgetSpentNow = false
        var controlArmNow = false
        var stage: Stage? = null
        val at = nextHedgeAtMs
        if (episodeActive && !received && at != null && nowMs >= at) {
            when {
                relayAnswered -> endSchedule()
                !hedgeEnabled -> {
                    endSchedule()
                    if (!controlArmLogged) { controlArmLogged = true; controlArmNow = true }
                }
                spent !in 0 until HSDESC_FETCH_BUDGET -> {
                    endSchedule()
                    if (!budgetSpentLogged) { budgetSpentLogged = true; budgetSpentNow = true }
                }
                liveOpen(nowMs) + unconfirmedSentAtMs.size >= HSDESC_MAX_IN_FLIGHT -> {
                    // Deferred, not dropped: fires once an outcome, an
                    // unconfirmed hedge's expiry or a request AGING past
                    // HSDESC_PRESUMED_DEAD_MS frees a slot (≤ 4 s by construction).
                }
                else -> {
                    spent++
                    hedgesThisEpisode++
                    unconfirmedSentAtMs.addLast(nowMs)
                    if (hedgesThisEpisode == 1) {
                        stage = Stage.FIRST
                        nextHedgeAtMs = nowMs + HSDESC_SECOND_HEDGE_MS
                    } else {
                        stage = Stage.SECOND
                        nextHedgeAtMs = null
                    }
                }
            }
        }
        var stageStalled = false
        if (stageStallCondition(nowMs)) {
            // Latched whether or not it is acted on, so a refused stall never
            // re-arms a zero-delay check.
            stageStallFired = true
            stageStalled = !relayAnswered && hedgeEnabled
        }
        Decision(stage, notStarted, budgetSpentNow, controlArmNow, spent, stageStalled)
    }

    /**
     * Tor rejected a PINNED [Stage.SECOND] (551/552): may the plain retry go out?
     * It is one more `HSFETCH`, so it is charged like any other; false = the
     * budget is spent and the retry must NOT be sent.
     */
    fun tryChargeRetry(): Boolean = lock.withLock {
        if (spent !in 0 until HSDESC_FETCH_BUDGET) return@withLock false
        spent++
        true
    }

    /**
     * Milliseconds until the platform should call [due] again, or null = wait for
     * the next event. Covers the next hedge (if the in-flight cap blocks it: the
     * moment the oldest live request ages out), every unconfirmed hedge's expiry,
     * and the descriptor-stage deadline.
     */
    fun msUntilNextCheck(nowMs: Long): Long? = lock.withLock {
        expireUnconfirmed(nowMs)
        val candidates = ArrayList<Long>(4)
        val at = nextHedgeAtMs
        if (episodeActive && !received && at != null) {
            if (liveOpen(nowMs) + unconfirmedSentAtMs.size < HSDESC_MAX_IN_FLIGHT) {
                candidates += at
            } else {
                openRequestedAtMs.firstOrNull { nowMs - it < HSDESC_PRESUMED_DEAD_MS }
                    ?.let { candidates += maxOf(at, it + HSDESC_PRESUMED_DEAD_MS) }
            }
        }
        unconfirmedSentAtMs.firstOrNull()?.let { candidates += it + HSDESC_HEDGE_CONFIRM_MS }
        if (episodeActive && !received && !stageStallFired) {
            val deadline = episodeStartMs + HSDESC_STAGE_DEADLINE_MS
            if (nowMs < deadline) candidates += deadline
            else if (stageStallCondition(nowMs)) candidates += nowMs
        }
        candidates.minOrNull()?.let { (it - nowMs).coerceAtLeast(0L) }
    }

    /** The session owner's NEWNYM for a [Decision.stageStalled] was accepted. */
    fun noteStageNewnymFired() {
        lock.withLock { stageNewnymFired = true }
    }

    /**
     * An app-fired `SIGNAL NEWNYM` was accepted: Tor purged its HS client state —
     * pending fetches cancelled, the descriptor cache and the recently-asked-HSDir
     * memory gone. So the in-flight count, the episode (and its stage deadline)
     * and the "received" state start over (the next REQUESTED is a fresh miss and
     * gets its 1 s hedge). The BUDGET IS NOT RESET — that is the bound.
     */
    fun noteNewnym() {
        lock.withLock { resetTorState() }
    }

    /** A fresh Tor child inside the same session (Android's restart rung / corrupt-
     *  state retry): same as [noteNewnym] — the budget is NOT reset. */
    fun resetForNewTorProcess() {
        lock.withLock { resetTorState() }
    }

    private fun startEpisode(nowMs: Long) {
        episodeActive = true
        episodeStartMs = nowMs
        stageStallFired = false
        hedgesThisEpisode = 0
        nextHedgeAtMs = nowMs + HSDESC_HEDGE_MS
    }

    /** Caller holds [lock]. */
    private fun stageStallCondition(nowMs: Long): Boolean =
        episodeActive && !received && !stageStallFired &&
            nowMs - episodeStartMs >= HSDESC_STAGE_DEADLINE_MS &&
            (spent !in 0 until HSDESC_FETCH_BUDGET || openRequestedAtMs.size >= 2)

    /** Caller holds [lock]. */
    private fun liveOpen(nowMs: Long): Int = openRequestedAtMs.count { nowMs - it < HSDESC_PRESUMED_DEAD_MS }

    private fun resetTorState() {
        received = false
        openRequestedAtMs.clear()
        unconfirmedSentAtMs.clear()
        notStartedUnreported = 0
        episodeActive = false
        stageStallFired = false
        hedgesThisEpisode = 0
        nextHedgeAtMs = null
    }

    private fun endSchedule() {
        nextHedgeAtMs = null
    }

    /** Caller holds [lock]. */
    private fun expireUnconfirmed(nowMs: Long) {
        while (unconfirmedSentAtMs.isNotEmpty() &&
            nowMs - unconfirmedSentAtMs.first() >= HSDESC_HEDGE_CONFIRM_MS
        ) {
            unconfirmedSentAtMs.removeFirst()
            notStartedUnreported++
        }
    }

    override fun toString(): String = "DescriptorHedge"

    companion object {
        /** Delay from the descriptor cache miss (first unanswered `HS_DESC
         *  REQUESTED`) to the first, bare hedge. Healthy fetches land in 0.5–1.8 s
         *  on device; a slow-but-healthy one costs one extra directory request. */
        const val HSDESC_HEDGE_MS = 1_000L

        /** Delay from the first hedge to the second re-request (the old watchdog's
         *  4 s stall window, kept as the second stage). */
        const val HSDESC_SECOND_HEDGE_MS = 4_000L

        /** At most this many descriptor fetches in flight at once (Tor's REQUESTED
         *  events without an outcome, plus young unconfirmed hedges). */
        const val HSDESC_MAX_IN_FLIGHT = 2

        /** Hedge `HSFETCH`es per SESSION, never replenished (NEWNYM / Tor restart). */
        const val HSDESC_FETCH_BUDGET = 4

        /** A hedge whose `HS_DESC REQUESTED` has not shown this long after it was
         *  sent is treated as never started: it stops counting in flight (it stays
         *  charged). Tor emits the REQUESTED while handling the command, so a real
         *  start shows within milliseconds. */
        const val HSDESC_HEDGE_CONFIRM_MS = 1_000L

        /** A REQUESTED with no outcome this old is presumed dead: it stops counting
         *  toward [HSDESC_MAX_IN_FLIGHT] (it stays charged / counted for the stage
         *  deadline). Equal to [HSDESC_SECOND_HEDGE_MS], so the second re-request
         *  ALWAYS fires when the budget allows — the 1 s hedge is purely additive
         *  over the old 4 s watchdog (physical-phone A/B 2026-10-13: both fetches hung and
         *  the cap held the re-request for 24 s). */
        const val HSDESC_PRESUMED_DEAD_MS = HSDESC_SECOND_HEDGE_MS

        /** Descriptor-stage early recovery: an episode still open this long after
         *  its first request, with the budget spent or ≥ 2 requests outcome-less,
         *  asks the session for a NEWNYM through the shared early-NEWNYM gate. */
        const val HSDESC_STAGE_DEADLINE_MS = 10_000L

        // --- fixed phrases: the ONLY text either platform writes for the hedge.
        // Uncoded (no ConnectionLog.Code) → never part of the connect telemetry.
        const val NOT_STARTED_PHRASE = "descriptor hedge not started by Tor"
        const val BUDGET_SPENT_PHRASE = "descriptor hedge budget spent"
        const val CONTROL_PHRASE = "descriptor hedge off (control arm)"
        const val STAGE_STALLED_PHRASE = "descriptor stage stalled - requesting fresh circuits"

        /** `descriptor fetch hedged after 1s (1/4)` / `descriptor fetch re-requested
         *  after 4s more (2/4)` — fixed text + counts. */
        fun sentPhrase(stage: Stage, spent: Int): String = when (stage) {
            Stage.FIRST -> "descriptor fetch hedged after ${HSDESC_HEDGE_MS / 1000}s ($spent/$HSDESC_FETCH_BUDGET)"
            Stage.SECOND -> "descriptor fetch re-requested after ${HSDESC_SECOND_HEDGE_MS / 1000}s more ($spent/$HSDESC_FETCH_BUDGET)"
        }

        /** Writes every phrase [d] calls for, except the send line ([logSent],
         *  written once the command is handed over). Platform log + uncoded panel line. */
        fun logDecision(d: Decision) {
            repeat(d.notStartedCount) { line(NOT_STARTED_PHRASE) }
            if (d.controlArmNow) line(CONTROL_PHRASE)
            if (d.budgetSpentNow) line(BUDGET_SPENT_PHRASE)
        }

        fun logSent(stage: Stage, spent: Int) = line(sentPhrase(stage, spent))

        /** Written by the SESSION owner right before its descriptor-stage NEWNYM
         *  (only when the shared gate allowed it). */
        fun logStageStalled() = line(STAGE_STALLED_PHRASE)

        private fun line(text: String) {
            platformLog("TorManager", text)
            ConnectionLog.append(ConnectionLog.Kind.TOR, text)
        }

        @Volatile
        private var noHedgeControl = false

        /**
         * Physical-phone A/B no-hedge control arm. DEBUG BUILDS ONLY: returns false and
         * changes nothing in a release binary, so a shipped app always hedges.
         * Process-wide; read at decision time ([isHedgeEnabled]).
         */
        fun setNoHedgeControl(on: Boolean): Boolean {
            if (!isDebugBuild) return false
            noHedgeControl = on
            return true
        }

        /** False only while the debug-only control arm is set. */
        fun isHedgeEnabled(): Boolean = !noHedgeControl

        private val CLOCK_ORIGIN = TimeSource.Monotonic.markNow()

        /** The one monotonic clock both platforms feed [observe] / [due] with. */
        fun nowMs(): Long = CLOCK_ORIGIN.elapsedNow().inWholeMilliseconds
    }
}

package com.vg.run

/**
 * Paces the PRE-CONNECT progress percent that both platforms show while Tor
 * bootstraps and the first relay round-trip is in flight ("Connecting to Tor…
 * N%" → "Connecting to Relay… N%").
 *
 * WHY (App Store review 2.1, 1.6.15): the main screen sat on "Connecting to
 * Relay… 95%" for a full minute on a cold start and the reviewer read it as
 * "loads indefinitely". Two independent sources of a FROZEN number fed that:
 *
 *  - Tor's own bootstrap parks at 95% (`circuit_create`, first circuit build)
 *    for 1–3 minutes on a cold start, and
 *  - the old relay-phase curve `100 * (1 - e^(-t/7))` was CAPPED at 95, so it
 *    reached its ceiling ~21 s in and then never moved again.
 *
 * A frozen number reads as a hang no matter how honest it is. This pacer makes
 * the displayed value a smoothed, always-moving, never-overclaiming function of
 * the real state:
 *
 *  - MONOTONE within a session (never counts down — only [reset], or a real
 *    regression that means Tor restarted, takes it back).
 *  - BOUNDED CLIMB: at most [CLIMB_STEP] per [CLIMB_INTERVAL_MS] below
 *    [CREEP_FLOOR], so Tor's characteristic bursts (10 → 75 in one log line)
 *    are shown as ~30 s of visible movement instead of one jump followed by a
 *    long freeze.
 *  - IDLE CREEP (phase one): if the real value STOPS RISING for
 *    [IDLE_CREEP_AFTER_MS] once the display has caught up to it, the display
 *    creeps +1 on the same doubling schedule (first after
 *    [IDLE_CREEP_FIRST_MS], then 12 s, 24 s, 48 s …) up to
 *    `real + `[IDLE_CREEP_ROOM],
 *    hard-capped at [IDLE_CREEP_CEILING] so it can never enter the phase-two
 *    band or overtake a real jump. This is what keeps the number alive through
 *    Tor's `circuit_create` hang at 95% (which, scaled, is a parked 66). Any
 *    real rise wins immediately: the bounded climb resumes from wherever the
 *    creep had got to.
 *  - CREEP: once the real value reaches [CREEP_FLOOR] (i.e. Tor is connected
 *    and we are waiting on the relay's first answer) it creeps toward
 *    [CREEP_CEILING] on a GEOMETRIC schedule — the first +1 after
 *    [CREEP_FIRST_MS], and every further +1 takes TWICE as long as the one
 *    before (4, 8, 16, 32, 64, 128, 256, 512, 1024 s). So 93 lands at ~30 s,
 *    94 at 1 min, 96 at ~4 min, 97 at ~8.5 min, 98 at 17 min and 99 only at
 *    ~34 min. Doubling (rather than a fixed cadence) is what makes "parked"
 *    unreachable in practice: the number is always still moving on the
 *    timescale the user has been waiting, yet it can never run out of room.
 *    It NEVER reaches 100 on its own — 100 means "done", and only
 *    [observe]`(done = true)` sets it.
 *
 * Pure and clock-injected so the schedule is unit-testable without sleeping
 * ([BootstrapProgressPacerTest]); no coroutines, no platform types. Call
 * [observe] on a 1 Hz UI tick and render [displayed].
 *
 * Both platforms use THIS class (Android: ContactListScreen / AddContactScreen;
 * iOS: ContactListView / AddContactView via the shared framework) so the two
 * can't drift the way the two hand-mirrored `relayPhasePercent` copies could.
 * Label selection (Tor phase vs Relay phase) stays in the UI layer and is
 * unchanged — only the NUMBER comes from here.
 */
class BootstrapProgressPacer(private val nowMs: () -> Long) {

    private var value: Int = 0
    /** Last real target seen; a strict drop means a NEW bootstrap session. */
    private var lastReal: Int = 0
    private var finished: Boolean = false
    /** Anchor for the bounded climb; advanced in whole [CLIMB_INTERVAL_MS] units. */
    private var climbAnchorMs: Long = 0
    /** Anchor for the creep schedule; advanced by the interval actually spent. */
    private var creepAnchorMs: Long = 0
    /** Last time the REAL target rose — the idle creep's trigger. */
    private var lastRealRiseMs: Long = 0
    /** Anchor for the phase-one idle creep; refreshed while it doesn't apply. */
    private var idleCreepAnchorMs: Long = 0
    /** Steps taken in the CURRENT idle episode — the doubling exponent. */
    private var idleCreepSteps: Int = 0
    private var started: Boolean = false

    /**
     * Feed the pacer the REAL state. Call once per UI tick (1 Hz).
     *
     * [realPercent] is the honest target, already mapped into this pacer's
     * scale by [realTarget]: 0…[TOR_PHASE_CEILING] while Tor bootstraps,
     * [CREEP_FLOOR] once Tor is connected and only the relay answer is
     * missing. [done] is the real completion signal (the relay answered / the
     * mint landed) and is the ONLY thing that produces 100.
     */
    fun observe(realPercent: Int, done: Boolean = realPercent >= 100) {
        val now = nowMs()
        if (!started) {
            started = true
            climbAnchorMs = now
            creepAnchorMs = now
            lastRealRiseMs = now
            idleCreepAnchorMs = now
        }
        if (done) {
            finished = true
            value = 100
            lastReal = 100
            climbAnchorMs = now
            creepAnchorMs = now
            lastRealRiseMs = now
            idleCreepAnchorMs = now
            idleCreepSteps = 0
            return
        }
        val real = realPercent.coerceIn(0, CREEP_CEILING)
        // A strict regression means a NEW session (Tor restarted, or the relay
        // went unreachable again after we'd snapped to 100) — start over rather
        // than freezing at a stale high-water mark for the rest of the process.
        if (finished || real < lastReal) {
            reset()
            started = true
            climbAnchorMs = now
            creepAnchorMs = now
            lastRealRiseMs = now
            idleCreepAnchorMs = now
        }
        if (real > lastReal) {
            // A fresh idle episode: the doubling starts over from the first step.
            lastRealRiseMs = now
            idleCreepSteps = 0
        }
        lastReal = real

        // --- bounded climb, capped by the honest value (and by CREEP_FLOOR) ---
        val climbCap = if (real < CREEP_FLOOR) real else CREEP_FLOOR
        // Whether the climb STARTED this tick below the creep floor: if it
        // crosses into the creep band right now, the creep clock must start
        // from this tick, not from the previous one (a 1 s head start on the
        // first creep step is a small lie about when we reached 90).
        val crossedIntoCreepThisTick = value < CREEP_FLOOR
        if (value >= climbCap) {
            // Capped: keep the anchor fresh so a later rise in `real` doesn't
            // cash in a huge backlog of "unused" ticks as one visible jump.
            climbAnchorMs = now
        } else {
            val steps = ((now - climbAnchorMs) / CLIMB_INTERVAL_MS).toInt()
            if (steps > 0) {
                value = minOf(value + steps * CLIMB_STEP, climbCap)
                climbAnchorMs += steps * CLIMB_INTERVAL_MS
            }
        }

        // --- phase-one idle creep: the number must never stand still ---
        // Tor's bootstrap hangs at 95% (circuit_create) for 1-3 minutes on a
        // cold start, and a display that is honestly parked at the real value
        // is STILL a frozen number to the person holding the phone. So once the
        // display has caught up and the real value has stopped rising, inch
        // forward — but only into a small, bounded lead ([IDLE_CREEP_ROOM]),
        // never into the phase-two band ([IDLE_CREEP_CEILING] < [CREEP_FLOOR]).
        val idleCeiling = minOf(real + IDLE_CREEP_ROOM, IDLE_CREEP_CEILING)
        if (real >= CREEP_FLOOR || value < climbCap ||
            now - lastRealRiseMs < IDLE_CREEP_AFTER_MS || value >= idleCeiling
        ) {
            idleCreepAnchorMs = now
        } else {
            while (value < idleCeiling) {
                val interval = idleCreepIntervalMs(idleCreepSteps)
                if (now - idleCreepAnchorMs < interval) break
                value += 1
                idleCreepSteps += 1
                idleCreepAnchorMs += interval
            }
        }

        // --- decelerating creep, only once the REAL state says "almost there" ---
        if (real < CREEP_FLOOR || value < CREEP_FLOOR || crossedIntoCreepThisTick) {
            creepAnchorMs = now
        } else {
            var anchor = creepAnchorMs
            while (value < CREEP_CEILING) {
                val interval = creepIntervalMs(value)
                if (now - anchor < interval) break
                value += 1
                anchor += interval
            }
            creepAnchorMs = anchor
        }
    }

    /** The percent to render. 0…99 until [observe] is told `done`, then 100. */
    fun displayed(): Int = value

    /** Forget everything — a new Tor session starts the display back at 0. */
    fun reset() {
        value = 0
        lastReal = 0
        finished = false
        started = false
        climbAnchorMs = 0
        creepAnchorMs = 0
        lastRealRiseMs = 0
        idleCreepAnchorMs = 0
        idleCreepSteps = 0
    }

    companion object {
        /**
         * Ceiling for phase one. Tor's raw 0-100 bootstrap is squeezed into
         * 0…70 so that (a) the long 95% circuit-build park displays as a much
         * less "why isn't it finished" 66%, and (b) there is real headroom left
         * for phase two — the relay round-trip that still has to happen after
         * Tor says 100.
         */
        const val TOR_PHASE_CEILING = 70

        /** Phase two's honest target: Tor is up, only the relay answer is missing. */
        const val CREEP_FLOOR = 90

        /** The creep's hard ceiling. Only a real `done` is allowed to show 100. */
        const val CREEP_CEILING = 99

        const val CLIMB_STEP = 2
        const val CLIMB_INTERVAL_MS = 1_000L

        /** Phase-one idle creep: how long the real value must stand still first. */
        const val IDLE_CREEP_AFTER_MS = 5_000L
        /** First idle-creep step; every later one takes twice as long. */
        const val IDLE_CREEP_FIRST_MS = 6_000L
        /** How far the idle creep may run AHEAD of the real value. */
        const val IDLE_CREEP_ROOM = 12
        /** Hard cap — must stay below [CREEP_FLOOR] so the two creeps can't collide. */
        const val IDLE_CREEP_CEILING = 85

        /** First relay-phase creep step; every later one takes twice as long. */
        const val CREEP_FIRST_MS = 4_000L

        /**
         * Map the real transport state onto this pacer's scale. Shared by both
         * platforms and both pre-connect screens so phase one and phase two are
         * ONE monotone run of numbers instead of two 0→100 ramps.
         */
        fun realTarget(torConnected: Boolean, torPercent: Int): Int =
            if (torConnected) CREEP_FLOOR
            else torPercent.coerceIn(0, 100) * TOR_PHASE_CEILING / 100

        /**
         * Interval before the NEXT relay-phase creep step, given the currently
         * shown value: [CREEP_FIRST_MS] doubled once per step already taken
         * (the step index IS `displayed - CREEP_FLOOR`, since every step is +1).
         */
        fun creepIntervalMs(displayed: Int): Long =
            CREEP_FIRST_MS shl (displayed - CREEP_FLOOR).coerceIn(0, 20)

        /** Same doubling for the phase-one idle creep, by step index. */
        fun idleCreepIntervalMs(stepsTaken: Int): Long =
            IDLE_CREEP_FIRST_MS shl stepsTaken.coerceIn(0, 20)
    }
}

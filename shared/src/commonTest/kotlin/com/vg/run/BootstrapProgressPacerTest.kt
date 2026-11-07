package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Pins the pre-connect percent pacing for BOTH platforms (Android's
 * ContactListScreen / AddContactScreen and iOS's ContactListView /
 * AddContactView all render [BootstrapProgressPacer.displayed]).
 *
 * The defect these lock down: App Store review 2.1 on 1.6.15 read a percent
 * that sat perfectly still at 95 for a minute as "loads indefinitely". So the
 * number must keep moving while the real state doesn't, must never jump, and
 * must never claim 100 before the connection actually exists.
 */
class BootstrapProgressPacerTest {

    private var clock = 0L
    private fun pacer(): BootstrapProgressPacer {
        clock = 0
        return BootstrapProgressPacer { clock }
    }

    /** One 1 Hz UI tick. */
    private fun BootstrapProgressPacer.tick(real: Int, done: Boolean = false): Int {
        clock += 1_000
        observe(real, done)
        return displayed()
    }

    private fun BootstrapProgressPacer.tickFor(seconds: Int, real: Int, done: Boolean = false): Int {
        repeat(seconds) { tick(real, done) }
        return displayed()
    }

    /** Ticks until [target] is displayed; returns the clock at that moment. */
    private fun BootstrapProgressPacer.climbTo(real: Int, target: Int): Long {
        var guard = 0
        while (displayed() < target) {
            tick(real)
            // 99 is ~34 simulated minutes away on the doubling schedule.
            check(guard++ < 5_000) { "never reached $target (stuck at ${displayed()})" }
        }
        return clock
    }

    private val floor = BootstrapProgressPacer.CREEP_FLOOR      // 90
    private val ceiling = BootstrapProgressPacer.CREEP_CEILING  // 99

    // ---------------------------------------------------------------- climb

    @Test
    fun climbsAtMostTwoPerTickAndNeverJumps() {
        val p = pacer()
        // Tor bursts 10% → 75% in a single log line; the display must spread it.
        val start = BootstrapProgressPacer.realTarget(torConnected = false, torPercent = 10)
        // 5 ticks: caught up, and still inside the idle-creep grace window.
        p.tickFor(5, start)
        assertEquals(start, p.displayed(), "should have caught up to the low real value")

        val burst = BootstrapProgressPacer.realTarget(torConnected = false, torPercent = 75)
        var prev = p.displayed()
        var ticks = 0
        while (p.displayed() < burst && ticks < 200) {
            val now = p.tick(burst)
            assertTrue(now - prev <= BootstrapProgressPacer.CLIMB_STEP, "jumped $prev -> $now in one tick")
            assertTrue(now >= prev, "went backwards $prev -> $now")
            prev = now
            ticks++
        }
        assertEquals(burst, p.displayed())
        // ~23 ticks at +2/s for a 45-point gap: half a minute of visible
        // movement, not one instant jump followed by a long freeze.
        assertTrue(ticks in 20..30, "burst shown over $ticks ticks, expected ~23")
    }

    @Test
    fun aParkedPhaseOneKeepsMovingInsteadOfFreezing() {
        // Tor hanging at 95% (circuit_create) is real target 66 — the exact
        // shape that used to freeze the display. It must keep inching.
        val p = pacer()
        val real = BootstrapProgressPacer.realTarget(torConnected = false, torPercent = 95) // 66
        val caughtUpAt = p.climbTo(real, real)
        assertEquals(66, p.displayed())
        // Same doubling as the relay phase: 6 s, 12 s, 24 s, 48 s …
        assertEquals(67, p.tickFor(6, real))
        assertEquals(68, p.tickFor(12, real))
        assertEquals(69, p.tickFor(24, real))
        assertEquals(caughtUpAt + 42_000, clock)
        // Ten minutes into a hung bootstrap it is still moving, and still
        // honest (a bounded lead over the real value).
        val atTenMin = p.tickFor(10 * 60, real)
        assertTrue(atTenMin in 70..78, "still alive but bounded, was $atTenMin")
    }

    @Test
    fun theIdleCreepNeverRunsIntoThePhaseTwoBand() {
        val p = pacer()
        // A real value high enough that real + room would overshoot the cap.
        val real = 80
        p.climbTo(real, real)
        repeat(600) {
            p.tick(real)
            assertTrue(
                p.displayed() <= BootstrapProgressPacer.IDLE_CREEP_CEILING,
                "idle creep reached ${p.displayed()}, above its cap",
            )
        }
        assertEquals(BootstrapProgressPacer.IDLE_CREEP_CEILING, p.displayed())
        assertTrue(BootstrapProgressPacer.IDLE_CREEP_CEILING < floor, "the two creeps must not collide")
    }

    @Test
    fun aRealRiseDuringTheIdleCreepResumesTheNormalSchedule() {
        val p = pacer()
        val parked = BootstrapProgressPacer.realTarget(torConnected = false, torPercent = 95) // 66
        p.climbTo(parked, parked)
        val crept = p.tickFor(30, parked)
        assertTrue(crept in 67..78, "idle creep should have moved, was $crept")
        // Tor connects: the bounded climb takes over again FROM the crept value
        // (never backwards), at +2/tick, and hands off to the phase-two creep.
        var prev = crept
        repeat(10) {
            val now = p.tick(floor)
            assertTrue(now >= prev && now - prev <= BootstrapProgressPacer.CLIMB_STEP, "$prev -> $now")
            prev = now
        }
        // +2/tick, clamped by the phase-two target it is now climbing toward.
        assertEquals(minOf(crept + 2 * 10, floor), p.displayed())
        p.climbTo(floor, ceiling)
        assertEquals(99, p.displayed())
    }

    @Test
    fun theIdleCreepNeverStartsBeforeTheRealValueHasStoodStill() {
        val p = pacer()
        // Real rises every 3 s: never idle long enough, so the display stays
        // honest (never ahead of the real value).
        for (tor in 0..60 step 5) {
            val real = BootstrapProgressPacer.realTarget(false, tor)
            repeat(3) {
                p.tick(real)
                assertTrue(p.displayed() <= real, "displayed ${p.displayed()} > real $real")
            }
        }
    }

    @Test
    fun startsAtZeroAndIsMonotoneAcrossTheWholeBootstrap() {
        val p = pacer()
        assertEquals(0, p.displayed())
        var prev = 0
        for (torPercent in listOf(0, 5, 10, 14, 15, 20, 25, 30, 40, 45, 50, 75, 90, 95)) {
            repeat(5) {
                val now = p.tick(BootstrapProgressPacer.realTarget(false, torPercent))
                assertTrue(now >= prev, "not monotone: $prev -> $now")
                prev = now
            }
        }
        // Phase two: Tor connected, relay still silent — the SAME run of
        // numbers continues upward, it does not restart at 0.
        repeat(120) {
            val now = p.tick(BootstrapProgressPacer.realTarget(true, 100))
            assertTrue(now >= prev, "not monotone across the phase switch: $prev -> $now")
            prev = now
        }
        // Two minutes in it is well into the relay-phase creep (which needs
        // ~34 min to reach 99) and has never gone backwards.
        assertTrue(p.displayed() in floor..ceiling, "phase two should be creeping, was ${p.displayed()}")
    }

    // ---------------------------------------------------------------- creep

    @Test
    fun creepsPast95WithNoRealUpdateAtAll() {
        val p = pacer()
        val at90 = p.climbTo(floor, floor)
        assertEquals(90, p.displayed())

        // Geometric: 4 s, then 8, 16, 32, 64 … each step twice the last.
        assertEquals(91, p.tickFor(4, floor))
        assertEquals(92, p.tickFor(8, floor))
        assertEquals(93, p.tickFor(16, floor))
        assertEquals(94, p.tickFor(32, floor))
        assertEquals(95, p.tickFor(64, floor))
        assertEquals(at90 + 124_000, clock)
    }

    @Test
    fun afterFiveMinutesItIsStillBelow98AndStillMoving() {
        // The user-visible contract: a realistic wait never finds the number
        // parked — it is always still below the ceiling AND has moved recently.
        val p = pacer()
        p.climbTo(floor, floor)
        var prev = p.displayed()
        var lastChangeAt = clock
        repeat(5 * 60) {
            p.tick(floor)
            if (p.displayed() != prev) {
                prev = p.displayed()
                lastChangeAt = clock
            }
        }
        assertTrue(p.displayed() <= 97, "5 min in it should still be climbing, was ${p.displayed()}")
        assertTrue(
            clock - lastChangeAt <= 3 * 60_000,
            "nothing moved for ${(clock - lastChangeAt) / 1000} s at the 5-minute mark",
        )
    }

    @Test
    fun doesNotReach99BeforeAboutHalfAnHour() {
        val p = pacer()
        p.climbTo(floor, floor)
        p.tickFor(25 * 60, floor)
        assertTrue(p.displayed() < ceiling, "reached the ceiling after only 25 min: ${p.displayed()}")
        // …and it does get there eventually (~34 min), without ever passing it.
        p.tickFor(15 * 60, floor)
        assertEquals(99, p.displayed())
    }

    @Test
    fun holdsAt99AndNeverClaims100BeforeDone() {
        val p = pacer()
        p.climbTo(floor, ceiling)
        assertEquals(99, p.displayed())
        // An hour of waiting must not produce a 100 the connection hasn't earned.
        repeat(3_600) {
            p.tick(floor)
            assertTrue(p.displayed() <= ceiling, "claimed ${p.displayed()} before done")
        }
        assertEquals(99, p.displayed())
    }

    @Test
    fun displayedNeverExceedsMaxOfRealAndTheCreepAtAnyPointOfARealSession() {
        val p = pacer()
        var prev = 0
        for (tor in 0..95 step 5) {
            repeat(3) {
                val real = BootstrapProgressPacer.realTarget(false, tor)
                val now = p.tick(real)
                assertTrue(
                    now <= minOf(real + BootstrapProgressPacer.IDLE_CREEP_ROOM, BootstrapProgressPacer.IDLE_CREEP_CEILING),
                    "displayed $now is more than the bounded lead over real $real",
                )
                assertTrue(now >= prev)
                prev = now
            }
        }
        repeat(300) {
            val now = p.tick(floor)
            assertTrue(now <= ceiling, "displayed $now > the creep ceiling")
            assertTrue(now >= prev)
            prev = now
        }
    }

    // ----------------------------------------------------------------- done

    @Test
    fun snapsTo100OnDone() {
        val p = pacer()
        p.tickFor(10, BootstrapProgressPacer.realTarget(false, 30))
        assertTrue(p.displayed() < 100)
        assertEquals(100, p.tick(floor, done = true))
        assertEquals(100, p.tick(floor, done = true))
    }

    @Test
    fun doneDefaultsToARealPercentOf100() {
        val p = pacer()
        p.tickFor(5, 20)
        clock += 1_000
        p.observe(100)
        assertEquals(100, p.displayed())
    }

    // ---------------------------------------------------------------- reset

    @Test
    fun resetStartsTheDisplayOver() {
        val p = pacer()
        p.climbTo(floor, floor)
        p.reset()
        assertEquals(0, p.displayed())
        // …and it climbs again from zero at the bounded rate.
        assertEquals(2, p.tickFor(2, floor))
    }

    @Test
    fun aTorRestartRegressionResetsTheDisplay() {
        val p = pacer()
        p.climbTo(floor, floor)
        assertTrue(p.displayed() >= 90)
        // Tor died and started over: the real target collapses to 0.
        assertEquals(0, p.tick(BootstrapProgressPacer.realTarget(false, 0)))
        assertEquals(2, p.tickFor(1, BootstrapProgressPacer.realTarget(false, 50)))
    }

    @Test
    fun reachabilityFlapAfterDoneRestartsInsteadOfFreezingAt100() {
        val p = pacer()
        p.tick(floor, done = true)
        assertEquals(100, p.displayed())
        assertEquals(0, p.tick(floor, done = false))
        assertTrue(p.tickFor(10, floor) in 1..99)
    }

    // ------------------------------------------------------------ realTarget

    @Test
    fun realTargetMapsTheTwoPhasesOntoOneMonotoneScale() {
        assertEquals(0, BootstrapProgressPacer.realTarget(torConnected = false, torPercent = 0))
        assertEquals(35, BootstrapProgressPacer.realTarget(torConnected = false, torPercent = 50))
        // Tor's long 95% circuit-build park is NOT displayed as "95".
        assertEquals(66, BootstrapProgressPacer.realTarget(torConnected = false, torPercent = 95))
        assertEquals(70, BootstrapProgressPacer.realTarget(torConnected = false, torPercent = 100))
        // Phase two ignores the (by then meaningless) Tor percent.
        assertEquals(90, BootstrapProgressPacer.realTarget(torConnected = true, torPercent = 0))
        assertEquals(90, BootstrapProgressPacer.realTarget(torConnected = true, torPercent = 100))
        // Defensive clamping.
        assertEquals(0, BootstrapProgressPacer.realTarget(torConnected = false, torPercent = -5))
        assertEquals(70, BootstrapProgressPacer.realTarget(torConnected = false, torPercent = 250))
    }

    @Test
    fun creepCadenceDoubles() {
        assertEquals(BootstrapProgressPacer.CREEP_FIRST_MS, BootstrapProgressPacer.creepIntervalMs(90))
        assertEquals(8_000L, BootstrapProgressPacer.creepIntervalMs(91))
        assertEquals(16_000L, BootstrapProgressPacer.creepIntervalMs(92))
        assertEquals(1_024_000L, BootstrapProgressPacer.creepIntervalMs(98))
        assertEquals(BootstrapProgressPacer.IDLE_CREEP_FIRST_MS, BootstrapProgressPacer.idleCreepIntervalMs(0))
        assertEquals(12_000L, BootstrapProgressPacer.idleCreepIntervalMs(1))
        assertEquals(48_000L, BootstrapProgressPacer.idleCreepIntervalMs(3))
    }
}

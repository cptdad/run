package com.vg.run

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The bounded Tor keep-alive (TorKeepAlive.kt) — hermetic: a fake scheduler
 * with a manual clock and a fake "Tor", no Android framework.
 *
 * Pins the four promises of the design:
 *  1. a new session that reclaims BEFORE expiry reuses the kept instance;
 *  2. expiry stops it (the preserving stop, never the discard), and the next
 *     session is told why it starts cold;
 *  3. MAXIMUM (and an unprovable tier) never keeps Tor alive;
 *  4. a wipe never keeps it alive, and discards (not merely stops) a kept one.
 */
class TorKeepAliveTest {

    private class FakeTor(val name: String)

    /** Manual-clock scheduler: [advance] fires every due task in order. */
    private class FakeScheduler {
        var now = 0L
        private val tasks = mutableListOf<Triple<Long, Int, () -> Unit>>()
        private var nextId = 0
        val pending: Int get() = tasks.size

        fun schedule(delayMs: Long, action: () -> Unit): () -> Unit {
            val id = nextId++
            tasks += Triple(now + delayMs, id, action)
            return { tasks.removeAll { it.second == id } }
        }

        fun advance(ms: Long) {
            now += ms
            while (true) {
                val due = tasks.filter { it.first <= now }.minByOrNull { it.first } ?: return
                tasks.remove(due)
                due.third()
            }
        }
    }

    private class Harness {
        val scheduler = FakeScheduler()
        val stopped = mutableListOf<FakeTor>()
        val discarded = mutableListOf<FakeTor>()
        var serviceReleases = 0
        val keeper = TorKeepAlive<FakeTor>(
            schedule = scheduler::schedule,
            stopTor = { stopped += it },
            discardTor = { discarded += it },
            releaseService = { serviceReleases++ },
        )
    }

    private val healthy: (FakeTor) -> Boolean = { true }

    // ------------------------------------------- over-age (S2 F4, 2026-11-06)

    /** The expiry timer runs on uptime; a sleep-inclusive clock that passed the
     *  window must refuse reuse even when the timer has not fired yet. */
    @Test
    fun reclaim_pastTheWindowOnTheSleepInclusiveClock_isExpired_evenIfTheTimerHasNotFired() {
        val scheduler = FakeScheduler()
        val stopped = mutableListOf<FakeTor>()
        var wall = 0L
        var releases = 0
        val keeper = TorKeepAlive<FakeTor>(
            schedule = scheduler::schedule,
            stopTor = { stopped += it },
            discardTor = { },
            releaseService = { releases++ },
            nowMs = { wall },
        )
        val tor = FakeTor("t1")
        assertTrue(keeper.arm())
        assertTrue(keeper.park(tor, connected = true))
        // The device slept: uptime (the scheduler) barely moved, wall time ran on.
        scheduler.advance(1_000)
        wall = TorKeepAlive.KEEP_ALIVE_MS + 1

        val r = keeper.reclaim(healthy)

        assertEquals(TorKeepAlive.Reclaim.Expired, r)
        assertEquals("the over-age child is stopped, not adopted", listOf(tor), stopped)
        assertEquals(1, releases)
        assertEquals(TorKeepAlive.State.IDLE, keeper.state)
    }

    @Test
    fun reclaim_insideTheWindowOnTheSleepInclusiveClock_stillReuses() {
        val scheduler = FakeScheduler()
        var wall = 0L
        val keeper = TorKeepAlive<FakeTor>(
            schedule = scheduler::schedule,
            stopTor = { },
            discardTor = { },
            releaseService = { },
            nowMs = { wall },
        )
        val tor = FakeTor("t1")
        keeper.arm()
        keeper.park(tor, connected = true)
        wall = TorKeepAlive.KEEP_ALIVE_MS
        assertTrue(keeper.reclaim(healthy) is TorKeepAlive.Reclaim.Warm)
    }

    /** The wake lock is bounded to the window and released with the service. */
    @Test
    fun holder_holdsATimedPartialWakeLock_releasedWithTheService() {
        val holder = stripComments(SourcePins.text("androidApp/src/main/java/com/vg/run/TorKeepAliveHolder.kt"))
        assertTrue(holder.contains("PowerManager.PARTIAL_WAKE_LOCK"))
        assertTrue("timed to the window, never open-ended", holder.contains("wl.acquire(TorKeepAlive.KEEP_ALIVE_MS)"))
        assertFalse("never an untimed acquire", Regex("""\.acquire\(\s*\)""").containsMatchIn(holder))
        assertTrue("not reference-counted, so one release is final", holder.contains("setReferenceCounted(false)"))
        val release = holder.indexOf("releaseService = {")
        assertTrue(release >= 0 && holder.indexOf("releaseWakeLock()", release) in release until holder.indexOf("TorKeepAliveService.release()", release))
        assertTrue("the keeper reads the sleep-inclusive clock", holder.contains("nowMs = { SystemClock.elapsedRealtime() }"))
        assertTrue(SourcePins.text("androidApp/src/main/AndroidManifest.xml").contains("android.permission.WAKE_LOCK\""))
    }

    // ---------------------------------------------------------------- 1. reuse

    @Test
    fun attachBeforeExpiry_reusesTheKeptInstance_andEndsTheKeepAlive() {
        val h = Harness()
        val tor = FakeTor("t1")
        assertTrue(h.keeper.arm())
        assertTrue(h.keeper.park(tor, connected = true))
        h.scheduler.advance(TorKeepAlive.KEEP_ALIVE_MS - 1)

        val r = h.keeper.reclaim(healthy)

        assertTrue(r is TorKeepAlive.Reclaim.Warm)
        assertTrue((r as TorKeepAlive.Reclaim.Warm).tor === tor)
        assertEquals(TorKeepAlive.State.IDLE, h.keeper.state)
        assertEquals("timer cancelled on reclaim", 0, h.scheduler.pending)
        assertEquals("service released exactly once", 1, h.serviceReleases)
        // The (cancelled) timer can never stop the adopted instance later.
        h.scheduler.advance(10 * TorKeepAlive.KEEP_ALIVE_MS)
        assertTrue(h.stopped.isEmpty())
        assertTrue(h.discarded.isEmpty())
    }

    @Test
    fun reclaim_ofAnInstanceThatDiedWhileParked_stopsIt_andReportsExpired() {
        val h = Harness()
        val tor = FakeTor("t1")
        h.keeper.arm()
        h.keeper.park(tor, connected = true)

        val r = h.keeper.reclaim { false }

        assertEquals(TorKeepAlive.Reclaim.Expired, r)
        assertEquals("stopped BEFORE the caller's cold start can race it", listOf(tor), h.stopped)
        assertEquals(1, h.serviceReleases)
    }

    @Test
    fun reclaim_withNothingKept_isCold() {
        val h = Harness()
        assertEquals(TorKeepAlive.Reclaim.Cold, h.keeper.reclaim(healthy))
        assertEquals(0, h.serviceReleases)
    }

    /** A new session that starts before the old one parked (fast return): the
     *  pending arm is dropped, and the late park is refused ⇒ caller stops. */
    @Test
    fun reclaimWhileOnlyArmed_dropsTheArm_andALateParkIsRefused() {
        val h = Harness()
        h.keeper.arm()
        assertEquals(TorKeepAlive.Reclaim.Cold, h.keeper.reclaim(healthy))
        assertEquals(1, h.serviceReleases)
        assertFalse(h.keeper.park(FakeTor("late"), connected = true))
        assertEquals(TorKeepAlive.State.IDLE, h.keeper.state)
    }

    // --------------------------------------------------------------- 2. expiry

    @Test
    fun expiry_stopsTheKeptInstance_withThePreservingStop() {
        val h = Harness()
        val tor = FakeTor("t1")
        h.keeper.arm()
        h.keeper.park(tor, connected = true)

        h.scheduler.advance(TorKeepAlive.KEEP_ALIVE_MS)

        assertEquals(listOf(tor), h.stopped)
        assertTrue("expiry is not a wipe", h.discarded.isEmpty())
        assertEquals(TorKeepAlive.State.IDLE, h.keeper.state)
        assertEquals(1, h.serviceReleases)
        // The next session learns why it starts cold — once.
        assertEquals(TorKeepAlive.Reclaim.Expired, h.keeper.reclaim(healthy))
        assertEquals(TorKeepAlive.Reclaim.Cold, h.keeper.reclaim(healthy))
    }

    @Test
    fun theWindowIsMeasuredFromArm_notFromPark() {
        val h = Harness()
        val tor = FakeTor("t1")
        h.keeper.arm()
        h.scheduler.advance(30_000)
        h.keeper.park(tor, connected = true)
        h.scheduler.advance(TorKeepAlive.KEEP_ALIVE_MS - 30_000)
        assertEquals(listOf(tor), h.stopped)
    }

    @Test
    fun systemTimeout_actsLikeExpiry_andIsIdempotent() {
        val h = Harness()
        val tor = FakeTor("t1")
        h.keeper.arm()
        h.keeper.park(tor, connected = true)
        h.keeper.expire()          // Service.onTimeout
        h.keeper.expire()          // …and the onDestroy that follows
        h.scheduler.advance(TorKeepAlive.KEEP_ALIVE_MS)
        assertEquals(listOf(tor), h.stopped)
        assertEquals(1, h.serviceReleases)
    }

    @Test
    fun aNotConnectedInstanceIsNeverKept() {
        val h = Harness()
        h.keeper.arm()
        assertFalse(h.keeper.park(FakeTor("boot"), connected = false))
        assertEquals(TorKeepAlive.State.IDLE, h.keeper.state)
        assertEquals("the arm's service is released at once", 1, h.serviceReleases)
        assertEquals(0, h.scheduler.pending)
    }

    @Test
    fun parkWithoutArm_isRefused() {
        val h = Harness()
        assertFalse(h.keeper.park(FakeTor("t"), connected = true))
        assertEquals(0, h.serviceReleases)
    }

    @Test
    fun theWindowIsTwoMinutes() {
        assertEquals(120_000L, TorKeepAlive.KEEP_ALIVE_MS)
    }

    // ------------------------------------------------------------ 3. tier gate

    @Test
    fun maximumTier_bypassesTheKeepAlive() {
        assertFalse(
            TorKeepAlive.shouldKeepAlive(
                isWipe = false, torConnected = true, notKnownWedged = true,
                liveTier = ProtectionLevelRead.Present(ProtectionLevel.MAXIMUM),
                sessionTierAllowed = true,
            ),
        )
    }

    @Test
    fun lowerTiers_keepAlive_whenConnected() {
        for (level in listOf(ProtectionLevel.CASUAL, ProtectionLevel.PRIVATE)) {
            assertTrue(
                level.name,
                TorKeepAlive.shouldKeepAlive(
                    isWipe = false, torConnected = true, notKnownWedged = true,
                    liveTier = ProtectionLevelRead.Present(level), sessionTierAllowed = null,
                ),
            )
        }
        assertTrue(
            "legacy never-chosen tier keeps today's constants",
            TorKeepAlive.shouldKeepAlive(false, true, true, ProtectionLevelRead.Absent, null),
        )
    }

    @Test
    fun damagedTier_failsSecure() {
        assertFalse(TorKeepAlive.shouldKeepAlive(false, true, true, ProtectionLevelRead.Damaged, true))
    }

    @Test
    fun unreadableTier_fallsBackToTheUnlockTimeDecision_andRefusesWithoutOne() {
        assertTrue(TorKeepAlive.shouldKeepAlive(false, true, true, ProtectionLevelRead.Unreadable, true))
        assertFalse(TorKeepAlive.shouldKeepAlive(false, true, true, ProtectionLevelRead.Unreadable, false))
        assertFalse(TorKeepAlive.shouldKeepAlive(false, true, true, ProtectionLevelRead.Unreadable, null))
    }

    @Test
    fun notConnected_bypassesTheKeepAlive() {
        assertFalse(
            TorKeepAlive.shouldKeepAlive(
                isWipe = false, torConnected = false, notKnownWedged = true,
                liveTier = ProtectionLevelRead.Present(ProtectionLevel.CASUAL), sessionTierAllowed = true,
            ),
        )
    }

    /** "Tor failing → restart the app": a session that never reached the relay
     *  must not hand its (possibly wedged) daemon to the next one. */
    @Test
    fun aSessionThatNeverReachedTheRelay_bypassesTheKeepAlive() {
        assertFalse(
            TorKeepAlive.shouldKeepAlive(
                isWipe = false, torConnected = true, notKnownWedged = false,
                liveTier = ProtectionLevelRead.Present(ProtectionLevel.CASUAL), sessionTierAllowed = true,
            ),
        )
    }

    // ------------------------------------------------------------------ 4. wipe

    @Test
    fun wipe_bypassesTheKeepAlive() {
        assertFalse(
            TorKeepAlive.shouldKeepAlive(
                isWipe = true, torConnected = true, notKnownWedged = true,
                liveTier = ProtectionLevelRead.Present(ProtectionLevel.CASUAL), sessionTierAllowed = true,
            ),
        )
    }

    @Test
    fun wipe_discardsAKeptInstance_neverTheMerePreservingStop() {
        val h = Harness()
        val tor = FakeTor("t1")
        h.keeper.arm()
        h.keeper.park(tor, connected = true)

        h.keeper.discard()

        assertEquals(listOf(tor), h.discarded)
        assertTrue(h.stopped.isEmpty())
        assertEquals(TorKeepAlive.State.IDLE, h.keeper.state)
        assertEquals(0, h.scheduler.pending)
        assertEquals(1, h.serviceReleases)
        // Nothing survives into the next session — not even the "expired" note.
        assertEquals(TorKeepAlive.Reclaim.Cold, h.keeper.reclaim(healthy))
        h.scheduler.advance(TorKeepAlive.KEEP_ALIVE_MS)
        assertTrue(h.stopped.isEmpty())
    }

    @Test
    fun wipe_withNothingKept_isANoOp() {
        val h = Harness()
        h.keeper.discard()
        assertEquals(0, h.serviceReleases)
        assertTrue(h.discarded.isEmpty())
    }

    // ---------------------------------------------------------- session hooks

    @Test
    fun hooks_areInertWhenUnbound_andFollowTheBoundSession() {
        val hooks = TorSessionHooks()
        assertNull("no descriptor hedge without a session", hooks.descriptorHedge())
        assertTrue("hung-circuit rung inert without a session", hooks.hsCircuitAnswered())
        hooks.onNewCircuitAccepted() // no-op, must not throw

        val oldSession = Any()
        val newSession = Any()
        var newCircuits = 0
        val oldHedge = DescriptorHedge()
        val newHedge = DescriptorHedge()
        hooks.bind(oldSession, { oldHedge }, { newCircuits += 100 }, { true })
        hooks.bind(newSession, { newHedge }, { newCircuits++ }, { false })
        assertSame("a kept Tor drives the NEW session's hedge (fresh budget)", newHedge, hooks.descriptorHedge())
        // The OLD session's late teardown must not unbind the new one.
        hooks.unbind(oldSession)
        assertTrue(hooks.isBound)
        hooks.onNewCircuitAccepted()
        assertEquals(1, newCircuits)
        assertFalse(hooks.hsCircuitAnswered())
        hooks.unbind(newSession)
        assertFalse(hooks.isBound)
        assertNull(hooks.descriptorHedge())
        assertTrue(hooks.hsCircuitAnswered())
    }

    // ------------------------------------------- no identifier in the phrases

    @Test
    fun panelPhrases_carryNoIdentifier_andSurviveRedaction() {
        for (p in listOf(TorKeepAlive.PHRASE_REUSED, TorKeepAlive.PHRASE_EXPIRED)) {
            ConnectionLog.clear()
            ConnectionLog.append(ConnectionLog.Kind.TOR, p)
            val line = ConnectionLog.lines.value.single()
            ConnectionLog.clear()
            assertEquals("redact() must leave a fixed phrase untouched", p, line.text)
            assertEquals("deliberately uncoded (relay allowlist unchanged)", null, line.code)
            assertFalse(p, Regex("\\d").containsMatchIn(p))
            assertFalse(p, p.contains(".onion"))
        }
    }

    // ------------------------------------------------- wiring (source-level)

    private fun src(path: String) = File(repoRoot(), path).readText()

    @Test
    fun wiring_lockSessionHandsOverInsteadOfStopping_andWipesDiscard() {
        val vm = src(SourcePins.RUN_VIEW_MODEL)
        assertTrue(vm.contains("if (!TorKeepAliveHolder.parkOnTeardown(tor, connected)) tor.stop()"))
        assertTrue(vm.contains("TorKeepAliveHolder.hooks.unbind(this)"))
        assertTrue("the emergency wipe keeps its discard", vm.contains("torManager?.stopAndDiscardState()"))
        val wipe = src(SourcePins.WIPE_ROUTINE)
        assertTrue(wipe.contains("TorKeepAliveHolder.discardForWipe()"))
        assertTrue(
            "the discard must precede the tor_direct deletion",
            wipe.indexOf("TorKeepAliveHolder.discardForWipe()") <
                wipe.indexOf("""java.io.File(context.filesDir, "tor_direct").deleteRecursively()"""),
        )
        val activity = src(SourcePins.MAIN_ACTIVITY)
        assertTrue(
            "arm before the teardown starts",
            activity.indexOf(".armTorKeepAliveOnBackground()") in 0 until
                activity.lastIndexOf("finishAndRemoveTask()"),
        )
        val manifest = src("androidApp/src/main/AndroidManifest.xml")
        assertTrue(manifest.contains("android:foregroundServiceType=\"shortService\""))
        assertTrue(manifest.contains("android.permission.FOREGROUND_SERVICE\""))
    }
}

package com.vg.run

import android.app.Application
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/**
 * Tor's working dirs must SURVIVE an ordinary stop and be DESTROYED by a wipe
 * (2026-08-01, deliberate tradeoff).
 *
 * A live capture showed a cold-started Tor reporting `Bootstrapped 100%` in ~7 s
 * and then failing to complete an onion rendezvous for minutes, while a warm
 * long-lived Tor on the same network reached the onion on every probe — so wiping
 * on every start AND stop made each relaunch re-pay a full cold
 * descriptor/guard/consensus fetch. It also re-sampled entry guards on every
 * launch, which is an anonymity cost in its own right.
 *
 * Runs WITHOUT spawning Tor: `stop()` on a manager that never started still
 * exercises the exact teardown path (`torProcess` is null, so it is pure
 * bookkeeping plus — before this change — the two `deleteRecursively()` calls).
 * That is what makes the preserve/discard split testable at all on a device.
 *
 * Run with:
 *   adb shell am instrument -w -e class com.vg.run.TorDataDirPreservationTest \
 *     com.vg.run.test/androidx.test.runner.AndroidJUnitRunner
 * (NOT `connectedAndroidTest` — it uninstalls the app afterwards and destroys
 * seeded device state.)
 */
@RunWith(AndroidJUnit4::class)
class TorDataDirPreservationTest {

    private lateinit var app: Application

    private val filesTorRoot: File get() = File(app.filesDir, "tor_direct")
    private val cacheTorRoot: File get() = File(app.cacheDir, "tor_direct")
    private val guardState: File get() = File(filesTorRoot, "data/state")
    private val consensus: File get() = File(cacheTorRoot, "cache/cached-microdesc-consensus")

    @Before
    fun setUp() {
        app = ApplicationProvider.getApplicationContext()
        ProcessWipeLatch.resetForTest()
        clean()
    }

    @After
    fun tearDown() {
        ProcessWipeLatch.resetForTest()
        clean()
    }

    /**
     * The core property: an ordinary teardown — background, lock, `onCleared` —
     * leaves Tor's guard state and cached consensus in place for the next launch.
     */
    @Test
    fun ordinaryStop_preservesGuardStateAndConsensusCache() {
        seedWarmState()

        TorManager(app).stop()

        assertTrue("entry-guard state must survive an ordinary stop", guardState.isFile)
        assertEquals("guard-state", guardState.readText())
        assertTrue("the consensus cache must survive an ordinary stop", consensus.isFile)
    }

    /** Idempotent: repeated stops (stop() is called from several teardowns) never erode it. */
    @Test
    fun repeatedOrdinaryStops_stillPreserve() {
        seedWarmState()

        val tor = TorManager(app)
        repeat(3) { tor.stop() }
        TorManager(app).stop()

        assertTrue("guard state must survive repeated ordinary stops", guardState.isFile)
        assertTrue("the consensus cache must survive repeated ordinary stops", consensus.isFile)
    }

    /**
     * The other half, and the one that must never regress: the wipe-path teardown
     * destroys both trees outright.
     */
    @Test
    fun stopAndDiscardState_destroysBothTrees() {
        seedWarmState()

        TorManager(app).stopAndDiscardState()

        assertFalse("filesDir/tor_direct must be gone after a discarding stop", filesTorRoot.exists())
        assertFalse("cacheDir/tor_direct must be gone after a discarding stop", cacheTorRoot.exists())
    }

    /**
     * And the shared wipe routine — the single path the emergency wipe, the
     * inactivity dead-man's switch, the launch-time orphan self-heal and the debug
     * test hook all go through — still destroys them even though nothing stopped a
     * daemon. This is the one that covers the wipes which never touch TorManager
     * at all.
     */
    @Test
    fun wipeRoutine_destroysPreservedStateWithoutAnyTeardown() {
        seedWarmState()

        WipeRoutine.wipePersistentState(app)

        assertFalse("a wipe must destroy the preserved data dir", filesTorRoot.exists())
        assertFalse("a wipe must destroy the preserved cache dir", cacheTorRoot.exists())
    }

    // -----------------------------------------------------------------------

    /** The exact production paths, seeded as a warm previous session would leave them. */
    private fun seedWarmState() {
        guardState.parentFile!!.mkdirs()
        guardState.writeText("guard-state")
        consensus.parentFile!!.mkdirs()
        consensus.writeText("consensus")
        // Per-session residue that a preserved dir may also carry.
        File(filesTorRoot, "data/tor.log").writeText("Socks listener listening on 127.0.0.1:41111\n")
        File(filesTorRoot, "data/lock").writeText("")
        assertTrue(guardState.isFile && consensus.isFile)
    }

    private fun clean() {
        filesTorRoot.deleteRecursively()
        cacheTorRoot.deleteRecursively()
    }
}

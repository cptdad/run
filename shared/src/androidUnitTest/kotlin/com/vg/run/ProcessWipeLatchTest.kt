package com.vg.run

import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * [ProcessWipeLatch] semantics — plain-JVM, because the latch is pure RAM state
 * with no Keystore/Tink/Context dependency (the live effect it drives needs a
 * real Android runtime and is covered by the instrumented
 * ManifestCapabilityPurgeTest (purgeAfterAWipe_recreatesNothing)).
 *
 * The properties locked here are the ones the post-wipe-regeneration fix rests
 * on (2026-07-30): the latch defaults to "no wipe yet", is ONE-WAY once set, and
 * — critically — lives only in RAM, so a fresh process starts clean and the
 * latch itself can never become the post-wipe artifact it exists to prevent.
 */
class ProcessWipeLatchTest {

    @AfterTest
    fun tearDown() {
        // Instrumented/unit tests share one JVM; never leave the latch set for a
        // later test class. (No-op in the release unit-test variant, where the
        // latch is deliberately not resettable — see the debug/release split
        // asserted below.)
        ProcessWipeLatch.resetForTest()
    }

    @Test
    fun defaultsToNotWiped_andIsOneWayOnceLatched() {
        ProcessWipeLatch.resetForTest()
        // Only meaningful in the debug variant, where the reset above works;
        // in release the latch may legitimately still be set by another test.
        if (isDebugBuild) {
            assertFalse(
                ProcessWipeLatch.wipedThisProcess,
                "a process that has not wiped must not refuse its guarded subsystem",
            )
        }

        ProcessWipeLatch.latch()
        assertTrue(ProcessWipeLatch.wipedThisProcess, "latch() must record the wipe")

        // Idempotent: a second wipe in the same process changes nothing, and
        // nothing in production can clear it.
        ProcessWipeLatch.latch()
        assertTrue(ProcessWipeLatch.wipedThisProcess, "latch() must stay set")
    }

    @Test
    fun isVisibleAcrossThreads() {
        ProcessWipeLatch.resetForTest()
        // The wipe runs on the caller's thread (MainActivity.onCreate / the
        // ViewModel), while a racing guarded write can run on any
        // other thread. A non-volatile flag could let that thread
        // keep reading a stale `false` and resurrect the key surface.
        val seen = java.util.concurrent.atomic.AtomicBoolean(false)
        ProcessWipeLatch.latch()
        val t = Thread { seen.set(ProcessWipeLatch.wipedThisProcess) }
        t.start()
        t.join(5_000)
        assertTrue(seen.get(), "another thread must observe the latch")
    }

    @Test
    fun resetIsDebugOnly() {
        ProcessWipeLatch.latch()
        ProcessWipeLatch.resetForTest()
        if (isDebugBuild) {
            assertFalse(
                ProcessWipeLatch.wipedThisProcess,
                "the test reset must work in debug so one wipe test can't latch the whole suite",
            )
        } else {
            assertTrue(
                ProcessWipeLatch.wipedThisProcess,
                "in a release build the latch must be one-way — resetForTest() is a no-op",
            )
        }
    }
}

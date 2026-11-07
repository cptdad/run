package com.vg.run

import androidx.lifecycle.Lifecycle
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Post-wipe deniability defeated by rotating the phone — AND the regression
 * its first fix shipped.
 *
 * `PinEntryScreen`'s black "powered-off-looking" cover (`isWiped`) lived in
 * `remember { mutableStateOf(false) }` — composition-local, not
 * `rememberSaveable`, not on the retained ViewModel. `MainActivity.onStop`
 * deliberately skips `finishAndRemoveTask()` during a configuration change, so
 * a rotation recreates the Activity in the SAME PROCESS and rebuilds the
 * composition from scratch, losing the flag — reverting the cover to an
 * interactive PIN prompt (or, via NavHost's restored back stack, straight past
 * it) on one tool-free action, in exactly the coercion scenario the cover
 * exists for. So `MainActivity.onCreate` now short-circuits on a
 * process-lifetime (RAM-only) flag, before any vault-state read, and renders
 * only the black cover.
 *
 * WHICH flag is the whole point, and the reason this class pins BOTH
 * directions. The first fix gated on [ProcessWipeLatch], which is armed by
 * EVERY wipe — including the launch-time ones (`InactivityWipe`, the
 * orphaned-credential self-heal, the debug test-wipe hook) that exist precisely
 * to fall through to setup so the user can re-provision in that same process.
 * Result: wipe at launch → provision a new vault → rotate the phone → a
 * PERMANENT black screen over a perfectly healthy vault, escapable only by
 * force-quitting. The gate now reads [ProcessWipeCover], armed only by a
 * DENIABLE in-session wipe (`RunViewModel.performEmergencyWipe`).
 *
 * INSTRUMENTED because it drives a real `Activity` lifecycle and the shared
 * `LogBuffer`/`ProcessWipeCover` singletons — neither is testable at the
 * plain-JVM `androidUnitTest`/`test` tier (no Robolectric). The ARMING half of
 * the same contract (who sets the cover, and who deliberately does not) is
 * pinned at the JVM tier by [ProcessWipeCoverTest], which runs in
 * `./gradlew test`. Must be run with `am instrument` against an
 * already-provisioned app, NOT `connectedAndroidTest`, which uninstalls the app
 * afterward and would destroy any seeded vault state a co-running suite relies
 * on:
 *
 *   adb shell am instrument -w \
 *     -e class com.vg.run.MainActivityWipeCoverTest \
 *     com.vg.run.test/androidx.test.runner.AndroidJUnitRunner
 *
 * NON-DESTRUCTIVE by construction: neither test calls a wipe. The covered case
 * arms an in-RAM flag; the uncovered case arms [ProcessWipeLatch] (also pure
 * RAM — no I/O, no erasure) to reproduce exactly what a launch-time wipe leaves
 * behind in the process. The uncovered launch does run the ordinary launch path
 * (`TestHooks`, `InactivityWipe.checkAndWipeIfNeeded`, the orphan check) — that
 * is the point of the test, and it is no more destructive than opening the app.
 */
@RunWith(AndroidJUnit4::class)
class MainActivityWipeCoverTest {

    @Before
    fun setUp() {
        // A wipe test that ran earlier in this shared instrumentation process
        // may have latched already (same hygiene as ManifestCapabilityPurgeTest
        // / LegacyTorWarmCachePurgeTest / KeyValueStoreWriteDurabilityTest).
        ProcessWipeLatch.resetForTest()
        ProcessWipeCover.resetForTest()
        LogBuffer.clear()
    }

    @After
    fun tearDown() {
        ProcessWipeLatch.resetForTest()
        ProcessWipeCover.resetForTest()
        LogBuffer.clear()
    }

    /** True if the onCreate short-circuit fired since the last [LogBuffer.clear]. */
    private fun coverWasRendered(): Boolean =
        LogBuffer.getAll().any { it.tag == "MainActivity" && it.message.contains("process-wipe cover") }

    private fun launchAndSettle() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.moveToState(Lifecycle.State.RESUMED)
        }
    }

    /**
     * Direction 1 — the property the cover exists for. After a DENIABLE in-session
     * emergency wipe, recreating the Activity in the same process (rotation)
     * must still show the black cover, never app content.
     *
     * Non-vacuousness: reverting the `MainActivity.onCreate` short-circuit (or
     * reverting to never consulting [ProcessWipeCover] at all) makes this fail,
     * because the `LogBuffer` entry it looks for is appended ONLY from inside
     * that branch.
     */
    @Test
    fun onCreate_afterDeniableInSessionWipe_rendersTheCover() {
        ProcessWipeCover.arm()   // what performEmergencyWipe(deniable = true) does
        assertTrue("precondition: the cover must be armed", ProcessWipeCover.armed)

        launchAndSettle()

        assertTrue(
            "MainActivity.onCreate must short-circuit to the black cover when " +
                "ProcessWipeCover.armed is true, before any vault-state read runs " +
                "(found log: ${LogBuffer.asText()})",
            coverWasRendered(),
        )
    }

    /**
     * Direction 2 — the regression pin. A LAUNCH-TIME wipe arms
     * [ProcessWipeLatch] and then deliberately routes to setup; the user
     * provisions a new vault and rotates the phone. That recreate must render
     * the app, NOT a black cover — the latch is a "refuse racing writes" flag,
     * not a "hide the UI forever" flag.
     *
     * Non-vacuousness is built IN, not assumed: the first half of this test is
     * a positive control in the same process (cover armed ⇒ the log line is
     * observable here), so its ABSENCE in the second half means the
     * short-circuit genuinely did not fire, rather than that the observable
     * never worked. Gating `onCreate` back on `ProcessWipeLatch
     * .wipedThisProcess` makes the second assertion fail.
     */
    @Test
    fun onCreate_afterLaunchTimeWipe_doesNotCover() {
        // --- positive control: the observable works in THIS process. ---
        ProcessWipeCover.arm()
        launchAndSettle()
        assertTrue(
            "control: an armed cover must render the cover (if this fails, the " +
                "negative assertion below proves nothing)",
            coverWasRendered(),
        )

        // --- the regression: a launch-time wipe's residue, and nothing else. ---
        ProcessWipeCover.resetForTest()
        LogBuffer.clear()
        assertFalse("precondition: the cover must be clear", ProcessWipeCover.armed)
        // Exactly what InactivityWipe / the orphan self-heal / TestHooks leave
        // behind: WipeRoutine.wipePersistentState arms the latch and nothing else.
        ProcessWipeLatch.latch()
        assertTrue("precondition: the wipe latch must be set", ProcessWipeLatch.wipedThisProcess)

        launchAndSettle()

        assertFalse(
            "a launch-time wipe (latch set, cover clear) must NOT black-screen the " +
                "Activity — the user re-provisions in this same process and a rotation " +
                "recreates it. Gating onCreate on ProcessWipeLatch instead of " +
                "ProcessWipeCover made this permanent and force-quit-only escapable " +
                "(found log: ${LogBuffer.asText()})",
            coverWasRendered(),
        )
    }
}

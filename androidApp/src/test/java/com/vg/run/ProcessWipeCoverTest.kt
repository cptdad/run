package com.vg.run

import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The post-wipe black deniability cover, and the two-sided contract that
 * decides WHO arms it.
 *
 * The first fix gated `MainActivity.onCreate` on [ProcessWipeLatch], which
 * `WipeRoutine.wipePersistentState` arms on EVERY wipe — including the
 * launch-time ones (`InactivityWipe`, the orphaned-credential self-heal, the
 * debug test-wipe hook) that exist precisely to fall through to setup so the
 * user can re-provision in that same process. `MainActivity.onStop` skips
 * `finishAndRemoveTask()` on a configuration change, so the process survives a
 * rotation: wipe at launch → provision a new vault → rotate → a PERMANENT black
 * screen over a healthy vault, escapable only by force-quitting. That broke the
 * invariant `WipeRoutine`'s own kdoc states ("a vault re-provisioned in this
 * same process … works normally").
 *
 * Two flags, two jobs — this class pins the split:
 *  - [ProcessWipeLatch] = refuse writes that would re-create wiped artifacts.
 *    Armed by every wipe. UNCHANGED.
 *  - [ProcessWipeCover] = hide the UI for the rest of this process. Armed ONLY
 *    by a deniable in-session `RunViewModel.performEmergencyWipe`.
 *
 * The [ProcessWipeCover] semantics below are plain behavioural tests (pure RAM
 * state, no Context). The arming/gating half is checked at the SOURCE level —
 * same technique and same reason as [VendorPushOptOutTeardownSourceTest] and
 * [PrefsApplySourceGuardTest]: `RunViewModel` is an `AndroidViewModel` needing a
 * real `Application` (CryptoProvider, KeyValueStore, VaultSelector, …) and
 * `WipeRoutine` performs Keystore erasure and file deletion, so neither is
 * reachable at the plain-JVM tier this module's `test` source set runs at (no
 * Robolectric, no mocking framework on the classpath). The rendered behaviour
 * is covered by the instrumented `MainActivityWipeCoverTest`, which pins both
 * directions against a real Activity lifecycle.
 */
class ProcessWipeCoverTest {

    @After
    fun tearDown() {
        // Unit tests share one JVM; never leave the cover armed for a later test
        // class. (No-op in the release unit-test variant, where the cover is
        // deliberately not resettable — see [resetIsDebugOnly].)
        ProcessWipeCover.resetForTest()
    }

    // -----------------------------------------------------------------------
    // The flag itself
    // -----------------------------------------------------------------------

    @Test
    fun defaultsToUncovered_andIsOneWayOnceArmed() {
        ProcessWipeCover.resetForTest()
        // Only meaningful in the debug variant, where the reset above works.
        if (BuildConfig.DEBUG) {
            assertFalse(
                "a process that has not wiped in-session must render its UI normally",
                ProcessWipeCover.armed,
            )
        }

        ProcessWipeCover.arm()
        assertTrue("arm() must record the cover", ProcessWipeCover.armed)

        // Idempotent; nothing in production can clear it.
        ProcessWipeCover.arm()
        assertTrue("arm() must stay set", ProcessWipeCover.armed)
    }

    @Test
    fun isVisibleAcrossThreads() {
        ProcessWipeCover.resetForTest()
        // The wipe runs on the main thread; onCreate reads the flag on the main
        // thread too, but a non-volatile field would still be a latent hazard for
        // any background reader. Same posture as ProcessWipeLatch.
        val seen = java.util.concurrent.atomic.AtomicBoolean(false)
        ProcessWipeCover.arm()
        val t = Thread { seen.set(ProcessWipeCover.armed) }
        t.start()
        t.join(5_000)
        assertTrue("another thread must observe the cover", seen.get())
    }

    @Test
    fun resetIsDebugOnly() {
        ProcessWipeCover.arm()
        ProcessWipeCover.resetForTest()
        if (BuildConfig.DEBUG) {
            assertFalse(
                "the test reset must work in debug so one wipe test can't cover the whole suite",
                ProcessWipeCover.armed,
            )
        } else {
            assertTrue(
                "in a release build the cover must be one-way — resetForTest() is a no-op",
                ProcessWipeCover.armed,
            )
        }
    }

    // -----------------------------------------------------------------------
    // Who arms it (the regression pin, both directions)
    // -----------------------------------------------------------------------

    /**
     * Direction A: the launch-time wipes must NOT cover. Every one of them
     * (`InactivityWipe.checkAndWipeIfNeeded`, `MainActivity`'s orphaned-credential
     * self-heal, the debug `TestHooks` wipe) goes through
     * `WipeRoutine.wipePersistentState` and nothing else — so as long as the
     * routine itself never arms the cover, all three stay able to fall through to
     * setup and let the user re-provision in this same process.
     */
    @Test
    fun wipeRoutine_neverArmsTheCover() {
        val src = SourcePins.text(SourcePins.WIPE_ROUTINE)
        assertTrue("precondition: WipeRoutine.wipePersistentState must exist", src.contains("fun wipePersistentState("))
        assertTrue(
            "precondition: WipeRoutine must still arm the write-refusal latch",
            src.contains("ProcessWipeLatch.latch()"),
        )
        assertFalse(
            "WipeRoutine.wipePersistentState is the shared routine EVERY launch-time wipe " +
                "calls, and those wipes deliberately fall through to setup. Arming the " +
                "black cover here black-screens a freshly re-provisioned vault on the next " +
                "Activity recreate (rotation), permanently — that was the regression.",
            src.contains("ProcessWipeCover.arm()"),
        )
    }

    /**
     * Direction B: the deniable in-session wipe MUST cover, and the one
     * user-initiated "start over" erase must not.
     */
    @Test
    fun performEmergencyWipe_armsTheCoverOnlyWhenDeniable() {
        val src = SourcePins.text(SourcePins.RUN_VIEW_MODEL)

        val fnStart = src.indexOf("fun performEmergencyWipe(")
        assertTrue("RunViewModel.performEmergencyWipe must exist", fnStart >= 0)
        assertTrue(
            "performEmergencyWipe must take a `deniable` flag defaulting to true, so a new " +
                "call site fails toward deniability (iOS parity: AppState.emergencyWipe(deniable:))",
            src.substring(fnStart, (fnStart + 120).coerceAtMost(src.length))
                .contains("deniable: Boolean = true"),
        )
        assertTrue(
            "the deniable in-session wipe must arm ProcessWipeCover — this is the property " +
                "the cover exists for: a rotation recreates the Activity in the same process and " +
                "must not reveal app content",
            src.contains("if (deniable) ProcessWipeCover.arm()"),
        )

        // The orphaned-vault "Erase" on the unlock screen is the one wipe the user
        // asks for in order to START OVER; it must land on setup, not on a black
        // screen. (iOS sibling: AppState.eraseOrphanedVault → emergencyWipe(deniable: false).)
        val pin = File(repoRoot(), "androidApp/src/main/java/com/vg/run/PinEntryScreen.kt").readText()
        val erase = pin.indexOf("user erased an orphaned vault")
        assertTrue("the orphaned-vault erase call site must exist", erase >= 0)
        assertTrue(
            "the orphaned-vault erase must pass deniable = false — the user chose to start " +
                "over and is routed to setup by onVaultErased(); arming the cover would " +
                "black-screen them on the next Activity recreate",
            pin.substring(erase, (erase + 600).coerceAtMost(pin.length))
                .contains("performEmergencyWipe(deniable = false)"),
        )
    }

    /**
     * The gate itself: `MainActivity.onCreate` must read the cover, not the latch.
     * Both names appear in that file's explanatory comment, so this asserts on the
     * `if` expression rather than on mere mentions.
     */
    @Test
    fun mainActivityGate_readsTheCoverNotTheLatch() {
        val src = SourcePins.text(SourcePins.MAIN_ACTIVITY)
        assertTrue(
            "MainActivity.onCreate must short-circuit on ProcessWipeCover.armed",
            src.contains("if (ProcessWipeCover.armed) {"),
        )
        assertFalse(
            "MainActivity must NOT gate the cover on ProcessWipeLatch.wipedThisProcess — " +
                "that flag is armed by launch-time wipes too, which is what black-screened " +
                "healthy re-provisioned vaults after a rotation",
            src.contains("if (ProcessWipeLatch.wipedThisProcess)"),
        )
    }

    /**
     * The cover gated ONLY
     * `MainActivity.onCreate`'s rendering. `onResume` runs on every foreground
     * transition regardless of what `onCreate` drew, including a launcher tap
     * landing on a process the OS kept CACHED after `finishAndRemoveTask()`
     * (not necessarily a fresh process — see [ProcessWipeCover]'s kdoc). Before
     * this fix, `onResume` unconditionally posted the `autoLockCheck` watchdog,
     * whose first statement looks up `RunViewModel` via `ViewModelProvider`
     * (constructing it if absent), whose `init` unconditionally calls
     * `startSpeculativeTor()` — restarting Tor and beaconing the relay from a
     * phone that must present as dead. Pins that the guard exists AND runs
     * before every side effect that mattered: the watchdog post and the
     * `AuthActivityHolder` publish (no BiometricPrompt surface over the cover).
     */
    @Test
    fun mainActivityOnResume_gatesOnTheCoverBeforeTheWatchdogAndAuthHolder() {
        val src = SourcePins.text(SourcePins.MAIN_ACTIVITY)

        val resumeStart = src.indexOf("override fun onResume() {")
        assertTrue("MainActivity.onResume must exist", resumeStart >= 0)
        val resumeEnd = src.indexOf("override fun onPause()", resumeStart)
        assertTrue("onPause must exist after onResume", resumeEnd > resumeStart)
        val body = src.substring(resumeStart, resumeEnd)

        val gateIdx = body.indexOf("if (ProcessWipeCover.armed) {")
        assertTrue(
            "onResume must early-return while the deniable-wipe cover is armed — " +
                "otherwise a launcher tap on a cached (not necessarily fresh) process " +
                "still fires the watchdog behind the black cover",
            gateIdx >= 0,
        )
        // The first side effect is the ViewModel lookup (onResume now obtains the
        // ViewModel itself to reset the idle clock, then runs the watchdog at once);
        // both construct RunViewModel when absent, so the gate must precede both.
        val vmLookupIdx = body.indexOf("ViewModelProvider(this).get(RunViewModel::class.java)")
        val runIdx = body.indexOf("autoLockCheck.run()")
        assertTrue("precondition: the ViewModel lookup and the watchdog run must still exist", vmLookupIdx > 0 && runIdx > 0)
        val watchdogIdx = minOf(vmLookupIdx, runIdx)
        assertTrue(
            "the cover gate must run BEFORE the ViewModel lookup and the watchdog, since " +
                "either constructs RunViewModel and starts speculative Tor",
            gateIdx < watchdogIdx,
        )

        // The bound is the watchdog post, not an arbitrary character window: what
        // matters is that the `return` belongs to the gate and lands before the
        // first side effect, which is exactly `gateIdx until watchdogIdx`.
        val returnIdx = body.indexOf("return", gateIdx)
        assertTrue(
            "the gate must actually return, and do it before the watchdog is posted",
            returnIdx in gateIdx until watchdogIdx,
        )

        val authHolderIdx = body.indexOf("AuthActivityHolder.activity = this")
        assertTrue("precondition: the AuthActivityHolder publish must still exist", authHolderIdx > 0)
        assertTrue(
            "the cover gate must also run BEFORE AuthActivityHolder is published — a " +
                "covered process must not offer a BiometricPrompt surface either",
            gateIdx < authHolderIdx,
        )
    }

    /**
     * Belt: [RunViewModel.startSpeculativeTor] (reached from `init`, which
     * runs on every construction of the ViewModel) must refuse to start Tor
     * while the cover is armed, independent of whatever gates its caller. This
     * is the second line of defense for any OTHER path that might construct
     * `RunViewModel` in a covered process. Must NOT be gated on
     * [ProcessWipeLatch] instead — that flag is armed by every launch-time wipe
     * too, all of which are designed to let Tor start normally afterwards.
     */
    @Test
    fun startSpeculativeTor_gatesOnTheCoverFirst() {
        val src = SourcePins.text(SourcePins.RUN_VIEW_MODEL)

        val fnStart = src.indexOf("private fun startSpeculativeTor() {")
        assertTrue("RunViewModel.startSpeculativeTor must exist", fnStart >= 0)
        // Bound the slice by the NEXT SIBLING DECLARATION, not by the first
        // 4-space-indented `}`: that brace is only the function's own end while no
        // nested construct in the body happens to close at that column, which is a
        // property of today's formatting rather than of the code.
        val fnEnd = src.indexOf("private fun newTorManager(): TorManager {", fnStart)
        assertTrue(
            "startSpeculativeTor's next sibling newTorManager must still follow it (the slice bound)",
            fnEnd > fnStart,
        )
        val body = src.substring(fnStart, fnEnd)

        val gateIdx = body.indexOf("if (ProcessWipeCover.armed) return")
        assertTrue(
            "startSpeculativeTor must refuse to run while the deniable-wipe cover is " +
                "armed, independent of its caller",
            gateIdx >= 0,
        )

        val torRequiredIdx = body.indexOf("if (!RelayConfig.isTorRequired) return")
        assertTrue("precondition: the existing isTorRequired guard must still exist", torRequiredIdx > 0)
        assertTrue(
            "the cover gate must run before any other guard/side effect in this function",
            gateIdx < torRequiredIdx,
        )
    }
}

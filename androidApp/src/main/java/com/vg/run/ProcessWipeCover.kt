package com.vg.run

/**
 * ProcessWipeCover — a one-way, RAM-ONLY "this process must keep showing the
 * black deniability cover" flag. Armed ONLY by an IN-SESSION emergency wipe
 * ([RunViewModel.performEmergencyWipe] with `deniable = true`); read by
 * `MainActivity.onCreate`, which then renders nothing but a black `Box`.
 *
 * WHY IT IS NOT [ProcessWipeLatch]. The two flags answer different questions and
 * conflating them shipped a product regression:
 *
 *  - [ProcessWipeLatch.wipedThisProcess] = "a wipe has happened in this process,
 *    so refuse any WRITE that would re-create an artifact it destroyed". Armed by
 *    EVERY wipe — including the launch-time ones (`InactivityWipe`, the
 *    orphaned-credential self-heal, the debug test-wipe hook) that are DESIGNED to
 *    fall through to setup and let the user provision a new vault in this same
 *    process. `WipeRoutine`'s own kdoc states that invariant.
 *  - [armed] (this flag) = "the user must not see app content again in this
 *    process". True only for the coercion scenario the cover exists for: a wipe
 *    the user triggered (or a wrong-PIN budget burned) WHILE USING the app, where
 *    the process is deliberately kept alive looking powered-off.
 *
 * Gating the cover on the LATCH black-screened a healthy vault: a launch-time wipe
 * armed the latch, the user provisioned a new vault, then ROTATED the phone —
 * `MainActivity.onStop` skips `finishAndRemoveTask()` on a configuration change, so
 * the process survives, `onCreate` runs again, and the still-set latch painted a
 * permanent black screen escapable only by force-quitting.
 *
 * The iOS sibling is `AppState.wipedThisSession`, which has always had exactly this
 * split: it is assigned only inside `AppState.emergencyWipe(deniable:)`, while the
 * launch-time wipes in `runLaunchSecurityChecks()` call the Kotlin
 * `controller.emergencyWipe()` directly and never touch it (and
 * `eraseOrphanedVault()` passes `deniable: false`). This flag is the Android side
 * of that same contract.
 *
 * LIFETIME: RAM only, deliberately — persisting it would itself be a post-wipe
 * artifact. Clearing needs a genuinely NEW PROCESS, NOT merely a relaunch: after
 * `finishAndRemoveTask()` the OS is free to keep this process CACHED (LRU, for a
 * fast future launch) instead of killing it, and a launcher tap then creates a
 * brand-new `MainActivity` in that SAME process — where this flag is still armed,
 * correctly. `onCreate` re-checks it and renders the black cover again, but until
 * a later fix every OTHER lifecycle callback that constructs
 * the ViewModel or publishes activity state (`onResume`'s watchdog, which builds
 * `RunViewModel` via `ViewModelProvider` and — through its `init` —
 * `startSpeculativeTor()`) ran unconditionally, restarting Tor and beaconing the
 * relay behind the cover. Both now gate on [armed] too (`MainActivity.onResume`,
 * `RunViewModel.startSpeculativeTor`) — see their call sites. Only an actual
 * process kill (LMK reclaim or a real force-quit) starts a genuinely fresh
 * process on the next launch and shows setup, matching iOS. One-way within the
 * process: nothing but a DEBUG-build test reset clears it.
 */
object ProcessWipeCover {

    private val covered = java.util.concurrent.atomic.AtomicBoolean(false)

    /** True once [arm] has run in this process. */
    val armed: Boolean get() = covered.get()

    /**
     * Called ONLY from the deniable in-session wipe path. Idempotent; never
     * cleared by any production path.
     */
    fun arm() {
        covered.set(true)
    }

    /**
     * DEBUG-ONLY reset, and a **no-op in release builds**. Instrumented tests
     * share one process, so a wipe test would otherwise cover every later test
     * class's Activity launch. Deliberately not usable in a shipped binary: the
     * cover must be one-way there. Mirrors [ProcessWipeLatch.resetForTest].
     */
    fun resetForTest() {
        if (BuildConfig.DEBUG) covered.set(false)
    }
}

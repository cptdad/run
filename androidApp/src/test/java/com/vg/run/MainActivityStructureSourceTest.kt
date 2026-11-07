package com.vg.run

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pins WHERE MainActivity's extracted pieces sit, because other source guards
 * read this file with first-match / last-match `indexOf` and only mean what
 * they say while the layout holds:
 *  - PeriodicReauthLockSourceTest takes the FIRST `NavHost(` as "the NavHost
 *    call" and requires the wipe cover before it, so the `RunNavHost` definition
 *    must sit BELOW onCreate (its call inside setContent is then the first hit).
 *  - TorKeepAliveTest compares `.armTorKeepAliveOnBackground()` with the LAST
 *    `finishAndRemoveTask()`; the onCreate helpers contain one, so they must sit
 *    ABOVE onStop. The real ordering is pinned here inside the onStop body.
 *  - The onCreate call order of the launch helpers is load-bearing (cover first,
 *    then the test hooks, the inactivity check, the orphan probe, the retirement
 *    observer, and only then setContent).
 */
class MainActivityStructureSourceTest {

    private val activity: String by lazy {
        SourcePins.stripped(SourcePins.MAIN_ACTIVITY)
    }

    @Test
    fun runNavHost_isDeclaredBelowOnCreate_andCalledAfterTheCover() {
        val onCreateAt = activity.indexOf("override fun onCreate(")
        val defAt = activity.indexOf("private fun RunNavHost(")
        assertTrue("precondition: onCreate and RunNavHost must exist", onCreateAt >= 0 && defAt >= 0)
        assertTrue("RunNavHost must be declared BELOW onCreate", defAt > onCreateAt)
        assertEquals("exactly one NavHost( call in the graph", 1, activity.occurrences("    NavHost(\n"))
        val coverAt = activity.indexOf("if (wipedThisSession || ProcessWipeCover.armed) {")
        val callAt = activity.indexOf("RunNavHost(")
        assertTrue("the RunNavHost call must come after the wipe cover", coverAt in 0 until callAt)
        assertTrue("…and before its own definition", callAt < defAt)
    }

    @Test
    fun launchHelpers_sitAboveOnStop_andRunInOrder() {
        val stopAt = activity.indexOf("override fun onStop()")
        assertTrue("precondition: onStop must exist", stopAt >= 0)
        val helpers = listOf(
            "private fun renderProcessWipeCoverIfArmed(): Boolean {",
            "private fun runLaunchTestHooks() {",
            "private fun selfHealOrphanedCredentials() {",
            "private fun observeSessionRetirement() {",
        )
        for (h in helpers) {
            val at = activity.indexOf(h)
            assertTrue("`$h` must exist", at >= 0)
            assertTrue("`$h` must be declared ABOVE onStop", at < stopAt)
        }
        val body = activity.functionBody("    override fun onCreate(savedInstanceState: Bundle?) {")
        val order = listOf(
            "if (renderProcessWipeCoverIfArmed()) return",
            "runLaunchTestHooks()",
            "InactivityWipe.checkAndWipeIfNeeded(this)",
            "selfHealOrphanedCredentials()",
            "observeSessionRetirement()",
            "setContent {",
        )
        var prev = -1
        for (step in order) {
            val at = body.indexOf(step)
            assertTrue("onCreate must call `$step` after the previous step. Body was:\n$body", at > prev)
            prev = at
        }
        val hooks = activity.functionBody("    private fun runLaunchTestHooks() {")
        assertTrue(
            "handleTestWipe must run before handleTestLanguage",
            hooks.indexOf("TestHooks.handleTestWipe(") in 0 until hooks.indexOf("TestHooks.handleTestLanguage("),
        )
    }

    @Test
    fun onStop_armsTheKeepAliveBeforeItsOwnTeardown() {
        val body = activity.functionBody("    override fun onStop() {")
        val armAt = body.indexOf(".armTorKeepAliveOnBackground()")
        val finishAt = body.indexOf("finishAndRemoveTask()")
        assertTrue("onStop must arm the keep-alive and finish the task", armAt >= 0 && finishAt >= 0)
        assertTrue("the keep-alive must be armed BEFORE finishAndRemoveTask() in onStop", armAt < finishAt)
        assertTrue(
            "the teardown must stay behind the configuration-change guard",
            body.indexOf("if (!isChangingConfigurations) {") in 0 until armAt,
        )
    }

    /**
     * S2 F1 (review 2026-11-06): the Activity's Runnable is its only evaluator of
     * Lever C and the periodic re-auth, and onPause removes it. When onResume
     * re-posted it 10 s out and reset an Activity-local idle clock, rotating the
     * phone every few seconds kept both locks from ever firing. Pins the three
     * parts of the fix: the clock lives in the ViewModel, onResume evaluates at
     * once and only resets the clock when the resume is not a config-change
     * recreation, and onPause marks a config change.
     */
    @Test
    fun idleClock_survivesRecreation_andOnResumeEvaluatesImmediately() {
        assertTrue(
            "the Lever-C idle clock must not be an Activity field (a recreation resets it)",
            !activity.contains("private var lastInteractionMs"),
        )
        val resume = activity.functionBody("    override fun onResume() {")
        assertTrue(
            "onResume must evaluate the watchdog immediately (run/post), not after a delay. Body:\n$resume",
            resume.contains("autoLockCheck.run()") || resume.contains("autoLockHandler.post(autoLockCheck)"),
        )
        assertTrue(
            "onResume must not post the watchdog with a delay",
            !resume.contains("postDelayed(autoLockCheck"),
        )
        val consumeAt = resume.indexOf("if (!vm.consumeConfigurationChangeRecreation()) vm.noteUserInteraction()")
        assertTrue("onResume must skip the idle-clock reset after a configuration change", consumeAt >= 0)
        assertTrue(
            "the idle-clock decision must come before the immediate evaluation",
            consumeAt < resume.indexOf("autoLockCheck.run()").let { if (it < 0) Int.MAX_VALUE else it },
        )
        val pause = activity.functionBody("    override fun onPause() {")
        assertTrue(
            "onPause must hand the config-change flag to the ViewModel",
            pause.contains("if (isChangingConfigurations) runVm?.markConfigurationChangeRecreation()"),
        )
        val interaction = activity.functionBody("    override fun onUserInteraction() {")
        assertTrue(
            "onUserInteraction must update the ViewModel clock through the cached reference only " +
                "(a lookup would construct the ViewModel under the wipe cover)",
            interaction.contains("runVm?.noteUserInteraction()") && !interaction.contains("ViewModelProvider"),
        )
    }

    private fun String.occurrences(needle: String): Int {
        var n = 0
        var i = indexOf(needle)
        while (i >= 0) { n++; i = indexOf(needle, i + needle.length) }
        return n
    }

    private fun String.functionBody(signature: String): String {
        val start = indexOf(signature)
        assertTrue("precondition: `$signature` must exist", start >= 0)
        val indent = signature.takeWhile { it == ' ' }
        val end = indexOf("\n$indent}", start)
        assertTrue("precondition: `$signature` must be closed", end > start)
        return substring(start, end)
    }
}

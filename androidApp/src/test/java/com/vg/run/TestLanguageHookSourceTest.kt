package com.vg.run

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Source guard for the e2e app-language pin (`--es test_language <tag>`), the
 * Android sibling of iOS's `--test-language=` launch argument.
 *
 * WHY A GUARD. The hook is only ever exercised by the e2e device suites, and its three
 * invariants all fail SILENTLY — the suite still runs, it just runs in the
 * device's own language, and every "this text is NOT on screen" assertion then
 * passes for the wrong reason. None of the three is observable from a green
 * local build:
 *
 *  1. ORDER. `TestHooks.handleTestLanguage` must run AFTER
 *     `TestHooks.handleTestWipe` in `MainActivity.onCreate`. The wipe resets the
 *     per-app language to follow-system (WipeRoutine), so pinning before it
 *     is pinning into the wipe's path.
 *  2. ONE-SHOT. The hook must consume the intent extra BEFORE calling
 *     `AppLocale.apply`. Both of apply()'s arms relaunch the Activity (33+ via
 *     LocaleManager, 29-32 via its own `recreate()`), and a relaunch re-delivers
 *     the SAME Intent object — an unconsumed extra is an infinite relaunch loop,
 *     the exact trap TEST_WIPE documents next door.
 *  3. THE KEY IS A CONTRACT WITH THE HARNESS. `e2e-tests/helpers/AppLocale.ts`
 *     puts the extra on the launch; renaming it on either side alone unpins
 *     every device and says nothing. Pinned here because nothing else spans
 *     both trees.
 *
 * Plus the release invariant: the shipped APK must have NO intent-driven
 * language override at all — the release `TestHooks` stub must declare the
 * function (so `MainActivity` can call it unconditionally) and do nothing.
 *
 * Comments are stripped before matching, so the (extensive) prose about these
 * very calls cannot satisfy a check on its own.
 */
class TestLanguageHookSourceTest {

    @Test
    fun mainActivityAppliesTheLanguageHookAfterTheWipeHook() {
        val code = strippedSource(SourcePins.MAIN_ACTIVITY)
        val wipeAt = code.indexOf("TestHooks.handleTestWipe(")
        val langAt = code.indexOf("TestHooks.handleTestLanguage(")
        assertTrue("MainActivity must call TestHooks.handleTestWipe(...)", wipeAt >= 0)
        assertTrue(
            "MainActivity must call TestHooks.handleTestLanguage(this, intent) — without it the " +
                "`--es test_language` launch extra has no effect below API 33, where " +
                "`cmd locale set-app-locales` does not exist (the API-30 bench phone)",
            langAt >= 0,
        )
        assertTrue(
            "TestHooks.handleTestLanguage must run AFTER TestHooks.handleTestWipe: the wipe resets " +
                "the per-app language to follow-system, so a pin applied before it is undone by it",
            langAt > wipeAt,
        )
    }

    @Test
    fun theDebugHookConsumesTheExtraBeforeItRelaunchesTheActivity() {
        val code = strippedSource("androidApp/src/debug/java/com/vg/run/TestHooks.kt")
        assertTrue(
            "the debug TestHooks must read the `$EXTRA_KEY` string extra",
            code.contains("getStringExtra(\"$EXTRA_KEY\")"),
        )
        val removeAt = code.indexOf("removeExtra(\"$EXTRA_KEY\")")
        val applyAt = code.indexOf("AppLocale.apply(")
        assertTrue("the debug TestHooks must consume the extra with removeExtra", removeAt >= 0)
        assertTrue("the debug TestHooks must apply the tag via AppLocale.apply", applyAt >= 0)
        assertTrue(
            "removeExtra must come BEFORE AppLocale.apply: apply() relaunches the Activity on both " +
                "API arms and the relaunch re-delivers the same Intent, so an unconsumed extra " +
                "re-applies and re-relaunches forever",
            removeAt < applyAt,
        )
    }

    @Test
    fun theReleaseStubIsAHardNoOp() {
        val code = strippedSource("androidApp/src/release/java/com/vg/run/TestHooks.kt")
        assertTrue(
            "the release TestHooks must declare handleTestLanguage so MainActivity can call it " +
                "unconditionally",
            code.contains("fun handleTestLanguage("),
        )
        assertTrue(
            "the release TestHooks must NOT apply a language override — a shipped APK has no " +
                "intent-driven language path at all",
            !code.contains("AppLocale.apply("),
        )
        assertTrue(
            "the release TestHooks must not read the $EXTRA_KEY extra either",
            !code.contains(EXTRA_KEY),
        )
    }

    @Test
    fun theHarnessSendsTheSameExtraKey() {
        val harness = File(repoRoot(), "e2e-tests/helpers/AppLocale.ts")
        assertTrue("the e2e harness helper is missing: ${harness.path}", harness.isFile)
        val ts = harness.readText()
        assertTrue(
            "e2e-tests/helpers/AppLocale.ts must name the same intent-extra key ($EXTRA_KEY) the " +
                "app reads — renaming it on one side alone silently unpins every device",
            ts.contains("'$EXTRA_KEY'") || ts.contains("\"$EXTRA_KEY\""),
        )
        assertTrue(
            "the harness must pass the key as a STRING extra (`--es`), matching getStringExtra",
            ts.contains("'--es'") || ts.contains("\"--es\"") || ts.contains("--es "),
        )
    }

    // -----------------------------------------------------------------------

    private fun strippedSource(relPath: String): String {
        val f = File(repoRoot(), relPath)
        assertTrue("scanned source file is missing: $relPath", f.isFile)
        return stripComments(f.readText())
    }

    companion object {
        /** The intent-extra key, spelled once here and asserted on both sides. */
        private const val EXTRA_KEY = "test_language"
    }
}

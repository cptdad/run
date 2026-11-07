package com.vg.run

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Task #11 (2026-07-31) — source guard: **no production Android code may write
 * SharedPreferences with `apply()`.**
 *
 * WHY A GUARD AND NOT JUST A FIX. `apply()` SNAPSHOTS the whole in-memory map
 * and hands it to a background flush. `Context.deleteSharedPreferences` (what
 * `WipeRoutine` runs over every prefs file) evicts the ContextImpl cache entry
 * and unlinks the file but neither cancels nor awaits that queued flush, and
 * `SharedPreferencesImpl.writeToFile` only short-circuits the "nothing changed"
 * case when the file still EXISTS. So a write issued moments before a wipe lands
 * AFTER it and RE-CREATES the file from the pre-wipe snapshot — `vlt_a`,
 * `vlt_c`, `vlt_rc` or the encrypted last-active timestamp back on disk, dated
 * after the crypto-erase. This exact primitive (a write that outlives the wipe
 * that was supposed to erase it) produced THREE separate bugs in one day, so the fixed state is worth pinning mechanically rather
 * than by review: the remaining `apply()` sites were `KeyValueStore.putString` /
 * `remove` and `InactivityWipe.refreshMtimeProbe`, and every prefs write in the
 * app now uses `commit()`.
 *
 * A source scan rather than a behavioural test because the property is
 * "nowhere", not "here": a behavioural test can only cover call sites that
 * already exist, which is precisely how the fourth instance of this bug gets
 * written. The behavioural half lives in the instrumented
 * KeyValueStoreWriteDurabilityTest (SharedPreferences needs a real Android
 * runtime; this project has no Robolectric).
 *
 * Comments are stripped before matching, so prose that merely NAMES `apply()` —
 * of which the fixed files have a lot — cannot trip it.
 */
class PrefsApplySourceGuardTest {

    @Test
    fun noProductionAndroidSourceCallsApplyOnASharedPreferencesEditor() {
        val offenders = mutableListOf<String>()

        for (dir in SCANNED_DIRS) {
            val root = File(repoRoot(), dir)
            assertTrue("scanned source dir is missing: $dir", root.isDirectory)
            root.walkTopDown()
                .filter { it.isFile && it.extension == "kt" }
                .filterNot { f -> f.relativeTo(root).invariantSeparatorsPath.substringBefore('/') in TEST_SOURCE_SETS }
                .forEach { f ->
                    val code = stripComments(f.readText()).replace(WHITESPACE, " ")
                    if (EDITOR_APPLY.containsMatchIn(code)) {
                        offenders += f.relativeTo(repoRoot()).path
                    }
                }
        }

        assertTrue(
            "SharedPreferences must be written with commit(), never apply() — a queued " +
                "apply() can flush AFTER WipeRoutine deletes the file and re-create it from " +
                "the pre-wipe snapshot. Offending file(s): $offenders",
            offenders.isEmpty(),
        )
    }

    /**
     * Sanity check on the detector itself: a guard that can never fire is worse
     * than no guard, because it reads as coverage. Fabricated source, both the
     * one-line and the wrapped-chain shape.
     */
    @Test
    fun theDetectorActuallyDetects() {
        val positives = listOf(
            "prefs.edit().putString(k, v).apply()",
            "prefs.edit()\n    .remove(k)\n    .apply()",
            "context.getSharedPreferences(N, MODE).edit().putBoolean(k, true).apply()",
        )
        for (src in positives) {
            assertTrue(
                "detector missed: $src",
                EDITOR_APPLY.containsMatchIn(stripComments(src).replace(WHITESPACE, " ")),
            )
        }

        val negatives = listOf(
            "prefs.edit().putString(k, v).commit()",
            // Kotlin's scope function takes a lambda, never parentheses.
            "KeyGenerator.getInstance(A, B).apply { init(spec) }.generateKey()",
            // Prose naming apply() is stripped with the comment it lives in.
            "// commit(), NOT apply() — see the class kdoc.\nprefs.edit().remove(k).commit()",
            "/* apply() snapshots the map */ prefs.edit().putString(k, v).commit()",
        )
        for (src in negatives) {
            assertTrue(
                "detector false-positived on: $src",
                !EDITOR_APPLY.containsMatchIn(stripComments(src).replace(WHITESPACE, " ")),
            )
        }
    }

    // -----------------------------------------------------------------------

    companion object {
        /**
         * The whole Android production surface, by DIRECTORY rather than by a
         * list of source-set names, so a flavor/build-type dir added later
         * (`androidApp/src/main`, `/foss`, `/google`, `/debug`, `/release`,
         * `/googleDebug`, …) is covered without anyone remembering to extend a
         * list — the "a named list cannot defend against a file we never knew
         * was created" lesson from `WipeRoutine`'s databases/ sweep.
         * commonMain/iosMain have no SharedPreferences at all.
         */
        private val SCANNED_DIRS = listOf(
            "androidApp/src",
            "shared/src/androidMain",
        )

        /**
         * Excluded: test sources seed prefs directly and are not part of the
         * shipped wipe surface. (Named relative to `androidApp/src`; the
         * shared/androidMain root has no such children.)
         */
        private val TEST_SOURCE_SETS = setOf("test", "androidTest")

        private val WHITESPACE = Regex("""\s+""")

        /**
         * `.edit()` … `.apply()` within one statement. The bound keeps it from
         * pairing an editor with an unrelated `apply()` far below, and `{}`/`;`
         * are excluded so it cannot span a block boundary. `.apply()` with
         * PARENTHESES is unambiguously `SharedPreferences.Editor.apply` — Kotlin's
         * scope function is `apply { ... }`.
         */
        private val EDITOR_APPLY = Regex("""\.edit\(\)[^;{}]{0,400}?\.apply\(\)""")
    }
}

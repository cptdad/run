package com.vg.run

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * A Compose `Dialog` / `Popup` renders in its own window, so touches inside it
 * never reach `Activity.onUserInteraction` and the Lever-C idle clock sees a
 * user reading or tapping in it as idle (DialogInteraction.kt). Every raw
 * `Dialog(` / `Popup(` under androidApp/src/main must therefore feed the clock
 * from its content ROOT: `keepUnlockedOnInteraction()` must appear in the
 * trailing content lambda before the root composable's own content block opens
 * (the first `) {`).
 *
 * Exempt by name: `LockCountdownOverlay` (MainActivity) — its tap IS the "stay"
 * action, and the re-auth variant is non-dismissable on purpose.
 *
 * Comment-stripped, so prose cannot satisfy the guard.
 */
class DialogKeepUnlockedSweepSourceTest {

    private val exemptFunctions = setOf("LockCountdownOverlay")
    private val call = Regex("""(?<![A-Za-z0-9_.])(Dialog|Popup)\(""")

    @Test
    fun everyDialogAndPopupRoot_feedsTheIdleClock() {
        val mainDir = File(repoRoot(), "androidApp/src/main/java")
        val offenders = mutableListOf<String>()
        var seen = 0
        mainDir.walkTopDown().filter { it.isFile && it.extension == "kt" }.forEach { f ->
            val src = stripComments(f.readText())
            for (m in call.findAll(src)) {
                // Skip declarations (`fun RuneDialog(` etc. never match: the regex
                // needs the bare name), and anything that is not a call site.
                val before = src.substring(maxOf(0, m.range.first - 4), m.range.first)
                if (before.endsWith("fun ")) continue
                seen++
                val enclosing = Regex("""fun\s+(?:[A-Za-z0-9_.]+\.)?([A-Za-z0-9_]+)\s*\(""")
                    .findAll(src.substring(0, m.range.first)).lastOrNull()?.groupValues?.get(1)
                if (enclosing in exemptFunctions) continue
                val argsClose = matchingParen(src, m.range.last)
                val lambdaOpen = src.indexOf('{', argsClose)
                val between = src.substring(argsClose + 1, lambdaOpen)
                val line = src.substring(0, m.range.first).count { it == '\n' } + 1
                if (between.isNotBlank()) {
                    offenders += "${f.name}:$line (no trailing content lambda)"
                    continue
                }
                val body = braceBody(src, lambdaOpen, includeBraces = false)
                val keepAt = body.indexOf("keepUnlockedOnInteraction()")
                val rootContentAt = body.indexOf(") {").let { if (it < 0) Int.MAX_VALUE else it }
                if (keepAt < 0 || keepAt > rootContentAt) offenders += "${f.name}:$line in $enclosing"
            }
        }
        assertTrue("the sweep must see the app's Dialog/Popup windows (saw $seen)", seen >= 7)
        assertTrue(
            "every Dialog/Popup content root must call Modifier.keepUnlockedOnInteraction() " +
                "(DialogInteraction.kt). Missing: $offenders",
            offenders.isEmpty(),
        )
    }

    private fun matchingParen(src: String, open: Int): Int {
        var depth = 0
        for (i in open until src.length) {
            when (src[i]) {
                '(' -> depth++
                ')' -> { depth--; if (depth == 0) return i }
            }
        }
        throw AssertionError("unbalanced parentheses from $open")
    }
}

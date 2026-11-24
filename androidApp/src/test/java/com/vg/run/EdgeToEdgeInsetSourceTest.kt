package com.vg.run

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The app draws edge to edge, so a screen that pads for the STATUS bar and forgets the
 * NAVIGATION bar ends under it: on a phone with a three-button bar the last control of a
 * scrolling column is covered and no amount of scrolling brings it out.
 *
 * Found on the Samsung A20e, 2026-11-24, by the screenshot check of the protection-level
 * screen (e2e-tests/helpers/visual): "Cancel" sat under the navigation bar and was not in
 * the element tree at all. RecoveryCodeScreen had the same column.
 *
 * SOURCE-LEVEL, like this file's siblings: the unit-test tier has no Compose host. The
 * rule is deliberately coarse — a file that names the top inset must name a bottom one —
 * and is checked with comments stripped. The runtime companion is the screenshot check
 * `protection-settings`, which requires `protection_level_back` on screen.
 */
class EdgeToEdgeInsetSourceTest {

    private val screensDir = File(repoRoot(), "androidApp/src/main/java/com/vg/run")

    private val bottomInset = listOf(
        "navigationBarsPadding()", "systemBarsPadding()", "safeDrawingPadding()",
        "WindowInsets.navigationBars", "WindowInsets.systemBars", "WindowInsets.safeDrawing",
    )

    @Test
    fun `every screen that pads for the status bar also pads for the navigation bar`() {
        val files = screensDir.listFiles { f -> f.isFile && f.name.endsWith(".kt") }.orEmpty().sortedBy { it.name }
        val padded = files.filter { stripComments(it.readText()).contains("statusBarsPadding()") }
        assertTrue("precondition: screens that pad for the status bar exist", padded.size >= 10)
        val missing = padded.filter { f ->
            val src = stripComments(f.readText())
            bottomInset.none { src.contains(it) }
        }.map { it.name }
        assertTrue(
            "these screens pad for the status bar but never for the navigation bar, so their last " +
                "control can end under it: $missing",
            missing.isEmpty(),
        )
    }

    @Test
    fun `the protection level and recovery code columns pad for the navigation bar before they scroll`() {
        for (name in listOf("ProtectionLevelScreen.kt", "RecoveryCodeScreen.kt")) {
            val src = stripComments(File(screensDir, name).readText())
            val inset = src.indexOf(".navigationBarsPadding()")
            val scroll = src.indexOf(".verticalScroll(")
            assertTrue("$name: the column pads for the navigation bar", inset >= 0)
            assertTrue("$name: the padding is applied outside the scroll, not inside it", scroll > inset)
        }
    }
}

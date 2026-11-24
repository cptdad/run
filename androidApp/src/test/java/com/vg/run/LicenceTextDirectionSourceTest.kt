package com.vg.run

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The licence texts are English in every app language and are laid out LEFT-TO-RIGHT.
 *
 * Found in the Arabic reference pictures of the Licences screen (iPhone 12 and Samsung
 * A20e, 2026-11-24): under the app's right-to-left direction every line was right-aligned
 * and its closing punctuation moved to the start of the line.
 *
 * SOURCE-LEVEL, like this file's siblings; comments are stripped before scanning.
 */
class LicenceTextDirectionSourceTest {

    @Test
    fun `android - the licence body is laid out left-to-right`() {
        val src = stripComments(File(repoRoot(), "androidApp/src/main/java/com/vg/run/LicencesScreen.kt").readText())
        val provider = "CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr)"
        assertTrue("the licence body must be wrapped in an LTR layout direction", src.contains(provider))
        assertTrue(
            "the LTR direction must cover the texts, not the title row",
            src.indexOf(provider) > src.indexOf("about_info_licences_close") &&
                src.indexOf(provider) < src.indexOf("FontFamily.Monospace"),
        )
    }

    @Test
    fun `ios - the licence body is laid out left-to-right`() {
        val src = File(repoRoot(), "iosApp/iosApp/ContactListView.swift").readText()
        val body = src.substringAfter("Text(verbatim: t.body)").substringBefore("about_info_licences_screen")
        assertTrue("the licence body must set a left-to-right layout direction", body.contains(".environment(\\.layoutDirection, .leftToRight)"))
    }
}

package com.vg.run

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * A string read through the APPLICATION context speaks the PHONE's language below API 33
 * (the per-app language is applied to activity contexts there, see [AppLocale.wrap]).
 *
 * Found on the Samsung A20e (Android 11, Swedish system language, Rún set to English),
 * 2026-11-24, by the screenshot check of the Support screen: the tip jar's "tips cannot be
 * given on this device" came out in Swedish between English lines. TipBillingManager kept
 * `context.applicationContext` for the messages its billing callbacks produce.
 *
 * SOURCE-LEVEL, like this file's siblings; comments are stripped before scanning.
 */
class AppContextStringLocaleSourceTest {

    private val sourceRoots = listOf(
        "androidApp/src/main/java/com/vg/run",
        "androidApp/src/google/kotlin/com/vg/run",
        "androidApp/src/foss/kotlin/com/vg/run",
    )

    private fun sources(): List<Pair<String, String>> = sourceRoots.flatMap { root ->
        File(repoRoot(), root).walkTopDown().filter { it.isFile && it.name.endsWith(".kt") }
            .map { it.name to stripComments(it.readText()) }.toList()
    }

    @Test
    fun `the tip jar resolves its messages in the app language`() {
        val tipJar = stripComments(File(repoRoot(), "androidApp/src/google/kotlin/com/vg/run/TipJar.kt").readText())
        assertTrue(
            "TipBillingManager must wrap the application context in the app's language",
            tipJar.contains("AppLocale.wrap(context.applicationContext)"),
        )
        assertFalse(
            "TipBillingManager must not keep a bare application context for getString",
            Regex("""appContext\s*=\s*context\.applicationContext\s*\n""").containsMatchIn(tipJar),
        )
    }

    @Test
    fun `no user-facing string is read straight off the application context`() {
        val all = sources()
        assertTrue("precondition: sources found", all.size > 20)
        val offenders = all.filter { (_, src) ->
            src.contains("applicationContext.getString(") || src.contains("applicationContext.resources.getString(")
        }.map { it.first }
        assertTrue(
            "read these strings through AppLocale.wrap(applicationContext) instead — below API 33 " +
                "the application context ignores the in-app language: $offenders",
            offenders.isEmpty(),
        )
    }
}

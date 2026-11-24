package com.vg.run

import java.io.File
import kotlin.test.Test
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// RÚN-06 — the contact-delete rewrite of the admin-of-record tombstone must land
// on BOTH platforms and in the test double, inside each `deleteContact`.
//
// A SOURCE guard (same shape as LegacyMessageTableRemovalTest): the iOS actual
// cannot run in the JVM suite, and a rewrite present on one platform only would
// leave a deleted contact's id in one platform's vaults while the commonTest
// suite (which runs InMemoryVault) stays green. The behaviour itself is pinned by
// GroupDeletionResidueTest (commonTest) through InMemoryVault.
// ---------------------------------------------------------------------------
class GroupAdminTombstoneParityTest {

    @Test
    fun everyDeleteContactRewritesTheTombstone() {
        for ((label, path) in SOURCES) {
            val body = deleteContactBody(source(path), label)
            assertTrue(
                body.contains("groupAdminTombstoneNamesContact("),
                "$label.deleteContact must classify admin-of-record tombstones with the shared " +
                    "groupAdminTombstoneNamesContact predicate.",
            )
            assertTrue(
                body.contains("GroupAdminTombstone.DELETED_ADMIN"),
                "$label.deleteContact must rewrite a matching tombstone to GroupAdminTombstone.DELETED_ADMIN.",
            )
        }
    }

    @Test
    fun theDetectorActuallyDetects() {
        val without = "override fun deleteContact(contactId: String) {\n for (k in metaKeys()) {}\n}\n override fun x() {}"
        val body = deleteContactBody(without, "fabricated")
        assertTrue(!body.contains("groupAdminTombstoneNamesContact("), "detector false-positived")
        assertTrue(body.contains("metaKeys()"), "body extraction failed")
    }

    // -----------------------------------------------------------------------

    /** Text from `fun deleteContact(` to the next `override fun` / `fun ` declaration at any depth. */
    private fun deleteContactBody(src: String, label: String): String {
        val start = src.indexOf("override fun deleteContact(")
        assertTrue(start >= 0, "$label has no deleteContact override")
        val next = Regex("""\n\s*(override\s+)?(public\s+|internal\s+|private\s+)?fun\s""")
            .find(src, start + 1)?.range?.first ?: src.length
        return src.substring(start, next)
    }

    private fun source(path: String): String {
        val f = File(repoRoot(), path)
        assertTrue(f.isFile, "scanned source is missing: $path")
        return f.readText().replace(BLOCK_COMMENT, " ").replace(LINE_COMMENT, " ")
    }

    private fun repoRoot(): File {
        var d: File? = File("").absoluteFile
        while (d != null) {
            if (File(d, "settings.gradle.kts").isFile) return d
            d = d.parentFile
        }
        throw AssertionError("repo root not found above ${File("").absoluteFile}")
    }

    private companion object {
        val SOURCES = listOf(
            "DatabaseManager" to "shared/src/androidMain/kotlin/com/vg/run/DatabaseManager.kt",
            "IosVaultDatabase" to "shared/src/iosMain/kotlin/com/vg/run/IosVaultDatabase.kt",
            "InMemoryVault" to "shared/src/commonTest/kotlin/com/vg/run/support/InMemoryVault.kt",
        )
        val BLOCK_COMMENT = Regex("""/\*.*?\*/""", RegexOption.DOT_MATCHES_ALL)
        val LINE_COMMENT = Regex("""//[^\n]*""")
    }
}

package com.vg.run

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

// Pins the in-app "Licences and notices" bundle (LicencesScreen.kt / iOS
// LicencesView) to the repo-root files it claims to show.
//
// The platform copies are committed, produced by scripts/sync-licence-bundle.sh.
// A root licence edit without a re-sync would ship a stale legal text silently —
// nothing renders differently enough to notice — so this fails the JVM suite
// instead. Fix a red here by running `./scripts/sync-licence-bundle.sh`.
class LicenceBundleTest {

    // Display order, and each bundled name's canonical root file.
    private val expected = linkedMapOf(
        "LICENSE-EXCEPTION" to "LICENSE-EXCEPTION",
        "LICENSE" to "LICENSE",
        "THIRD_PARTY_NOTICES.md" to "THIRD_PARTY_NOTICES.md",
        "OFL.txt" to "assets/fonts/OFL.txt",
    )

    private fun assertBundle(dir: File) {
        assertTrue("${dir.path} missing — run scripts/sync-licence-bundle.sh", dir.isDirectory)
        val names = dir.listFiles().orEmpty().filter { it.isFile && !it.name.startsWith(".") }.map { it.name }.sorted()
        assertEquals("${dir.path} must hold exactly the four licence files", expected.keys.sorted(), names)
        expected.forEach { (name, rootRel) ->
            val root = File(repoRoot(), rootRel)
            assertTrue("root file $rootRel missing", root.isFile)
            assertArrayEquals(
                "${dir.path}/$name differs from $rootRel — run scripts/sync-licence-bundle.sh",
                root.readBytes(),
                File(dir, name).readBytes(),
            )
        }
    }

    @Test
    fun androidAssetCopiesAreByteIdenticalToRootFiles() {
        assertBundle(File(repoRoot(), "androidApp/src/main/assets/$LICENCE_ASSET_DIR"))
    }

    @Test
    fun iosBundleCopiesAreByteIdenticalToRootFiles() {
        assertBundle(File(repoRoot(), "iosApp/iosApp/Licences"))
    }

    @Test
    fun androidDisplayOrderIsPinned() {
        assertEquals(expected.keys.toList(), LICENCE_BUNDLE_FILES)
    }

    @Test
    fun iosDisplayOrderMatchesAndroid() {
        val swift = stripComments(File(repoRoot(), "iosApp/iosApp/ContactListView.swift").readText())
        val literal = expected.keys.joinToString(", ") { "\"$it\"" }
        assertTrue(
            "iOS LicencesView must list the files in the Android order: [$literal]",
            swift.contains("[$literal]"),
        )
    }

    @Test
    fun iosLicencesFolderIsAResourceFolderReference() {
        val pbx = File(repoRoot(), "iosApp/iosApp.xcodeproj/project.pbxproj").readText()
        assertTrue(
            "Licences must be a folder reference (lastKnownFileType = folder)",
            Regex("""isa = PBXFileReference; lastKnownFileType = folder; path = Licences;""").containsMatchIn(pbx),
        )
        assertTrue("Licences must be in the Resources build phase", pbx.contains("/* Licences in Resources */,"))
    }
}

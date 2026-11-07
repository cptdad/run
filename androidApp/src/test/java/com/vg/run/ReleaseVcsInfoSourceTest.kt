package com.vg.run

import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The release build must not embed `META-INF/version-control-info.textproto` (AGP
 * writes the HEAD commit SHA there by default). The public repo is a one-commit
 * snapshot, so a private SHA in the shipped binary would match nothing public and
 * would leak where the private history stands.
 *
 * SOURCE-LEVEL: the JVM tier cannot run bundleRelease, so this pins the DSL line
 * inside the `release { … }` build type of androidApp/build.gradle.kts. Comments are
 * stripped first so prose that names the setting cannot satisfy the guard.
 */
class ReleaseVcsInfoSourceTest {

    private val gradle = "androidApp/build.gradle.kts"

    @Test
    fun releaseBuildTypeExcludesVcsInfo() {
        val src = SourcePins.stripped(gradle)
        val buildTypes = src.indexOf("buildTypes {")
        assertTrue("$gradle: no buildTypes block", buildTypes >= 0)
        val release = src.indexOf("release {", buildTypes)
        assertTrue("$gradle: no release build type", release >= 0)
        val body = braceBody(src, src.indexOf('{', release))
        val vcsOff = Regex("""vcsInfo\s*\{\s*include\s*=\s*false\s*\}|vcsInfo\.include\s*=\s*false""")
        assertTrue(
            "$gradle: the release build type must set `vcsInfo { include = false }` so the " +
                "AAB/APK carries no META-INF/version-control-info.textproto (private commit SHA)",
            vcsOff.containsMatchIn(body),
        )
    }

    @Test
    fun noBuildTypeReEnablesVcsInfo() {
        val src = SourcePins.stripped(gradle)
        assertTrue(
            "$gradle: vcsInfo include = true found — the private commit SHA would ship",
            !Regex("""vcsInfo(\s*\{[^}]*|\s*\.\s*)include\s*=\s*true""").containsMatchIn(src),
        )
    }
}

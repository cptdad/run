package com.vg.run

import java.io.File

/**
 * IntegrityCheck — detects rooted Android devices.
 *
 * Checks for common root indicators:
 *   - su binary in common paths
 *   - Magisk or SuperSU management apps
 *   - Test-keys build signature
 */
object IntegrityCheck {

    val isCompromised: Boolean by lazy {
        hasSuBinary() || hasRootApps() || hasTestKeys()
    }

    private fun hasSuBinary(): Boolean {
        val paths = listOf(
            "/system/bin/su", "/system/xbin/su", "/sbin/su",
            "/system/su", "/data/local/xbin/su", "/data/local/bin/su",
            "/system/sd/xbin/su", "/system/bin/failsafe/su",
            "/data/local/su", "/su/bin/su"
        )
        return paths.any { File(it).exists() }
    }

    private fun hasRootApps(): Boolean {
        val packages = listOf(
            "com.topjohnwu.magisk",
            "eu.chainfire.supersu",
            "com.koushikdutta.superuser",
            "com.noshufou.android.su"
        )
        // Check via package manager would need context; check common data dirs instead
        return packages.any { pkg ->
            File("/data/data/$pkg").exists()
        }
    }

    private fun hasTestKeys(): Boolean {
        val buildTags = android.os.Build.TAGS
        return buildTags != null && buildTags.contains("test-keys")
    }
}

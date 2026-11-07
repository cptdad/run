package com.vg.run

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import java.security.MessageDigest

// ---------------------------------------------------------------------------
// The running APK's signing-certificate SHA-256, shown in the About-info modal
// so a user can compare it with the published fingerprint (and with
// `apksigner verify --print-certs` on a self-built or downloaded APK).
// Android only: an App Store binary is re-signed by Apple, so iOS shows nothing.
// ---------------------------------------------------------------------------

// Uppercase, colon-separated hex ("AB:CD:…") of SHA-256(der). Pure, so the
// format is unit-tested (SigningCertFingerprintTest).
internal fun sha256ColonHex(der: ByteArray): String =
    MessageDigest.getInstance("SHA-256").digest(der).joinToString(":") { "%02X".format(it.toInt() and 0xFF) }

// The fingerprint of the certificate that signed the installed APK (the
// current signer — apkContentsSigners, i.e. the newest entry of the rotation
// history), or null if the platform does not hand it over. Never throws.
internal fun signingCertSha256(context: Context): String? =
    try {
        val pm = context.packageManager
        val info = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getPackageInfo(
                context.packageName,
                PackageManager.PackageInfoFlags.of(PackageManager.GET_SIGNING_CERTIFICATES.toLong()),
            )
        } else {
            // minSdk 30 >= 28, so GET_SIGNING_CERTIFICATES is always available.
            @Suppress("DEPRECATION")
            pm.getPackageInfo(context.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
        }
        info.signingInfo?.apkContentsSigners?.firstOrNull()?.toByteArray()?.let(::sha256ColonHex)
    } catch (_: Exception) {
        null
    }

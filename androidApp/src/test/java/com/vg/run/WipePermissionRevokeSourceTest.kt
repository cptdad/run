package com.vg.run

import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Review 2026-11-06, S1 F1: every wipe (they all funnel into
 * `WipeRoutine.wipePersistentState`) gives back the CAMERA and
 * POST_NOTIFICATIONS grants on API 33+, because each grant proves one feature
 * was used. The call must be the LAST step: after the crypto-erase (key
 * material first is the wipe's core invariant) and after every file delete,
 * since the revocation ends the process once it leaves the foreground.
 */
class WipePermissionRevokeSourceTest {

    private val wipe: String by lazy { SourcePins.stripped(SourcePins.WIPE_ROUTINE) }

    @Test
    fun revocation_isTheLastStep_afterTheEraseAndTheDeletes() {
        val start = wipe.indexOf("fun wipePersistentState(context: Context) {")
        assertTrue("precondition: wipePersistentState must exist", start >= 0)
        val end = wipe.indexOf("\n    }\n", start)
        val body = wipe.substring(start, end)

        val revokeAt = body.indexOf("revokeSelfPermissionsOnKill(")
        assertTrue("the wipe must revoke the feature grants. Body:\n$body", revokeAt >= 0)
        assertTrue(
            "both feature grants are revoked",
            body.contains("android.Manifest.permission.CAMERA") &&
                body.contains("android.Manifest.permission.POST_NOTIFICATIONS"),
        )
        assertTrue(
            "gated on API 33 (TIRAMISU), where the API exists",
            body.lastIndexOf("VERSION_CODES.TIRAMISU", revokeAt) >= 0,
        )
        for (earlier in listOf(
            "PREFS_FILES.forEach { context.deleteSharedPreferences(it) }",
            "VendorPush.sweepLocalArtifacts(app)",
            """java.io.File(context.filesDir, "tor_direct").deleteRecursively()""",
            "NotificationHelper.deleteChannel(context)",
            "ConnectionLog.clear()",
        )) {
            val at = body.indexOf(earlier)
            assertTrue("`$earlier` must exist in the wipe", at >= 0)
            assertTrue("`$earlier` must run BEFORE the permission revocation", at < revokeAt)
        }
        // The crypto-erase is the very first part of the routine; the revocation
        // must follow every key deletion it makes.
        for (erase in listOf("CryptoManager.eraseMasterKey(context)", "AuthBoundKeyStore.deleteKey(context)")) {
            val at = body.indexOf(erase)
            assertTrue("precondition: `$erase` must be in the routine", at >= 0)
            assertTrue("the revocation must follow `$erase`", at < revokeAt)
        }
        val tail = body.substring(revokeAt)
        assertTrue(
            "best-effort: the revocation is wrapped so a throw never aborts the wipe",
            body.lastIndexOf("try {", revokeAt) > body.lastIndexOf("ConnectionLog.clear()") &&
                tail.contains("catch (_: Exception)"),
        )
    }
}

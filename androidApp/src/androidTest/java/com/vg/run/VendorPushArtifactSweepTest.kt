package com.vg.run

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Push opt-out left the Firebase identity alive.
 *
 * Deterministic, non-network half of the fix: [VendorPush.sweepLocalArtifacts]
 * — new in this change — must delete the SAME on-disk Firebase/FCM artifacts
 * `WipeRoutine`'s private `deleteVendorPushArtifacts` removes on a full wipe
 * (mirrors [WipeRoutineResidueTest.wipe_deletesVendorPushArtifacts], scoped to
 * the new function instead of the whole wipe). The async, network-dependent
 * half — `VendorPush.destroyLocalPushIdentity`'s `deleteToken()` /
 * `FirebaseInstallations.delete()` round trip — is NOT exercised here, same
 * reasoning [WipeRoutineResidueTest]'s own kdoc gives for not exercising its
 * post-settle re-sweep pass.
 *
 * Run with: ./gradlew connectedAndroidTest --tests "*.VendorPushArtifactSweepTest"
 */
class VendorPushArtifactSweepTest {

    @Test
    fun sweepLocalArtifacts_removesFcmArtifacts() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        // A teardown in an EARLIER test of this run schedules delete-only passes
        // over these same artifacts for up to 10 s (VendorPush's late sweeps).
        // Let them finish before seeding, or one lands mid-setup and the "seeds
        // must exist" guard fails for a reason unrelated to the sweep.
        VendorPush.awaitLateSweepsForTest(20_000)

        ctx.getSharedPreferences("com.google.android.gms.appid", Context.MODE_PRIVATE)
            .edit().putString("token|T|*|", "fake-registration-token").commit()
        ctx.getSharedPreferences("com.google.firebase.messaging", Context.MODE_PRIVATE)
            .edit().putBoolean("auto_init", true).commit()
        val appIdPrefs = File(ctx.dataDir, "shared_prefs/com.google.android.gms.appid.xml")
        val fcmPrefs = File(ctx.dataDir, "shared_prefs/com.google.firebase.messaging.xml")
        // Legacy (pre-19.1.2) location — still seeded so an install that never
        // migrated stays covered.
        val fid = File(ctx.filesDir, "PersistedInstallation.W0RFRkFVTFRd.json")
            .apply { writeText("{\"Fid\":\"fake-installation-id\"}") }
        // 5A-1: firebase-installations 19.1.2 (this app's pinned firebase-bom
        // 34.18.0) moved PersistedInstallation's data file here FIRST.
        val fidNoBackup = File(ctx.noBackupFilesDir, "PersistedInstallation.W0RFRkFVTFRd.json")
            .apply { writeText("{\"Fid\":\"fake-installation-id\",\"AuthToken\":\"fake-auth\"}") }
        val noBackup = File(ctx.noBackupFilesDir, "com.google.android.gms.appid-no-backup")
            .apply { writeText("1") }
        // 2C-2 sibling: FirebaseInstallations' cross-process lock file.
        val fidLock = File(ctx.filesDir, "generatefid.lock").apply { writeText("") }
        // 2C-1 sibling: the Firebase heartbeat androidx.datastore store.
        val datastoreDir = File(ctx.filesDir, "datastore").apply { mkdirs() }
        val heartbeat = File(datastoreDir, "FirebaseHeartBeatW0RFRkFVTFRd.preferences_pb")
            .apply { writeText("fake heartbeat datastore") }
        assertTrue(
            "seeds must exist before the sweep",
            appIdPrefs.exists() && fcmPrefs.exists() && fid.exists() && fidNoBackup.exists() &&
                noBackup.exists() && fidLock.exists() && heartbeat.exists(),
        )

        try {
            VendorPush.sweepLocalArtifacts(ctx)

            assertFalse("the FCM token store must be gone", appIdPrefs.exists())
            assertFalse("the FCM auto-init prefs must be gone", fcmPrefs.exists())
            assertFalse("the legacy-location Firebase Installation ID must be gone", fid.exists())
            assertFalse(
                "the no_backup-location Firebase Installation ID (19.1.2+) must be gone",
                fidNoBackup.exists(),
            )
            assertFalse("the appid no-backup marker must be gone", noBackup.exists())
            assertFalse("the FirebaseInstallations cross-process lock file must be gone", fidLock.exists())
            assertFalse("the Firebase heartbeat datastore dir must be gone", datastoreDir.exists())
        } finally {
            // Belt-and-braces cleanup regardless of outcome.
            ctx.deleteSharedPreferences("com.google.android.gms.appid")
            ctx.deleteSharedPreferences("com.google.firebase.messaging")
            fid.delete()
            fidNoBackup.delete()
            noBackup.delete()
            fidLock.delete()
            datastoreDir.deleteRecursively()
        }
    }

    /**
     * The `com.google.android.gms.appid-no-backup` marker again, on its own,
     * because it is NOT residue — it is the SDK's own token-cache invalidator,
     * and deleting it is the only lever this app has over a FUTURE process.
     *
     * Mechanism (verified against firebase-messaging 24.1.0 bytecode).
     * `Store.<init>` calls `checkForRestore(context, "com.google.android.gms
     * .appid-no-backup")`. That method returns immediately if the marker exists;
     * if it is MISSING it recreates it and — when the token prefs are non-empty —
     * logs "App restored, clearing state" and calls `deleteAll()` on them. The
     * mechanism exists for backup/restore onto a new device, where a restored
     * token belongs to another installation; a destroyed installation is the
     * same situation reached from the other direction.
     *
     * Why that matters here (2026-08-09): `FirebaseMessaging.deleteToken()`
     * evicts the in-`Store` token only when its network RPC succeeds, while the
     * chained `FirebaseInstallations.delete()` runs regardless. A teardown whose
     * revocation failed therefore leaves a live cached token bound to a
     * destroyed installation — a token FCM keeps answering 2xx for and the
     * device never receives. `VendorPushIdentityEpoch` covers the CURRENT
     * process (`currentToken` must prove a delete before it fetches); this
     * marker deletion covers the NEXT one, where the latch is gone but a stale
     * `com.google.android.gms.appid` file could still be read back.
     *
     * So: do not "optimise" the marker deletion away as a duplicate of the
     * `deleteSharedPreferences("com.google.android.gms.appid")` a few lines
     * above it. That call removes the file; this one removes the SDK's reason to
     * trust whatever file is there next time.
     *
     * Non-vacuousness: deleting the `noBackupFilesDir` line from
     * `VendorPush.sweepLocalArtifacts` fails this test.
     */
    @Test
    fun sweepLocalArtifacts_deletesTheSdkTokenCacheInvalidatorMarker() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        VendorPush.awaitLateSweepsForTest(20_000)   // see the sibling test above

        val noBackup = File(ctx.noBackupFilesDir, "com.google.android.gms.appid-no-backup")
            .apply { writeText("1") }
        assertTrue("the marker must exist before the sweep", noBackup.exists())

        try {
            VendorPush.sweepLocalArtifacts(ctx)

            assertFalse(
                "the appid no-backup marker must be deleted: its ABSENCE is what makes the " +
                    "next Store construction call deleteAll() on the cached FCM token. Leaving " +
                    "it behind lets a process that follows a failed deleteToken() re-serve a " +
                    "token whose Firebase Installation was already destroyed — FCM accepts " +
                    "sends to it and the device never receives one.",
                noBackup.exists(),
            )
        } finally {
            noBackup.delete()
        }
    }
}

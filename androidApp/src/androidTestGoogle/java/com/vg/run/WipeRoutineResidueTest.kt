package com.vg.run

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Residue regressions for [WipeRoutine.wipePersistentState] (2026-07-30).
 *
 * Both cases are about artifacts this app never explicitly creates but is still
 * responsible for destroying: databases opened by a DEPENDENCY's merged startup
 * provider, and the local Firebase/FCM push identity. A wipe that leaves either
 * behind hands an examiner dated, app-attributable state.
 *
 * The seeded files are plain files — no live Firebase needed.
 *
 * Run with: ./gradlew connectedAndroidTest --tests "*.WipeRoutineResidueTest"
 */
class WipeRoutineResidueTest {

    private companion object {
        /**
         * Written into every seeded artifact, so an assertion can say "the file
         * WE put there is gone" rather than "no file of this name exists" — the
         * Firebase SDK re-creates several of these names out of band with the
         * wipe (see [wipe_deletesVendorPushArtifacts]).
         */
        const val SEED_MARK = "run-wipe-residue-seed"
    }

    /**
     * The databases/ sweep must mean "nothing survives", including artifacts no
     * named list could anticipate and artifacts that are not plain files.
     *
     * The earlier two-pass version (databaseList()+deleteDatabase(), then
     * listFiles()+File.delete()) READ as exhaustive but was not: databaseList()
     * only reports what the framework recognises as a database, and File.delete()
     * FAILS on a non-empty directory — so `nested/` below survived a sweep that
     * looked total. One deleteRecursively() on the directory replaces both.
     */
    @Test
    fun wipe_leavesNothingInDatabasesDir() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()

        // getDatabasePath() materialises databases/ if it is missing, so this both
        // locates and creates the directory under test.
        val dbDir = ctx.getDatabasePath("run.db").parentFile!!
        assertTrue("databases/ must exist before the wipe", dbDir.isDirectory)

        // (a) A database created by a DEPENDENCY without a line of our code running
        //     — androidx.work's merged androidx.startup provider did exactly this.
        File(dbDir, "androidx.work.workdb").writeText("dependency-owned db")
        File(dbDir, "androidx.work.workdb-wal").writeText("wal")
        // (b) A file the framework does not enumerate as a database at all.
        File(dbDir, "run.db-mj0123ABCD").writeText("master journal")
        // (c) A NESTED artifact — the case the old flat File.delete() pass could
        //     not remove, while reading as if it had.
        val nested = File(dbDir, "nested").apply { mkdirs() }
        File(nested, "leftover.db").writeText("nested db")

        WipeRoutine.wipePersistentState(ctx)

        assertFalse(
            "nothing may survive in databases/ after a wipe — including the directory itself",
            dbDir.exists(),
        )
    }

    /**
     * The local Firebase/FCM push identity is on-disk state that ties this
     * device to a Google-side identifier (registration token + Firebase
     * Installation ID). The wipe deletes those artifacts SYNCHRONOUSLY — it may
     * never block on the SDK's network-dependent Tasks — so a process death
     * mid-wipe already leaves nothing readable. (VendorPush additionally
     * re-runs this deletion once those Tasks settle, because they rewrite these
     * same files on their way through; that second pass needs live Play Services
     * and is not exercised here.)
     *
     * 5A-1 (2026-08-26 regression, introduced by the 2026-08-21 firebase-bom
     * 34.18.0 bump to firebase-installations 19.1.2): also seeds and asserts
     * the `noBackupFilesDir` copy of `PersistedInstallation.*.json` — the SDK's
     * new PRIMARY location — alongside the legacy `filesDir` copy, plus the
     * 2C-1/2C-2 siblings in the same family (`generatefid.lock`, the
     * `datastore/` heartbeat store).
     *
     * 2026-09-16, two phases, because a bare `exists()` cannot tell "the wipe
     * failed to delete our seed" from "the SDK re-created a file of the same
     * name a moment later" — and on firebase-bom 34.19.0 the second really
     * happens: the wipe's own teardown provokes a heartbeat write that
     * androidx.datastore performs ~140 ms later and an installations lock file
     * that `CrossProcessLock.acquire` re-takes, neither of them ordered against
     * the two FCM Tasks the existing post-settle sweep chains off. So:
     *
     *  1. every SEEDED artifact — identified by the marker it was written with —
     *     must be destroyed by the time `wipePersistentState` returns, which is
     *     the synchronous guarantee above. Since 2026-09-17 that phase EXCLUDES
     *     `PersistedInstallation.*.json`, whose deletion is deferred until the
     *     wipe's own revocation chain settles — see the comment at the split;
     *  2. and once the bounded late passes have run
     *     ([VendorPush.awaitLateSweepsForTest]), NOTHING from this family may
     *     survive, including whatever the SDK re-created out of band.
     *
     * Nothing is relaxed by the split: phase 2 is the same "nothing survives"
     * end state this test always asserted, and phase 1 is strictly new.
     */
    @Test
    fun wipe_deletesVendorPushArtifacts() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        // A teardown from an EARLIER test in this class schedules delete-only
        // passes over files/datastore for up to 10 s. Let them finish before
        // seeding, or one of them deletes this test's seeds mid-setup and the
        // "seeds must exist" guard below fails for a reason that has nothing to
        // do with the wipe.
        VendorPush.awaitLateSweepsForTest(20_000)

        ctx.getSharedPreferences("com.google.android.gms.appid", Context.MODE_PRIVATE)
            .edit().putString("token|T|*|", "fake-registration-token $SEED_MARK").commit()
        ctx.getSharedPreferences("com.google.firebase.messaging", Context.MODE_PRIVATE)
            .edit().putBoolean("auto_init", true).putString("seed", SEED_MARK).commit()
        val appIdPrefs = File(ctx.dataDir, "shared_prefs/com.google.android.gms.appid.xml")
        val fcmPrefs = File(ctx.dataDir, "shared_prefs/com.google.firebase.messaging.xml")
        // Legacy (pre-19.1.2) location — still seeded so an install that never
        // migrated stays covered.
        val fid = File(ctx.filesDir, "PersistedInstallation.W0RFRkFVTFRd.json")
            .apply { writeText("{\"Fid\":\"fake-installation-id $SEED_MARK\"}") }
        // 5A-1 (2026-08-26): firebase-installations 19.1.2 (this app's pinned
        // firebase-bom 34.18.0, unchanged by the 34.19.0 bump) moved
        // PersistedInstallation's data file here FIRST — the pre-bump sweep only
        // globbed `filesDir` and missed it.
        val fidNoBackup = File(ctx.noBackupFilesDir, "PersistedInstallation.W0RFRkFVTFRd.json")
            .apply { writeText("{\"Fid\":\"fake $SEED_MARK\",\"AuthToken\":\"fake-auth\"}") }
        val noBackup = File(ctx.noBackupFilesDir, "com.google.android.gms.appid-no-backup")
            .apply { writeText("1 $SEED_MARK") }
        // 2C-2 sibling: FirebaseInstallations' cross-process lock file. Seeded
        // with the marker because the SDK re-creates it (empty) on its next
        // acquire — an `exists()` alone cannot tell the two apart.
        val fidLock = File(ctx.filesDir, "generatefid.lock").apply { writeText(SEED_MARK) }
        // 2C-1 sibling: the Firebase heartbeat androidx.datastore store. Seeded
        // under BOTH observed name shapes — `FirebaseHeartBeat<base64 appName>`
        // (older firebase-common) and `FirebaseHeartBeat<base64 appName>+<base64
        // appId>` (22.2.x, what this app resolves today) — because the SDK has
        // moved that name once already. The sweep deletes the DIRECTORY, so it is
        // name-agnostic by design; these two only prove it.
        val datastoreDir = File(ctx.filesDir, "datastore").apply { mkdirs() }
        val heartbeat = File(datastoreDir, "FirebaseHeartBeatW0RFRkFVTFRd.preferences_pb")
            .apply { writeText("fake heartbeat datastore $SEED_MARK") }
        val heartbeatCurrent = File(
            datastoreDir,
            "FirebaseHeartBeatW0RFRkFVTFRd+MToxMjM0NTY3ODkwOmFuZHJvaWQ6ZmFrZQ.preferences_pb",
        ).apply { writeText("fake heartbeat datastore, current name shape $SEED_MARK") }
        // 2026-09-17: ONE artifact is deliberately NOT destroyed synchronously
        // any more — `PersistedInstallation.<key>.json`, the Installations SDK's
        // own state file. The wipe's revocation chain (`deleteToken()` needs an
        // installation to authenticate its RPC) re-reads that file on the FIS
        // network executor a few hundred ms in; deleting it in between made the
        // SDK read the absent-file default (ATTEMPT_MIGRATION, no fid) and POST
        // `installations/<null fid>/authTokens:generate`, whose 400
        // INVALID_ARGUMENT locks `RequestLimiter` — and therefore every later FCM
        // registration in the process — out for 24 HOURS. Measured on a Samsung
        // A20e; see VendorPush.FisTeardownGate. Its deletion is deferred only
        // until that chain settles (bounded by SETTLE_WAIT_CAP_MS) and is proven
        // by phase 2 below, so the file's life is still bounded — but the
        // synchronous claim would now be false, and a test that asserts a false
        // claim is worse than one that states the real, narrower one.
        val deferredSeeds = listOf(
            "the legacy-location Firebase Installation ID" to fid,
            "the no_backup-location Firebase Installation ID (19.1.2+)" to fidNoBackup,
        )
        val synchronousSeeds = listOf(
            "the FCM token store" to appIdPrefs,
            "the FCM auto-init prefs" to fcmPrefs,
            "the appid no-backup marker" to noBackup,
            "the FirebaseInstallations cross-process lock file" to fidLock,
            "the legacy-name Firebase heartbeat record" to heartbeat,
            "the current-name Firebase heartbeat record" to heartbeatCurrent,
        )
        val seeds = synchronousSeeds + deferredSeeds
        for ((what, f) in seeds) {
            assertTrue("$what must exist before the wipe", holdsSeed(f))
        }

        WipeRoutine.wipePersistentState(ctx)

        // Phase 1 — the synchronous guarantee, unchanged for every artifact that
        // the SDK's own teardown does not read: no seeded artifact survives the
        // call, whatever the SDK does afterwards.
        for ((what, f) in synchronousSeeds) {
            assertFalse("$what must be destroyed by the wipe itself", holdsSeed(f))
        }

        // Phase 2 — the end state, once the bounded late passes have run. This is
        // the same "nothing survives" assertion this test has always made, and it
        // is what bounds the deferred file above.
        VendorPush.awaitLateSweepsForTest(20_000)
        for ((what, f) in seeds) {
            assertFalse("$what must not survive the wipe", f.exists())
        }
        assertFalse("the Firebase heartbeat datastore dir must be gone", datastoreDir.exists())
    }

    /** Distinguishes OUR seed from a file the SDK re-created under the same name. */
    private fun holdsSeed(f: File): Boolean =
        f.exists() && runCatching { f.readText().contains(SEED_MARK) }.getOrDefault(false)

    /**
     * The UnifiedPush tier's artifacts — ours AND the connector library's.
     *
     * Same class of risk as the Firebase case above, and worse in one respect:
     * the connector persists under names it does not document (recovered by
     * disassembling connector-3.3.5.aar), and its `unifiedpush-connector`
     * database holds the AES-GCM-sealed WebPush PRIVATE key plus the distributor
     * choice. Our own `unifiedpush_state_prefs` holds the endpoint URL, which
     * names the user's push server.
     *
     * The wipe covers the database twice — by name via
     * `UnifiedPushSupport.sweepLocalArtifacts`, and again by the wholesale
     * `databases/` deleteRecursively — but ORDER is what makes that work: the
     * connector-side teardown re-creates the database when it is absent, so it
     * has to run before both. This test is the executable statement of that
     * ordering: get it wrong and one of the two files below survives.
     *
     * The connector ships in every build.
     */
    @Test
    fun wipe_deletesUnifiedPushArtifacts() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        ProcessWipeLatch.resetForTest()

        val connectorDb = ctx.getDatabasePath("unifiedpush-connector")
        connectorDb.parentFile?.mkdirs()
        connectorDb.writeText("fake connector db (distributor, tokens, sealed webpush keys)")
        ctx.getSharedPreferences("unifiedpush.connector", Context.MODE_PRIVATE)
            .edit().putString("unifiedpush.distributor", "io.heckel.ntfy").commit()
        UnifiedPushStateStore(ctx).saveSubscription(
            "https://ntfy.example/UP?up=1&i=abcdef0123456789",
            "B" + "A".repeat(86),
            "C".repeat(22),
        )
        val legacyPrefs = File(ctx.dataDir, "shared_prefs/unifiedpush.connector.xml")
        val ourPrefs = File(ctx.dataDir, "shared_prefs/${UnifiedPushStateStore.PREFS_NAME}.xml")
        assertTrue(
            "seeds must exist before the wipe",
            connectorDb.exists() && legacyPrefs.exists() && ourPrefs.exists(),
        )

        WipeRoutine.wipePersistentState(ctx)

        assertFalse("the connector's database must be gone", connectorDb.exists())
        assertFalse("the connector's legacy prefs must be gone", legacyPrefs.exists())
        assertFalse("our own endpoint store must be gone", ourPrefs.exists())

        ProcessWipeLatch.resetForTest()
    }
}

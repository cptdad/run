package com.vg.run

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.test.core.app.ApplicationProvider
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.unifiedpush.android.connector.UnifiedPush
import java.io.File
import java.security.KeyStore
import javax.crypto.KeyGenerator

/**
 * The UnifiedPush sibling of [VendorPushArtifactSweepTest].
 *
 * The connector library persists state this app never explicitly creates, under
 * names it does not document — they were recovered by disassembling
 * connector-3.3.5.aar. Missing any of them would be the "the code is
 * deleted but the data survives" bug, and
 * the risk is real here: the connector's `keys` table holds the AES-GCM-sealed
 * WebPush PRIVATE key, and its legacy prefs file is migrated OUT of but never
 * deleted by the library itself (`LegacyStore` calls no `deleteSharedPreferences`).
 *
 * The connector ships in every build (plain `implementation`, no Google
 * transitives), so this sweep must always delete — no conditional pass below.
 *
 * Seeds for the DELETION-LIST tests are plain files written by hand: the point
 * under test there is the list, and driving the library into creating genuine
 * state would require an installed distributor app that CI does not have.
 *
 * The IN-SESSION tests are the exception and must not take that shortcut. They
 * drive the connector's REAL API (`UnifiedPush.saveDistributor`, which needs no
 * distributor app installed — `setPrimary` documents that it does not check),
 * because what they assert is the connector's LIVE SQLite handle still working
 * after a teardown. A hand-written file cannot exhibit that; the entire
 * 2026-08-03 regression lived in the gap between "the files look right" and
 * "the library still works", and every earlier teardown in a device run
 * happened to be followed by a process restart that hid it.
 *
 * Run with: ./gradlew connectedAndroidTest --tests "*.UnifiedPushArtifactSweepTest"
 * (or `am instrument` with `-e class` against an already-provisioned device).
 */
class UnifiedPushArtifactSweepTest {

    private val ctx: Context get() = ApplicationProvider.getApplicationContext()

    private val connectorDb: File get() = ctx.getDatabasePath("unifiedpush-connector")
    private val connectorDbWal: File get() = File(connectorDb.path + "-wal")
    private val legacyPrefs: File
        get() = File(ctx.dataDir, "shared_prefs/unifiedpush.connector.xml")
    private val ourPrefs: File
        get() = File(ctx.dataDir, "shared_prefs/${UnifiedPushStateStore.PREFS_NAME}.xml")

    /**
     * Hard-coded on purpose (same reasoning as
     * [LegacyTorWarmCachePurgeTest]'s alias constant): the connector library
     * exposes no constant for it, `UnifiedPushSupport` keeps its copy private,
     * and if either side renames it the erase must fail LOUDLY here rather than
     * degrade into a silent no-op that leaves the sealed WebPush private keys
     * recoverable.
     */
    private val connectorAlias = "UnifiedPush"

    private fun levelStore() = KeyValueStore(ctx, RunViewModel.NOTIFICATION_LEVEL_PREFS_NAME)

    // The persisted opt-in is TWO slots now — the
    // PLAINTEXT wake gate these service callbacks read, plus a device-key AEAD
    // consent proof whose freshness epoch lives in the OPEN VAULT. These tests
    // are about the wake gate and have no vault, so they seed the plaintext slot
    // directly; `NotificationLevelStore.setLevel` deliberately refuses (and
    // writes nothing) without a vault, because a proof sealed against an epoch
    // it cannot read is one no later read could validate.
    private fun seedLevel(level: NotificationLevel) =
        levelStore().putString(NotificationLevelStore.KEY, level.storageValue)

    /**
     * A package name for [UnifiedPush.saveDistributor] that is deliberately NOT
     * installed. `setPrimary` documents that it does not check installation (the
     * `get*Distributor` readers do), so this exercises the real write path
     * without needing a distributor app on the device — and the broadcast that a
     * teardown would send to it is a silent no-op for a package that isn't there.
     */
    private val probeDistributor = "com.vg.run.test.absent.distributor"

    @Before
    fun setUp() {
        ProcessWipeLatch.resetForTest()
        resetConnectorStore()
    }

    @After
    fun tearDown() {
        ProcessWipeLatch.resetForTest()
        // BEFORE deleting the file, not after: unlinking it while the
        // connector's static DBStore singleton still holds an open handle pins
        // that handle in SQLITE_READONLY_DBMOVED for the whole instrumentation
        // process, and every later test in this run would then fail on a wedge
        // this teardown created rather than on anything under test.
        resetConnectorStore()
        connectorDb.delete()
        connectorDbWal.delete()
        ctx.deleteSharedPreferences("unifiedpush.connector")
        ctx.deleteSharedPreferences(UnifiedPushStateStore.PREFS_NAME)
        NotificationLevelStore.clearLevel(levelStore(), CryptoProvider(ctx), vault = null)
        deleteConnectorAlias()
        deleteStateAlias()
    }

    /**
     * The alias name is DATA, not just code: it names the key that opens
     * `up_keys_enc` on every install that has already sealed one. Renaming it
     * orphans that ciphertext — push then silently lapses until the user
     * re-registers, with no error anywhere. Pinned as a literal (the same
     * reasoning as [connectorAlias] above) so a rename has to be a deliberate,
     * migration-aware change rather than a refactor.
     */
    @Test
    fun stateKeyAliasName_isStable() {
        assertEquals(
            "renaming this alias orphans the sealed (p256dh, auth) pair of every already-" +
                "sealed install — it needs a migration, not a rename",
            "run_up_state_key",
            UnifiedPushStateStore.KEYSTORE_ALIAS,
        )
    }

    /**
     * `eraseKeySurface` is the ONE crypto-erase-first slot every teardown path
     * calls (WipeRoutine, the opt-out branch, the enable-failure branch), so it
     * must cover BOTH of this tier's aliases:
     *  - the connector's `UnifiedPush` (WebPush PRIVATE keys), pinned by
     *    [failedEnableTeardownSequence_removesEveryArtifactIncludingTheKeystoreAlias];
     *  - our own `run_up_state_key`, which seals the RFC 8291 `auth` SHARED
     *    secret — the value whose misclassification as "public" justified
     *    storing it in cleartext until 2026-08-11.
     *
     * A second erase entry point would be a second list to forget, which is why
     * this asserts on the SHARED function rather than on a new one.
     */
    @Test
    fun eraseKeySurface_alsoCryptoErasesOurOwnStateKey() {
        UnifiedPushStateStore(ctx).saveSubscription(
            "https://ntfy.example/UP?up=1&i=abcdef0123456789",
            "B" + "A".repeat(86),
            "C".repeat(22),
        )
        assertTrue(
            "precondition: sealing a subscription must have minted our alias",
            stateAliasExists(),
        )

        UnifiedPushSupport.eraseKeySurface(ctx)

        assertFalse(
            "eraseKeySurface must destroy the key that seals (p256dh, auth) in " +
                "unifiedpush_state_prefs — otherwise a teardown interrupted before the prefs " +
                "deletion leaves a recoverable wake-forgery input on disk",
            stateAliasExists(),
        )
        assertNull(
            "and the surviving ciphertext must read back as absent",
            UnifiedPushStateStore(ctx).readSubscription(),
        )
    }

    @Test
    fun sweepLocalArtifacts_removesEveryConnectorAndAppArtifact() {
        // (a) The connector's own SQLite store — distributor choice,
        //     registrations, connector tokens, and the sealed WebPush keys.
        connectorDb.parentFile?.mkdirs()
        connectorDb.writeText("fake connector db")
        connectorDbWal.writeText("wal")
        // (b) Its LEGACY pre-3.x SharedPreferences, which the library migrates
        //     out of but never deletes.
        ctx.getSharedPreferences("unifiedpush.connector", Context.MODE_PRIVATE)
            .edit().putString("unifiedpush.distributor", "io.heckel.ntfy").commit()
        // (c) Ours.
        UnifiedPushStateStore(ctx).saveSubscription(
            "https://ntfy.example/UP?up=1&i=abcdef0123456789",
            "B" + "A".repeat(86),
            "C".repeat(22),
        )
        assertTrue(
            "seeds must exist before the sweep",
            connectorDb.exists() && connectorDbWal.exists() && legacyPrefs.exists() && ourPrefs.exists(),
        )

        UnifiedPushSupport.sweepLocalArtifacts(ctx)

        assertFalse("the connector database must be gone", connectorDb.exists())
        assertFalse("the connector database's -wal sidecar must be gone", connectorDbWal.exists())
        assertFalse("the connector's legacy prefs must be gone", legacyPrefs.exists())
        assertFalse("our own endpoint store must be gone", ourPrefs.exists())
    }

    /**
     * The sweep is called on the OPT-OUT path too, where no full wipe runs — so
     * it must be safe on an install that never enabled the tier. Nothing to
     * delete must mean nothing created: `Context.deleteDatabase` resolving the
     * databases dir would otherwise be an easy way to leave a bare, freshly
     * dated `databases/` behind on a device that never opened one.
     */
    @Test
    fun sweepLocalArtifacts_isIdempotentAndCreatesNothing() {
        connectorDb.delete()
        ctx.deleteSharedPreferences("unifiedpush.connector")
        ctx.deleteSharedPreferences(UnifiedPushStateStore.PREFS_NAME)

        UnifiedPushSupport.sweepLocalArtifacts(ctx)
        UnifiedPushSupport.sweepLocalArtifacts(ctx)

        assertFalse(connectorDb.exists())
        assertFalse(legacyPrefs.exists())
        assertFalse(ourPrefs.exists())
    }

    /**
     * WIPE PATH ordering guard, stated as an executable fact rather than only a
     * comment: the connector-side teardown constructs its `DBStore` and
     * therefore RE-CREATES `databases/unifiedpush-connector` when it is absent.
     * That is exactly why `WipeRoutine` runs `destroyLocalPushIdentity` BEFORE
     * `sweepLocalArtifacts`, and why the pair runs before the wholesale
     * `databases/` deletion.
     *
     * `WipeRoutine` is the ONLY caller of this pair. The in-session paths use
     * `sweepInSessionArtifacts` and are covered by
     * [inSessionTeardown_leavesTheConnectorAbleToSelectADistributorAgain].
     *
     * If a future connector version stops touching the database here this test
     * still passes (it asserts the END state, not the intermediate one) — the
     * assertion that matters is that the documented order leaves nothing behind.
     */
    @Test
    fun destroyThenSweep_leavesNoConnectorDatabase() {
        UnifiedPushSupport.destroyLocalPushIdentity(ctx)
        UnifiedPushSupport.sweepLocalArtifacts(ctx)

        assertFalse(
            "destroyLocalPushIdentity re-creates the connector DB; the sweep must run AFTER it",
            connectorDb.exists(),
        )
    }

    /**
     * The FAILED-ENABLE path, end state.
     *
     * `RunViewModel.setBackgroundNotificationsEnabledAwaiting` writes the level
     * at TOGGLE time and only then awaits registration, so by the time an enable
     * can fail real artifacts exist — and the failure branch used to remove ONLY
     * the level, leaving all of the below plus a live distributor-side
     * subscription with nothing left to rediscover them (the modal's
     * `applyLevel` sets its local `enabled = false` without dispatching a
     * disable, and the control-poll dispatcher keys off the level that branch
     * just removed).
     *
     * Deliberately drives the ORDERED SEQUENCE rather than the ViewModel:
     * `RunViewModel` is an `AndroidViewModel` whose construction pulls in
     * `CryptoProvider` / `VaultSelector` / `AndroidDbKeyProtector` and whose
     * enable path needs an OPEN VAULT and a live Tor transport — none of which
     * exists here. The complementary half, that the branch actually INVOKES this
     * sequence in this order, is pinned at source level by
     * `VendorPushOptOutTeardownSourceTest.enableFailureBranch_*`.
     *
     * The KEYSTORE ALIAS is the assertion that matters most: it (and the
     * connector database) are created during DISTRIBUTOR SELECTION, i.e. before
     * the ViewModel is even called — so they are present in the sub-cases where
     * NO endpoint ever arrived (handshake timeout, DISTRIBUTOR_REFUSED,
     * VAPID_UNSUPPORTED), which is exactly why the teardown may not be gated on
     * having got one.
     */
    @Test
    fun failedEnableTeardownSequence_removesEveryArtifactIncludingTheKeystoreAlias() {
        // (1) State a real enable attempt has already produced by the time it
        //     can fail: the level (written at toggle time), a REAL distributor
        //     selection driven through the connector's own API (which is what
        //     creates its database), the sealed-key alias, the connector's
        //     legacy prefs, and — for the RELAY sub-case — our endpoint prefs.
        seedLevel(NotificationLevel.UNIFIED_PUSH)
        // The legacy-prefs seed goes FIRST and under a key the connector's
        // migration does NOT consume. Both details are about determinism, not
        // taste: constructing the DBStore (next line) submits `migrateFromLegacy`
        // to a background executor, which would (a) IMPORT a seeded
        // `unifiedpush.distributor` into the distributors table, breaking the
        // precondition below, and (b) mint the file itself if it did not already
        // exist, racing the sweep. With the file present and no migratable key in
        // it, that migration makes no change and writes nothing.
        // `sweepLocalArtifacts_removesEveryConnectorAndAppArtifact` carries the
        // realistic key name, with no connector call to race.
        ctx.getSharedPreferences("unifiedpush.connector", Context.MODE_PRIVATE)
            .edit().putString("unifiedpush.legacy_probe", "1").commit()
        UnifiedPush.saveDistributor(ctx, probeDistributor)
        UnifiedPushStateStore(ctx).saveSubscription(
            "https://ntfy.example/UP?up=1&i=abcdef0123456789",
            "B" + "A".repeat(86),
            "C".repeat(22),
        )
        val aliasSeeded = seedConnectorAlias()
        assertTrue(
            "seeds must exist before the teardown",
            connectorDb.exists() && legacyPrefs.exists() && ourPrefs.exists(),
        )
        assertEquals(
            "seeds must include a real distributor selection",
            setOf(probeDistributor), savedDistributorRows(),
        )

        // (2) EXACTLY the enable-failure branch's sequence, in its order:
        //     level first (so the UNREGISTERED broadcast the teardown provokes
        //     reads "the user did not ask for this" and re-creates nothing),
        //     then crypto-erase, then the connector-side teardown, then the
        //     IN-SESSION sweep.
        NotificationLevelStore.clearLevel(levelStore(), CryptoProvider(ctx), vault = null)
        UnifiedPushSupport.eraseKeySurface(ctx)
        UnifiedPushSupport.destroyLocalPushIdentity(ctx)
        UnifiedPushSupport.sweepInSessionArtifacts(ctx)

        assertEquals(
            "the local wake gate must read OFF after a failed enable",
            NotificationLevel.OFF, NotificationLevelStore.getLevel(levelStore()),
        )
        assertFalse(
            "a failed enable must not leave unifiedpush_state_prefs.xml behind — it holds " +
                "the endpoint URL, which names the user's push server",
            ourPrefs.exists(),
        )
        assertFalse("the connector's legacy prefs must be gone too", legacyPrefs.exists())
        assertEquals(
            "a failed enable must leave NO distributor selected — the connector's rows are " +
                "deleted through its own API (unregister / removeDistributor), which is what " +
                "lets the in-session path keep the database FILE and stay usable for a retry",
            emptySet<String>(), savedDistributorRows(),
        )
        if (aliasSeeded) {
            assertFalse(
                "a failed enable must crypto-erase the AndroidKeyStore alias '$connectorAlias' " +
                    "that wraps every stored WebPush private key — it is minted at DISTRIBUTOR " +
                    "SELECTION time, so it exists even when no endpoint ever arrived. This, not " +
                    "deleting the database file, is what makes the sealed private key " +
                    "unrecoverable — which is why the in-session path may keep the file",
                connectorAliasExists(),
            )
        }
    }

    // -----------------------------------------------------------------------
    // The IN-SESSION teardown (regression 2026-08-03).
    // -----------------------------------------------------------------------

    /**
     * THE regression test, and the one shape the whole existing suite was
     * missing: run a teardown and then KEEP USING the connector, in ONE process.
     *
     * Every earlier test asserted only on the END STATE of the files, and every
     * teardown in the device runs happened to be followed by a process restart —
     * so nobody ever exercised "tear down, then retry". That is precisely the
     * ordinary user sequence: toggle notifications ON, the enable fails (Tor
     * still bootstrapping, distributor slow to answer), toggle ON again.
     *
     * WHAT BROKE. `sweepLocalArtifacts` unlinked
     * `databases/unifiedpush-connector` while the connector's private static
     * `DBStore.instance` still held an open `SQLiteDatabase` on it. SQLite then
     * reports `SQLITE_READONLY_DBMOVED` (extended result 1032) for every write,
     * and `SQLiteOpenHelper.getWritableDatabase()` keeps handing the SAME dead
     * connection back — it is still `isOpen()`, and its open flags still say
     * read-write, so the helper never reopens. On the device this surfaced as:
     *
     *     E/SQLiteLog (1032) statement aborts at 76: attempt to write a readonly
     *     database; [INSERT OR REPLACE INTO distributors(...)]
     *
     * `saveDistributor` throwing means `UnifiedPushSupport
     * .useCurrentOrDefaultDistributor` reports `false`, which the modal renders
     * as "No notification distributor was selected." — permanently, because the
     * process survives `finishAndRemoveTask()`.
     *
     * The last assertion is the live one: before the fix it throws
     * `SQLiteReadOnlyDatabaseException`; after it, the row is readable back.
     * Read back through an INDEPENDENT connection to the same file rather than
     * through `getSavedDistributor`, which filters on installed packages and
     * would report null for the deliberately-absent probe package.
     */
    @Test
    fun inSessionTeardown_leavesTheConnectorAbleToSelectADistributorAgain() {
        // (1) Distributor selection — exactly what NotificationSettingsModal
        //     .setEnabled provokes, and what creates the database — plus the
        //     endpoint prefs a relay-stage failure would leave behind, so the
        //     "our prefs are gone" assertion below cannot pass vacuously.
        //
        //     Deliberately no `unifiedpush.connector` (legacy prefs) seed here:
        //     constructing the connector's DBStore submits its legacy migration
        //     to a BACKGROUND executor, whose no-change `apply()` mints an empty
        //     file when none exists, so asserting that file's absence would be a
        //     race. Its deletion is pinned deterministically instead by
        //     [sweepInSessionArtifacts_removesThePrefsButKeepsTheConnectorDatabase],
        //     which makes no connector call at all.
        UnifiedPushStateStore(ctx).saveSubscription(
            "https://ntfy.example/UP?up=1&i=abcdef0123456789",
            "B" + "A".repeat(86),
            "C".repeat(22),
        )
        UnifiedPush.saveDistributor(ctx, probeDistributor)
        assertTrue("precondition: the connector must have created its database", connectorDb.exists())
        assertTrue("precondition: our endpoint store must exist before the teardown", ourPrefs.exists())
        assertEquals(
            "precondition: the selection must be on disk before the teardown",
            setOf(probeDistributor), savedDistributorRows(),
        )

        // (2) The in-session teardown, in RunViewModel's exact order.
        UnifiedPushSupport.eraseKeySurface(ctx)
        UnifiedPushSupport.destroyLocalPushIdentity(ctx)
        UnifiedPushSupport.sweepInSessionArtifacts(ctx)

        // (3) The teardown must still have done its job: the connector's own
        //     rows are gone (deleted through its LIVE handle by unregister /
        //     removeDistributor), and our prefs are gone.
        assertEquals(
            "the teardown must leave NO distributor selected — it deletes the rows through " +
                "the connector's own API, which is what makes unlinking the file unnecessary",
            emptySet<String>(), savedDistributorRows(),
        )
        assertFalse("our own endpoint store must be gone", ourPrefs.exists())

        // (4) …but the FILE must survive, …
        assertTrue(
            "an IN-SESSION teardown must NOT unlink databases/unifiedpush-connector — the " +
                "connector caches an open handle to it in a static singleton it never closes",
            connectorDb.exists(),
        )
        // (5) …and the connector must still be usable. THIS is the regression:
        //     before the fix this line threw SQLiteReadOnlyDatabaseException.
        UnifiedPush.saveDistributor(ctx, probeDistributor)
        assertEquals(
            "after an in-session teardown the user must be able to select a distributor " +
                "again — a retry is the ordinary sequence after a failed enable, and a wedged " +
                "connector reports 'No notification distributor was selected' forever",
            setOf(probeDistributor), savedDistributorRows(),
        )
    }

    /**
     * The WIPE-path sibling of the regression test above (defect reproduced on
     * a Pixel, 2026-08-11): run the WIPE teardown and then KEEP USING the
     * connector, in ONE process.
     *
     * "WipeRoutine is a terminal path — no retry follows it in this process"
     * was the justification for leaving the bare unlink on the wipe path when
     * the in-session paths were fixed. It is false: four of the five wipe
     * entry points (the orphaned-vault "Erase and start over", the launch-time
     * inactivity wipe, the orphaned-credential self-heal, the debug TEST_WIPE
     * hook) deliberately fall through to setup in the SAME process — which
     * also survives `finishAndRemoveTask()` as a cached process — so
     * wipe → re-onboard → enable notifications reached `saveDistributor` on
     * the handle the wipe's own unlink had just pinned in
     * SQLITE_READONLY_DBMOVED. Every wipe arms that wedge deterministically:
     * `destroyLocalPushIdentity`, one line before the sweep, constructs the
     * connector's DBStore and opens the handle.
     *
     * The fix under test: `sweepLocalArtifacts` closes the connector's cached
     * handle (production reflection, `closeConnectorDbHandle`) BEFORE the
     * unlink. Step (3) is the live assertion — before the fix it throws
     * `SQLiteReadOnlyDatabaseException`. Step (2)'s file assertion pins that
     * the destructive guarantee did not move: the wipe still unlinks.
     *
     * NOTE this also exercises the PRODUCTION reflection against the real
     * connector (setUp's [resetConnectorStore] is test scaffolding; the close
     * inside the sweep is the shipped one), so a connector upgrade that
     * renames `DBStore.instance` fails here too, not only in the scaffolding.
     */
    @Test
    fun wipePathTeardown_leavesTheConnectorAbleToSelectADistributorAgain() {
        // (1) A real selection through the connector's own API — constructs
        //     DBStore and opens the cached handle, exactly the state every
        //     wipe runs the sweep in.
        UnifiedPush.saveDistributor(ctx, probeDistributor)
        assertTrue("precondition: the connector must have created its database", connectorDb.exists())
        assertEquals(
            "precondition: the selection must be on disk before the wipe",
            setOf(probeDistributor), savedDistributorRows(),
        )

        // (2) The WIPE-path teardown, in WipeRoutine's exact order.
        UnifiedPushSupport.eraseKeySurface(ctx)
        UnifiedPushSupport.destroyLocalPushIdentity(ctx)
        UnifiedPushSupport.sweepLocalArtifacts(ctx)
        assertFalse(
            "the wipe must STILL unlink the connector database — closing the handle first " +
                "must not weaken what the wipe erases",
            connectorDb.exists(),
        )

        // (3) The same process keeps running and re-onboards: selecting a
        //     distributor again must work. THIS is the 2026-08-11 defect —
        //     before the close-before-unlink fix this threw
        //     SQLiteReadOnlyDatabaseException (SQLITE_READONLY_DBMOVED) out of
        //     the connector's cached handle, and the modal rendered "No
        //     notification distributor was selected. Install ntfy…" while ntfy
        //     was installed.
        UnifiedPush.saveDistributor(ctx, probeDistributor)
        assertEquals(
            "after a wipe, a re-onboarded user in the SAME (cached) process must be able to " +
                "select a distributor again — UnifiedPush is the only transport on a " +
                "de-Googled device, so a wedge here is notifications silently dead until " +
                "real process death",
            setOf(probeDistributor), savedDistributorRows(),
        )
    }

    /**
     * The narrow file-level contract of the in-session sweep, stated separately
     * from the behavioural test above so a regression names itself: prefs gone,
     * database kept.
     */
    @Test
    fun sweepInSessionArtifacts_removesThePrefsButKeepsTheConnectorDatabase() {
        connectorDb.parentFile?.mkdirs()
        connectorDb.writeText("fake connector db")
        ctx.getSharedPreferences("unifiedpush.connector", Context.MODE_PRIVATE)
            .edit().putString("unifiedpush.distributor", "io.heckel.ntfy").commit()
        UnifiedPushStateStore(ctx).saveSubscription(
            "https://ntfy.example/UP?up=1&i=abcdef0123456789",
            "B" + "A".repeat(86),
            "C".repeat(22),
        )
        assertTrue(
            "seeds must exist before the sweep",
            connectorDb.exists() && legacyPrefs.exists() && ourPrefs.exists(),
        )

        UnifiedPushSupport.sweepInSessionArtifacts(ctx)

        assertFalse("our endpoint store must be gone", ourPrefs.exists())
        assertFalse("the connector's legacy prefs must be gone", legacyPrefs.exists())
        assertTrue(
            "the connector database must SURVIVE an in-session sweep — deleting it wedges " +
                "the connector's cached SQLite handle for the life of the process; the sealed " +
                "WebPush private keys are protected by eraseKeySurface instead",
            connectorDb.exists(),
        )
    }

    /**
     * Every `distributor` value the connector currently has on disk, read
     * through an INDEPENDENT connection to its file.
     *
     * Deliberately not the connector's own reader: `getSavedDistributor` /
     * `getAckDistributor` filter on packages that are actually installed and
     * DELETE the rows that aren't, so they cannot observe the probe package and
     * would silently mutate the state under test.
     *
     * Empty set when the file or the table doesn't exist yet.
     */
    private fun savedDistributorRows(): Set<String> {
        if (!connectorDb.exists()) return emptySet()
        return try {
            SQLiteDatabase.openDatabase(
                connectorDb.path, null, SQLiteDatabase.OPEN_READWRITE,
            ).use { db ->
                db.rawQuery("SELECT distributor FROM distributors", null).use { c ->
                    val out = mutableSetOf<String>()
                    while (c.moveToNext()) out.add(c.getString(0))
                    out
                }
            }
        } catch (_: Exception) {
            // No such table yet — the connector creates it on first write.
            emptySet()
        }
    }

    /**
     * Closes and drops the connector's private static `DBStore` singleton so
     * each test starts from a connector that can genuinely open its database.
     *
     * TEST-ONLY SCAFFOLDING, and reflective because the library offers nothing
     * else: `DBStore` is `internal`, is held in `private static DBStore
     * instance`, and inherits `SQLiteOpenHelper.close()` but exposes no reset.
     * Without this, ONE test that unlinks the database with raw `File.delete()`
     * calls (the seeded deletion-list tests, or this class's own teardown) pins
     * the singleton's handle in SQLITE_READONLY_DBMOVED for the remainder of
     * the instrumentation process, and every later test fails on that instead
     * of on its own subject. (Since 2026-08-11 the production sweep closes the
     * handle itself — `closeConnectorDbHandle`, the same surface as this — so
     * the sweep no longer wedges; the raw-file paths here still can.)
     *
     * Fails LOUDLY if the field is gone. A helper that silently degrades to a
     * no-op would turn the regression this class exists for back into a green
     * test — the same reasoning as the hard-coded [connectorAlias] above.
     */
    private fun resetConnectorStore() {
        val field = Class.forName("org.unifiedpush.android.connector.internal.DBStore")
            .getDeclaredField("instance")
        field.isAccessible = true
        (field.get(null) as? SQLiteOpenHelper)?.close()
        field.set(null, null)
    }

    /** True if the emulator minted the alias; a refusal must not fail the test —
     *  the file assertions still carry it (same allowance as
     *  [LegacyTorWarmCachePurgeTest]'s seed). */
    private fun seedConnectorAlias(): Boolean = try {
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
            init(
                KeyGenParameterSpec.Builder(
                    connectorAlias,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .build()
            )
        }.generateKey()
        connectorAliasExists()
    } catch (_: Exception) {
        false
    }

    private fun connectorAliasExists(): Boolean = try {
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.containsAlias(connectorAlias)
    } catch (_: Exception) {
        false
    }

    private fun deleteConnectorAlias() {
        try {
            KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry(connectorAlias)
        } catch (_: Exception) { /* absent */ }
    }

    /** Our own seal key (see [UnifiedPushStateStore.KEYSTORE_ALIAS]). */
    private fun stateAliasExists(): Boolean = try {
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            .containsAlias(UnifiedPushStateStore.KEYSTORE_ALIAS)
    } catch (_: Exception) {
        false
    }

    private fun deleteStateAlias() {
        try {
            KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
                .deleteEntry(UnifiedPushStateStore.KEYSTORE_ALIAS)
        } catch (_: Exception) { /* absent */ }
    }
}

/**
 * The connector performs its RFC 8291 decryption with Tink primitives it does
 * NOT bundle (only the `apps.fixed_webpush` wrapper is inside its own jar).
 * `androidApp/build.gradle.kts` excludes the JVM `com.google.crypto.tink:tink`
 * it declares — it overlaps `:shared`'s `tink-android` on 1357 of its 1366
 * classes — and relies on tink-android to satisfy it.
 *
 * That is a cross-module coupling with a SILENT failure mode: drop tink-android
 * from `:shared` and every incoming push arrives with `decrypted == false`,
 * which [RunPushService] drops by design. No crash, no log, just notifications
 * that stop working. This test makes it loud.
 */
class UnifiedPushTinkRuntimeTest {

    @Test
    fun webPushCryptoClassesAreOnTheRuntimeClasspath() {
        assertTrue(
            "The connector's WebPush decryptor needs com.google.crypto.tink.subtle.* at " +
                "runtime. androidApp/build.gradle.kts excludes the JVM `tink` artifact and " +
                "relies on :shared's `tink-android` to provide them — if that dependency was " +
                "removed or renamed, every push would silently fail to decrypt and be dropped.",
            UnifiedPushSupport.isWebPushCryptoLinked(),
        )
    }
}

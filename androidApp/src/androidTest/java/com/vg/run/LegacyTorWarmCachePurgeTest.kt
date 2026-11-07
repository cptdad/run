package com.vg.run

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.KeyStore
import javax.crypto.KeyGenerator

/**
 * The RETIRED warm-Tor-cache artifacts must be gone from installs that already
 * have them, not merely absent from new ones (2026-07-31).
 *
 * The removed feature persisted Tor's `state` + cached consensus/microdescriptors
 * into `filesDir/tor_warm_cache.enc`, sealed under a Keystore key
 * (`run_torcache_master_key`, wrapped keyset in `run_torcache_keyset_prefs`)
 * deliberately built WITHOUT `setUnlockedDeviceRequired(true)` — usable while the
 * phone is locked, the same weak gating as the removed relay-capability manifest. Its only
 * production caller (the FCM-woken poll runner) was deleted with the poll
 * manifest, so the class went too.
 *
 * DELETING THE CODE DELETES NONE OF THAT DATA, and the blob sits at a top-level
 * sibling OUTSIDE `tor_direct/` — the tree [WipeRoutine] and
 * `TorManager.stopAndDiscardState()` sweep — so every existing Tor cleanup steps
 * around it. Left alone it is permanent, dated, app-attributable proof Tor was
 * used. (Tor's own working dirs are PERSISTENT since 2026-08-01 — see
 * `TorManager.dataDir` — which does not retire this purge: those are plain files
 * in credential-encrypted storage that every wipe path deletes, while this blob is
 * sealed under a Keystore key usable while the phone is LOCKED.) This class covers
 * both removal paths ([WipeRoutine] and the one-time
 * [LegacyTorWarmCache.purgeLegacyWarmCache]) plus the property that must not
 * break: neither may CREATE anything on an install that never had the cache.
 *
 * INSTRUMENTED because the artifacts are a real AndroidKeystore alias and real
 * SharedPreferences files; neither exists in this project's plain-JVM
 * androidUnitTest tier (no Robolectric). Same tier and shape as
 * ManifestCapabilityPurgeTest, its manifest sibling.
 *
 * Run with: ./gradlew connectedAndroidTest --tests "com.vg.run.LegacyTorWarmCachePurgeTest"
 */
@RunWith(AndroidJUnit4::class)
class LegacyTorWarmCachePurgeTest {

    private lateinit var ctx: Context

    private val blob: File get() = File(ctx.filesDir, BLOB_FILE)
    private val blobTmp: File get() = File(ctx.filesDir, "$BLOB_FILE.tmp")
    private val keysetXml: File
        get() = File(ctx.dataDir, "shared_prefs/${LegacyTorWarmCache.LEGACY_KEYSET_PREFS_NAME}.xml")

    @Before
    fun setUp() {
        ctx = ApplicationProvider.getApplicationContext()
        // A wipe test that ran earlier in this shared process may have latched.
        // Nothing here gates on it, but leaving it set would be a confusing
        // precondition for the "creates nothing" assertions below.
        ProcessWipeLatch.resetForTest()
        clean()
    }

    @After
    fun tearDown() {
        ProcessWipeLatch.resetForTest()
        clean()
    }

    /**
     * The upgrade case: a device that ran a warm-cache build carries the alias,
     * the wrapped keyset, the blob and possibly a `.tmp` stranded by an
     * interrupted atomic write. One purge pass removes all four.
     */
    @Test
    fun purge_destroysAlias_keyset_blob_andStrandedTmp() {
        seedLegacyWarmCache()
        assertTrue("seed: the blob must exist", blob.isFile)
        assertTrue("seed: the stranded .tmp must exist", blobTmp.isFile)
        assertTrue("seed: the wrapped keyset must exist", keysetXml.exists())
        assertTrue("seed: the Keystore alias must exist", keystoreHasLegacyAlias())

        LegacyTorWarmCache.purgeLegacyWarmCache(ctx)

        assertFalse("the weak-gated Keystore alias must be crypto-erased", keystoreHasLegacyAlias())
        assertFalse("the wrapped Tink keyset must be gone", keysetXml.exists())
        assertFalse("the encrypted guard/consensus blob must be gone", blob.exists())
        assertFalse("a stranded .tmp is the same artifact — it must be gone too", blobTmp.exists())
    }

    /**
     * Idempotent, and inert on an install that never used the warm cache.
     *
     * The second property is why this purge is written as pure deletions with no
     * `edit().commit()` anywhere: the manifest sibling had to guard with `contains()`
     * because removing a key from a prefs file that does not exist CREATES it.
     * `deleteSharedPreferences` / `File.delete` / `KeyStore.deleteEntry` cannot
     * mint anything, so a launch-time purge on a fresh — or freshly wiped —
     * install must leave the data dir byte-for-byte as it found it.
     */
    @Test
    fun purge_isIdempotent_andCreatesNothingWhenThereWasNoCache() {
        val filesBefore = listing(ctx.filesDir)
        val prefsBefore = listing(File(ctx.dataDir, "shared_prefs"))

        repeat(3) { LegacyTorWarmCache.purgeLegacyWarmCache(ctx) }

        assertNoNewFiles("filesDir", filesBefore, listing(ctx.filesDir))
        assertNoNewFiles("shared_prefs", prefsBefore, listing(File(ctx.dataDir, "shared_prefs")))
        assertFalse("no keyset may be created", keysetXml.exists())
        assertFalse("no Keystore alias may be created", keystoreHasLegacyAlias())
        assertFalse("no blob may be created", blob.exists())

        // …and repeating it over a real cache converges to the same state.
        seedLegacyWarmCache()
        LegacyTorWarmCache.purgeLegacyWarmCache(ctx)
        LegacyTorWarmCache.purgeLegacyWarmCache(ctx)
        assertFalse("second pass must not resurrect the keyset", keysetXml.exists())
        assertFalse("second pass must not resurrect the alias", keystoreHasLegacyAlias())
        assertFalse("second pass must not resurrect the blob", blob.exists())
    }

    /**
     * The wipe must still destroy the legacy surface BY NAME, for an install that
     * is wiped before it is ever relaunched with the purge (e.g. the inactivity
     * dead-man's switch firing at MainActivity.onCreate on the first launch after
     * upgrade — the wipe runs, the app dies, the purge's own pass is moot).
     * `TorWarmCacheCrypto` owned these names and is deleted, so nothing else
     * would: this is the "deleted the class together with its wipe entries"
     * mistake, pinned.
     */
    @Test
    fun wipe_stillDestroysTheLegacyWarmCacheSurfaceByName() {
        seedLegacyWarmCache()

        WipeRoutine.wipePersistentState(ctx)

        assertFalse("the wipe must crypto-erase the legacy alias", keystoreHasLegacyAlias())
        assertFalse("the wipe must delete the legacy wrapped keyset", keysetXml.exists())
        assertFalse("the wipe must delete the legacy blob", blob.exists())
        assertFalse("the wipe must delete a stranded legacy .tmp", blobTmp.exists())
    }

    /**
     * A purge pass that runs after a wipe (RunApplication.onCreate in a process
     * whose MainActivity.onCreate already wiped is not the ordering, but a future
     * caller could be) must not re-create anything the wipe removed. It performs
     * no writes at all, so this holds without gating on [ProcessWipeLatch] — which
     * is exactly why it does not gate on it.
     */
    @Test
    fun purgeAfterAWipe_recreatesNothing() {
        seedLegacyWarmCache()
        WipeRoutine.wipePersistentState(ctx)
        val filesBefore = listing(ctx.filesDir)
        val prefsBefore = listing(File(ctx.dataDir, "shared_prefs"))

        LegacyTorWarmCache.purgeLegacyWarmCache(ctx)

        assertNoNewFiles("filesDir", filesBefore, listing(ctx.filesDir))
        assertNoNewFiles("shared_prefs", prefsBefore, listing(File(ctx.dataDir, "shared_prefs")))
        assertFalse("a post-wipe purge must create no keyset", keysetXml.exists())
        assertFalse("a post-wipe purge must create no Keystore alias", keystoreHasLegacyAlias())
    }

    // -----------------------------------------------------------------------

    /**
     * Reconstructs exactly what a pre-retirement install has on disk: the AEAD
     * blob (plus a stranded `.tmp`), the wrapped-keyset prefs file, and the
     * weak-gated Keystore master key — spec copied verbatim from the deleted
     * `TorWarmCacheCrypto.buildTorCacheKeySpec`, i.e. NO
     * `setUnlockedDeviceRequired`.
     */
    private fun seedLegacyWarmCache() {
        blob.writeBytes(ByteArray(128) { (it % 251).toByte() })
        blobTmp.writeBytes(ByteArray(32) { it.toByte() })
        ctx.getSharedPreferences(
            LegacyTorWarmCache.LEGACY_KEYSET_PREFS_NAME, Context.MODE_PRIVATE
        ).edit().putString("run_torcache_aead_keyset", "wrapped-keyset").commit()
        try {
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
                init(
                    KeyGenParameterSpec.Builder(
                        LEGACY_MASTER_KEY_ALIAS,
                        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
                    )
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .setKeySize(256)
                        .build()
                )
            }.generateKey()
        } catch (_: Exception) {
            // If the emulator refuses to mint the key the alias assertions still
            // hold (absent is absent); the file assertions carry the test.
        }
    }

    private fun clean() {
        blob.delete()
        blobTmp.delete()
        ctx.deleteSharedPreferences(LegacyTorWarmCache.LEGACY_KEYSET_PREFS_NAME)
        try {
            KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
                .deleteEntry(LEGACY_MASTER_KEY_ALIAS)
        } catch (_: Exception) { /* absent */ }
    }

    private fun listing(dir: File): Set<String> =
        dir.listFiles()?.map { it.name }?.toSortedSet() ?: sortedSetOf()

    /**
     * Asserted as "no NEW name", not as equality: WipeRoutine's Firebase
     * onSettled sweep can still be REMOVING files on its own thread, which must
     * not read as a failure here.
     *
     * Scoped to names this purge could plausibly MINT, deliberately. Asserting
     * that the whole directory is frozen fails spuriously: instrumented classes
     * share ONE app process, so unrelated tests (and RunApplication itself) can
     * legitimately create prefs — `vault_selector_prefs.xml` did exactly that on
     * 2026-07-31 and reported as a purge failure, which it was not. The property
     * actually under test is narrow: a purge that finds nothing must not CREATE
     * the artifacts it exists to delete. That is the real hazard here — an
     * `edit().remove().commit()` against a missing prefs file creates it, which
     * is how the sibling manifest purge would have minted `notif_manifest_prefs.xml`
     * on fresh installs (it is guarded by a `contains()` check for that reason).
     */
    private fun assertNoNewFiles(where: String, before: Set<String>, after: Set<String>) {
        val relevant = { n: String -> n.contains("torcache") || n.contains("tor_warm_cache") }
        val added = (after - before).filter(relevant)
        assertTrue(
            "$where must gain no warm-cache file, but got $added " +
                "(all new names: ${after - before})",
            added.isEmpty(),
        )
    }

    private fun keystoreHasLegacyAlias(): Boolean = try {
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            .containsAlias(LEGACY_MASTER_KEY_ALIAS)
    } catch (_: Exception) {
        false
    }

    companion object {
        /** Hard-coded on purpose: the test must fail if production quietly
         *  renames these instead of deleting them. */
        private const val BLOB_FILE = "tor_warm_cache.enc"
        private const val LEGACY_MASTER_KEY_ALIAS = "run_torcache_master_key"
    }
}

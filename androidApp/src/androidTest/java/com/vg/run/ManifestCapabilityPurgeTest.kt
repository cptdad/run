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
 * The AFU-class relay-capability mirror must
 * be GONE from installs that already have it, not merely absent from new ones.
 *
 * The removed feature stored, in `notif_manifest_prefs/manifest_enc`, an AEAD
 * blob of (inboxId, relay READ capability) pairs sealed under a Keystore key
 * (`run_manifest_master_key`) deliberately built WITHOUT
 * `setUnlockedDeviceRequired(true)` — usable while the phone is locked. The read
 * capability is the inbox OWNER capability (drain / delete-inbox / rotate BOTH
 * capabilities), so an AFU forensic image of a locked-but-powered device yielded
 * that authority per inbound inbox.
 *
 * Deleting the code deletes none of that data. This class covers the one-time
 * purge that does — plus the two properties it must not break: the plaintext
 * opt-in flag survives, and nothing is created on an install that never had the
 * mirror.
 *
 * INSTRUMENTED because the artifacts are a real AndroidKeystore alias and real
 * SharedPreferences files; neither exists in this project's plain-JVM
 * androidUnitTest tier (no Robolectric). Same tier and shape as
 * WipeRoutineResidueTest / LegacyTorWarmCachePurgeTest.
 *
 * Run with: ./gradlew connectedAndroidTest --tests "com.vg.run.ManifestCapabilityPurgeTest"
 */
@RunWith(AndroidJUnit4::class)
class ManifestCapabilityPurgeTest {

    private lateinit var ctx: Context

    private val optInPrefsXml: File
        get() = File(ctx.dataDir, "shared_prefs/${NotificationPollStore.PREFS_NAME}.xml")
    private val legacyKeysetXml: File
        get() = File(ctx.dataDir, "shared_prefs/${NotificationPollStore.LEGACY_KEYSET_PREFS_NAME}.xml")

    @Before
    fun setUp() {
        ctx = ApplicationProvider.getApplicationContext()
        // A wipe test that ran earlier in this shared process may have latched;
        // the purge deliberately refuses to write once latched.
        ProcessWipeLatch.resetForTest()
        clean()
    }

    @After
    fun tearDown() {
        ProcessWipeLatch.resetForTest()
        clean()
    }

    /**
     * The upgrade case: a device that shipped the feature carries all three
     * artifacts. After one purge pass every one of them is gone — and the opt-in
     * flag, which is a plain boolean and NOT capability material, is untouched.
     *
     * The opt-in flag is read via [legacyOptInFlagRaw] — a raw SharedPreferences
     * read against the LITERAL legacy key — rather than
     * `NotificationPollStore.isEnabled`, which Task #12 (2026-07-31) deleted:
     * the live opt-in now lives in `NotificationLevelStore`
     * (`notification_level_prefs`), a completely separate file this purge
     * never touches. What THIS test still needs to prove is narrower and
     * unchanged: that `purgeLegacyCapabilityMirror` — which targets exactly
     * one key (`manifest_enc`) inside `notif_manifest_prefs` — does not
     * collaterally erase a sibling key in the SAME file.
     */
    @Test
    fun purge_destroysBlob_keyset_andKeystoreAlias_butKeepsTheOptIn() {
        seedLegacyMirror(optedIn = true)
        assertTrue("seed: the cap mirror must exist", ctx.getSharedPreferences(
            NotificationPollStore.PREFS_NAME, Context.MODE_PRIVATE
        ).contains(LEGACY_KEY_MANIFEST))
        assertTrue("seed: the wrapped keyset must exist", legacyKeysetXml.exists())
        assertTrue("seed: the Keystore alias must exist", keystoreHasLegacyAlias())

        NotificationPollStore.purgeLegacyCapabilityMirror(ctx)

        assertFalse(
            "the (inboxId, readCap) blob must be gone",
            ctx.getSharedPreferences(NotificationPollStore.PREFS_NAME, Context.MODE_PRIVATE)
                .contains(LEGACY_KEY_MANIFEST),
        )
        assertFalse("the wrapped Tink keyset must be gone", legacyKeysetXml.exists())
        assertFalse("the weak-gated Keystore alias must be crypto-erased", keystoreHasLegacyAlias())
        assertTrue(
            "the (legacy, now-dead) opt-in key is not capability material and must survive",
            legacyOptInFlagRaw(),
        )
    }

    /**
     * Stronger than "the key is gone": no file under shared_prefs may still hold
     * the mirror's key name or its value. A purge that removed the Keystore alias
     * but left the ciphertext (or moved it) would still be a dated artifact
     * proving inbox ids were mirrored outside the vault.
     */
    @Test
    fun purge_leavesNoCapabilityMaterialInAnyPrefsFile() {
        seedLegacyMirror(optedIn = true)

        NotificationPollStore.purgeLegacyCapabilityMirror(ctx)

        val offenders = File(ctx.dataDir, "shared_prefs").listFiles().orEmpty().filter { f ->
            val text = try { f.readText() } catch (_: Exception) { "" }
            text.contains(LEGACY_KEY_MANIFEST) || text.contains(SENTINEL_BLOB)
        }
        assertTrue(
            "no prefs file may retain the cap mirror, but found: ${offenders.map { it.name }}",
            offenders.isEmpty(),
        )
    }

    /**
     * Idempotent, and inert on an install that never opted into push.
     *
     * The second property is not cosmetic. `edit().remove().commit()` against a
     * prefs file that does not exist CREATES it, so an unguarded purge running on
     * every launch would MINT notif_manifest_prefs.xml on a fresh — or freshly
     * wiped — install: exactly the "this app was configured" artifact the wipe
     * paths exist to remove.
     */
    @Test
    fun purge_isIdempotent_andCreatesNothingWhenThereWasNoMirror() {
        // Clean slate: no opt-in file, no keyset, no alias.
        assertFalse("precondition: no opt-in prefs file", optInPrefsXml.exists())

        repeat(3) { NotificationPollStore.purgeLegacyCapabilityMirror(ctx) }

        assertFalse(
            "the purge must never create the prefs file it only deletes from",
            optInPrefsXml.exists(),
        )
        assertFalse("no keyset may be created", legacyKeysetXml.exists())
        assertFalse("no Keystore alias may be created", keystoreHasLegacyAlias())
        assertFalse("opt-in must stay off by default", legacyOptInFlagRaw())

        // …and repeating it over a real mirror converges to the same state.
        seedLegacyMirror(optedIn = true)
        NotificationPollStore.purgeLegacyCapabilityMirror(ctx)
        NotificationPollStore.purgeLegacyCapabilityMirror(ctx)
        assertFalse("second pass must not resurrect the keyset", legacyKeysetXml.exists())
        assertFalse("second pass must not resurrect the alias", keystoreHasLegacyAlias())
        assertTrue("second pass must not disturb the opt-in", legacyOptInFlagRaw())
    }

    /**
     * The wipe still destroys the legacy surface BY NAME, for installs that are
     * wiped before they are ever relaunched with the purge (e.g. the inactivity
     * dead-man's switch firing at MainActivity.onCreate on the first launch after
     * upgrade — the wipe runs, the app dies, the purge's own pass is moot).
     * `ManifestCrypto` owned these names and is deleted, so nothing else would.
     */
    @Test
    fun wipe_stillCryptoErasesTheLegacyManifestKeySurfaceByName() {
        seedLegacyMirror(optedIn = true)

        WipeRoutine.wipePersistentState(ctx)

        assertFalse("the wipe must crypto-erase the legacy alias", keystoreHasLegacyAlias())
        assertFalse("the wipe must delete the legacy wrapped keyset", legacyKeysetXml.exists())
        assertFalse("the wipe must delete the opt-in prefs file entirely", optInPrefsXml.exists())
    }

    /**
     * A purge pass that runs after a wipe must not re-create the prefs file the
     * wipe deleted — a post-wipe-dated notif_manifest_prefs.xml carrying the
     * wiped install's opt-in flag is precisely the residue class fixed twice
     * already today (apply()-after-delete, and the warm-cache resurrection).
     */
    @Test
    fun purgeAfterAWipe_recreatesNothing() {
        seedLegacyMirror(optedIn = true)
        WipeRoutine.wipePersistentState(ctx)
        assertFalse("precondition: the wipe removed the prefs file", optInPrefsXml.exists())

        NotificationPollStore.purgeLegacyCapabilityMirror(ctx)

        assertFalse("a post-wipe purge must create no prefs file", optInPrefsXml.exists())
        assertFalse("a post-wipe purge must create no keyset", legacyKeysetXml.exists())
        assertFalse("a post-wipe purge must create no Keystore alias", keystoreHasLegacyAlias())
    }

    // -----------------------------------------------------------------------

    /**
     * Reconstructs exactly what a pre-manifest-removal install has on disk: the base64 AEAD
     * blob under `manifest_enc`, the wrapped-keyset prefs file, and the
     * weak-gated Keystore master key (spec copied verbatim from the deleted
     * `ManifestCrypto.buildManifestKeySpec` — no `setUnlockedDeviceRequired`).
     */
    private fun seedLegacyMirror(optedIn: Boolean) {
        ctx.getSharedPreferences(NotificationPollStore.PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .putBoolean(LEGACY_KEY_OPT_IN, optedIn)
            .putString(LEGACY_KEY_MANIFEST, SENTINEL_BLOB)
            .commit()
        ctx.getSharedPreferences(NotificationPollStore.LEGACY_KEYSET_PREFS_NAME, Context.MODE_PRIVATE)
            .edit().putString("run_manifest_aead_keyset", "wrapped-keyset").commit()
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
            // If the emulator refuses to mint the key the alias assertions below
            // still hold (absent is absent); the prefs assertions carry the test.
        }
    }

    private fun clean() {
        ctx.deleteSharedPreferences(NotificationPollStore.PREFS_NAME)
        ctx.deleteSharedPreferences(NotificationPollStore.LEGACY_KEYSET_PREFS_NAME)
        try {
            KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
                .deleteEntry(LEGACY_MASTER_KEY_ALIAS)
        } catch (_: Exception) { /* absent */ }
    }

    private fun keystoreHasLegacyAlias(): Boolean = try {
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            .containsAlias(LEGACY_MASTER_KEY_ALIAS)
    } catch (_: Exception) {
        false
    }

    /**
     * Raw read of the RETIRED `bg_notifications_enabled` key inside
     * `notif_manifest_prefs` (Task #12, 2026-07-31 — `NotificationPollStore
     * .isEnabled` is deleted; nothing reads this key for real any more). Reads
     * straight off SharedPreferences rather than through any store API, on
     * purpose: this test's job is to prove `purgeLegacyCapabilityMirror`
     * doesn't collaterally erase a SIBLING key in the same prefs file, not to
     * exercise the (now-defunct) opt-in accessor.
     */
    private fun legacyOptInFlagRaw(): Boolean =
        ctx.getSharedPreferences(NotificationPollStore.PREFS_NAME, Context.MODE_PRIVATE)
            .getBoolean(LEGACY_KEY_OPT_IN, false)

    companion object {
        /** The removed blob's prefs key — hard-coded on purpose: the test must
         *  fail if production quietly renames it instead of deleting it. */
        private const val LEGACY_KEY_MANIFEST = "manifest_enc"
        private const val LEGACY_MASTER_KEY_ALIAS = "run_manifest_master_key"
        private const val SENTINEL_BLOB = "H3SENTINELreadCapMirrorBase64Blob=="

        /** The retired opt-in key (Task #12) — hard-coded, same reasoning as
         *  [LEGACY_KEY_MANIFEST]: this test reads it raw specifically so it
         *  does not depend on the (now-deleted) `NotificationPollStore.isEnabled`. */
        private const val LEGACY_KEY_OPT_IN = "bg_notifications_enabled"
    }
}

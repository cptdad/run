package com.vg.run

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/**
 * Task #11 (2026-07-31): the remaining post-wipe write window on the general
 * key-value path.
 *
 * THE BUG. `SharedPreferences.Editor.apply()` SNAPSHOTS the whole in-memory map
 * and hands it to a background flush. `Context.deleteSharedPreferences` (what
 * `WipeRoutine` runs over every prefs file) evicts the ContextImpl cache entry
 * and unlinks the file but neither cancels nor awaits that queued flush — and
 * `SharedPreferencesImpl.writeToFile` only short-circuits the "nothing changed"
 * case WHEN THE FILE STILL EXISTS. So a write issued moments before a wipe lands
 * AFTER it and RE-CREATES vault_selector_prefs.xml from the pre-wipe snapshot:
 * `vlt_a`, `vlt_c` and `vlt_rc` back on disk, dated after the crypto-erase. The
 * fix is `commit()` on both remaining sites (plus a `contains()` guard so a
 * no-op removal cannot MINT the file it was only meant to delete from).
 *
 * INSTRUMENTED because SharedPreferences needs a real Android runtime; this
 * project has no Robolectric in its plain-JVM `androidUnitTest` tier. Same tier
 * and shape as WipeRoutineResidueTest / ManifestCapabilityPurgeTest /
 * LegacyTorWarmCachePurgeTest.
 *
 * Assertions read the XML OFF DISK, never through SharedPreferences: the
 * in-memory map is updated by `apply()` too, so a `getString` read-back proves
 * nothing about durability. Scoped to the two prefs names under test —
 * instrumented classes share ONE app process, so asserting a whole directory is
 * unchanged fails spuriously.
 *
 * Run with: ./gradlew connectedAndroidTest --tests "com.vg.run.KeyValueStoreWriteDurabilityTest"
 */
@RunWith(AndroidJUnit4::class)
class KeyValueStoreWriteDurabilityTest {

    private lateinit var ctx: Context

    private fun xml(name: String) = File(ctx.dataDir, "shared_prefs/$name.xml")

    @Before
    fun setUp() {
        ctx = ApplicationProvider.getApplicationContext()
        // An earlier wipe test in this shared process may have latched. Nothing
        // here gates on it — deliberately, see postWipe_writeStillLands — but a
        // set latch would be a confusing precondition.
        ProcessWipeLatch.resetForTest()
        clean()
    }

    @After
    fun tearDown() {
        ProcessWipeLatch.resetForTest()
        clean()
    }

    private fun clean() {
        ctx.deleteSharedPreferences(SCRATCH_PREFS)
        ctx.deleteSharedPreferences(SELECTOR_PREFS)
    }

    // -----------------------------------------------------------------------
    // The property that closes the window: nothing is left queued.
    // -----------------------------------------------------------------------

    /**
     * `putString` must have reached the XML file by the time it returns. With
     * `apply()` the file frequently does not exist yet at this point, and even
     * when it does the value is whatever the last flush happened to carry — i.e.
     * there is a queued write outstanding, which is precisely what can land after
     * a wipe.
     */
    @Test
    fun putString_isOnDiskBeforeItReturns() {
        KeyValueStore(ctx, SCRATCH_PREFS).putString(KEY_A, VALUE_A)

        assertTrue("putString must create the prefs file synchronously", xml(SCRATCH_PREFS).isFile)
        assertTrue(
            "the value must be on disk when putString returns, not queued",
            xml(SCRATCH_PREFS).readText().contains(VALUE_A),
        )
    }

    /**
     * Same for `remove`. A removal here is a security-state transition — dropping
     * `vlt_rc` revokes the recovery code, the SECOND independent vault-decrypt
     * path — so it must not be discardable by a process death, and must not be
     * sitting in a queue when a wipe unlinks the file.
     */
    @Test
    fun remove_isOnDiskBeforeItReturns() {
        val store = KeyValueStore(ctx, SCRATCH_PREFS)
        store.putString(KEY_A, VALUE_A)
        assertTrue("seed must be on disk", xml(SCRATCH_PREFS).readText().contains(VALUE_A))

        store.remove(KEY_A)

        assertFalse(
            "the removal must be on disk when remove returns, not queued",
            xml(SCRATCH_PREFS).readText().contains(VALUE_A),
        )
    }

    // -----------------------------------------------------------------------
    // The minting guard.
    // -----------------------------------------------------------------------

    /**
     * Removing a key that is not there must touch nothing at all.
     *
     * `edit().remove(k).commit()` on an absent key makes NO change, and
     * SharedPreferencesImpl only skips the disk write for a no-change commit when
     * the file ALREADY EXISTS — with the file missing it writes an empty map,
     * MINTING the file. That is not hypothetical: `VaultSelector`'s constructor
     * issues four unconditional `remove` calls (the leftover-decoy purge) and a
     * VaultSelector is constructed three times per launch, including the launch
     * right after a wipe. Same guard, same reason, as
     * `NotificationPollStore.purgeLegacyCapabilityMirror`'s `contains()` check.
     */
    @Test
    fun remove_ofAnAbsentKey_createsNoPrefsFile() {
        assertFalse("precondition: no prefs file", xml(SCRATCH_PREFS).exists())

        repeat(4) { KeyValueStore(ctx, SCRATCH_PREFS).remove(KEY_A) }

        assertFalse(
            "a no-op removal must never mint the prefs file it only deletes from",
            xml(SCRATCH_PREFS).exists(),
        )
    }

    // -----------------------------------------------------------------------
    // End-to-end: the residue the wipe exists to remove.
    // -----------------------------------------------------------------------

    /**
     * Credential material written just before a wipe must not come back.
     *
     * The seeded values stand in for what really lives here: the credential
     * verifier (`vlt_a`), the PIN-wrapped SQLCipher passphrase (`vlt_c`) and the
     * Lever-B recovery blob (`vlt_rc`) — the last of which is an INDEPENDENT wrap
     * of the same passphrase, so resurrecting the file post-wipe restores a
     * second decrypt path's ciphertext alongside the first.
     *
     * The settle window is a belt: the durability assertions above already prove
     * nothing is queued, so a regression fails this test at the first check
     * rather than by timing. A false PASS would need a flush delayed past the
     * window; a false FAIL is impossible — nothing else in this process writes
     * these names.
     */
    @Test
    fun writeThenWipe_leavesNoResurrectedSelectorPrefs() {
        val store = KeyValueStore(ctx, SELECTOR_PREFS)
        store.putString(CREDENTIAL_KEY, "verifier-blob-base64==")
        store.putString(VAULT_DBKEY_STORAGE_KEY, "wrapped-db-key-base64==")
        store.putString(RECOVERY_BLOB_KEY, "recovery-blob-base64==")
        assertTrue("seed must be on disk", xml(SELECTOR_PREFS).isFile)

        WipeRoutine.wipePersistentState(ctx)
        assertFalse("the wipe must delete the selector prefs", xml(SELECTOR_PREFS).exists())

        Thread.sleep(SETTLE_MS)

        assertFalse(
            "no queued write may re-create the selector prefs after the wipe",
            xml(SELECTOR_PREFS).exists(),
        )
    }

    /**
     * The decoy-purge minting path, end to end: constructing a `VaultSelector`
     * after a wipe must not hand the examiner a freshly dated
     * vault_selector_prefs.xml. Its constructor's only writes are the four
     * leftover-decoy removes and a legacy-key-name migration that has nothing to
     * migrate — on a wiped install every one of them is a no-op, and a no-op must
     * write nothing.
     */
    @Test
    fun vaultSelectorConstructedAfterAWipe_mintsNoSelectorPrefs() {
        KeyValueStore(ctx, SELECTOR_PREFS).putString(VAULT_DBKEY_STORAGE_KEY, "wrapped-db-key")
        WipeRoutine.wipePersistentState(ctx)
        assertFalse("precondition: the wipe removed the file", xml(SELECTOR_PREFS).exists())

        repeat(3) {
            VaultSelector(
                store = KeyValueStore(ctx, SELECTOR_PREFS),
                crypto = CryptoProvider(ctx),
                vaultFactory = androidVaultFactory(ctx),
            )
        }

        assertFalse(
            "a post-wipe VaultSelector construction must create no prefs file",
            xml(SELECTOR_PREFS).exists(),
        )
    }

    // -----------------------------------------------------------------------
    // BRICK-SAFETY: the fix must not become a silent-write-failure mode.
    // -----------------------------------------------------------------------

    /**
     * The load-bearing counterpart to everything above, and the reason this fix
     * is `commit()` and NOT a [ProcessWipeLatch] gate.
     *
     * Re-provisioning in the SAME process after a wipe is an explicitly supported
     * flow — MainActivity's orphaned-credential wipe runs in `onCreate` and then
     * routes straight to setup — and `provisionCredentialAndVault` persists the
     * credential verifier and the wrapped DB key through `putString`. A latch that
     * refused post-wipe writes would let setup create the vault FILE while
     * silently dropping the credential behind it: `isConfigured()` false + vault
     * present = the orphaned-vault dead end, i.e. the Android equivalent of iOS's
     * locked-keybag `kvPut` failing silently. If this test ever fails, the fix has
     * acquired exactly the failure mode it was written to avoid.
     */
    @Test
    fun postWipe_credentialShapedWriteStillLands() {
        WipeRoutine.wipePersistentState(ctx)
        assertTrue("precondition: the wipe latched", ProcessWipeLatch.wipedThisProcess)

        val store = KeyValueStore(ctx, SELECTOR_PREFS)
        store.putString(CREDENTIAL_KEY, "fresh-verifier==")
        store.putString(VAULT_DBKEY_STORAGE_KEY, "fresh-wrapped-db-key==")

        val onDisk = xml(SELECTOR_PREFS).readText()
        assertTrue("a post-wipe re-provision must persist the verifier", onDisk.contains("fresh-verifier=="))
        assertTrue("a post-wipe re-provision must persist the DB key", onDisk.contains("fresh-wrapped-db-key=="))
        assertTrue("…and it must be readable back", store.contains(VAULT_DBKEY_STORAGE_KEY))

        // A real removal after a wipe must still land too (e.g. disabling Lever B
        // on the freshly re-provisioned vault revokes the recovery blob).
        store.putString(RECOVERY_BLOB_KEY, "fresh-recovery==")
        store.remove(RECOVERY_BLOB_KEY)
        assertFalse(
            "a post-wipe revocation must not be silently dropped",
            xml(SELECTOR_PREFS).readText().contains("fresh-recovery=="),
        )
    }

    companion object {
        /** Its own file so nothing here collides with a sibling test class. */
        private const val SCRATCH_PREFS = "kv_durability_scratch_prefs"

        /** The real name, because this is the file WipeRoutine must leave deleted. */
        private const val SELECTOR_PREFS = "vault_selector_prefs"

        /**
         * Hard-coded on purpose (the `VaultSelector` companion holding these is
         * `internal` to :shared, so this module cannot name them — same as
         * VaultSelectorTest's own K_* constants): the test must fail if
         * production quietly renames a credential slot rather than keeping it in
         * the wipe's blast radius. `vlt_c` DOES have a public alias
         * ([VAULT_DBKEY_STORAGE_KEY]) and is referenced through it below.
         */
        private const val CREDENTIAL_KEY = "vlt_a"
        private const val RECOVERY_BLOB_KEY = "vlt_rc"

        private const val KEY_A = "probe_key"
        private const val VALUE_A = "TASK11-DURABILITY-SENTINEL"

        /** Generous enough that a pre-fix `apply()` flush would certainly have landed. */
        private const val SETTLE_MS = 750L
    }
}

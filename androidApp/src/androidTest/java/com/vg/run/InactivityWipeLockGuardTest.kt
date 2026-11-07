package com.vg.run

import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/**
 * Instrumented regression test for the locked-device InactivityWipe bug.
 *
 * The bug: checkAndWipeIfNeeded() decrypts the last-opened timestamp with the
 * unlocked-device-required Keystore key. While the device is locked that key is
 * unusable, decryption fails, and the fail-open path treated the timestamp as
 * expired and wiped the vault. The fix DEFERS the check when the device is
 * locked (returns false, no wipe) and still wipes on a genuine
 * expired+unlocked launch.
 *
 * Run with: ./gradlew connectedAndroidTest
 */
@RunWith(AndroidJUnit4::class)
class InactivityWipeLockGuardTest {

    companion object {
        private const val DB_NAME        = "run.db"
        private const val DB_KEY_PREFS   = "db_key_prefs"
        private const val INACTIVITY_PREFS = "inactivity_prefs"
        // The check reads the protection level from here (device-key AEAD blob);
        // cleared so a leftover level from other tests can't skew thresholds.
        private const val SELECTOR_PREFS = "vault_selector_prefs"

        private const val CONTACT_ID = "lockguard-contact-001"

        // CR-1: DatabaseManager takes the SQLCipher passphrase directly.
        private val TEST_DB_KEY = ByteArray(32) { (it + 1).toByte() }
    }

    private lateinit var context: Context
    private lateinit var databaseManager: DatabaseManager
    private var originalThreshold: Long = 0L

    @Before
    fun setUp() {
        context = InstrumentationRegistry.getInstrumentation().targetContext
        originalThreshold = InactivityWipe.thresholdMs

        // Clean slate.
        context.deleteDatabase(DB_NAME)
        context.deleteSharedPreferences(DB_KEY_PREFS)
        context.deleteSharedPreferences(INACTIVITY_PREFS)
        context.deleteSharedPreferences(SELECTOR_PREFS)

        // isProvision=true: setUp creates a fresh vault DB, so this is the provision
        // open, exempt from the unlock-path empty-vault guard (reopen helper stays false).
        databaseManager = DatabaseManager(context, TEST_DB_KEY, isProvision = true)

        // Seed detectable state — a contact that any wipe destroys.
        val now = System.currentTimeMillis()
        databaseManager.insertContact(ContactRecord(
            contactId        = CONTACT_ID,
            sharedSecret     = ByteArray(0),
            trustLevel       = 1,
            alias            = "Lock Guard Contact",
            aliasLastRotated = now
        ))
    }

    @After
    fun tearDown() {
        InactivityWipe.thresholdMs = originalThreshold
        context.deleteDatabase(DB_NAME)
        context.deleteSharedPreferences(DB_KEY_PREFS)
        context.deleteSharedPreferences(INACTIVITY_PREFS)
        context.deleteSharedPreferences(SELECTOR_PREFS)
    }

    private fun contactSurvives(): Boolean {
        // Re-open the DB each time so we observe on-disk state, not a stale handle.
        // A genuine wipe crypto-erases/removes the vault DB; the reopen here
        // (isProvision=false) then trips the fail-closed empty-vault guard added
        // after this test was written (DatabaseManager.kt) and
        // THROWS rather than returning an empty DB. That thrown guard IS the
        // "vault is gone" signal, so treat it as "contact did not survive" — not
        // as a test error. (The only IllegalStateException a plain open raises is
        // that guard.)
        return try {
            DatabaseManager(context, TEST_DB_KEY).getContact(CONTACT_ID) != null
        } catch (e: IllegalStateException) {
            false
        }
    }

    @Test
    fun inactivityWipe_whileLocked_defersAndPreservesData_butStillWipesWhenUnlocked() {
        // 1. Sanity: seeded contact present.
        assertTrue("Seeded contact must exist before any check", contactSurvives())

        // 2. Prime an OLD last-opened timestamp. With a large threshold the
        //    first (unlocked) call simply stores "now" and does not wipe.
        InactivityWipe.thresholdMs = Long.MAX_VALUE
        val storedFirst = InactivityWipe.checkAndWipeIfNeeded(context, deviceLocked = false)
        assertFalse("First call must only record the timestamp, not wipe", storedFirst)
        assertTrue("Contact must survive timestamp recording", contactSurvives())

        // Now make that stored timestamp count as expired.
        InactivityWipe.thresholdMs = 1L
        Thread.sleep(5)

        // 3. Deferral: a locked device must NOT wipe even though expired.
        val lockedResult = InactivityWipe.checkAndWipeIfNeeded(context, deviceLocked = true)
        assertFalse("Locked device must defer (return false)", lockedResult)
        assertTrue("Data must SURVIVE when the device is locked", contactSurvives())

        // 4. Genuine wipe: unlocked + expired must still destroy data.
        val unlockedResult = InactivityWipe.checkAndWipeIfNeeded(context, deviceLocked = false)
        assertTrue("Unlocked + expired must wipe (return true)", unlockedResult)
        assertFalse("Data must be GONE after a genuine inactivity wipe", contactSurvives())
    }

    /** Selector on the REAL prefs the wipe check reads (cleared in setUp/tearDown). */
    private fun selectorOnRealPrefs() = VaultSelector(
        store = KeyValueStore(context, SELECTOR_PREFS),
        crypto = CryptoProvider(context),
        vaultFactory = androidVaultFactory(context)
    )

    /**
     * Regression: the stored level is a device-key AEAD
     * blob, and the check must read it through the DECRYPTING path. The old
     * raw SharedPreferences read parsed the blob as null and silently kept the
     * (shorter) default threshold — here forced to 1 ms, standing in for the
     * 7-day default against CASUAL's 180-day window — and wiped early.
     */
    @Test
    fun blobStoredLevel_overridesShorterDefault_noEarlyWipe() {
        // Prime a timestamp, then make the DEFAULT window count as expired.
        InactivityWipe.thresholdMs = Long.MAX_VALUE
        InactivityWipe.checkAndWipeIfNeeded(context, deviceLocked = false)
        assertTrue(selectorOnRealPrefs().setProtectionLevel(ProtectionLevel.CASUAL))
        InactivityWipe.thresholdMs = 1L
        Thread.sleep(5)

        val wiped = InactivityWipe.checkAndWipeIfNeeded(context, deviceLocked = false)
        assertFalse("CASUAL's 180-day window must beat the shorter default", wiped)
        assertTrue("Data must survive — the chosen tier's window applies", contactSurvives())
        assertTrue("The level's window must now be in effect",
            InactivityWipe.thresholdMs == ProtectionLevel.CASUAL.inactivityWipeMs)
    }

    /**
     * Finding 1 fail-safe sibling: a level that EXISTS but cannot be read
     * (damaged blob here; a transient Keystore outage behaves the same) must
     * DEFER the check — never fall back to a shorter window and wipe.
     */
    @Test
    fun damagedLevelBlob_defersInsteadOfApplyingShorterWindow() {
        InactivityWipe.thresholdMs = Long.MAX_VALUE
        InactivityWipe.checkAndWipeIfNeeded(context, deviceLocked = false)
        // Blob-shaped (≥ IV+tag raw bytes) but fails AEAD — a damaged level blob.
        KeyValueStore(context, SELECTOR_PREFS)
            .putString("vlt_lvl", encodeBase64(ByteArray(40) { it.toByte() }))
        InactivityWipe.thresholdMs = 1L
        Thread.sleep(5)

        val wiped = InactivityWipe.checkAndWipeIfNeeded(context, deviceLocked = false)
        assertFalse("Unreadable level must defer the check (return false)", wiped)
        assertTrue("Data must SURVIVE when the stored level is unreadable", contactSurvives())
    }

    /**
     * The last-active clock is refreshed ONLY on a
     * real UNLOCK (recordUnlock), never on a bare launch — so a bare, un-authenticated
     * launch (including a defer on an unreadable level) must NOT re-stamp the
     * timestamp. Supersedes the old "defer still refreshes" contract: the early-wipe
     * concern it guarded against is now structurally gone, because the owner who keeps
     * using the app is the owner who keeps UNLOCKING it, and every unlock refreshes.
     */
    @Test
    fun damagedLevelBlob_deferDoesNotRecord_butUnlockDoes() {
        // Prime a baseline timestamp with a healthy (absent) level. vaultFileExists()
        // is true (setUp seeded run.db), so the absent-timestamp branch records once.
        InactivityWipe.thresholdMs = Long.MAX_VALUE
        InactivityWipe.checkAndWipeIfNeeded(context, deviceLocked = false)
        val prefs = context.getSharedPreferences(INACTIVITY_PREFS, Context.MODE_PRIVATE)
        val before = prefs.getString("last_opened_enc", null)
        assertNotNull("baseline timestamp must exist", before)

        // Damage the level blob → the check defers…
        KeyValueStore(context, SELECTOR_PREFS)
            .putString("vlt_lvl", encodeBase64(ByteArray(40) { it.toByte() }))
        Thread.sleep(5)
        val wiped = InactivityWipe.checkAndWipeIfNeeded(context, deviceLocked = false)
        assertFalse("Unreadable level must defer the check (return false)", wiped)

        // …and the defer (a bare launch) must NOT touch the timestamp any more.
        val afterDefer = prefs.getString("last_opened_enc", null)
        assertTrue("defer/bare-launch must NOT re-stamp the timestamp", afterDefer == before)

        // A real UNLOCK is the only thing that advances the clock.
        Thread.sleep(5)
        InactivityWipe.recordUnlock(context, CryptoProvider(context))
        val afterUnlock = prefs.getString("last_opened_enc", null)
        assertNotNull("unlock must record a timestamp", afterUnlock)
        assertTrue("unlock must refresh the timestamp (fresh AES-GCM IV differs)",
            afterUnlock != before)
    }

    /**
     * (c) The timestamp refreshes on UNLOCK, not on a bare
     * launch. A seized-but-not-vault-unlocked phone (repeated bare launches) must not
     * be able to hold the dead-man's-switch open.
     */
    @Test
    fun timestampRefreshesOnUnlock_notOnBareLaunch() {
        val prefs = context.getSharedPreferences(INACTIVITY_PREFS, Context.MODE_PRIVATE)
        // First bare launch starts the clock (vault file present).
        InactivityWipe.thresholdMs = Long.MAX_VALUE
        InactivityWipe.checkAndWipeIfNeeded(context, deviceLocked = false)
        val t0 = prefs.getString("last_opened_enc", null)
        assertNotNull("first launch must start the clock", t0)

        // A SECOND bare launch with a present, non-expired timestamp must leave it
        // byte-for-byte unchanged (no re-stamp).
        Thread.sleep(5)
        val wiped = InactivityWipe.checkAndWipeIfNeeded(context, deviceLocked = false)
        assertFalse("valid timestamp must not wipe", wiped)
        val t1 = prefs.getString("last_opened_enc", null)
        assertTrue("a bare launch must NOT refresh the timestamp", t1 == t0)

        // Only an unlock advances it.
        Thread.sleep(5)
        InactivityWipe.recordUnlock(context, CryptoProvider(context))
        val t2 = prefs.getString("last_opened_enc", null)
        assertTrue("unlock must refresh the timestamp", t2 != t0)
    }

    /**
     * (a) CRITICAL (2026-07-23): after an expiry wipe, NO new inactivity_prefs blob
     * may be written — the old code re-encrypted `now` through the just-erased key,
     * recreating the wipe-fingerprint artifact and arming a wipe-on-every-launch loop.
     */
    @Test
    fun expiredWipe_doesNotRewriteInactivityPrefs() {
        // Prime a timestamp, then make it expired.
        InactivityWipe.thresholdMs = Long.MAX_VALUE
        InactivityWipe.checkAndWipeIfNeeded(context, deviceLocked = false)
        assertTrue("timestamp must be primed before the wipe",
            context.getSharedPreferences(INACTIVITY_PREFS, Context.MODE_PRIVATE)
                .getString("last_opened_enc", null) != null)
        InactivityWipe.thresholdMs = 1L
        Thread.sleep(5)

        val wiped = InactivityWipe.checkAndWipeIfNeeded(context, deviceLocked = false)
        assertTrue("expired + unlocked must wipe", wiped)
        assertFalse("seeded data must be gone", contactSurvives())

        // The wipe deletes inactivity_prefs and must NOT recreate it: an absent blob
        // is what a never-configured install shows, so no wipe fingerprint remains.
        val after = context.getSharedPreferences(INACTIVITY_PREFS, Context.MODE_PRIVATE)
            .getString("last_opened_enc", null)
        assertTrue("no inactivity_prefs blob may exist after a wipe", after == null)
    }

    /**
     * (b) CRITICAL siblings: with NO vault configured, neither an ABSENT timestamp nor
     * a present-but-undecryptable one may trigger a wipe (post-wipe residue), and the
     * absent case must not recreate the inactivity_prefs blob.
     */
    @Test
    fun absentOrUndecryptableTimestamp_noVault_doesNotWipeOrRecreatePrefs() {
        // Clean, un-configured state: no vault file, no selector config, no timestamp.
        context.deleteDatabase(DB_NAME)
        context.deleteSharedPreferences(SELECTOR_PREFS)
        context.deleteSharedPreferences(INACTIVITY_PREFS)
        InactivityWipe.thresholdMs = 1L

        // b1: absent timestamp, no vault → no wipe, and nothing recreated.
        val wipedAbsent = InactivityWipe.checkAndWipeIfNeeded(context, deviceLocked = false)
        assertFalse("absent timestamp with no vault must never wipe", wipedAbsent)
        assertTrue("absent branch must not create a blob when no vault exists",
            context.getSharedPreferences(INACTIVITY_PREFS, Context.MODE_PRIVATE)
                .getString("last_opened_enc", null) == null)

        // b2: present-but-undecryptable blob (post-wipe orphan sealed under an erased
        // key), still no vault → must DEFER, never re-arm the wipe loop.
        context.getSharedPreferences(INACTIVITY_PREFS, Context.MODE_PRIVATE)
            .edit().putString("last_opened_enc", encodeBase64(ByteArray(40) { it.toByte() })).commit()
        InactivityWipe.thresholdMs = 1L
        val wipedOrphan = InactivityWipe.checkAndWipeIfNeeded(context, deviceLocked = false)
        assertFalse("undecryptable orphan blob with no vault must not wipe", wipedOrphan)
    }

    /**
     * (d) Regression 2026-07-30: the inactivity wipe must do NOTHING after
     * WipeRoutine returns. A reverted revision fired a relay-side push
     * unregister from here, which — with no ViewModel/transport existing at
     * Activity.onCreate time — had to stand up its OWN TorManager, warm cache
     * enabled. Its `finally` snapshotted that cache, whose AEAD init
     * REGENERATED the run_torcache_master_key Keystore alias and the
     * run_torcache_keyset_prefs Tink keyset when absent and then rewrote
     * filesDir/tor_warm_cache.enc — all three destroyed moments earlier by the
     * wipe, and TorManager.stop()'s wipeWorkingDirs() only removes
     * tor_direct/$sessionName, never the top-level blob. Net: a Keystore key, a
     * keyset file and an encrypted Tor guard/consensus blob all dated AFTER the
     * wipe, on the ONE wipe path that fires while the user is absent and cannot
     * re-wipe.
     *
     * The warm cache itself is RETIRED (2026-07-31) — nothing can write those
     * artifacts any more — but this test still seeds them and still asserts they
     * are gone, because the wipe must keep destroying them BY NAME on installs
     * that already have them ([LegacyTorWarmCache]), and because the real subject
     * here is "the inactivity path starts no Tor", which is unchanged.
     *
     * Background push is enabled on purpose: the reverted code was gated on the
     * opt-in flag, so without this seed it would never have reached the Tor start
     * this test watches for. (It was ALSO gated on a non-empty poll manifest,
     * which no longer exists — the manifest removal deleted the (inboxId, readCap) mirror along
     * with the whole locked-device relay path. The opt-in flag alone is now the
     * strongest precondition that can be seeded, and it is sufficient: the
     * assertions below are about Tor artifacts, not about the relay call.)
     */
    @Test
    fun expiredWipe_startsNoTor_andRecreatesNoTorArtifacts() {
        // What the reverted code would have tried to unregister. Task #12
        // (2026-07-31) retired NotificationPollStore.setEnabled — the opt-in
        // is now NotificationLevelStore's persisted level (same store/key
        // RunViewModel.setBackgroundNotificationsEnabledAwaiting writes at
        // toggle time), so seed that directly.
        // The opt-in is two slots now — the plaintext wake gate and a
        // device-key AEAD consent proof epoch-bound to the OPEN vault. This test
        // has no vault and asserts about Tor artifacts, so it seeds the plaintext
        // slot directly (`setLevel` refuses without a vault, by design).
        KeyValueStore(context, RunViewModel.NOTIFICATION_LEVEL_PREFS_NAME)
            .putString(NotificationLevelStore.KEY, NotificationLevel.VENDOR_PUSH.storageValue)

        // Tor state as it exists on a device that has actually used Tor.
        val torRoot = File(context.filesDir, "tor_direct")
        val torSession = File(torRoot, "sess-inactivity").apply { mkdirs() }
        File(torSession, "state").writeText("guard-state")
        val warmBlob = File(context.filesDir, "tor_warm_cache.enc").apply { writeText("ciphertext") }
        context.getSharedPreferences(LegacyTorWarmCache.LEGACY_KEYSET_PREFS_NAME, Context.MODE_PRIVATE)
            .edit().putString("keyset", "wrapped").commit()
        val warmKeyset =
            File(context.dataDir, "shared_prefs/${LegacyTorWarmCache.LEGACY_KEYSET_PREFS_NAME}.xml")
        assertTrue("Tor seeds must exist before the wipe",
            torRoot.exists() && warmBlob.exists() && warmKeyset.exists())

        // Prime, expire, and take the real wipe branch.
        InactivityWipe.thresholdMs = Long.MAX_VALUE
        InactivityWipe.checkAndWipeIfNeeded(context, deviceLocked = false)
        InactivityWipe.thresholdMs = 1L
        Thread.sleep(5)
        assertTrue("expired + unlocked must wipe",
            InactivityWipe.checkAndWipeIfNeeded(context, deviceLocked = false))

        fun assertNoTorResidue(phase: String) {
            assertFalse("$phase: tor_direct must not exist", torRoot.exists())
            assertFalse("$phase: tor_warm_cache.enc must not exist", warmBlob.exists())
            assertFalse("$phase: the warm-cache Tink keyset must not exist", warmKeyset.exists())
        }
        assertNoTorResidue("immediately after the wipe")

        // The reverted code's detached CoroutineScope(Dispatchers.IO) recreated
        // tor_direct/<session> (dir + torrc) within milliseconds of the wipe
        // returning, long before Tor finished bootstrapping. Give any such
        // background work a window to betray itself.
        Thread.sleep(2_000)
        assertNoTorResidue("2s after the wipe")
    }

    // -----------------------------------------------------------------------
    // The STORAGE half of the monotonic anchor.
    // InactivityPolicyTest (commonTest) pins the pure decision; these pin the
    // on-disk format change: every legacy vault must still read, must migrate on
    // write, and must not become easier to wipe.
    // -----------------------------------------------------------------------

    /** The AEAD context InactivityWipe seals the last-active record with. */
    private val stampAeadContext = "inactivity-wipe-timestamp".toByteArray(Charsets.UTF_8)

    /** Seals [plaintext] into the real KEY_LAST_OPENED slot, exactly as a build of
     *  the given vintage would have written it. */
    private fun seedStamp(crypto: CryptoProvider, plaintext: String) {
        context.getSharedPreferences(INACTIVITY_PREFS, Context.MODE_PRIVATE)
            .edit()
            .putString("last_opened_enc",
                encodeBase64(crypto.encrypt(plaintext.toByteArray(Charsets.UTF_8), stampAeadContext)))
            .commit()
    }

    private fun readStamp(crypto: CryptoProvider): String {
        val b64 = context.getSharedPreferences(INACTIVITY_PREFS, Context.MODE_PRIVATE)
            .getString("last_opened_enc", null)!!
        return crypto.decrypt(decodeBase64(b64), stampAeadContext).toString(Charsets.UTF_8)
    }

    /**
     * A vault provisioned BEFORE the anchor stored a bare decimal. It must still
     * read (no wipe, no crash), a bare launch must still not re-stamp it (finding
     * #11), and the next real UNLOCK must migrate it to the anchored shape.
     */
    @Test
    fun legacyBareDecimalStamp_stillReads_andMigratesOnUnlock() {
        val crypto = CryptoProvider(context)
        seedStamp(crypto, System.currentTimeMillis().toString())

        InactivityWipe.thresholdMs = ProtectionLevel.MAXIMUM.inactivityWipeMs
        assertFalse("a fresh legacy stamp must not wipe",
            InactivityWipe.checkAndWipeIfNeeded(context, deviceLocked = false))
        assertTrue("data must survive a legacy-format read", contactSurvives())
        assertFalse("a bare launch must NOT migrate the stamp",
            readStamp(crypto).contains('|'))

        InactivityWipe.recordUnlock(context, crypto)
        val migrated = readStamp(crypto)
        assertTrue("recordUnlock must write the anchored shape", migrated.contains('|'))
        val parsed = InactivityPolicy.parseStamp(migrated)
        assertNotNull("the migrated stamp must parse", parsed)
        assertTrue("the migrated stamp must carry a real uptime anchor",
            parsed!!.uptimeMs >= 0L)
    }

    /** The legacy read path must stay honest in the DESTRUCTIVE direction too — a
     *  genuinely expired pre-anchor stamp still wipes. */
    @Test
    fun legacyBareDecimalStamp_pastItsWindow_stillWipes() {
        val crypto = CryptoProvider(context)
        seedStamp(crypto, (System.currentTimeMillis() - 10_000L).toString())
        InactivityWipe.thresholdMs = 1L

        assertTrue("an expired legacy stamp must still wipe",
            InactivityWipe.checkAndWipeIfNeeded(context, deviceLocked = false))
        assertFalse("data must be gone", contactSurvives())
    }

    /**
     * End-to-end: a routine backward clock correction must NOT crypto-erase a
     * healthy vault. Under the old zero-tolerance rule, a stamp even ONE ms ahead
     * of `now` — which is what an NTP/NITZ snap-back after RTC drift produces, on
     * a timestamp that is refreshed at every unlock — wiped everything, including
     * the recovery blob.
     */
    @Test
    fun clockCorrectionWithinTolerance_doesNotWipe_butADeliberateBackSetDoes() {
        val crypto = CryptoProvider(context)
        val hour = 60L * 60 * 1000
        // Legacy (unanchored) stamp, i.e. the worst case: nothing can vouch for the
        // elapsed time except the wall clock itself.
        seedStamp(crypto, (System.currentTimeMillis() + 6 * hour).toString())
        InactivityWipe.thresholdMs = ProtectionLevel.MAXIMUM.inactivityWipeMs

        assertFalse("a 6h backward correction must not wipe",
            InactivityWipe.checkAndWipeIfNeeded(context, deviceLocked = false))
        assertTrue("data must survive a routine clock correction", contactSurvives())

        // …while the move the branch exists for still fires.
        seedStamp(crypto, (System.currentTimeMillis() + 72 * hour).toString())
        assertTrue("a 3-day back-set must still wipe",
            InactivityWipe.checkAndWipeIfNeeded(context, deviceLocked = false))
        assertFalse("data must be gone after a deliberate back-set", contactSurvives())
    }
}

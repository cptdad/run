package com.vg.run

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented tests for the (single) vault system (VaultSelector,
 * DatabaseManager).
 *
 * These verify that the vault is opened only by the correct credential, that
 * the SQLCipher passphrase is PIN-wrapped (CR-1) and survives a process
 * restart, and that PIN rotation preserves the vault's data. They also cover
 * the one-time key-name migration and the purge of decoy artifacts left by
 * installs provisioned before the decoy feature was removed.
 *
 * Run with: ./gradlew connectedAndroidTest --tests "*.VaultSelectorTest"
 */
@RunWith(AndroidJUnit4::class)
class VaultSelectorTest {

    private lateinit var context: android.content.Context
    private lateinit var vaultSelector: VaultSelector
    private var savedInactivityThresholdMs: Long = InactivityPolicy.THRESHOLD_MS

    companion object {
        private const val REAL_DB_NAME      = "run.db"
        private const val DECOY_DB_NAME     = "run_b.db"   // removed; cleaned up only
        private const val REAL_DB_PREFS     = "db_key_prefs"
        private const val SELECTOR_PREFS    = "vault_selector_prefs"
        // Read/written by the InactivityWipe end-to-end cases below; cleared per
        // test so a stamp (or the armed marker in SELECTOR_PREFS) left by
        // another class can't steer this one's dead-man's-switch decisions.
        private const val INACTIVITY_PREFS  = "inactivity_prefs"

        private const val REAL_PIN  = "1234"
        private const val WRONG_PIN = "0000"
        private const val NEW_REAL_PIN  = "246810"

        private val FAKE_SECRET  = "test-shared-secret".toByteArray(Charsets.UTF_8)

        // Neutral storage-key names (kept in sync with VaultSelector's internal
        // constants, which are not visible from this module). See the key-name
        // migration test below.
        private const val K_REAL_CRED   = "vlt_a"
        private const val K_REAL_DBKEY  = "vlt_c"
        private const val K_RECOVERY_BLOB    = "vlt_rc"
        private const val K_AUTHBOUND_SCHEME = "vlt_abk"   // strict-key marker
        private const val K_RECOVERY_PENDING = "vlt_rp"    // in-flight Lever B enable
        // Pre-migration discriminating names.
        private const val OLD_REAL_CRED   = "real_credential_hash"
        private const val OLD_REAL_DBKEY  = "real_db_wrapped"
        // Removed decoy blobs (purged on construction).
        private const val K_DECOY_CRED    = "vlt_b"
        private const val K_DECOY_DBKEY   = "vlt_d"
        private const val OLD_DECOY_CRED  = "decoy_credential_hash"
        private const val OLD_DECOY_DBKEY = "decoy_db_wrapped"
    }

    /** Creates a VaultSelector with the current context. */
    private fun createVaultSelector(): VaultSelector {
        return VaultSelector(
            store = KeyValueStore(context, SELECTOR_PREFS),
            crypto = CryptoProvider(context),
            // CR-1: dbKey is supplied by VaultSelector (PIN-wrapped).
            vaultFactory = androidVaultFactory(context)
        ).apply {
            // Disable the 5s change-PIN rate-limit floor so the suite stays fast;
            // its behaviour is verified separately, not its wall-clock duration.
            changePinMinDelayMs = 0
        }
    }

    @Before
    fun setUp() {
        context = InstrumentationRegistry.getInstrumentation().targetContext

        context.deleteDatabase(REAL_DB_NAME)
        context.deleteDatabase(DECOY_DB_NAME)
        context.deleteSharedPreferences(REAL_DB_PREFS)
        context.deleteSharedPreferences(SELECTOR_PREFS)
        context.deleteSharedPreferences(INACTIVITY_PREFS)
        // InactivityWipe.thresholdMs is process-global mutable state that the
        // enforcement path overwrites; snapshot it so this class can never leak a
        // tightened window into another test class.
        savedInactivityThresholdMs = InactivityWipe.thresholdMs

        vaultSelector = createVaultSelector()

        vaultSelector.setRealCredential(REAL_PIN)
    }

    @After
    fun tearDown() {
        InactivityWipe.thresholdMs = savedInactivityThresholdMs
        context.deleteDatabase(REAL_DB_NAME)
        context.deleteDatabase(DECOY_DB_NAME)
        context.deleteSharedPreferences(REAL_DB_PREFS)
        context.deleteSharedPreferences(SELECTOR_PREFS)
        context.deleteSharedPreferences(INACTIVITY_PREFS)
    }

    @Test
    fun realCredential_opensVault_dataAccessible() {
        val result = vaultSelector.unlock(REAL_PIN)
        assertTrue("Real PIN should open the vault", result is VaultSelector.UnlockResult.Opened)

        val vault = (result as VaultSelector.UnlockResult.Opened).vault
        val contact = ContactRecord("real-contact-1", FAKE_SECRET, 1, "RealAlice", 1_700_000_000_000L)
        vault.insertContact(contact)

        val retrieved = vault.getContact("real-contact-1")
        assertNotNull("Contact inserted into the vault should be retrievable", retrieved)
        assertEquals("Alias should match", "RealAlice", retrieved!!.alias)
    }

    @Test
    fun wrongCredential_isDenied() {
        val result = vaultSelector.unlock(WRONG_PIN)
        assertTrue("Wrong PIN should be denied", result is VaultSelector.UnlockResult.Denied)
    }

    @Test
    fun vault_implementsVaultDatabaseInterface() {
        val vault = (vaultSelector.unlock(REAL_PIN) as VaultSelector.UnlockResult.Opened).vault
        assertTrue("Vault must implement VaultDatabase", vault is VaultDatabase)
    }

    // -----------------------------------------------------------------------
    // CR-1: SQLCipher passphrase is bound to the user PIN. Device-key
    // extraction alone must not open the vault.
    // -----------------------------------------------------------------------

    /** The wrapped DB-key blob is persisted, and it is not the raw key. */
    @Test
    fun cr1_wrappedDbKey_persisted() {
        val prefs = KeyValueStore(context, SELECTOR_PREFS)
        val realWrapped = prefs.getString(K_REAL_DBKEY)

        assertNotNull("wrapped DB key must be stored", realWrapped)

        // The stored value is the scheme-neutral "v:"+base64 form — decode
        // the payload (scheme framing stripped) to reach the ciphertext bytes.
        val realBytes = android.util.Base64.decode(
            DbKeyScheme.payloadOf(realWrapped!!), android.util.Base64.DEFAULT)
        assertTrue("wrapped blob carries salt + ciphertext", realBytes.size > 16)
    }

    /**
     * The vault's passphrase is gated by the PIN: a fresh selector instance
     * (same prefs + Keystore, simulating app restart) still unlocks with the
     * real PIN, but a wrong PIN opens nothing.
     */
    @Test
    fun cr1_vaultKey_requiresPin_acrossRestart() {
        val vault = (vaultSelector.unlock(REAL_PIN) as VaultSelector.UnlockResult.Opened).vault
        vault.insertContact(
            ContactRecord("persist-1", FAKE_SECRET, 1, "Persisted", 1_700_000_000_000L)
        )

        // Simulate process restart: brand-new selector over the same
        // persisted wrapped-key blob and device Keystore key.
        val restarted = createVaultSelector()
        assertTrue("selector must still be configured after restart", restarted.isConfigured())

        assertTrue("wrong PIN must be denied",
            restarted.unlock(WRONG_PIN) is VaultSelector.UnlockResult.Denied)

        val reopened = restarted.unlock(REAL_PIN)
        assertTrue("real PIN must reopen the vault after restart",
            reopened is VaultSelector.UnlockResult.Opened)
        assertNotNull("data must survive restart (key correctly unwrapped)",
            (reopened as VaultSelector.UnlockResult.Opened).vault.getContact("persist-1"))
    }

    /**
     * CR-1 clean re-provision: a legacy install (credential hash present but no
     * wrapped-DB-key blob) is purged so the app returns to first-run setup
     * rather than trying to open an old-format DB.
     */
    @Test
    fun cr1_legacyVault_isPurgedForCleanReprovision() {
        val prefs = KeyValueStore(context, SELECTOR_PREFS)
        assertTrue("precondition: configured", vaultSelector.isConfigured())

        // Simulate a pre-CR-1 install: drop the wrapped-key blob, keep the
        // credential hash.
        prefs.remove(K_REAL_DBKEY)

        val legacySelector = createVaultSelector()
        assertTrue("legacy vault must be treated as not configured",
            !legacySelector.isConfigured())
        // Purge must also clear the orphaned credential hash.
        assertNull("real credential hash must be purged",
            prefs.getString(K_REAL_CRED))
    }

    /**
     * Deniability: the credential/DB-key storage keys were
     * renamed from discriminating "real_*" (which leaked vault layout as
     * cleartext key names) to neutral labels. A one-time migration moves an
     * existing install's entries to the neutral keys — preserving the wrapped
     * DB key (and thus the vault file + contacts) — and deletes the old names.
     */
    @Test
    fun legacyKeyNames_migrateToNeutralNames_preservingVaultAccess() {
        val prefs = KeyValueStore(context, SELECTOR_PREFS)
        // Capture the configured install's values, then rewrite them under the
        // OLD discriminating names to simulate a pre-migration install.
        val realCred  = prefs.getString(K_REAL_CRED)!!
        val realDb    = prefs.getString(K_REAL_DBKEY)!!
        prefs.putString(OLD_REAL_CRED, realCred);   prefs.remove(K_REAL_CRED)
        prefs.putString(OLD_REAL_DBKEY, realDb);    prefs.remove(K_REAL_DBKEY)

        // Constructing a selector runs the one-time migration in its init block.
        val migrated = createVaultSelector()

        // Old discriminating names gone; neutral names hold the same values.
        assertNull("old real credential key name must be removed", prefs.getString(OLD_REAL_CRED))
        assertNull("old real db key name must be removed", prefs.getString(OLD_REAL_DBKEY))
        assertEquals("wrapped DB key preserved verbatim under the neutral name",
            realDb, prefs.getString(K_REAL_DBKEY))
        assertTrue("migrated install must still be configured", migrated.isConfigured())

        // And the REAL PIN still opens the vault — contacts intact.
        assertTrue("real PIN must still unlock the vault after key-name migration",
            migrated.unlock(REAL_PIN) is VaultSelector.UnlockResult.Opened)
    }

    /**
     * Decoy-removal cleanup: leftover decoy credential/DB-key blobs from an
     * install provisioned before the decoy feature was removed (both the
     * neutral and the older discriminating names) are purged on construction.
     */
    @Test
    fun removedDecoyArtifacts_arePurgedOnConstruction() {
        val prefs = KeyValueStore(context, SELECTOR_PREFS)
        // Simulate a pre-removal install carrying decoy blobs.
        prefs.putString(K_DECOY_CRED, "x")
        prefs.putString(K_DECOY_DBKEY, "y")
        prefs.putString(OLD_DECOY_CRED, "x")
        prefs.putString(OLD_DECOY_DBKEY, "y")

        createVaultSelector()  // init runs purgeDecoyArtifactsIfNeeded()

        assertNull("neutral decoy credential must be purged", prefs.getString(K_DECOY_CRED))
        assertNull("neutral decoy db key must be purged", prefs.getString(K_DECOY_DBKEY))
        assertNull("legacy decoy credential must be purged", prefs.getString(OLD_DECOY_CRED))
        assertNull("legacy decoy db key must be purged", prefs.getString(OLD_DECOY_DBKEY))
        // The real vault is untouched.
        assertTrue("real PIN must still unlock after decoy purge",
            vaultSelector.unlock(REAL_PIN) is VaultSelector.UnlockResult.Opened)
    }

    @Test
    fun isConfigured_reflectsCredentialState() {
        assertTrue("Selector should be configured after setting the credential",
            vaultSelector.isConfigured())

        context.deleteSharedPreferences(SELECTOR_PREFS)
        val freshSelector = createVaultSelector()
        assertTrue("Fresh selector without a credential should not be configured",
            !freshSelector.isConfigured())
    }

    /**
     * Invariant: after credential setup, the DB file must exist on disk
     * (provision creates it synchronously, before setup completes).
     */
    @Test
    fun dbFile_existsAfterCredentialSetup_evenWithoutUnlock() {
        val realFile = context.getDatabasePath(REAL_DB_NAME)
        assertTrue("DB must exist after setup",  realFile.exists())
        assertTrue("DB must be non-empty",  realFile.length()  > 0)
    }

    // -----------------------------------------------------------------------
    // changeCredential — PIN rotation. The random SQLCipher passphrase is
    // re-wrapped (not regenerated), so the vault's data survives the change.
    // -----------------------------------------------------------------------

    /** Rotating the PIN keeps the vault's data and swaps the PIN. */
    @Test
    fun change_preservesData_oldPinRejected_newPinWorks() {
        val vault = (vaultSelector.unlock(REAL_PIN) as VaultSelector.UnlockResult.Opened).vault
        vault.insertContact(
            ContactRecord("keep-1", FAKE_SECRET, 1, "KeepAlice", 1_700_000_000_000L)
        )

        val result = vaultSelector.changeCredential(REAL_PIN, NEW_REAL_PIN)
        assertEquals("PIN change should succeed",
            VaultSelector.ChangePinResult.SUCCESS, result)

        // Old PIN no longer opens anything.
        assertTrue("old PIN must be rejected after change",
            vaultSelector.unlock(REAL_PIN) is VaultSelector.UnlockResult.Denied)

        // New PIN opens the SAME vault, data intact (key was re-wrapped).
        val reopened = vaultSelector.unlock(NEW_REAL_PIN)
        assertTrue("new PIN must open the vault",
            reopened is VaultSelector.UnlockResult.Opened)
        assertNotNull("data must survive a PIN change",
            (reopened as VaultSelector.UnlockResult.Opened).vault.getContact("keep-1"))
    }

    // -----------------------------------------------------------------------
    // Provision guard — never provision on top of an existing vault file
    // -----------------------------------------------------------------------

    /**
     * The field failure this guard exists for: the credential store transiently
     * reads "not configured" for a vault that is very much configured, the app
     * routes to first-run setup, and completing setup provisions over the live
     * vault — the DB file is keyed with the OLD key, so it reads as SQLITE_NOTADB
     * and the isProvision branch DELETES it. Every contact gone, and the user
     * experiences it as "I used the same PIN and everything was missing".
     *
     * Simulated here by removing the credential blobs (exactly what a bad store
     * read looks like to every caller) while leaving run.db in place, then
     * driving a provision. The guard must refuse, and — the assertion that
     * actually matters — the original vault must still open with the ORIGINAL PIN
     * once the blobs are restored, with its data intact.
     */
    @Test
    fun provision_overExistingVault_isRefused_andDataSurvives() {
        val vault = (vaultSelector.unlock(REAL_PIN) as VaultSelector.UnlockResult.Opened).vault
        vault.insertContact(
            ContactRecord("survivor-1", FAKE_SECRET, 1, "SurvivorAlice", 1_700_000_000_000L)
        )
        vault.close()

        val prefs = KeyValueStore(context, SELECTOR_PREFS)
        val credBlob  = prefs.getString(K_REAL_CRED)
        val dbKeyBlob = prefs.getString(K_REAL_DBKEY)
        assertNotNull("precondition: credential blob stored", credBlob)
        assertNotNull("precondition: db-key blob stored", dbKeyBlob)

        // The transient: both blobs unreadable, so isConfigured() says "fresh
        // install" while run.db sits right there full of the user's contacts.
        prefs.remove(K_REAL_CRED)
        prefs.remove(K_REAL_DBKEY)

        val misrouted = createVaultSelector()
        assertTrue("precondition: the vault FILE is still present",
            misrouted.vaultFileExists())

        // Setup would call exactly this. It must refuse rather than destroy.
        val provisioned = misrouted.setRealCredential(
            NEW_REAL_PIN, passphraseMode = false, level = ProtectionLevel.CASUAL
        )
        assertTrue("provision over an existing vault must be refused", !provisioned)
        assertTrue("the vault file must still exist after the refusal",
            context.getDatabasePath(REAL_DB_NAME).exists())

        // Restore what the transient hid and prove the ORIGINAL vault is intact —
        // same PIN, same data. Without the guard the file would have been deleted
        // and recreated empty, and this unlock would open a vault with no contacts.
        prefs.putString(K_REAL_CRED, credBlob!!)
        prefs.putString(K_REAL_DBKEY, dbKeyBlob!!)

        val reopened = createVaultSelector().unlock(REAL_PIN)
        assertTrue("the original PIN must still open the original vault",
            reopened is VaultSelector.UnlockResult.Opened)
        assertNotNull("the original contacts must survive the refused provision",
            (reopened as VaultSelector.UnlockResult.Opened).vault.getContact("survivor-1"))
    }

    /**
     * The unlock screen's "Erase and start over" offer keys on this, and showing
     * it for a healthy vault would hand the user the data loss the guard just
     * closed — so pin both directions.
     */
    @Test
    fun orphanedVaultFile_onlyWhenCredentialIsConfirmedAbsent() {
        // Healthy, fully provisioned vault: never offer an erase.
        assertTrue("precondition: configured", vaultSelector.isConfigured())
        assertTrue("precondition: vault file present", vaultSelector.vaultFileExists())
        assertTrue("a configured vault is NOT orphaned",
            !vaultSelector.orphanedVaultFile())

        // Credential gone, file still there — the unopenable dead end.
        val prefs = KeyValueStore(context, SELECTOR_PREFS)
        prefs.remove(K_REAL_CRED)
        prefs.remove(K_REAL_DBKEY)
        assertTrue("a vault file with no credential IS orphaned",
            createVaultSelector().orphanedVaultFile())
    }

    /**
     * PROVISION-1 (2026-08-09): BOTH halves of a torn credential pair must reach the
     * unlock screen's "Erase and start over" offer, not a silent dead end.
     *
     * The shipped race dropped `vlt_c` while `vlt_a` landed, and the two halves take
     * DIFFERENT routes to `orphanedVaultFile()`: the creds-without-dbkey half is first
     * cleared wholesale by `purgeHalfCredentialPairIfNeeded` (which `isConfigured` calls), while
     * the dbkey-without-creds half is simply never `configured`. Both must answer
     * true, or a user stranded by the race gets a prompt that rejects every entry with
     * no way out.
     */
    @Test
    fun orphanedVaultFile_coversBothHalvesOfATornCredentialPair() {
        val prefs = KeyValueStore(context, SELECTOR_PREFS)
        val credBlob  = prefs.getString(K_REAL_CRED)!!
        val dbKeyBlob = prefs.getString(K_REAL_DBKEY)!!

        // Half 1 — the shipped race: verifier landed, wrapped DB key dropped.
        prefs.remove(K_REAL_DBKEY)
        assertTrue("vlt_a without vlt_c over a vault file must be orphaned",
            createVaultSelector().orphanedVaultFile())
        // …and the legacy purge really did clear the stranded verifier.
        assertNull("purgeHalfCredentialPairIfNeeded must clear the lone verifier",
            prefs.getString(K_REAL_CRED))

        // Half 2 — the mirror: wrapped DB key landed, verifier dropped.
        prefs.putString(K_REAL_DBKEY, dbKeyBlob)
        assertNull("precondition: no verifier", prefs.getString(K_REAL_CRED))
        assertTrue("vlt_c without vlt_a over a vault file must be orphaned",
            createVaultSelector().orphanedVaultFile())

        // Control: restore both and the erase offer disappears again.
        prefs.putString(K_REAL_CRED, credBlob)
        prefs.putString(K_REAL_DBKEY, dbKeyBlob)
        assertFalse("a healthy vault must never be offered an erase",
            createVaultSelector().orphanedVaultFile())
    }

    /**
     * PROVISION-1: the rollback primitive a failed provision uses must remove the
     * vault file AND every sidecar, at the same path the guard probes — otherwise the
     * retry meets the guard instead of a clean slate. Never throws when absent.
     */
    @Test
    fun deleteVaultFileAfterFailedProvision_removesTheFileAndItsSidecars() {
        val factory = androidVaultFactory(context)
        assertTrue("precondition: setUp provisioned a vault file", factory.vaultFileExists())
        val base = context.getDatabasePath(REAL_DB_NAME).path
        listOf("-wal", "-shm", "-journal").forEach { java.io.File(base + it).writeText("x") }

        factory.deleteVaultFileAfterFailedProvision()

        assertFalse("the vault file must be gone", factory.vaultFileExists())
        listOf("", "-wal", "-shm", "-journal").forEach {
            assertFalse("sidecar '$it' must be gone", java.io.File(base + it).exists())
        }
        // Idempotent: a second call on an absent file is a no-op, never a throw.
        factory.deleteVaultFileAfterFailedProvision()

        // And the whole point: with the file gone, provisioning is possible again.
        context.deleteSharedPreferences(SELECTOR_PREFS)
        assertTrue("a clean slate must provision",
            createVaultSelector().setRealCredential(
                NEW_REAL_PIN, passphraseMode = false, level = ProtectionLevel.CASUAL))
    }

    /**
     * PROVISION-1 / Part E: a healthy provision must persist ALL FOUR values it
     * claims — the verifier, the wrapped DB key, the credential mode and the tier —
     * in the one verified batch. A dropped `vlt_lvl` reads as "no tier ever chosen"
     * and marches the user through the protection chooser on every unlock; a dropped
     * `vlt_m` renders the PIN keypad on a passphrase vault, whose forced-wrong entries
     * burn the wipe budget.
     */
    @Test
    fun provision_persistsTheWholeSelectorBatch_notJustTheCredentialPair() {
        context.deleteDatabase(REAL_DB_NAME)
        context.deleteSharedPreferences(SELECTOR_PREFS)
        val vs = createVaultSelector()
        // Six distinct diceware words — the same known-above-the-floor shape the
        // passphrase cases below use (5 words is ~64.6 bits and would be refused).
        assertTrue(vs.setRealCredential(
            "correct horse battery staple ozone thicket",
            passphraseMode = true, level = ProtectionLevel.MAXIMUM))

        val prefs = KeyValueStore(context, SELECTOR_PREFS)
        assertNotNull("vlt_a must persist", prefs.getString(K_REAL_CRED))
        assertNotNull("vlt_c must persist", prefs.getString(K_REAL_DBKEY))
        assertNotNull("vlt_m must persist (entry widget)", prefs.getString("vlt_m"))
        assertNotNull("vlt_lvl must persist (tier — else the chooser loops)",
            prefs.getString("vlt_lvl"))
        assertEquals(ProtectionLevel.MAXIMUM, createVaultSelector().protectionLevelOrNull())
        assertTrue("a MAXIMUM vault must render the passphrase field",
            createVaultSelector().isPassphraseMode())
    }

    /** No vault file at all is a plain fresh install, not an orphan. */
    @Test
    fun orphanedVaultFile_falseOnFreshInstall() {
        context.deleteSharedPreferences(SELECTOR_PREFS)
        context.deleteDatabase(REAL_DB_NAME)
        val fresh = createVaultSelector()
        assertTrue("precondition: no vault file", !fresh.vaultFileExists())
        assertTrue("a fresh install is not an orphaned vault", !fresh.orphanedVaultFile())
    }

    /** A wrong current PIN changes nothing and reports WRONG_CURRENT. */
    @Test
    fun changeWithWrongCurrentPin_isRejected_nothingChanges() {
        assertEquals(VaultSelector.ChangePinResult.WRONG_CURRENT,
            vaultSelector.changeCredential(WRONG_PIN, NEW_REAL_PIN))

        // The original PIN must still work; the rejected new PIN must not.
        assertTrue(vaultSelector.unlock(REAL_PIN)  is VaultSelector.UnlockResult.Opened)
        assertTrue(vaultSelector.unlock(NEW_REAL_PIN) is VaultSelector.UnlockResult.Denied)
    }

    /**
     * The shared rotation API enforces the Lever A passphrase
     * entropy floor, not just the UI. A weak new passphrase is rejected with
     * WEAK_CREDENTIAL and nothing changes; the current PIN still opens the vault.
     */
    @Test
    fun changeToWeakPassphrase_isRejected_atTheApi() {
        assertEquals(VaultSelector.ChangePinResult.WEAK_CREDENTIAL,
            vaultSelector.changeCredentialAndMode(REAL_PIN, "weak", newModePassphrase = true))

        // Nothing rotated: the original PIN still opens the vault; the weak
        // passphrase does not.
        assertTrue(vaultSelector.unlock(REAL_PIN) is VaultSelector.UnlockResult.Opened)
        assertTrue(vaultSelector.unlock("weak") is VaultSelector.UnlockResult.Denied)

        // A strong passphrase (>=70-bit floor) IS accepted.
        assertEquals(VaultSelector.ChangePinResult.SUCCESS,
            vaultSelector.changeCredentialAndMode(REAL_PIN,
                "correct horse battery staple ozone thicket", newModePassphrase = true))
    }

    /**
     * A correct PIN must NOT silently open a fresh EMPTY vault when
     * run.db is missing (e.g. a root/forensic actor deleted it while shared_prefs
     * + the Keystore key survive). Unlock must fail closed to Error, mirroring the
     * iOS guard.
     */
    @Test
    fun unlock_withMissingDbFile_failsClosed_notEmptyVault() {
        val opened = vaultSelector.unlock(REAL_PIN) as VaultSelector.UnlockResult.Opened
        opened.vault.insertContact(
            ContactRecord("c1", FAKE_SECRET, 1, "Alice", 1_700_000_000_000L))
        opened.vault.close()

        // Delete ONLY run.db + sidecars; keep the credential prefs + device key.
        for (sfx in listOf("", "-wal", "-shm", "-journal")) {
            java.io.File(context.getDatabasePath("run.db").path + sfx).delete()
        }

        assertTrue("a missing DB must fail closed to Error, not open an empty vault",
            vaultSelector.unlock(REAL_PIN) is VaultSelector.UnlockResult.Error)
    }

    // -----------------------------------------------------------------------
    // A credential TIER UPGRADE re-keys the database.
    //
    // The problem: the SQLCipher passphrase was minted once at provision and never
    // regenerated, so an archived copy of the credential store taken while the vault
    // was weak (6-digit PIN), plus that old PIN, plus the still-current device key,
    // opened TODAY's vault — a vault's effective protection was the weakest
    // configuration it had ever had, forever, for anyone holding a copy from that era.
    //
    // These must run instrumented: the whole safety argument rests on real SQLCipher
    // behaviour (sqlite3_rekey_v2 reports SQLITE_OK on its ROLLBACK branch too, so
    // only opening the file proves anything), which no JVM double can model. The pure
    // decisions and the S0–S5 crash points live in commonTest's DbKeyRotationTest.
    // -----------------------------------------------------------------------

    /** A selector wired to a LIVE vault handle, as RunViewModel wires it — the
     *  precondition for the rotation (there is nothing to re-key without one).
     *  [onRetired] mirrors RunViewModel's onRekeyHandleRetired wiring: fired when the rotation closed the handle because the re-key
     *  did not verifiably commit, i.e. "the session must re-lock". */
    private fun createVaultSelectorWithVault(
        vault: () -> VaultDatabase?,
        onRetired: () -> Unit = {},
    ): VaultSelector =
        VaultSelector(
            store = KeyValueStore(context, SELECTOR_PREFS),
            crypto = CryptoProvider(context),
            vaultFactory = androidVaultFactory(context),
            vaultProvider = vault,
            onRekeyHandleRetired = onRetired,
        ).apply { changePinMinDelayMs = 0 }

    @Test
    fun pinToPassphraseUpgrade_reKeysTheVault_archivedWeakEraStoreNoLongerOpensIt() {
        val phrase = "runes harbor violet stapler mountain ledger"
        val prefs = KeyValueStore(context, SELECTOR_PREFS)

        // The exfiltration: a copy of the credential store taken while the vault was
        // a 6-digit PIN vault. The device key is untouched, so this pair is all an
        // attacker needs — plus the old PIN, which they are assumed to have.
        val archivedCred = prefs.getString(K_REAL_CRED)!!
        val archivedDbKey = prefs.getString(K_REAL_DBKEY)!!

        val opened = vaultSelector.unlock(REAL_PIN) as VaultSelector.UnlockResult.Opened
        val live = opened.vault
        live.insertContact(ContactRecord("m1-contact", FAKE_SECRET, 1, "Rotated", 1_700_000_000_000L))

        var retired = 0
        val vs = createVaultSelectorWithVault({ live }, onRetired = { retired++ })
        assertEquals("the tier upgrade must succeed",
            VaultSelector.ChangePinResult.SUCCESS,
            vs.changeCredentialAndMode(REAL_PIN, phrase, newModePassphrase = true))
        // Review 2026-08-03: a probe-PROVEN commit keeps the session — both codec
        // contexts are on the new key, so there is nothing to retire.
        assertEquals("a committed re-key must NOT force the session to re-lock", 0, retired)
        live.close()

        // The rotation resolved in-line: no pending record is left behind.
        assertNull("a completed rotation must leave no pending record",
            prefs.getString("vlt_cn"))

        // The upgraded vault works, with its data.
        val afterOpen = createVaultSelector().unlock(phrase)
        assertTrue("the new passphrase must open the vault",
            afterOpen is VaultSelector.UnlockResult.Opened)
        val afterVault = (afterOpen as VaultSelector.UnlockResult.Opened).vault
        assertNotNull("the re-keyed vault must still hold its rows",
            afterVault.getContact("m1-contact"))
        afterVault.close()

        // THE RE-KEY PROPERTY: restore the archived weak-era store — the exact state an
        // examiner would replay — and the old PIN must no longer reach the data. It
        // still unwraps to a DB key (nothing else changed), but that key no longer
        // opens the file, so unlock fails CLOSED with the neutral Error.
        prefs.putStringsSync(mapOf(K_REAL_CRED to archivedCred, K_REAL_DBKEY to archivedDbKey))
        val replayed = createVaultSelector().unlock(REAL_PIN)
        assertTrue("the archived weak-era credential store must no longer open the vault",
            replayed is VaultSelector.UnlockResult.Error)
    }

    /**
     * The scope control. A SAME-TIER PIN rotation must NOT re-key: it retires nothing
     * the user just upgraded away from, and re-keying on every ordinary PIN change
     * would pay the rotation's risk for free. (Known limitation: an
     * archive from before a plain PIN change still opens the vault with that old PIN.)
     */
    @Test
    fun sameTierPinRotation_doesNotReKeyTheVault() {
        val prefs = KeyValueStore(context, SELECTOR_PREFS)
        val archivedCred = prefs.getString(K_REAL_CRED)!!
        val archivedDbKey = prefs.getString(K_REAL_DBKEY)!!

        val live = (vaultSelector.unlock(REAL_PIN) as VaultSelector.UnlockResult.Opened).vault
        val vs = createVaultSelectorWithVault({ live })
        assertEquals(VaultSelector.ChangePinResult.SUCCESS,
            vs.changeCredential(REAL_PIN, NEW_REAL_PIN))
        live.close()

        assertNull("a same-tier rotation must never write a pending record",
            prefs.getString("vlt_cn"))

        prefs.putStringsSync(mapOf(K_REAL_CRED to archivedCred, K_REAL_DBKEY to archivedDbKey))
        assertTrue("the DB key is unchanged, so the archived store still opens the vault",
            createVaultSelector().unlock(REAL_PIN) is VaultSelector.UnlockResult.Opened)
    }

    /**
     * BRICK-SAFETY: a vault with a recovery code must NEVER be re-keyed. `vlt_rc`
     * wraps the STABLE SQLCipher passphrase under a 160-bit code shown once and never
     * persisted, so a re-key would silently kill a code the user has written down.
     * The decisive assertion is the last one: the code still opens the vault.
     */
    @Test
    fun tierUpgradeOnAVaultWithARecoveryCode_isNeverRotated_andTheCodeStillWorks() {
        val setup = provisionLeverBVaultWithRecovery()
        val phrase = "runes harbor violet stapler mountain ledger"
        // A PRIVATE → MAXIMUM upgrade: a PIN vault with a live recovery code, which is
        // the state the rotation must refuse. (Both gates veto here — the recovery
        // blob AND the auth-bound blob — which is deliberate belt-and-braces; the
        // recovery blob alone is the one that must never be relaxed.)
        val prefs = KeyValueStore(context, SELECTOR_PREFS)
        assertTrue("precondition: a recovery code exists", setup.vs.hasRecoveryCode())

        val live = (setup.vs.unlock(REAL_PIN) as VaultSelector.UnlockResult.Opened).vault
        val vs = VaultSelector(
            store = KeyValueStore(context, SELECTOR_PREFS),
            crypto = CryptoProvider(context),
            vaultFactory = androidVaultFactory(context),
            dbKeyProtector = setup.protector,
            vaultProvider = { live },
        ).apply { changePinMinDelayMs = 0 }
        assertEquals("the credential change itself must still succeed",
            VaultSelector.ChangePinResult.SUCCESS,
            vs.changeCredentialAndMode(REAL_PIN, phrase, newModePassphrase = true))
        live.close()

        assertNull("a vault with a recovery code must never get a pending record",
            prefs.getString("vlt_cn"))
        assertTrue("the new passphrase must open the vault",
            vs.unlock(phrase) is VaultSelector.UnlockResult.Opened)
        // The point of the whole gate: the code the user wrote down still works.
        assertTrue("the recovery code must still recover the vault after the upgrade",
            vs.recoverWithCode(setup.code, phrase) is VaultSelector.UnlockResult.Opened)
    }

    /**
     * The crash point a single-record rotation cannot survive: the re-key
     * LANDED (the file is on the new key) but the promotion never ran, so `vlt_c`
     * still holds a key that opens nothing. The pending record is the only thing
     * standing between this state and total data loss.
     *
     * Reproduced against REAL SQLCipher rather than modelled: the vault handle the
     * rotation re-keys is wrapped so that it performs the genuine `changePassword`
     * and then THROWS, which is where `changeCredentialInner`'s defensive catch
     * takes over — the credential change still reports SUCCESS (it landed) and the
     * rotation is left unresolved, exactly as a process death there would leave it.
     */
    @Test
    fun interruptedRotation_reKeyLanded_theNextUnlockPromotesTheRecordAndOpens() {
        val phrase = "runes harbor violet stapler mountain ledger"
        val prefs = KeyValueStore(context, SELECTOR_PREFS)

        val live = (vaultSelector.unlock(REAL_PIN) as VaultSelector.UnlockResult.Opened).vault
        live.insertContact(ContactRecord("s3-contact", FAKE_SECRET, 1, "Interrupted", 1_700_000_000_000L))
        val crashing = CrashAfterRekeyVault(live)

        val vs = createVaultSelectorWithVault({ crashing })
        assertEquals("the credential change itself must still report SUCCESS",
            VaultSelector.ChangePinResult.SUCCESS,
            vs.changeCredentialAndMode(REAL_PIN, phrase, newModePassphrase = true))
        live.close()

        assertTrue("precondition: the re-key really ran", crashing.rekeyed)
        assertNotNull("an unresolved rotation must leave its pending record",
            prefs.getString("vlt_cn"))

        // The reconcile: `vlt_c`'s key no longer opens the file, so the PENDING key is
        // tried and — strictly after that open succeeds — promoted.
        val opened = createVaultSelector().unlock(phrase)
        assertTrue("the pending record must open the re-keyed vault",
            opened is VaultSelector.UnlockResult.Opened)
        assertNotNull("the re-keyed vault must still hold its rows",
            (opened as VaultSelector.UnlockResult.Opened).vault.getContact("s3-contact"))
        opened.vault.close()
        assertNull("a proven promotion must drop the pending record",
            prefs.getString("vlt_cn"))

        // The promotion write landed, the removal did not (crash between them).
        // Restoring that state must converge on the next unlock, not loop.
        prefs.putStringSync("vlt_cn", prefs.getString(K_REAL_DBKEY)!!)
        val again = createVaultSelector().unlock(phrase)
        assertTrue("S4 must still open the vault", again is VaultSelector.UnlockResult.Opened)
        (again as VaultSelector.UnlockResult.Opened).vault.close()
        assertNull("the next unlock finishes the cleanup", prefs.getString("vlt_cn"))
    }

    /**
     * THE brick this design's most dangerous branch used to create. `sqlite3_rekey_v2`
     * returns SQLITE_OK on its ROLLBACK branch too, and on that branch it has already
     * installed the new key in the codec's WRITE context of the still-live handle
     * without undoing it — so a "rolled back" re-key leaves a handle that writes
     * new-key pages onto an old-key file (page 1 on the very next commit).
     *
     * The probes therefore report DROP_PENDING (only the old key opens the file), and
     * removing `vlt_cn` on that evidence is total, permanent data loss: it is the ONLY
     * surviving record of the key those pages are under, the local copy having been
     * secureWipe'd on the way out. So the record is KEPT and the unlock reconcile
     * decides on positive evidence instead.
     *
     * Review 2026-08-03: the rotation now also RETIRES (closes) the poisoned handle,
     * so the only commit that can still move the file is one already in flight when
     * the re-key returned — the race the close cannot cover. Modelled here with
     * `closeThrough = false` (the close is recorded but hasn't taken hold yet) and
     * the deferred re-key landing as that racing commit; the kept record is what
     * recovers it. The shipped close-through behaviour is pinned by
     * [rolledBackRekey_retiresTheLiveHandle_soNoLaterWriteCanPoisonTheFile].
     */
    @Test
    fun rolledBackRekeyThatLaterMovesTheFile_isRecoveredByTheKeptPendingRecord() {
        val phrase = "runes harbor violet stapler mountain ledger"
        val prefs = KeyValueStore(context, SELECTOR_PREFS)

        val live = (vaultSelector.unlock(REAL_PIN) as VaultSelector.UnlockResult.Opened).vault
        live.insertContact(ContactRecord("rollback-1", FAKE_SECRET, 1, "Rolled", 1_700_000_000_000L))
        val rollingBack = RollingBackRekeyVault(live, closeThrough = false)

        val vs = createVaultSelectorWithVault({ rollingBack })
        assertEquals(VaultSelector.ChangePinResult.SUCCESS,
            vs.changeCredentialAndMode(REAL_PIN, phrase, newModePassphrase = true))

        // The probes said "only the old key opens it". The record must survive that:
        // a commit already in flight may still land under the new key.
        assertNotNull("a reported rollback must KEEP both key records — vlt_cn may be" +
            " the only record of the key the poisoned handle writes under",
            prefs.getString("vlt_cn"))
        assertTrue("the rotation must have requested the handle's retirement",
            rollingBack.closeRequested)

        // The racing commit reaches the file (page 1) before the close took hold.
        assertTrue("precondition: the deferred re-key must land", rollingBack.applyDeferredRekey())
        live.close()

        val opened = createVaultSelector().unlock(phrase)
        assertTrue("the kept record must still open the vault after the file moved",
            opened is VaultSelector.UnlockResult.Opened)
        assertNotNull("…with its data intact",
            (opened as VaultSelector.UnlockResult.Opened).vault.getContact("rollback-1"))
        opened.vault.close()
        assertNull("and the promotion then retires the record", prefs.getString("vlt_cn"))
    }

    /**
     * Review 2026-08-03 — the retire itself, against real SQLCipher: after a
     * probe-reported rollback the LIVE handle must be CLOSED before the rotation
     * returns ([VaultDatabase.rekey]'s "prefer closing… over continuing to write"
     * contract, previously ignored by its only caller) and the session owner told
     * to re-lock. The deferred re-key that used to model "page 1 moves on the next
     * commit" now has nowhere to land: it must FAIL, the file must stay on
     * `vlt_c`'s key, and the next unlock must drop the pending record on that
     * positive evidence — no mixed-key file, no promotion over unread pages.
     */
    @Test
    fun rolledBackRekey_retiresTheLiveHandle_soNoLaterWriteCanPoisonTheFile() {
        val phrase = "runes harbor violet stapler mountain ledger"
        val prefs = KeyValueStore(context, SELECTOR_PREFS)

        val live = (vaultSelector.unlock(REAL_PIN) as VaultSelector.UnlockResult.Opened).vault
        live.insertContact(ContactRecord("retire-1", FAKE_SECRET, 1, "Retired", 1_700_000_000_000L))
        val rollingBack = RollingBackRekeyVault(live)   // closeThrough: the shipped retire
        var retired = 0

        val vs = createVaultSelectorWithVault({ rollingBack }, onRetired = { retired++ })
        assertEquals("the credential change itself must still report SUCCESS",
            VaultSelector.ChangePinResult.SUCCESS,
            vs.changeCredentialAndMode(REAL_PIN, phrase, newModePassphrase = true))

        assertTrue("the rotation must CLOSE the poisoned handle before returning",
            rollingBack.closeRequested)
        assertEquals("…and tell the session owner to re-lock, exactly once", 1, retired)
        assertFalse("no write may land through the retired handle",
            rollingBack.applyDeferredRekey())
        assertNotNull("both key records are kept for the reconcile", prefs.getString("vlt_cn"))

        // The forced re-unlock recovers: the file never moved, so vlt_c's key opens
        // it and the never-landed record is dropped on that positive evidence.
        val opened = createVaultSelector().unlock(phrase)
        assertTrue("the vault must open on the stored key — the file never moved",
            opened is VaultSelector.UnlockResult.Opened)
        assertNotNull("…with its data intact",
            (opened as VaultSelector.UnlockResult.Opened).vault.getContact("retire-1"))
        opened.vault.close()
        assertNull("the never-landed record is dropped once vlt_c is proven to open the file",
            prefs.getString("vlt_cn"))
    }

    /**
     * The other half of the same branch: a re-key that genuinely rolled back and whose
     * handle never touches the file again must ALSO converge — `vlt_c` still opens the
     * vault, so the next unlock drops the record on that positive evidence. Keeping the
     * record must cost one deferral cycle, never a stuck state.
     */
    @Test
    fun rolledBackRekeyThatNeverMovesTheFile_convergesOnTheNextUnlock() {
        val phrase = "runes harbor violet stapler mountain ledger"
        val prefs = KeyValueStore(context, SELECTOR_PREFS)

        val live = (vaultSelector.unlock(REAL_PIN) as VaultSelector.UnlockResult.Opened).vault
        live.insertContact(ContactRecord("rollback-2", FAKE_SECRET, 1, "Rolled2", 1_700_000_000_000L))
        val vs = createVaultSelectorWithVault({ RollingBackRekeyVault(live) })
        assertEquals(VaultSelector.ChangePinResult.SUCCESS,
            vs.changeCredentialAndMode(REAL_PIN, phrase, newModePassphrase = true))
        live.close()
        assertNotNull("precondition: the record is kept at rotate time", prefs.getString("vlt_cn"))

        val opened = createVaultSelector().unlock(phrase)
        assertTrue("the vault must open on the stored key", opened is VaultSelector.UnlockResult.Opened)
        assertNotNull("…with its data intact",
            (opened as VaultSelector.UnlockResult.Opened).vault.getContact("rollback-2"))
        opened.vault.close()
        assertNull("the never-landed record must be dropped once vlt_c is proven to open the file",
            prefs.getString("vlt_cn"))
    }

    /**
     * A pending record left by an interrupted rotation is reconciled on the next
     * unlock by OPENING the file — here the re-key never ran, so `vlt_c`'s key still
     * opens it and the record is simply dropped. No wipe, no Denied.
     */
    @Test
    fun pendingRotationRecordWithNoReKey_isDiscardedOnTheNextUnlock() {
        val prefs = KeyValueStore(context, SELECTOR_PREFS)
        // A pending record is byte-identical in FORM to vlt_c, so the current blob is
        // a valid stand-in for "a record that unwraps but does not open the file"…
        // except that it DOES open it, which is exactly the never-landed case.
        prefs.putStringSync("vlt_cn", prefs.getString(K_REAL_DBKEY)!!)

        val opened = createVaultSelector().unlock(REAL_PIN)
        assertTrue("the vault must open normally with a pending record present",
            opened is VaultSelector.UnlockResult.Opened)
        (opened as VaultSelector.UnlockResult.Opened).vault.close()
        assertNull("the never-landed record must be dropped once vlt_c is proven to open the file",
            prefs.getString("vlt_cn"))
    }

    /**
     * A GARBAGE pending record must yield the neutral Error — never Denied (which
     * counts toward the emergency wipe on the correct credential) — and must never be
     * removed on an ambiguous path: it might be the only record of the key the file is
     * actually on.
     */
    @Test
    fun unreadablePendingRotationRecord_isNeutralError_andIsKept() {
        val prefs = KeyValueStore(context, SELECTOR_PREFS)
        // Blob-shaped but undecryptable, over a vlt_c that no longer opens the file:
        // delete the DB so NEITHER key can open it — the ambiguity branch.
        prefs.putStringSync("vlt_cn", "Z" + prefs.getString(K_REAL_DBKEY)!!.drop(1))
        for (sfx in listOf("", "-wal", "-shm", "-journal")) {
            java.io.File(context.getDatabasePath(REAL_DB_NAME).path + sfx).delete()
        }

        val result = createVaultSelector().unlock(REAL_PIN)
        assertTrue("an undecidable rotation state must be the neutral Error, never Denied",
            result is VaultSelector.UnlockResult.Error)
        assertNotNull("an ambiguous path must never remove the pending record",
            prefs.getString("vlt_cn"))
        assertNotNull("…nor the current one", prefs.getString(K_REAL_DBKEY))
    }

    /** A rotated PIN survives a simulated process restart (durably persisted). */
    @Test
    fun changedPin_survivesRestart() {
        assertEquals(VaultSelector.ChangePinResult.SUCCESS,
            vaultSelector.changeCredential(REAL_PIN, NEW_REAL_PIN))

        val restarted = createVaultSelector()
        assertTrue("old PIN must stay rejected after restart",
            restarted.unlock(REAL_PIN) is VaultSelector.UnlockResult.Denied)
        assertTrue("new PIN must open the vault after restart",
            restarted.unlock(NEW_REAL_PIN) is VaultSelector.UnlockResult.Opened)
    }

    @Test
    fun verifyCredential_matchesVault_rejectsWrong() {
        assertTrue("real PIN must verify",  vaultSelector.verifyCredential(REAL_PIN))
        assertTrue("wrong PIN must not verify", !vaultSelector.verifyCredential(WRONG_PIN))
    }

    // -----------------------------------------------------------------------
    // Lever B data-recovery code (threat-level slider spec #2): a vault whose
    // hardware auth-bound key later invalidates (biometric re-enroll / device-
    // passcode change) is RECOVERED via the code + credential, not bricked.
    //
    // Uses a FAKE auth-binding protector so the recovery CRYPTO runs on a real
    // vault (real Tink CryptoProvider, real Argon2, real SharedPreferences)
    // WITHOUT a BiometricPrompt (unapprovable headlessly). Invalidation is
    // simulated by flipping the fake to throw on ab: unwrap — exactly what the
    // dead SE/Keystore key does.
    // -----------------------------------------------------------------------

    /** [armedMarker] is the app's OWN authenticated `vlt_rp` blob, captured while the
     *  enable was in flight — the only way a test can re-arm the marker later without
     *  forging one (a forged/unauthenticated value is deliberately inert). */
    private class RecoverySetup(
        val vs: VaultSelector,
        val protector: FakeAuthBindingProtector,
        val code: String,
        val armedMarker: String,
    )

    /**
     * A selector over the CURRENT prefs/vault wired to [protector] — i.e. what the
     * next process launch would construct. Used by the abandoned-enable cases to cross a
     * "relaunch" boundary, which is what drops the RAM-only pendingAuthBoundBlob.
     */
    private fun createLeverBSelector(protector: DbKeyProtector): VaultSelector =
        VaultSelector(
            store = KeyValueStore(context, SELECTOR_PREFS),
            crypto = CryptoProvider(context),
            vaultFactory = androidVaultFactory(context),
            dbKeyProtector = protector,
        ).apply { changePinMinDelayMs = 0 }

    private fun provisionLeverBVaultWithRecovery(): RecoverySetup {
        context.deleteSharedPreferences(SELECTOR_PREFS)
        context.deleteDatabase(REAL_DB_NAME)
        val protector = FakeAuthBindingProtector()
        val vs = VaultSelector(
            store = KeyValueStore(context, SELECTOR_PREFS),
            crypto = CryptoProvider(context),
            vaultFactory = androidVaultFactory(context),
            dbKeyProtector = protector,
        ).apply { changePinMinDelayMs = 0 }

        assertTrue("PRIVATE provision should succeed",
            vs.setRealCredential(REAL_PIN, passphraseMode = false, level = ProtectionLevel.PRIVATE))
        val opened = vs.unlock(REAL_PIN) as VaultSelector.UnlockResult.Opened
        opened.vault.insertContact(ContactRecord("recov-1", FAKE_SECRET, 1, "RecovAlice", 1_700_000_000_000L))
        opened.vault.close()

        val enable = vs.enableDbKeyAuthBindingWithRecovery(REAL_PIN)
        assertTrue("Lever B prepare + recovery mint should succeed",
            enable is VaultSelector.RecoveryEnableResult.Enabled)
        val code = (enable as VaultSelector.RecoveryEnableResult.Enabled).recoveryCode
        assertTrue("recovery code must be non-blank", code.isNotBlank())
        // Two-phase enable: prepare writes + verifies the recovery blob but keeps the vault
        // PLAIN; the strict auth-bound blob is committed only when finalize runs (after
        // the user acknowledges the code) — so a lost code can never brick the vault.
        assertTrue("recovery blob must be present after prepare", vs.hasRecoveryCode())
        assertTrue("vault must stay PLAIN until finalize", !vs.isDbKeyAuthBound())
        // Captured mid-flight: this is a genuine, device-key-AUTHENTICATED marker, which
        // the abandoned-enable cases need because an unauthenticated one can never be actionable.
        val armedMarker = KeyValueStore(context, SELECTOR_PREFS).getString(K_RECOVERY_PENDING)
        assertNotNull("prepare must arm the in-flight marker", armedMarker)
        assertTrue("finalize must commit the auth-bound blob",
            vs.finalizeDbKeyAuthBinding(ProtectionLevel.PRIVATE))
        assertTrue("Lever B must be on after finalize", vs.isDbKeyAuthBound())
        assertTrue("recovery blob must remain after finalize", vs.hasRecoveryCode())
        return RecoverySetup(vs, protector, code, armedMarker!!)
    }

    @Test
    fun leverB_invalidated_recoveredWithCodeAndPin_dataIntact() {
        val setup = provisionLeverBVaultWithRecovery()
        val vs = setup.vs

        // Simulate the hardware key invalidating (re-enroll / passcode change).
        setup.protector.invalidated = true
        assertTrue("a bricked Lever B unlock must be a neutral Error, never a counted Denial",
            vs.unlock(REAL_PIN) is VaultSelector.UnlockResult.Error)

        // Recover with code + PIN → opens, data preserved (dbKey unchanged).
        val recovered = vs.recoverWithCode(setup.code, REAL_PIN)
        assertTrue("recovery with the correct code + PIN must open the vault",
            recovered is VaultSelector.UnlockResult.Opened)
        assertNotNull("recovered vault must still hold the seeded contact (dbKey preserved)",
            (recovered as VaultSelector.UnlockResult.Opened).vault.getContact("recov-1"))

        // Post-recovery: downgraded to plain (re-provision floor), recovery consumed.
        assertTrue("Lever B must be OFF after recovery", !vs.isDbKeyAuthBound())
        assertTrue("recovery blob must be consumed after recovery", !vs.hasRecoveryCode())
        // #8/#27: the fake reports the re-establish round-trip fails (still
        // invalidated), so Lever B can't be restored. The DISPLAY honestly drops the
        // hardware-barrier claim (currentProtectionLevel → CASUAL art, prompting
        // re-harden), reconciled LIVE from isDbKeyAuthBound()==false — so an
        // interrupted reconcile could never strand a false PRIVATE-over-plain claim.
        assertEquals("unrestorable Lever B must DISPLAY honestly, not over-claim PRIVATE",
            ProtectionLevel.CASUAL, vs.currentProtectionLevel())
        // …but the ENFORCEMENT timer tier must NOT be silently relaxed to CASUAL's
        // lax windows (regression #8): it stays at the user's chosen PRIVATE.
        assertEquals("recovery must keep the persisted PRIVATE timer tier, not relax it to CASUAL",
            ProtectionLevel.PRIVATE, vs.protectionLevelOrNull())
        val enforced = vs.protectionLevelForEnforcement()
        assertTrue("enforcement tier must read Present after recovery",
            enforced is ProtectionLevelRead.Present)
        assertEquals("enforcement must keep PRIVATE timers, never drop to CASUAL",
            ProtectionLevel.PRIVATE, (enforced as ProtectionLevelRead.Present).level)
        assertEquals("wrong-PIN budget must stay PRIVATE's (8), not CASUAL's (10)",
            ProtectionLevel.PRIVATE.maxConsecutiveAttempts,
            CredentialPolicy.maxConsecutiveAttempts(enforced))
        assertEquals("inactivity self-wipe must stay PRIVATE's 90d, not CASUAL's 180d",
            ProtectionLevel.PRIVATE.inactivityWipeMs,
            InactivityPolicy.thresholdMsOrNull(enforced))
        // Plain PIN unlock works again even though the ab: key is still 'dead'.
        assertTrue("plain PIN unlock must work after recovery",
            vs.unlock(REAL_PIN) is VaultSelector.UnlockResult.Opened)
    }

    /**
     * When the device STILL supports auth-binding at recovery
     * time (fresh biometric enrolment works — modeled by a non-invalidated fake),
     * recovery RE-ESTABLISHES Lever B and re-mints the recovery blob under the SAME
     * code, so the persisted PRIVATE tier stays honest (no silent downgrade to a
     * PIN-only vault while Settings keeps saying "Private").
     */
    @Test
    fun leverB_recovery_reEstablishesLeverB_whenDeviceStillSupportsIt_tierStaysPrivate() {
        val setup = provisionLeverBVaultWithRecovery()
        val vs = setup.vs
        // NOT invalidated: the (fresh) hardware key round-trips, so re-establish succeeds.

        val recovered = vs.recoverWithCode(setup.code, REAL_PIN)
        assertTrue("recovery must open the vault",
            recovered is VaultSelector.UnlockResult.Opened)
        assertNotNull("recovered vault keeps its data (dbKey preserved)",
            (recovered as VaultSelector.UnlockResult.Opened).vault.getContact("recov-1"))

        // Lever B re-armed, recovery blob re-minted, tier legitimately still PRIVATE.
        assertTrue("Lever B must be re-established on a still-capable device",
            vs.isDbKeyAuthBound())
        assertTrue("recovery blob must be re-minted", vs.hasRecoveryCode())
        assertEquals("tier stays PRIVATE because the hardware barrier is genuinely back",
            ProtectionLevel.PRIVATE, vs.currentProtectionLevel())

        // The SAME code still recovers (re-minted under the same secret) — no new
        // code needs to be surfaced from the unlock result.
        assertTrue("the same recovery code must still work after the re-mint",
            vs.recoverWithCode(setup.code, REAL_PIN) is VaultSelector.UnlockResult.Opened)
    }

    /**
     * BRICK-SAFETY (biometric strict-invalidate): the auth-bound key now
     * strict-invalidates on any biometric re-enrollment, so the recovery code is the
     * ONLY way back into a PRIVATE vault. The raw setDbKeyAuthBinding(true) toggle
     * cannot mint a code, so it must REFUSE to create an ab: blob without an existing
     * recovery path — enabling from scratch has to go through
     * enableDbKeyAuthBindingWithRecovery. A refused enable leaves a working plain vault.
     */
    @Test
    fun setDbKeyAuthBinding_true_refusedWithoutRecoveryBlob() {
        context.deleteSharedPreferences(SELECTOR_PREFS)
        context.deleteDatabase(REAL_DB_NAME)
        val protector = FakeAuthBindingProtector()
        val vs = VaultSelector(
            store = KeyValueStore(context, SELECTOR_PREFS),
            crypto = CryptoProvider(context),
            vaultFactory = androidVaultFactory(context),
            dbKeyProtector = protector,
        ).apply { changePinMinDelayMs = 0 }

        assertTrue("PRIVATE provision should succeed",
            vs.setRealCredential(REAL_PIN, passphraseMode = false, level = ProtectionLevel.PRIVATE))
        (vs.unlock(REAL_PIN) as VaultSelector.UnlockResult.Opened).vault.close()

        assertFalse("no recovery blob → setDbKeyAuthBinding(true) must refuse",
            vs.setDbKeyAuthBinding(true))
        assertFalse("DB key must stay plain after a refused enable", vs.isDbKeyAuthBound())
        assertFalse("no recovery blob should have been created", vs.hasRecoveryCode())
        // The vault still opens on the plain (PIN) path — a refused enable never bricks.
        assertTrue("plain PIN unlock must still work after a refused enable",
            vs.unlock(REAL_PIN) is VaultSelector.UnlockResult.Opened)

        // The sanctioned path DOES enable (mints + read-back-verifies a recovery code),
        // then finalize commits the strict auth-bound blob (two-phase enable).
        val enable = vs.enableDbKeyAuthBindingWithRecovery(REAL_PIN)
        assertTrue("sanctioned enable (prepare) must succeed",
            enable is VaultSelector.RecoveryEnableResult.Enabled)
        assertTrue("recovery blob present after prepare", vs.hasRecoveryCode())
        assertTrue("vault plain until finalize", !vs.isDbKeyAuthBound())
        assertTrue("finalize commits ab:", vs.finalizeDbKeyAuthBinding(ProtectionLevel.PRIVATE))
        assertTrue("Lever B on after finalize", vs.isDbKeyAuthBound())
    }

    /**
     * The two-phase enable must NEVER persist a PRIVATE-over-plain-key state.
     * PHASE ONE (prepare) leaves the key PLAIN and the tier at its base; only
     * finalize(PRIVATE) promotes the tier ATOMICALLY with the ab: commit.
     */
    @Test
    fun twoPhaseEnable_neverPersistsPrivateOverPlainKey() {
        context.deleteSharedPreferences(SELECTOR_PREFS)
        context.deleteDatabase(REAL_DB_NAME)
        val protector = FakeAuthBindingProtector()
        val vs = VaultSelector(
            store = KeyValueStore(context, SELECTOR_PREFS),
            crypto = CryptoProvider(context),
            vaultFactory = androidVaultFactory(context),
            dbKeyProtector = protector,
        ).apply { changePinMinDelayMs = 0 }
        // Provision at the HONEST BASE (Casual) — the enable phase keeps this until ack.
        assertTrue(vs.setRealCredential(REAL_PIN, passphraseMode = false, level = ProtectionLevel.CASUAL))
        (vs.unlock(REAL_PIN) as VaultSelector.UnlockResult.Opened).vault.close()

        // PHASE ONE: prepare. Key stays PLAIN, tier stays base — no PRIVATE-over-plain.
        val prep = vs.enableDbKeyAuthBindingWithRecovery(REAL_PIN)
        assertTrue("prepare must succeed", prep is VaultSelector.RecoveryEnableResult.Enabled)
        assertTrue("recovery blob written at prepare", vs.hasRecoveryCode())
        assertTrue("key must stay PLAIN before finalize", !vs.isDbKeyAuthBound())
        assertFalse("tier must NOT be PRIVATE while the key is plain (M8)",
            vs.protectionLevelOrNull() == ProtectionLevel.PRIVATE)

        // PHASE TWO: finalize promotes ab: + PRIVATE atomically.
        assertTrue("finalize must succeed", vs.finalizeDbKeyAuthBinding(ProtectionLevel.PRIVATE))
        assertTrue("key auth-bound after finalize", vs.isDbKeyAuthBound())
        assertEquals("tier PRIVATE after finalize", ProtectionLevel.PRIVATE, vs.protectionLevelOrNull())
        assertEquals("PRIVATE is honest (ab: key present)",
            ProtectionLevel.PRIVATE, vs.currentProtectionLevel())
    }

    /**
     * Close the cracked-passcode door on UPGRADED installs: a PRIVATE vault whose
     * auth-bound key is the LEGACY WEAK scheme (no strict marker) is re-minted to the
     * strict biometric-only scheme on the next unlock — when biometrics + a recovery
     * code are present. The legacy state is simulated by removing the strict marker
     * that finalize wrote.
     */
    @Test
    fun legacyWeakAuthBoundKey_reconciledToStrictOnUnlock() {
        val setup = provisionLeverBVaultWithRecovery()   // finalized → strict marker present
        val vs = setup.vs
        val store = KeyValueStore(context, SELECTOR_PREFS)

        assertTrue("freshly finalized vault must NOT need reharden (already strict)",
            !vs.needsLeverBReharden())

        // Simulate a LEGACY (pre-hardening) auth-bound vault: strip the strict marker.
        store.remove(K_AUTHBOUND_SCHEME)
        assertTrue("a legacy-scheme ab: vault must report needing reharden",
            vs.needsLeverBReharden())

        // Unlock with biometrics available (fake supports auth-binding) + recovery present
        // → the legacy key is reconciled to strict in place; data preserved.
        val opened = vs.unlock(REAL_PIN)
        assertTrue("unlock must open the vault", opened is VaultSelector.UnlockResult.Opened)
        assertNotNull("data preserved across reconcile",
            (opened as VaultSelector.UnlockResult.Opened).vault.getContact("recov-1"))
        opened.vault.close()

        assertTrue("still Lever B after reconcile", vs.isDbKeyAuthBound())
        assertTrue("recovery blob preserved across reconcile", vs.hasRecoveryCode())
        assertTrue("reconcile must clear the reharden signal (now strict)",
            !vs.needsLeverBReharden())
    }

    /**
     * SAFETY: a legacy weak key with NO recovery blob (Gen A: Lever B enabled before
     * the recovery code existed) must NOT be silently strict-invalidated on unlock — that
     * could brick without a recovery net. The vault keeps its working legacy key and the
     * reharden signal stays raised for the UI to act on.
     */
    @Test
    fun legacyWeakAuthBoundKey_noRecovery_notReconciled_staysUsable() {
        val setup = provisionLeverBVaultWithRecovery()
        val vs = setup.vs
        val store = KeyValueStore(context, SELECTOR_PREFS)

        // Legacy scheme + Gen-A (no recovery blob).
        store.remove(K_AUTHBOUND_SCHEME)
        store.remove(K_RECOVERY_BLOB)
        assertTrue("legacy ab: vault reports needing reharden", vs.needsLeverBReharden())

        val opened = vs.unlock(REAL_PIN)
        assertTrue("unlock still opens the vault (legacy key kept)",
            opened is VaultSelector.UnlockResult.Opened)
        (opened as VaultSelector.UnlockResult.Opened).vault.close()

        // Not reconciled (no recovery net) → signal remains raised for the UI.
        assertTrue("without a recovery code the key is NOT auto-reconciled",
            vs.needsLeverBReharden())
    }

    // -----------------------------------------------------------------------
    // At-rest metadata indistinguishability.
    // -----------------------------------------------------------------------

    /**
     * Finding 29 (part b): a PIN provision must ALWAYS write vlt_m (as MODE_PIN),
     * so its presence/absence can't leak the credential mode with no device key.
     */
    @Test
    fun pinProvision_alwaysWritesVltM_asABlob() {
        val stored = KeyValueStore(context, SELECTOR_PREFS).getString("vlt_m")
        assertNotNull("a PIN provision must WRITE vlt_m (never rely on its absence)", stored)
        assertTrue("vlt_m must be an AEAD blob, not cleartext", decodeBase64(stored!!).size >= 28)
        assertTrue("a PIN vault must read as NOT passphrase mode", !vaultSelector.isPassphraseMode())
    }

    /**
     * Findings 29 & 35: the vlt_m and vlt_lvl ciphertext lengths must be CONSTANT
     * across credential mode (PIN vs passphrase) and protection tier, so a
     * key-free length read off the SharedPreferences XML no longer distinguishes
     * them (the device-key wrap alone left the length side-channel open).
     */
    @Test
    fun selectorMeta_ciphertextLength_isConstant_acrossModeAndTier() {
        // vlt_m: the PIN vault from setUp.
        val pinModeLen = decodeBase64(
            KeyValueStore(context, SELECTOR_PREFS).getString("vlt_m")!!).size

        // A fresh passphrase (MAXIMUM) vault.
        context.deleteSharedPreferences(SELECTOR_PREFS)
        context.deleteDatabase(REAL_DB_NAME)
        val vs2 = createVaultSelector()
        assertTrue("passphrase provision should succeed", vs2.setRealCredential(
            "correct horse battery staple ozone thicket",
            passphraseMode = true, level = ProtectionLevel.MAXIMUM))
        val prefs2 = KeyValueStore(context, SELECTOR_PREFS)
        val phraseModeLen = decodeBase64(prefs2.getString("vlt_m")!!).size
        assertEquals("vlt_m ciphertext length must NOT distinguish PIN from passphrase",
            pinModeLen, phraseModeLen)

        // vlt_lvl across tiers (MAXIMUM just written; switch to CASUAL and compare).
        val maxTierLen = decodeBase64(prefs2.getString("vlt_lvl")!!).size
        assertTrue(vs2.setProtectionLevel(ProtectionLevel.CASUAL))
        val casualTierLen = decodeBase64(
            KeyValueStore(context, SELECTOR_PREFS).getString("vlt_lvl")!!).size
        assertEquals("vlt_lvl ciphertext length must NOT distinguish CASUAL from MAXIMUM",
            maxTierLen, casualTierLen)
    }

    /**
     * Finding 34: the stored DB-key blob must carry no cleartext "ab:"/"cp:" scheme
     * word an examiner can grep to learn whether Lever B is on. A plain vault's blob
     * uses the scheme-neutral form and still reads as NOT auth-bound.
     */
    @Test
    fun dbKeyBlob_carriesNoCleartextSchemeWord() {
        val stored = KeyValueStore(context, SELECTOR_PREFS).getString(K_REAL_DBKEY)
        assertNotNull("wrapped DB key must be stored", stored)
        assertTrue("plain DB-key blob must not expose an 'ab:' scheme word",
            !stored!!.startsWith("ab:"))
        assertTrue("plain DB-key blob must not expose a 'cp:' scheme word",
            !stored.startsWith("cp:"))
        assertTrue("a plain vault must not read as Lever B", !vaultSelector.isDbKeyAuthBound())
        // And it still round-trips: the vault opens with the correct PIN.
        assertTrue("the neutral-form blob must still unwrap on unlock",
            vaultSelector.unlock(REAL_PIN) is VaultSelector.UnlockResult.Opened)
    }

    @Test
    fun recovery_wrongCode_wrongPin_orMalformed_areDenied_stateUnchanged() {
        val setup = provisionLeverBVaultWithRecovery()
        val vs = setup.vs
        setup.protector.invalidated = true

        // Wrong (well-formed) code → AEAD tag miss → Denied.
        assertTrue("a wrong recovery code must be Denied",
            vs.recoverWithCode("0000000000000000000000000000000Z", REAL_PIN) is VaultSelector.UnlockResult.Denied)
        // Wrong PIN (correct code) → credential miss → Denied.
        assertTrue("a wrong PIN must be Denied",
            vs.recoverWithCode(setup.code, WRONG_PIN) is VaultSelector.UnlockResult.Denied)
        // Malformed code (invalid Base32) → Denied.
        assertTrue("a malformed code must be Denied",
            vs.recoverWithCode("not a valid code!!!", REAL_PIN) is VaultSelector.UnlockResult.Denied)

        // None of the failed attempts mutated anything: the correct code + PIN still recovers.
        assertTrue("recovery state must be intact after failed attempts", vs.hasRecoveryCode())
        assertTrue("the correct code + PIN still recovers after failed attempts",
            vs.recoverWithCode(setup.code, REAL_PIN) is VaultSelector.UnlockResult.Opened)
    }

    @Test
    fun disablingLeverB_dropsTheRecoveryBlob() {
        val setup = provisionLeverBVaultWithRecovery()
        assertTrue("precondition: recovery blob present", setup.vs.hasRecoveryCode())
        // Disable Lever B (fake unwrap succeeds — not invalidated) → recovery must go.
        assertTrue("disable should succeed", setup.vs.setDbKeyAuthBinding(false))
        assertTrue("Lever B off after disable", !setup.vs.isDbKeyAuthBound())
        assertTrue("recovery blob must be dropped when Lever B is disabled", !setup.vs.hasRecoveryCode())
    }

    // -----------------------------------------------------------------------
    // An ABANDONED Lever B enable must not leave a
    // permanent orphan recovery code.
    //
    // Phase one commits + read-back-verifies `vlt_rc` and then holds the
    // auth-bound blob in RAM only, so if finalize never runs (back press —
    // that screen registers no back handler — auto-lock, backgrounding, process
    // death) the vault stays PLAIN while a second, live, independent
    // vault-decrypt path survives on disk forever. A durable in-flight marker
    // (`vlt_rp`) names exactly that state so the next unlock can revoke it —
    // and, just as importantly, so the purge can never fire on the post-recovery
    // re-establish window, which deliberately re-mints `vlt_rc` under the SAME
    // code the user already holds.
    // -----------------------------------------------------------------------

    @Test
    fun abandonedLeverBEnable_orphanRecoveryCode_isRevokedOnTheNextUnlock() {
        context.deleteSharedPreferences(SELECTOR_PREFS)
        context.deleteDatabase(REAL_DB_NAME)
        val protector = FakeAuthBindingProtector()
        val vs = createLeverBSelector(protector)
        assertTrue("provision should succeed",
            vs.setRealCredential(REAL_PIN, passphraseMode = false, level = ProtectionLevel.CASUAL))
        (vs.unlock(REAL_PIN) as VaultSelector.UnlockResult.Opened).vault.close()

        // PHASE ONE only — the user never acknowledges the code, so finalize never runs.
        val prep = vs.enableDbKeyAuthBindingWithRecovery(REAL_PIN)
        assertTrue("prepare must succeed", prep is VaultSelector.RecoveryEnableResult.Enabled)
        val code = (prep as VaultSelector.RecoveryEnableResult.Enabled).recoveryCode
        assertTrue("precondition: the recovery blob is on disk", vs.hasRecoveryCode())
        assertFalse("precondition: the vault is still PLAIN", vs.isDbKeyAuthBound())
        assertNotNull("prepare must arm the in-flight marker",
            KeyValueStore(context, SELECTOR_PREFS).getString(K_RECOVERY_PENDING))

        // SAME process: the prepared blob is still in RAM and the user can still
        // finalize, so an unlock here must NOT revoke anything. (Purging while a
        // finalize — or an iOS journal replay — can still commit the ab: blob would
        // land an auth-bound vault with no recovery path: the one true brick.)
        (vs.unlock(REAL_PIN) as VaultSelector.UnlockResult.Opened).vault.close()
        assertTrue("an in-flight enable must keep its recovery blob", vs.hasRecoveryCode())

        // RELAUNCH: the RAM-only pending blob is gone, so the enable is provably
        // abandoned and the orphan code is revoked.
        val relaunched = createLeverBSelector(protector)
        val opened = relaunched.unlock(REAL_PIN)
        assertTrue("the vault must still open with the PIN", opened is VaultSelector.UnlockResult.Opened)
        (opened as VaultSelector.UnlockResult.Opened).vault.close()

        assertFalse("the orphan recovery code must be revoked", relaunched.hasRecoveryCode())
        assertNull("and the marker cleared with it",
            KeyValueStore(context, SELECTOR_PREFS).getString(K_RECOVERY_PENDING))
        assertTrue("the abandoned code must no longer open anything",
            relaunched.recoverWithCode(code, REAL_PIN) is VaultSelector.UnlockResult.Error)
        // The vault itself is untouched: the PIN still opens it.
        assertTrue("revoking an orphan must never cost the user their vault",
            relaunched.unlock(REAL_PIN) is VaultSelector.UnlockResult.Opened)
    }

    /**
     * The control the purge exists to not break: a COMPLETED enable (prepare +
     * finalize) keeps its recovery code through unlock after unlock.
     */
    @Test
    fun finalizedLeverBEnable_recoveryCodeSurvivesUnlocks() {
        val setup = provisionLeverBVaultWithRecovery()
        val vs = setup.vs
        assertNull("finalize must disarm the in-flight marker",
            KeyValueStore(context, SELECTOR_PREFS).getString(K_RECOVERY_PENDING))

        repeat(2) {
            val opened = vs.unlock(REAL_PIN)
            assertTrue("Lever B unlock must open the vault", opened is VaultSelector.UnlockResult.Opened)
            (opened as VaultSelector.UnlockResult.Opened).vault.close()
            assertTrue("a finalized enable's recovery code must survive every unlock",
                vs.hasRecoveryCode())
        }
        assertTrue("…and must still actually recover the vault",
            vs.recoverWithCode(setup.code, REAL_PIN) is VaultSelector.UnlockResult.Opened)
    }

    /**
     * BRICK-SAFETY: an armed marker over an AUTH-BOUND vault — what a crash between
     * finalize's atomic ab: commit and its marker clear leaves — must clear the marker
     * and NOT touch `vlt_rc`. That blob is the only way back into a Lever B vault once
     * the hardware key invalidates.
     */
    @Test
    fun armedMarkerOverAnAuthBoundVault_neverRevokesTheRecoveryCode() {
        context.deleteSharedPreferences(SELECTOR_PREFS)
        context.deleteDatabase(REAL_DB_NAME)
        val protector = FakeAuthBindingProtector()
        val vs = createLeverBSelector(protector)
        assertTrue(vs.setRealCredential(REAL_PIN, passphraseMode = false, level = ProtectionLevel.CASUAL))
        (vs.unlock(REAL_PIN) as VaultSelector.UnlockResult.Opened).vault.close()

        val prep = vs.enableDbKeyAuthBindingWithRecovery(REAL_PIN)
        assertTrue("prepare must succeed", prep is VaultSelector.RecoveryEnableResult.Enabled)
        val code = (prep as VaultSelector.RecoveryEnableResult.Enabled).recoveryCode
        val prefs = KeyValueStore(context, SELECTOR_PREFS)
        // Capture the app's OWN authenticated marker blob while the enable is in flight.
        val armed = prefs.getString(K_RECOVERY_PENDING)
        assertNotNull("precondition: the marker is armed during phase one", armed)

        assertTrue("finalize must commit the ab: blob",
            vs.finalizeDbKeyAuthBinding(ProtectionLevel.PRIVATE))
        assertTrue("precondition: the vault is auth-bound", vs.isDbKeyAuthBound())
        assertNull("finalize must disarm the marker", prefs.getString(K_RECOVERY_PENDING))

        // The crash window: ab: committed, marker never cleared.
        prefs.putString(K_RECOVERY_PENDING, armed!!)

        val relaunched = createLeverBSelector(protector)
        val opened = relaunched.unlock(REAL_PIN)
        assertTrue("the Lever B vault must open", opened is VaultSelector.UnlockResult.Opened)
        (opened as VaultSelector.UnlockResult.Opened).vault.close()

        assertTrue("an auth-bound vault's recovery code must NEVER be revoked",
            relaunched.hasRecoveryCode())
        assertNull("only the stale marker is cleared", prefs.getString(K_RECOVERY_PENDING))
        // The decisive assertion: the code the user wrote down still opens the vault.
        assertTrue("the recovery code must still recover the vault",
            relaunched.recoverWithCode(code, REAL_PIN) is VaultSelector.UnlockResult.Opened)
    }

    /**
     * The objection to a naive purge, locked in: the post-recovery re-establish
     * deliberately re-mints `vlt_rc` under the SAME code the user just used, and if the
     * FINAL ab: write silently no-ops (iOS `kvPut` on a locked keybag) the vault is left
     * PLAIN beside a LIVE recovery blob — permanently. A purge keyed on "plain blob +
     * recovery blob present" would revoke a code the user was explicitly told still
     * works. Here the no-op is modelled by a protector whose auth-bound wrap produces a
     * plain blob, so the store really does end up plain after the re-establish.
     *
     * The marker is ARMED before the recovery on purpose. Without that, no `vlt_rp`
     * exists anywhere in this scenario, the "no marker across the window" assertion is
     * trivially true, and the doc's clear-BEFORE-re-mint rule is never exercised at all
     * — the state under test would be indistinguishable from the abandoned-enable purge being absent.
     *
     * Honest limit, stated so nobody reads more into this than it proves: the recovery
     * path disarms the marker TWICE (once in `recoverWithCode` right after the plain
     * blob is committed, once at the top of `tryReEstablishLeverBAfterRecovery`, before
     * the re-mint), and on Android both writes always land — so removing EITHER one
     * alone is invisible through the public API. This test fails when the disarm is
     * gone from the window as a whole, and when the purge stops requiring an armed
     * marker. The iOS half, where a store write can genuinely be lost, is in
     * IosDbKeyRotationTest's sibling coverage.
     */
    @Test
    fun postRecoveryReEstablish_withTheAbCommitLostToANoOp_keepsTheUsersCode() {
        val setup = provisionLeverBVaultWithRecovery()
        val vs = setup.vs
        val prefs = KeyValueStore(context, SELECTOR_PREFS)
        // Arm the app's OWN authenticated marker over the vault: the state a Lever B
        // enable that was interrupted before this recovery would have left behind.
        prefs.putString(K_RECOVERY_PENDING, setup.armedMarker)
        assertNotNull("precondition: a marker is armed going INTO the recovery",
            prefs.getString(K_RECOVERY_PENDING))
        // From here every "auth-bound" wrap lands as a PLAIN blob — the ab: commit at
        // the end of the re-establish is effectively lost, exactly like a silent kvPut.
        setup.protector.authBoundWriteNoOps = true

        val recovered = vs.recoverWithCode(setup.code, REAL_PIN)
        assertTrue("recovery must open the vault", recovered is VaultSelector.UnlockResult.Opened)
        assertNotNull("recovered vault keeps its data",
            (recovered as VaultSelector.UnlockResult.Opened).vault.getContact("recov-1"))
        recovered.vault.close()

        // The dangerous-looking state the abandoned-enable purge must NOT act on: plain DB key + live vlt_rc.
        assertFalse("precondition: the ab: commit was lost — the vault is plain",
            vs.isDbKeyAuthBound())
        assertTrue("precondition: the code was re-minted under the same secret",
            vs.hasRecoveryCode())
        assertNull("the recovery path must disarm the marker BEFORE re-minting vlt_rc —" +
            " an armed marker across this window revokes a code the UI still promises",
            prefs.getString(K_RECOVERY_PENDING))

        val relaunched = createLeverBSelector(setup.protector)
        (relaunched.unlock(REAL_PIN) as VaultSelector.UnlockResult.Opened).vault.close()

        assertTrue("the re-minted recovery code must survive the unlock purge",
            relaunched.hasRecoveryCode())
        assertTrue("and must still recover the vault — the code the user holds is valid",
            relaunched.recoverWithCode(setup.code, REAL_PIN) is VaultSelector.UnlockResult.Opened)
    }

    /**
     * PROSPECTIVE-ONLY: a recovery blob with NO armed marker — an install that abandoned
     * an enable before this marker existed, or anything hand-written — is never purged.
     * A delete may only fire on evidence THIS app wrote; absence is not evidence.
     */
    @Test
    fun orphanRecoveryBlob_withNoArmedMarker_isNeverPurged() {
        val prefs = KeyValueStore(context, SELECTOR_PREFS)
        assertNull("precondition: nothing in flight", prefs.getString(K_RECOVERY_PENDING))
        assertFalse("precondition: the vault is plain", vaultSelector.isDbKeyAuthBound())
        prefs.putString(K_RECOVERY_BLOB, "legacy-orphan-recovery-blob")

        val opened = createVaultSelector().unlock(REAL_PIN)
        assertTrue("the vault must open normally", opened is VaultSelector.UnlockResult.Opened)
        (opened as VaultSelector.UnlockResult.Opened).vault.close()

        assertEquals("an unmarked orphan must be left exactly as it was",
            "legacy-orphan-recovery-blob", prefs.getString(K_RECOVERY_BLOB))
    }

    // -----------------------------------------------------------------------
    // Selector metadata (vlt_m / vlt_lvl) — sealed blob storage + the 2026-07-14
    // regressions: the level must round-trip through the DECRYPTING read on
    // Android (the raw SharedPreferences read parsed the blob as null and fell
    // back to the 7-day default → ~173-day-early wipe).
    //
    // Plus the 2026-07-30 pair, which sharpened what a NON-decrypting read means
    // for the destructive sites:
    //  - an UNAUTHENTICATED value (the legacy-cleartext tolerance, which any
    //    filesystem writer can forge) still DISPLAYS, but enforces MAXIMUM.
    //  - a blob-shaped value that fails AEAD under a WORKING device key is
    //    Damaged (positive tamper evidence) → MAXIMUM's window/budget, NOT the
    //    old Unreadable "skip forever". Unreadable now means only "device key
    //    transiently unavailable" and keeps deferring.
    // Both fail SECURE without ever becoming a wipe trigger on their own.
    // -----------------------------------------------------------------------

    @Test
    fun protectionLevel_blobStored_yieldsItsOwnEnforcementWindow() {
        assertTrue("setProtectionLevel must persist (device key available)",
            vaultSelector.setProtectionLevel(ProtectionLevel.CASUAL))

        // At rest the value is an AEAD blob, not the cleartext tier name.
        val stored = KeyValueStore(context, SELECTOR_PREFS).getString("vlt_lvl")
        assertNotNull("level must be stored", stored)
        assertTrue("stored level must be a blob, not cleartext", stored != "casual")

        // Finding 1 regression: the decrypting enforcement read yields CASUAL's
        // own 180-day window — not null → the 7-day default.
        val read = vaultSelector.protectionLevelForEnforcement()
        assertTrue("blob level must read as Present", read is ProtectionLevelRead.Present)
        assertEquals(ProtectionLevel.CASUAL, (read as ProtectionLevelRead.Present).level)
        assertEquals(ProtectionLevel.CASUAL.inactivityWipeMs, InactivityPolicy.thresholdMsOrNull(read))
        assertEquals(ProtectionLevel.CASUAL, vaultSelector.protectionLevelOrNull())
    }

    /**
     * Fail-secure, half one — MIGRATION SAFETY. An install provisioned before the sealed-blob
     * change stores the raw tier name, and the fail-secure enforcement read below
     * must not make such a vault LOOK downgraded: the DISPLAY path still reports
     * the tier the user actually chose, so Settings/the runestone art stay honest
     * and the user is not told their Casual vault is now Maximum.
     */
    @Test
    fun protectionLevel_legacyCleartext_stillDisplaysItsTrueTier() {
        KeyValueStore(context, SELECTOR_PREFS).putString("vlt_lvl", "casual")

        assertEquals("a legacy cleartext level must still DISPLAY its true tier",
            ProtectionLevel.CASUAL, vaultSelector.protectionLevelOrNull())
        assertEquals("the UI art selector must agree with it",
            ProtectionLevel.CASUAL, vaultSelector.displayProtectionLevel())
    }

    /**
     * Fail-secure, half two — FAIL-SECURE ENFORCEMENT. The legacy-cleartext tolerance is
     * unauthenticated by construction: `casual` is six ASCII bytes anyone who can
     * write vault_selector_prefs.xml (or, on iOS, the NSUserDefaults fallback slot)
     * can plant, and nothing distinguishes a genuine pre-sealed-level value from that
     * forgery. So the DESTRUCTIVE read must refuse to trust it and enforce the
     * strictest tier — matching what a pre-slider vault has always enforced
     * (7-day wipe, 5 attempts) plus MAXIMUM's tighter auto-lock.
     *
     * The genuine legacy vault is not punished permanently: it still displays its
     * real tier (test above) and the next level write upgrades it to a blob, after
     * which enforcement honours the chosen tier again — the migrate-on-write half.
     */
    @Test
    fun protectionLevel_legacyCleartext_cannotLoosenEnforcement() {
        KeyValueStore(context, SELECTOR_PREFS).putString("vlt_lvl", "casual")

        val read = vaultSelector.protectionLevelForEnforcement()
        assertTrue("an unauthenticated level must still read as Present (not Absent)",
            read is ProtectionLevelRead.Present)
        assertEquals("an unauthenticated 'casual' must enforce MAXIMUM, never CASUAL",
            ProtectionLevel.MAXIMUM, (read as ProtectionLevelRead.Present).level)

        // Self-heal: one authenticated write and the vault's real tier is back in
        // force — the fail-secure is a floor for untrusted values, not a one-way trap.
        assertTrue(vaultSelector.setProtectionLevel(ProtectionLevel.CASUAL))
        val healed = vaultSelector.protectionLevelForEnforcement()
        assertTrue("a re-written (authenticated) level must read as Present",
            healed is ProtectionLevelRead.Present)
        assertEquals("after migrate-on-write the chosen tier is enforced again",
            ProtectionLevel.CASUAL, (healed as ProtectionLevelRead.Present).level)
        assertEquals(ProtectionLevel.CASUAL.inactivityWipeMs,
            InactivityPolicy.thresholdMsOrNull(healed))
    }

    /**
     * The OTHER direction of the same slot. An earlier fix stopped an
     * unauthenticated `vlt_lvl` from LOOSENING a timer/budget/auto-lock by failing
     * secure to MAXIMUM. The Lever A credential FLOOR
     * (DeviceLockPolicy.needsForcedMigration — "a phone with no lock screen must run
     * at MAXIMUM") asks the opposite question, so MAXIMUM is fail-OPEN there:
     * planting the seven ASCII bytes `maximum` (5 decoded bytes, under the 28-byte
     * blob floor ⇒ legacy-cleartext branch) used to satisfy the floor forever, on
     * exactly the device class where CR-1 has already collapsed to a ~20-bit PIN.
     *
     * protectionLevelForFloorCheck() is the provenance-aware read that closes it.
     */
    @Test
    fun protectionLevel_plantedCleartextMaximum_cannotSatisfyTheDeviceLockFloor() {
        KeyValueStore(context, SELECTOR_PREFS).putString("vlt_lvl", "maximum")

        // Pre-fix path, still present for DISPLAY-of-a-legacy-vault reasons: the
        // lenient read hands the planted token straight through…
        assertEquals("the lenient read still returns the planted token",
            ProtectionLevel.MAXIMUM, vaultSelector.protectionLevelOrNull())
        assertFalse("…which is exactly what disarmed the gate",
            DeviceLockPolicy.needsForcedMigration(
                vaultSelector.protectionLevelOrNull(), DeviceLockState.Absent))

        // …while the FLOOR read refuses to be satisfied by an unauthenticated claim.
        val floor = vaultSelector.protectionLevelForFloorCheck()
        assertNotNull("an unauthenticated tier must still resolve to SOME tier", floor)
        assertTrue("an unauthenticated tier must read as the WEAKEST tier, never MAXIMUM",
            floor!!.ordinal < ProtectionLevel.MAXIMUM.ordinal)
        assertTrue("a lock-less phone must now be routed to the forced tier change",
            DeviceLockPolicy.needsForcedMigration(floor, DeviceLockState.Absent))

        // And the UI must stop CORROBORATING the plant — the forced screen no-ops
        // when the pick equals the displayed current level, so a display that still
        // said "Maximum" would leave the user on a screen that writes nothing.
        assertTrue("display must not claim the planted tier",
            vaultSelector.currentProtectionLevel().ordinal < ProtectionLevel.MAXIMUM.ordinal)
        assertTrue("the runestone art must not claim it either",
            vaultSelector.displayProtectionLevel().ordinal < ProtectionLevel.MAXIMUM.ordinal)

        // Self-heal, migrate-on-write: one AUTHENTICATED tier write and a genuine
        // MAXIMUM vault is left alone again — the floor read is a proof requirement,
        // not a one-way trap.
        assertTrue(vaultSelector.setProtectionLevel(ProtectionLevel.MAXIMUM))
        assertEquals(ProtectionLevel.MAXIMUM, vaultSelector.protectionLevelForFloorCheck())
        assertFalse("a sealed MAXIMUM must not be dragged through the forced flow",
            DeviceLockPolicy.needsForcedMigration(
                vaultSelector.protectionLevelForFloorCheck(), DeviceLockState.Absent))
        assertEquals(ProtectionLevel.MAXIMUM, vaultSelector.currentProtectionLevel())
    }

    /**
     * 2A-1 brick-safety half: the two AMBIGUOUS reads must NOT be turned into
     * "below the floor". A damaged blob and a never-chosen tier both keep the
     * pre-fix routing (null → the one-time chooser, which is itself gated by
     * DeviceLockPolicy.isSelectable and whose write self-heals the slot), so no
     * vault whose credential really is a passphrase can be parked on a forced
     * screen that has nothing left to change.
     */
    @Test
    fun protectionLevel_damagedOrAbsent_isNotTreatedAsBelowTheFloor() {
        // Never chosen (the fixture provisions through the level-less overload).
        assertNull("precondition: no tier stored",
            KeyValueStore(context, SELECTOR_PREFS).getString("vlt_lvl"))
        assertNull(vaultSelector.protectionLevelForFloorCheck())
        assertFalse(DeviceLockPolicy.needsForcedMigration(
            vaultSelector.protectionLevelForFloorCheck(), DeviceLockState.Absent))

        // Damaged: blob-shaped (≥ IV+tag) but fails AEAD under a WORKING device key.
        KeyValueStore(context, SELECTOR_PREFS)
            .putString("vlt_lvl", encodeBase64(ByteArray(40) { it.toByte() }))
        assertNull("a damaged blob proves nothing about the tier",
            vaultSelector.protectionLevelForFloorCheck())
        assertFalse("…and must not be forced on that basis",
            DeviceLockPolicy.needsForcedMigration(
                vaultSelector.protectionLevelForFloorCheck(), DeviceLockState.Absent))
        // It still fails SECURE for the destructive windows — unchanged.
        assertTrue(vaultSelector.protectionLevelForEnforcement() is ProtectionLevelRead.Damaged)
    }

    /**
     * 2A-1 regression guard for the case DeviceLockPolicy was actually written for
     * (Android CASUAL, lock screen removed after provisioning): an AUTHENTICATED
     * sub-floor tier must still force, and a device that HAS a lock screen must
     * never be forced whatever the provenance.
     */
    @Test
    fun protectionLevel_sealedSubFloorTier_stillForcesOnlyWithoutALockScreen() {
        assertTrue(vaultSelector.setProtectionLevel(ProtectionLevel.CASUAL))
        val floor = vaultSelector.protectionLevelForFloorCheck()
        assertEquals(ProtectionLevel.CASUAL, floor)
        assertTrue(DeviceLockPolicy.needsForcedMigration(floor, DeviceLockState.Absent))
        assertFalse(DeviceLockPolicy.needsForcedMigration(floor, DeviceLockState.Present))
        assertFalse(DeviceLockPolicy.needsForcedMigration(floor, DeviceLockState.Unknown))
    }

    /**
     * A blob-SHAPED value that fails AEAD under a WORKING
     * device key is positive tamper evidence, not an outage — flipping one byte
     * inside the base64 used to fold into Unreadable, whose threshold is null
     * ("skip this launch") on EVERY launch, permanently disarming the dead-man's
     * switch while simultaneously handing the tamperer the most LENIENT attempt
     * budget. Damaged must therefore select the STRICTEST window/budget.
     *
     * BRICK-SAFETY (the point of the split): Damaged only picks a policy
     * WINDOW. It is never itself a wipe trigger — the timestamp-vs-now check still
     * has to find a genuinely expired stamp, which a recently used vault does not.
     */
    @Test
    fun protectionLevel_damagedBlob_isDamaged_andFailsSecure() {
        // Blob-shaped (≥ IV+tag bytes) but fails AEAD — a damaged/tampered blob.
        val damaged = encodeBase64(ByteArray(40) { it.toByte() })
        KeyValueStore(context, SELECTOR_PREFS).putString("vlt_lvl", damaged)

        // Display read: null → routes to the level chooser, whose write self-heals.
        assertNull("damaged level blob must not parse to a level",
            vaultSelector.protectionLevelOrNull())

        // Enforcement read: Damaged — distinct from Unreadable (device key out).
        val read = vaultSelector.protectionLevelForEnforcement()
        assertTrue("damaged level blob must read as Damaged", read is ProtectionLevelRead.Damaged)

        // …and Damaged fails SECURE on all three enforcement decisions.
        assertEquals("damaged must enforce MAXIMUM's 7-day window, never skip the check",
            ProtectionLevel.MAXIMUM.inactivityWipeMs, InactivityPolicy.thresholdMsOrNull(read))
        assertEquals("damaged must enforce MAXIMUM's (smallest) attempt budget",
            ProtectionLevel.MAXIMUM.maxConsecutiveAttempts,
            CredentialPolicy.maxConsecutiveAttempts(read))
        assertEquals("damaged must enforce the shortest auto-lock",
            ProtectionLevel.MAXIMUM.autoLockTimeoutMs, CredentialPolicy.autoLockTimeoutMs(read))

        // The two states must NOT be conflated: a transient device-key outage still
        // defers (null) and still keeps the most lenient budget, because a healthy
        // blob is indistinguishable from a damaged one while the key is unusable.
        assertNull("a transient key outage must still DEFER, unlike Damaged",
            InactivityPolicy.thresholdMsOrNull(ProtectionLevelRead.Unreadable))
        assertEquals("a transient key outage must still get the most lenient budget",
            ProtectionLevel.MOST_LENIENT_MAX_ATTEMPTS,
            CredentialPolicy.maxConsecutiveAttempts(ProtectionLevelRead.Unreadable))

        // BRICK-SAFETY: selecting the strictest window is not the same as expiring.
        // A vault used seconds ago is not expired under MAXIMUM's window either.
        val now = System.currentTimeMillis()
        assertFalse("a damaged tier blob must never make a recently-used vault expired",
            InactivityPolicy.isExpired(
                lastOpenedMs = now - 5_000L,
                nowMs = now,
                thresholdMs = InactivityPolicy.thresholdMsOrNull(read)!!))

        // Self-heal: the next level write replaces the damaged blob.
        assertTrue(vaultSelector.setProtectionLevel(ProtectionLevel.PRIVATE))
        assertEquals(ProtectionLevel.PRIVATE, vaultSelector.protectionLevelOrNull())
        val healed = vaultSelector.protectionLevelForEnforcement()
        assertTrue(healed is ProtectionLevelRead.Present)
        assertEquals(ProtectionLevel.PRIVATE, (healed as ProtectionLevelRead.Present).level)
    }

    /**
     * Fail-secure end-to-end, every enforcement decision at once: a filesystem-write
     * attacker plants a short unauthenticated token in vlt_lvl and must not be
     * able to LOOSEN a single destructive parameter — not the dead-man's window,
     * not the wrong-credential budget (the only rate limit unlock() has), not
     * auto-lock. Covers the tier tokens (including the retired "hardened" alias,
     * which maps forward to PRIVATE when authenticated) and a junk token.
     *
     * The closing act pins the other direction: an AUTHENTICATED CASUAL value is
     * still honoured in full, so the fix costs a legitimate Casual user nothing.
     */
    @Test
    fun protectionLevel_forgedCleartext_cannotLoosenAnyEnforcementDecision() {
        val prefs = KeyValueStore(context, SELECTOR_PREFS)
        for (forged in listOf("casual", "private", "hardened", "zzz")) {
            prefs.putString("vlt_lvl", forged)
            val read = vaultSelector.protectionLevelForEnforcement()
            assertTrue("forged '$forged' must read as Present, never Absent (which would" +
                " take the legacy-default path)", read is ProtectionLevelRead.Present)
            assertEquals("forged '$forged' must enforce MAXIMUM",
                ProtectionLevel.MAXIMUM, (read as ProtectionLevelRead.Present).level)

            // Stated as "never looser than the strictest tier", so the assertions keep
            // meaning if a tier's numbers are ever retuned.
            val window = InactivityPolicy.thresholdMsOrNull(read)
            assertEquals("forged '$forged' must not stretch the dead-man's window",
                ProtectionLevel.MAXIMUM.inactivityWipeMs, window)
            assertTrue("forged '$forged' must not exceed any tier's window",
                window!! <= ProtectionLevel.entries.maxOf { it.inactivityWipeMs })

            val budget = CredentialPolicy.maxConsecutiveAttempts(read)
            assertEquals("forged '$forged' must not raise the wrong-credential budget",
                ProtectionLevel.MAXIMUM.maxConsecutiveAttempts, budget)
            assertTrue("forged '$forged' must not exceed the most lenient budget",
                budget <= ProtectionLevel.MOST_LENIENT_MAX_ATTEMPTS)

            val autoLock = CredentialPolicy.autoLockTimeoutMs(read)
            assertEquals("forged '$forged' must not relax auto-lock",
                ProtectionLevel.MAXIMUM.autoLockTimeoutMs, autoLock)
            assertTrue("forged '$forged' must not exceed the shortest tier auto-lock",
                autoLock <= ProtectionLevel.entries.minOf { it.autoLockTimeoutMs })

            // docs/periodic-reauth-design.md: a fourth enforcement decision sharing
            // this fail-secure destination. "Looser" means DISABLED here (not a
            // larger number) — a forged token must not turn the periodic re-auth OFF.
            assertTrue("forged '$forged' must not disable the periodic re-auth",
                ReauthPolicy.appliesTo(read))
        }

        // No collateral damage: an AUTHENTICATED CASUAL level still gets CASUAL's
        // (lenient) numbers — the fail-secure keys on provenance, not on the token.
        assertTrue(vaultSelector.setProtectionLevel(ProtectionLevel.CASUAL))
        val authentic = vaultSelector.protectionLevelForEnforcement()
        assertEquals(ProtectionLevel.CASUAL, (authentic as ProtectionLevelRead.Present).level)
        assertEquals(ProtectionLevel.CASUAL.inactivityWipeMs,
            InactivityPolicy.thresholdMsOrNull(authentic))
        assertEquals(ProtectionLevel.CASUAL.maxConsecutiveAttempts,
            CredentialPolicy.maxConsecutiveAttempts(authentic))
    }

    /**
     * BRICK-SAFETY, end-to-end through the REAL Android enforcement site. This
     * is the single most important property of the damaged-level handling: Damaged now returns
     * a threshold instead of null, so checkAndWipeIfNeeded no longer early-returns
     * — it runs the full decision. On a vault whose last-active stamp is seconds
     * old that decision must be "not expired", i.e. a damaged tier blob ALONE can
     * never destroy a live vault, and the vault + its data must be untouched.
     *
     * The threshold assertion is the other half: it proves the check SELECTED
     * MAXIMUM's window rather than skipping the check forever.
     */
    @Test
    fun inactivityWipe_damagedLevelBlob_onRecentlyUsedVault_selectsMaximumWindow_andDoesNotWipe() {
        val opened = vaultSelector.unlock(REAL_PIN) as VaultSelector.UnlockResult.Opened
        opened.vault.insertContact(
            ContactRecord("brick-safety-1", FAKE_SECRET, 1, "BrickAlice", 1_700_000_000_000L))
        opened.vault.close()
        // A real unlock is the only thing that stamps the dead-man's clock.
        InactivityWipe.recordUnlock(context, CryptoProvider(context))

        // Tamper: blob-shaped, AEAD-invalid tier value.
        KeyValueStore(context, SELECTOR_PREFS)
            .putString("vlt_lvl", encodeBase64(ByteArray(40) { it.toByte() }))

        val wiped = InactivityWipe.checkAndWipeIfNeeded(context, deviceLocked = false)

        assertFalse("a damaged tier blob must NEVER be a wipe trigger on its own", wiped)
        assertEquals("Damaged must SELECT MAXIMUM's window, not skip the check forever",
            ProtectionLevel.MAXIMUM.inactivityWipeMs, InactivityWipe.thresholdMs)

        // The vault is completely untouched — same PIN, same data.
        val reopened = createVaultSelector().unlock(REAL_PIN)
        assertTrue("the vault must still open after a damaged-tier launch",
            reopened is VaultSelector.UnlockResult.Opened)
        assertNotNull("the contact must survive a damaged-tier launch",
            (reopened as VaultSelector.UnlockResult.Opened).vault.getContact("brick-safety-1"))
    }

    /**
     * Fail-secure end-to-end at the Android enforcement site: planting cleartext `casual`
     * used to stretch the dead-man's switch from 7 days to 180 — the examiner's
     * cheapest way to buy half a year of offline credential work. The window the
     * check actually adopts must be MAXIMUM's.
     */
    @Test
    fun inactivityWipe_forgedCleartextLevel_cannotStretchTheDeadMansWindow() {
        InactivityWipe.recordUnlock(context, CryptoProvider(context))
        KeyValueStore(context, SELECTOR_PREFS).putString("vlt_lvl", "casual")

        val wiped = InactivityWipe.checkAndWipeIfNeeded(context, deviceLocked = false)

        assertFalse("a freshly stamped vault is not expired under any window", wiped)
        assertEquals("an unauthenticated 'casual' must not buy CASUAL's 180-day window",
            ProtectionLevel.MAXIMUM.inactivityWipeMs, InactivityWipe.thresholdMs)
        assertTrue("the forgery must not have widened the dead-man's window at all",
            InactivityWipe.thresholdMs < ProtectionLevel.CASUAL.inactivityWipeMs)
    }

    @Test
    fun credentialMode_damagedBlob_failsOpenToPassphraseEntry_unlockStillWorks() {
        val damaged = encodeBase64(ByteArray(40) { (it + 7).toByte() })
        KeyValueStore(context, SELECTOR_PREFS).putString("vlt_m", damaged)

        // Fail OPEN to the free-text entry: a PIN can be typed in a text field;
        // the digit keypad would hard-lock a passphrase user out entirely.
        assertTrue("damaged mode blob must render the free-text entry",
            vaultSelector.isPassphraseMode())

        // Input-agnostic unlock: the PIN submitted from the text field still opens.
        assertTrue("PIN must still unlock with a damaged mode blob",
            vaultSelector.unlock(REAL_PIN) is VaultSelector.UnlockResult.Opened)
    }

    /**
     * `vlt_m` has the same legacy-cleartext fallback `vlt_lvl`
     * has — and, unlike the tier read, this one discarded the provenance flag
     * entirely. So three ASCII bytes written into vault_selector_prefs.xml (or the
     * iOS NSUserDefaults slot) chose the entry widget. On a MAXIMUM/passphrase vault
     * `pin` renders the 6-digit keypad; Lever A's ≥70-bit floor guarantees the real
     * credential is not six digits, every entry auto-submits and durably counts, and
     * MAXIMUM's budget of 5 fires an emergency wipe — with no recovery code, since
     * that is tied to Lever B / PRIVATE. An UNAUTHENTICATED value must therefore fail
     * OPEN to the free-text field, exactly like the damaged-blob branch.
     */
    @Test
    fun credentialMode_unauthenticatedCleartext_failsOpenToPassphraseEntry() {
        val prefs = KeyValueStore(context, SELECTOR_PREFS)
        prefs.putString("vlt_m", "phrase")
        assertTrue("legacy cleartext 'phrase' must read as passphrase mode",
            vaultSelector.isPassphraseMode())

        // The planted-downgrade case: unauthenticated, so it may not pick the keypad.
        prefs.putString("vlt_m", "pin")
        assertTrue("an unauthenticated 'pin' must NOT render the digit keypad",
            vaultSelector.isPassphraseMode())

        // Input-agnostic unlock: the cost of failing open is a cosmetic mislabel for a
        // genuine legacy PIN install — the credential still opens the vault from the
        // text field. (The keypad, by contrast, hard-locks a passphrase user out.)
        assertTrue("the stored credential must still unlock through the text field",
            vaultSelector.unlock(REAL_PIN) is VaultSelector.UnlockResult.Opened)
    }

    /**
     * Sibling: with the entry UI now on free text for an unauthenticated mode, a
     * rotation must NOT re-persist the untrusted token as an authenticated blob — that
     * would launder a planted `pin` onto a vault whose credential is a passphrase and
     * pin the keypad permanently. The persisted mode is derived from the NEW
     * credential's shape instead (the damaged-mode rule, extended from damaged to untrusted).
     */
    @Test
    fun credentialMode_plantedCleartextPin_healsToPhraseWhenTheNewCredentialIsAPassphrase() {
        val prefs = KeyValueStore(context, SELECTOR_PREFS)
        prefs.putString("vlt_m", "pin")

        val phrase = "runes harbor violet stapler mountain ledger"
        assertEquals(VaultSelector.ChangePinResult.SUCCESS,
            vaultSelector.changeCredential(REAL_PIN, phrase))

        assertTrue("the plant must not survive as an authenticated 'pin'",
            vaultSelector.isPassphraseMode())
        val healed = prefs.getString("vlt_m")
        assertNotNull("vlt_m must be re-written by the rotation", healed)
        assertTrue("healed vlt_m must be an AEAD blob (≥ IV+tag), not cleartext",
            decodeBase64(healed!!).size >= 28)
        assertTrue("the new passphrase must open the vault",
            vaultSelector.unlock(phrase) is VaultSelector.UnlockResult.Opened)
    }

    /** Sibling control: a GENUINE pre-sealed-level cleartext 'pin' install must still rotate
     *  a 6-digit PIN with no entropy floor, healing to an authenticated PIN blob. */
    @Test
    fun credentialMode_legacyCleartextPin_pinRotationStillSucceeds() {
        val prefs = KeyValueStore(context, SELECTOR_PREFS)
        prefs.putString("vlt_m", "pin")

        assertEquals("a 6-digit rotation must not be gated on the passphrase floor",
            VaultSelector.ChangePinResult.SUCCESS,
            vaultSelector.changeCredential(REAL_PIN, NEW_REAL_PIN))

        assertTrue("healed mode must read as PIN again", !vaultSelector.isPassphraseMode())
        val healed = prefs.getString("vlt_m")
        assertNotNull("vlt_m must be re-written by the rotation", healed)
        assertTrue("healed vlt_m must be an AEAD blob, not the cleartext token",
            decodeBase64(healed!!).size >= 28)
        assertTrue("rotated PIN must open the vault",
            vaultSelector.unlock(NEW_REAL_PIN) is VaultSelector.UnlockResult.Opened)
    }

    /** Sibling control: an untrusted 'phrase' token must still hold a 6-digit
     *  "rotation" to the Lever A floor — the fix may only ever tighten it. */
    @Test
    fun credentialMode_unauthenticatedPhrase_stillFloorsAWeakRotation() {
        KeyValueStore(context, SELECTOR_PREFS).putString("vlt_m", "phrase")

        assertEquals("an untrusted passphrase claim must not become a Lever A downgrade path",
            VaultSelector.ChangePinResult.WEAK_CREDENTIAL,
            vaultSelector.changeCredential(REAL_PIN, NEW_REAL_PIN))
        assertTrue("the original credential must still open the vault",
            vaultSelector.unlock(REAL_PIN) is VaultSelector.UnlockResult.Opened)
    }

    /**
     * A mode-preserving rotation with a DAMAGED vlt_m blob must
     * NOT resolve the stored mode through isPassphraseMode()'s fail-open
     * (passphrase) — that held every new 6-digit PIN to the ≥70-bit floor
     * (WEAK_CREDENTIAL → PIN rotation permanently blocked) and, since a
     * mode-preserving change wrote no vlt_m, the damage never self-healed. The
     * resulting mode is instead derived from the NEW credential's shape and
     * vlt_m re-written in the same atomic swap.
     */
    @Test
    fun credentialMode_damagedBlob_pinRotationSucceeds_andHealsModeToPin() {
        val prefs = KeyValueStore(context, SELECTOR_PREFS)
        val damaged = encodeBase64(ByteArray(40) { (it + 3).toByte() })
        prefs.putString("vlt_m", damaged)
        assertTrue("sanity: the entry-UI fail-open reads the damage as passphrase",
            vaultSelector.isPassphraseMode())

        assertEquals("6-digit PIN rotation must not be gated on the passphrase floor",
            VaultSelector.ChangePinResult.SUCCESS,
            vaultSelector.changeCredential(REAL_PIN, NEW_REAL_PIN))

        assertTrue("healed mode must read as PIN", !vaultSelector.isPassphraseMode())
        val healed = prefs.getString("vlt_m")
        assertNotNull("vlt_m must be re-written by the rotation", healed)
        assertTrue("healed vlt_m must replace the damaged blob", healed != damaged)
        assertTrue("healed vlt_m must be an AEAD blob (≥ IV+tag), not cleartext",
            decodeBase64(healed!!).size >= 28)
        assertTrue("rotated PIN must open the vault",
            vaultSelector.unlock(NEW_REAL_PIN) is VaultSelector.UnlockResult.Opened)
    }

    /** Damaged-mode sibling: with a damaged mode blob, a passphrase-SHAPED new credential
     *  derives (and heals to) phrase mode — the entropy floor still applies. */
    @Test
    fun credentialMode_damagedBlob_passphraseRotation_healsModeToPhrase() {
        val prefs = KeyValueStore(context, SELECTOR_PREFS)
        val damaged = encodeBase64(ByteArray(40) { (it + 5).toByte() })
        prefs.putString("vlt_m", damaged)

        val phrase = "runes harbor violet stapler mountain ledger"
        assertEquals(VaultSelector.ChangePinResult.SUCCESS,
            vaultSelector.changeCredential(REAL_PIN, phrase))

        assertTrue("healed mode must read as passphrase", vaultSelector.isPassphraseMode())
        val healed = prefs.getString("vlt_m")
        assertNotNull("vlt_m must be re-written by the rotation", healed)
        assertTrue("healed vlt_m must replace the damaged blob", healed != damaged)
        assertTrue("rotated passphrase must open the vault",
            vaultSelector.unlock(phrase) is VaultSelector.UnlockResult.Opened)
    }

    /** Damaged-mode guard: the entropy floor still bites a weak NON-PIN-shaped credential even
     *  while the mode blob is damaged (the derived mode is phrase → floored). */
    @Test
    fun credentialMode_damagedBlob_weakNonPinCredential_isStillFloored() {
        KeyValueStore(context, SELECTOR_PREFS)
            .putString("vlt_m", encodeBase64(ByteArray(40) { (it + 9).toByte() }))
        assertEquals(VaultSelector.ChangePinResult.WEAK_CREDENTIAL,
            vaultSelector.changeCredential(REAL_PIN, "hello world"))
    }
}

/**
 * A LIVE vault handle whose re-key genuinely lands and then dies — the post-rekey crash
 * point. Everything else delegates to the real [DatabaseManager], so the file is
 * really re-encrypted by real SQLCipher before the throw; `changeCredentialInner`'s
 * defensive catch turns the throw into "the credential change SUCCEEDED, the
 * rotation is unresolved", which is exactly the state a process death leaves.
 */
private class CrashAfterRekeyVault(private val delegate: VaultDatabase) : VaultDatabase by delegate {
    var rekeyed = false
    override fun rekey(newDbKey: ByteArray): Boolean {
        rekeyed = delegate.rekey(newDbKey)
        throw IllegalStateException("simulated process death immediately after the re-key")
    }
}

/**
 * A LIVE vault handle that models `sqlite3_rekey_v2`'s ROLLBACK branch: it reports
 * SQLITE_OK (`true`) while the file is NOT re-keyed, and it RETAINS the new key —
 * which is precisely what the real function does to the codec's WRITE context and
 * never undoes. [applyDeferredRekey] is that retained key finally reaching the file,
 * i.e. the next commit through the poisoned handle.
 *
 * Review 2026-08-03: the rotation now RETIRES (closes) the handle on a
 * probe-reported rollback. [closeThrough] = true (default) lets that close reach
 * the real delegate — the shipped behaviour, under which [applyDeferredRekey] must
 * FAIL; false records the close but defers it, modelling the one window the retire
 * cannot cover — a commit already in flight when the re-key returned.
 *
 * The `copyOf` is load-bearing: `VaultSelector` secureWipe()s the candidate key as
 * soon as the rotation returns, so a retained reference would be all zeroes.
 */
private class RollingBackRekeyVault(
    private val delegate: VaultDatabase,
    private val closeThrough: Boolean = true,
) : VaultDatabase by delegate {
    private var captured: ByteArray? = null
    var closeRequested = false
        private set
    override fun rekey(newDbKey: ByteArray): Boolean {
        captured = newDbKey.copyOf()
        return true   // SQLITE_OK on the rollback branch — the lie the design assumes
    }
    override fun close() {
        closeRequested = true
        if (closeThrough) delegate.close()
    }
    fun applyDeferredRekey(): Boolean = captured?.let { delegate.rekey(it) } ?: false
}

/**
 * Test double for the hardware auth-binding protector. Supports binding without a
 * BiometricPrompt: "ab:" blobs are the auth-bound ones, plain blobs are untagged
 * (matching CryptoProviderDbKeyProtector's legacy form). Flip [invalidated] to
 * simulate the SE/Keystore key dying — ab: unwrap then throws exactly as the real
 * protector does (KeyUnavailableException), while plain blobs still unwrap.
 *
 * [authBoundWriteNoOps] models the OTHER platform failure (a lost auth-bound write): an auth-bound
 * blob that never actually reaches the store — iOS `kvPut` returns WITHOUT writing on a
 * locked keybag — leaving the vault PLAIN where the code believes it committed ab:.
 * Wrapping still round-trips, so only the persisted RESULT differs.
 */
private class FakeAuthBindingProtector : DbKeyProtector {
    var invalidated = false
    var authBoundWriteNoOps = false
    override fun supportsAuthBinding(): Boolean = true
    override fun isAuthBoundBlob(stored: String): Boolean = stored.startsWith("ab:")
    override fun wrap(inner: ByteArray, authBound: Boolean): String {
        val b64 = android.util.Base64.encodeToString(inner, android.util.Base64.NO_WRAP)
        return if (authBound && !authBoundWriteNoOps) "ab:$b64" else b64
    }
    override fun unwrap(stored: String): ByteArray {
        if (stored.startsWith("ab:")) {
            if (invalidated) throw KeyUnavailableException("simulated Lever B key invalidated")
            return android.util.Base64.decode(stored.removePrefix("ab:"), android.util.Base64.NO_WRAP)
        }
        return android.util.Base64.decode(stored, android.util.Base64.NO_WRAP)
    }
}

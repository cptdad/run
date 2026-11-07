package com.vg.run

import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented tests for auto-wipe and inactivity-wipe security features.
 *
 * Run with: ./gradlew connectedAndroidTest
 */
@RunWith(AndroidJUnit4::class)
class SecurityFeaturesTest {

    companion object {
        private const val DB_NAME      = "run.db"
        private const val DB_KEY_PREFS = "db_key_prefs"
        private const val WIPE_PREFS   = "auto_wipe_prefs"

        private const val CONTACT_ID   = "test-contact-001"
    }

    private lateinit var context: Context
    private lateinit var databaseManager: DatabaseManager

    @Before
    fun setUp() {
        context = InstrumentationRegistry.getInstrumentation().targetContext

        // Start each test from a clean slate.
        context.deleteDatabase(DB_NAME)
        context.deleteSharedPreferences(DB_KEY_PREFS)
        context.deleteSharedPreferences(WIPE_PREFS)

        // CR-1: DatabaseManager takes the SQLCipher passphrase directly.
        // isProvision=true: setUp creates a fresh vault DB (deleteDatabase above), so
        // this is the provision open, exempt from the unlock-path empty-vault guard.
        databaseManager = DatabaseManager(context, ByteArray(32) { (it + 1).toByte() }, isProvision = true)

        val now    = System.currentTimeMillis()
        val expiry = now + 86_400_000L

        databaseManager.insertContact(ContactRecord(
            contactId        = CONTACT_ID,
            sharedSecret     = ByteArray(0),
            trustLevel       = 1,
            alias            = "Test Contact",
            aliasLastRotated = now
        ))
        databaseManager.insertInboxId(InboxIdRecord(
            inboxId   = "inbox-test-001",
            contactId = CONTACT_ID,
            createdAt = now,
            expiresAt = expiry,
            direction = "outbound"
        ))
    }

    @After
    fun tearDown() {
        context.deleteDatabase(DB_NAME)
        context.deleteSharedPreferences(DB_KEY_PREFS)
        context.deleteSharedPreferences(WIPE_PREFS)
    }

    // -----------------------------------------------------------------------
    // Test 4 — Vault is null before unlock
    // -----------------------------------------------------------------------

    /**
     * Verifies that VaultSelector does not expose a vault without a valid PIN.
     * This is the underlying security property that the PIN-on-every-open
     * behaviour relies on: if the ViewModel is destroyed (Activity finished),
     * the vault reference is null and no data can be accessed until the user
     * re-enters the correct PIN.
     */
    @Test
    fun vaultSelector_withoutUnlock_returnsNoVault() {
        // This test drives VaultSelector's OWN provision→unlock lifecycle and does
        // not use the setUp-seeded run.db. setUp now provisions that DB
        // (isProvision=true), so clear it (and this test's dedicated selector prefs)
        // first, else setRealCredential() → provisionCredentialAndVault() trips the
        // "a vault database already exists — refusing to provision over it" guard.
        context.deleteDatabase(DB_NAME)
        context.deleteSharedPreferences("vault_selector_prefs_test")

        val store = KeyValueStore(context, "vault_selector_prefs_test")
        val crypto = CryptoProvider(context)
        val cryptoMgr = CryptoManager(context)
        val vaultSelector = VaultSelector(
            store = store,
            crypto = crypto,
            // CR-1: dbKey supplied by VaultSelector (PIN-wrapped).
            vaultFactory = androidVaultFactory(context)
        )

        vaultSelector.setRealCredential("123456")

        // Without calling unlock(), there is no vault.
        // This simulates the state after Activity recreation (finishAndRemoveTask).
        val wrongResult = vaultSelector.unlock("000000")
        assertTrue(
            "Wrong PIN must not produce a vault",
            wrongResult is VaultSelector.UnlockResult.Denied
        )

        // Only the correct PIN opens the vault.
        val correctResult = vaultSelector.unlock("123456")
        assertTrue(
            "Correct PIN must produce a vault",
            correctResult is VaultSelector.UnlockResult.Opened
        )

        context.deleteSharedPreferences("vault_selector_prefs_test")
    }

    // -----------------------------------------------------------------------
    // Test 5 — Inactivity wipe triggers on expired timestamp
    // -----------------------------------------------------------------------

    /**
     * Verifies that InactivityWipe destroys all data when the threshold
     * is exceeded. This test uses a 1-second threshold and records a
     * timestamp 2 seconds in the past to deterministically trigger the wipe.
     */
    @Test
    fun inactivityWipe_thresholdExceeded_wipesAllData() {
        // Set a very short threshold.
        val originalThreshold = InactivityWipe.thresholdMs
        InactivityWipe.thresholdMs = 1_000L

        // Simulate a previous opening 2 seconds ago.
        val prefs = context.getSharedPreferences("inactivity_prefs", Context.MODE_PRIVATE)
        val crypto = CryptoProvider(context)
        val twoSecondsAgo = (System.currentTimeMillis() - 2_000L).toString()
        val encrypted = crypto.encrypt(
            twoSecondsAgo.toByteArray(Charsets.UTF_8),
            "inactivity-wipe-timestamp".toByteArray(Charsets.UTF_8)
        )
        prefs.edit().putString("last_opened_enc", encodeBase64(encrypted)).apply()

        // Verify contacts exist before wipe.
        assertTrue("Contacts must exist before inactivity wipe",
            databaseManager.getAllContacts().isNotEmpty())

        // This should trigger the wipe.
        val wiped = InactivityWipe.checkAndWipeIfNeeded(context)
        assertTrue("Inactivity wipe should have been triggered", wiped)

        // Restore threshold.
        InactivityWipe.thresholdMs = originalThreshold

        // Clean up.
        context.deleteSharedPreferences("inactivity_prefs")
    }

    // -----------------------------------------------------------------------
    // Test 6 — Inactivity wipe does NOT trigger within threshold
    // -----------------------------------------------------------------------

    /**
     * Verifies that InactivityWipe does not destroy data when the app
     * was opened recently (within the threshold window).
     */
    @Test
    fun inactivityWipe_withinThreshold_preservesData() {
        val originalThreshold = InactivityWipe.thresholdMs
        InactivityWipe.thresholdMs = 60_000L  // 60 seconds

        // Seed a recent encrypted timestamp (just now).
        val crypto = CryptoProvider(context)
        val prefs = context.getSharedPreferences("inactivity_prefs", Context.MODE_PRIVATE)
        val now = System.currentTimeMillis().toString()
        val encrypted = crypto.encrypt(
            now.toByteArray(Charsets.UTF_8),
            "inactivity-wipe-timestamp".toByteArray(Charsets.UTF_8)
        )
        prefs.edit().putString("last_opened_enc", encodeBase64(encrypted)).apply()

        // Check — should not wipe because the timestamp is recent.
        val wiped = InactivityWipe.checkAndWipeIfNeeded(context)
        assertTrue("Check within threshold should not wipe", !wiped)

        // Data must still be present.
        assertTrue("Contacts must be preserved within inactivity threshold",
            databaseManager.getAllContacts().isNotEmpty())

        InactivityWipe.thresholdMs = originalThreshold
        context.deleteSharedPreferences("inactivity_prefs")
    }
}

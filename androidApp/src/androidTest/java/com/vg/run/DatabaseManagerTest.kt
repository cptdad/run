package com.vg.run

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented tests for DatabaseManager.
 *
 * These tests must run on a real device or emulator because:
 *   1. SQLCipher loads native (.so) libraries that are not available in the JVM.
 *   2. DatabaseManager relies on CryptoManager, which uses the Android Keystore.
 *
 * Each test starts with a clean database: [setUp] deletes any leftover database
 * file and SharedPreferences from prior runs so tests are fully independent.
 *
 * Run with: ./gradlew connectedAndroidTest
 */
@RunWith(AndroidJUnit4::class)
class DatabaseManagerTest {

    private lateinit var context: android.content.Context
    private lateinit var cryptoManager: CryptoManager
    private lateinit var databaseManager: DatabaseManager

    companion object {
        // Must match the private constants in DatabaseManager.
        private const val DATABASE_NAME   = "run.db"
        private const val DB_KEY_PREFS    = "db_key_prefs"

        // CR-1: DatabaseManager now takes the SQLCipher passphrase directly
        // (VaultSelector owns PIN-wrapping). A fixed key keeps the reopen
        // test deterministic.
        private val TEST_DB_KEY = ByteArray(32) { (it + 1).toByte() }

        // Stable fake values reused across tests.
        private val FAKE_SHARED_SECRET     = "fake-encrypted-secret".toByteArray(Charsets.UTF_8)
    }

    @Before
    fun setUp() {
        context = InstrumentationRegistry.getInstrumentation().targetContext

        // --- Isolation: delete all persistent state before each test ---
        // Deleting the database file ensures every test starts with an empty schema.
        context.deleteDatabase(DATABASE_NAME)
        // Deleting the SharedPreferences that hold the encrypted db password forces
        // DatabaseManager to generate a fresh key, consistent with the fresh db file.
        context.deleteSharedPreferences(DB_KEY_PREFS)

        cryptoManager   = CryptoManager(context)
        // isProvision=true: setUp CREATES a fresh vault DB (deleteDatabase above),
        // so this is the provision open — the unlock-path fail-closed guard
        // (DatabaseManager.kt "refusing to open an empty vault")
        // is for reopening an existing vault, exercised by the reopen tests below.
        databaseManager = DatabaseManager(context, TEST_DB_KEY, isProvision = true)
    }

    @After
    fun tearDown() {
        // Clean up after each test so leftover state cannot leak into later tests.
        context.deleteDatabase(DATABASE_NAME)
        context.deleteSharedPreferences(DB_KEY_PREFS)
    }

    // -----------------------------------------------------------------------
    // Helper builders — keep test bodies focused on assertions
    // -----------------------------------------------------------------------

    private fun makeContact(
        contactId: String        = "contact-001",
        sharedSecret: ByteArray  = FAKE_SHARED_SECRET,
        trustLevel: Int          = 2,
        alias: String            = "Alice",
        aliasLastRotated: Long   = 1_700_000_000_000L
    ) = ContactRecord(contactId, sharedSecret, trustLevel, alias, aliasLastRotated)

    // -----------------------------------------------------------------------
    // Test 1 — Insert and retrieve a contact
    // -----------------------------------------------------------------------

    /**
     * Verifies that a ContactRecord survives a round-trip through the database
     * with every field intact — including the sharedSecret BLOB.
     *
     * Why it matters: a corrupt or truncated sharedSecret would make it
     * impossible to decrypt future messages from that contact. Field-level
     * verification catches schema mismatches or incorrect column bindings early.
     */
    @Test
    fun insertContact_thenRetrieve_returnsMatchingRecord() {
        val contact = makeContact()
        databaseManager.insertContact(contact)

        val retrieved = databaseManager.getContact(contact.contactId)

        assertNotNull("Contact should be found after insertion", retrieved)
        retrieved!! // smart-cast

        assertEquals("contactId mismatch",        contact.contactId,        retrieved.contactId)
        assertArrayEquals("sharedSecret mismatch", contact.sharedSecret,     retrieved.sharedSecret)
        assertEquals("trustLevel mismatch",        contact.trustLevel,       retrieved.trustLevel)
        assertEquals("alias mismatch",             contact.alias,            retrieved.alias)
        assertEquals("aliasLastRotated mismatch",  contact.aliasLastRotated, retrieved.aliasLastRotated)
    }

    // -----------------------------------------------------------------------
    // Test 4 — Database persistence across instances
    // -----------------------------------------------------------------------

    /**
     * Inserts a contact via one DatabaseManager instance, then creates a second
     * instance (simulating an app restart) and verifies the contact is still
     * present and unchanged.
     *
     * Why it matters: persistence is the foundational guarantee of a local store.
     * For a secure messenger this also confirms that the key derivation path
     * (CryptoManager → encrypted db password → SQLCipher) is deterministic:
     * if the stored key were lost or regenerated, the database would be
     * permanently inaccessible.
     */
    @Test
    fun insertContact_thenReopenDatabase_contactStillPresent() {
        val contact = makeContact(contactId = "contact-persist")
        databaseManager.insertContact(contact)

        // Simulate an app restart by constructing a fresh DatabaseManager.
        // It reads the encrypted db password from SharedPreferences and reopens
        // the same on-disk database file — no data should be lost.
        val secondInstance = DatabaseManager(context, TEST_DB_KEY)
        val retrieved = secondInstance.getContact(contact.contactId)

        assertNotNull("Contact must survive a DatabaseManager restart", retrieved)
        retrieved!!

        assertEquals("contactId must match after reopen",        contact.contactId,        retrieved.contactId)
        assertArrayEquals("sharedSecret must match after reopen", contact.sharedSecret,     retrieved.sharedSecret)
        assertEquals("alias must match after reopen",            contact.alias,            retrieved.alias)
        assertEquals("trustLevel must match after reopen",       contact.trustLevel,       retrieved.trustLevel)
        assertEquals("aliasLastRotated must match after reopen", contact.aliasLastRotated, retrieved.aliasLastRotated)
    }

    /**
     * Requirement (2026-05-17): contacts must persist across ordinary
     * version updates. An in-scope ("same-schema") update is an APK swap
     * with the DB key and DATABASE_VERSION unchanged — i.e. exactly a new
     * DatabaseManager opening the existing file in a new process. This
     * verifies the *full* contact set survives, with every field intact,
     * across repeated reopens (multiple sequential updates), not just a
     * single contact / single restart.
     *
     * Guards against a routine release silently dropping contacts (e.g. a
     * future onCreate/onUpgrade regression or a wipe-on-launch slip).
     */
    @Test
    fun allContactsSurviveSimulatedVersionUpdates() {
        val contacts = listOf(
            makeContact(contactId = "c-1", alias = "Alice",   trustLevel = 2),
            makeContact(contactId = "c-2", alias = "Bob",     trustLevel = 0,
                sharedSecret = "secret-2".toByteArray(Charsets.UTF_8)),
            makeContact(contactId = "c-3", alias = "Carol",   trustLevel = 1,
                sharedSecret = "secret-3".toByteArray(Charsets.UTF_8),
                aliasLastRotated = 1_711_111_111_111L),
        )
        contacts.forEach { databaseManager.insertContact(it) }

        // Three sequential "app updates": each new DatabaseManager over the
        // same file + key + schema must still see every contact unchanged.
        repeat(3) { update ->
            val reopened = DatabaseManager(context, TEST_DB_KEY)
            contacts.forEach { original ->
                val got = reopened.getContact(original.contactId)
                assertNotNull("contact ${original.contactId} lost after update #$update", got)
                got!!
                assertEquals(original.contactId, got.contactId)
                assertArrayEquals("sharedSecret changed for ${original.contactId}",
                    original.sharedSecret, got.sharedSecret)
                assertEquals(original.alias, got.alias)
                assertEquals(original.trustLevel, got.trustLevel)
                assertEquals(original.aliasLastRotated, got.aliasLastRotated)
            }
            reopened.close()
        }
    }

    // -----------------------------------------------------------------------
    // Test 5 — Database file exists on disk
    // -----------------------------------------------------------------------

    /**
     * Verifies that after DatabaseManager is initialised the encrypted database
     * file actually exists on the device's filesystem.
     *
     * Why it matters: SQLCipher encrypts the database *file*. If the file were
     * somehow created in memory only (e.g. in-memory SQLite mode), the encryption
     * guarantees would vanish on process death. This test confirms the file is
     * present at the expected path, meaning data is persisted and protected at
     * rest by SQLCipher's AES-256 encryption.
     */
    @Test
    fun databaseFile_existsOnDisk_afterInitialisation() {
        val dbFile = context.getDatabasePath(DATABASE_NAME)

        assertTrue(
            "Database file should exist at ${dbFile.absolutePath} after DatabaseManager init",
            dbFile.exists()
        )
        assertTrue(
            "Database file should not be empty",
            dbFile.length() > 0
        )
    }

    // -----------------------------------------------------------------------
    // Bonus — Query for non-existent contact returns null
    // -----------------------------------------------------------------------

    /**
     * Verifies that querying an unknown contactId returns null rather than
     * throwing or returning a default object.
     *
     * Why it matters: returning a default ContactRecord with an empty sharedSecret
     * instead of null could lead callers to silently use a zero key for decryption,
     * a subtle but catastrophic security failure.
     */
    @Test
    fun getContact_withUnknownId_returnsNull() {
        assertNull(
            "Querying an unknown contactId must return null, not a default record",
            databaseManager.getContact("does-not-exist")
        )
    }

    // -----------------------------------------------------------------------
    // Generic key/value (`_meta`) — backs the Double Ratchet markers. Exercised
    // against REAL SQLCipher here because commonTest only has the in-memory fake.
    // -----------------------------------------------------------------------

    @Test
    fun meta_putThenGet_roundTrips() {
        assertNull("absent key must read null", databaseManager.getMeta("dr-intent/c1"))
        databaseManager.putMeta("dr-intent/c1", "1")
        assertEquals("1", databaseManager.getMeta("dr-intent/c1"))
    }

    @Test
    fun meta_put_overwritesExistingKey() {
        databaseManager.putMeta("dr-on/c1", "1")
        databaseManager.putMeta("dr-on/c1", "2")
        assertEquals("overwrite must replace, not duplicate", "2", databaseManager.getMeta("dr-on/c1"))
    }

    @Test
    fun meta_delete_removesKey() {
        databaseManager.putMeta("dr-rxseen/c1", "1")
        assertEquals("1", databaseManager.getMeta("dr-rxseen/c1"))
        databaseManager.deleteMeta("dr-rxseen/c1")
        assertNull(databaseManager.getMeta("dr-rxseen/c1"))
    }

    @Test
    fun meta_survivesReopen() {
        databaseManager.putMeta("dr-intent/c2", "1")
        databaseManager.close()
        databaseManager = DatabaseManager(context, TEST_DB_KEY)
        assertEquals("marker must persist across reopen", "1", databaseManager.getMeta("dr-intent/c2"))
    }

    // -----------------------------------------------------------------------
    // Inbox rows must not hard-expire 365 days after pairing.
    //
    // These run against the REAL SQL (the commonTest double can only model it):
    // getInboxIdForContact used to carry `expires_at > now`, so a healthy,
    // actively-polled pairing went dark on day 366 — poll/peek/send/push all
    // resolved to "no inbox" without a packet leaving the device, while the relay
    // (sliding TTL) still held the inbox and the peer's messages piled up.
    // -----------------------------------------------------------------------

    private fun inboxRow(
        inboxId: String,
        contactId: String = "contact-001",
        createdAt: Long,
        expiresAt: Long,
        direction: String = "inbound",
        cap: String? = "R".repeat(43),
    ) = InboxIdRecord(inboxId, contactId, createdAt, expiresAt, direction, cap)

    @Test
    fun getInboxIdForContact_returnsARowPastItsExpiry() {
        val created = System.currentTimeMillis() - 400L * 24 * 60 * 60 * 1000
        databaseManager.insertInboxId(inboxRow(
            "LEASEinbound00000000000000000001",
            createdAt = created,
            expiresAt = created + VaultSeedDefaults.INBOX_LIFETIME_MS,   // ~35 days ago
        ))

        val row = databaseManager.getInboxIdForContact("contact-001", "inbound")
        assertNotNull("a 400-day-old pairing must still resolve its inbox", row)
        assertEquals("LEASEinbound00000000000000000001", row!!.inboxId)
    }

    @Test
    fun getInboxIdForContact_picksTheNewestRow_evenWhenItIsTheExpiredOne() {
        // A peer's in-band announce inserts a NEW primary key and leaves the old row
        // behind, so recency is live routing, not a tie-break.
        val now = System.currentTimeMillis()
        databaseManager.insertInboxId(inboxRow(
            "OLDoutbound000000000000000000001",
            createdAt = now - 800L * 24 * 60 * 60 * 1000,
            expiresAt = Long.MAX_VALUE, direction = "outbound",
        ))
        databaseManager.insertInboxId(inboxRow(
            "LEASEoutbound0000000000000000001",
            createdAt = now - 400L * 24 * 60 * 60 * 1000,
            expiresAt = now - 35L * 24 * 60 * 60 * 1000, direction = "outbound",
        ))

        assertEquals(
            "LEASEoutbound0000000000000000001",
            databaseManager.getInboxIdForContact("contact-001", "outbound")!!.inboxId,
        )
    }

    @Test
    fun getInboxId_stillSeesAnExpiredRow_soTheOwnershipGateStillBlocks() {
        // The PK lookup behind the ownership gate was never expiry-filtered and
        // must stay that way: the row still occupies the key and would still be
        // silently overwritten by INSERT-OR-REPLACE.
        databaseManager.insertInboxId(inboxRow(
            "LEASEinbound00000000000000000001", createdAt = 1L, expiresAt = 2L,
        ))
        assertNotNull(databaseManager.getInboxId("LEASEinbound00000000000000000001"))
    }

    @Test
    fun touchInboxExpiry_movesTheStampForwardOnly_andNeverInserts() {
        databaseManager.insertInboxId(inboxRow(
            "LEASEinbound00000000000000000001", createdAt = 1L, expiresAt = 10_000L,
        ))

        databaseManager.touchInboxExpiry("LEASEinbound00000000000000000001", 5_000L)
        assertEquals("must never walk the stamp backward", 10_000L,
            databaseManager.getInboxId("LEASEinbound00000000000000000001")!!.expiresAt)

        databaseManager.touchInboxExpiry("LEASEinbound00000000000000000001", 20_000L)
        val bumped = databaseManager.getInboxId("LEASEinbound00000000000000000001")!!
        assertEquals(20_000L, bumped.expiresAt)
        assertEquals("the re-stamp must not disturb the capability", "R".repeat(43), bumped.cap)

        // A row that no longer exists must not be re-created (T2/A1 non-resurrection).
        databaseManager.touchInboxExpiry("ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ", 30_000L)
        assertNull(databaseManager.getInboxId("ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"))
    }

    // -----------------------------------------------------------------------
    // Re-key primitives — VaultDatabase.rekey + VaultFactory.probeKey.
    //
    // These MUST run against real SQLCipher: the whole point of the pair is that
    // `rekey`'s return value is not proof (sqlite3_rekey_v2 returns SQLITE_OK on
    // both its commit and its rollback branch), so only opening the file with a
    // candidate key says anything. A JVM/in-memory double cannot model that.
    //
    // Both are wired into VaultSelector's credential-tier-upgrade rotation; the
    // end-to-end behaviour lives in VaultSelectorTest, this is the contract.
    // -----------------------------------------------------------------------

    /** A second, unrelated 32-byte key. Deliberately not derived from TEST_DB_KEY. */
    private val REKEYED_DB_KEY = ByteArray(32) { (0xA0 + it).toByte() }

    @Test
    fun rekey_reEncryptsTheVault_newKeyOpensIt_oldKeyDoesNot() {
        val contact = makeContact(contactId = "contact-rekey", alias = "Rekeyed")
        databaseManager.insertContact(contact)
        databaseManager.putMeta("dr-intent/contact-rekey", "1")

        assertTrue("rekey must report no visible error", databaseManager.rekey(REKEYED_DB_KEY))
        databaseManager.close()

        // Proof, not the return value: the file opens under the NEW key and the
        // row is intact (so the whole DB really was re-encrypted, not truncated).
        val reopened = DatabaseManager(context, REKEYED_DB_KEY)
        val got = reopened.getContact("contact-rekey")
        assertNotNull("the re-keyed vault must still hold its rows", got)
        got!!
        assertArrayEquals("sharedSecret must survive the re-key", contact.sharedSecret, got.sharedSecret)
        assertEquals("Rekeyed", got.alias)
        assertEquals("_meta must survive the re-key", "1", reopened.getMeta("dr-intent/contact-rekey"))
        reopened.close()

        // The OLD key must no longer open the file. isProvision defaults to false,
        // so this must FAIL CLOSED (throw) and must NOT delete-and-recreate.
        try {
            DatabaseManager(context, TEST_DB_KEY).close()
            fail("the old key must not open a re-keyed vault")
        } catch (_: Throwable) {
            // expected
        }

        // …and that failed open left the vault intact.
        assertTrue("the vault file must survive a wrong-key open",
            context.getDatabasePath(DATABASE_NAME).exists())
        val again = DatabaseManager(context, REKEYED_DB_KEY)
        assertNotNull("the vault must still open under the new key", again.getContact("contact-rekey"))
        again.close()
    }

    @Test
    fun probeKey_acceptsTheRealKey_rejectsGarbage_andNeverDamagesTheFile() {
        databaseManager.insertContact(makeContact(contactId = "contact-probe"))
        databaseManager.close()

        val factory = androidVaultFactory(context)
        assertTrue("the real key must probe true", factory.probeKey(TEST_DB_KEY))

        // Baseline taken AFTER a successful probe, so what follows measures the
        // FAILED probes specifically (a successful open legitimately applies the
        // same journal-mode pragma the app's own open applies).
        val sizeBefore = context.getDatabasePath(DATABASE_NAME).length()

        // A garbage key must answer false — never throw, never delete.
        assertFalse("a garbage key must probe false", factory.probeKey(ByteArray(32) { 0x7F }))
        // A wrong key of a different LENGTH takes the same PBKDF2 branch; still false.
        assertFalse("a short garbage key must probe false", factory.probeKey(ByteArray(16)))

        assertTrue("a failed probe must leave the vault file in place",
            context.getDatabasePath(DATABASE_NAME).exists())
        assertEquals("a failed probe must not truncate or rewrite the vault",
            sizeBefore, context.getDatabasePath(DATABASE_NAME).length())

        // Still openable, and its data is still there.
        assertTrue("the real key must still probe true after a failed probe",
            factory.probeKey(TEST_DB_KEY))
        val reopened = DatabaseManager(context, TEST_DB_KEY)
        assertNotNull("the vault must still hold its rows after a failed probe",
            reopened.getContact("contact-probe"))
        reopened.close()
    }

    @Test
    fun probeKey_afterRekey_followsTheFile_notTheOldKey() {
        databaseManager.insertContact(makeContact(contactId = "contact-probe-rekey"))
        assertTrue(databaseManager.rekey(REKEYED_DB_KEY))
        databaseManager.close()

        val factory = androidVaultFactory(context)
        assertTrue("probe must follow the file onto the new key",
            factory.probeKey(REKEYED_DB_KEY))
        assertFalse("the superseded key must probe false",
            factory.probeKey(TEST_DB_KEY))
    }

    @Test
    fun probeKey_withNoVaultFile_isFalse_andProvisionsNothing() {
        databaseManager.close()
        context.deleteDatabase(DATABASE_NAME)

        val factory = androidVaultFactory(context)
        assertFalse("a missing vault must probe false", factory.probeKey(TEST_DB_KEY))
        assertFalse("the probe must never CREATE the vault it was asked about",
            context.getDatabasePath(DATABASE_NAME).exists())
    }

    @Test
    fun probeKey_withATruncatedVaultStub_isFalse_andLeavesTheStubAlone() {
        // #28 shape: a present-but-tiny run.db (an examiner truncating instead of
        // deleting). It must read as "no", exactly like the unlock guard treats it,
        // and the probe must not delete it — an unexplained file is evidence.
        databaseManager.close()
        context.deleteDatabase(DATABASE_NAME)
        val dbFile = context.getDatabasePath(DATABASE_NAME)
        dbFile.parentFile?.mkdirs()
        dbFile.writeBytes(ByteArray(64) { 0x11 })

        assertFalse("a truncated stub must probe false",
            androidVaultFactory(context).probeKey(TEST_DB_KEY))
        assertTrue("the probe must not delete the stub", dbFile.exists())
        assertEquals(64L, dbFile.length())
    }
}

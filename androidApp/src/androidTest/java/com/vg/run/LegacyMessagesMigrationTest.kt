package com.vg.run

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import net.zetetic.database.sqlcipher.SQLiteDatabase
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
 * Schema v8 → v9 (2026-09-15): a vault that still carries the legacy `Messages`
 * table must open at v9 with the table GONE, its pages reclaimed, and everything
 * else untouched.
 *
 * Why this needs a real fixture rather than review: until a933616e (2026-05-24)
 * both platforms INSERTed every message into that table. The commit that stopped
 * writing left the table behind, so a vault provisioned before that date and never
 * wiped still holds years of message rows — encrypted, but under a key one
 * compelled PIN recovers. The migration is the only thing that removes them, it
 * runs exactly once per vault, and it runs on the unlock path, where a throw is a
 * user locked out of their data. Both halves are asserted here:
 *
 *  - the drop actually happens on a real v8 file (not just that the code compiles);
 *  - the contact rows beside it survive, because this migration runs on vaults full
 *    of real data and "existing vaults must still unlock" outranks the cleanup.
 *
 * Instrumented because SQLCipher is a native library with no JVM equivalent. The
 * source-level "no message table anywhere, on either platform" guard is the JVM
 * `LegacyMessageTableRemovalTest` (shared/androidUnitTest).
 *
 * Run with: ./gradlew connectedAndroidTest — or, to preserve device state,
 * `am instrument` targeting this class.
 */
@RunWith(AndroidJUnit4::class)
class LegacyMessagesMigrationTest {

    private lateinit var context: android.content.Context

    private companion object {
        const val DATABASE_NAME = "run.db"

        /** DatabaseManager.DATABASE_VERSION is internal to :shared; pinned literally. */
        const val EXPECTED_SCHEMA_VERSION = 10L   // 07c7bf9d (2026-09-27) bumped DATABASE_VERSION to 10

        /** Deliberately not the key any other test uses. */
        val TEST_DB_KEY = ByteArray(32) { (it + 11).toByte() }
    }

    @Before
    fun setUp() {
        System.loadLibrary("sqlcipher")
        context = InstrumentationRegistry.getInstrumentation().targetContext
        context.deleteDatabase(DATABASE_NAME)
    }

    @After
    fun tearDown() {
        context.deleteDatabase(DATABASE_NAME)
    }

    // -----------------------------------------------------------------------
    // The migration
    // -----------------------------------------------------------------------

    @Test
    fun aV8VaultHoldingMessageRows_opensAtV9WithTheTableDroppedAndItsPagesReclaimed() {
        seedV8Vault(messageRows = 200)

        // The fixture really is the pre-migration shape — otherwise this test would
        // pass against a vault that never had the table.
        withRawDb { db ->
            assertEquals("fixture must be a v8 vault", 8L, userVersion(db))
            assertTrue("fixture must carry the legacy table", tableExists(db, "Messages"))
            assertEquals(200L, rowCount(db, "Messages"))
        }

        // The upgrade: exactly what an unlock does after the app update.
        val vault = DatabaseManager(context, TEST_DB_KEY)
        try {
            // Existing vaults must still unlock — with their data.
            val kept = vault.getContact("c-1")
            assertNotNull("the migration must not disturb the contact rows", kept)
            assertEquals("Alice", kept!!.alias)
            assertEquals("meta must survive the migration", "1", vault.getMeta("dr-on/c-1"))
        } finally {
            vault.close()
        }

        withRawDb { db ->
            assertEquals("the schema must be stamped v9", EXPECTED_SCHEMA_VERSION, userVersion(db))
            assertFalse(
                "the legacy Messages table must be GONE after the v8 → v9 upgrade",
                tableExists(db, "Messages"),
            )
            assertEquals(
                "the VACUUM must have run: freed message pages belong to the OS, not the " +
                    "freelist (secure_delete zeroed them at free time; VACUUM returns them)",
                0L,
                freelistCount(db),
            )
        }
    }

    @Test
    fun theUpgradeIsOneShot_andASecondOpenChangesNothing() {
        seedV8Vault(messageRows = 3)

        DatabaseManager(context, TEST_DB_KEY).close()
        DatabaseManager(context, TEST_DB_KEY).let { second ->
            assertNotNull("the vault must still open on every later launch", second.getContact("c-1"))
            second.close()
        }

        withRawDb { db ->
            assertFalse(tableExists(db, "Messages"))
            assertEquals(EXPECTED_SCHEMA_VERSION, userVersion(db))
        }
    }

    @Test
    fun aFreshlyProvisionedVaultNeverHasAMessageTable() {
        DatabaseManager(context, TEST_DB_KEY, isProvision = true).close()

        withRawDb { db ->
            assertFalse(
                "a fresh vault must not even have somewhere to put messages",
                tableExists(db, "Messages"),
            )
            assertEquals(EXPECTED_SCHEMA_VERSION, userVersion(db))
        }
    }

    @Test
    fun deletingAContactStillClearsEverythingItOwned() {
        // The delete path lost one statement with the table; the rest must be intact.
        seedV8Vault(messageRows = 5)
        val vault = DatabaseManager(context, TEST_DB_KEY)
        try {
            vault.deleteContact("c-1")
            assertNull("the contact row must be gone", vault.getContact("c-1"))
            assertNull("its ratchet meta must be gone", vault.getMeta("dr-on/c-1"))
        } finally {
            vault.close()
        }
    }

    // -----------------------------------------------------------------------
    // Fixture — a pre-2026-05-24 vault, written the way that build wrote it
    // -----------------------------------------------------------------------

    /**
     * Builds a real SQLCipher vault at exactly schema v8: the v8 table set (including
     * `Messages`, populated), `user_version = 8`, keyed with the same RAW BYTES the
     * app keys with, so `DatabaseManager`'s own open — and its onUpgrade — treats it
     * as the vault it is.
     */
    private fun seedV8Vault(messageRows: Int) {
        val dbFile = context.getDatabasePath(DATABASE_NAME)
        dbFile.parentFile?.mkdirs()
        val db = SQLiteDatabase.openOrCreateDatabase(dbFile.absolutePath, TEST_DB_KEY, null, null)
        try {
            db.execSQL(
                "CREATE TABLE Contacts (" +
                    "contactId TEXT PRIMARY KEY NOT NULL, sharedSecret BLOB NOT NULL, " +
                    "trustLevel INTEGER NOT NULL DEFAULT 0, alias TEXT NOT NULL, " +
                    "aliasLastRotated INTEGER NOT NULL, mnemonic TEXT NOT NULL DEFAULT '', " +
                    "outboundCounter INTEGER NOT NULL DEFAULT 0, inboundCounter INTEGER NOT NULL DEFAULT 0, " +
                    "inboundEpoch TEXT NOT NULL DEFAULT '', outboundCtlCounter INTEGER NOT NULL DEFAULT 0, " +
                    "inboundCtlCounter INTEGER NOT NULL DEFAULT 0, vouchedByContactId TEXT, " +
                    "vouchedAt INTEGER NOT NULL DEFAULT 0)"
            )
            db.execSQL(
                "CREATE TABLE InboxIds (inboxId TEXT PRIMARY KEY NOT NULL, contactId TEXT NOT NULL, " +
                    "createdAt INTEGER NOT NULL, expiresAt INTEGER NOT NULL, " +
                    "direction TEXT NOT NULL DEFAULT 'outbound', cap TEXT)"
            )
            // The table this whole test is about, exactly as v8 created it.
            db.execSQL(
                "CREATE TABLE Messages (messageId TEXT PRIMARY KEY NOT NULL, contactId TEXT NOT NULL, " +
                    "encryptedContent BLOB NOT NULL, timestamp INTEGER NOT NULL, " +
                    "isRead INTEGER NOT NULL DEFAULT 0)"
            )
            db.execSQL(
                "CREATE TABLE IF NOT EXISTS ContactGroups (groupId TEXT PRIMARY KEY NOT NULL, " +
                    "name TEXT NOT NULL, epoch INTEGER NOT NULL DEFAULT 1, adminMemberId TEXT NOT NULL, " +
                    "myMemberId TEXT NOT NULL, createdAt INTEGER NOT NULL)"
            )
            db.execSQL(
                "CREATE TABLE IF NOT EXISTS GroupMembers (groupId TEXT NOT NULL, memberId TEXT NOT NULL, " +
                    "contactId TEXT, addedAt INTEGER NOT NULL, tags TEXT NOT NULL DEFAULT '', " +
                    "PRIMARY KEY (groupId, memberId))"
            )
            db.execSQL("CREATE TABLE IF NOT EXISTS _meta (key TEXT PRIMARY KEY, value TEXT)")

            db.execSQL(
                "INSERT INTO Contacts (contactId, sharedSecret, trustLevel, alias, aliasLastRotated) " +
                    "VALUES (?, ?, ?, ?, ?)",
                arrayOf<Any>("c-1", ByteArray(32) { 0x42.toByte() }, 2, "Alice", 1_700_000_000_000L),
            )
            db.execSQL("INSERT INTO _meta (key, value) VALUES ('dr-on/c-1', '1')")
            for (i in 0 until messageRows) {
                db.execSQL(
                    "INSERT INTO Messages (messageId, contactId, encryptedContent, timestamp, isRead) " +
                        "VALUES (?, ?, ?, ?, 0)",
                    arrayOf<Any>("m-$i", "c-1", ByteArray(512) { (i and 0xFF).toByte() }, i.toLong()),
                )
            }
            db.execSQL("PRAGMA user_version = 8")
        } finally {
            db.close()
        }

        // Fixture self-check, on a FRESH handle and through the same helpers the
        // assertions use. Every test in this class asserts the table is GONE
        // afterwards, and an assertFalse over a table that was never there is a
        // vacuous pass — which is exactly what this class did while [tableExists]
        // was silently answering false for everything. Failing here makes a broken
        // fixture (or a broken helper) loud in every seeded test instead of
        // quietly blessing the migration.
        withRawDb { db ->
            check(tableExists(db, "Messages")) {
                "fixture is not a v8 vault: the legacy Messages table was not created"
            }
            check(rowCount(db, "Messages") == messageRows.toLong()) {
                "fixture did not seed its $messageRows message rows"
            }
            check(userVersion(db) == 8L) { "fixture is not stamped user_version 8" }
        }
    }

    // -----------------------------------------------------------------------
    // Raw inspection helpers — the app's own API deliberately exposes none of this
    // -----------------------------------------------------------------------

    private fun withRawDb(block: (SQLiteDatabase) -> Unit) {
        val db = SQLiteDatabase.openOrCreateDatabase(
            context.getDatabasePath(DATABASE_NAME).absolutePath, TEST_DB_KEY, null, null
        )
        try {
            block(db)
        } finally {
            db.close()
        }
    }

    private fun userVersion(db: SQLiteDatabase): Long =
        db.rawQuery("PRAGMA user_version", null).use { if (it.moveToFirst()) it.getLong(0) else -1L }

    private fun freelistCount(db: SQLiteDatabase): Long =
        db.rawQuery("PRAGMA freelist_count", null).use { if (it.moveToFirst()) it.getLong(0) else -1L }

    /**
     * `arrayOf(name)` — an `Array<String>` — on purpose, and NOT `arrayOf<Any>(…)`.
     *
     * SQLCipher's [SQLiteDatabase] overloads this as both `rawQuery(String,
     * String[])` and `rawQuery(String, Object...)`. An `Array<Any>` does not match
     * the first, so Kotlin binds the second as a VARARG and (no spread operator)
     * passes the whole array as ONE element: SQLCipher then binds parameter 1 to
     * `Object.toString()` — the literal text `[Ljava.lang.Object;@f7b16ae` — and
     * leaves the rest NULL. The query silently matched nothing, so this helper
     * answered `false` for a table that was right there in `sqlite_master`
     * (verified on a Pixel 7: same statement, `Array<String>` → 1, `Array<Any>` → 0).
     * That turned the one `assertTrue` here into the red, and every `assertFalse`
     * below into a VACUOUS pass. `Array<String>` matches the non-vararg overload
     * exactly, which binds each argument as a string.
     */
    private fun tableExists(db: SQLiteDatabase, name: String): Boolean =
        db.rawQuery(
            "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?",
            arrayOf(name),
        ).use { it.moveToFirst() && it.getLong(0) > 0L }

    private fun rowCount(db: SQLiteDatabase, table: String): Long =
        db.rawQuery("SELECT count(*) FROM $table", null).use { if (it.moveToFirst()) it.getLong(0) else -1L }
}

package com.vg.run

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import net.zetetic.database.sqlcipher.SQLiteDatabase
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Schema v9 → v10 (2026-09-24): a REAL v9 SQLCipher vault must open at v10 with
 * the two group-channel counter columns added, every contact / inbox row / `_meta`
 * row intact, and the new columns reading 0.
 *
 * Why a real fixture rather than review: the columns back
 * `ContactRecord.outboundGrpCounter` / `inboundGrpCounter`, the anti-replay counter
 * space of the third pairwise inbox. Both failure modes are silent:
 *
 *  - a MISSING `ALTER` makes `getColumnIndexOrThrow` throw on the first contact
 *    read of the first unlock after the update — i.e. a user locked out of a vault
 *    full of real data, which is the one outcome that outranks every feature;
 *  - a missing DEFAULT (or a non-additive rebuild) loses contacts.
 *
 * "Existing vaults must still unlock, with their data" is asserted directly: the
 * v9 fixture carries a contact, both older inbox directions and a `_meta` row, and
 * all of them are read back through the app's own API after the upgrade.
 *
 * Instrumented because SQLCipher is a native library with no JVM equivalent. The
 * source-level "both actuals carry the columns" guard is the JVM
 * `GroupCounterSchemaPinTest` (shared/androidUnitTest); the codec/move halves are
 * `MigrationBundleTest` / `VaultSnapshotIoTest` (commonTest).
 *
 * Run with: ./gradlew connectedAndroidTest — or, to preserve device state,
 * `am instrument` targeting this class.
 */
@RunWith(AndroidJUnit4::class)
class LegacyContactsMigrationTest {

    private lateinit var context: android.content.Context

    private companion object {
        const val DATABASE_NAME = "run.db"

        /** DatabaseManager.DATABASE_VERSION is internal to :shared; pinned literally. */
        const val EXPECTED_SCHEMA_VERSION = 10L

        /** Deliberately not the key any other test uses. */
        val TEST_DB_KEY = ByteArray(32) { (it + 29).toByte() }
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

    @Test
    fun aV9Vault_opensAtV10WithTheGroupCountersAtZeroAndEverythingElseIntact() {
        seedV9Vault()

        withRawDb { db ->
            assertEquals("fixture must be a v9 vault", 9L, userVersion(db))
            assertFalse("fixture must predate the columns", hasColumn(db, "outboundGrpCounter"))
        }

        // The upgrade: exactly what an unlock does after the app update.
        val vault = DatabaseManager(context, TEST_DB_KEY)
        try {
            val kept = vault.getContact("c-1")
            assertNotNull("the migration must not disturb the contact rows", kept)
            assertEquals("Alice", kept!!.alias)
            // The pre-existing counters are untouched…
            assertEquals(41L, kept.outboundCounter)
            assertEquals(39L, kept.inboundCounter)
            assertEquals(7L, kept.outboundCtlCounter)
            assertEquals("ep-1", kept.inboundEpoch)
            // …and the new pair reads the establish-on-read baseline.
            assertEquals(0L, kept.outboundGrpCounter)
            assertEquals(0L, kept.inboundGrpCounter)

            assertEquals("meta must survive the migration", "1", vault.getMeta("dr-on/c-1"))
            assertEquals(
                "every inbox row of every direction must survive",
                setOf("ib-in", "ib-out", "ib-inctl", "ib-outctl"),
                vault.getAllInboxIds().map { it.inboxId }.toSet(),
            )
            assertEquals("caps must survive", "cap-in", vault.getInboxId("ib-in")?.cap)
        } finally {
            vault.close()
        }

        withRawDb { db ->
            assertEquals("the schema must be stamped v10", EXPECTED_SCHEMA_VERSION, userVersion(db))
            assertTrue(hasColumn(db, "outboundGrpCounter"))
            assertTrue(hasColumn(db, "inboundGrpCounter"))
            assertEquals("no contact may be lost by an additive migration", 1L, rowCount(db, "Contacts"))
        }
    }

    @Test
    fun theGroupCountersPersistAcrossAReopen() {
        // The whole point of DB v10: a counter that only lived in RAM reset to 0 on
        // every relaunch, and the peer's strict-monotonic check would then drop every
        // group message after the first restart — silently, forever.
        seedV9Vault()

        DatabaseManager(context, TEST_DB_KEY).let { first ->
            val c = first.getContact("c-1")!!
            first.insertContact(c.copy(outboundGrpCounter = 12L, inboundGrpCounter = 9L))
            first.close()
        }

        DatabaseManager(context, TEST_DB_KEY).let { second ->
            val c = second.getContact("c-1")!!
            assertEquals(12L, c.outboundGrpCounter)
            assertEquals(9L, c.inboundGrpCounter)
            // The siblings must not have moved.
            assertEquals(41L, c.outboundCounter)
            assertEquals(7L, c.outboundCtlCounter)
            second.close()
        }
    }

    @Test
    fun theUpgradeIsOneShot_andASecondOpenChangesNothing() {
        seedV9Vault()

        DatabaseManager(context, TEST_DB_KEY).close()
        DatabaseManager(context, TEST_DB_KEY).let { second ->
            assertNotNull("the vault must still open on every later launch", second.getContact("c-1"))
            second.close()
        }

        withRawDb { db -> assertEquals(EXPECTED_SCHEMA_VERSION, userVersion(db)) }
    }

    @Test
    fun aFreshlyProvisionedVaultHasTheColumnsFromTheStart() {
        DatabaseManager(context, TEST_DB_KEY, isProvision = true).close()

        withRawDb { db ->
            assertTrue(hasColumn(db, "outboundGrpCounter"))
            assertTrue(hasColumn(db, "inboundGrpCounter"))
            assertEquals(EXPECTED_SCHEMA_VERSION, userVersion(db))
        }
    }

    @Test
    fun deletingAContactStillClearsEveryInboxDirection() {
        // The purge is direction-agnostic, which is what makes the third (group)
        // inbox pair free — and what stops an orphaned capability row surviving.
        seedV9Vault()
        val vault = DatabaseManager(context, TEST_DB_KEY)
        try {
            vault.insertInboxId(
                InboxIdRecord("ib-ingrp", "c-1", 1L, 2L, MessageManager.DIR_INBOUND_GRP, "cap-ingrp")
            )
            vault.insertInboxId(
                InboxIdRecord("ib-outgrp", "c-1", 1L, 2L, MessageManager.DIR_OUTBOUND_GRP, "cap-outgrp")
            )
            vault.deleteContact("c-1")
            assertTrue("every inbox row must go with the contact", vault.getAllInboxIds().isEmpty())
        } finally {
            vault.close()
        }
    }

    // -----------------------------------------------------------------------
    // Fixture — a v9 vault, written the way that build wrote it
    // -----------------------------------------------------------------------

    /**
     * Builds a real SQLCipher vault at exactly schema v9: the v9 table set (no
     * `Messages` — v9 is where it was dropped — and no group counters),
     * `user_version = 9`, keyed with the same RAW BYTES the app keys with.
     */
    private fun seedV9Vault() {
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
                "INSERT INTO Contacts (contactId, sharedSecret, trustLevel, alias, aliasLastRotated, " +
                    "outboundCounter, inboundCounter, inboundEpoch, outboundCtlCounter, inboundCtlCounter) " +
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                arrayOf<Any>(
                    "c-1", ByteArray(32) { 0x42.toByte() }, 2, "Alice", 1_700_000_000_000L,
                    41L, 39L, "ep-1", 7L, 6L,
                ),
            )
            // Both pre-v10 pairs, so "every direction survives" is not vacuous.
            for ((id, dir, cap) in listOf(
                Triple("ib-in", "inbound", "cap-in"),
                Triple("ib-out", "outbound", "cap-out"),
                Triple("ib-inctl", "inbound-ctl", "cap-inctl"),
                Triple("ib-outctl", "outbound-ctl", "cap-outctl"),
            )) {
                db.execSQL(
                    "INSERT INTO InboxIds (inboxId, contactId, createdAt, expiresAt, direction, cap) " +
                        "VALUES (?, ?, ?, ?, ?, ?)",
                    arrayOf<Any>(id, "c-1", 1_000L, 2_000L, dir, cap),
                )
            }
            db.execSQL("INSERT INTO _meta (key, value) VALUES ('dr-on/c-1', '1')")
            db.execSQL("PRAGMA user_version = 9")
        } finally {
            db.close()
        }

        // Fixture self-check on a FRESH handle, through the same helpers the
        // assertions use — a broken fixture would otherwise bless the migration
        // vacuously (the lesson from LegacyMessagesMigrationTest's tableExists bug).
        withRawDb { db ->
            check(userVersion(db) == 9L) { "fixture is not stamped user_version 9" }
            check(rowCount(db, "Contacts") == 1L) { "fixture did not seed its contact" }
            check(rowCount(db, "InboxIds") == 4L) { "fixture did not seed its inbox rows" }
            check(!hasColumn(db, "outboundGrpCounter")) { "fixture must predate the v10 columns" }
        }
    }

    // -----------------------------------------------------------------------
    // Raw inspection helpers
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

    /**
     * `PRAGMA table_info` rather than a `SELECT <col>`: it answers without throwing,
     * and it is the only way to tell "column absent" from "column present but empty".
     * Note the `arrayOf(name)` discipline from `LegacyMessagesMigrationTest` does not
     * apply here — PRAGMA takes no bind parameters, so the name is interpolated.
     */
    private fun hasColumn(db: SQLiteDatabase, name: String): Boolean =
        db.rawQuery("PRAGMA table_info(Contacts)", null).use { c ->
            val idx = c.getColumnIndex("name")
            var found = false
            while (c.moveToNext()) {
                if (idx >= 0 && c.getString(idx) == name) { found = true; break }
            }
            found
        }

    private fun rowCount(db: SQLiteDatabase, table: String): Long =
        db.rawQuery("SELECT count(*) FROM $table", null).use { if (it.moveToFirst()) it.getLong(0) else -1L }
}

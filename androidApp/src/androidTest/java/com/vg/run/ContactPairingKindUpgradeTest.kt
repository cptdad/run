package com.vg.run

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import net.zetetic.database.sqlcipher.SQLiteDatabase
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * RÚN-03: an app update alone never changes a contact's pairing label.
 *
 * A real SQLCipher vault at schema v10 (before the `ratchetV3` column existed), with
 * two contacts, is opened by today's [DatabaseManager] (v11). Both contacts must read
 * "Older pairing" with their secrets and counters intact; a contact saved as a
 * one-time-key pairing afterwards must read "Current", and every label must survive a
 * close and reopen. The label rule is the shared [ContactPairing.kindOf].
 *
 * Instrumented because SQLCipher is a native library with no JVM equivalent. The iOS
 * sibling is `IosContactV3FlagTest` (scripted bridge; no SQLCipher in the iOS test
 * host). Run with: ./gradlew connectedAndroidTest — or `am instrument` targeting this
 * class to keep device state.
 */
@RunWith(AndroidJUnit4::class)
class ContactPairingKindUpgradeTest {

    private lateinit var context: android.content.Context

    private companion object {
        const val DATABASE_NAME = "run.db"
        /** Deliberately not the key any other test uses. */
        val TEST_DB_KEY = ByteArray(32) { (it + 23).toByte() }
        val SECRET_1 = ByteArray(32) { 0x31 }
        val SECRET_2 = ByteArray(32) { 0x32 }
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

    @Test
    fun aV10Vault_opensWithEveryContactOlder_andANewCurrentPairingKeepsItsLabel() {
        seedV10Vault()

        val vault = DatabaseManager(context, TEST_DB_KEY)
        try {
            for ((id, secret) in listOf("c-1" to SECRET_1, "c-2" to SECRET_2)) {
                val c = vault.getContact(id)
                assertNotNull("$id must survive the upgrade", c)
                c!!
                assertEquals("$id after the update", ContactPairingKind.OLDER, ContactPairing.kindOf(c))
                assertArrayEquals("$id keeps its pairing secret", secret, c.sharedSecret)
                assertEquals("$id keeps its counters", 41L, c.outboundCounter)
                assertEquals(7L, c.inboundGrpCounter)
            }
            // A pairing made after the update with a current peer.
            vault.insertContact(
                ContactRecord("c-3", ByteArray(32) { 0x33 }, 1, "Carol", 1L, ratchetBootstrapV3 = true)
            )
            // A rewrite of an existing older row (what a counter bump does) keeps it older.
            vault.insertContact(vault.getContact("c-1")!!.copy(outboundCounter = 42L))
        } finally {
            vault.close()
        }

        DatabaseManager(context, TEST_DB_KEY).let { reopened ->
            try {
                assertEquals(ContactPairingKind.OLDER, ContactPairing.kindOf(reopened.getContact("c-1")!!))
                assertEquals(42L, reopened.getContact("c-1")!!.outboundCounter)
                assertEquals(ContactPairingKind.OLDER, ContactPairing.kindOf(reopened.getContact("c-2")!!))
                assertEquals(ContactPairingKind.CURRENT, ContactPairing.kindOf(reopened.getContact("c-3")!!))
            } finally {
                reopened.close()
            }
        }
    }

    /**
     * A real SQLCipher vault at exactly schema v10: the v10 Contacts columns (no
     * `ratchetV3`), the other v10 tables, `user_version = 10`, keyed with the raw
     * bytes the app keys with, so [DatabaseManager]'s own open runs only the v11 step.
     */
    private fun seedV10Vault() {
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
                    "vouchedAt INTEGER NOT NULL DEFAULT 0, outboundGrpCounter INTEGER NOT NULL DEFAULT 0, " +
                    "inboundGrpCounter INTEGER NOT NULL DEFAULT 0)"
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
            for ((id, secret) in listOf("c-1" to SECRET_1, "c-2" to SECRET_2)) {
                db.execSQL(
                    "INSERT INTO Contacts (contactId, sharedSecret, trustLevel, alias, aliasLastRotated, " +
                        "outboundCounter, inboundGrpCounter) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    arrayOf<Any>(id, secret, 2, "Alias-$id", 1_700_000_000_000L, 41L, 7L),
                )
            }
            db.execSQL("PRAGMA user_version = 10")
        } finally {
            db.close()
        }
    }
}

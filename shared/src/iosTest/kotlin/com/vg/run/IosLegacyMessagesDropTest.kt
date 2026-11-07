@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package com.vg.run

import platform.Foundation.NSArray
import platform.Foundation.NSMutableArray
import platform.Foundation.NSMutableDictionary
import platform.Foundation.NSString
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * v9 (2026-09-15) — the iOS half of the legacy-`messages`-table removal.
 *
 * Until a933616e (2026-05-24) `IosAppController` INSERTed every message into this
 * table. That commit removed the writer and left the table, so a vault provisioned
 * by an older build still holds every message it ever received — encrypted, but
 * under a key one compelled PIN recovers. iOS has no `user_version` counter (the
 * schema is idempotent-create), so the DROP inside `createTables` IS the migration,
 * and the `sqlite_master` probe is what keeps it a no-op on a fresh vault.
 *
 * The SQL layer is the same scriptable [DatabaseBridge] stand-in the other iOS
 * vault tests use — what is under test is the STATEMENT SEQUENCE the vault issues
 * at open, which is exactly what a bridge fake can observe and a real SQLCipher
 * cannot (nothing in the app's API reports "did you drop it?").
 */
class IosLegacyMessagesDropTest {

    private class RecordingBridge(var messagesTablePresent: Boolean) : DatabaseBridge {
        /** Every statement passed to `execute`, in order. */
        val executed = mutableListOf<String>()
        var sqliteMasterProbes = 0

        override fun open(path: String, key: ByteArray): Int = 0
        override fun rekey(key: ByteArray): Int = 21   // SQLITE_MISUSE — not exercised here

        override fun execute(sql: String, params: NSArray): Boolean {
            executed += sql
            // Model the real effect, so a second open sees a vault that no longer
            // has the table (the idempotency this migration relies on).
            if (sql.startsWith("DROP TABLE IF EXISTS messages")) messagesTablePresent = false
            return true
        }

        override fun query(sql: String, params: NSArray): NSArray {
            val rows = NSMutableArray()
            when {
                sql.contains("cipher_version") -> {
                    val row = NSMutableDictionary()
                    row.setObject("4.17.0-fake" as NSString, forKey = "cipher_version" as NSString)
                    rows.addObject(row)
                }
                sql.contains("sqlite_master") -> {
                    sqliteMasterProbes++
                    if (messagesTablePresent) {
                        val row = NSMutableDictionary()
                        row.setObject("messages" as NSString, forKey = "name" as NSString)
                        rows.addObject(row)
                    }
                }
            }
            return rows
        }

        override fun close() {}
    }

    /** Captured at CONSTRUCTION (one instance per test), so a second `open()` in the
     *  same test cannot overwrite it with our own fake. */
    private val previousFactory: DatabaseBridgeFactory? = DatabaseBridgeHolder.factory

    @AfterTest
    fun restore() {
        DatabaseBridgeHolder.factory = previousFactory
    }

    private fun open(bridge: RecordingBridge): IosVaultDatabase {
        DatabaseBridgeHolder.factory = DatabaseBridgeFactory { bridge }
        // isProvision = true: this test is about the statement sequence, and the
        // provision path is the one that does not require a materialised db file.
        // The drop runs in createTables(), which both paths share.
        return IosVaultDatabase(dbKey = ByteArray(32) { it.toByte() }, isProvision = true)
    }

    // -----------------------------------------------------------------------

    @Test
    fun aVaultThatStillHasTheTable_dropsItAndReclaimsThePages() {
        val bridge = RecordingBridge(messagesTablePresent = true)
        open(bridge).close()

        val dropAt = bridge.executed.indexOfFirst { it.startsWith("DROP TABLE IF EXISTS messages") }
        assertTrue(dropAt >= 0, "the legacy messages table must be DROPped on open")

        val vacuumAt = bridge.executed.indexOfFirst { it.trim() == "VACUUM" }
        assertTrue(vacuumAt > dropAt, "a VACUUM must FOLLOW the drop — secure_delete zeroes the " +
            "freed pages at free time, VACUUM is what returns them to the OS")

        assertEquals(1, bridge.sqliteMasterProbes, "one probe per open, not one per statement")
        assertNoMessageTableSql(bridge)
    }

    @Test
    fun aFreshVault_neitherCreatesNorDropsNorVacuums() {
        val bridge = RecordingBridge(messagesTablePresent = false)
        open(bridge).close()

        assertTrue(
            bridge.executed.none { it.startsWith("DROP TABLE IF EXISTS messages") },
            "a vault that never had the table must not issue the DROP",
        )
        assertTrue(
            bridge.executed.none { it.trim() == "VACUUM" },
            "a fresh vault must not pay for a whole-file VACUUM on every launch — that is what " +
                "the sqlite_master probe is for",
        )
        assertNoMessageTableSql(bridge)
    }

    @Test
    fun theMigrationIsIdempotent_theSecondOpenDoesNothing() {
        val bridge = RecordingBridge(messagesTablePresent = true)
        open(bridge).close()
        bridge.executed.clear()
        bridge.sqliteMasterProbes = 0

        // Same "file", opened again: the table is gone now, so nothing happens.
        open(bridge).close()

        assertTrue(
            bridge.executed.none { it.startsWith("DROP TABLE IF EXISTS messages") },
            "the drop must not repeat once the table is gone",
        )
        assertTrue(bridge.executed.none { it.trim() == "VACUUM" }, "…and neither must the VACUUM")
        assertEquals(1, bridge.sqliteMasterProbes)
    }

    @Test
    fun deleteContactAndWipeAllTables_noLongerNameTheMessagesTable() {
        val bridge = RecordingBridge(messagesTablePresent = false)
        val vault = open(bridge)
        vault.deleteContact("c-1")
        vault.wipeAllTables()
        vault.close()

        assertNoMessageTableSql(bridge)
    }

    // -----------------------------------------------------------------------

    /** No statement may CREATE, read from or write to a message table. DROP is the exception. */
    private fun assertNoMessageTableSql(bridge: RecordingBridge) {
        for (sql in bridge.executed) {
            if (sql.startsWith("DROP TABLE IF EXISTS messages")) continue
            assertFalse(
                sql.contains("messages"),
                "no statement other than the v9 DROP may name a message table: $sql",
            )
        }
    }
}

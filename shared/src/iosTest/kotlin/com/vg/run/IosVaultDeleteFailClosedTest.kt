@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package com.vg.run

import platform.Foundation.NSArray
import platform.Foundation.NSMutableArray
import platform.Foundation.NSMutableDictionary
import platform.Foundation.NSString
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * P-4 (review iteration 1): iOS `deleteContact` / `deleteGroup` used plain `exec`
 * inside `withTransaction`, so a statement the bridge reported as FAILED was ignored
 * and the transaction still COMMITTED the rest — a contact row gone with its ratchet
 * `_meta` keys left behind, reported as a successful delete. Android's `db.delete`
 * throws and rolls back. Both iOS deletes now use `execChecked`.
 *
 * Pinned here, on the statement sequence a scripted [DatabaseBridge] observes:
 *  - success path: the same statements as before, ending in COMMIT, no ROLLBACK;
 *  - a failing statement: the call THROWS, ROLLBACK is issued, COMMIT is not;
 *  - `wipeAllTables` deliberately stays best-effort: one failing DELETE neither
 *    throws nor stops the other clears from committing.
 */
class IosVaultDeleteFailClosedTest {

    private class ScriptedBridge : DatabaseBridge {
        val executed = mutableListOf<String>()
        /** A statement for which this returns true is reported as FAILED. */
        var fails: (String) -> Boolean = { false }

        override fun open(path: String, key: ByteArray): Int = 0
        override fun rekey(key: ByteArray): Int = 21   // SQLITE_MISUSE — not exercised here

        override fun execute(sql: String, params: NSArray): Boolean {
            executed += sql
            return !fails(sql)
        }

        override fun query(sql: String, params: NSArray): NSArray {
            val rows = NSMutableArray()
            when {
                sql.contains("cipher_version") -> {
                    val row = NSMutableDictionary()
                    row.setObject("4.17.0-fake" as NSString, forKey = "cipher_version" as NSString)
                    rows.addObject(row)
                }
                // One ratchet-free residue row so the `_meta` loop issues a DELETE.
                sql.startsWith("SELECT key FROM _meta") -> {
                    val row = NSMutableDictionary()
                    row.setObject("grp_inv_rl:c1" as NSString, forKey = "key" as NSString)
                    rows.addObject(row)
                }
            }
            return rows
        }

        override fun close() {}
    }

    private val previousFactory: DatabaseBridgeFactory? = DatabaseBridgeHolder.factory

    @AfterTest
    fun restore() {
        DatabaseBridgeHolder.factory = previousFactory
    }

    private fun open(bridge: ScriptedBridge): IosVaultDatabase {
        DatabaseBridgeHolder.factory = DatabaseBridgeFactory { bridge }
        // isProvision = true: the provision path does not require a materialised db
        // file; the delete paths under test are identical on both.
        val db = IosVaultDatabase(dbKey = ByteArray(32) { it.toByte() }, isProvision = true)
        bridge.executed.clear()   // only the statements of the call under test
        return db
    }

    private fun ScriptedBridge.txnEnd(): List<String> =
        executed.filter { it == "COMMIT" || it == "ROLLBACK" }

    @Test
    fun deleteContact_successPath_commitsEveryStatement() {
        val bridge = ScriptedBridge()
        val db = open(bridge)
        db.deleteContact("c1")
        assertEquals("BEGIN", bridge.executed.first())
        assertEquals(listOf("COMMIT"), bridge.txnEnd())
        assertTrue(bridge.executed.contains("DELETE FROM contacts WHERE contact_id = ?"))
        assertTrue(bridge.executed.contains("DELETE FROM inbox_ids WHERE contact_id = ?"))
        assertTrue(bridge.executed.contains("UPDATE group_members SET contact_id = NULL WHERE contact_id = ?"))
        assertTrue(
            bridge.executed.count { it == "DELETE FROM _meta WHERE key = ?" } >=
                ratchetMetaKeysForContact("c1").size + 1,
            "every ratchet key plus the classified group residue is deleted",
        )
        db.close()
    }

    @Test
    fun deleteContact_aFailedStatement_rollsBackAndThrows() {
        val bridge = ScriptedBridge()
        val db = open(bridge)
        bridge.fails = { it == "DELETE FROM inbox_ids WHERE contact_id = ?" }
        assertFailsWith<Throwable> { db.deleteContact("c1") }
        assertEquals(listOf("ROLLBACK"), bridge.txnEnd(), "a failed delete must roll back, never commit")
        db.close()
    }

    @Test
    fun deleteContact_aFailedMetaPurge_rollsBackAndThrows() {
        val bridge = ScriptedBridge()
        val db = open(bridge)
        bridge.fails = { it == "DELETE FROM _meta WHERE key = ?" }
        assertFailsWith<Throwable> { db.deleteContact("c1") }
        assertFalse("COMMIT" in bridge.executed, "orphaned ratchet state must not be committed as a delete")
        assertTrue("ROLLBACK" in bridge.executed)
        db.close()
    }

    @Test
    fun deleteGroup_aFailedStatement_rollsBackAndThrows() {
        val bridge = ScriptedBridge()
        val db = open(bridge)
        db.deleteGroup("g1")
        assertEquals(listOf("COMMIT"), bridge.txnEnd(), "success path unchanged")

        bridge.executed.clear()
        bridge.fails = { it == "DELETE FROM contact_groups WHERE group_id = ?" }
        assertFailsWith<Throwable> { db.deleteGroup("g1") }
        assertEquals(listOf("ROLLBACK"), bridge.txnEnd())
        db.close()
    }

    // P-4b (review iteration 2): deleteMeta / deleteGroupMember join the checked set,
    // matching Android's throwing SQLiteDatabase.delete; touchInboxExpiry stays
    // best-effort on BOTH platforms (interface contract).

    @Test
    fun deleteMeta_aFailedDelete_throws() {
        val bridge = ScriptedBridge()
        val db = open(bridge)
        db.deleteMeta("grp_inv_rl:c1")   // success path: no throw
        bridge.fails = { it == "DELETE FROM _meta WHERE key = ?" }
        assertFailsWith<Throwable> { db.deleteMeta("grp_inv_rl:c1") }
        db.close()
    }

    @Test
    fun deleteGroupMember_insideATransaction_aFailedDeleteRollsBackThePairedWrite() {
        val bridge = ScriptedBridge()
        val db = open(bridge)
        bridge.fails = { it == "DELETE FROM group_members WHERE group_id = ? AND member_id = ?" }
        assertFailsWith<Throwable> {
            db.withTransaction { db.deleteGroupMember("g1", "m1") }
        }
        assertEquals(listOf("ROLLBACK"), bridge.txnEnd(), "a failed member delete must not commit")
        db.close()
    }

    @Test
    fun touchInboxExpiry_staysBestEffort_aFailedUpdateDoesNotThrow() {
        val bridge = ScriptedBridge()
        val db = open(bridge)
        bridge.fails = { it.startsWith("UPDATE inbox_ids SET expires_at") }
        db.touchInboxExpiry("i1", 1_000L)   // must not throw
        assertTrue(bridge.executed.any { it.startsWith("UPDATE inbox_ids SET expires_at") })
        db.close()
    }

    @Test
    fun wipeAllTables_staysBestEffort_oneFailedClearDoesNotStopTheOthers() {
        val bridge = ScriptedBridge()
        val db = open(bridge)
        bridge.fails = { it == "DELETE FROM inbox_ids" }
        db.wipeAllTables()   // must not throw
        assertEquals(listOf("COMMIT"), bridge.txnEnd(), "the other clears still commit")
        for (table in listOf("contacts", "group_members", "contact_groups", "_meta")) {
            assertTrue("DELETE FROM $table" in bridge.executed, "$table is still cleared")
        }
        db.close()
    }
}

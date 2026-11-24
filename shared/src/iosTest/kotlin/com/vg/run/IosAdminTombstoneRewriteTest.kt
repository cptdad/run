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
 * RÚN-06 on the REAL iOS actual: `IosVaultDatabase.deleteContact` rewrites every
 * `group_admin:<groupId>` record naming the deleted contact to "gone", inside the
 * delete transaction, and touches no other record. Observed on the statement
 * sequence (and bound parameters) a scripted [DatabaseBridge] sees — the same
 * technique as [IosVaultDeleteFailClosedTest].
 */
class IosAdminTombstoneRewriteTest {

    private class ScriptedBridge(val meta: Map<String, String>) : DatabaseBridge {
        val executed = mutableListOf<Pair<String, List<String?>>>()
        var fails: (String) -> Boolean = { false }
        /** When true, `SELECT value FROM _meta` answers no row (the bridge's error shape). */
        var valueReadsFail = false

        override fun open(path: String, key: ByteArray): Int = 0
        override fun rekey(key: ByteArray): Int = 21

        override fun execute(sql: String, params: NSArray): Boolean {
            executed += sql to params.strings()
            return !fails(sql)
        }

        override fun query(sql: String, params: NSArray): NSArray {
            val rows = NSMutableArray()
            when {
                sql.contains("cipher_version") -> rows.addObject(row("cipher_version", "4.17.0-fake"))
                sql.startsWith("SELECT key FROM _meta") -> meta.keys.forEach { rows.addObject(row("key", it)) }
                sql.startsWith("SELECT value FROM _meta WHERE key = ?") -> {
                    val v = meta[params.strings().firstOrNull()]
                    if (v != null && !valueReadsFail) rows.addObject(row("value", v))
                }
            }
            return rows
        }

        override fun close() {}

        private fun row(k: String, v: String): NSMutableDictionary {
            val r = NSMutableDictionary()
            r.setObject(v as NSString, forKey = k as NSString)
            return r
        }

        private fun NSArray.strings(): List<String?> =
            (0 until count.toInt()).map { objectAtIndex(it.toULong()) as? String }
    }

    private val previousFactory: DatabaseBridgeFactory? = DatabaseBridgeHolder.factory

    @AfterTest
    fun restore() {
        DatabaseBridgeHolder.factory = previousFactory
    }

    private fun open(bridge: ScriptedBridge): IosVaultDatabase {
        DatabaseBridgeHolder.factory = DatabaseBridgeFactory { bridge }
        val db = IosVaultDatabase(dbKey = ByteArray(32) { it.toByte() }, isProvision = true)
        bridge.executed.clear()
        return db
    }

    private val updateSql = "UPDATE _meta SET value = ? WHERE key = ?"

    private fun bridgeWithRecords() = ScriptedBridge(
        linkedMapOf(
            "group_admin:g1" to "c1",
            "group_admin:g2" to "c2",
            "group_admin:g3" to GroupManager.SELF_ADMIN_MARKER,
            "group_admin:g4" to GroupAdminTombstone.DELETED_ADMIN,
        )
    )

    @Test
    fun deleteContact_rewritesOnlyTheRecordNamingTheContact_insideTheTransaction() {
        val bridge = bridgeWithRecords()
        val db = open(bridge)
        db.deleteContact("c1")

        val updates = bridge.executed.filter { it.first == updateSql }
        assertEquals(listOf(listOf<String?>("gone", "group_admin:g1")), updates.map { it.second })
        val sqls = bridge.executed.map { it.first }
        assertEquals("BEGIN", sqls.first())
        assertTrue(sqls.indexOf(updateSql) < sqls.indexOf("COMMIT"), "the rewrite commits with the delete")
        assertFalse("ROLLBACK" in sqls)
        assertTrue(
            bridge.executed.none { it.first == "DELETE FROM _meta WHERE key = ?" && it.second.firstOrNull()?.startsWith("group_admin:") == true },
            "a tombstone is never purged by a contact delete",
        )
        db.close()
    }

    @Test
    fun aFailedRewrite_rollsTheWholeDeleteBack() {
        val bridge = bridgeWithRecords()
        val db = open(bridge)
        bridge.fails = { it == updateSql }
        assertFailsWith<Throwable> { db.deleteContact("c1") }
        val sqls = bridge.executed.map { it.first }
        assertFalse("COMMIT" in sqls, "a delete whose rewrite failed must not commit")
        assertTrue("ROLLBACK" in sqls)
        db.close()
    }

    @Test
    fun anUnreadableValue_rewritesNothing_andTheDeleteStillCommits() {
        val bridge = bridgeWithRecords()
        bridge.valueReadsFail = true
        val db = open(bridge)
        db.deleteContact("c1")
        val sqls = bridge.executed.map { it.first }
        assertFalse(updateSql in sqls, "an unreadable record is left for the session-start pass")
        assertTrue("COMMIT" in sqls)
        db.close()
    }
}

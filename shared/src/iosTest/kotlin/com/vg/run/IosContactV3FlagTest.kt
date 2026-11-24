@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package com.vg.run

import platform.Foundation.NSArray
import platform.Foundation.NSMutableArray
import platform.Foundation.NSMutableDictionary
import platform.Foundation.NSNull
import platform.Foundation.NSNumber
import platform.Foundation.numberWithLongLong
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The v11 contact-row flag on iOS (docs/ratchet-bootstrap-plan.md §3.4) — the reason
 * the flag is in the row is that a failed read must never turn a v3 contact into a
 * legacy one, so the mapper is STRICT:
 *  - no `ratchet_v3` column at all ⇒ legacy (a vault whose v11 ALTER never landed
 *    cannot hold a v3 row: the v3 INSERT names the column);
 *  - 0 / 1 ⇒ false / true;
 *  - anything else (NULL, a stray value) ⇒ the row is DROPPED (unreadable), never
 *    read as legacy.
 * And the INSERT names the column only for a v3 row, so a legacy write never depends
 * on the v11 ALTER.
 */
class IosContactV3FlagTest {

    private class FakeBridge : DatabaseBridge {
        val executed = mutableListOf<Pair<String, NSArray>>()
        var contactRows: NSArray = NSMutableArray()
        override fun open(path: String, key: ByteArray): Int = 0
        override fun rekey(key: ByteArray): Int = 21
        override fun execute(sql: String, params: NSArray): Boolean { executed.add(sql to params); return true }
        override fun query(sql: String, params: NSArray): NSArray = when {
            sql.startsWith("SELECT * FROM contacts") -> contactRows
            // The open refuses a database that does not report SQLCipher.
            sql.contains("cipher_version") -> NSMutableArray().apply {
                addObject(NSMutableDictionary().apply {
                    setObject("4.17.0-fake" as platform.Foundation.NSString, forKey = "cipher_version" as platform.Foundation.NSString)
                })
            }
            else -> NSMutableArray()
        }
        override fun close() {}
    }

    private fun row(v3: Any?, includeColumn: Boolean = true): NSArray {
        val d = NSMutableDictionary()
        d.setObject("c1", forKey = "contact_id" as platform.Foundation.NSString)
        d.setObject(encodeBase64(ByteArray(32) { 1 }), forKey = "shared_secret" as platform.Foundation.NSString)
        d.setObject("A", forKey = "alias" as platform.Foundation.NSString)
        if (includeColumn) d.setObject(v3 ?: NSNull(), forKey = "ratchet_v3" as platform.Foundation.NSString)
        return NSMutableArray().apply { addObject(d) }
    }

    private fun <T> withDb(block: (IosVaultDatabase, FakeBridge) -> T): T {
        val fake = FakeBridge()
        val previous = DatabaseBridgeHolder.factory
        DatabaseBridgeHolder.factory = DatabaseBridgeFactory { fake }
        try {
            // isProvision = true: these tests are about the contact statements and the row
            // mapper; the unlock path refuses to open when no database file exists, and
            // the test host has none (the fake bridge creates no file).
            val db = IosVaultDatabase(dbKey = ByteArray(32) { it.toByte() }, isProvision = true)
            try { return block(db, fake) } finally { db.close() }
        } finally {
            DatabaseBridgeHolder.factory = previous
        }
    }

    @Test
    fun insert_namesTheV3ColumnOnlyForAV3Row() = withDb { db, fake ->
        fake.executed.clear()
        db.insertContact(ContactRecord("c1", ByteArray(32), 0, "A", 0L))
        val legacy = fake.executed.single { it.first.startsWith("INSERT OR REPLACE INTO contacts") }
        assertFalse("ratchet_v3" in legacy.first, "a legacy write must not depend on the v11 column")
        fake.executed.clear()
        db.insertContact(ContactRecord("c2", ByteArray(32), 0, "B", 0L, ratchetBootstrapV3 = true))
        val v3 = fake.executed.single { it.first.startsWith("INSERT OR REPLACE INTO contacts") }
        assertTrue("ratchet_v3" in v3.first)
        assertEquals(1L, (v3.second.objectAtIndex(15uL) as NSNumber).longLongValue)
    }

    @Test
    fun mapper_isStrict() = withDb { db, fake ->
        fake.contactRows = row(null, includeColumn = false)
        assertEquals(false, db.getContact("c1")?.ratchetBootstrapV3, "no column ⇒ legacy (no v3 row can exist)")
        fake.contactRows = row(NSNumber.numberWithLongLong(0))
        assertEquals(false, db.getContact("c1")?.ratchetBootstrapV3)
        fake.contactRows = row(NSNumber.numberWithLongLong(1))
        assertEquals(true, db.getContact("c1")?.ratchetBootstrapV3)
        fake.contactRows = row(NSNumber.numberWithLongLong(7))
        assertNull(db.getContact("c1"), "a stray value is an unreadable row, never 'legacy'")
        fake.contactRows = row(null)
        assertNull(db.getContact("c1"), "NULL is an unreadable row, never 'legacy'")
    }

    /**
     * RÚN-03: the contact menu's label on iOS, through the same strict mapper. An app
     * update alone changes nothing: the open only ADDS the column with DEFAULT 0
     * (every pre-v11 row reads "Older pairing"), and a stored 1 stays "Current".
     * Scripted bridge: there is no SQLCipher in the iOS test host, so this pins the
     * statement and the row mapping, not a file on disk.
     */
    @Test
    fun theLabel_survivesTheUpgradeOpen_andFollowsTheRowFlag() = withDb { db, fake ->
        assertTrue(
            fake.executed.any { it.first == "ALTER TABLE contacts ADD COLUMN ratchet_v3 INTEGER NOT NULL DEFAULT 0" },
            "the open adds the v11 column additively, DEFAULT 0",
        )
        assertTrue(
            fake.executed.none { it.first.startsWith("UPDATE contacts") && "ratchet_v3" in it.first },
            "the open never rewrites the flag of an existing row",
        )
        fake.contactRows = row(null, includeColumn = false)
        assertEquals(ContactPairingKind.OLDER, ContactPairing.kindOf(db.getContact("c1")!!), "a pre-v11 row")
        fake.contactRows = row(NSNumber.numberWithLongLong(0))
        assertEquals(ContactPairingKind.OLDER, ContactPairing.kindOf(db.getContact("c1")!!))
        fake.contactRows = row(NSNumber.numberWithLongLong(1))
        assertEquals(ContactPairingKind.CURRENT, ContactPairing.kindOf(db.getContact("c1")!!))
    }
}

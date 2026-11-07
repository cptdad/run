@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package com.vg.run

import platform.Foundation.NSArray
import platform.Foundation.NSMutableArray
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * The Swift SQLite bridge used to discard
 * sqlite3_step's result and report every write as a success, so a failed
 * persist on iOS looked identical to a successful one. That made
 * MessageManager's fail-closed replay guards (inbound baseline +
 * outbound counter) unreachable on iOS — a relay could replay same-epoch
 * blobs after a device-side write failure.
 *
 * The fix makes DatabaseBridge.execute return success and IosVaultDatabase
 * throw on the anti-replay-critical persist. This test pins that behavior:
 * insertContact succeeds while the bridge reports success and THROWS when it
 * reports failure.
 */
class IosVaultWriteFailureTest {

    private class FakeBridge(
        var failWrites: Boolean = false,
        var openResult: Int = 0,   // 0 = SQLITE_OK; else a SQLite result code
    ) : DatabaseBridge {
        var openCalls = 0
        // Raw-key signature since the wipeable-key-buffer fix (b7e21af) — the
        // fake just counts opens and replays the scripted result code.
        override fun open(path: String, key: ByteArray): Int { openCalls++; return openResult }
        // Re-key is not exercised by these write-failure tests, and a counter no
        // assertion ever reads is worse than nothing (it looks like coverage).
        // SQLITE_MISUSE = "there is nothing here to re-key", which is exactly what
        // this fake models. IosVaultDatabase.rekey's own contract — bridge called
        // once, `true` only for SQLITE_OK — is pinned in IosDbKeyRotationTest.
        override fun rekey(key: ByteArray): Int = 21  // SQLITE_MISUSE
        override fun execute(sql: String, params: NSArray): Boolean = !failWrites
        override fun query(sql: String, params: NSArray): NSArray = NSMutableArray()
        override fun close() {}
    }

    @Test
    fun insertContact_throwsWhenBridgeReportsWriteFailure() {
        val fake = FakeBridge(failWrites = false)
        val previous = DatabaseBridgeHolder.factory
        DatabaseBridgeHolder.factory = DatabaseBridgeFactory { fake }
        try {
            // Unlock open — init's CREATE/_meta writes succeed while the bridge
            // reports success.
            val db = IosVaultDatabase(dbKey = ByteArray(32) { it.toByte() }, isProvision = false)

            // Succeeds while the bridge reports success.
            db.insertContact(ContactRecord("c1", ByteArray(32), 0, "A", 0L))

            // Simulate a disk/IO write failure: the anti-replay-critical persist
            // must THROW so the fail-closed guards fire — not silently "succeed".
            fake.failWrites = true
            assertFailsWith<Throwable> {
                db.insertContact(ContactRecord("c2", ByteArray(32), 0, "B", 0L))
            }
            db.close()
        } finally {
            DatabaseBridgeHolder.factory = previous
        }
    }

    // On the UNLOCK path (isProvision=false) a failed
    // open must fail closed after a SINGLE attempt and must NOT delete-and-
    // recreate the vault — deleting there would silently destroy the vault data.
    @Test
    fun unlockOpenFailure_failsClosedWithoutDeleteRetry() {
        val fake = FakeBridge(openResult = 5)  // SQLITE_BUSY (transient)
        val previous = DatabaseBridgeHolder.factory
        DatabaseBridgeHolder.factory = DatabaseBridgeFactory { fake }
        try {
            assertFailsWith<Throwable> {
                IosVaultDatabase(dbKey = ByteArray(32) { it.toByte() }, isProvision = false)
            }
            assertEquals(1, fake.openCalls, "unlock open failure must not delete + retry")
        } finally {
            DatabaseBridgeHolder.factory = previous
        }
    }

    // A genuine wrong-key/corrupt file (SQLITE_NOTADB) at PROVISION may be
    // recovered by a single delete-and-recreate (open attempted twice).
    @Test
    fun provisionNotADb_deletesAndRetriesOnce() {
        val fake = FakeBridge(openResult = 26)  // SQLITE_NOTADB
        val previous = DatabaseBridgeHolder.factory
        DatabaseBridgeHolder.factory = DatabaseBridgeFactory { fake }
        try {
            assertFailsWith<Throwable> {
                IosVaultDatabase(dbKey = ByteArray(32) { it.toByte() }, isProvision = true)
            }
            assertEquals(2, fake.openCalls, "provision NOTADB should delete + retry exactly once")
        } finally {
            DatabaseBridgeHolder.factory = previous
        }
    }

    // A TRANSIENT error even at provision must NOT trigger the destructive delete.
    @Test
    fun provisionTransient_doesNotDelete() {
        val fake = FakeBridge(openResult = 10)  // SQLITE_IOERR (transient)
        val previous = DatabaseBridgeHolder.factory
        DatabaseBridgeHolder.factory = DatabaseBridgeFactory { fake }
        try {
            assertFailsWith<Throwable> {
                IosVaultDatabase(dbKey = ByteArray(32) { it.toByte() }, isProvision = true)
            }
            assertEquals(1, fake.openCalls, "provision transient error must not delete + retry")
        } finally {
            DatabaseBridgeHolder.factory = previous
        }
    }
}

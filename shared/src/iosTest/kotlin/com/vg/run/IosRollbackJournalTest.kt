@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package com.vg.run

import platform.Foundation.NSArray
import platform.Foundation.NSMutableArray
import platform.Foundation.NSMutableDictionary
import platform.Foundation.NSNumber
import platform.Foundation.NSString
import platform.Foundation.numberWithLongLong
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * RUN-02 (2026-11-12) — the iOS vault must be PROVEN to run on a rollback journal,
 * and an unproven state must be retried at the next write boundary, never assumed.
 *
 * WAL kept every superseded Double Ratchet state (one `_meta` row rewritten per
 * step) in run.db-wal; db + wal + the current db key rebuilt an old chain key. The
 * bridge now opens in `journal_mode=TRUNCATE`; [IosVaultDatabase] reads the mode
 * back and, while it is not TRUNCATE/DELETE (the switch out of WAL is refused while
 * another connection holds the file), runs a VERIFIED `wal_checkpoint(TRUNCATE)` and
 * retries both at every write boundary — after a top-level `_meta` write, after the
 * outermost transaction (never inside it), after a re-key, before close.
 *
 * Same scripted-[DatabaseBridge] technique as `IosLegacyMessagesDropTest`: what is
 * under test is the STATEMENT SEQUENCE, which a real SQLCipher cannot report. The
 * on-disk half (no WAL frames survive, the prefix rebuild fails) is Android's
 * instrumented `VaultJournalResidueTest`; iOS needs the device check in the report.
 */
class IosRollbackJournalTest {

    /**
     * [modeAnswers] scripts what `PRAGMA journal_mode = TRUNCATE` answers, one per
     * call (the last one repeats). [checkpointBusy]/[checkpointLog] script the
     * checkpoint's result row.
     */
    private class ScriptedBridge(
        var modeAnswers: MutableList<String?>,
        var checkpointBusy: Long = 0,
        var checkpointLog: Long = 0,
    ) : DatabaseBridge {
        /** Every call, in order: "E:<sql>" for execute, "Q:<sql>" for query, "CLOSE". */
        val events = mutableListOf<String>()

        override fun open(path: String, key: ByteArray): Int = 0
        override fun rekey(key: ByteArray): Int = 0

        override fun execute(sql: String, params: NSArray): Boolean {
            events += "E:$sql"
            return true
        }

        override fun query(sql: String, params: NSArray): NSArray {
            events += "Q:$sql"
            val rows = NSMutableArray()
            when {
                sql.contains("cipher_version") -> rows.addObject(row("cipher_version", "4.19.0-fake" as NSString))
                sql == "PRAGMA journal_mode = TRUNCATE" -> {
                    val answer = if (modeAnswers.size > 1) modeAnswers.removeAt(0) else modeAnswers.firstOrNull()
                    if (answer != null) rows.addObject(row("journal_mode", answer as NSString))
                }
                sql == "PRAGMA wal_checkpoint(TRUNCATE)" -> {
                    val r = NSMutableDictionary()
                    r.setObject(NSNumber.numberWithLongLong(checkpointBusy), forKey = "busy" as NSString)
                    r.setObject(NSNumber.numberWithLongLong(checkpointLog), forKey = "log" as NSString)
                    r.setObject(NSNumber.numberWithLongLong(checkpointLog), forKey = "checkpointed" as NSString)
                    rows.addObject(r)
                }
                sql == "PRAGMA busy_timeout" -> rows.addObject(row("timeout", NSNumber.numberWithLongLong(2500)))
            }
            return rows
        }

        override fun close() { events += "CLOSE" }

        private fun row(k: String, v: Any): NSMutableDictionary =
            NSMutableDictionary().also { it.setObject(v, forKey = k as NSString) }

        fun modeSwitches() = events.count { it == "Q:PRAGMA journal_mode = TRUNCATE" }
        fun checkpoints() = events.count { it == "Q:PRAGMA wal_checkpoint(TRUNCATE)" }
    }

    private val previousFactory: DatabaseBridgeFactory? = DatabaseBridgeHolder.factory

    @AfterTest
    fun restore() { DatabaseBridgeHolder.factory = previousFactory }

    private fun open(bridge: ScriptedBridge): IosVaultDatabase {
        DatabaseBridgeHolder.factory = DatabaseBridgeFactory { bridge }
        return IosVaultDatabase(dbKey = ByteArray(32) { it.toByte() }, isProvision = true)
    }

    // -----------------------------------------------------------------------

    @Test
    fun theModeIsReadBackBeforeAnySchemaWrite() {
        val bridge = ScriptedBridge(mutableListOf("truncate"))
        open(bridge).close()

        val modeAt = bridge.events.indexOf("Q:PRAGMA journal_mode = TRUNCATE")
        val firstCreate = bridge.events.indexOfFirst { it.startsWith("E:CREATE TABLE") }
        assertTrue(modeAt >= 0, "the open must read the journal mode back")
        assertTrue(modeAt < firstCreate, "…before the first schema write of the session")
    }

    @Test
    fun aProvenRollbackJournal_costsNothingAtLaterWriteBoundaries() {
        val bridge = ScriptedBridge(mutableListOf("truncate"))
        val vault = open(bridge)
        bridge.events.clear()

        vault.putMeta("dr/c-1/text", "state-1")
        vault.putMeta("dr/c-1/text", "state-2")
        vault.withTransaction { vault.putMeta("dr/c-1/text", "state-3") }
        vault.deleteMeta("dr/c-1/text")
        vault.close()

        assertEquals(0, bridge.modeSwitches(), "steady state must not re-issue the mode PRAGMA")
        assertEquals(0, bridge.checkpoints(), "…nor a checkpoint")
        assertTrue(bridge.events.none { it.contains("busy_timeout") })
    }

    @Test
    fun aRefusedSwitch_runsAVerifiedCheckpointAndRetriesAtTheNextRatchetWrite() {
        // Open: still WAL (another connection held the file). Then the retry lands.
        val bridge = ScriptedBridge(mutableListOf("wal", "truncate"))
        val vault = open(bridge)

        assertEquals(1, bridge.modeSwitches())
        assertEquals(1, bridge.checkpoints(), "an unproven switch must at least empty the WAL now")
        bridge.events.clear()

        vault.putMeta("dr/c-1/text", "state-1")
        val writeAt = bridge.events.indexOfFirst { it.startsWith("E:INSERT OR REPLACE INTO _meta") }
        val retryAt = bridge.events.indexOf("Q:PRAGMA journal_mode = TRUNCATE")
        assertTrue(writeAt in 0 until retryAt, "the retry follows the ratchet-secret write")
        // Non-blocking retry: busy timeout dropped to 0 around it, then restored.
        val zeroAt = bridge.events.indexOf("Q:PRAGMA busy_timeout = 0")
        val restoreAt = bridge.events.indexOf("Q:PRAGMA busy_timeout = 2500")
        assertTrue(zeroAt in 0 until retryAt && retryAt < restoreAt,
            "a boundary retry must not sit in the 2.5 s busy wait under the vault lock")

        // Proven now: the next write issues nothing.
        bridge.events.clear()
        vault.putMeta("dr/c-1/text", "state-2")
        assertEquals(0, bridge.modeSwitches())
        assertEquals(0, bridge.checkpoints())
        vault.close()
    }

    @Test
    fun aBusyCheckpointIsNotAssumedDone_theNextBoundaryRetriesBoth() {
        val bridge = ScriptedBridge(mutableListOf("wal"), checkpointBusy = 1, checkpointLog = 12)
        val vault = open(bridge)
        bridge.events.clear()

        vault.putMeta("dr/c-1/text", "state-1")
        assertEquals(1, bridge.modeSwitches(), "still unproven ⇒ retried at this boundary")
        assertEquals(1, bridge.checkpoints())

        // A PARTIAL checkpoint (not busy, but frames left in the log) is not done either.
        bridge.checkpointBusy = 0
        bridge.checkpointLog = 7
        bridge.events.clear()
        vault.putMeta("dr/c-1/text", "state-2")
        assertEquals(1, bridge.modeSwitches())
        assertEquals(1, bridge.checkpoints())

        // Even a clean checkpoint does not end the retries while the MODE is WAL —
        // the next write would append frames again.
        bridge.checkpointLog = 0
        bridge.events.clear()
        vault.putMeta("dr/c-1/text", "state-3")
        assertEquals(1, bridge.modeSwitches())
        vault.close()
    }

    @Test
    fun insideATransaction_theRetryWaitsForTheCommit() {
        val bridge = ScriptedBridge(mutableListOf("wal", "wal", "truncate"))
        val vault = open(bridge)
        bridge.events.clear()

        vault.withTransaction {
            vault.putMeta("dr/c-1/text", "state-1")
            vault.putMeta("dr-on/c-1", "1")
        }
        val commitAt = bridge.events.indexOf("E:COMMIT")
        val switches = bridge.events.withIndex().filter { it.value == "Q:PRAGMA journal_mode = TRUNCATE" }
        assertEquals(1, switches.size, "one retry per outermost transaction, not one per inner write")
        assertTrue(switches.single().index > commitAt, "a journal-mode switch is refused inside a transaction")
        vault.close()
    }

    @Test
    fun aFailedTransaction_stillReachesTheBoundary_andStillRethrows() {
        val bridge = ScriptedBridge(mutableListOf("wal", "truncate"))
        val vault = open(bridge)
        bridge.events.clear()

        var thrown = false
        try {
            vault.withTransaction { throw IllegalStateException("boom") }
        } catch (e: IllegalStateException) {
            thrown = true
        }
        assertTrue(thrown, "the boundary must never mask the block's own exception")
        val rollbackAt = bridge.events.indexOf("E:ROLLBACK")
        val retryAt = bridge.events.indexOf("Q:PRAGMA journal_mode = TRUNCATE")
        assertTrue(rollbackAt in 0 until retryAt)
        vault.close()
    }

    @Test
    fun closeRetriesWhileUnproven_beforeTheHandleGoes() {
        val bridge = ScriptedBridge(mutableListOf("wal"))
        val vault = open(bridge)
        bridge.events.clear()

        vault.close()
        val retryAt = bridge.events.indexOf("Q:PRAGMA journal_mode = TRUNCATE")
        val closeAt = bridge.events.indexOf("CLOSE")
        assertTrue(retryAt in 0 until closeAt, "the last attempt must run while the handle exists")
        assertEquals(1, bridge.checkpoints())
    }

    @Test
    fun aRekey_isABoundary() {
        val bridge = ScriptedBridge(mutableListOf("wal", "truncate"))
        val vault = open(bridge)
        bridge.events.clear()

        assertTrue(vault.rekey(ByteArray(32) { 7 }), "the boundary must not change rekey's answer")
        assertEquals(1, bridge.modeSwitches())
        vault.close()
    }

    @Test
    fun anUnreadableAnswerIsNotProof_andNeverFailsTheOpen() {
        // Empty row set (prepare failed) — the open must still succeed.
        val bridge = ScriptedBridge(mutableListOf(null))
        val vault = open(bridge)
        assertEquals(1, bridge.checkpoints(), "unknown is treated as unproven")
        bridge.events.clear()
        vault.putMeta("dr/c-1/text", "state-1")
        assertEquals(1, bridge.modeSwitches())
        vault.close()
    }

    @Test
    fun deleteModeAlsoCountsAsProof() {
        val bridge = ScriptedBridge(mutableListOf("delete"))
        val vault = open(bridge)
        assertEquals(0, bridge.checkpoints())
        bridge.events.clear()
        vault.putMeta("dr/c-1/text", "state-1")
        assertEquals(0, bridge.modeSwitches())
        vault.close()
    }
}

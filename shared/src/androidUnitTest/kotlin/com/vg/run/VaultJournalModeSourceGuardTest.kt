package com.vg.run

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// RUN-02 (2026-11-12) — no superseded vault state may stay recoverable from the
// vault's journal sidecar, on EITHER platform.
//
// The Double Ratchet state is one `_meta` row replaced on every step. iOS opened
// the vault in WAL mode with no checkpoint policy, so run.db-wal kept every
// superseded ratchet state; an image of db + wal plus the CURRENT db key rebuilt an
// earlier committed view and an old chain key. The fix is the rollback journal
// (iOS TRUNCATE, Android DELETE), whose sidecar only ever holds the pre-images of
// the transaction in flight (= the last COMMITTED state) and is emptied at commit.
//
// SOURCE guard on purpose: the property is "no connection to this file ever runs
// WAL / PERSIST", which a behavioural test of today's code cannot keep true
// tomorrow. The behavioural halves are `IosRollbackJournalTest` (iosTest, scripted
// bridge: the read-back, the verified checkpoint and the retry boundaries) and
// `VaultJournalResidueTest` (Android instrumented, real SQLCipher: no -wal, and the
// auditor's WAL-prefix rebuild against both a WAL oracle and the vault).
// ---------------------------------------------------------------------------
class VaultJournalModeSourceGuardTest {

    @Test
    fun theSwiftBridgeOpensOnATruncateRollbackJournal_afterTheKeyIsProven() {
        val swift = source(SWIFT_BRIDGE)
        val modes = JOURNAL_MODE_SET.findAll(swift).map { it.groupValues[1].uppercase() }.toList()
        assertEquals(
            listOf("TRUNCATE"), modes,
            "SwiftDatabaseBridge.open must set exactly one journal mode, TRUNCATE (RUN-02). " +
                "WAL kept every superseded ratchet state in run.db-wal.",
        )
        val verifyAt = swift.indexOf("SELECT count(*) FROM sqlite_master")
        val modeAt = JOURNAL_MODE_SET.find(swift)!!.range.first
        assertTrue(verifyAt in 0 until modeAt,
            "the journal-mode switch must come AFTER the key verification — it reads the db")
        assertTrue(swift.contains("journal_size_limit=0"),
            "journal_size_limit=0 is the belt for the WAL-fallback case")
        assertTrue(Regex("""sqlite3_busy_timeout\(db,\s*2500\)""").containsMatchIn(swift),
            "the bridge must set the busy timeout IosVaultDatabase.BRIDGE_BUSY_TIMEOUT_MS restores")
    }

    @Test
    fun theIosVaultReadsTheModeBackAndRetriesAtWriteBoundaries() {
        val ios = source(IOS_VAULT)
        assertTrue(ios.contains("BRIDGE_BUSY_TIMEOUT_MS = 2500L"),
            "the Kotlin restore value must equal the bridge's sqlite3_busy_timeout")
        assertTrue(ios.contains("PRAGMA journal_mode = TRUNCATE"),
            "IosVaultDatabase must re-issue and READ BACK the journal mode, not trust the bridge")
        assertTrue(ios.contains("PRAGMA wal_checkpoint(TRUNCATE)"),
            "an unproven switch must at least run a verified TRUNCATE checkpoint")

        // Ordering inside init: proven BEFORE the first schema write.
        val initBody = ios.substring(ios.indexOf("init {"))
        val enforceAt = initBody.indexOf("enforceRollbackJournal()")
        val createAt = initBody.indexOf("createTables()")
        assertTrue(enforceAt in 0 until createAt,
            "enforceRollbackJournal() must run in init before createTables()")

        // Every boundary that persists ratchet state (or ends a transaction) retries.
        for (fn in listOf("putMeta", "deleteMeta", "withTransaction", "rekey", "close")) {
            assertTrue(bodyOf(ios, fn).contains("afterWriteBoundary()"),
                "$fn must be a RUN-02 write boundary (afterWriteBoundary())")
        }
        // withTransaction: AFTER the commit, i.e. in the finally, not inside the block.
        val txn = bodyOf(ios, "withTransaction")
        assertTrue(txn.indexOf("afterWriteBoundary()") > txn.indexOf("COMMIT"),
            "the withTransaction boundary must follow COMMIT — a mode switch is refused inside a transaction")

        // The state fields must be declared above init (Kotlin initialisation order).
        val fieldAt = ios.indexOf("private var rollbackJournalUnproven")
        assertTrue(fieldAt in 0 until ios.indexOf("init {"),
            "rollbackJournalUnproven must be declared ABOVE init, or its initialiser resets it")
    }

    @Test
    fun noVaultConnectionOnEitherPlatformEverSelectsWalOrPersist() {
        for ((label, src) in listOf(
            "SwiftDatabaseBridge" to source(SWIFT_BRIDGE),
            "IosVaultDatabase" to source(IOS_VAULT),
            "DatabaseManager" to source(ANDROID_VAULT),
        )) {
            for (m in JOURNAL_MODE_SET.findAll(src)) {
                assertTrue(m.groupValues[1].uppercase() in ALLOWED_MODES,
                    "$label sets journal_mode=${m.groupValues[1]} — only TRUNCATE/DELETE keep no superseded state")
            }
            assertFalse(src.contains("enableWriteAheadLogging("),
                "$label must never enable WAL")
            assertFalse(src.contains("ENABLE_WRITE_AHEAD_LOGGING"),
                "$label must never open with the WAL flag")
        }
    }

    @Test
    fun androidOpensWithTheWalFlagOff() {
        val android = source(ANDROID_VAULT)
        assertTrue(
            Regex("""SQLiteOpenHelper\(\s*context,\s*DATABASE_NAME,\s*password,\s*null,\s*DATABASE_VERSION,\s*0,\s*null,\s*null,\s*false\s*\)""")
                .containsMatchIn(android),
            "SecureDbHelper must pass enableWriteAheadLogging=false: sqlcipher-android then runs " +
                "journal_mode=delete (rollback journal). RUN-02.",
        )
    }

    /** The detectors must be able to fire — a guard that cannot reads as coverage. */
    @Test
    fun theDetectorActuallyDetects() {
        val bad = listOf(
            "sqlite3_exec(db, \"PRAGMA journal_mode=WAL;\", nil, nil, nil)",
            "queryRows(\"PRAGMA journal_mode = PERSIST\")",
            "db.rawQuery(\"PRAGMA journal_mode=wal\", null)",
        )
        for (s in bad) {
            val m = JOURNAL_MODE_SET.find(s)
            assertTrue(m != null && m.groupValues[1].uppercase() !in ALLOWED_MODES, "missed: $s")
        }
        val good = listOf(
            "sqlite3_exec(db, \"PRAGMA journal_mode=TRUNCATE;\", nil, nil, nil)",
            "queryRows(\"PRAGMA journal_mode = TRUNCATE\")",
        )
        for (s in good) {
            val m = JOURNAL_MODE_SET.find(s)
            assertTrue(m != null && m.groupValues[1].uppercase() in ALLOWED_MODES, "false positive: $s")
        }
        // The read-only form is not a SET and must not be matched.
        assertEquals(null, JOURNAL_MODE_SET.find("queryRows(\"PRAGMA journal_mode\")"))
        assertTrue(bodyOf("fun putMeta(k: String) { x(); afterWriteBoundary() }\n fun other() {}", "putMeta")
            .contains("afterWriteBoundary()"))
        assertFalse(bodyOf("fun putMeta(k: String) { x() }\n fun other() { afterWriteBoundary() }", "putMeta")
            .contains("afterWriteBoundary()"))
    }

    // -----------------------------------------------------------------------

    /** Brace-matched body of the first `fun <name>(` in [src]. */
    private fun bodyOf(src: String, name: String): String {
        val at = Regex("""fun\s+$name\s*\(""").find(src)?.range?.first
            ?: throw AssertionError("fun $name not found — the guard must never silently scan nothing")
        val open = src.indexOf('{', at)
        var depth = 0
        for (i in open until src.length) {
            when (src[i]) {
                '{' -> depth++
                '}' -> { depth--; if (depth == 0) return src.substring(open, i + 1) }
            }
        }
        throw AssertionError("unbalanced braces after fun $name")
    }

    /** File text with comments stripped, so prose ABOUT WAL cannot trip the guard. */
    private fun source(path: String): String {
        val f = File(repoRoot(), path)
        assertTrue(f.isFile, "scanned source is missing: $path")
        return f.readText().replace(BLOCK_COMMENT, " ").replace(LINE_COMMENT, " ")
    }

    private fun repoRoot(): File {
        var d: File? = File("").absoluteFile
        while (d != null) {
            if (File(d, "settings.gradle.kts").isFile) return d
            d = d.parentFile
        }
        throw AssertionError("repo root not found above ${File("").absoluteFile}")
    }

    private companion object {
        const val SWIFT_BRIDGE = "iosApp/iosApp/SwiftDatabaseBridge.swift"
        const val IOS_VAULT = "shared/src/iosMain/kotlin/com/vg/run/IosVaultDatabase.kt"
        const val ANDROID_VAULT = "shared/src/androidMain/kotlin/com/vg/run/DatabaseManager.kt"

        /** Rollback modes that empty the sidecar at commit. */
        val ALLOWED_MODES = setOf("TRUNCATE", "DELETE")

        /** `journal_mode = <word>` — the SET form only (the read-back has no `=`). */
        val JOURNAL_MODE_SET = Regex("""journal_mode\s*=\s*([A-Za-z]+)""", RegexOption.IGNORE_CASE)

        val BLOCK_COMMENT = Regex("""/\*.*?\*/""", RegexOption.DOT_MATCHES_ALL)
        val LINE_COMMENT = Regex("""//[^\n]*""")
    }
}

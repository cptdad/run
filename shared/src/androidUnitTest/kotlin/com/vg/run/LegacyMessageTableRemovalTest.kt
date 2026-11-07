package com.vg.run

import java.io.File
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// v9 (2026-09-15) — the vault has NO message table, on EITHER platform.
//
// Until a933616e (2026-05-24) both actuals wrote every message into it
// (`RunViewModel.kt:201` / `IosAppController.kt:177` called `vault.insertMessage`).
// That commit removed the writer and left the table, so the store listing's
// "messages live in memory only — they are never written to disk" was true of the
// CODE and false of a vault provisioned by an older build: the rows were still
// there, under a key one compelled PIN recovers. v9 destroys the table on open.
//
// This is a SOURCE guard, and deliberately so: the property is "nowhere", not
// "here". A behavioural test can only cover the schema as it exists today, which
// is exactly how a message table gets re-added later "just for the cache". The
// behavioural halves are the instrumented `LegacyMessagesMigrationTest` (Android,
// real SQLCipher v8 → v9 fixture) and `IosLegacyMessagesDropTest` (iosTest,
// scripted bridge) — neither can run in the JVM suite, and neither can prove
// absence across files.
//
// It lives in androidUnitTest because that is the only JVM test source set that
// can see `DatabaseManager.DATABASE_VERSION` (internal to :shared) — the same
// reason `MigrationSchemaPinTest` lives here.
// ---------------------------------------------------------------------------
class LegacyMessageTableRemovalTest {

    @Test
    fun schemaVersionIsAtLeastTheMessagesDropMigration() {
        assertTrue(
            DatabaseManager.DATABASE_VERSION >= MESSAGES_DROP_SCHEMA_VERSION,
            "DATABASE_VERSION must never go below $MESSAGES_DROP_SCHEMA_VERSION — that number is " +
                "what runs the DROP of the legacy `Messages` table on existing vaults.",
        )
    }

    @Test
    fun neitherVaultImplementationCreatesAMessageTable() {
        for ((label, src) in vaultSources()) {
            assertFalse(
                CREATES_MESSAGE_TABLE.containsMatchIn(src),
                "$label must not CREATE a message table. Messages are RAM-only; a table is " +
                    "somewhere for them to end up, and the last one silently kept years of " +
                    "them in vaults provisioned before 2026-05-24.",
            )
        }
    }

    @Test
    fun neitherVaultImplementationReadsOrWritesAMessageTable() {
        for ((label, src) in vaultSources()) {
            assertFalse(
                TOUCHES_MESSAGE_TABLE.containsMatchIn(src),
                "$label must not reference a message table in SQL — the v9 DROP is the only " +
                    "statement allowed to name it.",
            )
            assertFalse(
                src.contains("TABLE_MESSAGES"),
                "$label must not reintroduce the TABLE_MESSAGES constant.",
            )
        }
    }

    @Test
    fun bothVaultImplementationsDropTheLegacyTable() {
        val android = source(ANDROID_VAULT)
        assertTrue(
            Regex("""oldVersion\s*<\s*9""").containsMatchIn(android),
            "DatabaseManager.onUpgrade must carry the `oldVersion < 9` step.",
        )
        assertTrue(
            Regex("""DROP\s+TABLE\s+IF\s+EXISTS\s+Messages""", RegexOption.IGNORE_CASE)
                .containsMatchIn(android),
            "DatabaseManager.onUpgrade must DROP the legacy `Messages` table.",
        )
        assertTrue(
            android.contains("VACUUM"),
            "DatabaseManager must VACUUM after the drop — secure_delete zeroes freed pages at " +
                "free time; VACUUM is what returns them to the OS. It cannot run inside " +
                "onUpgrade (SQLiteOpenHelper wraps it in a transaction), so it runs at the end " +
                "of init, gated on the migration having fired.",
        )

        val ios = source(IOS_VAULT)
        assertTrue(
            Regex("""DROP\s+TABLE\s+IF\s+EXISTS\s+messages""", RegexOption.IGNORE_CASE)
                .containsMatchIn(ios),
            "IosVaultDatabase must DROP the legacy `messages` table — iOS has no user_version " +
                "counter, so the drop in the idempotent-create schema IS the migration.",
        )
        assertTrue(
            ios.contains("sqlite_master"),
            "IosVaultDatabase must probe sqlite_master before dropping, so the VACUUM (a whole " +
                "file rewrite) is paid only by a vault that actually held the table.",
        )
        assertTrue(
            ios.contains("VACUUM"),
            "IosVaultDatabase must VACUUM after the drop, outside any transaction.",
        )
    }

    /**
     * The detector must be able to fire. A guard that cannot is worse than none,
     * because it reads as coverage. (Fabricated source, both platforms' spelling.)
     */
    @Test
    fun theDetectorActuallyDetects() {
        val positives = listOf(
            "db.execSQL(\"CREATE TABLE Messages (messageId TEXT)\")",
            "exec(\"CREATE TABLE IF NOT EXISTS messages (message_id TEXT PRIMARY KEY)\")",
        )
        for (src in positives) {
            assertTrue(CREATES_MESSAGE_TABLE.containsMatchIn(src), "detector missed: $src")
        }
        val touches = listOf(
            "exec(\"DELETE FROM messages WHERE contact_id = ?\", contactId)",
            "exec(\"INSERT INTO messages (message_id) VALUES (?)\", id)",
            "queryRows(\"SELECT * FROM messages WHERE contact_id = ?\", contactId)",
        )
        for (src in touches) {
            assertTrue(TOUCHES_MESSAGE_TABLE.containsMatchIn(src), "detector missed: $src")
        }
        val negatives = listOf(
            // The one statement that is allowed to name it.
            "exec(\"DROP TABLE IF EXISTS messages\")",
            "db.execSQL(\"DROP TABLE IF EXISTS Messages\")",
            // Unrelated tables whose names merely contain the word.
            "exec(\"CREATE TABLE IF NOT EXISTS contacts (contact_id TEXT PRIMARY KEY)\")",
        )
        for (src in negatives) {
            assertFalse(
                CREATES_MESSAGE_TABLE.containsMatchIn(src) || TOUCHES_MESSAGE_TABLE.containsMatchIn(src),
                "detector false-positived on: $src",
            )
        }
    }

    // -----------------------------------------------------------------------

    private fun vaultSources(): List<Pair<String, String>> =
        listOf("DatabaseManager" to source(ANDROID_VAULT), "IosVaultDatabase" to source(IOS_VAULT))

    /** File text with comments stripped, so the prose ABOUT the removal cannot trip the guard. */
    private fun source(path: String): String {
        val f = File(repoRoot(), path)
        assertTrue(f.isFile, "scanned source is missing: $path")
        return f.readText().replace(BLOCK_COMMENT, " ").replace(LINE_COMMENT, " ")
    }

    /**
     * Walks up from the JVM working directory (Gradle sets it to the module dir)
     * to the directory holding `settings.gradle.kts`. Fails loudly rather than
     * returning a default: a guard that silently scans nothing passes forever.
     */
    private fun repoRoot(): File {
        var d: File? = File("").absoluteFile
        while (d != null) {
            if (File(d, "settings.gradle.kts").isFile) return d
            d = d.parentFile
        }
        throw AssertionError(
            "repo root not found above ${File("").absoluteFile} — this guard must never " +
                "silently scan nothing",
        )
    }

    private companion object {
        /** The schema version whose migration drops the table. Hard-coded on purpose:
         *  it is a historical fact about existing vaults, not a knob. */
        const val MESSAGES_DROP_SCHEMA_VERSION = 9

        const val ANDROID_VAULT = "shared/src/androidMain/kotlin/com/vg/run/DatabaseManager.kt"
        const val IOS_VAULT = "shared/src/iosMain/kotlin/com/vg/run/IosVaultDatabase.kt"

        val BLOCK_COMMENT = Regex("""/\*.*?\*/""", RegexOption.DOT_MATCHES_ALL)
        val LINE_COMMENT = Regex("""//[^\n]*""")

        /** `CREATE TABLE [IF NOT EXISTS] messages` in either platform's spelling. */
        val CREATES_MESSAGE_TABLE = Regex(
            """CREATE\s+TABLE\s+(IF\s+NOT\s+EXISTS\s+)?[`"\[]?messages\b""",
            RegexOption.IGNORE_CASE,
        )

        /** Any SQL that reads from or writes to it. DROP is deliberately NOT matched. */
        val TOUCHES_MESSAGE_TABLE = Regex(
            """(FROM|INTO|UPDATE)\s+[`"\[]?messages\b""",
            RegexOption.IGNORE_CASE,
        )
    }
}

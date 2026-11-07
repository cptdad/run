package com.vg.run

import java.io.File
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// DB v10 (2026-09-24) — the GROUP-text channel's counter columns, on BOTH actuals.
//
// `ContactRecord.outboundGrpCounter` / `inboundGrpCounter` are the anti-replay
// counter space of the third pairwise inbox (MessageManager.Chan.GRP). They are
// RAM-only until both `VaultDatabase` actuals persist them, and the failure mode
// of a half-done migration is silent and one-sided: the OUTBOUND counter resets
// to 0 on every relaunch, so the peer's strict-monotonic check drops every group
// message after the first restart, forever, with no error on either device.
//
// A SOURCE guard because the property is "on both platforms": iOS has no schema
// counter at all (idempotent ALTER) and cannot be reached from a JVM test, so
// there is no behavioural place to assert Android and iOS agree. The behavioural
// halves are the instrumented `LegacyContactsMigrationTest` (real v9 → v10
// SQLCipher fixture) and the commonTest suites over `MigrationBundle` /
// `VaultSnapshotIo`.
//
// androidUnitTest, like its siblings `MigrationSchemaPinTest` and
// `LegacyMessageTableRemovalTest`, because that is the only JVM source set that
// can see `DatabaseManager.DATABASE_VERSION` (internal to :shared).
// ---------------------------------------------------------------------------
class GroupCounterSchemaPinTest {

    @Test
    fun schemaVersionIsAtLeastTheGroupCounterMigration() {
        assertTrue(
            DatabaseManager.DATABASE_VERSION >= GRP_COUNTER_SCHEMA_VERSION,
            "DATABASE_VERSION must never go below $GRP_COUNTER_SCHEMA_VERSION — that number is " +
                "what runs the ALTER that gives an existing vault its group counters.",
        )
    }

    @Test
    fun androidCarriesBothColumnsInTheCreateAndInAnAdditiveUpgradeStep() {
        val src = source(ANDROID_VAULT)
        assertTrue(
            Regex("""oldVersion\s*<\s*10""").containsMatchIn(src),
            "DatabaseManager.onUpgrade must carry the `oldVersion < 10` step, or a vault " +
                "provisioned by a v9 build never gets the columns and every contact read " +
                "throws on the missing column.",
        )
        for (col in ANDROID_COLUMNS) {
            assertTrue(
                src.contains("ADD COLUMN \$$col INTEGER NOT NULL DEFAULT 0"),
                "DatabaseManager.onUpgrade must ALTER in \$$col with DEFAULT 0 — the default " +
                    "IS the legacy read path (an existing row reads 0 = establish-on-read)",
            )
            // CREATE (fresh vaults), ALTER (existing vaults), insertContact and the
            // cursor mapper: four sites, so a column added to only one is caught.
            assertTrue(
                Regex(Regex.escape(col)).findAll(src).count() >= 4,
                "$col must appear in the CREATE DDL, the upgrade step, insertContact and the " +
                    "row mapper — a column written but never read (or vice versa) is silent loss",
            )
        }
        // Additive ONLY: this migration must never drop or rebuild the contacts
        // table — existing vaults must keep every contact.
        assertFalse(
            Regex("""DROP\s+TABLE\s+(IF\s+EXISTS\s+)?[`"\[]?Contacts\b""", RegexOption.IGNORE_CASE)
                .containsMatchIn(src),
            "the v10 migration is ALTER-only; dropping/rebuilding Contacts would destroy " +
                "every pairing in an existing vault",
        )
    }

    @Test
    fun iosCarriesBothColumnsInTheCreateAndInTheIdempotentAlterList() {
        val src = source(IOS_VAULT)
        for (col in IOS_COLUMNS) {
            assertTrue(
                src.contains("$col INTEGER NOT NULL DEFAULT 0"),
                "IosVaultDatabase must declare `$col INTEGER NOT NULL DEFAULT 0` — once in the " +
                    "CREATE TABLE and once in migrateContactsSchema's idempotent ALTER list; " +
                    "iOS has no user_version, so the ALTER IS the migration.",
            )
            // Twice: the CREATE (fresh vaults) and the ALTER list (existing vaults).
            // One occurrence means one of the two populations is left behind.
            assertTrue(
                Regex(Regex.escape(col)).findAll(src).count() >= 3,
                "$col must appear in the CREATE, in the ALTER list and in the row mapper",
            )
        }
        assertTrue(
            src.contains("outbound_grp_counter") && src.contains("INSERT OR REPLACE INTO contacts"),
            "IosVaultDatabase.insertContact must WRITE the group counters, not only read them",
        )
    }

    /**
     * The contact delete stays DIRECTION-AGNOSTIC on both actuals, which is the
     * single reason the third inbox pair costs nothing on the purge path (and the
     * reason a new direction can never leak an orphaned capability row).
     */
    @Test
    fun bothActualsPurgeInboxRowsByContactIdWithNoDirectionFilter() {
        for ((label, src) in vaultSources()) {
            assertTrue(
                DELETES_INBOXES_BY_CONTACT.containsMatchIn(src),
                "$label.deleteContact must delete inbox rows by contact_id ALONE",
            )
            assertFalse(
                DELETES_INBOXES_BY_DIRECTION.containsMatchIn(src),
                "$label must not filter the inbox purge by direction — every direction, " +
                    "including the v10 group pair, has to go with the contact",
            )
        }
    }

    /** A guard that cannot fire reads as coverage. (Fabricated source.) */
    @Test
    fun theDetectorActuallyDetects() {
        assertTrue(
            DELETES_INBOXES_BY_CONTACT.containsMatchIn(
                """db.delete(TABLE_INBOX_IDS, "${'$'}COL_CONTACT_ID = ?", arrayOf(contactId))"""
            ),
        )
        assertTrue(
            DELETES_INBOXES_BY_CONTACT.containsMatchIn("""exec("DELETE FROM inbox_ids WHERE contact_id = ?", contactId)"""),
        )
        assertTrue(
            DELETES_INBOXES_BY_DIRECTION.containsMatchIn(
                """exec("DELETE FROM inbox_ids WHERE contact_id = ? AND direction = ?", contactId, d)"""
            ),
        )
        assertFalse(
            DELETES_INBOXES_BY_DIRECTION.containsMatchIn("""exec("DELETE FROM inbox_ids WHERE contact_id = ?", contactId)"""),
        )
    }

    // -----------------------------------------------------------------------

    private fun vaultSources(): List<Pair<String, String>> =
        listOf("DatabaseManager" to source(ANDROID_VAULT), "IosVaultDatabase" to source(IOS_VAULT))

    /** File text with comments stripped, so prose about the columns cannot satisfy the guard. */
    private fun source(path: String): String {
        val f = File(repoRoot(), path)
        assertTrue(f.isFile, "scanned source is missing: $path")
        return f.readText().replace(BLOCK_COMMENT, " ").replace(LINE_COMMENT, " ")
    }

    /** Walks up to the directory holding `settings.gradle.kts`; fails loudly rather than scanning nothing. */
    private fun repoRoot(): File {
        var d: File? = File("").absoluteFile
        while (d != null) {
            if (File(d, "settings.gradle.kts").isFile) return d
            d = d.parentFile
        }
        throw AssertionError("repo root not found above ${File("").absoluteFile}")
    }

    private companion object {
        /** The schema version whose migration adds the columns. A historical fact, not a knob. */
        const val GRP_COUNTER_SCHEMA_VERSION = 10

        const val ANDROID_VAULT = "shared/src/androidMain/kotlin/com/vg/run/DatabaseManager.kt"
        const val IOS_VAULT = "shared/src/iosMain/kotlin/com/vg/run/IosVaultDatabase.kt"

        /** Android spells its columns camelCase; iOS spells the same data snake_case. */
        val ANDROID_COLUMNS = listOf("COL_OUTBOUND_GRP_COUNTER", "COL_INBOUND_GRP_COUNTER")
        val IOS_COLUMNS = listOf("outbound_grp_counter", "inbound_grp_counter")

        val BLOCK_COMMENT = Regex("""/\*.*?\*/""", RegexOption.DOT_MATCHES_ALL)
        val LINE_COMMENT = Regex("""//[^\n]*""")

        /** `DELETE FROM inbox_ids WHERE contact_id = ?` in either platform's spelling. */
        val DELETES_INBOXES_BY_CONTACT = Regex(
            """DELETE\s+FROM\s+inbox_ids\s+WHERE\s+contact_id\s*=\s*\?""" +
                """|delete\(\s*TABLE_INBOX_IDS\s*,\s*["][^"]*COL_CONTACT_ID\s*=\s*\?["]""",
            RegexOption.IGNORE_CASE,
        )

        /** The shape this migration must never grow: a direction-filtered purge. */
        val DELETES_INBOXES_BY_DIRECTION = Regex(
            """DELETE\s+FROM\s+inbox_ids\s+WHERE[^"]*direction""",
            RegexOption.IGNORE_CASE,
        )
    }
}

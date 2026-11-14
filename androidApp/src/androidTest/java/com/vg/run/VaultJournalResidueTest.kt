package com.vg.run

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import net.zetetic.database.sqlcipher.SQLiteDatabase
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/**
 * RUN-02 (2026-11-12) — superseded vault state must not be recoverable from the
 * on-disk file set with the CURRENT db key.
 *
 * The external review (iOS, SQLCipher 4.19.0): the Double Ratchet state is one `_meta` row
 * replaced on every step; in WAL mode the -wal keeps every replaced version, so an
 * attacker who images db + wal while the vault is OPEN and later obtains the db key
 * truncates the WAL to a frame prefix, opens that, and reads an old chain key. iOS
 * now runs a rollback journal (TRUNCATE); Android runs one too (`journal_mode=delete`,
 * because `DatabaseManager.SecureDbHelper` passes `enableWriteAheadLogging=false`).
 *
 * Three tests, deliberately in this order of argument:
 *  1. the ORACLE — the auditor's attack, reproduced on this exact SQLCipher build in
 *     a scratch WAL database: some WAL prefix yields the superseded value. Without
 *     this, test 3's "nothing old found" could be a broken detector.
 *  2. the live vault keeps NO -wal and no non-empty -journal between commits.
 *  3. the same prefix rebuild against a copy of the live vault's file set (taken
 *     while open, as in the review) recovers only the current value.
 *
 * Instrumented because SQLCipher is a native library with no JVM equivalent. The
 * cross-platform source pin is the JVM `VaultJournalModeSourceGuardTest`; the iOS
 * statement-sequence half is `IosRollbackJournalTest`.
 *
 * What this cannot show (stated, not claimed): physical erasure. A deleted/truncated
 * journal's blocks are freed, not overwritten, and flash may keep them below the
 * filesystem; and no test can revoke an image captured earlier.
 *
 * Run with: ./gradlew connectedAndroidTest — or, to preserve device state,
 * `am instrument` targeting this class.
 */
@RunWith(AndroidJUnit4::class)
class VaultJournalResidueTest {

    private lateinit var context: android.content.Context
    private lateinit var scratch: File

    private companion object {
        const val DATABASE_NAME = "run.db"
        const val META_KEY = "dr/c-1/text"

        /** Deliberately not the key any other test uses. */
        val TEST_DB_KEY = ByteArray(32) { (it + 41).toByte() }

        /** Distinctive, so a hit cannot be a coincidence. */
        val SUPERSEDED = "SUPERSEDED-CHAIN-KEY-" + "A".repeat(96)
        val CURRENT = "CURRENT-CHAIN-KEY-" + "B".repeat(96)

        /** WAL file header and per-frame header sizes (SQLite file format §4). */
        const val WAL_HEADER = 32
        const val WAL_FRAME_HEADER = 24
    }

    @Before
    fun setUp() {
        System.loadLibrary("sqlcipher")
        context = InstrumentationRegistry.getInstrumentation().targetContext
        context.deleteDatabase(DATABASE_NAME)
        scratch = File(context.cacheDir, "run02-journal-residue").apply { deleteRecursively(); mkdirs() }
    }

    @After
    fun tearDown() {
        context.deleteDatabase(DATABASE_NAME)
        scratch.deleteRecursively()
    }

    // -----------------------------------------------------------------------

    @Test
    fun oracle_walModeKeepsASupersededStateThatAPrefixRebuildRecovers() {
        val path = File(scratch, "oracle.db")
        val key = rawKeySpec(TEST_DB_KEY)
        val db = SQLiteDatabase.openDatabase(
            path.path, key.copyOf(), null,
            SQLiteDatabase.OPEN_READWRITE or SQLiteDatabase.CREATE_IF_NECESSARY or
                SQLiteDatabase.ENABLE_WRITE_AHEAD_LOGGING,
            null, null,
        )
        try {
            db.execSQL("CREATE TABLE IF NOT EXISTS _meta (key TEXT PRIMARY KEY, value TEXT)")
            db.execSQL("INSERT OR REPLACE INTO _meta (key, value) VALUES ('$META_KEY', '$SUPERSEDED')")
            db.execSQL("INSERT OR REPLACE INTO _meta (key, value) VALUES ('$META_KEY', '$CURRENT')")

            // Imaged while OPEN, exactly as in the review.
            val wal = File(path.path + "-wal")
            assertTrue("oracle precondition: WAL mode must have produced a non-empty -wal",
                wal.exists() && wal.length() > WAL_HEADER)
            val views = recoverableValues(path, wal, key)
            assertTrue("oracle: the full WAL must read the current value", CURRENT in views)
            assertTrue(
                "oracle: a WAL prefix must rebuild the SUPERSEDED value — if this fails the " +
                    "detector in vaultFileSet_prefixRebuildRecoversOnlyTheCurrentState is blind",
                SUPERSEDED in views,
            )
        } finally {
            db.close()
        }
    }

    @Test
    fun liveVault_keepsNoWalAndNoNonEmptyJournalBetweenCommits() {
        val vault = DatabaseManager(context, TEST_DB_KEY, isProvision = true)
        try {
            val base = context.getDatabasePath(DATABASE_NAME).path
            repeat(25) { i ->
                vault.putMeta(META_KEY, "$SUPERSEDED-$i")
                assertFalse("step $i: the vault must never run WAL (RUN-02)", File("$base-wal").exists())
                assertFalse("step $i: no WAL index either", File("$base-shm").exists())
                val journal = File("$base-journal")
                assertTrue(
                    "step $i: between commits the rollback journal must be gone or empty",
                    !journal.exists() || journal.length() == 0L,
                )
            }
            // Same through a multi-statement transaction.
            vault.withTransaction {
                vault.putMeta(META_KEY, CURRENT)
                vault.putMeta("dr-on/c-1", "1")
            }
            assertFalse(File("$base-wal").exists())
            val journal = File("$base-journal")
            assertTrue(!journal.exists() || journal.length() == 0L)
        } finally {
            vault.close()
        }
    }

    @Test
    fun vaultFileSet_prefixRebuildRecoversOnlyTheCurrentState() {
        val vault = DatabaseManager(context, TEST_DB_KEY, isProvision = true)
        try {
            vault.putMeta(META_KEY, SUPERSEDED)
            vault.putMeta(META_KEY, CURRENT)

            // Imaged while OPEN: whatever sidecars exist right now go into the copy.
            val db = context.getDatabasePath(DATABASE_NAME)
            val wal = File(db.path + "-wal")
            assertFalse("the vault must have no -wal to rebuild a prefix from", wal.exists())
            val views = recoverableValues(db, wal, TEST_DB_KEY)
            assertTrue("the copy must open and show the current state (non-vacuous)", CURRENT in views)
            assertFalse(
                "a superseded ratchet state must not be recoverable from the vault's file set " +
                    "with the current key (RUN-02)",
                SUPERSEDED in views,
            )
            assertEquals(setOf(CURRENT), views)
        } finally {
            vault.close()
        }
    }

    // -----------------------------------------------------------------------

    /**
     * Every `_meta[META_KEY]` value an attacker holding [key] can read from a copy of
     * [db] plus every frame-aligned prefix of [wal] (prefix 0 = the db alone). SQLite's
     * WAL recovery stops at the last valid COMMIT frame of a prefix, so each prefix
     * is an earlier committed view — the review's technique.
     */
    private fun recoverableValues(db: File, wal: File, key: ByteArray): Set<String> {
        val dbBytes = db.readBytes()
        val walBytes = if (wal.exists()) wal.readBytes() else ByteArray(0)
        val prefixes = mutableListOf(0)
        if (walBytes.size > WAL_HEADER) {
            val pageSize = ((walBytes[8].toInt() and 0xFF) shl 24) or ((walBytes[9].toInt() and 0xFF) shl 16) or
                ((walBytes[10].toInt() and 0xFF) shl 8) or (walBytes[11].toInt() and 0xFF)
            val frame = WAL_FRAME_HEADER + pageSize
            val frames = (walBytes.size - WAL_HEADER) / frame
            for (k in 1..frames) prefixes += WAL_HEADER + k * frame
        }
        val found = mutableSetOf<String>()
        for ((i, len) in prefixes.withIndex()) {
            val dir = File(scratch, "view-$i").apply { deleteRecursively(); mkdirs() }
            val copy = File(dir, "v.db").apply { writeBytes(dbBytes) }
            if (len > 0) File(copy.path + "-wal").writeBytes(walBytes.copyOf(len))
            var h: SQLiteDatabase? = null
            try {
                h = SQLiteDatabase.openDatabase(copy.path, key.copyOf(), null, SQLiteDatabase.OPEN_READWRITE, null, null)
                h.rawQuery("SELECT value FROM _meta WHERE key = '$META_KEY'", null).use { c ->
                    if (c.moveToFirst()) found += c.getString(0)
                }
            } catch (_: Throwable) {
                // A prefix that does not open is simply not a view.
            } finally {
                try { h?.close() } catch (_: Throwable) { }
            }
        }
        return found
    }

    /** `x'<64 hex>'` — SQLCipher's raw-key form, so the oracle's many opens skip PBKDF2. */
    private fun rawKeySpec(k: ByteArray): ByteArray =
        ("x'" + k.joinToString("") { "%02x".format(it.toInt() and 0xFF) } + "'").toByteArray(Charsets.US_ASCII)
}

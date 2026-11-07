package com.vg.run

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import net.zetetic.database.sqlcipher.SQLiteDatabase
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/**
 * `PRAGMA cipher_memory_security = ON` must actually TAKE
 * EFFECT, not merely be issued.
 *
 * Why this test exists rather than trusting the `execSQL` line in
 * `DatabaseManager`: a pragma the binding silently swallows is strictly worse
 * than one that was never added, because the page-cache scrub would then be
 * recorded as mitigated while nothing scrubs anything. Two ways it could
 * silently no-op — a `sqlite3_config` failure at init (the wrapper is never
 * installed), or a future `sqlcipher-android` bump that stops routing unknown
 * pragmas to SQLCipher's own handler — and neither throws.
 *
 * SQLCipher provides the exact primitive to detect both. The NO-ARGUMENT form
 * of the pragma returns one row whose value is
 * `sqlcipher_mem_security_on && sqlcipher_mem_executed`. The second conjunct is
 * set only once `sqlcipher_mem_malloc`/`_free` have genuinely run, so `1` proves
 * the flag is set AND the allocator wrapper is installed and executing; `0` is
 * precisely the silent-no-op signal.
 *
 * Note the two different APIs, which is itself a trap: the ASSIGNMENT form emits
 * no result column (so `execSQL` is correct in DatabaseManager, and `rawQuery`
 * would be wrong), while this READ-BACK form does return a row (so `rawQuery` is
 * correct here, and `execSQL` would hit the binding's native "Queries can be
 * performed using query or rawQuery only" refusal).
 *
 * The flag is process-global and ONE-WAY — SQLCipher exposes no "off" — so this
 * cannot be asserted per-connection or reset between tests. It also means a
 * stale process would report `1` even if production dropped the call; that is
 * why this test opens its OWN connection and issues the pragma itself, verifying
 * the mechanism rather than a leftover from whichever test ran first.
 *
 * Instrumented because SQLCipher is a native library with no JVM equivalent.
 */
@RunWith(AndroidJUnit4::class)
class CipherMemorySecurityTest {

    private lateinit var dbFile: File

    @Before
    fun setUp() {
        System.loadLibrary("sqlcipher")
        val ctx = InstrumentationRegistry.getInstrumentation().targetContext
        dbFile = File(ctx.cacheDir, "cipher_mem_security_probe.db")
        dbFile.delete()
    }

    @After
    fun tearDown() {
        dbFile.delete()
    }

    @Test
    fun pragmaIsAcceptedAndTheAllocatorWrapperIsActuallyInstalled() {
        val key = ByteArray(32) { (it + 7).toByte() }
        val db = SQLiteDatabase.openOrCreateDatabase(dbFile.absolutePath, key, null, null)
        try {
            // Assignment form: no result row, so execSQL — exactly as production does.
            db.execSQL("PRAGMA cipher_memory_security = ON")

            // Force real allocator traffic through the wrapper, so `mem_executed`
            // is set for reasons this test caused rather than by luck of ordering.
            db.execSQL("CREATE TABLE t (id INTEGER PRIMARY KEY, blob BLOB)")
            db.execSQL("INSERT INTO t (blob) VALUES (?)", arrayOf<Any>(ByteArray(4096) { 0x5A }))

            val readBack = db.rawQuery("PRAGMA cipher_memory_security", null).use { c ->
                if (c.moveToFirst()) c.getString(0) else null
            }

            assertEquals(
                "cipher_memory_security read-back must be 1 — 0 means the flag is set but " +
                    "SQLCipher's allocator wrapper was never installed (sqlite3_config failed), " +
                    "and null means the binding swallowed the pragma instead of routing it to " +
                    "SQLCipher's handler. Either way the page-cache scrub the PRAGMA claims is NOT " +
                    "happening, and the documented guarantee is wrong.",
                "1",
                readBack,
            )
        } finally {
            db.close()
        }
    }
}

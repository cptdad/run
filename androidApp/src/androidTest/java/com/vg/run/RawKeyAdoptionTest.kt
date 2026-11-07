package com.vg.run

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import net.zetetic.database.sqlcipher.SQLiteDatabase
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * THE GATE for Android's raw-key adoption (2026-10-07): before any vault is ever
 * opened with an adopted raw key, prove on a REAL SQLCipher file that
 *
 *   a vault created in PASSPHRASE mode with key R opens, byte-for-byte unchanged,
 *   with the raw keyspec `x'<K'>'` where K' = PBKDF2-HMAC-SHA512(R, fileSalt, 256000, 32)
 *
 * — and the reverse (a raw-created file opens in passphrase mode), that pages
 * written by either mode are readable (and `cipher_integrity_check`-clean) in the
 * other (this is what lets the recovery-code path keep opening in passphrase mode
 * after adoption), that a wrong K' fails without touching the file, and that the
 * re-key still works from a raw-opened handle.
 *
 * If SQLCipher derived the page-HMAC key differently in raw mode, test 1 fails at
 * the very first open and the whole adoption design is void — that is the point.
 *
 * K' is computed here by an INDEPENDENT PBKDF2 implementation and compared with the
 * production `VaultFactory.deriveAdoptedRawKey`, so the production helper is checked
 * against both this oracle and SQLCipher itself.
 *
 * Timings are logged (no assertion): `adb logcat -d -s RawKeyAdoption`.
 *
 * Run: ANDROID_SERIAL=<serial> ./gradlew :androidApp:connectedDebugAndroidTest \
 *      -Pandroid.testInstrumentationRunnerArguments.class=com.vg.run.RawKeyAdoptionTest
 * (connectedAndroidTest uninstalls the app afterwards — reinstall the debug APK.)
 */
@RunWith(AndroidJUnit4::class)
class RawKeyAdoptionTest {

    private val tag = "RawKeyAdoption"
    private lateinit var context: android.content.Context
    private val rnd = SecureRandom()

    private companion object {
        const val DATABASE_NAME = "run.db"
        const val RAW_CREATED_NAME = "adopt-raw-created.db"
        const val KDF_ITER = 256_000
    }

    @Before
    fun setUp() {
        System.loadLibrary("sqlcipher")
        context = InstrumentationRegistry.getInstrumentation().targetContext
        context.deleteDatabase(DATABASE_NAME)
        context.deleteDatabase(RAW_CREATED_NAME)
    }

    @After
    fun tearDown() {
        context.deleteDatabase(DATABASE_NAME)
        context.deleteDatabase(RAW_CREATED_NAME)
    }

    // --- independent oracle ------------------------------------------------------

    /** RFC 8018 PBKDF2-HMAC-SHA512, one block — written independently of the shared helper. */
    private fun oraclePbkdf2(pw: ByteArray, salt: ByteArray, iter: Int): ByteArray {
        val mac = Mac.getInstance("HmacSHA512").apply { init(SecretKeySpec(pw, "HmacSHA512")) }
        var u = mac.doFinal(salt + byteArrayOf(0, 0, 0, 1))
        val t = u.copyOf()
        repeat(iter - 1) {
            u = mac.doFinal(u)
            for (j in t.indices) t[j] = (t[j].toInt() xor u[j].toInt()).toByte()
        }
        return t.copyOf(32)
    }

    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
    private fun rawSpec(k: ByteArray) = "x'${hex(k)}'".toByteArray(Charsets.US_ASCII)
    private fun rawSpecWithSalt(k: ByteArray, salt: ByteArray) =
        "x'${hex(k)}${hex(salt)}'".toByteArray(Charsets.US_ASCII)

    private fun dbFile(name: String = DATABASE_NAME): File = context.getDatabasePath(name)
    private fun fileSalt(name: String = DATABASE_NAME): ByteArray =
        dbFile(name).inputStream().use { s -> ByteArray(16).also { assertEquals(16, s.read(it)) } }
    private fun fileHash(name: String = DATABASE_NAME): String =
        hex(MessageDigest.getInstance("SHA-256").digest(dbFile(name).readBytes()))

    private fun openRaw(pass: ByteArray, flags: Int, name: String = DATABASE_NAME): SQLiteDatabase =
        SQLiteDatabase.openDatabase(dbFile(name).path, pass, null, flags, null, null)

    /** `PRAGMA cipher_integrity_check` → no rows means every page's HMAC verified. */
    private fun cipherIntegrityErrors(db: SQLiteDatabase): List<String> =
        db.rawQuery("PRAGMA cipher_integrity_check", null).use { c ->
            buildList { while (c.moveToNext()) add(c.getString(0)) }
        }

    private fun sqliteIntegrity(db: SQLiteDatabase): String =
        db.rawQuery("PRAGMA integrity_check", null).use { c -> c.moveToFirst(); c.getString(0) }

    private fun metaRows(db: SQLiteDatabase): Map<String, String> =
        db.rawQuery("SELECT key, value FROM _meta", null).use { c ->
            buildMap { while (c.moveToNext()) put(c.getString(0), c.getString(1)) }
        }

    private fun timeMs(block: () -> Unit): Double {
        val t = System.nanoTime(); block(); return (System.nanoTime() - t) / 1e6
    }

    /** A real vault, created by the production provision open (passphrase mode), with
     *  enough rows to span many pages so a full read exercises many page HMACs. */
    private fun provisionPassphraseVault(r: ByteArray): Map<String, String> {
        val dm = DatabaseManager(context, r, isProvision = true)
        val written = (0 until 400).associate { i -> "adopt/$i" to "v$i-" + "x".repeat(200) }
        dm.withTransaction { written.forEach { (k, v) -> dm.putMeta(k, v) } }
        dm.close()
        return written
    }

    // --- 1. THE proof ------------------------------------------------------------

    @Test
    fun passphraseCreatedVault_opensUnchangedWithRawKeyDerivedFromFileSalt() {
        val r = ByteArray(32).also { rnd.nextBytes(it) }
        val written = provisionPassphraseVault(r)
        val factory = androidVaultFactory(context)

        val salt = fileSalt()
        val kOracle = oraclePbkdf2(r, salt, KDF_ITER)
        var kProd: ByteArray? = null
        val deriveMs = timeMs { kProd = factory.deriveAdoptedRawKey(r) }
        assertNotNull("production derivation must read the salt of an existing vault", kProd)
        assertArrayEquals("production K' must equal the independent PBKDF2 oracle", kOracle, kProd)

        val before = fileHash()
        // Read-only raw open: proves the raw key OPENS the file and writes nothing.
        openRaw(rawSpec(kOracle), SQLiteDatabase.OPEN_READONLY).use { db ->
            assertEquals("every page HMAC must verify under the raw key",
                emptyList<String>(), cipherIntegrityErrors(db))
            assertEquals("ok", sqliteIntegrity(db))
            val rows = metaRows(db)
            written.forEach { (k, v) -> assertEquals("full read under raw key: $k", v, rows[k]) }
        }
        assertEquals("a raw-key open must leave the file byte-for-byte unchanged", before, fileHash())

        assertTrue("probeRawKey(K') must open the real vault", factory.probeRawKey(kOracle))
        assertTrue("passphrase probe must still open it", factory.probeKey(r))

        // Production open path in raw mode (DatabaseManager init: schema check, PRAGMAs).
        factory.createWithRawKey(kOracle).let { v ->
            assertEquals(written["adopt/123"], v.getMeta("adopt/123"))
            v.close()
        }
        Log.i(tag, "RESULT | derive K' (production PBKDF2-HMAC-SHA512 x$KDF_ITER) | %.1f ms".format(deriveMs))
    }

    // --- 2. pages written by a RAW handle read back in PASSPHRASE mode -----------

    @Test
    fun pagesWrittenThroughRawHandle_areReadableAndHmacValidInPassphraseMode() {
        val r = ByteArray(32).also { rnd.nextBytes(it) }
        val written = provisionPassphraseVault(r)
        val factory = androidVaultFactory(context)
        val k = factory.deriveAdoptedRawKey(r)!!

        val rawWritten = (0 until 600).associate { i -> "raw/$i" to "w$i-" + "y".repeat(180) }
        factory.createWithRawKey(k).let { v ->
            v.withTransaction { rawWritten.forEach { (kk, vv) -> v.putMeta(kk, vv) } }
            v.deleteMeta("adopt/7")   // frees/rewrites pages too (secure_delete is on)
            v.close()
        }

        // The recovery-code path keeps opening in PASSPHRASE mode after adoption: it
        // must see every page the raw-mode session wrote.
        openRaw(r.copyOf(), SQLiteDatabase.OPEN_READONLY).use { db ->
            assertEquals(emptyList<String>(), cipherIntegrityErrors(db))
            assertEquals("ok", sqliteIntegrity(db))
            val rows = metaRows(db)
            rawWritten.forEach { (kk, vv) -> assertEquals(vv, rows[kk]) }
            assertFalse(rows.containsKey("adopt/7"))
            assertEquals(written["adopt/8"], rows["adopt/8"])
        }
        // And through the production passphrase open.
        DatabaseManager(context, r, isProvision = false).let { v ->
            assertEquals(rawWritten["raw/599"], v.getMeta("raw/599"))
            v.close()
        }
        assertArrayEquals("no write may change the file salt", k,
            oraclePbkdf2(r, fileSalt(), KDF_ITER))
    }

    // --- 3. vice versa: a RAW-created file opens in PASSPHRASE mode --------------

    @Test
    fun rawCreatedVaultWithExplicitSalt_opensInPassphraseMode() {
        val r = ByteArray(32).also { rnd.nextBytes(it) }
        val salt = ByteArray(16).also { rnd.nextBytes(it) }
        val k = oraclePbkdf2(r, salt, KDF_ITER)
        dbFile(RAW_CREATED_NAME).parentFile?.mkdirs()
        openRaw(rawSpecWithSalt(k, salt),
            SQLiteDatabase.OPEN_READWRITE or SQLiteDatabase.CREATE_IF_NECESSARY, RAW_CREATED_NAME).use { db ->
            db.execSQL("CREATE TABLE _meta (key TEXT PRIMARY KEY, value TEXT)")
            db.beginTransaction()
            try {
                for (i in 0 until 300) db.execSQL("INSERT INTO _meta VALUES (?, ?)", arrayOf<Any>("k$i", "v$i".repeat(40)))
                db.setTransactionSuccessful()
            } finally { db.endTransaction() }
        }
        assertArrayEquals("the explicit salt must be what the header carries", salt, fileSalt(RAW_CREATED_NAME))
        openRaw(r.copyOf(), SQLiteDatabase.OPEN_READONLY, RAW_CREATED_NAME).use { db ->
            assertEquals(emptyList<String>(), cipherIntegrityErrors(db))
            assertEquals("ok", sqliteIntegrity(db))
            assertEquals("v299".repeat(40), metaRows(db)["k299"])
        }
        // ...and with the salt-less raw spec (salt read from the file), as unlock does.
        openRaw(rawSpec(k), SQLiteDatabase.OPEN_READONLY, RAW_CREATED_NAME).use { db ->
            assertEquals(emptyList<String>(), cipherIntegrityErrors(db))
        }
    }

    // --- 4. a WRONG raw key fails without touching the file ----------------------

    @Test
    fun wrongRawKey_failsNonDestructively() {
        val r = ByteArray(32).also { rnd.nextBytes(it) }
        provisionPassphraseVault(r)
        val factory = androidVaultFactory(context)
        val k = factory.deriveAdoptedRawKey(r)!!
        val wrong = k.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        val before = fileHash()

        assertFalse(factory.probeRawKey(wrong))
        try {
            factory.createWithRawKey(wrong).close()
            fail("a wrong raw key must not open the vault")
        } catch (_: Throwable) { /* expected: NOTADB, never a delete */ }
        // The passphrase itself is NOT a raw key (and vice versa): mode confusion fails closed.
        assertFalse("R must not open as a raw key", factory.probeRawKey(r))
        assertFalse("K' must not open as a passphrase", factory.probeKey(k))

        assertTrue("the vault file must survive every failed open", dbFile().exists())
        assertEquals("…byte-for-byte", before, fileHash())
        assertTrue(factory.probeKey(r))
        assertTrue(factory.probeRawKey(k))
    }

    // --- 5. Re-key from a RAW-opened handle -----------------------------------

    @Test
    fun rekeyFromRawHandle_movesFileToNewPassphraseAndReAdopts() {
        val r = ByteArray(32).also { rnd.nextBytes(it) }
        val written = provisionPassphraseVault(r)
        val factory = androidVaultFactory(context)
        val k = factory.deriveAdoptedRawKey(r)!!
        val saltBefore = fileSalt()
        val r2 = ByteArray(32).also { rnd.nextBytes(it) }

        val v = factory.createWithRawKey(k)
        assertTrue("rekey reports no visible error", v.rekey(r2))
        v.close()

        assertTrue("new passphrase opens after a rekey from a raw handle", factory.probeKey(r2))
        assertFalse("old passphrase no longer opens", factory.probeKey(r))
        assertFalse("old raw key no longer opens", factory.probeRawKey(k))
        val k2 = factory.deriveAdoptedRawKey(r2)!!
        assertTrue("the rotated vault can itself be adopted", factory.probeRawKey(k2))
        DatabaseManager(context, r2).let { dm ->
            assertEquals(written["adopt/42"], dm.getMeta("adopt/42")); dm.close()
        }
        Log.i(tag, "RESULT | rekey keeps file salt | ${saltBefore.contentEquals(fileSalt())}")
    }

    // --- 6. timings on the SAME file ------------------------------------------------

    @Test
    fun timing_passphraseVsRawOpenOfTheSameFile() {
        val r = ByteArray(32).also { rnd.nextBytes(it) }
        provisionPassphraseVault(r)
        val factory = androidVaultFactory(context)
        val k = factory.deriveAdoptedRawKey(r)!!
        val hash = fileHash()

        fun med(xs: List<Double>) = xs.sorted()[xs.size / 2]
        // warm-up both
        DatabaseManager(context, r).close(); factory.createWithRawKey(k).close()
        val pass = (1..3).map { timeMs { DatabaseManager(context, r).close() } }
        val raw = (1..3).map { timeMs { factory.createWithRawKey(k).close() } }
        val probePass = (1..3).map { timeMs { assertTrue(factory.probeKey(r)) } }
        val probeRaw = (1..3).map { timeMs { assertTrue(factory.probeRawKey(k)) } }
        Log.i(tag, "RESULT | DatabaseManager open, PASSPHRASE mode (same file) | median=%.1f ms | runs=%s"
            .format(med(pass), pass.joinToString { "%.1f".format(it) }))
        Log.i(tag, "RESULT | DatabaseManager open, RAW-KEY mode (same file)    | median=%.1f ms | runs=%s"
            .format(med(raw), raw.joinToString { "%.1f".format(it) }))
        Log.i(tag, "RESULT | probeKey PASSPHRASE | median=%.1f ms".format(med(probePass)))
        Log.i(tag, "RESULT | probeKey RAW        | median=%.1f ms".format(med(probeRaw)))
        Log.i(tag, "RESULT | file unchanged by 14 opens (incl. writes of init's INSERT OR IGNORE) | ${hash == fileHash()}")
    }
}

package com.vg.run

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import net.zetetic.database.sqlcipher.SQLiteDatabase
import org.junit.Test
import org.junit.runner.RunWith
import java.security.SecureRandom
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

/**
 * MEASUREMENT ONLY (no assertions): where does a PIN unlock spend its time?
 * Run: ANDROID_SERIAL=<serial> ./gradlew :androidApp:connectedDebugAndroidTest \
 *      -Pandroid.testInstrumentationRunnerArguments.class=com.vg.run.KdfBenchTest
 * Read: adb logcat -d -s KdfBench
 */
@RunWith(AndroidJUnit4::class)
class KdfBenchTest {
    private val tag = "KdfBench"
    private val rnd = SecureRandom()

    private fun bench(name: String, params: String, runs: Int = 3, warmups: Int = 1, block: () -> Unit) {
        repeat(warmups) { block() }
        val ms = (1..runs).map { val t = System.nanoTime(); block(); (System.nanoTime() - t) / 1e6 }
        val s = ms.sorted()
        Log.i(tag, "RESULT | $name | $params | min=%.1f median=%.1f max=%.1f ms | runs=%s".format(
            s.first(), s[s.size / 2], s.last(), ms.joinToString { "%.1f".format(it) }))
    }

    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

    // VaultSelector's companion is `internal` (invisible across modules), but its `const val`s
    // are hoisted to public static fields on the outer class: read the REAL constants.
    private fun vsConst(n: String): Int =
        Class.forName("com.vg.run.VaultSelector").getField(n).getInt(null)

    @Test
    fun kdfBench() {
        val ctx = InstrumentationRegistry.getInstrumentation().targetContext
        val m = vsConst("ARGON2_MEMORY_KIB")
        val t = vsConst("ARGON2_ITERATIONS")
        val p = vsConst("ARGON2_PARALLELISM")
        val pin = "123456".toByteArray()

        // a. Argon2id at RELEASE constants, same expect/actual the app calls.
        bench("argon2id-release", "m=${m}KiB t=$t p=$p out=32") {
            val salt = ByteArray(16).also { rnd.nextBytes(it) }
            argon2id(pin, salt, m, t, p, 32)
        }
        // b. debug constants (1 MiB x 1)
        bench("argon2id-debug", "m=1024KiB t=1 p=1 out=32") {
            val salt = ByteArray(16).also { rnd.nextBytes(it) }
            argon2id(pin, salt, 1024, 1, 1, 32)
        }

        // c1. SQLCipher passphrase mode via the real DatabaseManager (random 32-byte key).
        System.loadLibrary("sqlcipher")
        ctx.deleteDatabase("run.db")
        val key = ByteArray(32).also { rnd.nextBytes(it) }
        bench("sqlcipher-passphrase-provision", "DatabaseManager isProvision=true, fresh db each run (create+schema)") {
            ctx.deleteDatabase("run.db")
            DatabaseManager(ctx, key, isProvision = true).close()
        }
        ctx.deleteDatabase("run.db")
        DatabaseManager(ctx, key, isProvision = true).close()
        bench("sqlcipher-passphrase-reopen", "DatabaseManager isProvision=false (steady-state unlock)") {
            DatabaseManager(ctx, key, isProvision = false).close()
        }
        ctx.deleteDatabase("run.db")

        // c2. raw-key mode, plain SQLiteDatabase + cipher_memory_security ON, trivial schema.
        val rawFile = ctx.getDatabasePath("kdfbench-raw.db")
        rawFile.parentFile?.mkdirs()
        fun rawOpen(create: Boolean): SQLiteDatabase {
            val pass = ("x'" + hex(key) + "'").toByteArray()
            val flags = if (create) SQLiteDatabase.OPEN_READWRITE or SQLiteDatabase.CREATE_IF_NECESSARY
                        else SQLiteDatabase.OPEN_READWRITE
            val d = SQLiteDatabase.openDatabase(rawFile.path, pass, null, flags, null, null)
            d.execSQL("PRAGMA cipher_memory_security = ON")
            return d
        }
        bench("sqlcipher-rawkey-create", "x'<64hex>', fresh db each run") {
            ctx.deleteDatabase("kdfbench-raw.db")
            val d = rawOpen(true); d.execSQL("CREATE TABLE IF NOT EXISTS t(a)"); d.close()
        }
        ctx.deleteDatabase("kdfbench-raw.db")
        rawOpen(true).also { it.execSQL("CREATE TABLE IF NOT EXISTS t(a)") }.close()
        bench("sqlcipher-rawkey-reopen", "x'<64hex>' (no KDF)") {
            val d = rawOpen(false)
            d.rawQuery("SELECT count(*) FROM sqlite_master", null).use { it.moveToFirst() }
            d.close()
        }
        ctx.deleteDatabase("kdfbench-raw.db")

        // d. plain PBKDF2-HMAC-SHA512 x 256000 (SQLCipher default kdf_iter), javax.crypto.
        try {
            val f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512")
            val chars = hex(key).toCharArray()
            bench("pbkdf2-hmac-sha512-javax", "iter=256000 out=32B") {
                val salt = ByteArray(16).also { rnd.nextBytes(it) }
                f.generateSecret(PBEKeySpec(chars, salt, 256_000, 256)).encoded
            }
        } catch (e: Throwable) {
            Log.i(tag, "RESULT | pbkdf2-hmac-sha512-javax | unavailable: $e")
        }
        Log.i(tag, "DONE")
    }
}

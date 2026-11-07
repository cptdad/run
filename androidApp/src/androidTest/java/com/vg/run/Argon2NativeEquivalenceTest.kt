package com.vg.run

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.SecureRandom

/**
 * THE GATE for the native Argon2id (librunargon2.so): every vault already on a phone
 * was provisioned by BouncyCastle, so native must be BYTE-EQUAL to BouncyCastle or
 * those vaults stop unlocking. Calls both implementations DIRECTLY (not through the
 * argon2id actual, which would hide a silent fallback) and fails if the .so is absent.
 *
 * Run: ANDROID_SERIAL=<serial> ./gradlew :androidApp:connectedDebugAndroidTest \
 *      -Pandroid.testInstrumentationRunnerArguments.class=com.vg.run.Argon2NativeEquivalenceTest
 * Timing: adb logcat -d -s KdfBench
 */
@RunWith(AndroidJUnit4::class)
class Argon2NativeEquivalenceTest {
    private val tag = "KdfBench"
    private val rnd = SecureRandom()

    // The external method is only bound once System.loadLibrary has run, which the
    // production path does lazily via NativeArgon2.isAvailable. Trigger (and assert)
    // it before every test so JUnit's method order can't call an unbound native.
    @Before
    fun loadNative() {
        assertTrue("librunargon2.so did not load — the APK is missing it for this ABI", NativeArgon2.isAvailable)
    }

    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

    // VaultSelector's companion is `internal` (invisible across modules), but its
    // `const val`s are public static fields on the outer class: read the REAL constants.
    private fun vsConst(n: String): Int =
        Class.forName("com.vg.run.VaultSelector").getField(n).getInt(null)

    private fun native(pwd: ByteArray, salt: ByteArray, m: Int, t: Int, p: Int, out: Int = 32) =
        NativeArgon2.argon2idRaw(pwd, salt, m, t, p, out)

    private fun bc(pwd: ByteArray, salt: ByteArray, m: Int, t: Int, p: Int, out: Int = 32) =
        argon2idBouncyCastle(pwd, salt, m, t, p, out)

    private fun assertEqual(what: String, pwd: ByteArray, salt: ByteArray, m: Int, t: Int, p: Int) {
        val n = native(pwd, salt, m, t, p)
        val b = bc(pwd, salt, m, t, p)
        assertArrayEquals("native != BouncyCastle for $what (m=$m t=$t p=$p)", b, n)
    }

    private fun randomSalt() = ByteArray(16).also { rnd.nextBytes(it) }
    private fun randomPin() = (1..6).map { '0' + rnd.nextInt(10) }.joinToString("").encodeToByteArray()

    @Test
    fun nativeLibraryLoads() {
        assertTrue("librunargon2.so did not load — the APK is missing it for this ABI", NativeArgon2.isAvailable)
    }

    // PHC reference vectors (phc-winner-argon2 test.c; also pinned in VaultKdfTest):
    // the native output must equal the published tag, not merely BouncyCastle.
    @Test
    fun phcReferenceVectors_matchPublishedTags() {
        val pwd = "password".encodeToByteArray()
        val salt = "somesalt".encodeToByteArray()
        assertEquals("09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7", hex(native(pwd, salt, 65_536, 2, 1)))
        assertEquals("9dfeb910e80bad0311fee20f9c0e2b12c17987b4cac90c2ef54d5b3021c68bfe", hex(native(pwd, salt, 256, 2, 1)))
        assertEquals("6d093c501fd5999645e0ea3bf620d7b8be7fd2db59c20d9fff9539da2bf57037", hex(native(pwd, salt, 256, 2, 2)))
    }

    // RFC 9106 §5.3 cost shape (m=32 KiB, t=3, p=4; pwd 32×0x01, salt 16×0x02). The
    // RFC tag itself also binds a secret + AD, which argon2id_hash_raw (the iOS and
    // Android entry point) does not take — the exact tag is pinned on BouncyCastle in
    // :shared Argon2BouncyCastleKatTest; here the same shape (4 lanes, computed
    // single-threaded under ARGON2_NO_THREADS) must agree byte-for-byte.
    @Test
    fun rfc9106Shape_p4_nativeEqualsBouncyCastle() {
        assertEqual("RFC 9106 shape", ByteArray(32) { 0x01 }, ByteArray(16) { 0x02 }, 32, 3, 4)
    }

    @Test
    fun releaseConstants_nativeEqualsBouncyCastle_andPinnedVector() {
        val m = vsConst("ARGON2_MEMORY_KIB")
        val t = vsConst("ARGON2_ITERATIONS")
        val p = vsConst("ARGON2_PARALLELISM")
        // Pinned vector (vendored PHC C; same value Argon2BouncyCastleKatTest pins on BC).
        assertEquals(
            "9b0a9f24be07d83998f657d86a216621de37af21b9d3133fab03035e94fd58ec",
            hex(native("123456".encodeToByteArray(), ByteArray(16) { it.toByte() }, m, t, p)),
        )
        assertEqual("release constants, random salt/PIN", randomPin(), randomSalt(), m, t, p)
    }

    @Test
    fun debugConstants_nativeEqualsBouncyCastle_andPinnedVector() {
        assertEquals(
            "c5699c2168c8ef5beb4bff2b4c2fabe501a3daab342444465901eee93ac805e3",
            hex(native("123456".encodeToByteArray(), ByteArray(16) { it.toByte() }, 1_024, 1, 1)),
        )
        assertEqual("debug constants, random salt/PIN", randomPin(), randomSalt(), 1_024, 1, 1)
    }

    // 20 random (salt, credential) pairs at the debug cost: 10 six-digit PINs and 10
    // MAXIMUM-style passphrases (random length, arbitrary bytes incl. non-ASCII).
    @Test
    fun twentyRandomPairs_nativeEqualsBouncyCastle() {
        repeat(20) { i ->
            val cred = if (i < 10) randomPin()
                       else ByteArray(8 + rnd.nextInt(57)).also { rnd.nextBytes(it) }
            assertEqual("random pair #$i", cred, randomSalt(), 1_024, 1, 1)
        }
    }

    // A native argon2 ERROR must surface, never silently fall back to BouncyCastle
    // (which would CLAMP m=4 KiB up to 8 blocks and return a different "key").
    @Test
    fun argon2Error_throws_andTheActualDoesNotFallBack() {
        val salt = randomSalt()
        assertThrows(IllegalStateException::class.java) { native("123456".encodeToByteArray(), salt, 4, 1, 1) }
        assertThrows(IllegalStateException::class.java) { argon2id("123456".encodeToByteArray(), salt, 4, 1, 1, 32) }
    }

    // MEASUREMENT (logged, not asserted): native vs BouncyCastle at the release cost.
    @Test
    fun timing_releaseConstants() {
        val m = vsConst("ARGON2_MEMORY_KIB")
        val t = vsConst("ARGON2_ITERATIONS")
        val p = vsConst("ARGON2_PARALLELISM")
        fun bench(name: String, block: (ByteArray, ByteArray) -> ByteArray) {
            block(randomPin(), randomSalt()) // warm-up
            val ms = (1..3).map {
                val pin = randomPin(); val salt = randomSalt()
                val t0 = System.nanoTime(); block(pin, salt); (System.nanoTime() - t0) / 1e6
            }
            val s = ms.sorted()
            Log.i(tag, "RESULT | $name | m=${m}KiB t=$t p=$p out=32 | min=%.1f median=%.1f max=%.1f ms | runs=%s".format(
                s.first(), s[s.size / 2], s.last(), ms.joinToString { "%.1f".format(it) }))
        }
        bench("argon2id-release-native") { pin, salt -> native(pin, salt, m, t, p) }
        bench("argon2id-release-bouncycastle") { pin, salt -> bc(pin, salt, m, t, p) }
        Log.i(tag, "DONE equivalence-timing")
    }
}

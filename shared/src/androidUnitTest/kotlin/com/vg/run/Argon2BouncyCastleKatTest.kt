package com.vg.run

import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse

/**
 * Freezes Android's REFERENCE Argon2id (BouncyCastle, [argon2idBouncyCastle]) to
 * known answers, so the on-device native-vs-BouncyCastle equality proof
 * (androidApp Argon2NativeEquivalenceTest) compares against a pinned reference and
 * not against whatever BouncyCastle happens to output after a dependency bump.
 *
 * Plain JVM: librunargon2.so cannot load here, which also makes this the test of the
 * fallback — the argon2id actual must take the BouncyCastle path and agree with it.
 *
 * The p=1 vault-cost vectors were derived from the VENDORED PHC reference C
 * (iosApp/Argon2, the exact sources librunargon2.so and iOS compile) and pinned here,
 * so a green run is already a cross-implementation agreement on the vault's own
 * cost shape — the on-device test then proves the compiled .so matches too.
 */
class Argon2BouncyCastleKatTest {

    private fun ByteArray.toHex(): String =
        joinToString("") { b -> (b.toInt() and 0xFF).toString(16).padStart(2, '0') }

    /** Fixed vault-shaped inputs: a 6-digit PIN and a 16-byte salt 00..0f. */
    private val pin = "123456".encodeToByteArray()
    private val salt16 = ByteArray(VaultKdf.SALT_LENGTH) { it.toByte() }

    // RFC 9106 §5.3 — Argon2id, v=0x13, m=32 KiB, t=3, p=4, tag 32 B; password 32×0x01,
    // salt 16×0x02, secret 8×0x03, associated data 12×0x04. The vault (and the JNI
    // shim's argon2id_hash_raw) never uses secret/AD, so this vector exercises
    // BouncyCastle through its full parameter builder rather than through
    // argon2idBouncyCastle — it anchors the generator itself to the RFC.
    @Test
    fun rfc9106_argon2id_vector() {
        val params = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withSalt(ByteArray(16) { 0x02 })
            .withSecret(ByteArray(8) { 0x03 })
            .withAdditional(ByteArray(12) { 0x04 })
            .withMemoryAsKB(32)
            .withIterations(3)
            .withParallelism(4)
            .build()
        val out = ByteArray(32)
        Argon2BytesGenerator().apply { init(params) }.generateBytes(ByteArray(32) { 0x01 }, out)
        assertEquals("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659", out.toHex())
    }

    // PHC reference (phc-winner-argon2 test.c) — same vector VaultKdfTest pins via the
    // expect/actual; here it is pinned on the BouncyCastle function directly.
    @Test
    fun phc_vector_m65536_t2_p1() {
        val out = argon2idBouncyCastle("password".encodeToByteArray(), "somesalt".encodeToByteArray(), 65_536, 2, 1, 32)
        assertEquals("09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7", out.toHex())
    }

    // The RELEASE cost exactly as VaultSelector pins it into a new v3 blob.
    @Test
    fun vaultReleaseCost_vector() {
        assertEquals(65_536, VaultKdf.ARGON2_MEMORY_KIB)
        assertEquals(3, VaultKdf.ARGON2_ITERATIONS)
        assertEquals(1, VaultKdf.ARGON2_PARALLELISM)
        val out = argon2idBouncyCastle(
            pin, salt16,
            VaultKdf.ARGON2_MEMORY_KIB, VaultKdf.ARGON2_ITERATIONS, VaultKdf.ARGON2_PARALLELISM,
            VaultKdf.DBKEY_LENGTH,
        )
        assertEquals(RELEASE_VECTOR, out.toHex())
    }

    // The DEBUG cost (runtimeArgon2MemoryKiB / runtimeArgon2Iterations when isDebugBuild).
    @Test
    fun vaultDebugCost_vector() {
        val out = argon2idBouncyCastle(pin, salt16, 1_024, 1, 1, VaultKdf.DBKEY_LENGTH)
        assertEquals(DEBUG_VECTOR, out.toHex())
    }

    // Fallback: on a JVM the native library is absent, so the actual must route to
    // BouncyCastle (not throw) and produce the identical bytes.
    @Test
    fun actual_fallsBackToBouncyCastle_whenNativeUnavailable() {
        val out = argon2id(pin, salt16, 1_024, 1, 1, VaultKdf.DBKEY_LENGTH)
        assertFalse(NativeArgon2.isAvailable, "librunargon2.so must not be loadable on the plain JVM")
        assertEquals(DEBUG_VECTOR, out.toHex())
    }

    companion object {
        // argon2id(pwd="123456", salt=00..0f, m=65536 KiB, t=3, p=1, 32 B) — vendored PHC C.
        const val RELEASE_VECTOR = "9b0a9f24be07d83998f657d86a216621de37af21b9d3133fab03035e94fd58ec"
        // argon2id(pwd="123456", salt=00..0f, m=1024 KiB, t=1, p=1, 32 B) — vendored PHC C.
        const val DEBUG_VECTOR = "c5699c2168c8ef5beb4bff2b4c2fabe501a3daab342444465901eee93ac805e3"
    }
}

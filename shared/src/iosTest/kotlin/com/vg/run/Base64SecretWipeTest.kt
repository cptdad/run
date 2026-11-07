@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * `Platform.ios.kt`'s [encodeBase64] / [decodeBase64]
 * now scrub the app-minted `NSData` they mint before dropping it to ARC, because
 * two call sites carry raw PLAINTEXT key material through them:
 * `VaultRatchetStore` (RatchetManager.kt:43/45 — root key, both chain keys, the DH
 * private key) and `IosVaultDatabase` (:391 insert / :585 read — the 32-byte
 * pairing `sharedSecret`), plus `PairingPayload.parse` (:85/:93) on a scan.
 *
 * The security delta is deliberately modest (N copies → N-1; the base64 String is
 * immutable and survives). **The RISK is not modest**, which is what this suite
 * exists for: both call sites feed values that are then PERSISTED. A memset that
 * landed before the read would emit base64 of ZEROES — silently corrupting every
 * ratchet blob and every contact `shared_secret` written thereafter — or would
 * hand the caller an all-zero secret back. Neither fails loudly at the call site.
 *
 * So the load-bearing assertions here are CORRECTNESS, pinned against HARDCODED
 * expected values (never against a second call to the same function, which would
 * agree with itself if both were zeroed), plus the proof that the memset cannot
 * reach the caller's own `ByteArray`.
 */
class Base64SecretWipeTest {

    // Deliberately all-non-zero (0xA0..0xBF): stands in for a 32-byte pairing
    // sharedSecret and makes a base64-of-zeroes regression unmistakable.
    private val secret32 = ByteArray(32) { (0xA0 + it).toByte() }
    private val secret32B64 = "oKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr8="

    // What a wipe-before-read regression would produce for the same input.
    private val zeroes32B64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

    // Odd length + padding, stands in for a serialized Double Ratchet blob.
    private val blob37 = ByteArray(37) { (it * 31 + 7).toByte() }
    private val blob37B64 = "ByZFZIOiweD/Hj1ce5q52PcWNVRzkrHQ7w4tTGuKqcjnBiVEYw=="

    // --- encode ------------------------------------------------------------

    /**
     * THE catastrophic-failure pin. If the `secureWipeBytes()` in `encodeBase64`
     * ever moves above `base64EncodedStringWithOptions` — or if Foundation ever
     * returned a lazily-materialised String that reads its bytes late — this
     * returns [zeroes32B64] and every sharedSecret/ratchet blob persisted from
     * then on is 32 zero bytes.
     */
    @Test
    fun encode_returnsTheRealBase64_notBase64OfZeroes() {
        val encoded = encodeBase64(secret32)
        assertEquals(secret32B64, encoded, "encodeBase64 must emit the real bytes")
        assertTrue(encoded != zeroes32B64, "encodeBase64 emitted base64 of ZEROES — the wipe ran before the read")
    }

    @Test
    fun encode_ofARatchetSizedBlob_matchesTheKnownAnswer() {
        assertEquals(blob37B64, encodeBase64(blob37), "odd-length + padded encode must be unaffected by the wipe")
    }

    /**
     * The aliasing catastrophe. `toNSData()` copies (`+[NSData dataWithBytes:length:]`),
     * so the memset lands on our private copy. If it ever became a no-copy wrapper,
     * `IosVaultDatabase.insertContact` would zero `contact.sharedSecret` *in the live
     * ContactRecord* right after writing the row — the row would be correct and the
     * running session's crypto would silently break.
     */
    @Test
    fun encode_doesNotClobberTheCallersArray() {
        val caller = ByteArray(32) { (0xA0 + it).toByte() }
        encodeBase64(caller)
        assertTrue(caller.contentEquals(secret32), "the caller's ByteArray must be untouched — toNSData() copies")
    }

    /** Two encodes of the same array must agree: no cross-call state was corrupted. */
    @Test
    fun encode_isRepeatable() {
        assertEquals(encodeBase64(secret32), encodeBase64(secret32))
        assertEquals(secret32B64, encodeBase64(secret32))
    }

    /**
     * The `length == 0` early-return path in `secureWipeBytes`: an empty NSData may
     * be the shared `+[NSData data]` singleton and must never be memset.
     */
    @Test
    fun encode_ofEmptyArray_isEmptyString() {
        assertEquals("", encodeBase64(ByteArray(0)))
    }

    // --- decode ------------------------------------------------------------

    /**
     * Mirror pin on the read path — which runs far more often than the write path
     * (every contact read, every ratchet load, every polled blob). A wipe placed
     * before `toByteArray()` returns all-zero key material to the caller.
     */
    @Test
    fun decode_returnsTheRealBytes_notZeroes() {
        val out = decodeBase64(secret32B64)
        assertEquals(32, out.size)
        assertTrue(out.contentEquals(secret32), "decodeBase64 must return the real bytes, not the zeroed buffer")
        assertTrue(out.any { it != 0.toByte() }, "decodeBase64 returned all zeroes — the wipe ran before the copy-out")
    }

    @Test
    fun decode_ofARatchetSizedBlob_matchesTheKnownAnswer() {
        assertTrue(decodeBase64(blob37B64).contentEquals(blob37))
    }

    /**
     * The same String decoded twice must give identical bytes. Pins that the memset
     * reached nothing Foundation shares or caches, and that the input String (which
     * on the live paths comes straight out of SQLite) is not corrupted by it.
     */
    @Test
    fun decode_sameStringTwice_yieldsIdenticalBytes() {
        val first = decodeBase64(secret32B64)
        val second = decodeBase64(secret32B64)
        assertTrue(first.contentEquals(second), "a second decode of the same String must agree")
        assertTrue(second.contentEquals(secret32), "the second decode must still be the real bytes")
    }

    /** Behaviour preserved: the nil branch still throws what callers already catch. */
    @Test
    fun decode_ofInvalidBase64_stillThrows() {
        assertFailsWith<IllegalArgumentException> { decodeBase64("@@@@") }
    }

    /**
     * Empty input must not crash and must not memset a shared empty NSData.
     * Foundation is free to return an empty NSData or nil for `""` — both are
     * acceptable and both are pre-existing behaviour; only a crash or non-empty
     * output would be a regression.
     */
    @Test
    fun decode_ofEmptyString_doesNotCrash() {
        val out = try { decodeBase64("") } catch (_: IllegalArgumentException) { ByteArray(0) }
        assertEquals(0, out.size)
    }

    // --- the two production round trips ------------------------------------

    /**
     * `IosVaultDatabase.insertContact` (:391) then `toContact` (:585): the exact
     * write-then-read sequence a pairing's shared secret takes through the vault.
     */
    @Test
    fun sharedSecretRoundTrip_survivesBothWipes_andLeavesTheSourceIntact() {
        val live = ByteArray(32) { (0xA0 + it).toByte() }
        val stored = encodeBase64(live)
        val readBack = decodeBase64(stored)
        assertTrue(readBack.contentEquals(secret32), "sharedSecret must survive the vault round trip byte for byte")
        assertTrue(live.contentEquals(secret32), "the in-RAM ContactRecord's sharedSecret must not be clobbered")
    }

    /** `VaultRatchetStore.save` (:45) then `load` (:43). */
    @Test
    fun ratchetBlobRoundTrip_survivesBothWipes() {
        val blob = ByteArray(37) { (it * 31 + 7).toByte() }
        val readBack = decodeBase64(encodeBase64(blob))
        assertTrue(readBack.contentEquals(blob37), "ratchet state must survive the _meta round trip byte for byte")
    }

    // --- the mechanism the two actuals rely on -----------------------------

    /**
     * Direct proof of the CATEGORY-1 premise, independent of the base64 functions:
     * `toNSData()` yields an independent buffer, so `secureWipeBytes()` zeroes that
     * copy and provably cannot reach the source `ByteArray`.
     */
    @Test
    fun toNSDataCopyIsIndependent_soAWipeCannotReachTheSourceArray() {
        val source = ByteArray(32) { (0xA0 + it).toByte() }
        val copy = source.toNSData()

        copy.secureWipeBytes()

        assertTrue(copy.toByteArray().all { it == 0.toByte() }, "the app-minted NSData copy must be zeroed")
        assertTrue(source.contentEquals(secret32), "the source ByteArray must be untouched — toNSData() copies")
    }
}

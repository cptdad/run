package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The v3 `"ek"` field of the pairing code (docs/ratchet-bootstrap-plan.md §4.1):
 * appended after `rv` in both shapes; presence is the capability; a malformed,
 * low-order or reflected key rejects the code (the existing "invalid code" null);
 * absence is never a rejection; the store build's parser accepts a code carrying it.
 * The original builders stay byte-identical (PairingPayloadTest pins them).
 */
class PairingPayloadV3Test {

    private val inbox = "i".repeat(32)
    private val cib = "c".repeat(32)
    private val gib = "g".repeat(32)
    private val wcap = "w".repeat(43)
    private val cwcap = "x".repeat(43)
    private val gwcap = "y".repeat(43)
    private val secretB64 = encodeBase64(ByteArray(32) { it.toByte() })
    // Fixed, non-low-order 32-byte values: the codec never needs a real keypair, so
    // these tests also run where no X25519 bridge is registered (the bare iOS runner).
    private val myEk = encodeBase64Url(ByteArray(32).also { it[0] = 9 })              // the base point
    private val peerEk = encodeBase64Url(ByteArray(32) { (it * 7 + 3).toByte() })

    private fun secretOnly(ek: String = peerEk) = PairingPayload.buildSecretOnlyV3(secretB64, ek)
    private fun full(ek: String = peerEk) = PairingPayload.buildFullV3(inbox, wcap, cib, cwcap, secretB64, ek, gib, gwcap)

    /** The code with its `ek` value replaced by [raw] (a JSON literal, so non-strings can be tested). */
    private fun withEk(raw: String) = PairingPayload.buildSecretOnly(secretB64).dropLast(1) + ",\"ek\":$raw}"

    // --- build ---

    @Test
    fun ekIsAppendedAfterRv_inBothShapes_andTheRestIsByteIdentical() {
        assertEquals(PairingPayload.buildSecretOnly(secretB64).dropLast(1) + ",\"ek\":\"$peerEk\"}", secretOnly())
        assertEquals(
            PairingPayload.buildFull(inbox, wcap, cib, cwcap, secretB64, gib, gwcap).dropLast(1) + ",\"ek\":\"$peerEk\"}",
            full(),
        )
        assertTrue(secretOnly().indexOf("\"rv\"") < secretOnly().indexOf("\"ek\""))
    }

    /**
     * Sizes (plan §4.1 predicted 117 / 403 bytes): ids 32, caps 43, the secret 44
     * (standard base64 of 32 bytes), `ek` 43. Byte-mode QR capacities: EC L v5 106 /
     * v6 134, v12 367 / v13 425; EC M v6 106 / v7 122, v14 362 / v15 412. So the
     * secret-only code moves L v5→v6 (Android) and M v5→v7 (iOS); the full code with
     * the group pair L v12→v13 and M v14→v15 (9 bytes of headroom).
     */
    @Test
    fun codeSizes_matchThePlan() {
        assertEquals(66, PairingPayload.buildSecretOnly(secretB64).encodeToByteArray().size)
        assertEquals(117, secretOnly().encodeToByteArray().size)
        assertEquals(352, PairingPayload.buildFull(inbox, wcap, cib, cwcap, secretB64, gib, gwcap).encodeToByteArray().size)
        assertEquals(403, full().encodeToByteArray().size)
    }

    @Test
    fun aMalformedKeyIsNeverBuilt() {
        var threw = false
        try { PairingPayload.buildSecretOnlyV3(secretB64, "short") } catch (_: IllegalArgumentException) { threw = true }
        assertTrue(threw)
    }

    // --- parse: present / absent ---

    @Test
    fun presentEk_parsesInBothShapes() {
        for (raw in listOf(secretOnly(), full())) {
            val scan = assertNotNull(PairingPayload.parse(raw, null, null, false, myEk))
            assertEquals(peerEk, scan.ephemeralPubB64)
            assertTrue(scan.roleRuleV2)
        }
        assertEquals(gib, PairingPayload.parse(full(), null, null, true, myEk)?.grpInboxId)
    }

    @Test
    fun absentEk_isLegacy_neverARejection() {
        val scan = assertNotNull(PairingPayload.parse(PairingPayload.buildSecretOnly(secretB64), null, null, false, myEk))
        assertNull(scan.ephemeralPubB64)
        val pre = "{\"inbox\":\"$inbox\",\"wcap\":\"$wcap\",\"secret\":\"$secretB64\"}"   // a pre-v7 code
        assertNull(assertNotNull(PairingPayload.parse(pre, null, null, true, myEk)).ephemeralPubB64)
    }

    // --- parse: rejections (the whole code) ---

    @Test
    fun malformedEk_rejectsTheCode() {
        val bad = listOf(
            "\"\"", "\"short\"", "\"${peerEk}A\"", "\"${peerEk.dropLast(1)}\"",
            "\"${peerEk.dropLast(1)}=\"",                       // padding
            "\"+${peerEk.drop(1)}\"", "\"/${peerEk.drop(1)}\"",   // standard-base64 alphabet
            "\"${peerEk.dropLast(1)}B\"",                        // non-canonical tail (low bits set)
            "12345", "true", "null",
        )
        for (b in bad) {
            assertNull(PairingPayload.parse(withEk(b), null, null, false, myEk), "ek=$b must reject")
            assertNull(PairingPayload.parse(withEk(b), null, null, false), "ek=$b must reject in the 4-argument parse too")
        }
    }

    @Test
    fun aNonScalarEk_neverParsesAsV3() {
        // The depth-1 scanner may drop or reject a nested value; either way it must
        // never yield a v3 scan.
        for (b in listOf("{\"a\":\"b\"}", "[\"x\"]")) {
            assertNull(PairingPayload.parse(withEk(b), null, null, false, myEk)?.ephemeralPubB64, "ek=$b")
        }
    }

    private val lowOrderHex = listOf(
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    )

    @Test
    fun lowOrderEk_rejectsTheCode_withAndWithoutBit255() {
        for (h in lowOrderHex) {
            val p = ByteArray(32) { h.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
            for (pt in listOf(p, p.copyOf().also { it[31] = (it[31].toInt() or 0x80).toByte() })) {
                val ek = encodeBase64Url(pt)
                assertNull(PairingPayload.parse(withEk("\"$ek\""), null, null, false, myEk), "low-order $h")
                assertNull(PairingPayload.parse(withEk("\"$ek\""), null, null, false), "low-order $h (4-arg)")
            }
        }
    }

    @Test
    fun echoedOwnEk_rejectsTheCode_bit255Ignored() {
        assertNull(PairingPayload.parse(secretOnly(ek = myEk), null, null, false, myEk))
        val mine = PairingPayload.decodeEphemeralKey(myEk)!!
        val flipped = encodeBase64Url(mine.copyOf().also { it[31] = (it[31].toInt() xor 0x80).toByte() })
        assertNull(PairingPayload.parse(secretOnly(ek = flipped), null, null, false, myEk))
        // Without our own key (the 4-argument parse) the echo cannot be checked.
        assertNotNull(PairingPayload.parse(secretOnly(ek = myEk), null, null, false))
    }

    @Test
    fun ekCannotRelaxAnyOtherRule() {
        assertNull(PairingPayload.parse(full(), null, mySecretB64 = secretB64, requireFull = true, myEphemeralPubB64 = myEk))
        assertNull(PairingPayload.parse(secretOnly(), null, null, requireFull = true, myEphemeralPubB64 = myEk))
    }

    // --- an older build's parser ---

    @Test
    fun theStoreBuildParser_acceptsOurV3Codes_ignoringEk() {
        val old1 = assertNotNull(StoreBuildPairingParser.parse(secretOnly(), null, null, false))
        assertNull(old1.inboxId); assertEquals(secretB64, old1.secretB64); assertTrue(old1.roleRuleV2)
        assertNull(old1.ephemeralPubB64, "an older build never sees the key")
        val old2 = assertNotNull(StoreBuildPairingParser.parse(full(), null, null, true))
        assertEquals(inbox, old2.inboxId); assertEquals(cib, old2.ctlInboxId); assertEquals(gib, old2.grpInboxId)
        assertEquals(secretB64, old2.secretB64)
    }

    @Test
    fun decodeEphemeralKey_roundTrips() {
        if (!x25519Up()) return
        val k = x25519GenerateKeypair().publicKey
        assertTrue(PairingPayload.decodeEphemeralKey(encodeBase64Url(k))!!.contentEquals(k))
    }
}

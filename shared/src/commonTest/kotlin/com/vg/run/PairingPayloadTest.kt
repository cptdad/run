package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Pins the pairing codec — the TRUST boundary. Exhaustive accept/reject matrix
 * so the ONE shared validator can't drift from what each platform used to enforce
 * (Android parseQrPayload + iOS handleScannedCode/addContactFromPastedCode). A hole
 * here lets a reflected/malformed pairing code through.
 */
class PairingPayloadTest {

    private val inbox = "i".repeat(32)          // valid inbox id (32 base64url)
    private val cib = "c".repeat(32)            // valid, distinct control inbox
    private val wcap = "w".repeat(43)           // valid cap (43 base64url)
    private val cwcap = "x".repeat(43)
    private val secretB64 = encodeBase64(ByteArray(32) { it.toByte() })
    private val otherSecretB64 = encodeBase64(ByteArray(32) { (it + 7).toByte() })

    private fun full(
        inbox: String = this.inbox, wcap: String = this.wcap,
        cib: String = this.cib, cwcap: String = this.cwcap, secret: String = secretB64,
    ) = PairingPayload.buildFull(inbox, wcap, cib, cwcap, secret)

    // ---- build ----

    @Test
    fun buildSecretOnly_exactWireFormat() {
        // The role-binding change appended the optional role-rule marker LAST, so every
        // pre-existing byte of the payload is unchanged.
        assertEquals("{\"secret\":\"$secretB64\",\"rv\":\"2\"}", PairingPayload.buildSecretOnly(secretB64))
    }

    @Test
    fun buildFull_exactWireFormat() {
        assertEquals(
            "{\"inbox\":\"$inbox\",\"wcap\":\"$wcap\",\"cib\":\"$cib\",\"cwcap\":\"$cwcap\"," +
                "\"secret\":\"$secretB64\",\"rv\":\"2\"}",
            full(),
        )
    }

    @Test
    fun buildFull_roundTripsThroughParse() {
        val scan = PairingPayload.parse(full(), myInboxId = null, mySecretB64 = null, requireFull = true)
        assertNotNull(scan)
        assertEquals(inbox, scan.inboxId)
        assertEquals(wcap, scan.writeCap)
        assertEquals(cib, scan.ctlInboxId)
        assertEquals(cwcap, scan.ctlWriteCap)
        assertEquals(secretB64, scan.secretB64)
        assertTrue(scan.roleRuleV2, "a code this build produced must advertise role rule v2")
    }

    @Test
    fun buildSecretOnly_parsesAsSecretOnly() {
        val raw = PairingPayload.buildSecretOnly(secretB64)
        val scan = PairingPayload.parse(raw, null, null, requireFull = false)
        assertNotNull(scan)
        assertNull(scan.inboxId)
        assertNull(scan.writeCap)
        assertNull(scan.ctlInboxId)
        assertEquals(secretB64, scan.secretB64)
        assertTrue(scan.roleRuleV2, "the instant QR must carry the marker too — it is the only")
        // requireFull rejects a secret-only code (the paste path)
        assertNull(PairingPayload.parse(raw, null, null, requireFull = true))
    }

    // ---- accept ----

    @Test
    fun parse_pre_v7_fullCodeWithoutCtl_isAccepted() {
        val raw = "{\"inbox\":\"$inbox\",\"wcap\":\"$wcap\",\"secret\":\"$secretB64\"}"
        val scan = PairingPayload.parse(raw, null, null, requireFull = true)
        assertNotNull(scan)
        assertEquals(inbox, scan.inboxId)
        assertNull(scan.ctlInboxId)
    }

    // ---- The OPTIONAL role-rule marker ----

    @Test
    fun parse_preStepA_codeWithoutRv_isAcceptedAndReadsAsRuleV1() {
        // The whole migration story in one assertion: an old peer's code carries no
        // `rv`, still parses exactly as before, and reports roleRuleV2 = false —
        // which is what keeps BOTH devices on the id-order rule, the only answer
        // that agrees with what that peer is actually doing.
        val raw = "{\"inbox\":\"$inbox\",\"wcap\":\"$wcap\",\"cib\":\"$cib\"," +
            "\"cwcap\":\"$cwcap\",\"secret\":\"$secretB64\"}"
        val scan = PairingPayload.parse(raw, null, null, requireFull = true)
        assertNotNull(scan)
        assertEquals(inbox, scan.inboxId)
        assertFalse(scan.roleRuleV2, "absent rv must never read as v2")
    }

    @Test
    fun parse_unrecognisedOrMalformedRv_neverRejectsAndNeverReadsAsV2() {
        // `rv` may only ever turn the v2 rule ON. A future value, a wrong type, or a
        // garbage value must leave the scan ACCEPTED (rejecting would make a forward
        // version marker a pairing failure) and the rule at v1.
        for (rv in listOf("\"3\"", "\"\"", "\"2x\"", "2", "true", "{\"a\":\"b\"}", "[\"2\"]")) {
            val raw = "{\"inbox\":\"$inbox\",\"wcap\":\"$wcap\",\"cib\":\"$cib\"," +
                "\"cwcap\":\"$cwcap\",\"secret\":\"$secretB64\",\"rv\":$rv}"
            val scan = PairingPayload.parse(raw, null, null, requireFull = true)
            assertNotNull(scan, "rv=$rv must not reject the code")
            assertFalse(scan.roleRuleV2, "rv=$rv must not read as v2")
        }
    }

    @Test
    fun parse_rvIsNotAllowedToRelaxAnyOtherRule() {
        // Defence in depth: the marker is read AFTER every existing validation, so a
        // code carrying it is rejected for exactly the same reasons as one without.
        val echoed = "{\"inbox\":\"$inbox\",\"wcap\":\"$wcap\",\"secret\":\"$secretB64\",\"rv\":\"2\"}"
        assertNull(
            PairingPayload.parse(echoed, myInboxId = null, mySecretB64 = secretB64, requireFull = true),
            "an echoed secret must still be rejected when the code advertises rv:2",
        )
        val badCap = "{\"inbox\":\"$inbox\",\"wcap\":\"short\",\"secret\":\"$secretB64\",\"rv\":\"2\"}"
        assertNull(PairingPayload.parse(badCap, null, null, requireFull = true))
    }

    // ---- reject: secret ----

    @Test
    fun parse_rejects_non32ByteSecret() {
        val short = encodeBase64(ByteArray(31) { it.toByte() })
        assertNull(PairingPayload.parse(full(secret = short), null, null, false))
    }

    @Test
    fun parse_rejects_missingSecret() {
        assertNull(PairingPayload.parse("{\"inbox\":\"$inbox\",\"wcap\":\"$wcap\"}", null, null, false))
    }

    @Test
    fun parse_rejects_nonStringSecretValue() {
        assertNull(PairingPayload.parse("{\"secret\":12345}", null, null, false))
    }

    @Test
    fun parse_rejects_echoedOwnSecret() {
        // peer handed back our own secret half
        assertNull(PairingPayload.parse(full(secret = secretB64), null, mySecretB64 = secretB64, false))
        // a DIFFERENT secret is fine
        assertNotNull(PairingPayload.parse(full(secret = secretB64), null, mySecretB64 = otherSecretB64, false))
    }

    // ---- reject: inbox / cap shape ----

    @Test
    fun parse_rejects_echoedOwnInbox() {
        assertNull(PairingPayload.parse(full(), myInboxId = inbox, mySecretB64 = null, false))
    }

    @Test
    fun parse_rejects_halfPresentInboxWcapPair() {
        assertNull(PairingPayload.parse("{\"inbox\":\"$inbox\",\"secret\":\"$secretB64\"}", null, null, false))
        assertNull(PairingPayload.parse("{\"wcap\":\"$wcap\",\"secret\":\"$secretB64\"}", null, null, false))
    }

    @Test
    fun parse_rejects_invalidCap() {
        assertNull(PairingPayload.parse(full(wcap = "w".repeat(42)), null, null, false)) // too short
        assertNull(PairingPayload.parse(full(wcap = "!".repeat(43)), null, null, false)) // bad alphabet
    }

    @Test
    fun parse_rejects_invalidInboxId() {
        assertNull(PairingPayload.parse(full(inbox = "i".repeat(31)), null, null, false))
    }

    // ---- reject: control pair ----

    @Test
    fun parse_rejects_halfPresentCtlPair() {
        val raw = "{\"inbox\":\"$inbox\",\"wcap\":\"$wcap\",\"cib\":\"$cib\",\"secret\":\"$secretB64\"}"
        assertNull(PairingPayload.parse(raw, null, null, false))
    }

    @Test
    fun parse_rejects_ctlPairOnSecretOnlyCode() {
        val raw = "{\"cib\":\"$cib\",\"cwcap\":\"$cwcap\",\"secret\":\"$secretB64\"}"
        assertNull(PairingPayload.parse(raw, null, null, false))
    }

    @Test
    fun parse_rejects_ctlInboxEqualToMessageInbox() {
        assertNull(PairingPayload.parse(full(cib = inbox), null, null, false))
    }

    // ---- reject: malformed ----

    @Test
    fun parse_rejects_garbage() {
        assertNull(PairingPayload.parse("not json at all", null, null, false))
        assertNull(PairingPayload.parse("", null, null, false))
        assertNull(PairingPayload.parse("{", null, null, false))
    }

    // ---- isValidCap ----

    @Test
    fun isValidCap_matrix() {
        assertTrue(PairingPayload.isValidCap("A".repeat(43)))
        assertTrue(PairingPayload.isValidCap("aZ0-_".padEnd(43, 'x')))
        assertTrue(!PairingPayload.isValidCap("A".repeat(42)))
        assertTrue(!PairingPayload.isValidCap("A".repeat(44)))
        assertTrue(!PairingPayload.isValidCap("+".repeat(43)))  // std-base64 chars are not base64url
        assertTrue(!PairingPayload.isValidCap("/".repeat(43)))
    }
}

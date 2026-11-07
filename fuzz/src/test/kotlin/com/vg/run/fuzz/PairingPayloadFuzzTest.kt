package com.vg.run.fuzz

import com.code_intelligence.jazzer.api.FuzzedDataProvider
import com.code_intelligence.jazzer.junit.FuzzTest
import com.vg.run.Base32
import com.vg.run.MigrationSeal
import com.vg.run.MoveHandleCodec
import com.vg.run.PairingPayload
import com.vg.run.encodeBase64
import com.vg.run.isValidInboxId
import org.junit.jupiter.api.Test

/**
 * The QR / paste-code decoders — the only parsers that run on bytes a stranger
 * physically put in front of the camera.
 *
 * `PairingPayload.parse` is THE pairing trust boundary (it replaced five
 * divergent per-platform implementations), and `MoveHandleCodec.parse` is its
 * device-move twin. Both are documented as "never throws; returns null".
 *
 * The invariants worth asserting are the SECURITY ones the doc comments promise,
 * because "returns null" alone would be satisfied by a parser that also silently
 * accepted a reflected copy of our own secret:
 *   - the secret is standard base64 of EXACTLY 32 bytes;
 *   - our own inbox id handed back to us is refused (echo/reflection);
 *   - our own secret handed back to us is refused;
 *   - inbox/wcap travel together, ctl pair travels together;
 *   - the control inbox and the message inbox must differ;
 *   - every id/cap that survives is shape-valid.
 */
class PairingPayloadFuzzTest {

    @FuzzTest(maxDuration = "60s")
    fun fuzzPairingPayload(data: FuzzedDataProvider) {
        val raw = data.consumeRemainingAsString()

        for (requireFull in listOf(false, true)) {
            val scan = bounded("PairingPayload.parse") {
                PairingPayload.parse(raw, MY_INBOX, MY_SECRET_B64, requireFull)
            } ?: continue

            // --- the secret ------------------------------------------------
            val secret = com.vg.run.decodeBase64(scan.secretB64)
            check(secret.size == 32) { "accepted a ${secret.size}-byte pairing secret" }
            check(!secret.contentEquals(MY_SECRET)) { "accepted a REFLECTION of our own secret" }

            // --- the inbox / capability pair -------------------------------
            check((scan.inboxId == null) == (scan.writeCap == null)) {
                "accepted a half-present inbox/wcap pair"
            }
            if (requireFull) check(scan.inboxId != null) { "requireFull accepted a secret-only code" }
            scan.inboxId?.let {
                check(isValidInboxId(it)) { "accepted a malformed inbox id" }
                check(it != MY_INBOX) { "accepted our OWN inbox id echoed back" }
            }
            scan.writeCap?.let { check(PairingPayload.isValidCap(it)) { "accepted a malformed write cap" } }

            // --- the control pair ------------------------------------------
            check((scan.ctlInboxId == null) == (scan.ctlWriteCap == null)) {
                "accepted a half-present control pair"
            }
            scan.ctlInboxId?.let {
                check(scan.inboxId != null) { "accepted a control pair on a secret-only code" }
                check(isValidInboxId(it)) { "accepted a malformed control inbox id" }
                check(it != scan.inboxId) { "accepted control inbox == message inbox" }
            }
            scan.ctlWriteCap?.let { check(PairingPayload.isValidCap(it)) { "accepted a malformed ctl cap" } }
        }
    }

    @FuzzTest(maxDuration = "60s")
    fun fuzzMoveHandle(data: FuzzedDataProvider) {
        val raw = data.consumeRemainingAsString()

        val handle = bounded("MoveHandleCodec.parse") { MoveHandleCodec.parse(raw) }
        if (handle != null) {
            check(isValidInboxId(handle.inboxId)) { "accepted a malformed move inbox id" }
            check(PairingPayload.isValidCap(handle.readCap)) { "accepted a malformed read cap" }
            check(MoveHandleCodec.isValidBundleId(handle.bundleId)) { "accepted a malformed bundle id" }
            // The code must come back CANONICAL (uppercase, ungrouped) so every
            // downstream consumer sees one representation.
            val bytes = MigrationSeal.decodeCode(handle.code)
            check(bytes != null) { "handle carried a code its own decoder rejects" }
            check(MigrationSeal.encodeCode(bytes) == handle.code) { "handle code is not canonical" }
            // Re-rendering must be a fixed point.
            check(MoveHandleCodec.parse(MoveHandleCodec.toQrText(handle)) == handle) {
                "MoveHandleCodec is not idempotent"
            }
        }

        // The transfer-code decoder itself: "Returns null on anything else. Never throws."
        val code = bounded("MigrationSeal.decodeCode") { MigrationSeal.decodeCode(raw) }
        if (code != null) {
            check(code.size == 20) { "decodeCode returned ${code.size} bytes, expected 20" }
        }
        // …and the Crockford Base32 layer under it.
        bounded("Base32.decode") { Base32.decode(raw) }
    }

    // ------------------------------------------------------------------
    // Fixed regression tests.
    // ------------------------------------------------------------------

    @Test
    fun ourOwnSecretHandedBackIsRefused() {
        val reflected = PairingPayload.buildSecretOnly(MY_SECRET_B64)
        check(PairingPayload.parse(reflected, MY_INBOX, MY_SECRET_B64, requireFull = false) == null) {
            "a reflected own-secret QR was accepted"
        }
    }

    @Test
    fun ourOwnInboxHandedBackIsRefused() {
        val payload = PairingPayload.buildFull(MY_INBOX, FuzzIds.CAP, FuzzIds.INBOX_B, FuzzIds.CAP, PEER_SECRET_B64)
        check(PairingPayload.parse(payload, MY_INBOX, MY_SECRET_B64, requireFull = true) == null) {
            "our own inbox id echoed back was accepted"
        }
    }

    @Test
    fun controlInboxEqualToMessageInboxIsRefused() {
        val payload = PairingPayload.buildFull(FuzzIds.INBOX_A, FuzzIds.CAP, FuzzIds.INBOX_A, FuzzIds.CAP, PEER_SECRET_B64)
        check(PairingPayload.parse(payload, MY_INBOX, MY_SECRET_B64, requireFull = true) == null) {
            "control inbox == message inbox was accepted"
        }
    }

    @Test
    fun aLegalFullPayloadRoundTrips() {
        val payload = PairingPayload.buildFull(FuzzIds.INBOX_A, FuzzIds.CAP, FuzzIds.INBOX_B, FuzzIds.CAP, PEER_SECRET_B64)
        val scan = PairingPayload.parse(payload, MY_INBOX, MY_SECRET_B64, requireFull = true)
        check(scan?.inboxId == FuzzIds.INBOX_A && scan.ctlInboxId == FuzzIds.INBOX_B)
    }

    private companion object {
        const val MY_INBOX = FuzzIds.INBOX_C
        val MY_SECRET: ByteArray = ByteArray(32) { 0x11 }
        val MY_SECRET_B64: String = encodeBase64(MY_SECRET)
        val PEER_SECRET_B64: String = encodeBase64(ByteArray(32) { 0x22 })
    }
}

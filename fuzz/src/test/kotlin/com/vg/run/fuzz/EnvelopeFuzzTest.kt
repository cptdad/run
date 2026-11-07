package com.vg.run.fuzz

import com.code_intelligence.jazzer.api.FuzzedDataProvider
import com.code_intelligence.jazzer.junit.FuzzTest
import com.vg.run.MessageManager
import com.vg.run.unpadMessage
import org.junit.jupiter.api.Test

/**
 * The LEGACY (static AES-GCM) envelope's post-decrypt field parsing.
 *
 * `pollChannel` hands `MessageManager.parseEnvelope` the plaintext of an
 * AES-GCM-authenticated blob. "Authenticated" only means it came from the holder
 * of the pairing secret — i.e. THE PEER, who is precisely the party in the
 * malicious-peer threat model. The peer composes this JSON itself, so every
 * field here is attacker-controlled:
 *
 *   e  epoch       c  counter      t  timestamp    m  message text
 *   g  groupId     h  membership   k  controlKind  b  controlBody
 *   ch channel tag (cross-channel splice defence)
 *   di destination inbox id (relay-reflection defence)
 *
 * DOCUMENTED CONTRACT: `parseEnvelope` returns null on anything it cannot read
 * and NEVER throws (it wraps the whole body in `catch (_: Exception)`).
 * Anything else escaping — notably an `Error`, which that catch does not
 * cover — is a finding.
 *
 * Also fuzzed here: `unpadMessage`, the step immediately BEFORE parseEnvelope on
 * the receive path, which reads a 4-byte big-endian length prefix out of the
 * decrypted buffer.
 */
class EnvelopeFuzzTest {

    @FuzzTest(maxDuration = "60s")
    fun fuzzParseEnvelope(data: FuzzedDataProvider) {
        val raw = data.consumeRemainingAsString()

        val envelope = bounded("parseEnvelope") { manager.parseEnvelope(raw) } ?: return

        // ---- invariants on the parsed result -----------------------------
        val scanned = com.vg.run.parseTopLevelJson(raw)
        val mField = scanned["m"]?.takeIf { it.isString }?.text

        // A body that DID parse as an envelope but carries no "m" must
        // yield EMPTY text. Echoing the raw JSON instead would surface a control
        // body's inbox ids and capability tokens in a chat bubble.
        if (scanned.isNotEmpty() && mField == null) {
            check(envelope.text.isEmpty()) {
                "parseEnvelope echoed a non-\"m\" envelope as message text"
            }
        }
        if (mField != null) {
            check(envelope.text == mField) { "parseEnvelope altered the \"m\" field" }
        }

        // Depth-1 guarantee: a field parseEnvelope read as a STRING must be a
        // string in the scanner's own view, and vice versa for the counter.
        envelope.controlKind?.let { check(scanned["k"]?.isString == true) }
        envelope.channel?.let { check(scanned["ch"]?.isString == true) }
        envelope.destInbox?.let { check(scanned["di"]?.isString == true) }
        envelope.groupId?.let { check(scanned["g"]?.isString == true) }
        envelope.counter?.let { check(scanned["c"]?.isString == false) }
    }

    /**
     * `unpadMessage` runs on decrypted-but-attacker-composed bytes, before any
     * JSON is seen. It reads a big-endian length prefix and slices — the classic
     * shape for an IndexOutOfBounds / negative-size allocation.
     *
     * DOCUMENTED CONTRACT: it throws on invalid padding, and every caller wraps
     * it in `catch (_: Exception)`. So `Exception` is allowed; an `Error`
     * (OutOfMemoryError from a hostile 2 GiB length prefix, say) is a finding,
     * because no caller catches that.
     */
    @FuzzTest(maxDuration = "60s")
    fun fuzzUnpadMessage(data: FuzzedDataProvider) {
        val padded = data.consumeRemainingAsBytes()
        // `require(...)` is the ONLY declared failure: "Padded message too short"
        // and "Invalid padding length" both raise IllegalArgumentException.
        onlyThrows(IllegalArgumentException::class) {
            bounded("unpadMessage") { unpadMessage(padded) }
        }
    }

    // ------------------------------------------------------------------
    // Fixed regression tests.
    // ------------------------------------------------------------------

    /** A peer smuggling `"c":999` inside a string value must not move the counter. */
    @Test
    fun counterCannotBeSmuggledInsideAStringValue() {
        val hostile = """{"m":"hi \"c\":999 there","c":1}"""
        val e = manager.parseEnvelope(hostile)
        check(e?.counter == 1L) { "smuggled counter won: ${e?.counter}" }
    }

    /** …or inside a nested object. */
    @Test
    fun counterCannotBeSmuggledInsideANestedObject() {
        val hostile = """{"x":{"c":999},"c":1}"""
        val e = manager.parseEnvelope(hostile)
        check(e?.counter == 1L) { "nested counter won: ${e?.counter}" }
    }

    /** An envelope that parsed but carries no "m" must yield EMPTY text, not the raw JSON. */
    @Test
    fun envelopeWithoutTextDoesNotEchoTheWholeBody() {
        val e = manager.parseEnvelope("""{"k":"ctl","b":"{\"cap\":\"secret\"}"}""")
        check(e?.text == "") { "leaked control body as chat text: ${e?.text}" }
    }

    private companion object {
        /**
         * One shared MessageManager: `parseEnvelope` is pure w.r.t. instance
         * state (it only calls parseTopLevelJson), the vault is in-memory and
         * the transport can never open a socket.
         */
        val manager: MessageManager = MessageManager(
            InMemoryVault(),
            "http://127.0.0.1:1",
            DeadRelayHttp(),
            "1.0.0",
        )
    }
}

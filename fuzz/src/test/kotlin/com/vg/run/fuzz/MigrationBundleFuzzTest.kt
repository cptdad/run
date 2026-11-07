package com.vg.run.fuzz

import com.code_intelligence.jazzer.api.FuzzedDataProvider
import com.code_intelligence.jazzer.junit.FuzzTest
import com.vg.run.MigJson
import com.vg.run.MigrationBundle
import com.vg.run.MigrationBundleCodec
import com.vg.run.MigrationSeal
import com.vg.run.MoveHandleCodec
import com.vg.run.VaultSnapshot
import org.junit.jupiter.api.Test

/**
 * The device-move bundle: the JSON document that becomes a freshly provisioned
 * vault on the NEW phone.
 *
 * This one is AEAD-authenticated under a 160-bit one-time code before it is
 * parsed, so it is not an open attack surface — the codec's own header says so.
 * It is fuzzed anyway for the reason that header gives: "the alternative to
 * defensive parsing here is corrupting a freshly provisioned vault". A bundle
 * that decodes to nonsense does not fail loudly, it produces a wrong vault.
 *
 * DOCUMENTED CONTRACTS:
 *  - `MigrationBundleCodec.decode` — throws `FormatException` for every
 *    malformed/unsupported input. Nothing else.
 *  - `MigJson.parseBundleDocument` — returns null when the shape is not exactly
 *    the expected one. Iterative and depth-bounded, so no StackOverflowError.
 *  - `MigrationSeal.open` — throws `SealException`/`TooLargeException` only, and
 *    "no detail leaks" between the failure causes.
 */
class MigrationBundleFuzzTest {

    @FuzzTest(maxDuration = "60s")
    fun fuzzBundleDecode(data: FuzzedDataProvider) {
        val bytes = data.consumeRemainingAsBytes()

        val bundle = try {
            bounded("MigrationBundleCodec.decode") { MigrationBundleCodec.decode(bytes) }
        } catch (_: MigrationBundleCodec.FormatException) {
            null   // the one documented rejection
        }

        if (bundle != null) {
            // Version FIRST: nothing may be interpreted under an unknown format.
            check(bundle.version == MigrationBundleCodec.CURRENT_VERSION) {
                "decoded a bundle at version ${bundle.version}"
            }
            check(bundle.createdMs >= 0) { "decoded a negative 'created' timestamp" }
            check(MoveHandleCodec.isValidBundleId(bundle.bundleId)) { "decoded an invalid bundle id" }
            // `_meta` must have been filtered through MoveMetaPolicy — no vault
            // key material may ride a bundle in, even inside the ciphertext.
            for (key in bundle.snapshot.meta.keys) {
                check(com.vg.run.MoveMetaPolicy.isAllowedKey(key)) {
                    "decode let a policy-denied _meta key through: '$key'"
                }
            }
            // Re-encoding what it accepted must decode identically: a document the
            // reader accepts but the writer cannot reproduce means the halves of
            // the format disagree, and a move would silently lose rows.
            val roundTripped = MigrationBundleCodec.decode(MigrationBundleCodec.encode(bundle))
            check(roundTripped.snapshot.contacts.size == bundle.snapshot.contacts.size) {
                "bundle round trip lost contacts"
            }
            check(roundTripped.snapshot.meta == bundle.snapshot.meta) { "bundle round trip lost _meta" }
        }
    }

    /** The bundle document scanner beneath the codec — the recursion-free one. */
    @FuzzTest(maxDuration = "60s")
    fun fuzzBundleDocument(data: FuzzedDataProvider) {
        val text = data.consumeRemainingAsString()
        val doc = bounded("MigJson.parseBundleDocument") { MigJson.parseBundleDocument(text) }
        if (doc != null) {
            // The `meta` block is a FLAT object of string values only — the reader
            // rejects a non-string there rather than coercing it.
            check(doc.meta.size <= 200_000) { "parseBundleDocument returned ${doc.meta.size} meta rows" }
        }
        // strictLong: deliberately NOT toLongOrNull (which accepts Unicode digits
        // and a leading '+'), so two different texts can never denote one counter.
        val n = bounded("MigJson.strictLong") { MigJson.strictLong(text) }
        if (n != null) {
            check(text.all { it in '0'..'9' || it == '-' }) {
                "strictLong accepted a non-ASCII-decimal text: '${text.take(32)}'"
            }
            // Whatever it accepted must have been ASCII decimal with at most a
            // single leading '-' — no Unicode digits, no '+', no whitespace.
            val digits = if (text.startsWith("-")) text.substring(1) else text
            check(digits.isNotEmpty() && digits.all { it in '0'..'9' }) {
                "strictLong accepted '${text.take(32)}'"
            }
        }
    }

    /** Deep nesting into the bundle reader: iterative by construction, must not use stack. */
    @FuzzTest(maxDuration = "60s")
    fun fuzzBundleDocumentNesting(data: FuzzedDataProvider) {
        val depth = data.consumeInt(1, 100_000)
        val payload = data.consumeRemainingAsString().take(32).replace('"', '\'')
        val nested = "{\"unknown\":" + "[".repeat(depth) + payload + "]".repeat(depth) + "}"
        bounded("parseBundleDocument(deep)") { MigJson.parseBundleDocument(nested) }
    }

    /** The sealed-chunk opener — structural checks on relay-supplied chunk lists. */
    @FuzzTest(maxDuration = "60s")
    fun fuzzSealOpen(data: FuzzedDataProvider) {
        val chunkCount = data.consumeInt(0, 8)
        val chunkSize = data.consumeInt(0, 512)
        val code = data.consumeBytes(20)
        val filler = data.consumeRemainingAsBytes()

        val chunks = (0 until chunkCount).map { i ->
            ByteArray(chunkSize) { j -> filler.getOrElse((i * chunkSize + j) % maxOf(filler.size, 1)) { 0 } }
        }
        val key = if (code.size == 20) code else ByteArray(20)

        onlyThrows(MigrationSeal.SealException::class, MigrationSeal.TooLargeException::class) {
            bounded("MigrationSeal.open") {
                MigrationSeal.open(chunks, key, FuzzIds.INBOX_A, LEGAL_BUNDLE_ID)
            }
        }
    }

    // ------------------------------------------------------------------
    // Fixed regression tests.
    // ------------------------------------------------------------------

    @Test
    fun malformedBundlesThrowOnlyFormatException() {
        val malformed = listOf(
            "", "{", "}", "null", "[]", "{\"v\":1", "{\"v\":\"1\"}",
            "{\"v\":2,\"schema\":9}", "{\"v\":1,\"schema\":9,\"from\":\"\"}",
            "{\"v\":1,\"schema\":9,\"from\":\"android\",\"created\":-1}",
        )
        for (text in malformed) {
            try {
                MigrationBundleCodec.decode(text.encodeToByteArray())
                throw AssertionError("decode accepted '$text'")
            } catch (_: MigrationBundleCodec.FormatException) {
                // documented
            }
        }
    }

    @Test
    fun anEmptyBundleRoundTrips() {
        val bundle = MigrationBundle(
            version = MigrationBundleCodec.CURRENT_VERSION,
            schema = MigrationBundleCodec.CURRENT_SCHEMA,
            from = MigrationBundle.FROM_ANDROID,
            createdMs = 1L,
            bundleId = LEGAL_BUNDLE_ID,
            snapshot = VaultSnapshot(emptyList(), emptyList(), emptyList(), emptyList(), emptyMap()),
        )
        val decoded = MigrationBundleCodec.decode(MigrationBundleCodec.encode(bundle))
        check(decoded.bundleId == LEGAL_BUNDLE_ID && decoded.createdMs == 1L)
    }

    @Test
    fun strictLongRejectsUnicodeDigitsAndLeadingPlus() {
        check(MigJson.strictLong("+1") == null) { "strictLong accepted a leading '+'" }
        check(MigJson.strictLong("١٢٣") == null) { "strictLong accepted Arabic-Indic digits" }
        check(MigJson.strictLong("9223372036854775808") == null) { "strictLong overflowed" }
        // FINDING (fuzz 2026-09-16, LOW/cosmetic): Long.MIN_VALUE is NOT parseable.
        // The overflow guard runs on the MAGNITUDE before the sign is applied, so
        // "-9223372036854775808" is rejected while "-9223372036854775807" is fine.
        // Harmless in practice — every field this parses is a counter, epoch or
        // millisecond timestamp, none of which legitimately reaches Long.MIN_VALUE,
        // and the failure mode is a clean FormatException. Pinned so a future
        // "fix" is a deliberate choice rather than an accident.
        check(MigJson.strictLong("-9223372036854775808") == null) {
            "strictLong now parses Long.MIN_VALUE — update this pin and the fuzz README"
        }
        check(MigJson.strictLong("-9223372036854775807") == -9223372036854775807L)
    }

    private companion object {
        /** 16 base64url chars — passes MoveHandleCodec.isValidBundleId. */
        const val LEGAL_BUNDLE_ID = "AAAAAAAAAAAAAAAA"
    }
}

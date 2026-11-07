package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class EnvelopeEscapingTest {

    private val mm = MessageManager(InMemoryVault(), "http://x.onion", RecordingRelayHttp())

    /** Mirrors parseEnvelope: jsonEscape wraps+escapes; the regex extracts the
     *  inner string (without the surrounding quotes); jsonUnescape decodes it. */
    private fun roundTrip(s: String): String {
        val escaped = mm.jsonEscape(s)
        assertTrue(escaped.startsWith("\"") && escaped.endsWith("\""))
        val inner = escaped.substring(1, escaped.length - 1)
        return mm.jsonUnescape(inner)
    }

    // --- PoW challenge field validation (CRLF / header-injection guard) ---

    @Test
    fun parseChallenge_acceptsCleanToken() {
        val body = """{"nonce":"abc123","token":"opaqueTok.-_=","difficulty":10}"""
        val c = mm.parseChallenge(body)
        assertNotNull(c)
        assertEquals("opaqueTok.-_=", c!!.token)
    }

    @Test
    fun parseChallenge_rejectsControlCharsInToken() {
        // A hostile relay embeds CRLF in the token to inject an extra header on
        // the iOS raw-HTTP X-PoW-Token request. Must be rejected.
        val body = "{\"nonce\":\"abc\",\"token\":\"tok\r\nX-Evil: 1\",\"difficulty\":10}"
        assertNull(mm.parseChallenge(body))
    }

    @Test
    fun parseChallenge_rejectsOverlongToken() {
        // The token/nonce is echoed verbatim into an HTTP header, so an
        // unbounded relay value is rejected (bound = MAX_POW_FIELD_LEN).
        val tooLong = "a".repeat(MAX_POW_FIELD_LEN + 1)
        assertNull(mm.parseChallenge("""{"nonce":"abc","token":"$tooLong","difficulty":10}"""))
        // A value exactly at the bound is still accepted.
        val atBound = "b".repeat(MAX_POW_FIELD_LEN)
        assertNotNull(mm.parseChallenge("""{"nonce":"abc","token":"$atBound","difficulty":10}"""))
    }

    @Test
    fun parseChallenge_hugeField_parsesLinearly_noStackOverflow() {
        // The pre-auth mint handshake now parses via the non-regex
        // depth-1 scanner (parseTopLevelJson), not Kotlin/Native's recursive regex
        // engine. A multi-MB relay-controlled field must be handled in a single
        // O(n) pass without a stack overflow. It's over the length bound so it's
        // rejected — the point is it returns promptly rather than crashing.
        val huge = "a".repeat(2_000_000)
        assertNull(mm.parseChallenge("""{"nonce":"abc","token":"$huge","difficulty":10}"""))
    }

    @Test
    fun roundtrips_backslashes_and_escape_sequences() {
        // The middle cases are the backslash-before-escape-letter regression: a literal backslash followed
        // by an escape letter (e.g. the text `\n` typed by a user) must survive
        // intact, not collapse into a control character.
        val samples = listOf(
            "hello world",
            "back\\slash",                 // a single literal backslash
            "literal \\n not a newline",   // backslash + 'n' as literal text
            "literal \\t \\r \\\\ end",    // mixed literal escapes
            "tab\tinside",                 // a real tab
            "line\nbreak",                 // a real newline
            "quote \" inside",
            "emoji 🦊 ünïcode ☃",
            "",
        )
        for (s in samples) {
            assertEquals(s, roundTrip(s), "round-trip must be lossless for: <$s>")
        }
    }
}

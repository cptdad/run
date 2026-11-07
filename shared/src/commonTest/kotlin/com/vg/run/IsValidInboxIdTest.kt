package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class IsValidInboxIdTest {

    // Sample produced by encodeBase64Url on 24 deterministic bytes — checked
    // against the regex's "32 chars of [A-Za-z0-9_-]" rule. Several of the
    // tests below derive variants from this baseline.
    private val sampleInboxId = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYX"

    @Test
    fun accepts_well_formed_capability_inbox_id() {
        assertTrue(isValidInboxId(sampleInboxId))
    }

    @Test
    fun accepts_full_alphabet_including_dash_and_underscore() {
        // 32 chars covering uppercase, lowercase, digit, '-' and '_'.
        val sample = "Aa0-_BbCcDdEeFfGgHhIiJjKkLlMmNnOo"
        // sanity-check the fixture itself before using it as a positive case
        assertEquals(33, sample.length)
        assertTrue(!isValidInboxId(sample))
        assertTrue(isValidInboxId(sample.substring(0, 32)))
    }

    @Test
    fun rejects_legacy_uuid_format() {
        // Hard-break: pre-migration UUIDs are no longer valid inbox IDs.
        assertEquals(false, isValidInboxId("550e8400-e29b-41d4-a716-446655440000"))
        assertEquals(false, isValidInboxId("550E8400-E29B-41D4-A716-446655440000"))
    }

    @Test
    fun rejects_empty_string() {
        assertEquals(false, isValidInboxId(""))
    }

    @Test
    fun rejects_path_traversal_attempt() {
        assertEquals(false, isValidInboxId("../../../../etc/passwd"))
    }

    @Test
    fun rejects_url_with_id_inside() {
        assertEquals(false, isValidInboxId("http://evil.example.com/$sampleInboxId"))
    }

    @Test
    fun rejects_trailing_garbage() {
        assertEquals(false, isValidInboxId("$sampleInboxId/x"))
        assertEquals(false, isValidInboxId("$sampleInboxId\n"))
    }

    @Test
    fun rejects_leading_whitespace() {
        assertEquals(false, isValidInboxId(" $sampleInboxId"))
    }

    @Test
    fun rejects_standard_base64_plus_and_slash() {
        // The relay emits base64url (`-` and `_`), not standard base64 (`+`
        // and `/`). A '+' or '/' indicates a non-conforming source.
        assertEquals(false, isValidInboxId("AAECAwQFBgcICQoLDA0ODxAREhMUFRY+"))
        assertEquals(false, isValidInboxId("AAECAwQFBgcICQoLDA0ODxAREhMUFRY/"))
    }

    @Test
    fun anInboxIdWithTrailingPadding_isRejected() {
        // base64url-NO-pad — a trailing '=' must be rejected.
        assertEquals(false, isValidInboxId("AAECAwQFBgcICQoLDA0ODxAREhMUFRY="))
    }

    @Test
    fun anInboxIdOfTheWrongLength_isRejected() {
        assertEquals(false, isValidInboxId("AAECAwQFBgcICQoLDA0ODxAREhMUFRY"))   // 31
        assertEquals(false, isValidInboxId("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXY")) // 33
    }
}

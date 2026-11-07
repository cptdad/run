package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// Regression: a malicious relay returning a huge array of tiny
// elements must NOT be materialized unbounded (→ OutOfMemoryError, an Error
// that escapes the poll path's `catch (Exception)` and crashes the process).
// parseStringArrayField now hard-caps element count DURING the scan and fails
// closed (null → parseJsonStringArray throws → caller treats as empty poll).
// ---------------------------------------------------------------------------

class ParseArrayCapTest {

    @Test
    fun overCapArray_failsClosed_noOom() {
        // A body of many tiny elements — well under the 16 MiB transport cap in
        // raw bytes, but far over the element cap. Must return null, not a giant list.
        val n = MAX_PARSE_ARRAY_ELEMENTS + 100
        val body = buildString {
            append("{\"blobs\":[")
            repeat(n) { if (it > 0) append(','); append("\"a\"") }
            append("]}")
        }
        assertNull(parseStringArrayField(body, "blobs"))
        // The public entry point surfaces it as a thrown parse error, which the
        // poll callers catch and treat as an empty poll (no OOM, no crash).
        assertFailsWith<IllegalArgumentException> { parseJsonStringArray(body, "blobs") }
    }

    @Test
    fun atCapArray_stillParses() {
        // Exactly at the cap is accepted (the guard trips only ABOVE it).
        val body = buildString {
            append("{\"blobs\":[")
            repeat(MAX_PARSE_ARRAY_ELEMENTS) { if (it > 0) append(','); append("\"x\"") }
            append("]}")
        }
        val parsed = parseStringArrayField(body, "blobs")
        assertTrue(parsed != null && parsed.size == MAX_PARSE_ARRAY_ELEMENTS)
    }

    @Test
    fun normalSmallArray_unaffected() {
        val parsed = parseStringArrayField("{\"mem\":[\"alice\",\"bob\",\"carol\"]}", "mem")
        assertEquals(listOf("alice", "bob", "carol"), parsed)
    }
}

// ---------------------------------------------------------------------------
// Regression: the OBJECT sibling of the cap above.
// parseTopLevelJson built an unbounded LinkedHashMap from relay-supplied bytes —
// a 16 MiB body of distinct short keys is ~1.68M entries (~300 MB), i.e. an
// OutOfMemoryError (an Error, so it escapes `catch (Exception)`) on every poll
// and PRE-AUTH on the mint handshake. Both bounds fail closed to an empty map,
// exactly as a malformed body already did; the relay call sites go through
// parseRelayJsonOrNull, which turns a refusal/VM Error into a relay error.
// ---------------------------------------------------------------------------

class ParseObjectCapTest {

    private fun obj(pairs: Int, key: (Int) -> String) = buildString {
        append('{')
        repeat(pairs) { if (it > 0) append(','); append('"').append(key(it)).append("\":0") }
        append('}')
    }

    @Test
    fun overCapObject_failsClosed_emptyMap() {
        val body = obj(MAX_PARSE_OBJECT_KEYS + 1) { "k$it" }
        assertTrue(parseTopLevelJson(body).isEmpty(), "cap+1 distinct keys must be refused whole")
        // Guarded entry point: still a map (the body is well under the LENGTH bound),
        // but an empty one — no field is readable, which is what every caller treats
        // as a malformed/failed relay answer.
        assertTrue(parseRelayJsonOrNull(body)!!.isEmpty())
    }

    @Test
    fun atCapObject_stillParses() {
        val body = obj(MAX_PARSE_OBJECT_KEYS) { "k$it" }
        val parsed = parseTopLevelJson(body)
        assertEquals(MAX_PARSE_OBJECT_KEYS, parsed.size)
        assertEquals("0", parsed["k0"]?.text)
        assertEquals("0", parsed["k${MAX_PARSE_OBJECT_KEYS - 1}"]?.text)
    }

    @Test
    fun duplicateKeyFlood_isAlsoCapped() {
        // Duplicates never grow the map (first occurrence wins), so a map-size-only
        // cap would let a relay spin the scanner over 16 MiB of them. The cap counts
        // key OCCURRENCES, so this is refused too.
        val body = obj(MAX_PARSE_OBJECT_KEYS + 1) { "same" }
        assertTrue(parseTopLevelJson(body).isEmpty())
    }

    @Test
    fun overLengthBody_refusedBeforeScanning() {
        val body = "{\"pending\":7}" + " ".repeat(MAX_PARSE_OBJECT_CHARS)
        assertTrue(body.length > MAX_PARSE_OBJECT_CHARS)
        assertTrue(parseTopLevelJson(body).isEmpty(), "an over-length body must not be scanned at all")
        // The relay call sites need the refusal to be DISTINGUISHABLE from `{}`:
        // null is what routes them onto the same path a non-2xx takes.
        assertNull(parseRelayJsonOrNull(body))
    }

    @Test
    fun exactlyAtLengthBound_stillParses() {
        val head = "{\"pending\":7}"
        val body = head + " ".repeat(MAX_PARSE_OBJECT_CHARS - head.length)
        assertEquals(MAX_PARSE_OBJECT_CHARS, body.length)
        assertEquals("7", parseTopLevelJson(body)["pending"]?.text)
        assertEquals("7", parseRelayJsonOrNull(body)?.get("pending")?.text)
    }

    @Test
    fun everyLegitimateBodyStillParses_andIsFarUnderTheCap() {
        // The full enumeration the bounds were sized against (see the comment above
        // MAX_PARSE_OBJECT_KEYS). Largest is the 10-field message envelope.
        val id = "A".repeat(32)
        val cap43 = "B".repeat(43)
        val fixtures = mapOf(
            // relay: PoW challenge (the pre-auth body), mint response, peek,
            // ONE batch-peek result element, move peek.
            "challenge" to """{"error":"pow","nonce":"n1","token":"t1","difficulty":12,"ttlSeconds":60,"algorithm":"sha256","preimage":"nonce:counter"}""",
            "mint" to """{"inboxId":"$id","readCapability":"$cap43","writeCapability":"$cap43","expiresAt":1713364800000}""",
            "peek" to """{"pending":3}""",
            "batchElement" to """{"id":"$id","pending":3}""",
            "batchElementStatus" to """{"id":"$id","status":404}""",
            "movePeek" to """{"pending":1}""",
            // peer: the message envelope (the widest legitimate object) and a
            // group roster control body.
            "envelope" to """{"e":"ep1","c":7,"t":60000,"ch":"m","di":"$id","g":"g1","h":"h1","k":"inbox","b":"{}","m":"hi"}""",
            "roster" to """{"n":"grp","ep":4,"adm":"m1","mem":["m1:","m2:"]}""",
            // local/QR: pairing payload and move handle.
            "pairing" to """{"inbox":"$id","wcap":"$cap43","cib":"$id","cwcap":"$cap43","secret":"s","rv":"2"}""",
            "moveHandle" to """{"v":"1","inbox":"$id","rcap":"$cap43","code":"C","bid":"D"}""",
        )
        for ((name, body) in fixtures) {
            val parsed = parseTopLevelJson(body)
            assertTrue(parsed.isNotEmpty(), "$name must still parse")
            assertTrue(
                parsed.size * 8 < MAX_PARSE_OBJECT_KEYS,
                "$name has ${parsed.size} top-level keys — the cap is meant to sit far above every legitimate body",
            )
            assertTrue(body.length < MAX_PARSE_OBJECT_CHARS, "$name must be far under the length bound")
            assertEquals(parsed.size, parseRelayJsonOrNull(body)?.size, "$name must parse identically when guarded")
        }
        // Spot-check the two the mint handshake actually reads.
        assertEquals("n1", parseTopLevelJson(fixtures.getValue("challenge"))["nonce"]?.text)
        assertEquals(id, parseTopLevelJson(fixtures.getValue("mint"))["inboxId"]?.text)
        assertEquals("hi", parseTopLevelJson(fixtures.getValue("envelope"))["m"]?.text)
    }

    @Test
    fun overLengthEnvelope_isHardDropped_notSurfacedAsABubble() {
        // An empty map means "legacy plaintext blob" inside parseEnvelope, which would
        // otherwise turn a refused (over-length) envelope into a multi-MB chat bubble.
        val mm = MessageManager(InMemoryVault(), "http://x.onion", RecordingRelayHttp())
        val padding = "x".repeat(MAX_PARSE_OBJECT_CHARS)
        assertNull(mm.parseEnvelope("""{"e":"ep1","c":7,"t":60000,"m":"$padding"}"""))
        // …while a normal envelope is untouched.
        val env = mm.parseEnvelope("""{"e":"ep1","c":7,"t":60000,"m":"hi"}""")
        assertEquals("hi", env?.text)
        assertEquals(7L, env?.counter)
    }
}

class ParseEnvelopeKeyCapTest {
    @Test
    fun envelopeWithTooManyKeysIsHardDropped_notEchoedAsBubble() {
        val mm = MessageManager(InMemoryVault(), "http://x.onion", RecordingRelayHttp())
        val keys = (0..MAX_PARSE_OBJECT_KEYS).joinToString(",") { "\"k$it\":0" }
        val raw = "{\"e\":\"abc\",\"c\":1,\"t\":0,\"m\":\"hi\",$keys}"
        assertNull(mm.parseEnvelope(raw))
    }

    @Test
    fun malformedBraceBlobIsHardDropped() {
        val mm = MessageManager(InMemoryVault(), "http://x.onion", RecordingRelayHttp())
        assertNull(mm.parseEnvelope("{not json at all"))
    }
}

package com.vg.run

// ---------------------------------------------------------------------------
// JsonParser — platform-agnostic JSON parsing for relay responses.
//
// The ARRAY scanners live here: [parseStringArrayField] (string arrays — the
// relay's {"blobs":[…]} poll answer and group control bodies) and
// [parseObjectArrayField] (raw object substrings — the batch /peek answer), both
// over the shared [findArrayOpen]. The scalar helpers live in RelayJson.kt.
//
// Two lookup semantics coexist and are NOT interchangeable:
// [firstStringFieldAnywhere] and the two array scanners here return the FIRST
// `"key":` match ANYWHERE in the text (nested objects included);
// [parseTopLevelJson] (RelayJson.kt) surfaces depth-1 keys only. Both keep the
// FIRST of duplicate keys.
//
// One implementation on both platforms means identical accept/reject behavior
// (per-platform JSON divergence was a real problem: org.json's
// getString() coerced numbers/booleans to strings, NSJSONSerialization didn't).
// It also makes the poll path exercisable from JVM unit tests, where org.json
// is unavailable ("not mocked"). [parseJsonStringArray] alone THROWS on a
// missing/malformed array (callers catch and treat it as an empty/failed poll);
// every other scanner here returns null.
// ---------------------------------------------------------------------------

/** Extracts a JSON array of strings from [json] under the FIRST [arrayKey]
 *  found anywhere in the text (not depth-aware). */
fun parseJsonStringArray(json: String, arrayKey: String): List<String> =
    parseStringArrayField(json, arrayKey)
        ?: throw IllegalArgumentException("no string array under '$arrayKey'")

// Hard cap on parsed array elements, enforced DURING the scan.
// A malicious relay can return a 16 MiB body of ~4-byte elements
// (`{"blobs":["a","a",…]}`) → ~4M String objects (~150-200 MB transient) →
// OutOfMemoryError, which is an Error (NOT an Exception) and so escapes every
// `catch (_: Exception)` on the poll path, crashing the process on demand. No
// legitimate response approaches this: the poll blob list is separately capped
// at MAX_BLOBS_PER_POLL (2048) and rosters/tags are tiny. Failing closed
// (return null) here makes the caller treat it as an empty/failed poll.
internal const val MAX_PARSE_ARRAY_ELEMENTS = 8192

// Non-regex array-open finder — parseStringArrayField runs on the
// relay's {"blobs":[…]} poll response AND group control bodies (relay + malicious
// contact reach), so the array-open scan must not touch Kotlin/Native's recursive
// regex engine either. Finds `"key"` then a whitespace-tolerant `:` then `[`, and
// returns the index just after `[` (or null). Same match semantics as
// Regex(""""key"\s*:\s*\["""), scanned linearly.
private fun findArrayOpen(body: String, key: String): Int? {
    val token = "\"$key\""
    var from = 0
    while (true) {
        val k = body.indexOf(token, from)
        if (k < 0) return null
        var i = k + token.length
        while (i < body.length && body[i].isWhitespace()) i++
        if (i < body.length && body[i] == ':') {
            i++
            while (i < body.length && body[i].isWhitespace()) i++
            if (i < body.length && body[i] == '[') return i + 1
        }
        from = k + token.length
    }
}

/**
 * Minimal string-array field scanner. ONE plain commonMain implementation (NOT
 * expect/actual) — [parseJsonStringArray] above delegates here, so both
 * platforms accept and reject the exact same inputs (per-platform JSON divergence
 * was a real past defect, and org.json is additionally unavailable in JVM unit
 * tests). Used for GroupManager control bodies and the relay's
 * {"blobs":[…]} poll response. Returns null on any structural mismatch or
 * non-string element.
 */
internal fun parseStringArrayField(body: String, key: String): List<String>? {
    var i = findArrayOpen(body, key) ?: return null
    val items = mutableListOf<String>()
    val sb = StringBuilder()
    var inString = false
    while (i < body.length) {
        val c = body[i]
        if (inString) {
            when {
                c == '\\' && i + 1 < body.length -> { sb.append(c).append(body[i + 1]); i += 2 }
                c == '"' -> {
                    items.add(jsonUnescapeString(sb.toString())); sb.setLength(0); inString = false; i++
                    // Stop the object explosion before it OOMs (Error escapes the
                    // callers' Exception catch); reject the whole response.
                    if (items.size > MAX_PARSE_ARRAY_ELEMENTS) return null
                }
                else -> { sb.append(c); i++ }
            }
            continue
        }
        when (c) {
            '"' -> { inString = true; i++ }
            ']' -> return items
            ',', ' ', '\t', '\n', '\r' -> i++
            else -> return null   // non-string element — malformed for this protocol
        }
    }
    return null   // unterminated array
}

/**
 * The OBJECT-array sibling of [parseStringArrayField]: returns each element of
 * `"key":[{…},{…}]` as its RAW substring, for a caller that then runs
 * [parseTopLevelJson] over each one. Used by [MessageManager.peekInboxesBatch] on
 * the relay's `{"v":1,"results":[…]}` answer.
 *
 * Same three rules as its sibling, and for the same reasons:
 *  - **Regex-free and NON-RECURSIVE**: this runs on a raw
 *    malicious-relay response, and Kotlin/Native's regex engine matches
 *    recursively — a long body would overflow the native stack.
 *  - **Element-capped DURING the scan**, here at [maxElements],
 *    which the caller sets to the number of items it actually asked about. A
 *    relay answering with more elements than were requested is rejected outright
 *    rather than materialised.
 *  - **Fails CLOSED**: any structural malformation (a non-object element, an
 *    unterminated string or object, an unterminated array, a missing key)
 *    returns null, which the caller reads as "this batch told us nothing" —
 *    never as "the inboxes are empty".
 */
internal fun parseObjectArrayField(body: String, key: String, maxElements: Int): List<String>? {
    var i = findArrayOpen(body, key) ?: return null
    val out = mutableListOf<String>()
    while (i < body.length) {
        when (body[i]) {
            ' ', '\t', '\n', '\r', ',' -> i++
            ']' -> return out
            '{' -> {
                val start = i
                var depth = 0
                var closed = false
                while (i < body.length && !closed) {
                    when (body[i]) {
                        '"' -> {
                            // Consume the whole string so a brace INSIDE it can never
                            // move the depth counter.
                            i++
                            var terminated = false
                            while (i < body.length) {
                                if (body[i] == '\\' && i + 1 < body.length) i += 2
                                else if (body[i] == '"') { i++; terminated = true; break }
                                else i++
                            }
                            if (!terminated) return null
                        }
                        '{', '[' -> { depth++; i++ }
                        '}', ']' -> { depth--; i++; if (depth <= 0) closed = true }
                        else -> i++
                    }
                }
                if (!closed) return null
                out.add(body.substring(start, i))
                if (out.size > maxElements) return null
            }
            else -> return null   // non-object element — malformed for this protocol
        }
    }
    return null   // unterminated array
}

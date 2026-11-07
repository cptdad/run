package com.vg.run

// ---------------------------------------------------------------------------
// The relay / envelope JSON helpers: string escape + unescape, the single-field
// scanner and the depth-1 top-level object parser with its two bounds. Pure
// functions, shared by MessageManager, GroupManager and the pairing / move codecs.
// (Moved verbatim out of MessageManager.kt, 2026-11-06.)
// ---------------------------------------------------------------------------

/** Same tag the lines had while this code lived in MessageManager.kt. */
private const val LOG_TAG = "MessageManager"

/**
 * Escapes [s] as a double-quoted JSON string literal (the inverse of
 * [jsonUnescapeString]). Shared by the message envelope and GroupManager's
 * control bodies.
 */
internal fun jsonEscapeString(s: String): String {
    val sb = StringBuilder("\"")
    for (c in s) {
        when (c) {
            '"'  -> sb.append("\\\"")
            '\\' -> sb.append("\\\\")
            '\n' -> sb.append("\\n")
            '\r' -> sb.append("\\r")
            '\t' -> sb.append("\\t")
            else -> sb.append(c)
        }
    }
    sb.append('"')
    return sb.toString()
}

/**
 * Single left-to-right pass JSON string unescape. The previous
 * sequential .replace() chain unescaped `\\` LAST, so an escaped backslash
 * followed by an escape letter (e.g. the peer's literal `\n`, on the wire
 * as `\\n`) was mis-decoded to backslash + newline. A single pass consumes
 * each escape exactly once. Runs only on post-AEAD authenticated
 * plaintext, so there is no ReDoS / hostile-input surface.
 */
internal fun jsonUnescapeString(s: String): String {
    val sb = StringBuilder(s.length)
    var i = 0
    while (i < s.length) {
        val c = s[i]
        if (c == '\\' && i + 1 < s.length) {
            when (val n = s[i + 1]) {
                '"'  -> { sb.append('"'); i += 2 }
                '\\' -> { sb.append('\\'); i += 2 }
                '/'  -> { sb.append('/'); i += 2 }
                'n'  -> { sb.append('\n'); i += 2 }
                'r'  -> { sb.append('\r'); i += 2 }
                't'  -> { sb.append('\t'); i += 2 }
                'b'  -> { sb.append(8.toChar()); i += 2 }
                'f'  -> { sb.append(12.toChar()); i += 2 }
                'u'  -> {
                    val hex = if (i + 6 <= s.length) s.substring(i + 2, i + 6) else null
                    val code = hex?.toIntOrNull(16)
                    if (code != null) { sb.append(code.toChar()); i += 6 }
                    else { sb.append(c); i += 1 }  // malformed \u — keep the backslash literally
                }
                else -> { sb.append(n); i += 2 }   // unknown escape: drop the backslash, keep the char
            }
        } else {
            sb.append(c); i += 1
        }
    }
    return sb.toString()
}

/**
 * The FIRST `"key":"…"` ANYWHERE in [body] — not depth-aware (a key inside a
 * nested object matches too); for depth-1 keys use [parseTopLevelJson].
 *
 * Extracts a JSON string field `"key":"value"` by a LINEAR scan, returning the
 * unescaped value (or null if absent / not a quoted string).
 *
 * Deliberately NOT a regex. Kotlin/Native's regex engine matches RECURSIVELY,
 * so the natural pattern `"((?:[^"\\]|\\.)*)"` overflows the native stack on a
 * long value (a referral accept body / inbox offer carries base64 keys + caps,
 * ~250 chars) and crashes iOS with EXC_BAD_ACCESS / Bus error — observed taking
 * down both the referral introducer and introducees, and message-envelope
 * parsing. A scan has no recursion and cannot overflow. Every control/envelope
 * parser routes through this; keep new ones off the `(?:…)*` regex too.
 */
internal fun firstStringFieldAnywhere(body: String, key: String): String? {
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
            if (i < body.length && body[i] == '"') {
                i++
                val sb = StringBuilder()
                while (i < body.length) {
                    val c = body[i]
                    when {
                        // Keep escape sequences intact for jsonUnescapeString;
                        // only an UNescaped quote terminates the value.
                        c == '\\' -> {
                            if (i + 1 >= body.length) return null   // dangling escape
                            sb.append(c).append(body[i + 1]); i += 2
                        }
                        c == '"' -> return jsonUnescapeString(sb.toString())
                        else -> { sb.append(c); i++ }
                    }
                }
                return null   // unterminated string
            }
        }
        // This "key" wasn't a real key:"…" — keep scanning for the next one.
        from = k + token.length
    }
}

/** A parsed top-level JSON scalar: [text] is the value (unescaped if a string),
 *  [isString] distinguishes `"..."` from a number/literal. See [parseTopLevelJson]. */
internal class JsonScalar(val text: String, val isString: Boolean)

// ---------------------------------------------------------------------------
// The two BOUNDS on the depth-1 object scanner (2026-09-22).
//
// Its array sibling has long had [MAX_PARSE_ARRAY_ELEMENTS]; the
// object scanner never got one, so its only ceiling was the 16 MiB transport cap
// ([MAX_RESPONSE_BYTES]) — and 16 MiB of `"aaaa":0,` pairs is ~1.68M DISTINCT
// top-level keys, i.e. a few hundred MB of LinkedHashMap entries.
// OutOfMemoryError is an Error, not an Exception, so it escapes every
// `catch (e: Exception)` on the poll path: a repeatable, unauthenticated process
// kill by any relay, on every poll AND pre-auth on the mint handshake.
//
// Both bounds are sized against the LARGEST LEGITIMATE top-level object this
// scanner ever sees. Enumerated in full:
//   relay bodies  — PoW challenge 7 fields (error/nonce/token/difficulty/
//                   ttlSeconds/algorithm/preimage), mint response 4, GET /peek 1
//                   (`pending`), ONE POST /peek result element 2 (`id` +
//                   `pending`|`status` — the batch body itself is an ARRAY and is
//                   parsed by parseObjectArrayField, already capped at the number
//                   of items we asked about), move /peek 1. Telemetry/version
//                   answers never reach this scanner at all (POST /telemetry/connect
//                   is fire-and-forget and the app-store version arrives in an
//                   allowlisted HEADER, see MAX_APP_VERSION_HEADER_CHARS).
//   peer bodies   — the message ENVELOPE, 12 fields (e,c,t,ch,di,g,h,k,b,m,cr,crw), and
//                   group control bodies 4-5 (n,ep,adm,you,mem).
//   local/QR      — pairing payload 6, move handle 5.
// So TWELVE is the real maximum and [MAX_PARSE_OBJECT_KEYS] is over 20x it.
//
// The LENGTH bound is sized the same way: the biggest legitimate input is the
// message envelope, whose hard ceiling is [MAX_PADDED_PAYLOAD_BYTES] (131 068 B —
// what padMessage will pack, and a String's char count can never exceed its UTF-8
// byte count). 1 MiB is 8x that, and 16x BELOW the transport cap — which stays at
// 16 MiB, because an inbox DRAIN is a blob array and is parsed by
// parseStringArrayField, never here.
//
// Both fail CLOSED, to an EMPTY map — exactly what a malformed body already
// returns, and what every caller already reads as "no fields present".
// ---------------------------------------------------------------------------
internal const val MAX_PARSE_OBJECT_KEYS = 256
internal const val MAX_PARSE_OBJECT_CHARS = 1024 * 1024

/**
 * Parses the TOP-LEVEL keys of a flat JSON object into key -> [JsonScalar].
 *
 * Only keys at object depth 1 are surfaced; string values and any nested
 * object/array values are consumed WITHOUT exposing their contents. So a sender
 * cannot smuggle a `"c":N` (or any key) inside a string value or a nested
 * object and have it mistaken for a real top-level field — this is the depth
 * awareness the old per-key scanners lacked.
 *
 * Regex-free, single forward pass with an explicit depth counter and no
 * recursion (Kotlin/Native stack-safe). Best-effort: on structural malformation
 * it returns whatever was parsed up to that point, and callers treat missing
 * keys as absent. Duplicate keys keep the FIRST occurrence.
 *
 * BOUNDED: an over-long body is refused before the scan and an over-wide
 * object is refused during it — both to an EMPTY map, the same answer a
 * malformed body gives. See [MAX_PARSE_OBJECT_CHARS] / [MAX_PARSE_OBJECT_KEYS].
 * Relay-controlled bodies should go through [parseRelayJsonOrNull], which also
 * turns a VM Error out of this scanner into a relay error instead of a crash.
 */
internal fun parseTopLevelJson(body: String): Map<String, JsonScalar> {
    val out = LinkedHashMap<String, JsonScalar>()
    // Length pre-check, BEFORE a single character is scanned.
    if (body.length > MAX_PARSE_OBJECT_CHARS) return emptyMap()
    val n = body.length
    var i = 0
    while (i < n && body[i] != '{') i++
    if (i >= n) return out
    i++ // past '{'
    var pairs = 0
    while (i < n) {
        while (i < n && (body[i].isWhitespace() || body[i] == ',')) i++
        if (i >= n || body[i] == '}') break
        if (body[i] != '"') break // key must be a quoted string; bail on malformed
        // ---- key ----
        val keySb = StringBuilder()
        i++
        var keyClosed = false
        while (i < n) {
            val c = body[i]
            if (c == '\\' && i + 1 < n) { keySb.append(c).append(body[i + 1]); i += 2 }
            else if (c == '"') { i++; keyClosed = true; break }
            else { keySb.append(c); i++ }
        }
        if (!keyClosed) break
        // Element cap, enforced DURING the scan like its array sibling's.
        // It counts every top-level key OCCURRENCE — duplicates (which never grow
        // `out`) and nested values (which are skipped, not surfaced) included — so
        // it bounds the LOOP as well as the map. Fails closed on the whole object.
        if (++pairs > MAX_PARSE_OBJECT_KEYS) return emptyMap()
        val key = jsonUnescapeString(keySb.toString())
        while (i < n && body[i].isWhitespace()) i++
        if (i >= n || body[i] != ':') break
        i++ // past ':'
        while (i < n && body[i].isWhitespace()) i++
        if (i >= n) break
        // ---- value ----
        when (body[i]) {
            '"' -> {
                val sb = StringBuilder()
                i++
                var closed = false
                while (i < n) {
                    val c = body[i]
                    if (c == '\\' && i + 1 < n) { sb.append(c).append(body[i + 1]); i += 2 }
                    else if (c == '"') { i++; closed = true; break }
                    else { sb.append(c); i++ }
                }
                if (!closed) break
                if (!out.containsKey(key)) out[key] = JsonScalar(jsonUnescapeString(sb.toString()), true)
            }
            '{', '[' -> {
                // Skip the nested structure without surfacing its inner keys.
                var depth = 0
                while (i < n) {
                    when (body[i]) {
                        '"' -> {
                            i++
                            while (i < n) {
                                if (body[i] == '\\' && i + 1 < n) i += 2
                                else if (body[i] == '"') { i++; break }
                                else i++
                            }
                        }
                        '{', '[' -> { depth++; i++ }
                        '}', ']' -> { depth--; i++; if (depth == 0) break }
                        else -> i++
                    }
                }
            }
            else -> {
                val start = i
                while (i < n && body[i] != ',' && body[i] != '}' && !body[i].isWhitespace()) i++
                if (!out.containsKey(key)) out[key] = JsonScalar(body.substring(start, i), false)
            }
        }
    }
    return out
}

/**
 * The GUARDED entry point to [parseTopLevelJson] for RELAY-CONTROLLED
 * bodies. Returns null when the body was refused or the scan died on it; the
 * caller must then take the SAME path it takes for a non-2xx (unknown — never
 * "empty", never a crash).
 *
 * Two things it adds over calling the scanner directly:
 *
 *  - **The refusal is distinguishable.** The scanner fails closed to an empty
 *    map, which an honest `{}` also produces; a relay call site needs to tell
 *    those apart, so an over-length body becomes null here.
 *  - **A VM Error becomes a relay error.** `OutOfMemoryError` /
 *    `StackOverflowError` are `Error`s, not `Exception`s, so they escape every
 *    `catch (e: Exception)` on the poll and mint paths and kill the process —
 *    the whole point of this guard. The catch is deliberately NARROW: anything else
 *    (including `CancellationException`, which is an Exception) is rethrown
 *    untouched. The two are matched by simple NAME because neither is a
 *    common-stdlib declaration — `kotlin.OutOfMemoryError` exists on Native but
 *    not on JVM/common, so it cannot be named from commonMain — and both are
 *    platform classes that no shrinker renames.
 */
internal fun parseRelayJsonOrNull(body: String): Map<String, JsonScalar>? {
    if (body.length > MAX_PARSE_OBJECT_CHARS) {
        platformLogWarn(LOG_TAG, "relay body of ${body.length} chars is over the parse cap — refused")
        return null
    }
    return try {
        parseTopLevelJson(body)
    } catch (t: Throwable) {
        val name = t::class.simpleName
        if (t is Error && (name == "OutOfMemoryError" || name == "StackOverflowError")) {
            // No interpolation here on purpose: this branch may be running with the
            // heap already exhausted.
            platformLogWarn(LOG_TAG, "relay body parse hit a VM Error — treated as a relay error")
            null
        } else {
            throw t
        }
    }
}

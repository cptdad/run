package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// Property sweep over DebugLogRedactor: every identifier SHAPE the app emits ×
// every CONTEXT a producer can put it in × every line PREFIX, from one seeded,
// target-independent generator (SeededLcg — never kotlin.random).
//
//  I1  idempotent: redactLine(redactLine(x)) == redactLine(x)
//  I2  the clock + `LEVEL/Tag:` / `KIND ` prefix survives verbatim
//  I3  no full-length secret other than a bare contactId survives ANY context
//  I4  no identifier (full, or a 4/6/8-char prefix) survives a MARKED,
//      LABELLED, CHAINED-LABEL, QUOTED, JSON, URL or value-label context
//  I5  in a BARE context the only 8+-char survivors are the documented hole:
//      pure letters, fewer than 3 lower→upper transitions. (A bare 4- or 6-char
//      run is below rule 3's 8-char floor and is indistinguishable from a word,
//      so it is out of scope here; only its marked/labelled forms are, in I4.)
//  I6  the keep-list (Tor reason keywords, ordinary CamelCase names) survives
//      next to a secret
// ---------------------------------------------------------------------------

private const val SLOT = "@@"
private const val B32 = "abcdefghijklmnopqrstuvwxyz234567"
private const val HEX = "0123456789abcdef"

private fun SeededLcg.from(alphabet: String, n: Int): String {
    val sb = StringBuilder(n)
    for (i in 0 until n) sb.append(alphabet[nextBits() % alphabet.length])
    return sb.toString()
}

private fun lowerToUpperTransitions(s: String): Int {
    var n = 0
    for (i in 1 until s.length) if (s[i - 1] in 'a'..'z' && s[i] in 'A'..'Z') n++
    return n
}

private class Kind(val name: String, val gen: (SeededLcg) -> String)

class DebugModeRedactorPropertyTest {

    private val fullKinds = listOf(
        Kind("inbox") { it.b64Url(32) },
        Kind("group") { it.b64Url(32) },
        Kind("cap") { it.b64Url(43) },
        Kind("member") { it.from(HEX, 16) },
        Kind("onion") { it.from(B32, 56) + ".onion" },
        Kind("url") { "https://" + it.from(B32, 56) + ".onion/inbox/" + it.b64Url(32) },
        Kind("ipv4") { "${1 + it.nextBits() % 223}.${it.nextBits() % 256}.${it.nextBits() % 256}.${1 + it.nextBits() % 254}" },
        Kind("ipv6") { "2001:db8:${it.from(HEX, 4)}::${it.from(HEX, 4)}" },
    )
    private val contactKind = Kind("contactId") { it.b64Url(24) }
    private val prefixKinds = listOf(4, 6, 8).map { n -> Kind("prefix$n") { it.b64Url(32).substring(0, n) } }

    private val bareLabels = listOf(
        "inbox", "inboxid", "contact", "contactid", "group", "groupid", "cap", "token", "peer", "target",
    )

    private val bare = listOf("peek $SLOT done", SLOT, "($SLOT)", "x,$SLOT,y", "$SLOT:", "$SLOT.")
    private val marked = listOf("$SLOT...", "$SLOT…")
    private val labelled = bareLabels.flatMap { listOf("$it $SLOT", "$it=$SLOT", "$it: $SLOT") } +
        listOf("readCap=$SLOT", "peer_id=$SLOT", "targetInbox=$SLOT", "introId=$SLOT")
    private val chained = listOf("contact inbox $SLOT", "group token $SLOT")
    private val quoted = listOf("\"$SLOT\"", "'$SLOT'", "“$SLOT”")
    private val json = listOf("{\"ib\":\"$SLOT\"}")
    private val urlPath = listOf("GET https://h/inbox/$SLOT")
    private val valueLabel = listOf("alias=$SLOT")
    private val contextual = marked + labelled + chained + quoted + json + urlPath + valueLabel

    private val prefixes = listOf("12:34:56.789 D/Tag: ", "12:34:56.789 RELAY ", "")

    // Everything the output can contain BESIDES the token: the template, the
    // prefix and every placeholder/bucket. A draw that already occurs in that
    // text is skipped, so a survivor check can never be a coincidence.
    private val background = listOf(
        "[url]", "[onion]", "[ip]", "[str]", "[id]", "[hex]", "[num]", "[path]", "[redacted]",
        "1-5", "6-20", "20+",
    ).joinToString(" ")

    private fun draw(rng: SeededLcg, kind: Kind, template: String, prefix: String): String {
        while (true) {
            val t = kind.gen(rng)
            if (!(prefix + template + background).contains(t)) return t
        }
    }

    private fun windows8(s: String): List<String> = if (s.length < 8) listOf(s) else (0..s.length - 8).map { s.substring(it, it + 8) }

    private fun checkCommon(line: String, prefix: String, out: String) {
        assertEquals(out, DebugLogRedactor.redactLine(out), "I1 idempotence\n  in: $line\n out: $out")
        assertTrue(out.startsWith(prefix), "I2 prefix\n  in: $line\n out: $out")
    }

    @Test
    fun i3_noFullLengthSecretSurvivesAnyContext() {
        val rng = SeededLcg(0x13AL)
        for (kind in fullKinds) for (template in bare + contextual) for (prefix in prefixes) repeat(40) {
            val token = draw(rng, kind, template, prefix)
            val line = prefix + template.replace(SLOT, token)
            val out = DebugLogRedactor.redactLine(line)
            checkCommon(line, prefix, out)
            assertFalse(out.contains(token), "I3 LEAK (${kind.name})\n  in: $line\n out: $out")
            if (kind.name == "inbox" || kind.name == "group" || kind.name == "cap" || kind.name == "member") {
                for (w in windows8(token)) {
                    if ((prefix + template + background).contains(w)) continue
                    assertFalse(out.contains(w), "I3 WINDOW LEAK (${kind.name}) \"$w\"\n  in: $line\n out: $out")
                }
            }
        }
    }

    @Test
    fun i4_noIdentifierSurvivesAMarkedLabelledQuotedOrUrlContext() {
        val rng = SeededLcg(0x14BL)
        for (kind in fullKinds + contactKind + prefixKinds) for (template in contextual) for (prefix in prefixes) repeat(40) {
            val token = draw(rng, kind, template, prefix)
            val line = prefix + template.replace(SLOT, token)
            val out = DebugLogRedactor.redactLine(line)
            checkCommon(line, prefix, out)
            assertFalse(out.contains(token), "I4 LEAK (${kind.name}, \"$template\")\n  in: $line\n out: $out")
        }
    }

    @Test
    fun i4_chainedLabels_takeTheIdAfterTheLastLabel() {
        assertEquals("contact inbox [id]", DebugLogRedactor.redactMessage("contact inbox abcdefgh"))
        assertEquals("group token [id]", DebugLogRedactor.redactMessage("group token abcdefgh"))
        // A label with nothing after it is just a word.
        assertEquals("contact inbox", DebugLogRedactor.redactMessage("contact inbox"))
        // The bare-label narration case is unchanged.
        assertEquals("contact [id]:", DebugLogRedactor.redactMessage("contact added:"))
    }

    @Test
    fun i5_bareSurvivorsAreOnlyTheDocumentedHole() {
        val rng = SeededLcg(0x15CL)
        var contactSurvivors = 0
        var contactDraws = 0
        for (kind in listOf(prefixKinds.last(), contactKind)) for (template in bare) for (prefix in prefixes) repeat(400) {
            val token = draw(rng, kind, template, prefix)
            val line = prefix + template.replace(SLOT, token)
            val out = DebugLogRedactor.redactLine(line)
            checkCommon(line, prefix, out)
            if (kind === contactKind) contactDraws++
            if (out.contains(token)) {
                assertTrue(
                    token.all { it in 'A'..'Z' || it in 'a'..'z' } && lowerToUpperTransitions(token) < 3 && token.length < 32,
                    "I5: only a pure-letter, low-transition run may survive bare\n  in: $line\n out: $out",
                )
                if (kind === contactKind) contactSurvivors++
            }
        }
        // ~2.5e-5 per bare contactId: at most 2 per 10 000 draws.
        assertTrue(contactSurvivors * 10_000 <= 2 * contactDraws, "bare contactId survivors: $contactSurvivors of $contactDraws")

        // The hole is real (the generator draws realistic base64url): ~19 % of
        // 8-char prefixes are all letters — the same sanity window DebugModeTest uses.
        val sanity = SeededLcg(0x5EEDL)
        var allLetters = 0
        repeat(20_000) { if (sanity.b64Url(32).substring(0, 8).all { it in 'A'..'Z' || it in 'a'..'z' }) allLetters++ }
        assertTrue(allLetters in 3_000..4_600, "all-letter prefixes: $allLetters of 20000")
    }

    @Test
    fun i6_theKeepListSurvivesNextToASecret() {
        val rng = SeededLcg(0x16DL)
        for (word in listOf("QUERY_NO_HSDIR", "MessageManager", "Bootstrapped", "PeekTarget")) {
            for (kind in listOf(fullKinds[0], fullKinds[2], fullKinds[3])) repeat(50) {
                val secret = kind.gen(rng)
                for (line in listOf("12:34:56.789 D/Tag: $word $secret", "12:34:56.789 D/Tag: $secret $word")) {
                    val out = DebugLogRedactor.redactLine(line)
                    assertTrue(out.contains(word), "I6: \"$word\" must survive\n  in: $line\n out: $out")
                    assertFalse(out.contains(secret), "I6: the secret still goes\n  in: $line\n out: $out")
                }
            }
        }
    }
}

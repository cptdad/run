package com.vg.run

import java.io.File
import kotlin.test.Test
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// The log-hygiene rule, AS A SOURCE GUARD: **no identifier and no raw transport
// text in a log line — the exception CLASS NAME or the HTTP code only.**
//
// Scanned: every Kotlin file of commonMain, androidMain and iosMain (the shared
// module's main sources). androidApp and the Swift sources have their own
// scanners (or none yet — see the review changelog).
//
// Both platforms' `platformLog*` feed `LogBuffer`, which Debug mode uploads in
// release builds, and `ConnectionLog` is a release-visible panel. The DebugMode
// redactor is a deny-list over free text and says itself that it cannot be
// exhaustive (a bare `take(8)` prefix with no marker and no label survives it
// ~14 % of the time), so the guarantee has to live at the PRODUCER. This test is
// that guarantee for commonMain. It fails on any `platformLog` /
// `platformLogWarn` / `platformLogError` / `ConnectionLog.append` call whose
// argument list contains (calls: `platformLog*`, `ConnectionLog.append`, and a
// direct `LogBuffer.append`):
//
//  * `.take(<digit>` / `.takeLast(` / `.substring(` / `.prefix(` — an identifier
//    prefix or slice (`${inboxId.take(8)}`);
//  * `.message` — an exception message, which carries URLs, onion hosts and
//    inbox-id prefixes from deeper layers (`RelayMoveTransport` used to throw
//    `"…for inbox ${inboxId.take(8)}"`, OkHttp embeds full request URLs);
//  * `.localizedMessage` / `.localizedDescription` / `.stackTraceToString(` /
//    `.cause` / `.toString()` — the same text by another name;
//  * a bare `$e` / `${e}` (and `t` / `ex` / `err` / `exception` / `cause` /
//    `throwable` / `it`) — `toString()` of a Throwable is its class
//    name PLUS its message;
//  * a raw identifier-named template (`$inboxId`, `${contactId}`, `$readCap`, …)
//    — no truncation makes it any better;
//  * string concatenation (`"…" + x`): the guard cannot see what a concatenated
//    value holds, so a log line is one template.
//
// Use `${e::class.simpleName}`, the HTTP code, or nothing.
//
// It lives in androidUnitTest because that is the only JVM test source set with a
// filesystem (same reason as GroupTextNeverOnContactSourceGuardTest).
// ---------------------------------------------------------------------------
class LogLineNoIdentifierSourceGuardTest {

    @Test
    fun noSharedMainLogCallCarriesAnIdentifierOrAnExceptionMessage() {
        val violations = mutableListOf<String>()
        for ((root, floor) in ROOTS) {
            val dir = File(repoRoot(), root)
            val files = dir.listFiles { f -> f.isFile && f.name.endsWith(".kt") }.orEmpty().sortedBy { it.name }
            assertTrue(files.size > floor, "sources not found under $dir — a guard that scans nothing passes forever")
            for (f in files) {
                if ("$root/${f.name}" in KNOWN_EXCEPTIONS) continue
                for ((line, span) in violationsIn(f.readText())) {
                    violations += "$root/${f.name}:$line  ${span.take(140)}"
                }
            }
        }
        assertTrue(
            violations.isEmpty(),
            "Log lines must carry no identifier and no exception message — use " +
                "\${e::class.simpleName} or the HTTP code:\n" + violations.joinToString("\n"),
        )
    }

    /** The detector must be able to fire — and must not fire on the sanctioned shapes. (Fabricated source.) */
    @Test
    fun theDetectorActuallyDetects() {
        val bad = listOf(
            "platformLogWarn(TAG, \"rotation failed for \${id.take(8)}: x\")",
            "platformLogWarn(TAG, \"x failed: \${e.message}\")",
            "platformLog(\n    TAG,\n    \"multi-line \${t.message}\",\n)",
            "platformLogError(TAG, \"boom: \$e\")",
            "ConnectionLog.append(Kind.INFO, \"inbox \${inboxId.take(6)}\")",
            "platformLog(TAG, \"x \${id.takeLast(4)}\")",
            "platformLog(TAG, \"x \${id.substring(0, 8)}\")",
            "platformLog(TAG, \"x \${id.prefix(8)}\")",
            "platformLogWarn(TAG, \"x \${e.toString()}\")",
            "platformLogWarn(TAG, \"x \${e.localizedMessage}\")",
            "platformLogWarn(TAG, \"x \${e.cause}\")",
            "platformLogWarn(TAG, \"x \${e.stackTraceToString()}\")",
            "runCatching { }.onFailure { platformLogWarn(TAG, \"x \$it\") }",
            "platformLogWarn(TAG, \"x \$exception\")",
            "platformLog(TAG, \"inbox \$inboxId\")",
            "platformLog(TAG, \"contact \${contactId}\")",
            "platformLog(TAG, \"cap \$readCap\")",
            "platformLog(TAG, \"cap \$cap ok\")",
            "LogBuffer.append(\"W\", TAG, \"x \${e.message}\")",
            "platformLog(TAG, \"x \" + inboxId)",
            "platformLog(TAG, line + \" more\")",
        )
        for (src in bad) assertTrue(violationsIn(src).isNotEmpty(), "detector missed: $src")
        val good = listOf(
            "platformLogWarn(TAG, \"x failed: \${e::class.simpleName}\")",
            "platformLog(TAG, \"code=\${result.code} n=\${items.size}\")",
            "platformLogError(TAG, \"persist failed\", e)",
            "// platformLogWarn(TAG, \"\${e.message}\") — a comment is not a log line",
            "platformLog(TAG, \"name \${name.take(MAX_GROUP_NAME_CHARS)} is fine\")",
            "platformLogWarn(TAG, \"x failed: \${it::class.simpleName}\")",
            "platformLog(TAG, \"inboxes=\${inboxIds.size} caps=\${capCount}\")",
            "LogBuffer.append(\"D\", tag, message)",
            "platformLog(TAG, httpLogLine(method, path, result.code))",
            "platformLogWarn(TAG, \"export failed (\$error, retryable=\$retryable)\")",
            "platformLogWarn(\n    TAG,\n    \"a long fixed phrase \" +\n        \"split for line length\",\n)",
        )
        for (src in good) assertTrue(violationsIn(src).isEmpty(), "detector false-positived on: $src")
    }

    // -----------------------------------------------------------------------

    /** (line, call text) for every log call in [source] that trips a [BAD] pattern. */
    private fun violationsIn(source: String): List<Pair<Int, String>> {
        val src = stripComments(source)
        val out = mutableListOf<Pair<Int, String>>()
        for (m in CALL.findAll(src)) {
            // Paren-balanced argument span. Crude on purpose (no Kotlin parser): an
            // unbalanced paren inside a string can only LENGTHEN the span, i.e. err
            // toward scanning more, never toward scanning nothing.
            var i = m.range.last + 1
            var depth = 1
            while (i < src.length && depth > 0) {
                when (src[i]) {
                    '(' -> depth++
                    ')' -> depth--
                }
                i++
            }
            val span = src.substring(m.range.first, i)
            if (BAD.any { it.containsMatchIn(span) }) {
                out += (src.substring(0, m.range.first).count { it == '\n' } + 1) to span.replace('\n', ' ')
            }
        }
        return out
    }

    /** Comments blanked (newlines kept, so line numbers stay right). `//` after a
     *  `:` or a `"` is left alone so a URL inside a string is not cut short. */
    private fun stripComments(src: String): String =
        src.replace(BLOCK_COMMENT) { m -> m.value.replace(Regex("[^\n]"), " ") }
            .replace(LINE_COMMENT, "$1")

    /** Walks up to the directory holding `settings.gradle.kts`; fails loudly. */
    private fun repoRoot(): File {
        var d: File? = File("").absoluteFile
        while (d != null) {
            if (File(d, "settings.gradle.kts").isFile) return d
            d = d.parentFile
        }
        throw AssertionError("repo root not found above ${File("").absoluteFile} — this guard must never silently scan nothing")
    }

    private companion object {
        // The scanned roots and each one's "found something" floor.
        val ROOTS = listOf(
            "shared/src/commonMain/kotlin/com/vg/run" to 20,
            "shared/src/androidMain/kotlin/com/vg/run" to 10,
            "shared/src/iosMain/kotlin/com/vg/run" to 10,
        )

        // Files (root-relative paths) with known violations. EMPTY: never add one —
        // fix the log line instead.
        val KNOWN_EXCEPTIONS: Set<String> = emptySet()

        val CALL = Regex("""\b(platformLog|platformLogWarn|platformLogError|ConnectionLog\.append|LogBuffer\.append)\(""")
        val BAD = listOf(
            Regex("""\.take\(\d"""),
            Regex("""\.(takeLast|substring|prefix)\("""),
            Regex("""\.message\b"""),
            Regex("""\.(localizedMessage|localizedDescription|cause)\b"""),
            Regex("""\.(stackTraceToString|toString)\("""),
            // Not `error`: in this codebase that name is a MoveError / enum value as often as a Throwable.
            Regex("""\$\{?(e|t|ex|err|exception|cause|throwable|it)\}?(?![\w:.])"""),
            Regex("""\$\{?[A-Za-z_]*(InboxId|inboxId|ContactId|contactId|BundleId|bundleId|Cap|cap)\}?(?![\w(.])"""),
            // Concatenation with a non-literal on either side (two literals joined
            // for line length are fine: `"a " +\n "b"`).
            Regex("\"\\s*\\+\\s*[^\"\\s]|[^\"\\s]\\s*\\+\\s*\""),
        )
        val BLOCK_COMMENT = Regex("""/\*.*?\*/""", RegexOption.DOT_MATCHES_ALL)
        val LINE_COMMENT = Regex("""(?m)(^|[^:"])//[^\n]*""")
    }
}

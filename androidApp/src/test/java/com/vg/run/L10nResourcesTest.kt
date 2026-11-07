package com.vg.run

import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.w3c.dom.Document
import org.w3c.dom.Element
import org.w3c.dom.Node
import java.io.File
import javax.xml.parsers.DocumentBuilderFactory

/**
 * L10nResourcesTest — JVM validator for the single-source-of-truth l10n tree
 * (`androidApp/src/main/res/values{,-sv,-de,-fr,-es,-nb,-da,-fi}/strings_*.xml`)
 * and the files `scripts/l10n/gen-l10n.mjs` derives from it
 * (`iosApp/iosApp/Localizable.xcstrings`, `iosApp/iosApp/InfoPlist.xcstrings`,
 * `androidApp/src/main/java/com/vg/run/l10n/L10nKeys.kt`).
 *
 * Deliberately javax.xml + hand-rolled JSON (no Android deps, no Robolectric —
 * this project has none, see PrefsApplySourceGuardTest) so it runs as a plain
 * JVM unit test. Independent of the generator's own hand-written parser: this
 * test uses the JDK's own DOM parser, so a bug shared between the two would
 * have to be a bug in genuinely different code, not the same code path twice.
 *
 * Every check below collects ALL violations before asserting once, so a
 * single run reports every problem instead of stopping at the first — and
 * every message names the offending key + locale (+ file, where the model
 * tracks one) so a failure is actionable without re-deriving context.
 */
class L10nResourcesTest {

    // -------------------------------------------------------------------
    // Locale-tree model
    // -------------------------------------------------------------------

    // The supported locale set is READ from res/xml/locales_config.xml rather than
    // hard-coded here: gen-l10n.mjs --check (pre-push) keeps that file in lockstep
    // with its own LOCALES list and build.gradle.kts localeFilters, so this test can't
    // silently fall behind when a locale is added (it did for ar/fa, 2026-09-01).
    private val ALL_LANGS: List<String> by lazy {
        val cfg = File(resDir(), "xml/locales_config.xml")
        assertTrue("${cfg.path} is missing", cfg.isFile)
        val names = Regex("android:name=\"([A-Za-z-]+)\"").findAll(cfg.readText()).map { it.groupValues[1] }.toList()
        assertTrue("locales_config.xml must list \"en\" first: $names", names.firstOrNull() == "en")
        names
    }
    private val ALL_LOCALES: List<String> by lazy { ALL_LANGS.filter { it != "en" } }

    private val STRINGS_FILE_REGEX = Regex("^strings_.*\\.xml$")
    private val EXACT_NUMBER_QUANTITIES = setOf("zero", "one", "two")
    private val KEY_REGEX = Regex("^[a-z][a-z0-9_]*$")

    private data class StringEntry(val value: String, val translatable: Boolean, val file: String)
    private data class PluralEntry(val items: Map<String, String>, val file: String)
    private data class LocaleData(
        val strings: Map<String, StringEntry>,
        val plurals: Map<String, PluralEntry>,
        val duplicateStrings: List<String>,
        val duplicatePlurals: List<String>,
        val fileSet: Set<String>,
    )

    private data class RawEntry(
        val key: String,
        val quantity: String?, // null for <string>, "one"/"other"/etc for a plural <item>
        val rawText: String, // TEXT_NODE content only (entities resolved, escapes NOT decoded)
        val value: String, // fully resolved runtime value (escapes decoded, CDATA raw)
        val translatable: Boolean,
        val fileName: String,
    )

    private fun resDir(): File = File(repoRoot(), "androidApp/src/main/res")

    private fun dirNameFor(locale: String): String = if (locale == "en") "values" else "values-$locale"

    private fun parseXmlFile(file: File): Document {
        val factory = DocumentBuilderFactory.newInstance()
        try {
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
        } catch (_: Exception) {
            // best-effort hardening only; not all parser implementations support the feature name
        }
        val builder = factory.newDocumentBuilder()
        return builder.parse(file)
    }

    private fun decodeAndroidEscapes(s: String): String {
        val out = StringBuilder()
        var i = 0
        while (i < s.length) {
            val c = s[i]
            if (c == '\\' && i + 1 < s.length) {
                when (s[i + 1]) {
                    'n' -> { out.append('\n'); i += 2 }
                    't' -> { out.append('\t'); i += 2 }
                    '\'' -> { out.append('\''); i += 2 }
                    '"' -> { out.append('"'); i += 2 }
                    '\\' -> { out.append('\\'); i += 2 }
                    else -> { out.append(c); i += 1 } // unrecognized escape: leave as-is (not this test's job to reject)
                }
            } else {
                out.append(c)
                i += 1
            }
        }
        return out.toString()
    }

    private fun extractValue(el: Element): String {
        val sb = StringBuilder()
        for (i in 0 until el.childNodes.length) {
            val n = el.childNodes.item(i)
            when (n.nodeType) {
                Node.TEXT_NODE -> sb.append(decodeAndroidEscapes(n.nodeValue ?: ""))
                Node.CDATA_SECTION_NODE -> sb.append(n.nodeValue ?: "")
                else -> { /* nested element — not this test's concern (the generator rejects it) */ }
            }
        }
        return sb.toString()
    }

    private fun extractRawTextOnly(el: Element): String {
        val sb = StringBuilder()
        for (i in 0 until el.childNodes.length) {
            val n = el.childNodes.item(i)
            if (n.nodeType == Node.TEXT_NODE) sb.append(n.nodeValue ?: "")
        }
        return sb.toString()
    }

    private data class CollectResult(
        val entries: List<RawEntry>,
        val duplicateStrings: List<String>,
        val duplicatePlurals: List<String>,
        val fileSet: Set<String>,
    )

    private fun collectEntries(locale: String): CollectResult? {
        val dir = File(resDir(), dirNameFor(locale))
        if (!dir.isDirectory) return null
        val files = (dir.listFiles { f -> f.isFile && STRINGS_FILE_REGEX.matches(f.name) } ?: emptyArray())
            .map { it.name }
            .sorted()
        val out = mutableListOf<RawEntry>()
        val seenStrings = mutableSetOf<String>()
        val seenPlurals = mutableSetOf<String>()
        val dupStrings = mutableListOf<String>()
        val dupPlurals = mutableListOf<String>()
        for (fname in files) {
            val file = File(dir, fname)
            val doc = parseXmlFile(file)
            val root = doc.documentElement
            for (i in 0 until root.childNodes.length) {
                val node = root.childNodes.item(i)
                if (node !is Element) continue
                when (node.tagName) {
                    "string" -> {
                        val name = node.getAttribute("name")
                        if (!seenStrings.add(name)) {
                            dupStrings += "\"$name\" duplicated in $fname (${dirNameFor(locale)})"
                        } else {
                            val translatable = node.getAttribute("translatable") != "false"
                            out += RawEntry(name, null, extractRawTextOnly(node), extractValue(node), translatable, fname)
                        }
                    }
                    "plurals" -> {
                        val name = node.getAttribute("name")
                        if (!seenPlurals.add(name)) {
                            dupPlurals += "\"$name\" duplicated in $fname (${dirNameFor(locale)})"
                        } else {
                            for (j in 0 until node.childNodes.length) {
                                val itemNode = node.childNodes.item(j)
                                if (itemNode !is Element || itemNode.tagName != "item") continue
                                val quantity = itemNode.getAttribute("quantity")
                                out += RawEntry(
                                    name,
                                    quantity,
                                    extractRawTextOnly(itemNode),
                                    extractValue(itemNode),
                                    true,
                                    fname,
                                )
                            }
                        }
                    }
                }
            }
        }
        return CollectResult(out, dupStrings, dupPlurals, files.toSet())
    }

    private fun loadLocale(locale: String): LocaleData? {
        val result = collectEntries(locale) ?: return null
        val strings = LinkedHashMap<String, StringEntry>()
        val pluralItems = LinkedHashMap<String, LinkedHashMap<String, String>>()
        val pluralFiles = LinkedHashMap<String, String>()
        for (e in result.entries) {
            if (e.quantity == null) {
                strings[e.key] = StringEntry(e.value, e.translatable, e.fileName)
            } else {
                pluralItems.getOrPut(e.key) { LinkedHashMap() }[e.quantity] = e.value
                pluralFiles.putIfAbsent(e.key, e.fileName)
            }
        }
        val plurals = pluralItems.mapValues { (key, items) -> PluralEntry(items, pluralFiles.getValue(key)) }
        return LocaleData(strings, plurals, result.duplicateStrings, result.duplicatePlurals, result.fileSet)
    }

    private fun requireEnLocale(): LocaleData =
        loadLocale("en") ?: throw AssertionError("androidApp/src/main/res/values/ is missing or has no strings_*.xml files")

    // -------------------------------------------------------------------
    // Placeholder scanning (independent re-implementation of the same rules
    // gen-l10n.mjs enforces, so a bug would have to be duplicated in both)
    // -------------------------------------------------------------------

    private data class Placeholder(val index: Int, val type: Char)

    private fun scanPlaceholders(value: String): Result<List<Placeholder>> {
        val found = mutableListOf<Placeholder>()
        var i = 0
        while (i < value.length) {
            if (value[i] == '%') {
                if (i + 1 < value.length && value[i + 1] == '%') {
                    i += 2
                    continue
                }
                val rest = value.substring(i)
                val m = Regex("^%(\\d+)\\$([sd])").find(rest)
                if (m != null) {
                    found += Placeholder(m.groupValues[1].toInt(), m.groupValues[2][0])
                    i += m.value.length
                    continue
                }
                val bare = Regex("^%([sd])").find(rest)
                if (bare != null) {
                    return Result.failure(
                        IllegalStateException("bare \"%${bare.groupValues[1]}\" placeholder — must be positional"),
                    )
                }
                return Result.failure(
                    IllegalStateException("malformed placeholder near \"${rest.take(8)}\""),
                )
            }
            i++
        }
        return Result.success(found)
    }

    // -------------------------------------------------------------------
    // Minimal JSON reader (zero deps — org.json isn't safely usable in a
    // pure JVM unit test without Robolectric, and this project has none)
    // -------------------------------------------------------------------

    private class JsonParser(private val s: String) {
        private var i = 0

        fun parse(): Any? {
            skipWs()
            val v = parseValue()
            skipWs()
            return v
        }

        private fun skipWs() {
            while (i < s.length && s[i].isWhitespace()) i++
        }

        private fun parseValue(): Any? {
            skipWs()
            return when (s[i]) {
                '{' -> parseObject()
                '[' -> parseArray()
                '"' -> parseString()
                't' -> { expect("true"); true }
                'f' -> { expect("false"); false }
                'n' -> { expect("null"); null }
                else -> parseNumber()
            }
        }

        private fun expect(lit: String) {
            require(s.startsWith(lit, i)) { "expected \"$lit\" at offset $i" }
            i += lit.length
        }

        private fun parseObject(): LinkedHashMap<String, Any?> {
            val map = LinkedHashMap<String, Any?>()
            i++ // {
            skipWs()
            if (i < s.length && s[i] == '}') { i++; return map }
            while (true) {
                skipWs()
                val key = parseString()
                skipWs()
                require(s[i] == ':') { "expected ':' at offset $i" }
                i++
                val value = parseValue()
                map[key] = value
                skipWs()
                when (s[i]) {
                    ',' -> { i++; continue }
                    '}' -> { i++; break }
                    else -> throw IllegalStateException("malformed JSON object at offset $i")
                }
            }
            return map
        }

        private fun parseArray(): MutableList<Any?> {
            val list = mutableListOf<Any?>()
            i++ // [
            skipWs()
            if (i < s.length && s[i] == ']') { i++; return list }
            while (true) {
                list += parseValue()
                skipWs()
                when (s[i]) {
                    ',' -> { i++; continue }
                    ']' -> { i++; break }
                    else -> throw IllegalStateException("malformed JSON array at offset $i")
                }
            }
            return list
        }

        private fun parseString(): String {
            require(s[i] == '"') { "expected string at offset $i" }
            i++
            val sb = StringBuilder()
            while (s[i] != '"') {
                if (s[i] == '\\') {
                    i++
                    when (s[i]) {
                        '"' -> sb.append('"')
                        '\\' -> sb.append('\\')
                        '/' -> sb.append('/')
                        'n' -> sb.append('\n')
                        't' -> sb.append('\t')
                        'r' -> sb.append('\r')
                        'b' -> sb.append('\b')
                        'f' -> sb.append('\u000C')
                        'u' -> {
                            val hex = s.substring(i + 1, i + 5)
                            sb.append(hex.toInt(16).toChar())
                            i += 4
                        }
                        else -> sb.append(s[i])
                    }
                    i++
                } else {
                    sb.append(s[i])
                    i++
                }
            }
            i++ // closing quote
            return sb.toString()
        }

        private fun parseNumber(): Double {
            val start = i
            while (i < s.length && (s[i].isDigit() || s[i] in "-+.eE")) i++
            return s.substring(start, i).toDouble()
        }
    }

    private fun parseJson(text: String): Any? = JsonParser(text).parse()

    @Suppress("UNCHECKED_CAST")
    private fun asMap(v: Any?): Map<String, Any?>? = v as? Map<String, Any?>

    // -------------------------------------------------------------------
    // 1. Locale dirs
    // -------------------------------------------------------------------

    @Test
    fun localeDirectoriesAreLimitedToTheSupportedSetAndShareTheSameFileSet() {
        val allowedDirNames = ALL_LANGS.map { dirNameFor(it) }.toSet()
        val resDirs = resDir().listFiles { f -> f.isDirectory && f.name.startsWith("values") } ?: emptyArray()
        val unexpected = resDirs
            .filter { d ->
                d.name !in allowedDirNames &&
                    (d.listFiles { f -> f.isFile && STRINGS_FILE_REGEX.matches(f.name) }?.isNotEmpty() == true)
            }
            .map { it.name }
        assertTrue(
            "Unexpected values-* director{y,ies} carrying strings_*.xml resources outside the supported " +
                "locale set from res/xml/locales_config.xml (${ALL_LOCALES.joinToString("/")}): $unexpected",
            unexpected.isEmpty(),
        )

        val enDir = File(resDir(), "values")
        assertTrue("androidApp/src/main/res/values/ is missing", enDir.isDirectory)
        val enFiles = (enDir.listFiles { f -> f.isFile && STRINGS_FILE_REGEX.matches(f.name) } ?: emptyArray())
            .map { it.name }
            .toSortedSet()

        val violations = mutableListOf<String>()
        for (locale in ALL_LOCALES) {
            val dir = File(resDir(), dirNameFor(locale))
            if (!dir.isDirectory) continue
            val files = (dir.listFiles { f -> f.isFile && STRINGS_FILE_REGEX.matches(f.name) } ?: emptyArray())
                .map { it.name }
                .toSortedSet()
            if (files != enFiles) {
                violations += "${dirNameFor(locale)}/ strings_*.xml file set differs from values/ — " +
                    "missing: ${enFiles - files}; extra: ${files - enFiles}"
            }
        }
        assertTrue(violations.joinToString("\n"), violations.isEmpty())
    }

    // -------------------------------------------------------------------
    // 2. Key sets identical + no duplicate keys + app_name lock
    // -------------------------------------------------------------------

    @Test
    fun keySetsMatchAcrossLocalesWithNoDuplicatesAndAppNameLocked() {
        val violations = mutableListOf<String>()
        val en = requireEnLocale()

        for (locale in ALL_LANGS) {
            val data = loadLocale(locale) ?: continue
            violations += data.duplicateStrings.map { "${dirNameFor(locale)}: duplicate string $it" }
            violations += data.duplicatePlurals.map { "${dirNameFor(locale)}: duplicate plurals $it" }
        }

        for (locale in ALL_LOCALES) {
            val data = loadLocale(locale) ?: continue
            val missingStrings = en.strings.keys - data.strings.keys
            val extraStrings = data.strings.keys - en.strings.keys
            if (missingStrings.isNotEmpty() || extraStrings.isNotEmpty()) {
                violations += "${dirNameFor(locale)}: string key set differs from values/ — " +
                    "missing: $missingStrings; extra: $extraStrings"
            }
            val missingPlurals = en.plurals.keys - data.plurals.keys
            val extraPlurals = data.plurals.keys - en.plurals.keys
            if (missingPlurals.isNotEmpty() || extraPlurals.isNotEmpty()) {
                violations += "${dirNameFor(locale)}: plurals key set differs from values/ — " +
                    "missing: $missingPlurals; extra: $extraPlurals"
            }
        }

        // app_name lives in strings.xml (NOT strings_*.xml) — checked wherever that file exists.
        for (locale in ALL_LANGS) {
            val stringsXml = File(File(resDir(), dirNameFor(locale)), "strings.xml")
            if (!stringsXml.isFile) continue
            val doc = parseXmlFile(stringsXml)
            val root = doc.documentElement
            for (i in 0 until root.childNodes.length) {
                val node = root.childNodes.item(i)
                if (node is Element && node.tagName == "string" && node.getAttribute("name") == "app_name") {
                    val value = extractValue(node)
                    if (value != "Rún") {
                        violations += "${dirNameFor(locale)}/strings.xml: app_name = \"$value\" (expected \"Rún\")"
                    }
                }
            }
        }

        assertTrue(violations.joinToString("\n"), violations.isEmpty())
    }

    // -------------------------------------------------------------------
    // 3. Key regex
    // -------------------------------------------------------------------

    @Test
    fun everyKeyMatchesTheNamingConvention() {
        val violations = mutableListOf<String>()
        for (locale in ALL_LANGS) {
            val data = loadLocale(locale) ?: continue
            for (key in data.strings.keys) {
                if (!KEY_REGEX.matches(key)) {
                    violations += "${dirNameFor(locale)}/${data.strings.getValue(key).file}: string key \"$key\" " +
                        "does not match ^[a-z][a-z0-9_]*$"
                }
            }
            for (key in data.plurals.keys) {
                if (!KEY_REGEX.matches(key)) {
                    violations += "${dirNameFor(locale)}/${data.plurals.getValue(key).file}: plurals key \"$key\" " +
                        "does not match ^[a-z][a-z0-9_]*$"
                }
            }
        }
        assertTrue(violations.joinToString("\n"), violations.isEmpty())
    }

    // -------------------------------------------------------------------
    // 4. Placeholders
    // -------------------------------------------------------------------

    private fun checkPlaceholderSyntax(
        value: String,
        context: String,
        dirName: String,
        file: String,
        violations: MutableList<String>,
    ) {
        val result = scanPlaceholders(value)
        if (result.isFailure) {
            violations += "$dirName/$file: $context — ${result.exceptionOrNull()?.message}"
            return
        }
        val indices = result.getOrThrow().map { it.index }.toSortedSet()
        for (idx in indices) {
            if (idx > 1 && (idx - 1) !in indices) {
                violations += "$dirName/$file: $context — has %$idx\$.. without a preceding " +
                    "%${idx - 1}\$.. (placeholders must be contiguous starting at %1\$..)"
            }
        }
    }

    @Test
    fun placeholdersArePositionalAndConsistentAcrossLocales() {
        val violations = mutableListOf<String>()
        val en = requireEnLocale()

        for (locale in ALL_LANGS) {
            val data = loadLocale(locale) ?: continue
            for ((key, entry) in data.strings) {
                checkPlaceholderSyntax(entry.value, "string \"$key\"", dirNameFor(locale), entry.file, violations)
            }
            for ((key, plural) in data.plurals) {
                for ((quantity, value) in plural.items) {
                    checkPlaceholderSyntax(
                        value,
                        "plurals \"$key\" item \"$quantity\"",
                        dirNameFor(locale),
                        plural.file,
                        violations,
                    )
                }
            }
        }

        for ((key, enEntry) in en.strings) {
            val enPlaceholders = scanPlaceholders(enEntry.value).getOrNull() ?: continue
            val enMultiset = enPlaceholders.groupingBy { it }.eachCount()
            for (locale in ALL_LOCALES) {
                val data = loadLocale(locale) ?: continue
                val entry = data.strings[key] ?: continue // key-set mismatch already reported by check #2
                val placeholders = scanPlaceholders(entry.value).getOrNull() ?: continue
                val multiset = placeholders.groupingBy { it }.eachCount()
                if (multiset != enMultiset) {
                    violations += "string \"$key\": placeholder multiset differs between values/ ($enMultiset) " +
                        "and ${dirNameFor(locale)}/ ($multiset)"
                }
            }
        }

        assertTrue(violations.joinToString("\n"), violations.isEmpty())
    }

    // -------------------------------------------------------------------
    // 5. Plurals: one+other required; every item carries other's placeholders
    // -------------------------------------------------------------------

    @Test
    fun pluralsHaveRequiredQuantitiesAndConsistentPlaceholders() {
        val violations = mutableListOf<String>()
        for (locale in ALL_LANGS) {
            val data = loadLocale(locale) ?: continue
            for ((key, plural) in data.plurals) {
                val items = plural.items
                if ("one" !in items) {
                    violations += "${dirNameFor(locale)}/${plural.file}: plurals \"$key\" is missing the \"one\" quantity"
                }
                if ("other" !in items) {
                    violations += "${dirNameFor(locale)}/${plural.file}: plurals \"$key\" is missing the \"other\" quantity"
                    continue
                }
                val otherPlaceholders = scanPlaceholders(items.getValue("other")).getOrNull()?.toSet() ?: continue
                for ((quantity, value) in items) {
                    val itemPlaceholders = scanPlaceholders(value).getOrNull()?.toSet() ?: continue
                    val extra = itemPlaceholders - otherPlaceholders
                    if (extra.isNotEmpty()) {
                        violations += "${dirNameFor(locale)}/${plural.file}: plurals \"$key\" item \"$quantity\" " +
                            "has placeholder(s) absent from \"other\": $extra"
                    }
                    // CLDR's exact-number categories (zero/one/two) legitimately spell the
                    // number out instead of formatting it — Arabic "عضوان" (two members),
                    // Swedish "En kontakt" — so a missing count placeholder is only a defect
                    // in few/many/other, where the number MUST be rendered.
                    if (quantity in EXACT_NUMBER_QUANTITIES) continue
                    val missing = otherPlaceholders - itemPlaceholders
                    if (missing.isNotEmpty()) {
                        violations += "${dirNameFor(locale)}/${plural.file}: plurals \"$key\" item \"$quantity\" " +
                            "is missing placeholder(s) present in \"other\": $missing"
                    }
                }
            }
        }
        assertTrue(violations.joinToString("\n"), violations.isEmpty())
    }

    // -------------------------------------------------------------------
    // 6. Escaping
    // -------------------------------------------------------------------

    @Test
    fun valuesAreProperlyEscapedWithNoStrayWhitespace() {
        val violations = mutableListOf<String>()
        for (locale in ALL_LANGS) {
            val result = collectEntries(locale) ?: continue
            for (e in result.entries) {
                val context = if (e.quantity == null) "string \"${e.key}\"" else "plurals \"${e.key}\" item \"${e.quantity}\""
                val label = "${dirNameFor(locale)}/${e.fileName}: $context"

                // Unescaped apostrophe in a plain TEXT_NODE run (CDATA is exempt — raw by design).
                var j = 0
                while (j < e.rawText.length) {
                    if (e.rawText[j] == '\'' && (j == 0 || e.rawText[j - 1] != '\\')) {
                        violations += "$label has an unescaped ' — use \\' "
                        break
                    }
                    j++
                }
                if ('\n' in e.rawText) violations += "$label contains a raw newline — use \\n"
                if ('\t' in e.rawText) violations += "$label contains a raw tab — use \\t"

                if (e.value.isNotEmpty() && e.value != e.value.trim()) {
                    violations += "$label has leading/trailing whitespace in its resolved value"
                }
            }
        }
        assertTrue(violations.joinToString("\n"), violations.isEmpty())
    }

    // -------------------------------------------------------------------
    // 7. _android / _ios twin parity
    // -------------------------------------------------------------------

    @Test
    fun androidIosTwinKeysComeInPairs() {
        val violations = mutableListOf<String>()
        for (locale in ALL_LANGS) {
            val data = loadLocale(locale) ?: continue
            val allKeys = data.strings.keys + data.plurals.keys
            for (key in allKeys) {
                when {
                    key.endsWith("_android") -> {
                        val twin = key.removeSuffix("_android") + "_ios"
                        if (twin !in allKeys) violations += "${dirNameFor(locale)}: \"$key\" has no matching \"$twin\""
                    }
                    key.endsWith("_ios") -> {
                        val twin = key.removeSuffix("_ios") + "_android"
                        if (twin !in allKeys) violations += "${dirNameFor(locale)}: \"$key\" has no matching \"$twin\""
                    }
                }
            }
        }
        assertTrue(violations.joinToString("\n"), violations.isEmpty())
    }

    // -------------------------------------------------------------------
    // 8. shared/commonMain platformString() keys + L10nKeys.kt parity
    // -------------------------------------------------------------------

    @Test
    fun sharedPlatformStringKeysExistAndL10nKeysMatchesStringsShared() {
        val sharedFile = File(resDir(), "values/strings_shared.xml")
        assumeTrue(
            "values/strings_shared.xml does not exist yet — skipping (owned by another in-flight run)",
            sharedFile.isFile,
        )

        val en = requireEnLocale()
        val sharedKeys = en.strings.filterValues { it.file == "strings_shared.xml" }.keys

        val commonMainDir = File(repoRoot(), "shared/src/commonMain")
        assertTrue("shared/src/commonMain is missing", commonMainDir.isDirectory)
        val callRegex = Regex("""platformString\(\s*"([^"]*)"""")
        val violations = mutableListOf<String>()
        commonMainDir.walkTopDown()
            .filter { it.isFile && it.extension == "kt" }
            .forEach { f ->
                val code = stripComments(f.readText())
                for (m in callRegex.findAll(code)) {
                    val key = m.groupValues[1]
                    if (key !in sharedKeys) {
                        violations += "${f.relativeTo(repoRoot()).path}: platformString(\"$key\") has no matching " +
                            "key in values/strings_shared.xml"
                    }
                }
            }

        val l10nKeysFile = File(repoRoot(), "androidApp/src/main/java/com/vg/run/l10n/L10nKeys.kt")
        assertTrue(
            "androidApp/src/main/java/com/vg/run/l10n/L10nKeys.kt is missing — regenerate with " +
                "'node scripts/l10n/gen-l10n.mjs'",
            l10nKeysFile.isFile,
        )
        val kt = l10nKeysFile.readText()
        val mapKeyRegex = Regex(""""([a-z][a-z0-9_]*)"\s+to\s+R\.string\.""")
        val mapKeys = mapKeyRegex.findAll(kt).map { it.groupValues[1] }.toSet()
        val onlyInShared = sharedKeys - mapKeys
        val onlyInKeysKt = mapKeys - sharedKeys
        if (onlyInShared.isNotEmpty() || onlyInKeysKt.isNotEmpty()) {
            violations += "L10nKeys.kt map does not match values/strings_shared.xml keys — " +
                "missing from L10nKeys.kt: $onlyInShared; extra in L10nKeys.kt: $onlyInKeysKt " +
                "(regenerate with 'node scripts/l10n/gen-l10n.mjs')"
        }

        assertTrue(violations.joinToString("\n"), violations.isEmpty())
    }

    // -------------------------------------------------------------------
    // 9. Glossary — Rún / Tor must survive translation
    // -------------------------------------------------------------------

    @Test
    fun glossaryTermsSurviveTranslation() {
        val violations = mutableListOf<String>()
        val en = requireEnLocale()
        val runRegex = Regex("(?U)\\bRún\\b")
        val torRegex = Regex("(?U)\\bTor\\b")

        fun checkTerms(context: String, enValue: String, locale: String, localeValue: String) {
            if (runRegex.containsMatchIn(enValue) && !runRegex.containsMatchIn(localeValue)) {
                violations += "${dirNameFor(locale)}: $context drops the glossary term \"Rún\" present in values/"
            }
            if (torRegex.containsMatchIn(enValue) && !torRegex.containsMatchIn(localeValue)) {
                violations += "${dirNameFor(locale)}: $context drops the glossary term \"Tor\" present in values/"
            }
        }

        for (locale in ALL_LOCALES) {
            val data = loadLocale(locale) ?: continue
            for ((key, enEntry) in en.strings) {
                val localeEntry = data.strings[key] ?: continue
                checkTerms("string \"$key\"", enEntry.value, locale, localeEntry.value)
            }
            for ((key, enPlural) in en.plurals) {
                val localePlural = data.plurals[key] ?: continue
                for ((quantity, enValue) in enPlural.items) {
                    val localeValue = localePlural.items[quantity] ?: continue
                    checkTerms("plurals \"$key\" item \"$quantity\"", enValue, locale, localeValue)
                }
            }
        }
        assertTrue(violations.joinToString("\n"), violations.isEmpty())
    }

    // -------------------------------------------------------------------
    // 10. Generated parity — Localizable.xcstrings / InfoPlist.xcstrings
    // -------------------------------------------------------------------

    @Test
    fun generatedCatalogsMatchTheXmlSourceOfTruth() {
        val violations = mutableListOf<String>()
        val en = requireEnLocale()
        val existingLocales = ALL_LOCALES.filter { File(resDir(), dirNameFor(it)).isDirectory }

        fun catalogKeyFor(xmlKey: String) = if (xmlKey == "apns_notification_body") "Notification" else xmlKey

        val localizableFile = File(repoRoot(), "iosApp/iosApp/Localizable.xcstrings")
        assertTrue(
            "iosApp/iosApp/Localizable.xcstrings is missing — regenerate with 'node scripts/l10n/gen-l10n.mjs'",
            localizableFile.isFile,
        )
        val localizableStrings = asMap(asMap(parseJson(localizableFile.readText()))?.get("strings")) ?: emptyMap()

        val expectedCatalogKeys = mutableSetOf<String>()
        for (key in en.strings.keys) if (!key.startsWith("infoplist_")) expectedCatalogKeys += catalogKeyFor(key)
        for (key in en.plurals.keys) expectedCatalogKeys += catalogKeyFor(key)
        val actualCatalogKeys = localizableStrings.keys
        val missingKeys = expectedCatalogKeys - actualCatalogKeys
        val extraKeys = actualCatalogKeys - expectedCatalogKeys
        if (missingKeys.isNotEmpty() || extraKeys.isNotEmpty()) {
            violations += "Localizable.xcstrings key set mismatch — missing: $missingKeys; extra: $extraKeys"
        }

        for (key in en.strings.keys) {
            if (key.startsWith("infoplist_")) continue
            val catalogKey = catalogKeyFor(key)
            val entry = asMap(localizableStrings[catalogKey]) ?: continue
            val localizations = asMap(entry["localizations"]) ?: emptyMap()
            val enValue = asMap(asMap(localizations["en"])?.get("stringUnit"))?.get("value") as? String
            if (enValue.isNullOrEmpty()) {
                violations += "Localizable.xcstrings[\"$catalogKey\"] has no non-empty en localization"
            }
            for (locale in existingLocales) {
                if (localizations[locale] == null) {
                    violations += "Localizable.xcstrings[\"$catalogKey\"] is missing the \"$locale\" " +
                        "localization even though values-$locale/ exists"
                }
            }
        }

        for (key in en.plurals.keys) {
            val catalogKey = catalogKeyFor(key)
            val entry = asMap(localizableStrings[catalogKey]) ?: continue
            val localizations = asMap(entry["localizations"]) ?: emptyMap()
            val enPlural = asMap(asMap(localizations["en"])?.get("variations"))?.let { asMap(it["plural"]) }
            if (enPlural == null || "one" !in enPlural || "other" !in enPlural) {
                violations += "Localizable.xcstrings[\"$catalogKey\"] en localization is missing " +
                    "variations.plural.one/other"
            }
            for (locale in existingLocales) {
                if (localizations[locale] == null) {
                    violations += "Localizable.xcstrings[\"$catalogKey\"] is missing the \"$locale\" " +
                        "localization even though values-$locale/ exists"
                }
            }
        }

        val infoPlistFile = File(repoRoot(), "iosApp/iosApp/InfoPlist.xcstrings")
        assertTrue(
            "iosApp/iosApp/InfoPlist.xcstrings is missing — regenerate with 'node scripts/l10n/gen-l10n.mjs'",
            infoPlistFile.isFile,
        )
        val infoPlistStrings = asMap(asMap(parseJson(infoPlistFile.readText()))?.get("strings")) ?: emptyMap()
        for (catalogKey in listOf("NSCameraUsageDescription", "NSFaceIDUsageDescription")) {
            val entry = asMap(infoPlistStrings[catalogKey])
            if (entry == null) {
                violations += "InfoPlist.xcstrings is missing \"$catalogKey\""
                continue
            }
            val localizations = asMap(entry["localizations"]) ?: emptyMap()
            val enValue = asMap(asMap(localizations["en"])?.get("stringUnit"))?.get("value") as? String
            if (enValue.isNullOrEmpty()) {
                violations += "InfoPlist.xcstrings[\"$catalogKey\"] has no non-empty en localization"
            }
        }

        assertTrue(violations.joinToString("\n"), violations.isEmpty())
    }

    // -------------------------------------------------------------------
    // 11. English content locks (only where the key exists)
    // -------------------------------------------------------------------

    @Test
    fun englishContentLocksHoldWhereKeysExist() {
        val en = requireEnLocale()
        val locks = mapOf(
            "about_welcome_title" to "Welcome to Rún",
            "about_ready_title" to "Ready when you are",
            "protection_tier_name_casual" to "Decent",
            "protection_tier_name_private" to "Secure",
            "protection_tier_name_maximum" to "Maximum",
            "protection_empty_state" to "Pick a level to continue. No level is chosen for you.",
            "notification_title" to "Notification",
            "apns_notification_body" to "Notification",
        )
        val violations = mutableListOf<String>()
        for ((key, expected) in locks) {
            val actual = en.strings[key]?.value ?: continue
            if (actual != expected) violations += "values/: \"$key\" = \"$actual\" (expected \"$expected\")"
        }
        assertTrue(violations.joinToString("\n"), violations.isEmpty())
    }

    // -------------------------------------------------------------------
    // 12. Store listing length limits
    // -------------------------------------------------------------------

    @Test
    fun storeListingTextsRespectPlatformLengthLimits() {
        val dir = File(repoRoot(), "docs/store-listing")
        // The public snapshot (scripts/export) ships no store copy; it is marked by
        // EXPORT_MANIFEST.txt at the root. There the check has nothing to read and
        // is skipped. In the development tree the directory is mandatory.
        assumeTrue(
            "docs/store-listing/ is not part of the public snapshot — skipping",
            dir.isDirectory || !File(repoRoot(), "EXPORT_MANIFEST.txt").isFile,
        )
        assertTrue("docs/store-listing/ is missing", dir.isDirectory)
        val violations = mutableListOf<String>()
        val files = dir.listFiles { f -> f.isFile && f.name.endsWith(".txt") } ?: emptyArray()
        for (f in files) {
            val name = f.name
            val limit = when {
                name.startsWith("play-short-") -> 80
                name.startsWith("play-full-") -> 4000
                name.startsWith("appstore-full-") -> 4000
                name.startsWith("appstore-whatsnew-") -> 4000
                else -> null
            } ?: continue
            val text = f.readText(Charsets.UTF_8).trim()
            if (text.length > limit) {
                violations += "docs/store-listing/$name is ${text.length} chars (limit $limit)"
            }
        }
        assertTrue(violations.joinToString("\n"), violations.isEmpty())
    }
}

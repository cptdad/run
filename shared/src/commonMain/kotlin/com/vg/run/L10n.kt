package com.vg.run

/**
 * Localization bridge for the copy that lives in commonMain (About / Donate /
 * NotificationEducation / ProtectionLevel content, rune vocabulary, device-lock
 * reasons). The shared objects hold RESOURCE KEYS; the text itself is resolved at
 * render time through the platform's native string resources:
 *
 *  - Android: `res/values-<lang>/strings_<area>.xml` via a compile-time key → `R.string` map
 *    (`L10nKeys.kt`, generated) installed from `RunApplication.onCreate`.
 *  - iOS: `Localizable.xcstrings` (generated from the SAME Android XML by
 *    `scripts/l10n/gen-l10n.mjs`) via `NSBundle.localizedStringForKey`.
 *
 * The Android XML is the single source of truth, so both platforms render identical
 * copy per language by construction — the property the old hardcoded `val`s existed
 * to guarantee.
 *
 * FAIL-SOFT: when no resolver is installed (JVM unit tests, early process start) or
 * the key is unknown, the KEY ITSELF is returned. Never throw from a string lookup —
 * a missing translation must degrade to a visible token, not a crash on the PIN
 * screen. Callers must treat the returned string as display text only.
 *
 * Placeholders are positional (`%1$s`, `%1$d`); see [formatPositional] for the
 * subset both platforms honour.
 */
expect fun platformString(key: String, vararg args: Any?): String

/**
 * Test seam: when non-null, BOTH platform actuals consult this first, so commonTest
 * can install an English map (or a spy) without a Context / bundle. Never set in
 * production code.
 */
internal var platformStringOverride: ((key: String, args: Array<out Any?>) -> String)? = null

/**
 * Minimal positional formatter shared by the iOS actual (Foundation's
 * `stringWithFormat` is awkward with K/N varargs) and by tests.
 *
 * Supported: `%N$s` / `%N$@` (any value, `toString()`), `%N$d` / `%N$lld` / `%N$ld`
 * (integers), `%%` (literal percent). `N` is 1-based. Anything else is emitted
 * verbatim. A missing argument renders as an empty string rather than throwing.
 */
internal fun formatPositional(fmt: String, args: Array<out Any?>): String {
    if (args.isEmpty() && !fmt.contains('%')) return fmt
    val out = StringBuilder(fmt.length + 16)
    var i = 0
    while (i < fmt.length) {
        val c = fmt[i]
        if (c != '%') { out.append(c); i++; continue }
        // "%%" → "%"
        if (i + 1 < fmt.length && fmt[i + 1] == '%') { out.append('%'); i += 2; continue }
        // "%N$<conv>"
        var j = i + 1
        var n = 0
        var digits = 0
        while (j < fmt.length && fmt[j].isDigit()) { n = n * 10 + (fmt[j] - '0'); j++; digits++ }
        if (digits == 0 || j >= fmt.length || fmt[j] != '$') { out.append(c); i++; continue }
        j++ // skip '$'
        // conversion: s | @ | d | ld | lld
        val conv = when {
            j < fmt.length && (fmt[j] == 's' || fmt[j] == '@' || fmt[j] == 'd') -> fmt[j].toString().also { j++ }
            fmt.startsWith("lld", j) -> "lld".also { j += 3 }
            fmt.startsWith("ld", j) -> "ld".also { j += 2 }
            else -> null
        }
        if (conv == null) { out.append(c); i++; continue }
        val arg = args.getOrNull(n - 1)
        out.append(arg?.toString() ?: "")
        i = j
    }
    return out.toString()
}

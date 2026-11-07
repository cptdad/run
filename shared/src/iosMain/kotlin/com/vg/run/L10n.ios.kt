package com.vg.run

import platform.Foundation.NSBundle

/**
 * iOS resolver for [platformString]: `Localizable.xcstrings` (generated from the
 * Android XML by `scripts/l10n/gen-l10n.mjs`) via the main bundle. The catalog's
 * placeholders are already iOS-style (`%1$@`, `%1$lld`), which [formatPositional]
 * substitutes directly — no `stringWithFormat` varargs dance.
 *
 * `value = key` makes an unknown key degrade to the key text (fail-soft, matching
 * the Android actual); an EMPTY value is also treated as unknown.
 */
actual fun platformString(key: String, vararg args: Any?): String {
    platformStringOverride?.let { return it(key, args) }
    val fmt = NSBundle.mainBundle.localizedStringForKey(key, key, null)
    if (fmt.isEmpty()) return key
    return if (args.isEmpty()) fmt else formatPositional(fmt, args)
}

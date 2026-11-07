package com.vg.run

// ---------------------------------------------------------------------------
// UpdateCheck — the in-app update nudge's version arithmetic.
//
// THE INPUT IS RELAY-CONTROLLED. The relay advertises "the latest published
// version for your platform" as a response header on every reply; the transport
// actuals allowlist exactly one header per platform, cap its length and hand it
// to [isNewerVersion] as an opaque string. The relay is untrusted, so:
//
//   • the grammar is closed and tiny — exactly three `.`-separated runs of 1–4
//     ASCII digits, ≤ 14 chars total, nothing else. Anything outside it parses
//     to null and NEVER nudges (fail closed on ambiguity);
//   • the ONLY value that may ever reach the UI or the vault is
//     [AppVersion.render] — a string rebuilt from the parsed integer triple, so
//     at most 3 × 4 ASCII digits of relay-chosen state can travel onward. The
//     raw header must not be stored, rendered or logged;
//   • nothing here throws, allocates unboundedly, or logs.
//
// Deliberately regex-free (a K/N client rule) and deliberately NOT built on
// `toIntOrNull`: that accepts Unicode decimal digits (`١٢٣`), a leading `+`,
// and platform-specific whitespace, none of which the wire grammar allows. The
// gate is an explicit `'0'..'9'` range check per character.
// ---------------------------------------------------------------------------

/**
 * The response-header key the platform actuals normalise their own
 * platform-specific relay header onto (Android reads `android-version`, iOS
 * reads `ios-version`; both store it here). Declared locally so the update
 * nudge owns its own lookup key and cannot silently start reading a different
 * header if the transport layer's naming changes.
 */
internal const val UPDATE_NUDGE_HEADER_KEY = APP_VERSION_HEADER_KEY

/** Longest version string the grammar can produce: `9999.9999.9999`. */
internal const val MAX_VERSION_CHARS = MAX_APP_VERSION_HEADER_CHARS

/** Digits allowed per component. Four keeps every component < 10_000. */
private const val MAX_COMPONENT_DIGITS = 4

/**
 * A parsed `MAJOR.MINOR.PATCH` triple. Every field is in `0..9999` by
 * construction of [parseAppVersion] — this type is only ever produced by that
 * parser, so an instance is proof the wire grammar was satisfied.
 */
data class AppVersion(val major: Int, val minor: Int, val patch: Int) {
    /**
     * The canonical rendering, rebuilt from the integers. This — never the raw
     * header — is the only form that may reach the UI or the vault throttle key.
     */
    fun render(): String = "$major.$minor.$patch"

    /** Strict numeric (not lexicographic) precedence: major, then minor, then patch. */
    fun isNewerThan(other: AppVersion): Boolean = when {
        major != other.major -> major > other.major
        minor != other.minor -> minor > other.minor
        else -> patch > other.patch
    }
}

/**
 * Parses [s] against the closed wire grammar, or returns null.
 *
 * Accepted: exactly three `.`-separated components, each 1–4 characters, every
 * character in `'0'..'9'`, total length ≤ [MAX_VERSION_CHARS]. So `0.0.0` and
 * `12.34.5678` parse; `1.2`, `1.2.3.4`, `v1.2.3`, `1.2.3-beta`, `+1.2.3`,
 * `" 1.2.3"`, `"1.2.3 "`, `1.2.12345`, `1..2`, `` and Unicode digits do not.
 *
 * Pure, non-throwing, single pass, no regex and no `toIntOrNull` (see the file
 * header for why both are disqualified).
 */
fun parseAppVersion(s: String?): AppVersion? {
    if (s == null || s.isEmpty() || s.length > MAX_VERSION_CHARS) return null
    val parts = IntArray(3)
    var component = 0
    var digits = 0
    var value = 0
    for (ch in s) {
        if (ch == '.') {
            // An empty component ("1..2", ".1.2", "1.2.") and a 4th component
            // are both grammar violations.
            if (digits == 0 || component >= 2) return null
            parts[component] = value
            component++
            digits = 0
            value = 0
            continue
        }
        // The gate: ASCII digits only. Rejects whitespace, sign characters,
        // letters, and every Unicode digit outside U+0030..U+0039.
        if (ch < '0' || ch > '9') return null
        if (digits >= MAX_COMPONENT_DIGITS) return null
        value = value * 10 + (ch - '0')
        digits++
    }
    if (component != 2 || digits == 0) return null
    parts[2] = value
    return AppVersion(parts[0], parts[1], parts[2])
}

/**
 * Returns the parsed REMOTE version when [remote] is strictly newer than
 * [local], and null otherwise — including whenever EITHER side fails to parse.
 *
 * Never nudge on ambiguity: an unparseable local version (an odd
 * `versionName` / `CFBundleShortVersionString`) or an unparseable, absent or
 * hostile relay header both mean "we cannot tell", and "cannot tell" must not
 * produce a modal that invites the user to make a clearnet store request.
 * Returning the parsed [AppVersion] rather than a Boolean
 * is what keeps the raw header out of every downstream consumer.
 */
fun isNewerVersion(remote: String?, local: String?): AppVersion? {
    val parsedRemote = parseAppVersion(remote) ?: return null
    val parsedLocal = parseAppVersion(local) ?: return null
    return if (parsedRemote.isNewerThan(parsedLocal)) parsedRemote else null
}

package com.vg.run

// ---------------------------------------------------------------------------
// UpdateNudge — the per-vault throttle for the in-app update nudge.
//
// Cadence (locked decision): ONCE PER DAY PER ADVERTISED VERSION. One encrypted
// `_meta` row remembers what we last nudged about and when:
//
//     update_nudge_v1 = "<maj>.<min>.<pat>|<epochDay>"
//
// The version half is [AppVersion.render] — rebuilt from the parsed integer
// triple, NEVER the raw relay header (the relay controls this
// value, so the grammar is what bounds how many relay-chosen bits can be parked
// in the vault; ≤ 3 × 4 ASCII digits). The row lives in the vault's `_meta`
// table, which is SQLCipher on BOTH platforms — no Keychain, no
// `putStringsSync` journal — and is a vault SINGLETON: it names no contact and
// no group, so it belongs to no purge list, and a wipe destroys it with the
// vault like every other row.
//
// Trade-offs:
//   • A relay that keeps advertising a HIGHER version can re-arm the nudge
//     once per app open. Bounded by the monotonic rule below (equal or lower
//     never re-arms, so a relay cannot flip-flop between two versions) and by
//     the RAM latch in MessageManager (at most one evaluation per instance).
//   • The stored version is relay-chosen state persisted in the vault.
//     Bounded by the grammar and erased with the vault.
//
// Same never-throws convention as PushPromptOnboarding.consumePushPromptOnce:
// `putMeta` is `@Throws`, and a write issued after the vault was locked throws a
// catchable exception on both platforms, so every entry point here swallows it.
// A read failure fails toward "do not show" — the nudge is cosmetic and must
// never be the reason a screen crashes.
//
// WRITE ON SHOW, from the UI/VM path only — never from the HTTP thread. A
// force-quit (or Android's `onStop` → `finishAndRemoveTask()` teardown) between
// rendering the modal and the user's tap must not re-nag on the next foreground.
// ---------------------------------------------------------------------------

/** Encrypted per-vault meta key holding `"<version>|<epochDay>"`. */
internal const val UPDATE_NUDGE_META_KEY = "update_nudge_v1"

/** Separator between the rendered version and the epoch day in the stored value. */
private const val UPDATE_NUDGE_SEPARATOR = '|'

/** Milliseconds in a day — the epoch-day divisor. */
private const val MILLIS_PER_DAY = 86_400_000L

/**
 * Today as a UTC day number. Wall-clock based (`Platform.currentTimeMillis`)
 * because there is no kotlinx-datetime here and none is needed: the only thing
 * a clock jump can do is cause ONE extra nag (a changed day number re-arms), and
 * a stored day that no longer parses is treated as "no key" — also a re-arm.
 * Suppression is never the failure direction.
 */
fun epochDayNow(): Long = currentTimeMillis() / MILLIS_PER_DAY

/**
 * True when the nudge for [advertised] may be shown today.
 *
 * Shown iff ANY of:
 *   • no key stored (fresh vault, or never nudged);
 *   • the stored value does not parse (treated exactly like "no key");
 *   • the stored day is not [today];
 *   • [advertised] is STRICTLY newer than the stored version — monotonic, so an
 *     equal or lower advertised version can never re-arm the nudge on the same
 *     day (this bounds the re-arm trade-off above).
 *
 * The caller is responsible for the newer-than-LOCAL test — this function only
 * throttles; see [isNewerVersion].
 *
 * Never throws: a vault whose `getMeta` fails answers `false` (no nudge).
 */
fun shouldShowUpdateNudge(
    vault: VaultDatabase,
    advertised: AppVersion,
    today: Long = epochDayNow(),
): Boolean =
    try {
        val stored = vault.getMeta(UPDATE_NUDGE_META_KEY)
        if (stored == null) {
            true
        } else {
            val sep = stored.indexOf(UPDATE_NUDGE_SEPARATOR)
            val storedVersion =
                if (sep <= 0) null else parseAppVersion(stored.substring(0, sep))
            val storedDay =
                if (sep < 0) null else parseEpochDay(stored.substring(sep + 1))
            if (storedVersion == null || storedDay == null) {
                true                                   // unparseable ⇒ as if absent
            } else {
                storedDay != today || advertised.isNewerThan(storedVersion)
            }
        }
    } catch (_: Exception) {
        false
    }

/**
 * Records that the nudge for [advertised] was shown on [today]. Call this from
 * the UI/VM path AT SHOW TIME (before any store navigation — on Android the
 * `startActivity` can be followed by `onStop` → `finishAndRemoveTask()` in the
 * same UI turn), never from the HTTP thread.
 *
 * Never throws: a locked/failed vault write is swallowed, and the only cost is
 * one extra nudge later.
 */
fun markUpdateNudgeShown(
    vault: VaultDatabase,
    advertised: AppVersion,
    today: Long = epochDayNow(),
) {
    try {
        vault.putMeta(UPDATE_NUDGE_META_KEY, "${advertised.render()}$UPDATE_NUDGE_SEPARATOR$today")
    } catch (_: Exception) {
        // Cosmetic state — a lost write only re-offers the nudge.
    }
}

/**
 * Digits-only epoch-day parse. Same explicit `'0'..'9'` gate as
 * [parseAppVersion] (no Unicode digits, no sign, no whitespace) and a 10-digit
 * cap so the value can never overflow a Long. A negative day — possible only if
 * the device clock is set before 1970 — never parses, which re-arms rather than
 * suppresses.
 */
private fun parseEpochDay(s: String): Long? {
    if (s.isEmpty() || s.length > 10) return null
    for (ch in s) if (ch < '0' || ch > '9') return null
    return s.toLongOrNull()
}

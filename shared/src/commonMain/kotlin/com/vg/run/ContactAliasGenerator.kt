package com.vg.run

// ---------------------------------------------------------------------------
// ContactAliasGenerator — the single source of truth for random contact
// aliases on BOTH platforms.
//
// The add-contact flows (Android AddContactScreen, iOS AddContactView) draw
// aliases from a single shared alphabet AND format distribution. This object
// is that one implementation; every call site delegates here.
//
// (History: the lists used to be declared four times — androidMain, iosMain,
// and Swift — and the Android and iOS copies had silently drifted apart in
// both size and content. commonMain consolidation fixes that class of bug.)
//
// Formats (uniform draw, CSPRNG):
//   • "Verb Animal"        — Running Fox        (the original format)
//   • "Title Animal"       — Captain Otter
//   • "Title Noun"         — Baron Lantern
//   • "Adjective Noun"     — Crimson Harbor
//   • "Historical figure"  — Cleopatra
// ---------------------------------------------------------------------------

// Public (not `internal`): the androidApp module and the Swift layer call in,
// and Kotlin `internal` is per-module.
object ContactAliasGenerator {

    val VERBS: List<String> = listOf(
        "Running", "Jumping", "Silent", "Dancing", "Falling",
        "Glowing", "Hidden", "Drifting", "Burning", "Frozen",
        "Swift", "Howling", "Sleeping", "Rising", "Fading",
        "Rolling", "Spinning", "Diving", "Prowling", "Soaring",
    )

    val ANIMALS: List<String> = listOf(
        "Fox", "Wolf", "Bear", "Hawk", "Raven",
        "Otter", "Lynx", "Elk", "Owl", "Hare",
        "Crane", "Viper", "Falcon", "Badger", "Seal",
        "Eagle", "Stag", "Crow", "Pike", "Moth",
    )

    val TITLES: List<String> = listOf(
        "Captain", "Baron", "Duchess", "Major", "Professor",
        "Sergeant", "Countess", "Admiral", "Doctor", "Keeper",
        "Warden", "Ranger", "Marshal", "Knight", "Squire",
        "Pilot", "Chief", "Scout", "Curator", "Envoy",
    )

    val NOUNS: List<String> = listOf(
        "Lantern", "River", "Anvil", "Willow", "Ember",
        "Harbor", "Summit", "Thicket", "Compass", "Beacon",
        "Cinder", "Hollow", "Meadow", "Quarry", "Saddle",
        "Tundra", "Boulder", "Canyon", "Drift", "Glacier",
    )

    val ADJECTIVES: List<String> = listOf(
        "Quiet", "Amber", "Velvet", "Crimson", "Misty",
        "Golden", "Wild", "Pale", "Stormy", "Dusty",
        "Iron", "Mossy", "Brisk", "Shaded", "Lunar",
        "Coastal", "Thorny", "Silver", "Northern", "Ashen",
    )

    // Long-dead, globally recognizable figures only — a pseudonym, not a
    // hint: nothing here can plausibly identify a living contact.
    val FIGURES: List<String> = listOf(
        "Cleopatra", "Tesla", "Napoleon", "Galileo", "Hypatia",
        "Magellan", "Mozart", "Darwin", "Archimedes", "Boudicca",
        "Caesar", "Leonardo", "Newton", "Plato", "Sappho",
        "Socrates", "Vivaldi", "Hannibal", "Confucius", "Nefertiti",
    )

    /**
     * Random alias in one of the configured formats, format and word(s)
     * drawn independently with the CSPRNG ([secureRandomInt]). Collisions
     * between contacts are allowed by design.
     */
    fun generate(): String = when (secureRandomInt(5)) {
        0 -> "${VERBS[secureRandomInt(VERBS.size)]} ${ANIMALS[secureRandomInt(ANIMALS.size)]}"
        1 -> "${TITLES[secureRandomInt(TITLES.size)]} ${ANIMALS[secureRandomInt(ANIMALS.size)]}"
        2 -> "${TITLES[secureRandomInt(TITLES.size)]} ${NOUNS[secureRandomInt(NOUNS.size)]}"
        3 -> "${ADJECTIVES[secureRandomInt(ADJECTIVES.size)]} ${NOUNS[secureRandomInt(NOUNS.size)]}"
        else -> FIGURES[secureRandomInt(FIGURES.size)]
    }

    /**
     * Format check used by tests + belt-and-braces callers. True iff [alias]
     * matches ANY of the configured formats. The regression test asserts
     * this for every generated contact, so a drift between the generator and
     * a call site gets caught before it ships.
     */
    fun matchesGeneratedFormat(alias: String): Boolean {
        val parts = alias.split(" ")
        if (parts.size == 1) return parts[0] in FIGURES
        if (parts.size != 2) return false
        return (parts[0] in VERBS && parts[1] in ANIMALS) ||
            (parts[0] in TITLES && (parts[1] in ANIMALS || parts[1] in NOUNS)) ||
            (parts[0] in ADJECTIVES && parts[1] in NOUNS)
    }

    /**
     * Collision-comparison key for two aliases that should be treated as "the
     * same displayed name" (referral-offer alias hygiene). commonMain has
     * no platform Unicode-normalizer available without a new expect/actual (out
     * of scope for this fix), so this is a deliberately NARROW, dependency-free
     * fold rather than full ICU/Unicode NFKC — it covers the cases relevant to
     * comparing against our own pure-ASCII generated wordlist:
     *  - Unicode-aware case folding (`lowercase()`), so "running fox" and
     *    "Running Fox" collide.
     *  - The fullwidth Latin compatibility block (U+FF01-FF5E), the single most
     *    common homoglyph trick against an ASCII wordlist (e.g. "Ｒunning Ｆox"),
     *    folded down to plain ASCII exactly as real NFKC would.
     *  - Bidi override/isolate + zero-width + other invisible format
     *    characters, and C0/C1 control characters, stripped — two aliases that
     *    RENDER identically must compare equal even if one hides invisible
     *    codepoints inside a word.
     */
    fun normalizeForCompare(alias: String): String {
        val sb = StringBuilder(alias.length)
        for (ch in alias) {
            val cp = ch.code
            when {
                // Fullwidth ASCII variants (！to ～) fold to their ASCII form.
                cp in 0xFF01..0xFF5E -> sb.append((cp - 0xFEE0).toChar())
                isInvisibleOrControl(cp) -> {}
                else -> sb.append(ch)
            }
        }
        return sb.toString().lowercase()
    }

    /** Shared by [normalizeForCompare] and [sanitizeDisplayName] so the two can
     *  never drift on WHICH code points are dangerous, even though they differ
     *  on what happens to the rest (comparison-key folding + lowercasing in one,
     *  display-preserving in the other):
     *   - C0 controls + DEL + C1 controls.
     *   - Zero-width space/joiner/non-joiner, LRM/RLM.
     *   - Bidi embedding/override (LRE/RLE/PDF/LRO/RLO).
     *   - Word joiner + invisible operators.
     *   - Bidi isolates (LRI/RLI/FSI/PDI).
     *   - Zero-width no-break space / BOM. */
    private fun isInvisibleOrControl(cp: Int): Boolean =
        cp <= 0x1F || cp in 0x7F..0x9F ||
            cp in 0x200B..0x200F ||
            cp in 0x202A..0x202E ||
            cp in 0x2060..0x2064 ||
            cp in 0x2066..0x2069 ||
            cp == 0xFEFF

    /**
     * Display-preserving peer-string sanitiser. Strips the same
     * invisible/control/bidi code points as [normalizeForCompare] — so a
     * peer-supplied string (a group name, currently) can't smuggle a newline,
     * a bidi override/isolate, or a zero-width run into a rendered UI string
     * (e.g. an eclipse-warning dialog) — WITHOUT [normalizeForCompare]'s
     * fullwidth folding or lowercasing, since this is for DISPLAY, not
     * comparison: an ordinary Unicode name (including non-Latin scripts, e.g.
     * Arabic/Persian letters) must render completely unchanged. Tab/LF/CR are
     * mapped to a plain space rather than dropped outright, so a
     * newline-separated string collapses to a normal word gap instead of
     * splicing two words together; runs of whitespace are then folded to one
     * space and the ends trimmed. Callers apply their own length cap
     * (`take(n)`) AFTER this — stripping can shrink a string that was
     * non-blank only in what would have been its truncated-away tail.
     */
    fun sanitizeDisplayName(raw: String): String {
        val sb = StringBuilder(raw.length)
        for (ch in raw) {
            val cp = ch.code
            when {
                cp == 0x09 || cp == 0x0A || cp == 0x0D -> sb.append(' ')
                isInvisibleOrControl(cp) -> {}
                else -> sb.append(ch)
            }
        }
        return sb.toString().replace(Regex("\\s+"), " ").trim()
    }
}

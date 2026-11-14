package com.vg.run

import kotlin.math.log2
import kotlin.math.max

// ---------------------------------------------------------------------------
// CredentialPolicy — cross-platform security policy constants + the passphrase
// strength estimator for "high-risk mode" (Lever A).
//
// Lives in commonMain so Android (Compose) and iOS (SwiftUI) enforce the SAME
// entropy floor and drive the SAME strength meter — a floor that drifted
// between platforms would silently weaken one of them.
// ---------------------------------------------------------------------------

object CredentialPolicy {

    /**
     * Foreground inactivity auto-lock (Lever C):
     * after this long with no user interaction while the vault is open, the
     * app locks (drops the vault + key material from RAM, forces credential
     * re-entry). Fixed, not user-configurable — a configurable timeout is a
     * coercion surface ("set it to 8 hours"). Backgrounding already locks
     * immediately on both platforms; this bounds the app-open-but-idle window
     * an AFU seizure could exploit.
     */
    val AUTO_LOCK_TIMEOUT_MS: Long = 2 * 60 * 1000L

    /** How often the platforms poll the idle clock. UI-cadence only. */
    val AUTO_LOCK_CHECK_INTERVAL_MS: Long = 10 * 1000L

    /**
     * Lever-C warning countdown (threat-slider spec, 2026-07-16): an in-app
     * overlay ("Locking in 5… — tap to stay") appears this long BEFORE the idle
     * auto-lock fires, at every tier. The deadline itself NEVER moves — the
     * warning sits inside the Lever-C window, not after it (a grace period
     * would widen the AFU exposure it bounds). Must stay well under the
     * shortest tier timeout (MAXIMUM = 60 s) so the overlay is a warning, not
     * a fixture — asserted in CredentialPolicyTest.
     */
    val AUTO_LOCK_WARNING_MS: Long = 5 * 1000L

    /** Once idle is within this of the deadline, the platforms poll at
     *  [AUTO_LOCK_FINE_CHECK_INTERVAL_MS] instead of the coarse cadence — that
     *  drives the 1 Hz countdown AND makes the lock punctual (the 10 s poll
     *  alone can fire it up to ~10 s late). */
    val AUTO_LOCK_FINE_WINDOW_MS: Long = 15 * 1000L
    val AUTO_LOCK_FINE_CHECK_INTERVAL_MS: Long = 1000L

    /**
     * B6a: PIN length (fixed 6-digit PIN). Both platforms render exactly this many
     * dots and complete entry when this many digits are typed. Single-sourced so a
     * mismatched length can't diverge between Android and iOS.
     */
    val PIN_LENGTH: Int = 6

    /**
     * True when [credential] is SHAPED like the fixed PIN the entry keypads
     * produce: exactly [PIN_LENGTH] ASCII digits (the keypad emits nothing
     * else). Used where the stored PIN-vs-passphrase mode flag is unavailable
     * (damaged vlt_m blob) and the resulting mode must be
     * derived from the credential itself instead of the unreadable flag.
     */
    fun isPinShaped(credential: String): Boolean =
        credential.length == PIN_LENGTH && credential.all { it in '0'..'9' }

    /**
     * B6a: consecutive wrong-credential attempts before the emergency wipe. The
     * durable counter (PinAttemptsStore) is checked against this on every failure
     * and at launch; a rolling-window cap can also trip the wipe.
     */
    val MAX_CONSECUTIVE_ATTEMPTS: Int = 5

    /**
     * Wrong-credential wipe budget for a persisted-level [read] — the single
     * shared decision both lock screens consume (PinEntryScreen / PinEntryView
     * via IosAppController.maxConsecutiveAttempts), like
     * [InactivityPolicy.thresholdMsOrNull] for the inactivity window:
     *  - Present    → the chosen tier's budget.
     *  - Absent     → [MAX_CONSECUTIVE_ATTEMPTS] (legacy pre-slider install).
     *  - Damaged    → MAXIMUM's (strictest) budget. A
     *    blob that fails AEAD under a WORKING device key is positive tamper
     *    evidence, and the lenient branch below handed that tamper the LARGEST
     *    budget — one flipped byte doubled the brute-force allowance from 5 to
     *    10 on the only rate limit unlock() has. Absence still takes the
     *    legacy-default branch, so nothing ambiguous lands here.
     *  - Unreadable → the MOST LENIENT tier's budget. A level that exists but
     *    can't be read because the DEVICE KEY is transiently unavailable must
     *    never shrink the budget below what the user chose — a CASUAL (10-try)
     *    vault handed the 5-try default would wipe honest data five typos
     *    early. The 24h window cap and backoff still bound an attacker in this
     *    state.
     */
    fun maxConsecutiveAttempts(read: ProtectionLevelRead): Int = when (read) {
        is ProtectionLevelRead.Present -> read.level.maxConsecutiveAttempts
        ProtectionLevelRead.Absent -> MAX_CONSECUTIVE_ATTEMPTS
        ProtectionLevelRead.Damaged -> ProtectionLevel.MAXIMUM.maxConsecutiveAttempts
        ProtectionLevelRead.Unreadable -> ProtectionLevel.MOST_LENIENT_MAX_ATTEMPTS
    }

    /**
     * Lever C auto-lock timeout for a persisted-level [read] (MainActivity's
     * idle check / IosAppController.autoLockTimeoutMs). Fail-safe direction is
     * INVERTED vs the destructive decisions above: locking sooner loses no
     * data, so BOTH non-readable states get the SHORTEST tier timeout — an
     * unreadable (or tampered) MAXIMUM (60s) level must not idle for the 2-min
     * default. This is the one decision where Damaged and Unreadable agree.
     */
    fun autoLockTimeoutMs(read: ProtectionLevelRead): Long = when (read) {
        is ProtectionLevelRead.Present -> read.level.autoLockTimeoutMs
        ProtectionLevelRead.Absent -> AUTO_LOCK_TIMEOUT_MS
        ProtectionLevelRead.Damaged, ProtectionLevelRead.Unreadable ->
            ProtectionLevel.entries.minOf { it.autoLockTimeoutMs }
    }

    /**
     * B6a: exponential unlock backoff after [failedAttempts] wrong tries — 1 s, 2 s,
     * 4 s, 8 s (capped at 8 s). Slows rapid brute force while the user still has
     * their [MAX_CONSECUTIVE_ATTEMPTS]. Returns milliseconds; iOS divides by 1000.
     */
    fun unlockBackoffMs(failedAttempts: Int): Long =
        1000L * (1 shl (failedAttempts - 1).coerceIn(0, 3))

    /**
     * Delay to re-apply when a credential-entry screen is (re)opened with
     * [persistedFailedAttempts] wrong tries already on the DURABLE counter
     * (PinAttemptsStore). The in-session backoff alone resets on a force-quit +
     * relaunch (the counter survives, the in-memory wait does not), so each fresh
     * launch must serve the wait for the current count before accepting the next
     * guess. 0 when no wrong try is outstanding. Callers measure it with a
     * MONOTONIC clock (elapsedRealtime / systemUptime) from screen-open — no wall
     * clock is persisted, so a clock change can neither skip nor stretch it.
     */
    fun launchBackoffMs(persistedFailedAttempts: Int): Long =
        if (persistedFailedAttempts <= 0) 0L else unlockBackoffMs(persistedFailedAttempts)

    /** Whole seconds to show in a "Try again in N s" hint: [remainingMs] rounded UP, 0 when elapsed. */
    fun backoffSecondsLeft(remainingMs: Long): Int =
        if (remainingMs <= 0L) 0 else ((remainingMs + 999L) / 1000L).toInt()

    /**
     * Entropy floor for a high-risk-mode passphrase: ≥ ~70 bits
     * ≈ 6 diceware words or 12+ mixed-class characters. Below this, offline
     * brute force of the passphrase-derived KEK (after a device-key
     * extraction) stops being "infeasible for decades" — the entire point of
     * the passphrase is to hold even when the hardware factor is defeated.
     */
    val MIN_PASSPHRASE_BITS: Double = 70.0

    /** Hard length cap — sanity bound, not a security parameter. */
    val MAX_PASSPHRASE_LENGTH: Int = 256

    /** Bits credited per distinct diceware-style word (EFF large list ≈ 2^12.9). */
    private const val BITS_PER_WORD = 12.925

    /**
     * CONSERVATIVE passphrase entropy estimate, in bits.
     *
     * Model selection: input with ≥ 2 whitespace-separated words is scored as
     * a diceware-style phrase (distinct words × ~12.9 bits, a repeated word
     * earns nothing) — NOT with the character model, which grossly overrates natural
     * words ("correct horse battery staple" is ~52 bits of word choice, not
     * the ~130 bits its 28 characters would suggest). A single token is
     * scored as length × log2(charset of the classes present), with a run of
     * same-case letters credited at natural-language rate (~1.4 bits per letter,
     * so a lyric typed without spaces is one "word", not random text), other
     * same-class runs at half credit, and repeated characters discounted so
     * "aaaaaaaaaaaaaaaa" cannot buy its way past the floor on length alone.
     * Character classes are Unicode-aware: "ä" is a letter, not a symbol.
     *
     * This is a heuristic LOWER-BOUND-ish estimate for gating and the meter,
     * not a cracker-grade model; it deliberately under-credits ambiguous
     * input so the floor errs toward stronger passphrases.
     */
    fun estimateBits(passphrase: String): Double {
        val trimmed = passphrase.trim()
        if (trimmed.isEmpty()) return 0.0
        val raw = estimateBitsRaw(trimmed)
        // Famous-phrase cap (2026-11-10, dynamic report fix #4). A line from the shared
        // culture — a national anthem, a common prayer, a proverb, a pangram, a famous
        // first line — is NOT its word-entropy however many words it has; an attacker
        // reads it straight off a phrase list. Cap any input whose canonical (case-,
        // space- and diacritic-insensitive) form IS, or is a leading span of, a known
        // famous phrase. min() keeps it monotone-decreasing — nothing that failed before
        // starts passing, and a famous OPENER extended with genuinely random words is not
        // matched (only the prefix direction), so real added entropy still counts.
        return if (isFamousPhrase(trimmed)) minOf(raw, FAMOUS_PHRASE_CAP) else raw
    }

    private fun estimateBitsRaw(trimmed: String): Double {
        val words = trimmed.split(whitespace).filter { it.isNotEmpty() }
        // A genuine single token is scored with the
        // same-class-run discount ON — a token that never (or rarely) changes
        // character class is one "word" from one alphabet ("sunshineforever"), and a
        // long same-class run inside a mixed token ("Sunshine2024!" → "unshine",
        // "2024") is dictionary/pattern-guessable far below its charset×length
        // product. Neither may clear the MAXIMUM floor on length alone.
        if (words.size < 2) {
            val single = charModelBits(trimmed, discountSameClassRuns = true)
            // CamelCase / PascalCase ("ToBeOrNotToBe", "CorrectHorseBatteryStaple") is a
            // spaceless phrase whose capitals at each word boundary are CLASS CHANGES that
            // defeat the same-class-run discount — so the char model over-credits it (exactly
            // hashcat's CamelCase-despace rule, the 2026-11-09 dynamic test's biggest single-
            // token bypass: ToBeOrNotToBe scored 70.1). If the token splits on lower→upper
            // boundaries into ≥ 2 segments, ALSO score those segments with the word model and
            // take the min: the segments lowercase-normalize to the same words the spaced
            // phrase would, so a CamelCase phrase can no longer out-score its own spaced form.
            // min() keeps it monotone-decreasing — a genuinely strong PascalCase password's
            // segments are non-dictionary and still earn ~12.9 each, so nothing that cleared
            // the floor on real entropy starts failing. GUARD: only an ALL-LETTER token is
            // treated as a possible CamelCase phrase — a random token with digits/symbols
            // ("aB3!xY9$kQ7%") also has lower→upper boundaries but is NOT a word phrase, and
            // its genuine char-model entropy must not be re-scored as a handful of "words".
            val caseSegments = if (trimmed.all { it.isLetter() }) splitCaseBoundaries(trimmed) else emptyList()
            return if (caseSegments.size >= 2) minOf(single, wordModelBits(caseSegments)) else single
        }
        // A space-separated SEQUENCE ("1 2 3 4 5 6", "a b c d e f",
        // "abc def ghi jkl mno pqr") would otherwise route to the word model and dodge
        // the char-model run/keyboard/sequence penalties — re-opening, for phrases, the
        // exact bypass class the run discount closes for single tokens. Score it as the MINIMUM of
        // the word model and the char model applied to the DESPACED string: a spaced
        // sequence collapses under the char model, while a genuine diceware phrase
        // keeps its (lower, correct) word-model score.
        // NOTE the despaced check keeps the same-class-run discount OFF: a genuine
        // short-word phrase ("cat dog fox pig cow hen") despaces to one long same-class
        // run, and discounting it would false-reject a real ~77-bit phrase (the word
        // model is already the correct, lower estimate there). The predictable-step and
        // low-period penalties — which real words do NOT trigger but spaced sequences
        // do — still bind on this path.
        return minOf(
            wordModelBits(words),
            charModelBits(trimmed.replace(whitespace, ""), discountSameClassRuns = false),
        )
    }

    /** True when [passphrase] clears the enforced high-risk-mode floor. */
    fun meetsFloor(passphrase: String): Boolean =
        passphrase.length <= MAX_PASSPHRASE_LENGTH &&
            estimateBits(passphrase) >= MIN_PASSPHRASE_BITS

    /**
     * Meter bucket for [bits]: 0 = weak, 1 = fair (still below the floor),
     * 2 = strong (floor met), 3 = excellent. The floor sits exactly on the
     * 1→2 boundary so "the bar turns strong" and "the button enables" agree.
     */
    fun strengthBucket(bits: Double): Int = when {
        bits < 45.0 -> 0
        bits < MIN_PASSPHRASE_BITS -> 1
        bits < 90.0 -> 2
        else -> 3
    }

    private val whitespace = Regex("\\s+")

    private fun wordModelBits(words: List<String>): Double {
        // The diceware model assumes words drawn RANDOMLY from a
        // ~7776-word list (12.9 bits each). A human picking the most FREQUENT words
        // ("the and for you but not") draws from a far smaller effective set, so
        // credit a common word at half — an all-common-word phrase (the concrete
        // bypass) then falls well below the floor. A repeated word earns nothing.
        //
        // Tokens are NORMALIZED before both the dedup and
        // every lookup. The old code used a bare `w.lowercase()`, so punctuation
        // walked straight past COMMON_WORDS: "the, and, for, you, but, not" scored
        // the full 77.55 bits and was ACCEPTED while its unpunctuated twin was
        // rejected — a one-keystroke bypass of the floor MAXIMUM leans on when the
        // device-key half of CR-1 is free (DeviceLockPolicy).
        val normalized = words.map { normalizeWord(it) }
        // Group memberships are resolved over the DISTINCT tokens first, so a
        // repeat can never inflate a group into (or out of) its penalty.
        val distinct = normalized.toSet()
        val categoryHits = HashMap<ClosedCategory, Int>()
        val stemHits = HashMap<String, Int>()
        for (w in distinct) {
            closedCategoryOf(w)?.let { categoryHits[it] = (categoryHits[it] ?: 0) + 1 }
            // A null stem (bare number / punctuation-only token) is INELIGIBLE for
            // family detection — never a matchable key. See [counterStem].
            counterStem(w)?.let { stemHits[it] = (stemHits[it] ?: 0) + 1 }
        }
        // The two NUMERIC-token patterns, resolved
        // over the whole phrase before scoring for the same reason the groups above
        // are. A bare number is not a diceware draw, and neither of these shapes is
        // visible to any rule that came before: [counterStem] deliberately returns
        // null for a bare number (removing the empty-stem collision that used to
        // false-reject "correct 2024 horse 1999 …"), the closed categories are all
        // word sets, and the despaced char model credits a full log2(10) per digit,
        // which is the RIGHT number for random digits and far too generous for
        // years. See [isYearShaped] and [numericProgressionMembers].
        val numbers = distinct.filter { isAsciiNumber(it) }
        val yearsSeen = numbers.count { isYearShaped(it) }
        val yearRun = yearsSeen >= MIN_YEAR_RUN && numbers.size - yearsSeen <= 1
        val progression = numericProgressionMembers(normalized)

        val seen = HashSet<String>()
        val stemSeen = HashSet<String>()
        var commonSeen = 0
        var bits = 0.0
        for ((index, w) in normalized.withIndex()) {
            var base = BITS_PER_WORD
            // Rung A (2026-11-09, dynamic passphrase test). A token that NORMALIZES to
            // nothing — pure punctuation / symbols ("!", "—", "…", "!!!") — is not a word
            // and must not buy a 12.9-bit diceware credit. That was the one-keystroke
            // bypass the test found across languages: a 5-word anthem line that scored
            // ~64 bits (refused) cleared the floor the instant a lone "!" was appended as
            // a sixth "word" ("Ja vi elsker dette landet" 64.6 → "Ja vi elsker dette
            // landet !" 77.55). Zero credit, and it consumes no word slot.
            if (w.isEmpty()) continue
            // Rung D-number (2026-11-10, owner call taken from the 2026-11-09 dynamic report
            // which this block previously deferred). A BARE number is not a 12.9-bit diceware
            // draw — a uniformly random number carries only log2(10) per digit. Cap it there,
            // so padding a sub-floor phrase with a short number no longer buys a full word
            // slot ("Ja vi elsker dette landet 7": the five words score 64.6, and the "7" now
            // adds 3.3 → 67.9, refused, not 12.9 → 77.5). A 4-digit year still earns ~full
            // credit (4·log2(10)=13.3 > 12.9, so min() leaves it at 12.9), which is correct —
            // a uniformly random year really does carry that much — and the year-run /
            // progression / counter rules below still bind on a RUN of them. Native-script
            // digits were folded to ASCII in [normalizeWord], so Arabic-Indic / Persian
            // numerals are capped too. Only ever lowers the word model: monotone-decreasing,
            // and it fires at provisioning/rotation only (never unlock), with the live meter
            // showing the shortfall.
            if (isAsciiNumber(w)) base = minOf(base, BITS_PER_COUNTER * w.length)
            // A CLOSED-CATEGORY run. Two or more tokens drawn from the same
            // small, fully enumerable set ("one two three four five six", weekdays,
            // months, the NATO alphabet, colours, planets, bare letters) are not
            // 12.9-bit diceware draws — each member carries at most log2(set size),
            // so the whole run collapses to ~17-29 bits. None of these sets appear
            // in COMMON_WORDS, which is why they cleared the floor untouched.
            // A LONE category word keeps full credit: a genuine diceware roll may
            // legitimately produce one, and only the RUN is the guessable pattern.
            val cat = closedCategoryOf(w)
            if (cat != null && (categoryHits[cat] ?: 0) >= 2) base = minOf(base, cat.bitsPerMember)
            // A YEAR run — the closed-category idea applied to the one
            // "closed set" a human reaches for when asked for six *numbers*.
            if (yearRun && isYearShaped(w)) base = minOf(base, BITS_PER_YEAR)
            // Common word → half diceware credit. Rung D-common (2026-11-10): the same
            // treatment extended to the high-frequency / function words of the 12 app
            // locales (LOCALIZED_COMMON_WORDS), so an all-function-word phrase in any
            // supported language falls the way the English one does ("der die das und oder
            // aber", "je tu il nous vous ils", "yo tu el ella nosotros vosotros"). Half
            // credit, monotone-decreasing, and a genuine diceware list excludes bare
            // function words so a real phrase is unaffected.
            val penalizeCommon = (w in COMMON_WORDS || w in LOCALIZED_COMMON_WORDS) && ++commonSeen > COMMON_FREEBIES
            if (penalizeCommon) base = minOf(base, BITS_PER_WORD / 2.0)
            // A word+COUNTER family ("cat1 cat2 cat3 …"). The tokens are all
            // distinct, so dedup saw six independent words; in truth the family is
            // one stem plus a trivially-enumerable counter. Credit the first member
            // normally and every later one at the counter's own ~log2(10) bits.
            // A token with NO stem left after the trim carries null and is skipped
            // — it belongs to no family (see [counterStem] for why that matters).
            val stem = counterStem(w)
            if (stem != null && (stemHits[stem] ?: 0) >= 2 && !stemSeen.add(stem)) {
                base = minOf(base, BITS_PER_COUNTER)
            }
            // The counter family again, for numbers with no stem to share
            // — "1990 1991 1992 …" is one starting value plus a step. The run's FIRST
            // member keeps whatever credit it earned above; every later one carries
            // the step's own ~log2(10) bits. See [numericProgressionMembers].
            if (index in progression) base = minOf(base, BITS_PER_COUNTER)
            // A REPEATED word earns NOTHING (2026-11-12, external review RUN-03). It used
            // to earn half credit, so a sub-floor phrase typed twice cleared the floor:
            // "correct horse battery staple" scored 51.7 (refused) and the same four words
            // twice scored 77.55 (accepted) — yet "say it again" is one cracker rule, worth
            // about a bit however long the repeated block is. A repeat is not a new
            // independent draw, so it adds no word credit at all; only DISTINCT words count.
            if (seen.add(w)) bits += base
        }
        return bits
    }

    /**
     * Canonical form of a phrase token — lowercased, with
     * every non-alphanumeric character stripped. Used for the dedup AND every
     * lookup below, so decorating a word with punctuation can no longer dodge a
     * penalty (nor buy a second "distinct word" credit for the same word).
     */
    private fun normalizeWord(w: String): String =
        buildString { for (c in w.lowercase()) if (c.isLetterOrDigit()) append(foldAsciiDigit(c)) }

    /**
     * Fold the decimal digits of the app's non-Latin locales to ASCII 0-9 so the
     * numeric rules ([isAsciiNumber], [isYearShaped], [numericProgressionMembers] and
     * the bare-number cap in [wordModelBits]) see them. Arabic-Indic (ar) and Extended
     * Arabic-Indic (fa) numerals otherwise slipped every number rule, which only matched
     * '0'..'9' — the one-keystroke "pad with a native-script digit" bypass the
     * 2026-11-09 dynamic test found. Explicit ranges (not digitToInt) keep the fold
     * byte-identical on every KMP target; a non-digit is returned unchanged.
     */
    private fun foldAsciiDigit(c: Char): Char = when (c) {
        in '٠'..'٩' -> '0' + (c - '٠')   // Arabic-Indic ٠..٩
        in '۰'..'۹' -> '0' + (c - '۰')   // Extended Arabic-Indic (Persian/Urdu) ۰..۹
        else -> c
    }

    /**
     * Split a single token at lower→upper CASE BOUNDARIES ("ToBeOrNotToBe" →
     * [To, Be, Or, Not, To, Be]). Used only to re-expose a CamelCase phrase to the
     * word model in [estimateBits]; the result is never the final score, only a min()
     * input, so an imperfect split can only lower an over-credited token, never raise
     * one. A token with no internal lower→upper transition yields a single-element list
     * (the caller then ignores it and keeps the plain char-model score).
     */
    private fun splitCaseBoundaries(token: String): List<String> {
        val out = ArrayList<String>()
        val cur = StringBuilder()
        for (i in token.indices) {
            val c = token[i]
            if (i > 0 && c.isUpperCase() && token[i - 1].isLowerCase()) {
                out.add(cur.toString()); cur.setLength(0)
            }
            cur.append(c)
        }
        if (cur.isNotEmpty()) out.add(cur.toString())
        return out
    }

    // -----------------------------------------------------------------------
    // Famous-phrase corpus (2026-11-10, dynamic report fix #4). A culturally shared
    // line — anthem, prayer, proverb, pangram, famous first line — carries almost no
    // guessing entropy however many words it has; it is one entry on an attacker's
    // phrase list. [FAMOUS_PHRASES] holds such lines in CANONICAL form; [isFamousPhrase]
    // caps any input that matches, space-/case-/diacritic-insensitively. The corpus is
    // SEEDED from the dynamic test's own accepted famous-category phrases (ground truth:
    // every one actually cleared the floor) plus a per-locale expansion, and is meant to
    // grow. Monotone-decreasing — it only ever lowers a score.
    // -----------------------------------------------------------------------

    /** A famous phrase is findable in a dictionary attack of well under 2^30 guesses;
     *  the exact cap only needs to sit below the 70-bit floor and land in the weak meter
     *  bucket (< 45), so the user sees "weak", not a near-miss. */
    private const val FAMOUS_PHRASE_CAP = 30.0

    /** Minimum canonical length for a famous-phrase match — ~4-5 words. Keeps a short
     *  canonical form from colliding with an unrelated passphrase, and bounds the prefix
     *  scan to inputs long enough to be a real famous span. */
    private const val FAMOUS_MIN_CANON_LEN = 15

    /** True when [trimmed]'s canonical form IS, or is a LEADING span of, a known famous
     *  phrase. Prefix-only on the stored side: a famous OPENER followed by genuinely
     *  random words is NOT matched, so "anthem line + 3 random words" keeps its entropy. */
    private fun isFamousPhrase(trimmed: String): Boolean {
        val canon = canonicalFold(trimmed)
        if (canon.length < FAMOUS_MIN_CANON_LEN) return false
        if (canon in FAMOUS_PHRASES) return true
        for (p in FAMOUS_PHRASES) if (p.length > canon.length && p.startsWith(canon)) return true
        return false
    }

    /**
     * Canonical form for the famous-phrase match: lowercased, Latin diacritics folded to
     * their base letter, Arabic harakat / combining marks dropped, native-script digits
     * folded to ASCII (see [foldAsciiDigit]), and EVERY non-alphanumeric removed — so
     * "Ja, vi elsker dette landet!", "ja vi elsker dette landet" and "Jà vì elsker…"
     * collapse to one key. This is why a single stored entry catches a famous line
     * however it is cased, spaced, punctuated or diacritic-stripped (the exact mangle
     * families the dynamic test used as free no-ops). Mirrors scripts/.../locdata/merge.py.
     */
    private fun canonicalFold(s: String): String = buildString {
        for (raw in s.lowercase()) {
            val d = foldAsciiDigit(raw)
            if (d != raw) { append(d); continue }          // folded a native-script digit
            val ch = ARABIC_FOLD[raw] ?: raw               // normalize hamza seats / Persian letters
            when {
                ch == 'ё' -> append('е')                   // Cyrillic yo → ye
                LATIN_FOLD[ch] != null -> append(LATIN_FOLD[ch]!!)
                isCombiningMark(ch) -> {}                  // drop harakat / combining marks
                ch.isLetterOrDigit() -> append(ch)
                else -> {}                                 // drop spaces / punctuation
            }
        }
    }

    /** Arabic/Persian letter normalization for [canonicalFold] (standard search fold):
     *  hamza seats → bare alif, waw-hamza → waw, alif-maqsura & Persian yeh → Arabic yeh,
     *  Persian keheh → Arabic kaf, teh-marbuta → heh — so one stored prayer/anthem catches
     *  its spelling variants. Mirrors merge.py's ARABIC_FOLD. */
    private val ARABIC_FOLD: Map<Char, Char> = mapOf(
        'ٱ' to 'ا', 'أ' to 'ا', 'إ' to 'ا', 'آ' to 'ا',
        'ؤ' to 'و', 'ئ' to 'ي', 'ى' to 'ي', 'ی' to 'ي',
        'ک' to 'ك', 'ة' to 'ه',
    )

    /** True for Unicode combining marks dropped by [canonicalFold] — general combining
     *  diacritics plus the Arabic harakat/tatweel/Quranic-annotation ranges. */
    private fun isCombiningMark(c: Char): Boolean {
        val o = c.code
        return o in 0x0300..0x036F || o in 0x064B..0x065F || o == 0x0670 || o == 0x0640 || o in 0x06D6..0x06ED
    }

    /** Latin accented letter → base, for [canonicalFold]. Expanding folds (æ→ae, ß→ss,
     *  œ→oe, þ→th) match the two spellings users actually type. Mirrors merge.py's FOLD. */
    private val LATIN_FOLD: Map<Char, String> = mapOf(
        'à' to "a", 'á' to "a", 'â' to "a", 'ã' to "a", 'ä' to "a", 'å' to "a", 'ą' to "a", 'ā' to "a", 'ă' to "a",
        'æ' to "ae", 'ç' to "c", 'ć' to "c", 'č' to "c",
        'è' to "e", 'é' to "e", 'ê' to "e", 'ë' to "e", 'ę' to "e", 'ě' to "e", 'ē' to "e", 'ė' to "e",
        'ì' to "i", 'í' to "i", 'î' to "i", 'ï' to "i", 'ī' to "i", 'į' to "i",
        'ł' to "l", 'ñ' to "n", 'ń' to "n", 'ň' to "n",
        'ò' to "o", 'ó' to "o", 'ô' to "o", 'õ' to "o", 'ö' to "o", 'ø' to "o", 'ő' to "o", 'ō' to "o",
        'œ' to "oe", 'ß' to "ss", 'š' to "s", 'ś' to "s", 'ş' to "s",
        'ù' to "u", 'ú' to "u", 'û' to "u", 'ü' to "u", 'ů' to "u", 'ű' to "u", 'ū' to "u",
        'ý' to "y", 'ÿ' to "y", 'ž' to "z", 'ź' to "z", 'ż' to "z", 'ð' to "d", 'þ' to "th",
    )

    /** Famous-phrase corpus — FILLED by scripts/.../locdata/merge.py (ground truth +
     *  per-locale expansion). Placeholder until the data integration edit. */
    private val FAMOUS_PHRASES: Set<String> = setOf(
        "abirdinthehandisworthtwo", "abirdinthehandisworthtwointhebush",
        "acaballoregaladonolemireseldiente", "acaballoregaladonoselemiraeldiente",
        "actionsspeaklouderthanwords", "actionsspeaklouderthanwordsalways",
        "aebletfalderikkelangtfrastammen", "afdaboolandahabwaakujiraa",
        "aguaquenohasdebeberdejalacorrer", "ahvousdiraijemamancequicausemontourment",
        "aikaparantaakaikkihaavatjasurut", "ainsifontfontfontlespetitesmarionnettes",
        "alhamdulillahirabbilalaminarrahmanirrahimimalikiyawmiddin",
        "allaahulaailaahaillaahuwalxayyulqayyuum", "allagodatingartrestycken",
        "allahuakbarallahuakbarlaailaahaillallah", "allahuakbarlailahaillaallah2024",
        "allahummasallialamuhammadinwaalaaalihi", "allefuglersmadeer",
        "allemeineentchenschwimmenaufdem", "allemeineentchenschwimmenaufdemsee",
        "allemenschenwerdenbruderwodeinsanfterflugelweilt", "allergutendingesinddrei2024",
        "allevogelsindschonda2024", "allforoneandoneforall", "allonsenfantsdelapatrie1792",
        "allonsenfantsdelapatrie2024", "allonsenfantsdelapatrielejour",
        "allonsenfantsdelapatrielejourdegloire", "allonsenfantsdelapatrielejourdegloireestarrive",
        "allthatglittersisnotgold", "alouettegentillealouettealouettejeteplumerai",
        "alussaolivatsuokuokkajajussi", "alussaolivatsuokuokkajajussiniin",
        "amaltiempobuenacarasiempre", "amanfangschufgotthimmelunderde",
        "ambrunnenvordemtoredastehteinlindenbaum", "anappleadaykeepsthedoctoraway",
        "anappleadaykeepsthedoctoraway2024", "anappleadaykeepsthedoctoraway7",
        "anotherbrickinthewall", "apreslapluielebeautemps", "aqoonlaaaniwaaiftiinlaaan",
        "aqoonlaaaniwaaiftiinlaaan1", "aqoonlaaaniwaaiftiinlaaan2024",
        "aqoonlaaaniwaaiftiinlaaanookale", "aqoonlaaniwaaiftiinlaan", "aquienmadrugadiosleayuda",
        "arrozconlechemequierocasar", "arrozconlechemequierocasarconunasenoritadelacapital",
        "aserrinaserranlosmaderosdesanjuan", "ashhaduallaailaahaillallaahmuxammadrasuulullaah",
        "assalamualaykumwarahmatullahiwabarakatuhu",
        "astaghfirullahrabbiminkullidhanbinwaatubuilayh", "attvaraellerintevaradetarfragan",
        "atvaereellerikkevaeredetersporgsmalet", "auclairdelalunemonamipierrot",
        "auclairdelalunemonamipierrotpretemoitaplume", "auclairdelalunepierrot",
        "aujourdhuimamanestmorte", "auxarmescitoyensformezvosbataillons",
        "auxarmescitoyensformezvosbataillons1792", "auxarmescitoyensformezvosbataillonsauxarmes",
        "avaereellerikkevaeredetersporsmalet", "ayatulkursiallahulailahaillahuwa",
        "b1sm1llah1rrahman1rrah1malhamdul1llah1rabb1lalam1n", "babavitalammhardu",
        "backebackekuchenderbackerhatgerufen", "baebaelillelamhardunoe",
        "battreenfagelihandenantio", "battreenfagelihandenantioiskogen",
        "beautyisintheeyeofthebeholder", "bedreenfuglihandenendti", "bedreforevarennettersnar",
        "beenwaaloodhashaarunbaaselagudhintaa", "besamebesamemuchocomosifueraestanoche",
        "birdsofafeatherflocktogether",
        "bismillaahirraxmaanirraxiimalxamdulillaahirabbilcaalamiin",
        "bismillahirrahmanirrahimalhamdulillah",
        "bismillahirrahmanirrahimalhamdulillahirabbilalamin",
        "blessedarethemeekfortheyshallinherittheearth", "blinkalillastjarnadar",
        "blinkalillastjarnadaruppepa", "bortabramenhemmabastja", "bortebramenhjemmebest",
        "camaronqueseduermeselollevalacorriente", "caminantenohaycaminosehacecaminoalandar",
        "chacunvoitmidiasaporte", "cielitolindocantaynollores",
        "cincolobitostienelalobablancosynegrosdetrasdelaescoba", "clavametuamorcomounaestaca",
        "coloresperanzanoshagaverlavida", "coloresperanzanoshagaverlavidadeotrocolor",
        "contigoaprendiqueexistennuevasemociones",
        "contrenousdelatyrannieletendardsanglantestleve",
        "corazonespinadocorazonespinadocomomeduele", "corazonpartiocomopudistehacermeestoami",
        "creoendiospadretodopoderosocreadordelcieloydelatierra", "criacuervosytesacaranlosojos",
        "curiositykilledthecatbutsatisfactionbroughtitback", "danoshoynuestropandecadadia",
        "danslafermedemathurinilyadesvaches", "debajodeunbotontontonqueencontromartintintin",
        "decoloresdecoloressevistenloscampos", "deldichoalhechohaymuchotrecho",
        "denblomstertidnukommer", "densomgapareftermycketmisterofta", "densomlersistlerbest",
        "derballistrunddasspieldauertneunzigminuten", "dereretyndigtland2024",
        "dereretyndigtlanddetstar", "dereretyndigtlanddetstarmedbredeboge",
        "derfruehevogelfaengtdenwurm", "derfruhevogelfangtdenwurm",
        "derherristmeinhirtemirwirdnichtsmangeln",
        "dermondistaufgegangendiegoldnensternleinprangen",
        "despacitoquierorespirartucuellodespacito", "detbugtersigibakkedal",
        "deterikkegullaltsomglimrer", "deteringenskamasnu",
        "deutschlanddeutschlanduberallesinderwelt",
        "deutschlanddeutschlanduberallesuberallesinderwelt", "deutschlanduberallesinderwelt1922",
        "dimeconquienandasytedirequieneres", "diostesalvemariallenaeresdegraciaelsenorescontigo",
        "donnenousaujourdhuinotrepaindecejour", "dontcountyourchickensbeforetheyhatch",
        "dugamladufriadufjaellhoeganord", "dugamladufriadufjallhoganord",
        "dugamladufriadufjallhoganord1", "dugamladufriadufjallhoganord2024",
        "dugamladufriadufjallhoganord7", "dugamladufriadufjallhoganorddutysta",
        "duskaintetrodetblirsommar", "dutronarpaminnenfranfornstoradar",
        "eenymeenyminymoecatchatigerbythetoe", "eikannatanuolaistaennenkuintipahtaa",
        "eimitaanuuttaauringonallakoskaan", "einigkeitrechtfreiheitvaterlanddeutschlandeinigkeit",
        "einigkeitundrechtundfreiheit1848", "einigkeitundrechtundfreiheit1871",
        "einigkeitundrechtundfreiheit7", "einigkeitundrechtundfreiheitfurdasdeutschevaterland",
        "einmannleinstehtimwaldeganzstillundstumm", "einprositdergemutlichkeit",
        "eisemiesjokakaatuuvaan", "eiseolekaikkikullankimallus",
        "elqueabuenarbolsearrimabuenasombralecobija", "elquenoarriesganogananipierde",
        "elskerdetogtenkerpavarfarogmor", "elvelozmurcielagohinducomiafelizcardillo",
        "elvelozmurcielagohinducomiafelizcardilloykiwi", "enbocacerradanoentranmoscas",
        "enbocacerradanoentranmoscas2024", "enhverersinegenlykkessmed", "enunlugardelamancha",
        "enunlugardelamanchadecuyonombre", "enunlugardelamanchadecuyonombrenoquieroacordarme",
        "eraseunavezuncircoquealegraba", "esirrtdermenschsolangerstrebt",
        "estrellitadondeestasmepreguntoqueseras", "estrellitadondeestasquierosaberqueeres",
        "everycloudhasasilverlining", "eyiraneymarzeporgoharey", "fadervardusomerihimmelen",
        "fadervardusomerihimmelenhelligetvordedittnavn", "fadervarsomarihimmelenhelgat",
        "fadervarsomarihimmelenhelgatvardedittnamn", "fadervordusomerihimlene",
        "fadervordusomerihimlenehelligetvaereditnavn",
        "fahrenheitjacelsiusyrjosivatasanbackgammonpeliinvolkswagenissa",
        "feliznavidadmerrychristmasjoyeuxnoel", "feliznavidadprosperoanoyfelicidad",
        "floatlikeabutterflystinglikeabee", "flygandebackasinersokahwilapamjukatuvor",
        "forgodsolovedtheworld", "fourscoreandsevenyearsago", "franklymydearidontgiveadamn",
        "franzjagtimkomplettverwahrlostentaxiquerdurchbayern",
        "frerejacquesdormezvoussonnezlesmatines", "frerejacquesfrerejacquesdormezvousdormezvous",
        "freudeschoenergoetterfunkentochterauselysium",
        "freudeschonergotterfunkentochterauselysium",
        "freudeschonergotterfunkentochterauselysium1785", "frihetjamlikhetbroderskapkarlekhopptro",
        "fuchsduhastdiegansgestohlen", "furetvaerbittovervannetmeddetusenhjem",
        "gloireaupereetaufilsetausaintesprit", "gloriaalpadreyalhijoyalespiritusanto",
        "godsaveourgraciousqueenlongliveournoblequeen", "grauteurerfreundistalletheorie",
        "gudsignevartdyrefedrelandog", "gutenmorgenliebesonnewiegehtesdir",
        "gutenmorgenschonentagnochdir", "habiaunavezunbarcochiquitito",
        "hadalbadaniwaahadhimoyareoodheer", "hailmaryfullofgracethelordiswiththee",
        "hanschenkleingingalleinindie", "hanschenkleingingalleinindieweitewelthinein",
        "harkommerpippilangstrumptjolahopptjolahejtjolahoppsan", "hejtomtegubbarslaiglasen",
        "hejtomtegubbarslaiglasenochlat", "helangarsjunghoppfaderallanlallanlej",
        "hellereenfuglihandenendtipataget", "hellodarknessmyoldfriend",
        "herecomesthesunlittledarling", "herraonminunpaimenenieiminulta",
        "herraonpaimeneniгосподепастир", "herrasiunatkoonjavarjelkoonsinuaaina",
        "hojblygomvandtfraeksexquizpawc", "holamundoприветмирbonjourmonde",
        "holaquetalcomoestasamigo", "honestyisthebestpolicy", "hooyomacaanwaankujeclahayaadiyoaad",
        "hoppehoppereiterwennerfallt", "howvexinglyquickdaftzebrasjump",
        "hvorbogenspejlersintopibolgenbla", "hyvaajouluajaonnellistauuttavuotta",
        "hyvaajouluajaonnellistauuttavuotta2026", "ichbineinberliner", "ichdenkealsobinich",
        "ichliebedichduliebstmich", "ichliebedichfurimmermeinschatz",
        "ichweissnichtwassollesbedeutendassichsotraurigbin", "idagerdetolfertsfodselsdaghurra",
        "idanmarkerjegfodtderhar", "ifyoucantbeatthemjointhem",
        "ilcourtilcourtlefuretlefuretdubois", "iletaitunefoisdansuneforetlointaine",
        "ilkowadajirbaywaxkugooyaan", "ilpleutilpleutbergererentretesblancsmoutons",
        "ilyalongtempsquejetaimejamaisjenetoublierai", "imagineallthepeoplelivingfortoday1971",
        "imfruhtauzubergewirziehnfallera", "imsevimsespindelklattraruppfortraden",
        "innaataynakalkawtharfasallilirabbikawanhar",
        "inthebeginninggodcreatedtheheavensandtheearth", "isaisameidanjokaolettaivaissa",
        "isameidanjokaolettaivaissa2026", "isameidanjokaolettaivaissapyhitetty",
        "isameidanjokaolettaivaissapyhitettyolkoon",
        "isameidanjokaolettaivaissapyhitettyolkoonsinunnimesi", "isameidanоченашjokaкој",
        "itwasthebestoftimesitwastheworstoftimes", "jamahanlevajamahanleva",
        "jamahanlevautihundradear", "janojussinmaenlaskuolivauhdikasjahauska",
        "javielskerdettelandet2024", "javielskerdettelandetsom", "javielskerdettelandetsomdet",
        "javielskerdettelandetsomdetstigerfrem",
        "jecroisendieuleperetoutpuissantcreateurducieletdelaterre", "jepensedoncjesuis1",
        "jepensedoncjesuis1637", "jepensedoncjesuisdescartes", "jepensedoncjesuisdoncjepense",
        "jetaimemoinonplustoujours", "jevoussaluemariepleinedegrace",
        "jevoussaluemariepleinedegraceleseigneurestavecvous",
        "jokakuuseenkurkottaasekatajaankapsahtaa", "jovanojovankekrajvardarotsedismori",
        "jovencilloemponzonadodewhiskyfigurotaexhibe",
        "jukolantaloetelaisessahameessasijaitseemaenrinteessa",
        "jumalaompilinnammejavahvaturvamme", "kaikkimitatarvitsetonrakkauttanyt",
        "kayfahalukayaakhiantabikhayrinalhamdulillah", "keepyourfriendscloseandyourenemiescloser",
        "knowledgeispowerfrancisbacon", "koivujatahtiolikaunissatu",
        "kommteinvogelgeflogensetztsichnieder", "kongchristianstodvedhojenmast",
        "kongchristianstodvedhojenmastirogogdamp", "korokorokirkkoonpapinmuorinkanssa",
        "laailaahaillallaahmuxammadrasuulullaah", "lacamisanegratengolacamisanegra",
        "laciguenatocabaelsaxofondetrasdelpalenque",
        "laciguenatocabaelsaxofondetrasdelpalenquedepaja",
        "lacucarachalacucarachayanopuedecaminar", "lafuerzateacompanejovenpadawan",
        "lahawlawalaquwwataillabillahilaliyyiladheem", "lailahaillallahlailahaillallahmuhammad",
        "lailahaillallahmuhammadurrasulullah",
        "lailahaillallahmuhammadurrasulullahsallallahualayhi",
        "lamacarenaeeehmacarenadaleatucuerpo", "lappetitvientenmangeantditonsouvent",
        "lavidaesuncarnaval2024", "lavidaesuncarnavalparareir", "lavidanovalenada7",
        "lavieestunlongfleuvetranquille", "leiserieseltderschneestillundstarr",
        "lennalennaleppakerttukesanensilampoon", "lessentielestinvisiblepourlesyeux",
        "levifrenardbrunsautepardessuslechienparesseux", "lhabitnefaitpaslemoine",
        "liberteegalitefraternite178917921794", "liberteegalitefraterniteoulamort",
        "liberteegalitefraterniterepubliquefrancaisemarianne", "lifeislikeaboxofchocolates",
        "lillepeteredderkop", "longtempsjemesuiscouchedebonneheure",
        "lospollitosdicenpiopiopiocuandotienenhambre", "maaonniinkauniskirkasluojan",
        "maaonniinkauniskirkasluojantaivas", "magacayguwaacabdiwaxaankudhashaymuqdisho",
        "mamajustkilledamangun1975", "manskaintesaljaskinnetforranbjornen",
        "manskalikkeskuehundenpaharene", "masvalepajaroenmanoqueciento",
        "masvalepajaroenmanoquecientovolando", "masvaletardequenunca", "masvaletardequenunca8",
        "maxamedcabdillexasansayidwuxuuahaahalyey", "maytheforcebewithyou",
        "maytheforcebewithyou7", "maytheforcebewithyoualways1977",
        "melimliavimamulikhmelozhanimasreli", "mellombakkarogbergutmedhavet", "mesterjakobsoverdu",
        "meuniertudorstonmoulinvatropvite", "mexicanosalgritodeguerra2024",
        "mexicanosalgritodeguerra9", "micasaessucasaamigo",
        "mieleniminuntekeviaivoniajattelevilaulamahan", "minkanuorenaoppiisenvanhanataitaa",
        "morgenstundharguldimundda", "morgenstundhatgoldimmund", "morgenstundhatgoldimmund1",
        "morgenstundhatgoldimmund2024", "morgonstundharguldmorgenstundhargullmorgen",
        "muchosanosdespuesfrentealpelotondefusilamientoelcoronelaurelianobuendia",
        "nabadiyocaanosoomaaliyahanoolaatoweligeed", "ninwalbameeshuukadhashayjacayl",
        "ninwalbameeshuukadhashayjacaylbuu", "ninwalbameeshuukadhashayjacaylbuuuqabaa",
        "nodejesparamananaloquepuedashacerhoy", "nohaymalqueporbiennovenga",
        "notreperequiesauxcieux", "notreperequiesauxcieuxquetonnomsoitsanctifie",
        "nowyouseemenowyoudont", "nuapuristakuulusepolkantahtijalakani",
        "nukkuunukkuumattipienipaansaalla", "nurdiehartenkommenindengarten",
        "nutandastusenjuleljuspajordensmorka", "ohsaycanyouseebythedawnsearlylight",
        "oikallissuomenmaasaihanajakaunis", "oimaammesuomisynnyinmaasoi1917",
        "oimaammesuomisynnyinmaasoisana", "oimaammesuomisynnyinmaasoisana2024",
        "oimaammesuomisynnyinmaasoisanakultainen", "oisuomikatsosinunpaivaskoittaa",
        "oisuomikatsosinunpaivaskoittaanyt", "ojosquenovencorazonquenosiente",
        "olkauniskesailtakunlaaksossakavelin", "oneforallandallforone",
        "onnellisuuseiolemaaranpaavaanmatka", "onnevoitbienquaveclecoeur",
        "onsuurempilahjaantaakuinsaada", "otannenbaumotannenbaumwietreusinddeineblatter",
        "ourfatherwhoartinheaven", "ourfatherwhoartinheaven2024",
        "ourfatherwhoartinheavenhallowedbethyname", "outofsightoutofmind",
        "ovelsegjormestersiermanofte", "packmyboxwithfivedozenliquorjugs",
        "padrenuestroqueestasenelcielosantificadoseatunombre", "padrenuestroqueestasenloscielos",
        "parempipyypivossakuinkymmenenoksalla", "pekkatopohantaasuimetsanpienessatalossa",
        "peoplewholiveinglasshousesshouldntthrowstones", "perroqueladranomuerde5",
        "petitapetitloiseaufaitsonnid", "pienikaunispienipaivansadejamenninkainen",
        "pierrequiroulenamassepasmousse", "piippolanvaarillaolitaloiaiaioo",
        "pinponesunmunecomuyguapodecarton", "portezcevieuxwhiskyaujugeblondquifume",
        "promenonsnousdanslesboispendantqueleloup", "qolobaacalankeedwaaceynoo",
        "qolobaacalankeedwaaceynooinnagakeenoomee", "quelluevaquelluevalavirgendelacueva",
        "queseraserawhateverwillbe", "quetonregneviennequetavolontesoitfaitesurlaterrecommeauciel",
        "quevivaespanavivaelrey", "quevivamexicosenoresquevivamexico",
        "quisemeleventrecoltelatempete", "quiseressemblesassemble", "quivaalachasseperdsaplace",
        "quivoleunoeufvoleunboeuf",
        "quizdeltagernespistejordbaermedflodemenscirkusklovnenwaltherspilledepaxylofon",
        "qulaudhubirabbilfalaqminsharrima", "qulaudhubirabbinnasmalikinnasilahin",
        "qulhuwallahuahadallahussamadlamyalid", "quunsangimpurabreuvenossillons",
        "rabbanaatinafiddunyahasanatanwafil", "rakassuomisynnyinmaakaunisjavapaa",
        "ravenraskaroverisenochtittar", "readyornothereicome", "redenistsilberschweigenistgold",
        "riennesertdecouririlfautpartirapoint", "rowrowrowyourboatgentlydownthestream",
        "s00maaliyeeyt00s00iskutiirsadaeehadba", "saheinknabeinrosleinstehn",
        "saintemariemerededieupriezpournouspauvrespecheurs",
        "salamalaykumwarahmatullahiwabarakatuhudear",
        "sanasanacolitaderanasinosanashoysanarasmanana",
        "santamariamadredediosruegapornosotrospecadores", "santificadoseatunombrevengatureino",
        "sarzadazufuqmehrkhavaranfarr", "savezvousplanterleschouxalamodedecheznous",
        "sayhellotomylittlefriend", "seinodernichtseindasisthierdiefrage",
        "sgtpepperslonelyheartsclubband", "sininenvalkoinensuomenlippuliehuukorkealla",
        "siniristilippuliehuusuomentaivaanallaylpeana",
        "siniristilippummesuomenlippukaunispuhdasvalkoinen", "sinoloseyoquien",
        "smagrodornasmagrodornaarlustigaattse", "sommanroperiskogenfarmansvar",
        "sonnezlesmatinesdingdangdong", "soomaaliyahanoolaatosoomaaliyahanoolaatoweligeed",
        "soomaaliyeeytoosooiskutiirsadahadbakiinataagdaranee",
        "soomaaliyeeytoosootoosooiskutiirsada1991", "soomaaliyeeytoosootoosooiskutiirsadaee",
        "soyuznerushimyrespubliksvobodnykhsplotilanavekivelikaya", "sphinxofblackquartzjudgemyvow",
        "sticksandstonesmaybreakmybones", "stillenachtheiligenachtallesschlafteinsamwacht",
        "subhaanallaahwalxamdulillaahwalaailaahaillallaahwallaahuakbar",
        "subhanallahwalhamdulillahwalailahaillallah",
        "subhanallahwalhamdulillahwalailahaillallah99",
        "subhanallahwalhamdulillahwalailahaillallahwallahuakbar", "surlepontdavignononydanse",
        "surlepontdavignononydanseonydanse", "sweetcarolinegoodtimesneverseemedsogood",
        "sweethomealabamawheretheskiesaresoblue", "taallapohjantahdenallaelamajatkuuedelleenaina",
        "taallapohjantahdenallaelamaonrauhallista", "tengounamunecavestidadeazulzapatitosblancos",
        "tequieromuchoятебялюблю", "tervesuomikaunissynnyinmaammekallispohjola",
        "theearlybirdcatchestheworm", "theearlybirdcatchestheworm1999",
        "theearlybirdcatchestheworm7", "theearlybirdgetstheworm", "thegrassisalwaysgreener",
        "thegrassisalwaysgreenerontheotherside", "thelordismyshepherd",
        "thelordismyshepherdishallnotwant", "thelordismyshepherdpsalm1611",
        "thepenismightierthanthesword", "thequickbrownfoxjumpsoverthelazydog", "tobeornottobe2024",
        "tobeornottobethatisthequestion", "tobeornottobethatisthequestion1603",
        "toomanycooksspoilthebroth", "toutcequibrillenestpasor", "tuikituikitahtonen",
        "tuikituikitahtoneniltaisinsaloistat", "twinkletwinklelittlestarhowiwonderwhatyouare",
        "ubimmertreuundredlichkeitbisandeinkuhlesgrab", "ukkonooaukkonooaolikunnonmies",
        "unesourisvertequicouraitdanslherbe", "untiensvautmieuxquedeuxtulauras",
        "vainamoinensoittikantelettamerenrannallakauniisti",
        "varpunenjouluaamunaistuikatollalumisellapienena",
        "varsaerezulufrabadeoyaspiltejowhistogquickstep", "vaterunserderdubistimhimmel",
        "vaterunserimhimmelgeheiligtwerdedeinname",
        "vengaanosotrostureinohagasetuvoluntadenlatierracomoenelcielo",
        "verdequetequieroverdevientoverde", "vielskerdettelandetsomstiger",
        "viveleventviveleventdhiver", "viveleventviveleventviveleventdhiver",
        "vivirmividalalalala", "vouloircestpouvoirmaispouvoircestagir",
        "waxaanahayninsoomaaliahoomuslim", "weallliveinayellowsubmarine1966",
        "wedontneednoeducationwedontneednothoughtcontrol",
        "werandereneinegrubegrabtfalltselbsthinein", "werreitetsospatdurchnachtundwind",
        "whatyouseeiswhatyouget", "wheninromedoastheromansdo", "whenlifegivesyoulemons",
        "whenthegoinggetstough", "whenthegoinggetstoughthetoughgetgoing",
        "withgreatpowercomesgreatresponsibility", "woeinwilleistdaistaucheinweg",
        "yosolosequenosenada", "yosoyunhombresincerodedondecrecelapalma", "youcanthandlethetruth",
        "youwinsomeyoulosesome", "zwolfboxkampferjagenviktorqueruberdengrossensylterdeich",
        "аяидушагаюпомоскве", "безмаканеманаука", "безмаканеманаукаeivaivatta",
        "безтруданевыловишьирыбкуизпруда", "белеетпарусодинокийвтуманеморяголубом",
        "биљанаплатнобелешенаохридскитеизвори", "блазесијанамајкати",
        "бурямглоюнебокроетвихриснежныекрутя", "влесуродиласьелочкавлесуонаросла",
        "вместевеселошагатьпопросторампопросторам", "воиметонаотецотсинотдухот",
        "волканогикормятачеловекаруки", "волковбоятьсявлеснеходить",
        "воспелипесназаслободатамакедонскагорда",
        "всесчастливыесемьипохожидругнадругакаждаянесчастливаясемьянесчастливапосвоему",
        "вставайстранаогромнаявставайнасмертныйбой", "втравесиделкузнечиксовсемкакогуречик",
        "выходиланаберегкатюшанавысокийберег", "гляжувозерасиниевполяхвижу",
        "господипомилујнасгрешнитеденессите", "даживеевардардопоследенздив",
        "даживееслободнаинезависнамакедонија", "двеглависепопаметниодедна",
        "денесденеснадмакедонијасераѓа", "денеснадмакедонијасераѓа1944",
        "денеснадмакедонијасераѓаново", "денеснадмакедонијасераѓановосонце",
        "денеснадмакедонијасераѓановосонценаслободата", "денеснадмакедонијаслободадомживот",
        "деньпобедыкаконбылотнасдалек", "другпознаетсявбеде", "еленоќеркоеленоснежанобелогрло",
        "жилбылубабушкисеренькийкозлик", "жилибылидеддабаба", "зајдизајдијасносонцезајдипомрачисе",
        "каковтаткотаковсин", "калинкакалинкакалинкамоявсадуягодамалинка",
        "катюшавыходиланаберегкрутойвысокий", "когападнанабалканоткрвавапланина",
        "којкопагробдругомусампаѓа", "којкопагробдругомусампаѓавонего", "којраноранидвесреќиграби",
        "којсокоготаковнакрај", "люблюгрозувначалемаякогдавесеннийпервыйгром",
        "магепсанодтвоитеочисумјас", "македонијоземјомилародиноубавамоја",
        "македонскодевојчекиткашаренавоградина", "македонскодевојчекиткашаренавоградинанабрана",
        "мойдядясамыхчестныхправилкогданевшутку", "мойдядясамыхчестныхправилкогданевшуткузанемог",
        "морозисолнцеденьчудесный", "морозисолнцеденьчудесный1",
        "надеждамойкомпасземнойаудачанаградазасмелость", "невсетозолоточтоблестит",
        "невсетозолоточтоблеститярко", "неимейсторублейаимейстодрузей",
        "ниесмемакедонцигордиислободни", "низпиринпланинапееславејпиле",
        "ойморозморознеморозьменя", "ойтоневечертоневечер", "оросевиенабелосело",
        "оросевиенависокосело", "оросевиенаселосега", "отченашижеесинанебесах",
        "отченашсущийнанебесахдасвятитсяимятвое", "оченашкојсинанебесата",
        "оченашкојсинанебесата1991", "оченашкојсинанебесатада",
        "оченашкојсинанебесатадасесветииметотвое", "пилепеенагранчезеленоубаво",
        "повтореньематьученья", "повторувањетоемајканазнаењето",
        "подоброденесјајцеотколкуутрекокошка", "пријателсепознававоневолјавистинска",
        "пустьбегутнеуклюжепешеходыполужам", "пустьвсегдабудетсолнцепустьвсегдабудетнебо",
        "работатагокрасичовекот", "работатагокрасичовекотнеоблеката",
        "раскинулосьмореширокоиволныбушуютвдали", "расцветалияблониигрушипоплылитуманынадрекой",
        "ревелабурягромгремелвомраке", "россиясвященнаянашадержавароссиялюбимаянашастрана",
        "семьразотмерьодинразотрежь", "семьразотмерьодинразотрежьдерево",
        "скажикадядяведьнедароммоскваспаленнаяпожаром", "снощитидојдовнаврататадушо",
        "солнцежешконадвардарблескасилно",
        "союзнерушимыйреспубликсвободныхсплотиланавекивеликаярусь",
        "степьдастепькругомпутьдалеклежит", "съешьжеещеэтихмягкихфранцузскихбулок",
        "съешьжеещеэтихмягкихфранцузскихбулокдавыпейчаю", "тешконатојштонеманикого",
        "тивкаводабрегронисекогашполека", "тишеедешьдальшебудешь",
        "тишеедешьдальшебудешьцелымдоедешь", "трпидушоцрнотиекркушо",
        "улукоморьядубзеленыйзлатаяцепьнадубетом", "унылаяпораочейочарованьеприятнамнетвоякраса",
        "чтопосеешьтоипожнешь", "чтопосеешьтоипожнешь2024", "чтопосеешьтоипожнешь7",
        "широкастранамояроднаямноговнейлесовполей", "штомиемилоемдраго",
        "штосечуестругастругабистравода", "япомнючудноемгновеньепередомнойявиласьты",
        "јованојованкекрајвардаротседишмори", "ادميراعقلميبايدنهزر", "اذاالشعبيوماارادالحياهفلا",
        "اذاغامرتفيشرفمرومفلاتقنعبمادونالنجوم", "استغفراللهالعظيم", "اشهدانلاالهالاالله",
        "اشهدانلاالهالااللهواشهدانمحمدارسولالله", "اطلبواالعلممنالمهدالياللحد",
        "الاياايهاالساقيادركاساوناولها", "الجارقبلالداروالرفيققبلالطريق",
        "الحبوالسلاموالحريهلكلالشعوبالعربيه", "الحمدللهربالعالمين",
        "الخيلوالليلوالبيداءتعرفنيوالسيفوالرمحوالقرطاسوالقلم", "السلامعليكمورحمهاللهوبركاته2024",
        "السلامعليكمورحمهاللهوبركاته7", "السلامعليكميااصدقاييالاعزاءجميعا", "الصبرمفتاحالفرج",
        "الطيورعلياشكالهاتقع", "العجلهمنالشيطانوالتانيمنالرحمن", "العقلالسليمفيالجسمالسليم",
        "العلمفيالصغركالنقشعليالحجر", "الكلاممنفضهوالسكوتمنذهب", "اللهاكبراللهاكبرلاالهالاالله",
        "اللهاكبركبيراوالحمدللهكثيرا", "اللهلاالهالاهوالحيالقيوم",
        "اللهمانكعفوكريمتحبالعفوفاعفعنا", "اللهمصلعليسيدنامحمدواله",
        "الوطنالعربيمنالمحيطاليالخليج", "الوقتكالسيفانلمتقطعهقطعك",
        "اناالبحرفياحشايهالدركامنفهلسالواالغواصعنصدفاتي", "اناللهوانااليهراجعون",
        "انماالاعمالبالنياتوانمالكلامريمانوي", "اهدناالصراطالمستقيم", "اياكنعبدواياكنستعين",
        "ايايرانايمرزپرگهرايخاكتسرچشمههنر", "اينقافلهعمرعجبميگذرد", "اگرانتركشيرازيبهدست",
        "اگرانتركشيرازيبهدستارددلمارا", "باركجبهمنزلنميرسد", "بسماللهالرحمنالرحيم",
        "بسماللهالرحمنالرحيمالحمدللهربالعالمين",
        "بسماللهالرحمنالرحيمالحمدللهربالعالمينالرحمنالرحيم",
        "بسماللهتوكلتعلياللهلاحولولاقوهالابالله", "بسيرنجبردمدراينسالسي", "بشنوازنيچونحكايتميكند",
        "بشنوازنيچونحكايتميكندازجداييهاشكايتميكند", "بلاديبلاديبلاديلكحبيوفوادي",
        "بنيادماعضاييكديگرندكهدرافرينشزيكگوهرند", "بنيادماعضاييكپيكرند2024",
        "بنيادماعضاييكپيكرند5", "بهنامخداوندبخشندهمهربان", "بهنامخداوندجانوخرد",
        "بهنامخداوندجانوخردكزينبرترانديشهبرنگذرد", "توانابودهركهدانابود",
        "توانابودهركهدانابود2024", "حسبناللهونعمالوكيل", "حسبياللهونعمالوكيلنعمالموليونعمالنصير",
        "حماهالديارعليكمسلامابتانتذلالنفوسالكرام", "خدايابهاميدتوزندگيميكنم", "خيرالكلامماقلودل",
        "دانشنوراستونادانيتاريكياست", "دانهفلفلسياهوخالمهرويانسياه", "دراينجهانهيچكسبيغمنيست",
        "درختدوستيبنشانكهكامدلبهبارارد", "دلميرودزدستمصاحبدلانخدارا", "دوستانباشدكهگيرددستدوست",
        "دوستانباشدكهگيرددستدوستدرپريشانحالي", "دوستدارمتوراايوطنمن", "دوصدگفتهچوننيمكردارنيست",
        "رباغفرليولوالديوللمومنينيوميقومالحساب", "ربنااتنافيالدنياحسنهوفيالاخرهحسنه",
        "ربنالاتواخذنااننسينااواخطانا", "سبحاناللهالحمدللهاللهاكبرلاالهالاالله",
        "سبحاناللهوالحمدللهولاالهالااللهواللهاكبر", "سبحاناللهوبحمدهسبحاناللهالعظيم",
        "سبحاناللهوبحمدهسبحاناللهالعظيم2024", "سحرخيزباشتاكامرواباشي",
        "سرزدازافقمهرخاورانفروغديدهحقباوران", "سلامبرهمهدوستانعزيزمن", "سلامعليكمورحمهاللهوبركاته",
        "سلامعليكمورحمهاللهوبركاته2024", "سلاممنصبابرديارقودمعلايكفكفيادمشق",
        "شتابكارشيطاناستودرنگكارخدا", "صباحالخيريااحباييجميعا7", "صبركليدگشايشهركاراست",
        "عشقاساننموداولوليافتادمشكلها", "عشقيعنيدوستداشتنبيقيد", "عليقدراهلالعزمتاتيالعزايم",
        "عيدفطرمباركسعيدعليكم2024", "فيالتانيالسلامهوفيالعجلهالندامه", "قلهواللهاحداللهالصمد",
        "قلهواللهاحداللهالصمدلميلد", "كتابخوببهتريندوستانساناست", "كلعاموانتمبخيردايما2024",
        "كلكمراعوكلكممسوولعنرعيته", "كناولاتكنتلكهيالمساله", "لاالهالااللهمحمدرسولالله",
        "لاالهالااللهمحمدرسولالله2024", "لاالهالااللهمحمدرسولاللهالله", "لاالهالااللهوحدهلاشريكله",
        "لاتحزناناللهمعنادايما", "لاحولولاقوهالابالله", "لاضررولاضرارفيالاسلام",
        "ماكلمايتمنيالمرءيدركه", "مصرياامالبلادانتغايتيوالمراد", "منايرانيهستموبهوطنمافتخارميكنم",
        "منتخدايراعزوجلكهطاعتشموجبقربتاست", "منجدوجدومنزرعحصد",
        "منجدوجدومنزرعحصدومنسارعليالدربوصل", "منحسناسلامالمرءتركهمالايعنيه", "منعاشقتوهستمايعشقمن",
        "منلميشكرالناسلميشكرالله", "موطنيموطنيالجلالوالجمالوالسناء",
        "موطنيموطنيالجلالوالجمالوالسناءوالبهاءفيرباك", "ميخوركهبهزيرگلبسيخواهيخفت",
        "نابردهرنجگنجميسرنميشود", "هرروزصبحزودبيدارشو", "هركسيكودورماندازاصلخويش",
        "هركهبامشبيشبرفشبيشتر", "هركهطاووسخواهدجورهندوستانكشد", "هركهنانماراخوردنانماراميدهد",
        "هرچهبگنددنمكشميزنند", "واذاالشعبيوماارادالحياهفلابدانيستجيبالقدر",
        "چراغيكهبهخانهرواستبهمسجدحراماست", "چوايراننباشدتنمنمباد", "گرصبركنيزغورهحلواسازي",
    )

    /**
     * Common words up to this count used to keep full diceware credit,
     * because half-crediting them false-rejected real ~77-bit phrases.
     * That allowance was WITHDRAWN — set to 0 — after the
     * punctuation bypass showed how little slack the floor has to give: two free
     * common words let a six-word phrase carry ~26 bits of real entropy and still
     * clear 70. The cost is that a genuine phrase which happens to draw two common
     * words now needs a seventh word (5 full + 2 half = 77.55 bits), which the
     * strength meter shows live. The project's 2026-07-23 decision to keep a strict
     * MAXIMUM floor governs the tradeoff; the constant is kept (rather than the
     * branch deleted) so the reversal stays greppable.
     */
    private const val COMMON_FREEBIES = 0

    /** Bits credited to the 2nd-and-later member of a word+counter family — the
     *  counter digit itself, log2(10). See [counterStem]. */
    private val BITS_PER_COUNTER = log2(10.0)

    /**
     * A token's stem with its TRAILING digits removed ("cat1" → "cat",
     * "cat" → "cat"), or NULL when nothing survives the trim — a bare number
     * ("42", "2024") or a punctuation-only token, which [normalizeWord] has
     * already reduced to "". Two or more DISTINCT tokens sharing a NON-NULL stem
     * are a counter family. A genuine diceware phrase never produces one: its
     * words differ in letters, not in a trailing digit.
     *
     * The null is load-bearing, not tidiness. While the empty stem was a
     * MATCHABLE key, any two DISTINCT stem-less tokens formed a bogus "family"
     * (a bare number and another number, or a number and a punctuation token):
     * "correct 2024 horse 1999 battery staple" collided its two unrelated
     * numbers, discounted the second to [BITS_PER_COUNTER] and scored 67.95 —
     * a FALSE REJECT of six genuinely distinct tokens worth 77.55, with the char
     * model (~160 bits) too high to rescue it. Direction matters: the collision
     * could only ever LOWER an estimate, so it was an availability defect, never
     * a floor bypass. The genuine target ("cat1 cat2 cat3 …") shares a non-empty
     * stem and is unaffected — CredentialPolicyTest pins both halves.
     */
    private fun counterStem(w: String): String? =
        w.trimEnd { it.isDigit() }.takeIf { it.isNotEmpty() }

    // -----------------------------------------------------------------------
    // Numeric-token patterns (2026-07-31).
    //
    // THE GAP. Six 4-digit groups ("2024 1999 1776 1492 1865 1969",
    // "1990 1991 1992 1993 1994 1995") cleared the 70-bit MAXIMUM floor: the word
    // model saw six distinct non-common, non-category, stem-less tokens (77.55) and
    // the despaced char model credited log2(10) per digit over 22 non-predictable
    // steps (73.08), so min() returned 73.08 — for input carrying ~10-30 real bits.
    // Re-enabling the same-class-run discount on the despaced path would catch it,
    // but that discount is OFF there deliberately: it would false-reject
    // "cat dog fox pig cow hen" (18 lowercase chars → ~44.7 bits). The near-tiling
    // collapse does not reach either vector (their best period-4 match rates are
    // 0.75 and 0.25, under NEAR_TILING_MATCH). So the fix is in the WORD model,
    // where the two shapes are actually distinguishable.
    //
    // BOTH rules only ever LOWER the word model, and estimateBits() returns
    // min(word, char) — so nothing that failed the floor before can start passing.
    // The change is monotone-decreasing by construction.
    // -----------------------------------------------------------------------

    /** A non-empty run of ASCII digits (on a NORMALIZED token, so "2024!"
     *  and "1,990" have already lost their punctuation). Unicode digits are
     *  deliberately NOT numbers here: they cannot be parsed by [String.toLongOrNull]
     *  and excluding them fails toward NO penalty, the safe direction. NOTE the
     *  isNotEmpty guard — a punctuation-only token normalizes to "" and `"".all{}`
     *  is vacuously true, which would make it a "number". */
    private fun isAsciiNumber(w: String): Boolean =
        w.isNotEmpty() && w.all { it in '0'..'9' }

    /** A 4-digit number in [1000, 2999] — the shape of every year a human
     *  reaches for (birth year, this year, a historic date). */
    private fun isYearShaped(w: String): Boolean =
        w.length == 4 && isAsciiNumber(w) && (w[0] == '1' || w[0] == '2')

    /** The exact counting bound on ONE year — log2(2999 - 1000 + 1). Not a
     *  guessed penalty: a UNIFORMLY random year really does carry this much, which is
     *  why a phrase of 7+ independent years still passes (and should). Six carry
     *  65.79 bits, under the floor; the real ones carry far less than the bound. */
    private val BITS_PER_YEAR = log2(2000.0)

    /**
     * How many year-shaped tokens make a "run". Three, NOT two, and the
     * rule additionally requires that at most ONE of the phrase's numbers is not
     * year-shaped. Both conditions exist to protect a user who types genuinely
     * RANDOM 4-digit groups, the one input this rule could wrongly reject:
     *
     *  - a random 4-digit group lands in [1000, 2999] only 20% of the time, so
     *    "all (or all but one) of them do" is itself the evidence they were chosen
     *    as years — P(fire) on six random groups is 0.2^6 + 6·0.2^5·0.8 ≈ 0.16%,
     *    and that user simply adds a seventh group (the live meter says so);
     *  - the 3-token minimum keeps "correct 2024 horse 1999 battery staple" at its
     *    full 77.55 bits. That phrase is a pinned regression vector — the counter-family
     *    empty-stem collision already false-rejected it once, and this must not
     *    reintroduce that by another route.
     */
    private const val MIN_YEAR_RUN = 3

    /** Tokens needed for an arithmetic run. Two numbers ALWAYS form one
     *  trivially, so the minimum is three; three random 4-digit groups agree on a
     *  step with probability ~1e-4, which is why this can be applied with no
     *  year-shape or magnitude restriction at all.
     *
     *  MEASURED CONSEQUENCE (2026-07-31): that ~1e-4 is a real
     *  false-reject, not a theoretical one. A 300k-trial Monte Carlo over
     *  "3 random words + 3 random 4-digit numbers" produced 13 pass→fail flips
     *  (0.0043%) — e.g. `0054 1989 3924 copper meadow ladder`, where the numbers
     *  happen to share a step of 1935 (77.550 → 58.344). THIS rule is the cause,
     *  not the year cap, which measured 0.0000% false rejects in isolation in the
     *  same run. It is inherent to an output-only heuristic: a coincidental
     *  progression is indistinguishable from a chosen one. Accepted because it
     *  fires only at provisioning/rotation — never at unlock, so it can never lock
     *  anyone out — and the live entropy meter shows the user the shortfall
     *  immediately. Do not "fix" it by weakening the rule; the deliberate
     *  `1990 1991 1992 …` case it exists to catch is far more likely than the
     *  coincidence. */
    private const val MIN_PROGRESSION_RUN = 3

    /**
     * Indices into [normalized] of every token that is the SECOND OR
     * LATER member of a maximal run of ≥ [MIN_PROGRESSION_RUN] consecutive numeric
     * tokens with a constant successive difference ("1990 1991 1992 1993 1994 1995",
     * "10 20 30 40 50 60"). Structurally the same claim [counterStem] makes about
     * "cat1 cat2 cat3": the run is one starting value plus a step, so only the first
     * member is an independent choice.
     *
     * This is what stops the obvious escape from the year rule — a user rejected at
     * six consecutive years appending a seventh. Seven years capped at
     * [BITS_PER_YEAR] alone would score 76.76 and PASS; as a progression they score
     * 30.9. Non-numeric tokens are skipped, not run-breaking, so the numbers in
     * "correct 2024 horse 2025 battery 2026" are still seen as the run they are.
     */
    private fun numericProgressionMembers(normalized: List<String>): Set<Int> {
        val positions = ArrayList<Int>()
        val values = ArrayList<Long>()
        for (i in normalized.indices) {
            val w = normalized[i]
            if (!isAsciiNumber(w)) continue
            // Digits-only, so never negative; a token too long for Long (or the
            // 256-char cap's worth of digits) yields null and is simply not a
            // progression candidate. Differences below therefore cannot overflow.
            val v = w.toLongOrNull() ?: continue
            positions.add(i)
            values.add(v)
        }
        if (values.size < MIN_PROGRESSION_RUN) return emptySet()
        val collapsed = HashSet<Int>()
        var start = 0
        while (start < values.size - 1) {
            val step = values[start + 1] - values[start]
            var end = start + 1
            while (end + 1 < values.size && values[end + 1] - values[end] == step) end++
            if (end - start + 1 >= MIN_PROGRESSION_RUN) {
                for (k in start + 1..end) collapsed.add(positions[k])
            }
            // Maximal runs overlap by one element (the last member of this run may
            // start the next), and end > start always, so this terminates.
            start = end
        }
        return collapsed
    }

    /**
     * A small, fully enumerable set a human reaches for when asked for
     * "six different words". [bitsPerMember] is log2(set size) — the true upper
     * bound on one draw — and is applied only when a phrase draws TWO OR MORE
     * members of the same category (see [wordModelBits]).
     */
    private enum class ClosedCategory(val bitsPerMember: Double) {
        DIGIT_WORD(log2(21.0)),      // zero..twenty (English)
        LOCALIZED_DIGIT_WORD(log2(213.0)),  // 0..~20 across the 12 app locales, pruned — see LOCALIZED_DIGIT_WORDS
        // Rung D (2026-11-10, dynamic report fix #2): the English closed categories below,
        // localized to the 12 app locales (sv de fr es nb da fi ar fa so ru mk) exactly as
        // the numbers were (Rung C), with the same homograph pruning. bitsPerMember =
        // log2(merged pruned set size); only a RUN of ≥ 2 members is capped. Monotone-
        // decreasing. See the LOCALIZED_* sets (generated by locdata/merge.py).
        LOCALIZED_WEEKDAY(log2(195.0)),
        LOCALIZED_MONTH(log2(258.0)),
        LOCALIZED_COLOUR(log2(465.0)),
        LOCALIZED_COMPASS(log2(122.0)),
        LOCALIZED_FAMILY(log2(229.0)),
        WEEKDAY(log2(7.0)),
        MONTH(log2(12.0)),
        NATO(log2(26.0)),
        COLOUR(log2(17.0)),
        PLANET(log2(9.0)),
        SINGLE_LETTER(log2(26.0)),
    }

    /** The [ClosedCategory] [w] belongs to, or null. [w] must be normalized. */
    private fun closedCategoryOf(w: String): ClosedCategory? = when {
        w.isEmpty() -> null
        w.length == 1 && w[0] in 'a'..'z' -> ClosedCategory.SINGLE_LETTER
        w in DIGIT_WORDS -> ClosedCategory.DIGIT_WORD
        w in LOCALIZED_DIGIT_WORDS -> ClosedCategory.LOCALIZED_DIGIT_WORD
        w in LOCALIZED_WEEKDAYS -> ClosedCategory.LOCALIZED_WEEKDAY
        w in LOCALIZED_MONTHS -> ClosedCategory.LOCALIZED_MONTH
        w in LOCALIZED_COLOURS -> ClosedCategory.LOCALIZED_COLOUR
        w in LOCALIZED_COMPASS -> ClosedCategory.LOCALIZED_COMPASS
        w in LOCALIZED_FAMILY -> ClosedCategory.LOCALIZED_FAMILY
        w in WEEKDAYS -> ClosedCategory.WEEKDAY
        w in MONTHS -> ClosedCategory.MONTH
        w in NATO_ALPHABET -> ClosedCategory.NATO
        w in COLOURS -> ClosedCategory.COLOUR
        w in PLANETS -> ClosedCategory.PLANET
        else -> null
    }

    private val DIGIT_WORDS = setOf(
        "zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine",
        "ten", "eleven", "twelve", "thirteen", "fourteen", "fifteen", "sixteen",
        "seventeen", "eighteen", "nineteen", "twenty",
    )

    // Rung C (2026-11-09, dynamic passphrase test): "count to six in your OWN language".
    // The number words 0..~20 of the 12 app locales (sv de fr es nb da fi ar fa so ru mk),
    // so a localized counting run collapses to log2(set size) per member exactly the way the
    // English DIGIT_WORDS run does — and only on a RUN of >= 2 members in the phrase; a LONE
    // localized number keeps full diceware credit (a genuine roll may produce one).
    // PRUNED (generated by scripts/passphrase-adversary/gen-localized-numbers.py from the
    // localization-lead data): per-locale article / everyday-word homographs are removed
    // (sv en/ett, fr un/une, mk еден, ru один, fa یک, ar واحد, …), as are <=2-char LATIN
    // tokens (to, ni, en, ti — cross-language collisions) and the English-word collisions
    // the data flagged (fire=4 nb/da, once=11 es, elf=11 de; sex/six/zero are already
    // English). Non-Latin short tokens (Cyrillic / Arabic / Persian) are KEPT — they cannot
    // collide with a Latin-script passphrase. Both the diacritic and the ascii-folded
    // spelling are members because normalizeWord keeps diacritics. bitsPerMember is
    // log2(size); like every closed-category rule this only ever LOWERS the word model, so it
    // is monotone-decreasing — nothing that failed the floor before can now pass.
    private val LOCALIZED_DIGIT_WORDS = setOf(
        "acht", "achtzehn", "afar", "arton", "atta", "atte",
        "atten", "catorce", "cero", "cinco", "cinq", "cuatro",
        "deux", "diecinueve", "dieciocho", "dieciseis", "diecisiete", "dieciséis",
        "diez", "dix", "dixhuit", "dixneuf", "dixsept", "doce",
        "dos", "douze", "drei", "dreizehn", "eber", "eins",
        "elleve", "elva", "fem", "femten", "femton", "fjorten",
        "fjorton", "funf", "funfzehn", "fyra", "fünf", "fünfzehn",
        "huit", "kahdeksan", "kahdeksantoista", "kaksi", "kaksikymmenta", "kaksikymmentä",
        "kaksitoista", "kolme", "kolmetoista", "kow", "kuusi", "kuusitoista",
        "kymmenen", "laba", "labaatan", "lix", "nelja", "neljatoista",
        "neljä", "neljätoista", "neuf", "neun", "neunzehn", "nio",
        "nitten", "nitton", "noll", "nolla", "nueve", "nul",
        "null", "ocho", "onze", "otte", "quatorze", "quatre",
        "quince", "quinze", "saddex", "sagaal", "sechs", "sechzehn",
        "seis", "seitseman", "seitsemantoista", "seitsemän", "seitsemäntoista", "seize",
        "seks", "seksten", "sept", "sexton", "shan", "siddeed",
        "sieben", "siebzehn", "siete", "sifir", "sju", "sjutton",
        "sytten", "syv", "tio", "tjue", "tjugo", "toban",
        "toddoba", "tolv", "tre", "trece", "treize", "tres",
        "tretten", "tretton", "trois", "tva", "två", "tyve",
        "veinte", "vier", "vierzehn", "viisi", "viisitoista", "vingt",
        "yhdeksan", "yhdeksantoista", "yhdeksän", "yhdeksäntoista", "yksi", "yksitoista",
        "zehn", "zwanzig", "zwei", "zwolf", "zwölf", "zéro",
        "åtta", "åtte", "восемнадцать", "восемь", "два", "двадцать",
        "дваесет", "дванаесет", "две", "двенадцать", "девет", "деветнаесет",
        "девятнадцать", "девять", "десет", "десять", "единаесет", "ноль",
        "нула", "нуль", "одиннадцать", "одна", "одно", "осум",
        "осумнаесет", "пет", "петнаесет", "пятнадцать", "пять", "седум",
        "седумнаесет", "семнадцать", "семь", "три", "тринадцать", "тринаесет",
        "четири", "четиринаесет", "четыре", "четырнадцать", "шеснаесет", "шест",
        "шестнадцать", "шесть", "أربعة", "اثنان", "اثنين", "بیست",
        "تسعة", "ثلاثة", "ثمانية", "خمسة", "ده", "دو",
        "دوازده", "سبعة", "ستة", "سه", "سیزده", "شانزده",
        "شش", "صفر", "عشرة", "عشرون", "عشرين", "نوزده",
        "هجده", "هشت", "هفت", "هفده", "پانزده", "پنج",
        "چهار", "چهارده", "یازده",
    )

    // Rung D localized closed-category sets (2026-11-10, dynamic report fix #2),
    // generated by scripts/passphrase-adversary/locdata/merge.py: weekday / month /
    // colour / compass / kinship terms across the 12 app locales, homograph-pruned and
    // made disjoint from each other and the English sets. Both diacritic and ascii-folded
    // spellings are members (normalizeWord keeps diacritics). Capped only on a RUN of >=2.
    private val LOCALIZED_WEEKDAYS = setOf(
        "arbacada", "arbaco", "axad", "axadda", "dienstag", "dienstags", "dimanche", "dimanches",
        "dom", "domingo", "domingos", "donnerstag", "donnerstags", "fredag", "fredagar",
        "fredagen", "fredager", "freitag", "freitags", "isniin", "isniinta", "jeudi", "jeudis",
        "jimcaha", "jimco", "jue", "jueves", "keskiviikko", "keskiviikkoa", "keskiviikkoisin",
        "keskiviikkona", "khamiis", "khamiista", "lauantai", "lauantaina", "lauantaisin",
        "lauantaita", "loerdag", "loerdagar", "loerdagen", "loerdager", "lordag", "lordagar",
        "lordagen", "lordager", "lundi", "lundis", "lunes", "lördag", "lördagar", "lördagen",
        "lørdag", "lørdagen", "lørdager", "maanantai", "maanantaina", "maanantaisin",
        "maanantaita", "maandag", "maandagar", "maandagen", "mandag", "mandagar", "mandagen",
        "mandager", "mardi", "mardis", "martes", "mercredi", "mercredis", "miercoles", "mittwoch",
        "mittwochs", "miércoles", "montag", "montags", "måndag", "måndagar", "måndagen", "onsdag",
        "onsdagar", "onsdagen", "onsdager", "perjantai", "perjantaina", "perjantaisin",
        "perjantaita", "sab", "sabado", "sabados", "sabti", "sabtida", "samedi", "samedis",
        "samstag", "samstags", "soendag", "soendagar", "soendagen", "soendager", "sondag",
        "sondagar", "sondagen", "sondager", "sonnabend", "sonnabends", "sonntag", "sonntags",
        "sunnuntai", "sunnuntaina", "sunnuntaisin", "sunnuntaita", "sáb", "sábado", "sábados",
        "söndag", "söndagar", "söndagen", "søndag", "søndagen", "søndager", "talaadada", "talaado",
        "tiistai", "tiistaina", "tiistaisin", "tiistaita", "tirsdag", "tirsdagen", "tirsdager",
        "tisdag", "tisdagar", "tisdagen", "torsdag", "torsdagar", "torsdagen", "torsdager",
        "torstai", "torstaina", "torstaisin", "torstaita", "vendredi", "vendredis", "viernes",
        "wochenende", "воскресенье", "вторник", "вторникот", "недела", "неделата", "петок",
        "петокот", "понеделник", "понеделникот", "понедельник", "пятница", "сабота", "саботата",
        "среда", "средата", "суббота", "четверг", "четврток", "четвртокот", "آدینه", "احد",
        "اربعاء", "الأحد", "الأربعاء", "الإثنين", "الاثنين", "الاحد", "الاربعاء", "الثلاثاء",
        "الجمعة", "الخميس", "السبت", "ثلاثاء", "جمعة", "جمعه", "خميس", "دوشنبه", "سبت", "سهشنبه",
        "شنبه", "يومالأحد", "يومالأربعاء", "يومالاثنين", "يومالثلاثاء", "يومالجمعة", "يومالخميس",
        "يومالسبت", "پنجشنبه", "چهارشنبه", "یکشنبه",
    )
    private val LOCALIZED_MONTHS = setOf(
        "abr", "abriil", "abriisha", "abril", "agoostada", "agoosto", "agosto", "aout", "août",
        "aprils", "augusti", "augusts", "avr", "avril", "decembre", "desember", "dezember",
        "dezembers", "dic", "diciembre", "diseembar", "diseembarka", "décembre", "elokuu",
        "elokuun", "elokuussa", "elokuuta", "ene", "enero", "febraayada", "febraayo", "febrero",
        "februar", "februari", "februars", "fevr", "fevrier", "févr", "février", "heinaekuu",
        "heinaekuun", "heinaekuussa", "heinaekuuta", "heinakuu", "heinakuun", "heinakuussa",
        "heinakuuta", "heinäkuu", "heinäkuun", "heinäkuussa", "heinäkuuta", "helmikuu",
        "helmikuun", "helmikuussa", "helmikuuta", "huhtikuu", "huhtikuun", "huhtikuussa",
        "huhtikuuta", "jaenner", "janaayada", "janaayo", "janner", "januar", "januari",
        "januarimaanad", "januarimanad", "januarimånad", "januars", "janv", "janvier", "joulukuu",
        "joulukuun", "joulukuussa", "joulukuuta", "juil", "juillet", "juin", "juli", "julio",
        "julis", "juni", "junio", "junis", "juun", "juunka", "jänner", "kesaekuu", "kesaekuun",
        "kesaekuussa", "kesaekuuta", "kesakuu", "kesakuun", "kesakuussa", "kesakuuta", "kesäkuu",
        "kesäkuun", "kesäkuussa", "kesäkuuta", "lokakuu", "lokakuun", "lokakuussa", "lokakuuta",
        "luuliyada", "luuliyo", "maajada", "maajo", "maaliskuu", "maaliskuun", "maaliskuussa",
        "maaliskuuta", "maarsada", "maarso", "maerz", "maerzen", "mais", "maj", "marraskuu",
        "marraskuun", "marraskuussa", "marraskuuta", "marts", "marz", "marzen", "marzo", "märz",
        "märzen", "nofembar", "nofembarka", "novembers", "novembre", "noviembre", "octobre",
        "octubre", "oktober", "oktobers", "oktoobar", "oktoobarka", "sebtembar", "sebtembarka",
        "septembers", "septembre", "septiembre", "set", "setiembre", "syyskuu", "syyskuun",
        "syyskuussa", "syyskuuta", "tammikuu", "tammikuun", "tammikuussa", "tammikuuta",
        "toukokuu", "toukokuun", "toukokuussa", "toukokuuta", "август", "августа", "апрель",
        "апреля", "април", "декабрь", "декабря", "декември", "июль", "июля", "июнь", "июня", "май",
        "март", "марта", "мая", "мај", "ноември", "ноябрь", "ноября", "октомври", "октябрь",
        "октября", "сентябрь", "сентября", "септември", "февраль", "февраля", "февруари", "январь",
        "января", "јануари", "јули", "јуни", "آب", "آبان", "آذار", "آذر", "آوریل", "أبريل",
        "أغسطس", "أكتوبر", "أيار", "أيلول", "إبريل", "اب", "ابريل", "اذار", "اردیبهشت", "اسفند",
        "اغسطس", "اكتوبر", "امرداد", "اوت", "ايار", "ايلول", "اکتبر", "بهمن", "تشرين",
        "تشرينالأول", "تشرينالثاني", "تموز", "تیر", "حزيران", "خرداد", "دجنبر", "دسامبر", "ديسمبر",
        "دی", "سبتمبر", "سپتامبر", "شباط", "شتنبر", "شهریور", "غشت", "فبراير", "فروردین", "فوریه",
        "كانون", "كانونالأول", "كانونالثاني", "مارس", "ماي", "مايو", "مرداد", "مه", "مهر", "می",
        "نوامبر", "نوفمبر", "نونبر", "نيسان", "يناير", "يوليه", "يوليو", "يوليوز", "يونيه",
        "يونيو", "ژانویه", "ژوئن", "ژوئیه",
    )
    private val LOCALIZED_COLOURS = setOf(
        "amarilla", "amarillas", "amarillo", "amarillos", "anil", "argent", "argente", "argentee",
        "argenté", "argentée", "azul", "azules", "añil", "beis", "bla", "blaa", "blaaa", "blaat",
        "blaatt", "blanc", "blanca", "blancas", "blanche", "blanches", "blanco", "blancos",
        "blancs", "blat", "blatt", "blau", "blaue", "blaues", "bleu", "bleue", "bleues", "bleus",
        "blå", "blåa", "blåt", "blått", "braun", "braune", "brun", "bruna", "brune", "brunes",
        "bruns", "brunt", "buluug", "bunni", "caddaan", "cagaar", "cas", "cawl", "celeste",
        "celestes", "dahab", "dorada", "dorado", "dore", "doree", "doré", "dorée", "gelb", "gelbe",
        "gelbes", "gra", "graa", "graaa", "graat", "graatt", "grat", "gratt", "grau", "graue",
        "graues", "gris", "grise", "grises", "groen", "groena", "groenn", "groenne", "groent",
        "gron", "grona", "gronn", "gronne", "gront", "gruen", "gruene", "gruenes", "grun", "grune",
        "grunes", "grå", "gråa", "gråt", "grått", "grön", "gröna", "grönt", "grøn", "grønn",
        "grønne", "grønt", "grün", "grüne", "grünes", "guduud", "gul", "gula", "guld", "gule",
        "gull", "gult", "harmaa", "harmaan", "harmaata", "hopea", "huruud", "hvid", "hvide",
        "hvidt", "hvit", "hvite", "hvitt", "jaale", "jaune", "jaunes", "keltainen", "keltaisen",
        "keltaiset", "keltaista", "kulta", "lila", "lilla", "lyserod", "lyserode", "lyseroed",
        "lyseroede", "lyserød", "lyserøde", "madow", "marron", "marrones", "marrons", "marrón",
        "morada", "moradas", "morado", "morados", "musta", "mustaa", "mustan", "mustat", "naranja",
        "naranjas", "negra", "negras", "negro", "negros", "noir", "noire", "noires", "noirs",
        "oranges", "oransje", "oranssi", "oranssia", "oranssin", "oro", "plata", "plateada",
        "plateado", "pourpre", "pourpres", "punainen", "punaisen", "punaiset", "punaista",
        "purppura", "purpura", "púrpura", "rod", "roda", "rode", "rodt", "roed", "roeda", "roede",
        "roedt", "roett", "roja", "rojas", "rojo", "rojos", "rosa", "rosane", "rosas", "rosor",
        "rote", "rotes", "rott", "rouges", "ruskea", "ruskeaa", "ruskean", "röd", "röda", "rött",
        "rød", "røde", "rødt", "schwarz", "schwarze", "schwarzes", "silber", "sininen", "sinisen",
        "siniset", "sinista", "sinistae", "sinistä", "soelv", "solv", "sorte", "svart", "svarta",
        "svarte", "sølv", "turquesa", "turquesas", "vaaleanpunainen", "vaaleanpunaisen",
        "valkoinen", "valkoisen", "valkoiset", "valkoista", "verde", "verdes", "vert", "verte",
        "vertes", "verts", "vihrea", "vihreaa", "vihreae", "vihreaeae", "vihreaen", "vihreaet",
        "vihrean", "vihreat", "vihreä", "vihreän", "vihreät", "vihreää", "violeta", "violetas",
        "violets", "violett", "violette", "violettes", "violetti", "violettia", "vit", "vita",
        "vitt", "weiss", "weisse", "weisses", "weiß", "weiße", "weißes", "бел", "бела", "белая",
        "бели", "бело", "белое", "белые", "белый", "виолетов", "виолетова", "виолетови",
        "виолетово", "голубая", "голубое", "голубой", "голубые", "желтая", "желтое", "желтые",
        "желтый", "жолт", "жолта", "жолти", "жолто", "жёлтая", "жёлтое", "жёлтые", "жёлтый",
        "зелен", "зелена", "зеленая", "зелени", "зелено", "зеленое", "зеленые", "зеленый",
        "зелёная", "зелёное", "зелёные", "зелёный", "златен", "златна", "златни", "златно",
        "золотая", "золотое", "золотой", "золотые", "кафеав", "кафеава", "кафеави", "кафеаво",
        "коричневая", "коричневое", "коричневые", "коричневый", "красная", "красное", "красные",
        "красный", "оранжевая", "оранжевое", "оранжевые", "оранжевый", "портокалов", "портокалова",
        "портокалови", "портокалово", "розов", "розова", "розовая", "розови", "розово", "розовое",
        "розовые", "розовый", "серая", "серебряная", "серебряное", "серебряные", "серебряный",
        "серое", "серые", "серый", "сив", "сива", "сиви", "сиво", "син", "сина", "синее", "сини",
        "синие", "синий", "сино", "синяя", "сребрен", "сребрена", "сребрени", "сребрено",
        "фиолетовая", "фиолетовое", "фиолетовые", "фиолетовый", "црвен", "црвена", "црвени",
        "црвено", "црн", "црна", "црни", "црно", "черная", "черное", "черные", "черный", "чёрная",
        "чёрное", "чёрные", "чёрный", "آبی", "أبيض", "أحمر", "أخضر", "أرجواني", "أزرق", "أسود",
        "أصفر", "ابيض", "احمر", "اخضر", "ارغوانی", "ازرق", "اسود", "اصفر", "الأبيض", "الأحمر",
        "الأخضر", "الأرجواني", "الأزرق", "الأسود", "الأصفر", "الابيض", "الاحمر", "الاخضر",
        "الارجواني", "الازرق", "الاسود", "الاصفر", "البرتقالي", "البنفسجي", "البني", "الذهبي",
        "الرمادي", "الزهري", "الفضي", "الوردي", "برتقالي", "بنفسجي", "بنفش", "بني", "بيضاء",
        "حمراء", "خاکستری", "خضراء", "ذهبي", "رمادي", "زرد", "زرشکی", "زرقاء", "زهري", "سبز",
        "سرخ", "سرمهای", "سفید", "سوداء", "سیاه", "صفراء", "صورتی", "طلایی", "طوسی", "فضي",
        "فیروزهای", "قرمز", "قهوهای", "مشکی", "نارنجی", "نقرهای", "وردي", "کبود", "یشمی",
    )
    private val LOCALIZED_COMPASS = setOf(
        "bari", "etela", "etelae", "etelä", "galbeed", "ita", "itae", "itä", "kaakko", "koillinen",
        "koonfur", "koonfurbari", "koonfurgalbeed", "laensi", "lansi", "lounas", "luode", "länsi",
        "norden", "nordest", "nordeste", "nordoest", "nordost", "nordosten", "nordouest",
        "nordvaest", "nordvast", "nordvest", "nordväst", "nordwesten", "nordøst", "noreste",
        "noroccidente", "noroeste", "norr", "norte", "oest", "oeste", "oester", "ost", "osten",
        "oster", "ouest", "pohjoinen", "soder", "soeder", "soer", "soeroest", "soervest", "sor",
        "sorost", "sorvest", "suden", "sudest", "sudeste", "sudoeste", "sudosten", "sudouest",
        "sudwesten", "sued", "sueden", "suedosten", "suedwesten", "sureste", "suroeste", "syd",
        "sydoest", "sydost", "sydvaest", "sydvast", "sydvest", "sydväst", "sydøst", "söder", "sør",
        "sørvest", "sørøst", "süden", "südosten", "südwesten", "vaest", "vaester", "vast",
        "vaster", "väst", "väster", "waqooyi", "waqooyibari", "waqooyigalbeed", "westen", "öst",
        "öster", "øst", "восток", "запад", "исток", "север", "северовосток", "северозапад",
        "североисток", "юг", "юговосток", "югозапад", "југ", "југозапад", "југоисток", "جنوب",
        "جنوبشرق", "جنوبشرقي", "جنوبشرقی", "جنوبغرب", "جنوبغربي", "جنوبغربی", "شرق", "شمال",
        "شمالشرق", "شمالشرقي", "شمالشرقی", "شمالغرب", "شمالغربي", "شمالغربی", "غرب",
    )
    private val LOCALIZED_FAMILY = setOf(
        "aabe", "aabo", "abti", "abuela", "abuelita", "abuelito", "abuelo", "adeer", "aeiti",
        "aiti", "aviomies", "awoowe", "ayeeyo", "bedstemor", "bestefar", "bestemor", "bror",
        "bruder", "cunug", "datter", "dotter", "eeddo", "ehefrau", "ehemann", "ektemann", "eltern",
        "enfant", "eno", "epouse", "epoux", "esposa", "esposo", "fader", "farbror", "farfar",
        "farmor", "femme", "fille", "foeraelder", "foeraeldrar", "foraeldre", "foralder",
        "foraldrar", "forelder", "foreldre", "forældre", "frau", "frere", "fru", "frère",
        "förälder", "föräldrar", "gabadh", "gabar", "grandmere", "grandmère", "grandpere",
        "grandpère", "grossmutter", "grossvater", "großmutter", "großvater", "habaryar", "hermana",
        "hermano", "hija", "hijo", "hooyo", "hustru", "ilmo", "isa", "isae", "isi", "isoaeiti",
        "isoaiti", "isoisa", "isoisae", "isoisä", "isoäiti", "isä", "kone", "lapsi", "madre",
        "maman", "mamie", "mand", "marido", "meme", "mies", "moder", "morbror", "morfar", "mormor",
        "moster", "mujer", "mummo", "mutter", "mutti", "mémé", "naag", "nieta", "nieto", "nin",
        "nino", "niño", "oma", "oncle", "onkel", "opa", "padre", "papy", "pepe", "pere", "poika",
        "père", "pépé", "schwester", "seda", "sedae", "sedä", "seta", "setae", "setä", "sisar",
        "sisko", "soen", "soenn", "soester", "soeur", "sohn", "sonn", "soster", "syster", "sønn",
        "søster", "sœur", "taeti", "tante", "tati", "tochter", "tytaer", "tytar", "tytär", "täti",
        "ukki", "vaimo", "vanhemmat", "vanhempi", "vater", "vati", "veli", "waalid", "walaal",
        "wiil", "xaas", "äiti", "épouse", "époux", "баба", "бабушка", "брат", "вујко", "дед",
        "дедо", "дедушка", "дете", "дочка", "дочь", "дядя", "жена", "маж", "мама", "мать", "мајка",
        "муж", "отец", "папа", "ребенок", "ребёнок", "родител", "родитель", "сестра", "сопруг",
        "сопруга", "сын", "татко", "тетка", "тетя", "тётя", "чичко", "ќерка", "أب", "أخ", "أخت",
        "أم", "ابن", "ابنة", "اخ", "اخت", "ام", "بابا", "برادر", "بنت", "جد", "جدة", "خال", "خالة",
        "خاله", "خواهر", "دایی", "دختر", "زن", "زوج", "زوجة", "شوهر", "عم", "عمة", "عمه", "عمو",
        "مادر", "مادربزرگ", "ماما", "مامان", "همسر", "والد", "والدة", "پدر", "پدربزرگ", "پسر",
    )

    private val WEEKDAYS = setOf(
        "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday",
    )

    private val MONTHS = setOf(
        "january", "february", "march", "april", "may", "june", "july", "august",
        "september", "october", "november", "december",
    )

    // 26 concepts; both spellings of the ambiguous ones are members, but
    // ClosedCategory.NATO's bit budget stays log2(26).
    private val NATO_ALPHABET = setOf(
        "alpha", "alfa", "bravo", "charlie", "delta", "echo", "foxtrot", "golf",
        "hotel", "india", "juliet", "juliett", "kilo", "lima", "mike", "november",
        "oscar", "papa", "quebec", "romeo", "sierra", "tango", "uniform", "victor",
        "whiskey", "whisky", "xray", "yankee", "zulu",
    )

    private val COLOURS = setOf(
        "red", "orange", "yellow", "green", "blue", "indigo", "violet", "purple",
        "black", "white", "grey", "gray", "brown", "pink", "cyan", "magenta",
        "gold", "silver",
    )

    private val PLANETS = setOf(
        "mercury", "venus", "earth", "mars", "jupiter", "saturn", "uranus",
        "neptune", "pluto",
    )

    private fun charModelBits(token: String, discountSameClassRuns: Boolean): Double {
        // Character classes by UNICODE category, not ASCII range. Until 2026-11-08 every
        // non-ASCII character counted as a SYMBOL (+33 to the alphabet, and a class change
        // that broke the same-class-run discount), so "dugamladufriadufjällhöganord" — a
        // national-anthem line typed without spaces — scored ~100 bits and was accepted for
        // MAXIMUM while its ASCII twin scored 68 and was refused. ä, ö, å, é, ß are letters
        // of the same alphabet as a..z: no symbol credit, and the run stays intact. Letters
        // without case (Arabic, Persian, …) join the lowercase class for the same reason;
        // the alphabet is still credited at 26 — a conservative lower bound on purpose.
        val classes = token.map { charClass(it) }.toSet()
        var charset = 0
        if (0 in classes) charset += 26
        if (1 in classes) charset += 26
        if (2 in classes) charset += 10
        // Everything else (symbols, punctuation) — credit a common symbol set.
        if (3 in classes) charset += 33
        val perChar = log2(max(charset, 1).toDouble())
        if (token.length <= 1) return perChar * token.length.toDouble()
        // Discount RUNS of predictable steps. A step is predictable
        // when the char follows its predecessor by a repeat, an alphabet/digit
        // sequence, or a keyboard-row adjacency — but only the 2nd-and-later steps of
        // a CONSECUTIVE run count as guessable, so a keyboard walk
        // ("qwertyuiopasdfgh") or a sequence ("abcdefghijklmnop" / "1234567890abcdef"
        // / "aaaaaaaa…") collapses to a handful of independent symbols, while an
        // otherwise-strong token with an INCIDENTAL adjacent pair ("aB3!xY9$kQ7%" has
        // a→b and x→y) keeps full credit.
        //
        // Additionally, when [discountSameClassRuns], a
        // neighbour of the SAME character class (both lower / upper / digit / symbol)
        // is a repeated unit from one alphabet → HALF credit. A single-class token
        // ("sunshineforever") or a long same-class run inside a mixed token
        // ("Sunshine2024!" → "unshine", "2024") then cannot clear the floor on length
        // alone, while a genuinely diverse token whose classes change nearly every
        // character ("aB3!xY9$kQ7%") keeps full credit. A fully guessable
        // predictable-run tail still wins at zero credit.
        var effectiveLength = discountedEffectiveLength(token, discountSameClassRuns)
        // A token that is an exact tiling of a unit
        // (e.g. period-2 "a1a1a1…", whose neighbours are individually NON-predictable
        // so the run penalty above can't see them) carries only ~one unit of entropy —
        // collapse the effective length to the period. The period search is NO LONGER
        // capped at 4: the common "repeat a base password to reach a length minimum"
        // pattern ("correcthorsecorrecthorse" p=12, "Secret1!Secret1!" p=8,
        // "hunter2hunter2" p=7) is an exact tiling with period 5-12+ and must collapse
        // too. Applied on BOTH paths (a spaced "a1 a1 a1 …" despaces to a period-2
        // tiling); real words/phrases are not exact tilings, so this never false-rejects.
        //
        // The collapse credits the DISCOUNTED
        // effective length of ONE period, not its raw character count — the raw count
        // re-inflates any base whose own same-class runs already discounted it below
        // the floor (e.g. an 11-char mixed base doubled to 22 chars previously scored
        // period.toDouble()=11 full symbols, undoing the exact discount that made the
        // single base fail on its own). Re-running the same discount over just the
        // unit means a doubled REJECTED base stays rejected, while a base that was
        // already strong on its own (few/no same-class runs) is barely affected.
        val period = repetitionPeriod(token)
        if (period != null) {
            val unitLength = discountedEffectiveLength(token.substring(0, period), discountSameClassRuns)
            effectiveLength = minOf(effectiveLength, unitLength)
        }
        // A base password repeated with a SMALL edit — a bumped counter
        // ("Secret1!Secret2!") or a flipped separator — is not an EXACT tiling but still
        // carries ~one unit of entropy. Collapse on a high-confidence NEAR tiling too.
        // Restricted to the single-token path (discountSameClassRuns) so a coincidental
        // near-period can never collapse the min(word,char) term of a genuine multi-word
        // phrase; genuinely strong single tokens are not near-periodic and keep full
        // credit. Only bother when no exact period was already found.
        if (discountSameClassRuns && period == null) {
            val approx = approxRepetitionPeriod(token)
            if (approx != null) {
                val unitLength = discountedEffectiveLength(token.substring(0, approx), discountSameClassRuns)
                effectiveLength = minOf(effectiveLength, unitLength)
            }
        }
        return perChar * effectiveLength
    }

    /** Runs the predictable-step-run + same-class-run discount (see [charModelBits])
     *  over [s] in isolation and returns the resulting effective length. Factored out
     *  of [charModelBits] so the tiling collapse can
     *  credit a repeated unit's DISCOUNTED entropy instead of its raw character count —
     *  see the call site for why crediting the raw count over-credits a doubled base. */
    private fun discountedEffectiveLength(s: String, discountSameClassRuns: Boolean): Double {
        if (s.length <= 1) return s.length.toDouble()
        var length = 1.0
        var prevPredictable = false
        for (i in 1 until s.length) {
            val pred = isPredictableStep(s[i - 1], s[i])
            val cls = charClass(s[i])
            length += when {
                pred && prevPredictable -> 0.0                                          // 2nd+ step of a run: guessable
                // A run of same-case LETTERS is natural language until proven otherwise: a
                // phrase or lyric typed without spaces carries ~1.3–1.5 bits per letter
                // (Shannon's estimate for text), not log2(26) ≈ 4.7 and not half of it.
                // 0.3 × 4.7 ≈ 1.4 bits per letter: a concatenated phrase needs ~50 letters
                // to clear 70 bits, so "dugamladufriadufjällhöganord" (28) cannot. A user who
                // really types random letters adds spaces (word model) or a second character
                // class; the live meter shows the effect. Digits and symbols keep 0.5 — their
                // runs are already caught by the predictable-step and period penalties.
                discountSameClassRuns && cls == charClass(s[i - 1]) && cls <= 1 -> LETTER_RUN_CREDIT
                discountSameClassRuns && cls == charClass(s[i - 1]) -> 0.5
                else -> 1.0
            }
            prevPredictable = pred
        }
        return length
    }

    /** Effective-length credit for the 2nd+ letter of a same-case letter run (see above). */
    private const val LETTER_RUN_CREDIT = 0.3

    /** Character class for the same-class-run discount — lowercase or caseless letter /
     *  uppercase letter / digit / other (symbols, punctuation). Unicode-aware: "ä" is a letter,
     *  not a symbol (2026-11-08 fix in [charModelBits]). */
    private fun charClass(c: Char): Int = when {
        c.isUpperCase() -> 1
        c.isLetter() -> 0
        c.isDigit() -> 2
        else -> 3
    }

    /** Smallest period p (1 ≤ p ≤ len/2) for which [token] is an
     *  EXACT whole-string tiling of its first p characters across at least two full
     *  periods, or null if it has none. The old small cap (period ≤ 4) is REMOVED: a
     *  base password repeated to reach a length minimum ("correcthorse"×2, "abcde"×3)
     *  tiles with period 5-12+ and must be caught. Exact (not approximate) tiling keeps
     *  the check from ever firing on a genuinely strong password, which never tiles. */
    private fun repetitionPeriod(token: String): Int? {
        val maxP = token.length / 2
        for (p in 1..maxP) {
            var tiled = true
            for (i in p until token.length) {
                if (token[i] != token[i - p]) { tiled = false; break }
            }
            if (tiled) return p
        }
        return null
    }

    /** Smallest period p (2 ≤ p ≤ len/2, at least two full periods) whose
     *  period-p tiling matches [token] in at least [NEAR_TILING_MATCH] of its compared
     *  positions, or null. Catches a base password repeated with a small edit (a bumped
     *  counter, a changed separator) — NOT an exact tiling but still ~one unit of
     *  entropy. The threshold is deliberately high and the caller runs this ONLY on the
     *  single-token path, so a coincidental near-period can never collapse a genuine
     *  phrase's score (strong non-repeating tokens are not near-periodic). */
    private fun approxRepetitionPeriod(token: String): Int? {
        val maxP = token.length / 2
        for (p in 2..maxP) {
            val compared = token.length - p
            if (compared < p) continue          // require at least two full periods (len ≥ 2p)
            var matches = 0
            for (i in p until token.length) {
                if (token[i] == token[i - p]) matches++
            }
            if (matches >= NEAR_TILING_MATCH * compared) return p
        }
        return null
    }

    /** Minimum fraction of positions that must match a period's tiling for
     *  the NEAR-tiling collapse to fire. High enough that only a base-password repeat
     *  (with at most a small edit) qualifies, never a strong non-repeating token. */
    private const val NEAR_TILING_MATCH = 0.8

    /** True when [cur] is trivially guessable from [prev]: a repeat, an alphabet or
     *  digit step of ±1, or a ±1 neighbour on a QWERTY row (either direction). */
    private fun isPredictableStep(prev: Char, cur: Char): Boolean {
        if (prev == cur) return true
        val p = prev.lowercaseChar()
        val c = cur.lowercaseChar()
        if (p in 'a'..'z' && c in 'a'..'z' && kotlin.math.abs(p - c) == 1) return true
        if (p in '0'..'9' && c in '0'..'9' && kotlin.math.abs(p - c) == 1) return true
        for (row in KEYBOARD_ROWS) {
            val pi = row.indexOf(p)
            if (pi >= 0) {
                val ci = row.indexOf(c)
                if (ci >= 0 && kotlin.math.abs(pi - ci) == 1) return true
            }
        }
        return false
    }

    // Rung H (2026-11-09): US-QWERTY plus the layouts the app's locales actually ship —
    // Nordic (å ä ö), German QWERTZ, French AZERTY, Russian ЙЦУКЕН. Adding rows can only
    // make MORE adjacent pairs predictable, so this is monotone-decreasing: it never turns
    // a refused passphrase into an accepted one, only catches more local keyboard walks.
    private val KEYBOARD_ROWS = listOf(
        "1234567890",
        "qwertyuiop", "asdfghjkl", "zxcvbnm",            // US QWERTY
        "qwertyuiopå", "asdfghjklöä", "zxcvbnm",          // Nordic (sv / nb / da / fi)
        "qwertzuiopü", "asdfghjklöä", "yxcvbnm",          // German QWERTZ
        "azertyuiop", "qsdfghjklm", "wxcvbn",             // French AZERTY
        "йцукенгшщзхъ", "фывапролджэ", "ячсмитьбю",       // Russian ЙЦУКЕН
    )

    // Localized high-frequency / function words (2026-11-10, dynamic report fix #2b),
    // generated by merge.py from the per-locale "common" lists: the non-English analog of
    // COMMON_WORDS, half-credited the same way so an all-function-word phrase in any app
    // locale falls below the floor. Disjoint from the localized closed-category sets.
    private val LOCALIZED_COMMON_WORDS: Set<String> = setOf(
        "aad", "aan", "abajo", "abend", "aber", "adieu", "adiga", "adios", "adiós", "adjo",
        "adjoe", "adjö", "aer", "aften", "ahora", "aina", "alas", "aldri", "aldrig", "alla",
        "alle", "aller", "allerede", "alli", "alltid", "allí", "alors", "als", "altid", "ama",
        "aniga", "annaga", "aqui", "aquí", "arag", "arriba", "att", "auch", "auf", "aus", "aussi",
        "aux", "avec", "avez", "avoir", "avons", "ayaa", "baa", "bajo", "beau", "bei", "bien",
        "bis", "bist", "bitte", "ble", "blev", "bli", "blir", "blive", "bliver", "bon", "bonjour",
        "bonsoir", "bra", "buenas", "bueno", "buenos", "ces", "cet", "cette", "chez", "comme",
        "comment", "como", "cuando", "cusub", "daalig", "daarlig", "daer", "dag", "dalig", "danke",
        "dann", "dans", "dar", "darf", "darlig", "das", "dass", "decir", "deg", "dein", "deja",
        "del", "dem", "denn", "der", "dere", "derecha", "des", "desde", "det", "dhahay", "dhaho",
        "dheer", "dias", "dich", "dig", "din", "dir", "donc", "donde", "dont", "dort", "droite",
        "durch", "där", "dålig", "dårlig", "déjà", "días", "efter", "ehka", "ehkae", "ehkä", "ein",
        "eine", "einem", "einen", "einer", "eivaet", "eivat", "eivät", "ella", "ellas", "elle",
        "eller", "elles", "ellos", "emme", "encore", "ennen", "entre", "eres", "esta", "estamos",
        "estan", "estar", "estas", "estoy", "está", "están", "estás", "etes", "etre", "ett",
        "etta", "ettae", "ette", "etter", "että", "euch", "eux", "faar", "fadlan", "fahan",
        "faire", "fais", "farvel", "fiican", "foer", "foere", "fore", "fra", "fraan", "fran",
        "från", "fuer", "fur", "före", "für", "gaaban", "gammal", "gammel", "garo", "gegen",
        "gennem", "genom", "gjennom", "gracias", "grande", "gross", "groß", "guten", "haa", "habe",
        "haben", "haber", "hacer", "hacia", "hadde", "hade", "haen", "haer", "halla", "hallaa",
        "hallo", "hallå", "haluan", "han", "har", "hast", "hasta", "hatte", "haut", "havde",
        "haye", "hayn", "hei", "hej", "hemos", "hende", "henne", "hidas", "hier", "hinter",
        "hoeger", "hoejre", "hoeyre", "hoger", "hojre", "hola", "hon", "honom", "hoyre", "hun",
        "huomenta", "hur", "hurtig", "hvis", "hvordan", "hyva", "hyvae", "hyvin", "hyvä", "hän",
        "här", "höger", "højre", "høyre", "ich", "ici", "idinka", "ihm", "ihn", "ihr", "ikke",
        "ilman", "ils", "iltaa", "immer", "imow", "inaad", "ingen", "innaga", "inte", "inuu",
        "isaga", "iso", "ist", "iyada", "iyaga", "iyo", "izquierda", "jaelkeen", "jag", "jalkeen",
        "jamais", "jeg", "jer", "jetzt", "jir", "jiraa", "jos", "jälkeen", "kaalay", "kaas", "kan",
        "kann", "kannst", "kanske", "kanskje", "kanssa", "kaunis", "kein", "kiitoksia", "kiitos",
        "klein", "koennen", "konnen", "koska", "kuin", "kuka", "kun", "kunde", "kunne", "kuwaas",
        "kuwan", "kvaell", "kvall", "kveld", "kväll", "kylla", "kyllae", "kyllä", "können",
        "laakiin", "laangsam", "langsam", "langsom", "leh", "les", "leur", "lidt", "lille",
        "links", "lite", "liten", "los", "lui", "långsam", "maa", "maaske", "maaste", "mae",
        "mahadsanid", "malaha", "malo", "maske", "maste", "maya", "med", "meg", "meget", "mein",
        "menen", "menos", "merci", "mes", "mich", "mig", "mihin", "mika", "mikae", "miksi", "mikä",
        "milloin", "min", "mina", "minae", "minä", "mir", "mis", "missa", "missae", "missä",
        "miten", "mitt", "mod", "moi", "moins", "mon", "morgen", "morgon", "muss", "mutta", "muy",
        "mycket", "mye", "myoes", "myos", "myös", "måske", "måste", "naa", "naagra", "naar",
        "nabad", "nach", "nacht", "naekemiin", "naemae", "naer", "nagra", "nakemiin", "nama",
        "nar", "nat", "natt", "neben", "ned", "nei", "nein", "nej", "ner", "neu", "nicht", "nie",
        "niin", "noch", "noches", "noen", "nogen", "nopea", "noqo", "nosotras", "nosotros",
        "notre", "nous", "nouveau", "nuestro", "nuevo", "nunca", "nuo", "nyt", "näkemiin", "nämä",
        "när", "några", "når", "oben", "och", "ocksa", "ocksaa", "också", "oder", "oever", "ogow",
        "ogsa", "ogsaa", "også", "ohne", "oikea", "ole", "olemme", "olen", "olet", "olette", "oli",
        "olla", "ont", "opp", "oss", "oui", "ovat", "paa", "paalla", "paeaellae", "paeivaeae",
        "paha", "paivaa", "paljon", "para", "pardon", "pequena", "pequeno", "pequeño", "perdon",
        "perdón", "pero", "peut", "peutetre", "peutêtre", "pieni", "poder", "por", "porque",
        "pourquoi", "pouvoir", "prendre", "puede", "puedo", "pues", "päivää", "päällä", "qaado",
        "quand", "que", "querer", "qui", "quien", "quiere", "quiero", "quiza", "quizas", "quizá",
        "quizás", "quoi", "qurux", "qué", "rab", "rabaa", "rask", "rechts", "redan", "saa",
        "saber", "sae", "salaan", "salut", "samee", "sameeyaa", "sans", "savoir", "schlecht",
        "schnell", "schoen", "schon", "schön", "sedan", "sehr", "seid", "sein", "seit", "ser",
        "ses", "sida", "sie", "siella", "siellae", "siellä", "siempre", "sii", "sina", "sinae",
        "sind", "sinä", "sisaellae", "sisalla", "sisällä", "sitten", "ska", "skal", "skulle",
        "smuk", "snabb", "snaella", "snalla", "snill", "snälla", "sobre", "sois", "soll", "som",
        "sommes", "somos", "sont", "sous", "stor", "suis", "sus", "svp", "taalla", "taas", "tack",
        "taeaellae", "taemae", "tahay", "tai", "tak", "takk", "tal", "tama", "tambien", "también",
        "tardes", "tehda", "tehdae", "tehdä", "tener", "tengo", "terve", "tes", "tiene", "til",
        "till", "toda", "todo", "todos", "toi", "ton", "toujours", "tous", "tout", "toute",
        "tschuess", "tschuss", "tschüss", "tulee", "tuo", "tus", "tämä", "täällä", "uber", "uden",
        "ueber", "ulkona", "una", "unas", "und", "une", "unos", "uns", "unser", "unten", "unter",
        "upp", "usted", "ustedes", "utan", "uten", "uusi", "vaar", "vacker", "vaehaen", "vaenster",
        "vaer", "vaere", "vahan", "vaikka", "vain", "vais", "vakker", "vamos", "vanha", "vanster",
        "var", "vara", "vas", "vasen", "ved", "venir", "venlig", "venstre", "ver", "vers", "veux",
        "vez", "vid", "viejo", "viel", "viela", "vielae", "vielleicht", "vielä", "vieux", "vil",
        "vill", "ville", "voi", "voin", "voir", "voit", "von", "vont", "vor", "vores", "vosotras",
        "vosotros", "votre", "vouloir", "vous", "voy", "vuestro", "vähän", "vänster", "vår", "vær",
        "være", "waa", "waad", "waan", "waannu", "wanaagsan", "waren", "weil", "wenig", "wenn",
        "werde", "werden", "weyn", "wie", "wir", "wird", "wirst", "wollen", "wuu", "xun", "yahay",
        "yar", "yli", "yloes", "ylos", "ylös", "yoetae", "yota", "yötä", "zum", "zur", "zwischen",
        "êtes", "être", "über", "а", "ако", "бев", "без", "беше", "би", "бидејќи", "благодарам",
        "большой", "будет", "бы", "был", "была", "были", "было", "быть", "в", "вам", "вас", "ваш",
        "веќе", "ви", "видеть", "вие", "во", "вот", "все", "всегда", "всё", "вы", "гледам",
        "говорить", "голем", "да", "дадам", "дать", "дека", "делать", "для", "до", "добар",
        "добрый", "думать", "е", "еве", "его", "ее", "ей", "ему", "если", "есть", "еще", "ещё",
        "её", "же", "за", "зборувам", "здесь", "здраво", "здравствуйте", "знам", "знать", "знаю",
        "и", "идти", "из", "извини", "извините", "или", "им", "има", "имам", "иметь", "иногда",
        "исто", "их", "к", "кај", "кога", "когда", "кого", "кое", "конечно", "который", "кој",
        "која", "красивый", "кто", "ли", "лош", "мал", "маленький", "между", "мене", "меня",
        "меѓу", "ми", "мислам", "млад", "мне", "многу", "могу", "можам", "може", "можеби", "может",
        "можно", "мой", "молам", "молодой", "мочь", "мој", "му", "мы", "на", "наверное", "над",
        "надо", "нам", "нас", "наш", "не", "неа", "него", "нет", "ни", "нив", "ние", "низ",
        "никогаш", "никогда", "но", "нов", "новый", "нормално", "нужно", "о", "об", "ова", "оваа",
        "овде", "овој", "од", "одам", "около", "околу", "он", "она", "они", "оно", "оној", "от",
        "оти", "очень", "па", "первый", "плохой", "по", "под", "пожалуйста", "пока", "последен",
        "последний", "потому", "правам", "прв", "пред", "преку", "при", "привет", "пријатно",
        "про", "с", "сакам", "свой", "свој", "се", "себе", "себя", "сега", "сейчас", "секако",
        "секогаш", "си", "сказать", "сме", "со", "спасибо", "стар", "старый", "сте", "сум", "та",
        "таа", "также", "там", "таму", "твой", "твој", "тебе", "тебя", "ти", "тие", "тоа", "тогаш",
        "тогда", "тоже", "тот", "тој", "треба", "тука", "туку", "тут", "ты", "у", "убав", "уже",
        "уште", "фала", "хороший", "хотеть", "хочу", "чао", "часто", "через", "често", "что",
        "чтобы", "што", "эта", "это", "этот", "я", "јас", "ќе", "آره", "آسان", "آمد", "آنها",
        "أجل", "أحب", "أخذ", "أراد", "أستغفرالله", "أكبر", "أكيد", "أن", "أنا", "أنت", "أنتم",
        "أهلا", "أهلاوسهلا", "أو", "إذا", "إلى", "إنشاء", "إنشاءالله", "إيمان", "اجل", "احب",
        "اخذ", "اذا", "اراد", "اره", "از", "اسان", "است", "استغفرالله", "اكبر", "اكيد", "البته",
        "الحمد", "الحمدلله", "الخير", "السلام", "الله", "اللهأكبر", "اللهاكبر", "الهی", "الى",
        "اما", "امد", "ان", "انا", "انت", "انتم", "انشاء", "انشاءالله", "انشاالله", "انها", "اهلا",
        "اهلاوسهلا", "او", "اون", "اگر", "ایشان", "با", "باركاللهفيك", "باشه", "ببخشید", "ببین",
        "بخیر", "بد", "بدون", "برای", "برو", "بزرگ", "بسمالله", "بعد", "بلند", "بله", "به",
        "بهنامخدا", "بود", "بين", "بگو", "بیا", "تا", "تحت", "تمام", "تو", "توكلتعلىالله", "ثم",
        "جاء", "جانم", "جديد", "جزاكاللهخيرا", "جميل", "جيد", "حبيبتي", "حبيبي", "حتما", "حتى",
        "حسبيالله", "خب", "خداحافظ", "خدانگهدار", "خدایا", "خواست", "خواهش", "خواهشمیکنم", "خوب",
        "خوبی", "خودت", "خودم", "خوشگل", "داد", "دارم", "داشت", "در", "درود", "دوست", "دوستدارم",
        "دون", "دید", "ذهب", "رب", "رسول", "رفت", "روی", "زیاد", "زیبا", "زیر", "سبحان",
        "سبحانالله", "سخت", "سلام", "سهل", "شب", "شببخیر", "شد", "شكرا", "شما", "صباح",
        "صباحالخير", "صبح", "صبحبخیر", "صعب", "صغير", "صلىاللهعليهوسلم", "ضعيف", "طبعا", "طويل",
        "عزیزم", "عشق", "عفوا", "على", "عمل", "عن", "عند", "فعل", "فوق", "في", "قال", "قبل",
        "قديم", "قدیمی", "قرآن", "قربانت", "قشنگ", "قصير", "قليل", "قوي", "كان", "كبير", "كثير",
        "لأن", "لا", "لاإلهإلاالله", "لان", "لكن", "لو", "ما", "ماشاءالله", "ماشاالله", "متشکرم",
        "مثل", "محمد", "مرحبا", "مرسی", "مساء", "مساءالخير", "مع", "ممنون", "من", "میخواهم",
        "میروم", "میکنم", "نحن", "نخیر", "نعم", "نه", "هست", "هم", "هو", "هي", "و", "وجد", "ولی",
        "يارب", "يريد", "يقول", "يكون", "پس", "پیش", "چطوری", "چون", "کرد", "کم", "کنار", "که",
        "کوتاه", "کوچک", "گفت", "یا", "یاالله", "یاعلی",
    )

    // Most-common English words (function words + high-frequency vocabulary). Not a
    // full 10k dictionary — a bounded, embedded set sized to catch all-common-word
    // phrases (the concrete bypass) while a KMP module carries no wordlist
    // asset. Words here are credited at half the diceware rate (see wordModelBits).
    private val COMMON_WORDS = setOf(
        "the", "be", "to", "of", "and", "a", "in", "that", "have", "i", "it", "for",
        "not", "on", "with", "he", "as", "you", "do", "at", "this", "but", "his", "by",
        "from", "they", "we", "say", "her", "she", "or", "an", "will", "my", "one", "all",
        "would", "there", "their", "what", "so", "up", "out", "if", "about", "who", "get",
        "which", "go", "me", "when", "make", "can", "like", "time", "no", "just", "him",
        "know", "take", "people", "into", "year", "your", "good", "some", "could", "them",
        "see", "other", "than", "then", "now", "look", "only", "come", "its", "over",
        "think", "also", "back", "after", "use", "two", "how", "our", "work", "first",
        "well", "way", "even", "new", "want", "because", "any", "these", "give", "day",
        "most", "us", "is", "was", "are", "been", "has", "had", "were", "said", "did",
        "man", "woman", "child", "world", "life", "hand", "part", "eye", "place", "week",
        "case", "point", "government", "company", "number", "group", "problem", "fact",
        "password", "secret", "welcome", "hello", "love", "money", "home", "name", "phone",
    )
}

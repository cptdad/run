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
     * a diceware-style phrase (words × ~12.9 bits, repeated words at half
     * credit) — NOT with the character model, which grossly overrates natural
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

        val words = trimmed.split(whitespace).filter { it.isNotEmpty() }
        // A genuine single token is scored with the
        // same-class-run discount ON — a token that never (or rarely) changes
        // character class is one "word" from one alphabet ("sunshineforever"), and a
        // long same-class run inside a mixed token ("Sunshine2024!" → "unshine",
        // "2024") is dictionary/pattern-guessable far below its charset×length
        // product. Neither may clear the MAXIMUM floor on length alone.
        if (words.size < 2) return charModelBits(trimmed, discountSameClassRuns = true)
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
        // bypass) then falls well below the floor. Repeated words at half too.
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
            // Common word → half diceware credit.
            val penalizeCommon = w in COMMON_WORDS && ++commonSeen > COMMON_FREEBIES
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
            bits += if (seen.add(w)) base else base * 0.5
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
        w.lowercase().filter { it.isLetterOrDigit() }

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
        DIGIT_WORD(log2(21.0)),      // zero..twenty
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

    private val KEYBOARD_ROWS = listOf("1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm")

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

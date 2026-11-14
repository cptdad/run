package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// CredentialPolicy tests — pin the high-risk-mode passphrase floor to the
// product decisions: ≥ ~70 bits ≈ 6 diceware
// words or 12+ mixed-class characters, estimated CONSERVATIVELY (word model
// for phrases, repetition-penalized character model for single tokens).
// ---------------------------------------------------------------------------

class CredentialPolicyTest {

    // -- Decision anchors --------------------------------------------

    @Test
    fun floor_is70Bits_andAutoLockIsTwoMinutes() {
        assertTrue(CredentialPolicy.MIN_PASSPHRASE_BITS == 70.0)
        assertEquals(2 * 60 * 1000L, CredentialPolicy.AUTO_LOCK_TIMEOUT_MS)
    }

    // -- Word model (diceware phrases) ----------------------------------------

    @Test
    fun sixDicewareWords_meetFloor() {
        assertTrue(CredentialPolicy.meetsFloor("correct horse battery staple lamp river"))
    }

    @Test
    fun fiveDicewareWords_doNotMeetFloor() {
        // 5 × 12.925 ≈ 64.6 bits < 70 — the "≈ 6 words" anchor.
        assertFalse(CredentialPolicy.meetsFloor("correct horse battery staple lamp"))
    }

    @Test
    fun repeatedWords_earnNothing() {
        // 6 distinct words pass; the same word 6 times must NOT.
        assertFalse(CredentialPolicy.meetsFloor("yes yes yes yes yes yes"))
        // 2 distinct words, however often repeated, stay 2 words ≈ 25.9 bits.
        assertFalse(CredentialPolicy.meetsFloor("red blue red blue red blue"))
        assertEquals(
            CredentialPolicy.estimateBits("red blue"),
            CredentialPolicy.estimateBits("red blue red blue red blue"),
            0.001,
        )
    }

    @Test
    fun repeatedPhraseBlock_doesNotMeetFloor() {
        // External review RUN-03 (2026-11-12): a sub-floor phrase typed twice scored
        // 77.55 and was ACCEPTED at half credit per repeat. Saying it again is one
        // cracker rule, not four more diceware draws.
        val base = "correct horse battery staple"
        val baseBits = CredentialPolicy.estimateBits(base)
        for (variant in listOf(
            "$base $base",
            "$base $base $base",
            "$base Correct Horse Battery Staple",
            "$base, $base!",
            "$base staple battery horse correct",
            "correct correct horse horse battery battery staple staple",
        )) {
            assertFalse(CredentialPolicy.meetsFloor(variant), variant)
            assertEquals(baseBits, CredentialPolicy.estimateBits(variant), 0.001, variant)
        }
        // A five-word phrase cannot be repeated over the floor either, at any length.
        val five = "correct horse battery staple lamp"
        assertFalse(CredentialPolicy.meetsFloor("$five $five $five $five"))
        // Positive controls: six DISTINCT words still pass, and a repeat does not
        // take anything away from a phrase that already has six.
        assertTrue(CredentialPolicy.meetsFloor("$five river"))
        assertTrue(CredentialPolicy.meetsFloor("$five river river"))
    }

    @Test
    fun phrases_areScoredByWords_notByCharacterLength() {
        // 28 chars of lowercase words would be ~130 bits under a naive char
        // model — the word model must keep it honest (4 words ≈ 51.7 bits).
        val bits = CredentialPolicy.estimateBits("correct horse battery staple")
        assertTrue(bits < 60.0, "expected word-model score, got $bits")
    }

    // -- Character model (single tokens) --------------------------------------

    @Test
    fun twelveMixedChars_meetFloor() {
        // Lower + upper + digit + symbol → charset 95, log2 ≈ 6.57 → 12 distinct
        // chars ≈ 78.8 bits — the "12+ mixed chars" anchor.
        assertTrue(CredentialPolicy.meetsFloor("aB3!xY9\$kQ7%"))
    }

    @Test
    fun twelveLowercaseChars_doNotMeetFloor() {
        // Single-class: 12 × log2(26) ≈ 56.4 bits < 70.
        assertFalse(CredentialPolicy.meetsFloor("abcdefghijkl"))
    }

    @Test
    fun repeatedCharacters_cannotBuyThePass() {
        // 20 × 'a' — distinct=1, effective length 10.5 → ~49 bits < 70. Without
        // the repetition penalty raw length would eventually clear any floor.
        assertFalse(CredentialPolicy.meetsFloor("aaaaaaaaaaaaaaaaaaaa"))
        assertFalse(CredentialPolicy.meetsFloor("abcabcabcabcabcabc"))
    }

    @Test
    fun sixDigitPin_isNowhereNearTheFloor() {
        val bits = CredentialPolicy.estimateBits("123456")
        assertTrue(bits < 25.0, "a 6-digit PIN must score tiny, got $bits")
        assertFalse(CredentialPolicy.meetsFloor("123456"))
    }

    // -- Keyboard-walks / sequences / all-common-word phrases -----

    @Test
    fun keyboardWalk_doesNotMeetFloor() {
        // log2(26)×16 ≈ 75.2 under the naive model, but it is a top-row→home-row
        // walk — must collapse below the floor.
        assertFalse(CredentialPolicy.meetsFloor("qwertyuiopasdfgh"))
    }

    @Test
    fun alphabetAndDigitSequences_doNotMeetFloor() {
        assertFalse(CredentialPolicy.meetsFloor("abcdefghijklmnop"))
        assertFalse(CredentialPolicy.meetsFloor("1234567890abcdef"))
    }

    @Test
    fun allCommonWordPhrase_doesNotMeetFloor() {
        // 6 × 12.925 ≈ 77.6 under the plain diceware model, but every word is a
        // top-frequency function word — must fall below the floor.
        assertFalse(CredentialPolicy.meetsFloor("the and for you but not"))
    }

    @Test
    fun strongTokenWithIncidentalAdjacency_stillMeetsFloor() {
        // Regression guard for the penalty: an otherwise-strong mixed token with
        // a couple of INCIDENTAL adjacent pairs (a→b, x→y) must NOT be penalized.
        assertTrue(CredentialPolicy.meetsFloor("aB3!xY9\$kQ7%"))
        // A fully random mixed token (no runs) clears comfortably.
        assertTrue(CredentialPolicy.meetsFloor("Xk7#mR2\$wZ9!v"))
    }

    // -- Space-separated sequences must not dodge the char penalties -

    @Test
    fun spaceSeparatedSequences_doNotMeetFloor() {
        // Inserting spaces used to route these to the unpenalized word model
        // (6×12.925 ≈ 77.6). The char model on the despaced string now binds.
        assertFalse(CredentialPolicy.meetsFloor("1 2 3 4 5 6"))
        assertFalse(CredentialPolicy.meetsFloor("a b c d e f"))
        assertFalse(CredentialPolicy.meetsFloor("abc def ghi jkl mno pqr"))
        // Also the all-short-junk-word variant (repeated-char "words").
        assertFalse(CredentialPolicy.meetsFloor("aaaa bbbb cccc dddd eeee ffff"))
    }

    // -- Common-word freebies -----

    @Test
    fun commonWordsInAPhrase_getNoFreebies_butOneMoreWordRestoresThePass() {
        // The first two common words used to get FULL diceware credit so a real phrase
        // wasn't false-rejected. That was withdrawn: two free common words let a
        // six-word phrase carry ~26 bits of real entropy and still clear 70.
        // "for" + "you" are now half-credited, so this six-word phrase falls to
        // ~64.6 bits and is REJECTED…
        assertFalse(CredentialPolicy.meetsFloor("correct horse for you battery staple"))
        // …while the same phrase with one more non-common word (5 full + 2 half =
        // 77.55 bits) still passes, so the tightening costs a word, not usability.
        assertTrue(CredentialPolicy.meetsFloor("correct horse for you battery staple lamp"))
    }

    // -- Single-token & low-period MAXIMUM bypasses -----

    @Test
    fun singleClassToken_doesNotMeetFloor() {
        // A single token that never changes character class is one "word"
        // from one alphabet — dictionary/sequence-guessable, so it must NOT clear the
        // floor on length alone. "sunshineforever" scored ~70.5 bits under the old
        // char model (charset 26 × 15 chars) and passed.
        assertFalse(CredentialPolicy.meetsFloor("sunshineforever"))
        assertFalse(CredentialPolicy.meetsFloor("SUNSHINEFOREVER"))
        assertFalse(CredentialPolicy.meetsFloor("thunderstormcloud"))
    }

    @Test
    fun wordPlusDigitsSymbolSingleToken_doesNotMeetFloor() {
        // Headline case: "Sunshine2024!" scored
        // ~85 bits under the old char model (charset 95 × 13 chars, no consecutive
        // predictable steps) and cleared the floor. The same-class-run discount now
        // collapses its "unshine"/"2024" runs below 70.
        assertFalse(CredentialPolicy.meetsFloor("Sunshine2024!"))
        assertFalse(CredentialPolicy.meetsFloor("Password123!"))
        // The perverse inversion: adding one space already rejected
        // it (word model). It must be rejected WITH or WITHOUT the space now.
        assertFalse(CredentialPolicy.meetsFloor("Sunshine 2024!"))
    }

    @Test
    fun period2AlternatingPattern_doesNotMeetFloor() {
        // A period-2 alternation whose
        // adjacent pairs are individually non-predictable (letter↔digit / letter↔symbol)
        // scored ~82 bits and passed — the period-1 run penalty cannot see it.
        assertFalse(CredentialPolicy.meetsFloor("a1a1a1a1a1a1a1a1"))
        assertFalse(CredentialPolicy.meetsFloor("a!a!a!a!a!a!a!a!"))
        assertFalse(CredentialPolicy.meetsFloor("X9X9X9X9X9X9X9X9"))
    }

    @Test
    fun period3And4Patterns_doNotMeetFloor() {
        // Period detection is class-agnostic, so even a mixed-class unit
        // ("xY!") repeated is collapsed to its single unit's entropy.
        assertFalse(CredentialPolicy.meetsFloor("ab1ab1ab1ab1ab1ab1"))   // period 3
        assertFalse(CredentialPolicy.meetsFloor("xY!xY!xY!xY!"))          // period 3, mixed
        assertFalse(CredentialPolicy.meetsFloor("aB3!aB3!aB3!aB3!"))      // period 4, mixed
    }

    @Test
    fun genuinelyStrongInputs_stillMeetFloor() {
        // The model must NOT reject genuinely strong credentials. A random single token
        // whose class changes nearly every character keeps full credit…
        assertTrue(CredentialPolicy.meetsFloor("aB3!xY9\$kQ7%"))
        assertTrue(CredentialPolicy.meetsFloor("Xk7#mR2\$wZ9!v"))
        // …a 6-word diceware phrase passes…
        assertTrue(CredentialPolicy.meetsFloor("correct horse battery staple lamp river"))
        // …and a 6-word phrase of SHORT words (despaces to one long same-class run)
        // must still pass — the despaced check keeps the class-run discount OFF so the
        // word model stays the binding term (regression guard).
        assertTrue(CredentialPolicy.meetsFloor("cat dog fox pig cow hen"))
    }

    // -- Doubled/tripled base password ---------
    // The period collapse capped at MAX_PATTERN_PERIOD=4, so a base
    // password repeated to reach the length minimum (period 5-12+) kept near-full
    // credit and cleared the ≥70-bit MAXIMUM floor. The cap is now removed.

    @Test
    fun doubledLongPassword_doesNotMeetFloor() {
        // The headline residual: exact tilings with period 5-12 were missed.
        assertFalse(CredentialPolicy.meetsFloor("correcthorsecorrecthorse"))  // period 12
        assertFalse(CredentialPolicy.meetsFloor("Secret1!Secret1!"))          // period 8
        assertFalse(CredentialPolicy.meetsFloor("hunter2hunter2"))            // period 7
        // Tripled base password (period 12, three copies).
        assertFalse(CredentialPolicy.meetsFloor("correcthorsecorrecthorsecorrecthorse"))
    }

    @Test
    fun nearDoubledPassword_doesNotMeetFloor() {
        // Not an EXACT tiling (the trailing counter is bumped) but still ~one unit
        // of entropy — the high-confidence near-tiling collapse must catch it.
        assertFalse(CredentialPolicy.meetsFloor("Secret1!Secret2!"))
    }

    // -- Period-collapse over-credited a MIXED-
    // class base's raw period length instead of its DISCOUNTED entropy, so doubling
    // an already-REJECTED 11+ char mixed base (unlike the all-lowercase bases
    // covered, which fail the floor even at the raw-period credit) still cleared
    // the floor: "Tr0ub4dor&3" (11 chars, ~62.4 bits alone, rejected) doubled to 22
    // chars scored period(11) × log2(95) ≈ 72.3 bits and was WRONGLY accepted.

    @Test
    fun doubledMixedBase_staysBelowFloor_evenThoughRawPeriodCreditWouldClearIt() {
        // The base alone must already be rejected (charset 95, but the same-class
        // runs "orrectHorse" discount it well under 70 bits)...
        assertFalse(CredentialPolicy.meetsFloor("correctHorse1!"))
        // ...and doubling it must NOT flip that to accepted. Under the pre-fix code,
        // crediting the raw period (14 chars × log2(95) ≈ 92 bits) wrongly passed.
        assertFalse(CredentialPolicy.meetsFloor("correctHorse1!correctHorse1!"))
        // Same shape, shorter/longer bases — the bug scaled with base length, so
        // pin more than one point on that curve.
        assertFalse(CredentialPolicy.meetsFloor("Tr0ub4dor&3Tr0ub4dor&3"))          // 11-char base × 2
        assertFalse(CredentialPolicy.meetsFloor("correctHorse1!correctHorse1!correctHorse1!"))  // × 3
    }

    @Test
    fun longNonRepeatingPassphrase_stillMeetsFloor() {
        // Regression guard for the cap removal + near-tiling collapse: a genuinely
        // strong long passphrase that never tiles must still pass.
        assertTrue(CredentialPolicy.meetsFloor("correct horse battery staple lamp river"))
        // A long random single token whose classes change nearly every character is
        // not (near-)periodic and keeps full credit.
        assertTrue(CredentialPolicy.meetsFloor("Xk7#mR2\$wZ9!v"))
        // A short-word phrase despaces to one long same-class run but has no exact
        // period; the near-tiling collapse is OFF on the despaced (phrase) path, so
        // its (correct, lower) word-model score still clears the floor.
        assertTrue(CredentialPolicy.meetsFloor("cat dog fox pig cow hen"))
    }

    // -- MAXIMUM's ≥70-bit floor was clearable by canonical
    // low-entropy phrases. This floor is load-bearing — DeviceLockPolicy forces a
    // lock-less phone to MAXIMUM precisely because the device-key half of CR-1 is
    // free there, leaving the passphrase as the ONLY factor.

    @Test
    fun punctuatedCommonWords_doNotDodgeTheCommonWordPenalty() {
        // The headline bypass: `lw in COMMON_WORDS` never stripped punctuation, so
        // the SAME six function words scored 77.55 bits (accepted) with commas and
        // 38.8 bits (rejected) without — a one-keystroke defeat of the floor.
        // Tokens are normalized (lowercase, non-alphanumerics dropped) before BOTH
        // the dedup and the lookup, so every decoration now scores identically.
        assertFalse(CredentialPolicy.meetsFloor("the, and, for, you, but, not"))
        assertFalse(CredentialPolicy.meetsFloor("the. and. for. you. but. not."))
        assertFalse(CredentialPolicy.meetsFloor("The! AND? for- you_ but* not+"))
        // Normalizing the dedup too: punctuation can't buy a repeated word a second
        // "distinct" credit.
        assertFalse(CredentialPolicy.meetsFloor("river river! river? river. river- river+"))
    }

    @Test
    fun punctuationPadding_doesNotMeetFloor() {
        // Rung A (2026-11-09, the dynamic passphrase test across 13 languages). The
        // estimator credited a token that NORMALIZES to nothing — a lone punctuation
        // mark — as a full 12.9-bit diceware word, so a five-word anthem/phrase that
        // scored ~64 bits (refused) cleared the floor the instant a single "!" was
        // appended as a sixth "word". That worked in every language at once, since the
        // trick needs no dictionary. A pure-punctuation token is now worth ZERO.
        assertFalse(CredentialPolicy.meetsFloor("Ja vi elsker dette landet !"))      // Norwegian anthem + lone !
        assertFalse(CredentialPolicy.meetsFloor("correct horse battery staple meadow !"))
        assertFalse(CredentialPolicy.meetsFloor("correct horse battery staple meadow —"))
        // The same five real words plus a sixth REAL word clears the floor, so the
        // tightening costs a word of padding, never a legitimate phrase.
        assertTrue(CredentialPolicy.meetsFloor("correct horse battery staple meadow river"))
    }

    @Test
    fun localizedKeyboardWalks_doNotMeetFloor() {
        // Rung H (2026-11-09): the predictable-step discount knew only US-QWERTY, so a
        // keyboard walk typed on the layout a locale actually ships ran straight past
        // the floor. The row table now also carries Nordic (å ä ö), German QWERTZ,
        // French AZERTY and Russian ЙЦУКЕН. Adding rows only ever makes MORE adjacent
        // pairs predictable, so this is monotone — it never turns a refused passphrase
        // into an accepted one.
        assertFalse(CredentialPolicy.meetsFloor("qwertyuiopåasdfghjklöä"))   // Nordic
        assertFalse(CredentialPolicy.meetsFloor("qwertzuiopüasdfghjklöä"))   // German QWERTZ
        assertFalse(CredentialPolicy.meetsFloor("azertyuiopqsdfghjklm"))     // French AZERTY
        assertFalse(CredentialPolicy.meetsFloor("йцукенгшщзхъфывапролджэ"))  // Russian ЙЦУКЕН
    }

    @Test
    fun closedCategoryRuns_doNotMeetFloor() {
        // Closed, fully enumerable sets are absent from the 148-word COMMON_WORDS
        // list, so six of them scored a clean 77.55 bits and PASSED while carrying
        // well under 25 bits of real entropy (< 2^20 candidates in every case).
        assertFalse(CredentialPolicy.meetsFloor("one two three four five six"))
        assertFalse(CredentialPolicy.meetsFloor("monday tuesday wednesday thursday friday saturday"))
        assertFalse(CredentialPolicy.meetsFloor("alpha bravo charlie delta echo foxtrot"))
        assertFalse(CredentialPolicy.meetsFloor("january february march april june july"))
        assertFalse(CredentialPolicy.meetsFloor("mercury venus mars jupiter saturn neptune"))
        assertFalse(CredentialPolicy.meetsFloor("red orange yellow green blue purple"))
        // Capitalised / punctuated variants normalize to the same tokens.
        assertFalse(CredentialPolicy.meetsFloor("Monday Tuesday Wednesday Thursday Friday Saturday"))
        assertFalse(CredentialPolicy.meetsFloor("Alpha, Bravo, Charlie, Delta, Echo, Foxtrot"))
    }

    @Test
    fun localizedDigitWordRuns_doNotMeetFloor() {
        // Rung C (2026-11-09): "count to six in your OWN language". A localized number run
        // collapses to log2(set size) per member exactly as the English run above does,
        // across every app locale — Latin, Cyrillic and Arabic/Persian scripts. (Members
        // that collide with an article, a short Latin token or an English word are pruned,
        // so these runs deliberately avoid sv "ett"/"sex", fr/en "six", etc.)
        assertFalse(CredentialPolicy.meetsFloor("tre fyra fem sju åtta nio"))          // sv 3,4,5,7,8,9
        assertFalse(CredentialPolicy.meetsFloor("drei vier fünf sechs sieben acht"))   // de 3-8
        assertFalse(CredentialPolicy.meetsFloor("trois quatre cinq sept huit neuf"))   // fr 3,4,5,7,8,9
        assertFalse(CredentialPolicy.meetsFloor("tres cuatro cinco siete ocho nueve")) // es 3,4,5,7,8,9
        assertFalse(CredentialPolicy.meetsFloor("три четыре пять шесть семь восемь"))   // ru 3-8 (Cyrillic)
        // The ascii-folded spelling is a member too: normalizeWord keeps diacritics, so
        // both "två"/"åtta" and "tva"/"atta" must be present to catch either keyboard.
        assertFalse(CredentialPolicy.meetsFloor("tva fyra fem sju atta nio"))          // sv ascii-folded
    }

    @Test
    fun loneLocalizedDigitWord_keepsFullWordCredit() {
        // Only a RUN of >= 2 localized numbers is the guessable pattern; a SINGLE one is a
        // legitimate diceware draw and must not drag a genuine six-word phrase under the
        // floor (categoryHits >= 2 is the gate, same as the English DIGIT_WORD rule).
        assertTrue(CredentialPolicy.meetsFloor("correct horse fyra battery staple river"))  // one sv number
        assertTrue(CredentialPolicy.meetsFloor("correct horse neun battery staple river"))  // one de number
    }

    @Test
    fun wordPlusCounterFamily_doesNotMeetFloor() {
        // Six DISTINCT tokens, so the dedup saw six independent words — but they
        // are one stem plus a trivially enumerable counter. The 2nd-and-later
        // members of a stem family carry only the counter's ~log2(10) bits.
        assertFalse(CredentialPolicy.meetsFloor("cat1 cat2 cat3 cat4 cat5 cat6"))
        assertFalse(CredentialPolicy.meetsFloor("horse1 horse2 horse3 horse4 horse5 horse6"))
        assertFalse(CredentialPolicy.meetsFloor("passphrase1 passphrase2 passphrase3 passphrase4 passphrase5 passphrase6"))
    }

    @Test
    fun stemlessTokens_areNotACounterFamily() {
        // The empty-stem collision: counterStem() trimmed a bare
        // number down to "", and "" was a MATCHABLE key — so two UNRELATED numbers
        // landed in one "family" and the second was discounted to log2(10) ≈ 3.32
        // bits. "correct 2024 horse 1999 battery staple" scored 67.95 and was
        // REJECTED (the char model, ~160 bits, is not the binding term here) even
        // though it is six genuinely distinct tokens worth 77.55. A stem-less token
        // now carries null and joins no family.
        assertTrue(CredentialPolicy.meetsFloor("correct 2024 horse 1999 battery staple"))
        // A bare 4-digit YEAR is still credited like an ordinary word — 4·log2(10)=13.3 ≥
        // the 12.9 word credit, so the bare-number cap leaves it at 12.9 and this still
        // scores EXACTLY the all-words control.
        assertEquals(
            CredentialPolicy.estimateBits("correct horse battery staple lamp river"),
            CredentialPolicy.estimateBits("correct 2024 horse 1999 battery staple"),
            0.001,
        )
        // Rung D-number (2026-11-10, owner call from the 2026-11-09 dynamic report, which
        // this test previously pinned as "deliberately NOT taken"): a bare SHORT number is
        // now capped at log2(10)/digit and can no longer pad a sub-floor phrase into a pass.
        // Four words (51.7) + "42" (6.6) + "7" (3.3) = 61.7 < 70 → REJECTED.
        assertFalse(CredentialPolicy.meetsFloor("correct 42 horse 7 battery staple"))
        // Rung A (2026-11-09): a token that normalizes to "" — pure punctuation — is NOT
        // a word and is worth ZERO, consuming no slot. "correct 2024 horse !!! battery
        // staple" is four words plus one year (~64.6 bits), not a six-word phrase: the
        // one-keystroke "pad with a lone !" bypass the dynamic passphrase test found
        // across languages. This is the ONLY stem-less change — bare numbers are untouched.
        assertFalse(CredentialPolicy.meetsFloor("correct 2024 horse !!! battery staple"))
        // Because punctuation-only tokens contribute zero and take no slot, scoring the
        // same phrase with identical vs. different punctuation tokens must still agree.
        assertEquals(
            CredentialPolicy.estimateBits("correct !!! horse !!! battery staple"),
            CredentialPolicy.estimateBits("correct !!! horse ??? battery staple"),
            0.001,
        )
    }

    @Test
    fun wordPlusCounterFamily_stillDoesNotMeetFloor_withAStemlessTokenPresent() {
        // Regression guard for the fix above: only the EMPTY stem became ineligible.
        // A genuine family keeps a non-empty shared stem and must stay rejected…
        assertFalse(CredentialPolicy.meetsFloor("cat1 cat2 cat3 cat4 cat5 cat6"))
        // …including when a stem-less token sits in the same phrase (it now carries
        // its own full word credit, and the "cat" family still collapses: ~39 bits).
        assertFalse(CredentialPolicy.meetsFloor("cat1 cat2 cat3 cat4 2024 cat5"))
        assertFalse(CredentialPolicy.meetsFloor("horse1 horse2 horse3 !!! horse4 horse5"))
    }

    @Test
    fun genuineDicewarePhrase_stillMeetsFloor_afterH2() {
        // The tightening must not eat real credentials. A 6-word phrase of ordinary
        // (non-common, non-category, non-family) words keeps its full 77.55 bits…
        assertTrue(CredentialPolicy.meetsFloor("correct horse battery staple lamp river"))
        assertTrue(CredentialPolicy.meetsFloor("cat dog fox pig cow hen"))
        assertTrue(CredentialPolicy.meetsFloor("correct horse battery staple ozone thicket"))
        // …a SINGLE closed-category word is not a "run" and keeps full credit, so a
        // real roll that happens to yield one colour/weekday still passes.
        assertTrue(CredentialPolicy.meetsFloor("correct horse battery staple lamp indigo"))
        // …and the mixed-class single-token credentials are untouched (the word
        // model never runs on them).
        assertTrue(CredentialPolicy.meetsFloor("aB3!xY9\$kQ7%"))
        assertTrue(CredentialPolicy.meetsFloor("Xk7#mR2\$wZ9!v"))
        // The passphrase the cross-platform e2e suites provision their MAXIMUM iOS seats
        // with. Until 2026-11-08 it was the eight words CONCATENATED
        // ("kallearnebollmolnhejapamongiskatt", 77.56 bits under the old character model) —
        // exactly the class of input the owner reported as a bug (a lyric typed without
        // spaces was accepted), so the concatenation is now refused and the suites type
        // the same eight words WITH spaces, which the word model scores at ~103 bits.
        // Pinned here because a prior round of this hardening broke the suite.
        assertFalse(CredentialPolicy.meetsFloor("kallearnebollmolnhejapamongiskatt"))
        assertTrue(CredentialPolicy.meetsFloor("kalle arne boll moln heja pa mongi skatt"))
    }

    // -- All-numeric multi-token phrases ----------
    // The gap: six 4-digit groups CLEARED the ≥70-bit floor. The word model saw six
    // distinct non-common, non-category, stem-less tokens (77.550) and the despaced
    // char model credited log2(10) per digit over 22 non-predictable steps (73.082),
    // so min() returned 73.082 — for input carrying ~10-30 bits of real entropy.
    // Not a regression from removing the empty-stem collision: that collision was
    // rejecting these for the WRONG reason (it also false-rejected
    // "correct 2024 horse 1999 battery staple"), and removing it merely exposed this.
    //
    // The char model cannot be the fix. Its same-class-run discount is OFF on the
    // despaced path on purpose — it protects "cat dog fox pig cow hen" (18 lowercase
    // chars → ~44.7 bits with the discount ON) — and the near-tiling collapse does
    // not reach either vector (their best period-4 match rates are 0.75 and 0.25,
    // both under NEAR_TILING_MATCH = 0.8). So the two new rules live in the WORD
    // model, where the shapes are actually distinguishable, and they only ever LOWER
    // it: estimateBits() returns min(word, char), so nothing that failed before can
    // start passing.

    @Test
    fun yearShapedNumberPhrases_doNotMeetFloor() {
        // The headline vectors. Six numbers that are ALL year-shaped (4 digits,
        // 1xxx/2xxx) are not six 12.9-bit draws: one year carries at most
        // log2(2000) ≈ 10.97 bits, so six carry 65.795.
        assertFalse(CredentialPolicy.meetsFloor("2024 1999 1776 1492 1865 1969"))
        assertFalse(CredentialPolicy.meetsFloor("1990 1991 1992 1993 1994 1995"))
        // Decorating them cannot dodge it — tokens are normalized first, the same
        // one-keystroke bypass closed for COMMON_WORDS (65.795, unchanged).
        assertFalse(CredentialPolicy.meetsFloor("2024! 1999, 1776. 1492; 1865: 1969?"))
        // The rule tolerates ONE non-year number in the run, so swapping a single
        // group for a random one does not buy the pass back (67.754).
        assertFalse(CredentialPolicy.meetsFloor("2024 1999 1776 1492 1865 8391"))
    }

    @Test
    fun numericProgressions_doNotMeetFloor() {
        // The obvious escape from the year rule: a user rejected at six consecutive
        // years appends a seventh. Under the year cap ALONE seven years score 76.760
        // and would PASS; as an arithmetic run they are one starting value plus a
        // step, so every later member carries only the step's ~log2(10) bits.
        assertFalse(CredentialPolicy.meetsFloor("1990 1991 1992 1993 1994 1995 1996"))
        assertFalse(CredentialPolicy.meetsFloor("1990 1991 1992 1993 1994 1995 1996 1997"))
        // Descending and non-unit steps are the same pattern.
        assertFalse(CredentialPolicy.meetsFloor("2024 2023 2022 2021 2020 2019"))
        assertFalse(CredentialPolicy.meetsFloor("1970 1980 1990 2000 2010 2020"))
        assertFalse(CredentialPolicy.meetsFloor("2000 2004 2008 2012 2016 2020"))
        // Non-numeric tokens do not BREAK a run — the numbers are still a sequence,
        // whatever is interleaved with them (56.385 for both).
        assertFalse(CredentialPolicy.meetsFloor("1970 1980 1990 correct horse battery"))
        assertFalse(CredentialPolicy.meetsFloor("correct 2024 horse 2025 battery 2026"))
        // Pre-existing controls: the char model already binds well below the floor on
        // these, and the word model may only go DOWN, so they must stay rejected.
        assertFalse(CredentialPolicy.meetsFloor("1 2 3 4 5 6"))                    // 6.644
        assertFalse(CredentialPolicy.meetsFloor("10 20 30 40 50 60"))              // 39.863 → 29.535
        assertFalse(CredentialPolicy.meetsFloor("1111 2222 3333 4444 5555 6666"))  // 6.644
        assertFalse(CredentialPolicy.meetsFloor("2024 1999 1776 1492 1865"))       // 5 groups: 59.795 → 54.829
    }

    @Test
    fun genuinelyRandomNumericPhrases_stillMeetFloor() {
        // FALSE REJECTS ARE THE DOMINANT RISK: this gates vault provisioning at
        // MAXIMUM. A user who types six RANDOM 4-digit groups has ~73-80 real bits
        // and must still be accepted. A random group lands in [1000, 2999] only 20%
        // of the time, so "all of them do" is itself the evidence the numbers were
        // chosen as years — the rule needs all-but-at-most-one to be year-shaped
        // (P ≈ 0.16% on six random groups) AND at least three of them, which is why
        // these pass untouched at their pre-change scores.
        assertTrue(CredentialPolicy.meetsFloor("8391 4027 6558 7194 7302 9846"))   // 73.082
        assertTrue(CredentialPolicy.meetsFloor("3947 8102 5563 9284 7710 4038"))   // 76.404
        // Three UNRELATED years plus three words still clears (71.672) — the year
        // cap is the exact counting bound on one year, not a punitive discount.
        assertTrue(CredentialPolicy.meetsFloor("1985 2001 2019 correct horse battery"))
        assertTrue(CredentialPolicy.meetsFloor("2024 1999 1776 correct horse battery staple"))
    }

    @Test
    fun numericTightening_leavesLegitimatePhrasesExactlyWhereTheyWere() {
        // Explicit must-still-pass guard, so a FUTURE tightening of the numeric
        // rules cannot silently eat these. Each is pinned to its exact pre-change
        // score, not merely to "passes".
        val control = CredentialPolicy.estimateBits("correct horse battery staple lamp river")
        // The short-word phrase the despaced-path discount is disabled for.
        assertTrue(CredentialPolicy.meetsFloor("cat dog fox pig cow hen"))
        assertEquals(control, CredentialPolicy.estimateBits("cat dog fox pig cow hen"), 0.001)
        // The empty-stem regression vector: TWO year-shaped numbers are below
        // the 3-token minimum, so they keep full word credit and this phrase still
        // scores EXACTLY the all-words control. Re-pinned here because the numeric
        // rules are the second mechanism that could false-reject it.
        assertEquals(
            control,
            CredentialPolicy.estimateBits("correct 2024 horse 1999 battery staple"),
            0.001,
        )
        // Rung D-number (2026-11-10): a bare SHORT number is now capped at log2(10)/digit,
        // so this phrase is deliberately NO LONGER equal to the control — "42" and "7" are
        // worth 6.6 + 3.3, not 2·12.9 — and it drops below the floor. (The 4-digit-year
        // phrases here are unchanged: 13.3 ≥ 12.9.)
        assertFalse(CredentialPolicy.meetsFloor("correct 42 horse 7 battery staple"))
        assertTrue(CredentialPolicy.estimateBits("correct 42 horse 7 battery staple") < control)
        assertEquals(
            control,
            CredentialPolicy.estimateBits("correct horse battery staple 2024 river"),
            0.001,
        )
        // A LONE year in an otherwise ordinary phrase is not a run, exactly like a
        // lone closed-category word.
        assertTrue(CredentialPolicy.meetsFloor("skate 1987 mango velvet turbine ladder"))
        assertTrue(CredentialPolicy.meetsFloor("ocean 1204 pepper granite falcon thunder"))
        // (Non-ASCII digits are deliberately NOT numbers to these rules — they
        // cannot be parsed by toLongOrNull and excluding them fails toward NO
        // penalty. Not pinned here: the resulting score depends on Char.isDigit /
        // isLetterOrDigit's Unicode tables, which are a PLATFORM behaviour, so an
        // assertion on it would pin the JVM's answer onto Kotlin/Native too.)
        //
        // Absurdly long digit runs must not overflow or throw on their way to being
        // ignored as progression candidates.
        assertFalse(CredentialPolicy.meetsFloor("99999999999999999999999 99999999999999999999999 99999999999999999999999"))
    }

    // -- Edge cases ------------------------------------------------------------

    @Test
    fun emptyAndBlank_scoreZero() {
        assertTrue(CredentialPolicy.estimateBits("") == 0.0)
        assertTrue(CredentialPolicy.estimateBits("   ") == 0.0)
        assertFalse(CredentialPolicy.meetsFloor(""))
    }

    @Test
    fun overlongPassphrase_isRejectedByFloorCheck() {
        val huge = buildString { repeat(300) { append(('a' + it % 26)) ; append(' ') } }
        assertFalse(CredentialPolicy.meetsFloor(huge))
    }

    @Test
    fun strengthBuckets_alignWithFloor() {
        assertEquals(0, CredentialPolicy.strengthBucket(10.0))
        assertEquals(1, CredentialPolicy.strengthBucket(60.0))
        assertEquals(2, CredentialPolicy.strengthBucket(CredentialPolicy.MIN_PASSPHRASE_BITS))
        assertEquals(3, CredentialPolicy.strengthBucket(95.0))
    }

    // -- Mode flag plumbing -----------------------------------------------------

    @Test
    fun credentialModeConstants_areStable() {
        // Storage-format constants: renaming them silently orphans the flag on
        // existing installs (entry UI falls back to PIN against a passphrase
        // credential). Locked in like the other vlt_* names.
        assertEquals("vlt_m", VaultStoreKeys.CREDENTIAL_MODE)
        assertEquals("phrase", SelectorMetaPolicy.MODE_PASSPHRASE)
        assertEquals("pin", SelectorMetaPolicy.MODE_PIN)
    }

    // -- PIN-unlock policy constants (single-sourced for both platforms) ----

    @Test
    fun pinPolicyConstants_areStable() {
        assertEquals(6, CredentialPolicy.PIN_LENGTH)
        assertEquals(5, CredentialPolicy.MAX_CONSECUTIVE_ATTEMPTS)
    }

    @Test
    fun isPinShaped_matchesExactlyTheKeypadShape() {
        // With a damaged vlt_m blob, changeCredential derives the
        // resulting mode from THIS shape — exactly PIN_LENGTH ASCII digits.
        assertTrue(CredentialPolicy.isPinShaped("123456"))
        assertTrue(CredentialPolicy.isPinShaped("000000"))
        assertFalse(CredentialPolicy.isPinShaped("12345"))        // too short
        assertFalse(CredentialPolicy.isPinShaped("1234567"))      // too long
        assertFalse(CredentialPolicy.isPinShaped("12345a"))       // non-digit
        assertFalse(CredentialPolicy.isPinShaped("１２３４５６"))   // unicode digits are not keypad output
        assertFalse(CredentialPolicy.isPinShaped("correct horse battery staple lamp river"))
        assertFalse(CredentialPolicy.isPinShaped(""))
    }

    @Test
    fun unlockBackoff_isExponentialAndCappedAt8s() {
        // 1 s, 2 s, 4 s, 8 s, then held at the 8 s cap. Both platforms drive their
        // wrong-PIN delay from this (Android ms, iOS ms/1000).
        assertEquals(1000L, CredentialPolicy.unlockBackoffMs(1))
        assertEquals(2000L, CredentialPolicy.unlockBackoffMs(2))
        assertEquals(4000L, CredentialPolicy.unlockBackoffMs(3))
        assertEquals(8000L, CredentialPolicy.unlockBackoffMs(4))
        assertEquals(8000L, CredentialPolicy.unlockBackoffMs(5))
        // Defensive: out-of-range inputs never negative-shift or overflow.
        assertEquals(1000L, CredentialPolicy.unlockBackoffMs(0))
        assertEquals(8000L, CredentialPolicy.unlockBackoffMs(99))
    }

    @Test
    fun launchBackoff_reappliesDelayForDurableCount() {
        assertEquals(0L, CredentialPolicy.launchBackoffMs(0))
        assertEquals(0L, CredentialPolicy.launchBackoffMs(-1))
        assertEquals(1000L, CredentialPolicy.launchBackoffMs(1))
        assertEquals(4000L, CredentialPolicy.launchBackoffMs(3))
        assertEquals(8000L, CredentialPolicy.launchBackoffMs(10))
    }

    @Test
    fun backoffSecondsLeft_roundsUpAndClampsAtZero() {
        assertEquals(0, CredentialPolicy.backoffSecondsLeft(0))
        assertEquals(0, CredentialPolicy.backoffSecondsLeft(-5))
        assertEquals(1, CredentialPolicy.backoffSecondsLeft(1))
        assertEquals(1, CredentialPolicy.backoffSecondsLeft(1000))
        assertEquals(2, CredentialPolicy.backoffSecondsLeft(1001))
        assertEquals(8, CredentialPolicy.backoffSecondsLeft(8000))
    }

    // -- Per-level wrong-credential budget ---------------
    // Both lock screens (PinEntryScreen, PinEntryView via IosAppController)
    // consume THIS mapping — one copy of the fail-safe for both platforms.

    @Test
    fun maxAttempts_storedLevel_yieldsItsOwnBudget() {
        for (level in ProtectionLevel.entries) {
            assertEquals(
                level.maxConsecutiveAttempts,
                CredentialPolicy.maxConsecutiveAttempts(ProtectionLevelRead.Present(level)),
            )
        }
    }

    @Test
    fun maxAttempts_absentLevel_keepsTheLegacyDefault() {
        assertEquals(
            CredentialPolicy.MAX_CONSECUTIVE_ATTEMPTS,
            CredentialPolicy.maxConsecutiveAttempts(ProtectionLevelRead.Absent),
        )
    }

    @Test
    fun autoLock_unreadableLevel_getsTheShortestTimeout() {
        // Fail-safe direction is inverted for auto-lock (locking sooner loses no
        // data): an unreadable level must use the tightest tier, not the default.
        assertEquals(
            ProtectionLevel.entries.minOf { it.autoLockTimeoutMs },
            CredentialPolicy.autoLockTimeoutMs(ProtectionLevelRead.Unreadable),
        )
        assertEquals(
            CredentialPolicy.AUTO_LOCK_TIMEOUT_MS,
            CredentialPolicy.autoLockTimeoutMs(ProtectionLevelRead.Absent),
        )
        for (level in ProtectionLevel.entries) {
            assertEquals(
                level.autoLockTimeoutMs,
                CredentialPolicy.autoLockTimeoutMs(ProtectionLevelRead.Present(level)),
            )
        }
    }

    @Test
    fun autoLockWarning_fitsInsideEveryTierWindow() {
        // The countdown is a warning INSIDE the Lever-C window, never a grace
        // period: it must leave real idle headroom even at the tightest tier
        // (MAXIMUM = 60 s), or the overlay becomes a permanent fixture there.
        val shortest = ProtectionLevel.entries.minOf { it.autoLockTimeoutMs }
        assertTrue(CredentialPolicy.AUTO_LOCK_WARNING_MS > 0)
        assertTrue(CredentialPolicy.AUTO_LOCK_WARNING_MS <= shortest / 2)
        // The fine-tick zone must cover the warning zone (the 1 s cadence is what
        // drives the countdown display), and tick faster than the warning lasts.
        assertTrue(CredentialPolicy.AUTO_LOCK_FINE_WINDOW_MS >= CredentialPolicy.AUTO_LOCK_WARNING_MS)
        assertTrue(CredentialPolicy.AUTO_LOCK_FINE_CHECK_INTERVAL_MS < CredentialPolicy.AUTO_LOCK_WARNING_MS)
    }

    @Test
    fun maxAttempts_unreadableLevel_getsTheMostLenientBudget() {
        // An unreadable stored level must never SHRINK the budget below what the
        // user chose (a CASUAL 10-try vault handed the 5-try default would wipe
        // honest data five typos early) — so it gets the largest tier budget.
        assertEquals(
            ProtectionLevel.MOST_LENIENT_MAX_ATTEMPTS,
            CredentialPolicy.maxConsecutiveAttempts(ProtectionLevelRead.Unreadable),
        )
        assertEquals(
            ProtectionLevel.entries.maxOf { it.maxConsecutiveAttempts },
            ProtectionLevel.MOST_LENIENT_MAX_ATTEMPTS,
        )
    }

    // -- Damaged is NOT Unreadable ----------------------

    @Test
    fun maxAttempts_damagedLevel_getsTheStrictestBudget() {
        // The bug: a blob-shaped but AEAD-invalid vlt_lvl took the lenient
        // Unreadable branch, so one flipped byte handed the tamperer the LARGEST
        // wrong-credential budget (5 → 10) on the only rate limit unlock() has.
        // A damaged blob is positive tamper evidence (the device key WORKS), so it
        // gets the strictest tier's budget instead.
        assertEquals(
            ProtectionLevel.MAXIMUM.maxConsecutiveAttempts,
            CredentialPolicy.maxConsecutiveAttempts(ProtectionLevelRead.Damaged),
        )
        // The two states must stay distinguishable in BOTH directions: a transient
        // device-key outage keeps the lenient budget.
        assertTrue(
            CredentialPolicy.maxConsecutiveAttempts(ProtectionLevelRead.Damaged) <
                CredentialPolicy.maxConsecutiveAttempts(ProtectionLevelRead.Unreadable),
        )
        // Absence is ambiguous (legacy / fresh / interrupted provision) and keeps
        // establish-on-read's legacy default — never the tamper branch.
        assertEquals(
            CredentialPolicy.MAX_CONSECUTIVE_ATTEMPTS,
            CredentialPolicy.maxConsecutiveAttempts(ProtectionLevelRead.Absent),
        )
    }

    @Test
    fun autoLock_damagedLevel_getsTheShortestTimeout() {
        // Auto-lock's fail-safe direction is inverted (locking sooner loses no
        // data), so this is the one decision where Damaged and Unreadable agree.
        assertEquals(
            ProtectionLevel.entries.minOf { it.autoLockTimeoutMs },
            CredentialPolicy.autoLockTimeoutMs(ProtectionLevelRead.Damaged),
        )
    }

    // ---- 2026-11-08: a well-known phrase typed WITHOUT spaces must not clear MAXIMUM ----

    @Test
    fun anthemLineWithoutSpaces_isRefused_andScoresWeak() {
        // Reported by the owner: the first line of the Swedish national anthem, lowercased
        // and concatenated, was accepted as a MAXIMUM passphrase. Two defects stacked:
        // ä/ö counted as SYMBOLS (+33 alphabet, run discount broken at each one) and a
        // same-case letter run was credited half of log2(26) per letter, ~3× the real
        // entropy of natural language.
        val anthem = "dugamladufriadufjällhöganord"
        assertFalse(CredentialPolicy.meetsFloor(anthem))
        assertEquals(0, CredentialPolicy.strengthBucket(CredentialPolicy.estimateBits(anthem)), "weak, not merely fair")
        // At ~1.4 bits per letter a concatenated phrase needs about 50 letters; 37 is not enough.
        assertFalse(CredentialPolicy.meetsFloor("dugamladufriadufjällhöganorddutystadu"))
    }

    @Test
    fun diacritics_areLetters_notSymbols() {
        // Same alphabet, same score: the diacritics neither add symbol credit nor break the run.
        val withDiacritics = CredentialPolicy.estimateBits("dugamladufriadufjällhöganord")
        val asciiTwin = CredentialPolicy.estimateBits("dugamladufriadufjallhoganord")
        assertEquals(asciiTwin, withDiacritics, 1e-9)
        // Uppercase letters with diacritics are the UPPERCASE class, not symbols either. (The
        // letters are chosen so no pair is an alphabet or keyboard step; a sequence like
        // "ABCD" would be discounted on its own and hide the comparison.)
        assertEquals(
            CredentialPolicy.estimateBits("KQZMWPLRTXVBNJCY"),
            CredentialPolicy.estimateBits("KQZMWÄLRTXVBNJÖY"),
            1e-9,
        )
        // Caseless letters (Arabic) are one alphabet too: a repeated-letter run is still discounted.
        assertFalse(CredentialPolicy.meetsFloor("سلامسلامسلامسلامسلامسلام"))
    }

    @Test
    fun letterRunTightening_leavesMixedClassAndPhrasePathsAlone() {
        // The pinned mixed-class tokens change class at every character: no run, no change.
        assertTrue(CredentialPolicy.meetsFloor("aB3!xY9\$kQ7%"))
        assertTrue(CredentialPolicy.meetsFloor("Xk7#mR2\$wZ9!v"))
        // Genuine phrases WITH spaces take the word model (despaced check runs with the run
        // discount OFF), so six short random words still pass exactly as before.
        assertTrue(CredentialPolicy.meetsFloor("cat dog fox pig cow hen"))
        assertTrue(CredentialPolicy.meetsFloor("correct horse battery staple lamp river"))
        // The same six words concatenated are one letter run — natural language — and fail.
        assertFalse(CredentialPolicy.meetsFloor("catdogfoxpigcowhen"))
    }

    // -- 2026-11-10 dynamic-report fixes: localized categories, famous phrases,
    //    CamelCase segmentation, bare-number cap, native-script digits ---------------

    @Test
    fun localizedClosedCategoryRuns_doNotMeetFloor() {
        // Fix #2 (Rung D): weekday / month / colour / … runs in the 12 app locales collapse
        // to log2(set size) per member, like the English and localized-NUMBER runs before
        // them — not six independent diceware draws.
        assertFalse(CredentialPolicy.meetsFloor("montag dienstag mittwoch donnerstag freitag samstag"))  // de weekdays
        assertFalse(CredentialPolicy.meetsFloor("heinakuu elokuu syyskuu lokakuu marraskuu joulukuu"))   // fi months
        // A LONE localized category word keeps full credit (a genuine roll may produce one),
        // so a real phrase with a single localized day/colour still clears with enough words.
        assertTrue(CredentialPolicy.meetsFloor("montag velvet turbine ladder falcon thunder"))
    }

    @Test
    fun famousPhrases_areCappedBelowFloor_butFamousOpenerPlusEntropyStillPasses() {
        // Fix #4: a culturally shared line (anthem, proverb, prayer, pangram, famous first
        // line) is one entry on an attacker's phrase list, not its word count.
        assertFalse(CredentialPolicy.meetsFloor("en boca cerrada no entran moscas"))        // es proverb
        assertFalse(CredentialPolicy.meetsFloor("the quick brown fox jumps over the lazy dog"))  // en pangram
        assertFalse(CredentialPolicy.meetsFloor("allons enfants de la patrie le jour de gloire"))  // fr anthem
        // Case-, space-, punctuation- and diacritic-insensitive: a mangled line still caps
        // (these despace/CamelCase/punctuation variants were "free no-op" bypasses).
        assertFalse(CredentialPolicy.meetsFloor("EnBocaCerradaNoEntranMoscas"))
        assertFalse(CredentialPolicy.meetsFloor("en boca cerrada no entran moscas!"))
        // PREFIX-only on the stored side: a famous OPENER + genuinely random words keeps its
        // real added entropy and still passes — the extension is NOT matched as famous.
        assertTrue(CredentialPolicy.meetsFloor("en boca cerrada no entran moscas zxqwpl frobnicate kettle"))
    }

    @Test
    fun camelCasePhrases_areScoredAsWords_notOvercredited() {
        // Fix #3: CamelCase/PascalCase capitals at each word boundary are class changes that
        // defeat the same-class-run discount; re-expose the token to the word model (min) so
        // it cannot out-score its own spaced form.
        assertFalse(CredentialPolicy.meetsFloor("ToBeOrNotToBe"))
        assertFalse(CredentialPolicy.meetsFloor("CorrectHorseBatteryStaple"))
        // GUARD: a genuinely strong random token with lower→upper boundaries but digits /
        // symbols (NOT a word phrase) keeps its char-model entropy — not re-scored as words.
        assertTrue(CredentialPolicy.meetsFloor("aB3!xY9\$kQ7%"))
    }

    @Test
    fun bareNumberCap_capsShortNumbers_andFoldsNativeScriptDigits() {
        // Fix #1: a bare SHORT number is worth log2(10)/digit, so it can no longer pad a
        // sub-floor phrase into a pass; a 4-digit year is unaffected (13.3 ≥ 12.9).
        assertFalse(CredentialPolicy.meetsFloor("correct horse battery staple lamp 7"))
        assertTrue(CredentialPolicy.meetsFloor("correct horse battery staple lamp seven"))  // the WORD, lone category
        // Arabic-Indic / Persian numerals fold to ASCII in normalizeWord, so they are capped
        // identically — no native-script-digit evasion of the number rules.
        assertEquals(
            CredentialPolicy.estimateBits("correct horse battery staple lamp 7"),
            CredentialPolicy.estimateBits("correct horse battery staple lamp ٧"),  // ٧ Arabic-Indic 7
            0.001,
        )
    }
}

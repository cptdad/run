package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ContactAliasGeneratorTest {

    @Test
    fun everyGeneratedAlias_matchesAConfiguredFormat() {
        repeat(2_000) {
            val alias = ContactAliasGenerator.generate()
            assertTrue(
                ContactAliasGenerator.matchesGeneratedFormat(alias),
                "generated alias not in any configured format: <$alias>",
            )
        }
    }

    @Test
    fun allFiveFormats_actuallyOccur() {
        // Every declared format must actually occur — a format that can never
        // be generated (or one generated but not recognized by
        // matchesGeneratedFormat) is a drift bug. 2000 draws at 1/5 each:
        // P(missing one) ≈ 5·(4/5)^2000 ≈ 0.
        var verbAnimal = 0; var titleAnimal = 0; var titleNoun = 0
        var adjNoun = 0; var figure = 0
        repeat(2_000) {
            val parts = ContactAliasGenerator.generate().split(" ")
            when {
                parts.size == 1 -> figure++
                parts[0] in ContactAliasGenerator.VERBS -> verbAnimal++
                parts[0] in ContactAliasGenerator.TITLES &&
                    parts[1] in ContactAliasGenerator.ANIMALS -> titleAnimal++
                parts[0] in ContactAliasGenerator.TITLES -> titleNoun++
                parts[0] in ContactAliasGenerator.ADJECTIVES -> adjNoun++
            }
        }
        assertTrue(verbAnimal > 0, "Verb Animal never generated")
        assertTrue(titleAnimal > 0, "Title Animal never generated")
        assertTrue(titleNoun > 0, "Title Noun never generated")
        assertTrue(adjNoun > 0, "Adjective Noun never generated")
        assertTrue(figure > 0, "Historical figure never generated")
        assertEquals(2_000, verbAnimal + titleAnimal + titleNoun + adjNoun + figure)
    }

    @Test
    fun nonGeneratedShapes_areRejected() {
        assertEquals(false, ContactAliasGenerator.matchesGeneratedFormat("Jordan"))
        assertEquals(false, ContactAliasGenerator.matchesGeneratedFormat("Running Lantern"))   // verb + noun: not a format
        assertEquals(false, ContactAliasGenerator.matchesGeneratedFormat("Fox Running"))
        assertEquals(false, ContactAliasGenerator.matchesGeneratedFormat("Captain Running Fox"))
        assertEquals(false, ContactAliasGenerator.matchesGeneratedFormat(""))
    }

    // -------------------------------------------------------------------
    // normalizeForCompare (referral-offer alias collision hygiene).
    // -------------------------------------------------------------------

    @Test
    fun normalizeForCompare_isCaseInsensitive() {
        assertEquals(
            ContactAliasGenerator.normalizeForCompare("Running Fox"),
            ContactAliasGenerator.normalizeForCompare("running fox"),
        )
        assertEquals(
            ContactAliasGenerator.normalizeForCompare("Running Fox"),
            ContactAliasGenerator.normalizeForCompare("RUNNING FOX"),
        )
    }

    @Test
    fun normalizeForCompare_foldsFullwidthLatinHomoglyphs() {
        // Fullwidth Latin "Running Fox" (U+FF01-FF5E block) — the classic
        // homoglyph substitution against a pure-ASCII wordlist.
        val fullwidth = "Ｒｕｎｎｉｎｇ Ｆｏｘ"
        assertEquals("running fox", ContactAliasGenerator.normalizeForCompare(fullwidth))
    }

    @Test
    fun normalizeForCompare_stripsBidiZeroWidthAndControlCharacters() {
        // Zero-width space + RLO override + a NUL byte hidden inside an
        // otherwise-plausible name must not change the comparison key.
        val hidden = "Run\u200Bning\u202E Fox" + 0.toChar()
        assertEquals("running fox", ContactAliasGenerator.normalizeForCompare(hidden))
    }

    @Test
    fun normalizeForCompare_leavesOrdinaryAsciiAliasesAlone() {
        assertEquals("crimson harbor", ContactAliasGenerator.normalizeForCompare("Crimson Harbor"))
    }

    // -------------------------------------------------------------------
    // sanitizeDisplayName (group-name eclipse-dialog hardening).
    // Display-preserving — unlike normalizeForCompare it must NOT lowercase
    // or fold fullwidth glyphs, only strip the dangerous invisible/control
    // code points and collapse whitespace.
    // -------------------------------------------------------------------

    @Test
    fun sanitizeDisplayName_stripsNewlines() {
        assertEquals("Team Alpha", ContactAliasGenerator.sanitizeDisplayName("Team\nAlpha"))
        assertEquals("Team Alpha", ContactAliasGenerator.sanitizeDisplayName("Team\r\nAlpha"))
    }

    @Test
    fun sanitizeDisplayName_stripsBidiOverrideCharacters() {
        // U+202E (RLO) could otherwise reverse everything rendered after it.
        val withRlo = "Team\u202EATL A"
        assertEquals("TeamATL A", ContactAliasGenerator.sanitizeDisplayName(withRlo))
    }

    @Test
    fun sanitizeDisplayName_stripsBidiIsolateCharacters() {
        // U+2066-2069 (LRI/RLI/FSI/PDI) — the same isolates this fix uses
        // defensively at display time must not survive coming FROM a peer.
        val withIsolates = "Te\u2066am\u2069 Alpha"
        assertEquals("Team Alpha", ContactAliasGenerator.sanitizeDisplayName(withIsolates))
    }

    @Test
    fun sanitizeDisplayName_stripsZeroWidthCharacters() {
        // Zero-width space (U+200B), word joiner (U+2060), BOM (U+FEFF).
        val hidden = "Te\u200Bam\u2060 Alpha\uFEFF"
        assertEquals("Team Alpha", ContactAliasGenerator.sanitizeDisplayName(hidden))
    }

    @Test
    fun sanitizeDisplayName_collapsesWhitespaceProducedByStrippedNewlines() {
        // A run of newlines/tabs must collapse to ONE space, not vanish (which
        // would splice two words together) and not survive as multiple spaces.
        assertEquals("Line1 Line2", ContactAliasGenerator.sanitizeDisplayName("Line1\n\n\tLine2"))
        assertEquals("Padded Name", ContactAliasGenerator.sanitizeDisplayName("  Padded   Name  "))
    }

    @Test
    fun sanitizeDisplayName_thenTake64_dropsExcessOnlyAfterStripping() {
        // 70 real characters plus 30 invisible ones: the CAP is meant to bound
        // the RENDERED result, not the raw byte count, so stripping must run
        // before take(64) — exactly what every GroupManager call site does.
        val raw = "A".repeat(70) + "\u200B".repeat(30)
        val capped = ContactAliasGenerator.sanitizeDisplayName(raw).take(64)
        assertEquals(64, capped.length)
        assertEquals("A".repeat(64), capped)
    }

    @Test
    fun sanitizeDisplayName_leavesOrdinaryUnicodeNamesAlone() {
        // Non-Latin scripts must render completely unchanged — this sanitiser
        // is NOT a Latin/ASCII filter, only an invisible/control-character one.
        assertEquals("مجموعة الأصدقاء", ContactAliasGenerator.sanitizeDisplayName("مجموعة الأصدقاء"))   // Arabic
        assertEquals("گروه دوستان", ContactAliasGenerator.sanitizeDisplayName("گروه دوستان"))             // Persian
        assertEquals("Crimson Harbor", ContactAliasGenerator.sanitizeDisplayName("Crimson Harbor"))
    }
}

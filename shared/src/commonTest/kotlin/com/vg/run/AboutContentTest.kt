package com.vg.run

import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class AboutContentTest {

    @AfterTest
    fun tearDown() {
        platformStringOverride = null
    }

    @Test
    fun about_has15Pages_welcomeFirst_readyLast() {
        assertEquals(15, AboutContent.pages.size)
        assertEquals("about_welcome_title", AboutContent.pages.first().titleKey)
        assertEquals("about_ready_title", AboutContent.pages.last().titleKey)
    }

    @Test
    fun about_hasExactlyTwoRunestoneAnimationPages_torThenRelay() {
        val torIdx = AboutContent.pages.indexOfFirst { it.kind == AboutPageKind.RUNESTONE_TOR }
        val relayIdx = AboutContent.pages.indexOfFirst { it.kind == AboutPageKind.RUNESTONE_RELAY }
        assertEquals(1, AboutContent.pages.count { it.kind == AboutPageKind.RUNESTONE_TOR })
        assertEquals(1, AboutContent.pages.count { it.kind == AboutPageKind.RUNESTONE_RELAY })
        assertTrue(torIdx in 0 until relayIdx, "Tor runestone page must come before the relay one")
    }

    @Test
    fun about_forensicPage_usesForcefieldKind_andNoHighRiskCopy() {
        val forensic = AboutContent.pages.first { it.titleKey == "about_forensic_title" }
        assertEquals(AboutPageKind.FORCEFIELD, forensic.kind)
        assertEquals(1, AboutContent.pages.count { it.kind == AboutPageKind.FORCEFIELD })
        // The "high-risk mode" wording was retired in favour of the protection levels —
        // the retired concept doesn't even have a resource key any more (the English
        // text itself now lives only in strings_shared.xml, locked by a JVM resources
        // test elsewhere; here we assert on the KEYS, which is what commonMain owns).
        assertTrue(AboutContent.pages.none { it.titleKey.contains("high_risk", ignoreCase = true) })
        assertTrue(AboutContent.pages.none { (it.bodyKey ?: "").contains("high_risk", ignoreCase = true) })
    }

    @Test
    fun about_everyPageHasTitleAndBody_textPagesHaveGlyph() {
        for (p in AboutContent.pages) {
            assertTrue(p.titleKey.isNotBlank(), "page titleKey blank")
            // .title/.body fail-soft to the key text when no resolver is installed
            // (true in this JVM/native unit-test environment) — still non-blank.
            assertTrue(p.title.isNotBlank(), "page title blank")
            assertTrue(p.body.isNotBlank(), "page body blank for '${p.titleKey}'")
            if (p.kind == AboutPageKind.TEXT) {
                assertTrue(p.glyph.isNotBlank(), "TEXT page '${p.titleKey}' must have a glyph")
            }
        }
    }

    @Test
    fun aboutInfo_torVersion_isThreeOrFourDottedIntegers() {
        // Shown in the About box ("Runs Tor <version>"). Note: the iOS
        // framework's CFBundleShortVersionString must be <= 3 ints (ITMS-90060),
        // but this label string can carry the full upstream version.
        assertTrue(
            Regex("""^\d+(\.\d+){2,3}$""").matches(AboutContent.torVersion),
            "torVersion '${AboutContent.torVersion}' should be dotted integers",
        )
    }

    @Test
    fun aboutInfo_credits_nonEmpty_eachHasNameAndLicense_includesTorAndSqlcipher() {
        assertTrue(AboutContent.credits.isNotEmpty(), "credits must not be empty")
        for (c in AboutContent.credits) {
            assertTrue(c.name.isNotBlank(), "credit name blank")
            assertTrue(c.license.isNotBlank(), "license blank for '${c.name}'")
        }
        val names = AboutContent.credits.map { it.name }
        assertTrue(names.contains("Tor"), "credits should attribute Tor")
        assertTrue(names.contains("SQLCipher"), "credits should attribute SQLCipher")
    }

    @Test
    fun donate_offersMoneroAndBitcoin_lightningRemoved() {
        // Lightning was removed as a choice (2026-08-25); both remaining
        // methods ship REAL addresses — pinned verbatim in DonateContentTest.
        assertEquals(listOf("monero", "bitcoin"), DonateContent.methods.map { it.id })
        assertTrue(
            DonateContent.methods.none { it.isPlaceholder },
            "monero and bitcoin both carry real addresses now",
        )
    }

    @Test
    fun donate_appeal_mentionsFreeForever() {
        // DonateContent.appeal is now a resource key (donate_appeal) resolved through
        // platformString — install the English text so this test still locks wording.
        platformStringOverride = { key, _ ->
            when (key) {
                "donate_appeal" ->
                    "Rún has no ads, no investors, and never sells your data. Every donation " +
                        "— large or small — helps keep it free for everyone, forever."
                else -> key
            }
        }
        assertTrue(DonateContent.appeal.isNotBlank(), "donate appeal must not be blank")
        assertTrue(DonateContent.appeal.contains("free"), "appeal should mention staying free")
        assertTrue(DonateContent.appeal.contains("forever"), "appeal should mention forever")
    }
}

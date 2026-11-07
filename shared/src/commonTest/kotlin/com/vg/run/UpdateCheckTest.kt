package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The update nudge's version arithmetic. The input is RELAY-CONTROLLED, so the
 * property under test is fail-closed parsing: anything outside the closed
 * `MAJOR.MINOR.PATCH` grammar must yield null (never a nudge), and the only
 * string that may travel onward is the one re-rendered from the parsed triple.
 */
class UpdateCheckTest {

    // ---- rejected by the grammar ------------------------------------------

    @Test
    fun parse_rejectsWrongComponentCount() {
        assertNull(parseAppVersion("1.2"), "two components is not the grammar")
        assertNull(parseAppVersion("1"), "one component is not the grammar")
        assertNull(parseAppVersion("1.2.3.4"), "a fourth component must be refused")
        assertNull(parseAppVersion("1.2."), "a trailing dot leaves an empty component")
        assertNull(parseAppVersion(".1.2"), "a leading dot leaves an empty component")
        assertNull(parseAppVersion("1..2"), "an empty middle component must be refused")
        assertNull(parseAppVersion("..."))
    }

    @Test
    fun parse_rejectsPrefixesSuffixesAndSigns() {
        assertNull(parseAppVersion("v1.2.3"))
        assertNull(parseAppVersion("1.2.3-beta"))
        assertNull(parseAppVersion("1.2.3-rc1"))
        // `+1.2.3` is the exact case toIntOrNull would have accepted.
        assertNull(parseAppVersion("+1.2.3"))
        assertNull(parseAppVersion("-1.2.3"))
        assertNull(parseAppVersion("1.2.+3"))
    }

    @Test
    fun parse_rejectsWhitespace() {
        assertNull(parseAppVersion(" 1.2.3"), "a leading space must not be trimmed away")
        assertNull(parseAppVersion("1.2.3 "), "a trailing space must not be trimmed away")
        assertNull(parseAppVersion("1. 2.3"))
        assertNull(parseAppVersion("1.2.3\n"))
        assertNull(parseAppVersion("1.2.3\t"))
    }

    @Test
    fun parse_rejectsUnicodeDigits() {
        // Arabic-Indic ١.٤.٠ (U+0661 U+0664 U+0660) — `toIntOrNull` accepts these,
        // which is precisely why the gate is an explicit '0'..'9' range check.
        assertNull(parseAppVersion("١.٤.٠"))
        // Devanagari ३ and a full-width ３ in an otherwise valid string.
        assertNull(parseAppVersion("1.2.३"))
        assertNull(parseAppVersion("１.2.3"))
    }

    @Test
    fun parse_rejectsOverlongComponentsAndStrings() {
        assertNull(parseAppVersion("1.2.12345"), "a 5-digit component must be refused")
        assertNull(parseAppVersion("12345.2.3"))
        assertNull(parseAppVersion("1.12345.3"))
        // 15 chars — one past the cap, even though each component is legal.
        assertNull(parseAppVersion("9999.9999.9999".padStart(15, '0')))
    }

    @Test
    fun parse_rejectsEmptyAndNull() {
        assertNull(parseAppVersion(""))
        assertNull(parseAppVersion(null))
        assertNull(parseAppVersion("."))
        assertNull(parseAppVersion("abc"))
    }

    // ---- accepted by the grammar ------------------------------------------

    @Test
    fun parse_acceptsTheWholeLegalRange() {
        assertEquals(AppVersion(0, 0, 0), parseAppVersion("0.0.0"))
        assertEquals(AppVersion(12, 34, 5678), parseAppVersion("12.34.5678"))
        assertEquals(AppVersion(0, 8, 184), parseAppVersion("0.8.184"))
        // The longest legal string: exactly MAX_VERSION_CHARS.
        assertEquals(MAX_VERSION_CHARS, "9999.9999.9999".length)
        assertEquals(AppVersion(9999, 9999, 9999), parseAppVersion("9999.9999.9999"))
        // Leading zeros are digits — legal, and they normalise on render.
        assertEquals(AppVersion(1, 2, 3), parseAppVersion("0001.0002.0003"))
    }

    @Test
    fun render_rebuildsFromTheIntegersNotTheInput() {
        assertEquals("1.2.3", parseAppVersion("0001.0002.0003")?.render())
        assertEquals("0.0.0", AppVersion(0, 0, 0).render())
        assertEquals("9999.9999.9999", AppVersion(9999, 9999, 9999).render())
        // Round-trip: everything the parser accepts re-parses from its rendering.
        for (s in listOf("0.0.0", "12.34.5678", "9999.9999.9999", "1.0.0")) {
            assertEquals(parseAppVersion(s), parseAppVersion(parseAppVersion(s)!!.render()))
        }
    }

    // ---- ordering ----------------------------------------------------------

    @Test
    fun isNewerThan_isNumericNotLexicographic() {
        assertTrue(AppVersion(0, 10, 0).isNewerThan(AppVersion(0, 9, 0)),
            "10 > 9 numerically, even though \"10\" < \"9\" as text")
        assertTrue(AppVersion(0, 8, 200).isNewerThan(AppVersion(0, 8, 99)))
        assertTrue(AppVersion(1, 0, 0).isNewerThan(AppVersion(0, 9999, 9999)))
        assertFalse(AppVersion(0, 9, 0).isNewerThan(AppVersion(0, 10, 0)))
        assertFalse(AppVersion(1, 2, 3).isNewerThan(AppVersion(1, 2, 3)), "equal is not newer")
    }

    // ---- the fail-closed compare ------------------------------------------

    @Test
    fun isNewerVersion_returnsTheRemoteOnlyWhenStrictlyNewer() {
        assertEquals(AppVersion(0, 8, 185), isNewerVersion("0.8.185", "0.8.184"))
        assertEquals(AppVersion(1, 0, 0), isNewerVersion("1.0.0", "0.9999.9999"))
    }

    @Test
    fun isNewerVersion_isNullOnEqualOrLower() {
        assertNull(isNewerVersion("0.8.184", "0.8.184"), "equal must never nudge")
        assertNull(isNewerVersion("0.8.183", "0.8.184"), "lower must never nudge")
        assertNull(isNewerVersion("0.0.0", "0.8.184"))
    }

    @Test
    fun isNewerVersion_isNullWheneverEitherSideIsAmbiguous() {
        // Local unparseable — we cannot tell, so we must not nudge.
        assertNull(isNewerVersion("9.9.9", "1.2"))
        assertNull(isNewerVersion("9.9.9", ""))
        assertNull(isNewerVersion("9.9.9", null))
        assertNull(isNewerVersion("9.9.9", "0.8.184-debug"))
        // Remote absent / hostile.
        assertNull(isNewerVersion(null, "0.8.184"))
        assertNull(isNewerVersion("", "0.8.184"))
        assertNull(isNewerVersion("99999.0.0", "0.8.184"))
        assertNull(isNewerVersion("v99.0.0", "0.8.184"))
        assertNull(isNewerVersion(" 99.0.0", "0.8.184"))
        assertNull(isNewerVersion("٩.٩.٩", "0.8.184"))
        assertNull(isNewerVersion(null, null))
    }

    @Test
    fun isNewerVersion_resultRendersToTheCanonicalTriple() {
        // The ONLY value allowed downstream is this rendering, never the header.
        val v = isNewerVersion("0009.0008.0185", "0.8.184")
        assertNotNull(v)
        assertEquals("9.8.185", v.render())
    }

    @Test
    fun headerKey_isTheCommonNormalisedName() {
        // The transport actuals normalise `android-version` / `ios-version` onto
        // this single key; the nudge must read exactly that.
        assertEquals("app-version", UPDATE_NUDGE_HEADER_KEY)
        // The nudge deliberately owns its own lookup constant rather than
        // importing the transport's, so pin the two together here: if the
        // transport layer ever renames its key, this test fails instead of the
        // nudge silently reading a header nobody writes.
        assertEquals(APP_VERSION_HEADER_KEY, UPDATE_NUDGE_HEADER_KEY)
        // Same for the length cap the actuals enforce before the value is stored:
        // the parser's own ceiling must not be looser than the transport's.
        assertTrue(MAX_VERSION_CHARS <= MAX_APP_VERSION_HEADER_CHARS)
    }
}

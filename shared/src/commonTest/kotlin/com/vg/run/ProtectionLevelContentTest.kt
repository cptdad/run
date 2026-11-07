package com.vg.run

import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

// ProtectionLevelContent — single-sourced copy for the "Choose protection
// level" chooser. Pins the display-name rename (Decent/Secure/Maximum) and the
// exact tagline strings so Android/iOS can't drift (AboutContentTest sibling).
//
// LOCALIZATION: every property under test is now a resource key resolved
// through platformString. Tests that assert on ENGLISH WORDING install the
// same English text via platformStringOverride (the real copy lives only in
// strings_shared.xml now, locked separately by a JVM resources test); tests
// that only assert non-blank/shape don't need it — fail-soft key text is
// already non-blank.
class ProtectionLevelContentTest {

    @AfterTest
    fun tearDown() {
        platformStringOverride = null
    }

    private val english = mapOf(
        "protection_title" to "Choose protection level against forensic attacks",
        "protection_empty_state" to "Pick a level to continue. No level is chosen for you.",
        "protection_tier_name_casual" to "Decent",
        "protection_tier_name_private" to "Secure",
        "protection_tier_name_maximum" to "Maximum",
        "protection_tier_tagline_casual" to
            "Six digit pin code for opening Rún. Can be brute forced by forensic tools in hours, " +
                "so Rún relies fully on the phone protection. Keyboard suggestions and emoji stay " +
                "on, so the keyboard may learn words you type.",
        "protection_tier_tagline_private" to
            "Six digit pin code, but the vault key is sealed in the phone's security chip and " +
                "released only by your fingerprint or face. A seized phone resists forensic " +
                "brute-forcing even if its passcode is cracked. Keyboard suggestions and emoji " +
                "stay on, so the keyboard may learn words you type.",
        "protection_tier_tagline_maximum" to
            "A long passphrase instead of a pin code — strong enough that no forensic tool can " +
                "brute force it, even from an unlocked phone. The keyboard runs in password mode: " +
                "nothing you type is learned or suggested, and on Android the emoji key is " +
                "unavailable.",
        "protection_forced_notice_title" to "Your phone has no %1\$s",
        "protection_forced_notice_body" to
            "Without one, your passphrase is the only thing between your messages and anyone " +
                "holding this phone. So Rún runs at Maximum here.\n\n" +
                "It asks for that passphrase every time, locks after 60 seconds idle, and if you don’t " +
                "open Rún for 7 days it erases everything — permanently.\n\n" +
                "Set a passcode on your phone to choose a gentler level.",
        "protection_device_lock_term_android" to "lock screen",
        "protection_device_lock_term_ios" to "passcode",
    )

    private fun installEnglish() {
        platformStringOverride = { key, args -> formatPositional(english[key] ?: key, args) }
    }

    @Test
    fun displayName_isDecentSecureMaximum() {
        installEnglish()
        assertEquals("Decent", ProtectionLevelContent.displayName(ProtectionLevel.CASUAL))
        assertEquals("Secure", ProtectionLevelContent.displayName(ProtectionLevel.PRIVATE))
        assertEquals("Maximum", ProtectionLevelContent.displayName(ProtectionLevel.MAXIMUM))
    }

    @Test
    fun tagline_isNonBlank_forEveryLevel() {
        for (l in ProtectionLevel.entries) {
            assertTrue(ProtectionLevelContent.tagline(l).isNotBlank(), "tagline blank for $l")
        }
    }

    @Test
    fun tagline_mentionsExpectedMechanism() {
        installEnglish()
        // CASUAL/PRIVATE both unlock with a PIN; only MAXIMUM swaps to a passphrase.
        assertTrue(ProtectionLevelContent.tagline(ProtectionLevel.CASUAL).contains("pin code", ignoreCase = true))
        assertTrue(ProtectionLevelContent.tagline(ProtectionLevel.PRIVATE).contains("security chip"))
        assertTrue(ProtectionLevelContent.tagline(ProtectionLevel.MAXIMUM).contains("passphrase"))
    }

    @Test
    fun title_isNotBlank_andMentionsForensic() {
        installEnglish()
        assertTrue(ProtectionLevelContent.title.contains("forensic", ignoreCase = true))
    }

    @Test
    fun emptyState_matchesPreRenameCopyVerbatim() {
        installEnglish()
        assertEquals("Pick a level to continue. No level is chosen for you.", ProtectionLevelContent.emptyState)
    }

    @Test
    fun forcedNotice_titleEmbedsPlatformDeviceLockTerm() {
        installEnglish()
        // Android → "lock screen", iOS → "passcode" (protectionDeviceLockTerm actual).
        assertTrue(
            ProtectionLevelContent.forcedNoticeTitle == "Your phone has no lock screen" ||
                ProtectionLevelContent.forcedNoticeTitle == "Your phone has no passcode",
        )
    }

    @Test
    fun forcedNotice_bodyMentionsTheIrreversibleConsequence() {
        installEnglish()
        assertTrue(ProtectionLevelContent.forcedNoticeBody.contains("7 days"))
        assertTrue(ProtectionLevelContent.forcedNoticeBody.contains("permanently"))
    }
}

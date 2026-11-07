package com.vg.run

// ---------------------------------------------------------------------------
// Content for the "About" carousel and the "Support Rún" (donate) modal.
//
// Kept in commonMain so Android (Compose) and iOS (SwiftUI) render identical
// copy, and so the page set is unit-testable. Only the rendering is
// platform-specific. This content is static and vault-agnostic.
//
// LOCALIZATION: pages hold resource KEYS, not literal English text. `title`
// and `body` are `get()`s that resolve through [platformString] at render
// time — re-evaluated on every access, so a language change is picked up
// without reconstructing the list. Every key referenced here MUST exist in
// `androidApp/src/main/res/values/strings_shared.xml` (the single source of
// truth for both platforms — see L10n.kt).
// ---------------------------------------------------------------------------

/**
 * How an About page is rendered:
 *  - TEXT shows [AboutPage.glyph] above the title.
 *  - RUNESTONE_TOR   plays the runestone "dark → red" animation (Tor connected).
 *  - RUNESTONE_RELAY plays the "red → white centre ᚱ" animation (relay connected).
 *  - FORCEFIELD shows the lit runestone WITH the full blue forcefield (the
 *    shield shown around the runestone at the Maximum level) — used as the
 *    Forensic-safe page's visual.
 */
enum class AboutPageKind { TEXT, RUNESTONE_TOR, RUNESTONE_RELAY, FORCEFIELD }

// Screen-privacy body text — platform-specific because the guarantee differs:
// Android FLAG_SECURE genuinely blocks screenshots; iOS cannot
// prevent a manual hardware screenshot (only the app-switcher preview and screen
// recording are covered), so the iOS copy must not claim otherwise. The actual
// is a getter over the platform's own resource key (about_screen_privacy_body_android
// / _ios in strings_shared.xml), so it stays reactive to a language change.
internal expect val screenPrivacyBody: String

data class AboutPage(
    val kind: AboutPageKind,
    val glyph: String,   // emoji for TEXT pages; "" for the runestone / forcefield pages
    val titleKey: String,
    // null only for the one page (Screen privacy) whose body differs by PLATFORM as well
    // as by language — that page falls back to [screenPrivacyBody] instead.
    val bodyKey: String? = null,
) {
    val title: String get() = platformString(titleKey)
    val body: String get() = bodyKey?.let { platformString(it) } ?: screenPrivacyBody
}

object AboutContent {
    val pages: List<AboutPage> = listOf(
        // A deliberate arc: an opener that names Rún (the etymology) and states the hook,
        // then GET THERE UNSEEN (Tor) → PROTECT THE MESSAGE (E2E, dumb relay) → THE PEOPLE
        // (contacts, vouched intros, groups) → NOTHING SURVIVES ON THE DEVICE (vanish,
        // no-phone-home, lock/wipe, screen) → FORENSIC-SAFE, where the protection level you
        // pick (Casual / Private / Maximum) decides how hard the contents are to reach →
        // an invitation to begin. The runestone UI is taught beside the concept it signals.
        // Copy is skimmable (2–3 sentences) and true to what the code does — the lock/wipe
        // thresholds are per protection level (ProtectionLevel); the forensic page doesn't
        // overclaim the live-unlocked case; no unverifiable superlatives.
        AboutPage(AboutPageKind.TEXT, "ᚱ", "about_welcome_title", "about_welcome_body"),
        AboutPage(AboutPageKind.TEXT, "🧅", "about_tor_intro_title", "about_tor_intro_body"),
        AboutPage(AboutPageKind.RUNESTONE_TOR, "", "about_tor_runestone_title", "about_tor_runestone_body"),
        AboutPage(AboutPageKind.TEXT, "🔒", "about_e2e_title", "about_e2e_body"),
        AboutPage(AboutPageKind.TEXT, "📮", "about_relay_title", "about_relay_body"),
        AboutPage(AboutPageKind.RUNESTONE_RELAY, "", "about_relay_runestone_title", "about_relay_runestone_body"),
        AboutPage(AboutPageKind.TEXT, "👥", "about_contacts_title", "about_contacts_body"),
        AboutPage(AboutPageKind.TEXT, "🤝", "about_referrals_title", "about_referrals_body"),
        AboutPage(AboutPageKind.TEXT, "🫂", "about_groups_title", "about_groups_body"),
        AboutPage(AboutPageKind.TEXT, "👻", "about_vanish_title", "about_vanish_body"),
        AboutPage(AboutPageKind.TEXT, "🔕", "about_quiet_title", "about_quiet_body"),
        AboutPage(AboutPageKind.TEXT, "🛡️", "about_lockwipe_title", "about_lockwipe_body"),
        AboutPage(AboutPageKind.TEXT, "📵", "about_screen_privacy_title", bodyKey = null),
        AboutPage(AboutPageKind.FORCEFIELD, "", "about_forensic_title", "about_forensic_body"),
        AboutPage(AboutPageKind.TEXT, "👋", "about_ready_title", "about_ready_body"),
    )

    /**
     * The Tor version both platforms bundle — iOS via iCepa Tor.framework,
     * Android via info.guardianproject:tor-android (see
     * iosApp/SwiftTor-VERIFICATION.md). Shown in the About box; keep in sync
     * when Tor is bumped.
     */
    // Keep in sync with the bundled Tor: tor-android in shared/build.gradle.kts and
    // TOR_VERSION in iosApp/scripts/build-tor-xcframework.sh. security-deps-report.sh
    // asserts this matches the Android pin.
    val torVersion: String = "0.4.9.14"

    /**
     * Key open-source components Rún is built on, shown (with licenses) in the
     * About box. Several of these licenses require attribution. Static and
     * identical on both platforms (deniability-safe). Component/license names
     * are proper nouns — not localized.
     */
    val credits: List<AboutCredit> = listOf(
        AboutCredit("Tor", "BSD 3-Clause"),
        AboutCredit("OpenSSL", "Apache 2.0"),
        AboutCredit("libevent", "BSD 3-Clause"),
        AboutCredit("liblzma (xz)", "0BSD"),
        AboutCredit("SQLCipher", "BSD 3-Clause"),
    )
}

/** One bundled open-source component, credited in the About box. */
data class AboutCredit(val name: String, val license: String)

/** Sentinel address meaning "no address configured"; see [DonateMethod.isPlaceholder]. */
const val DONATE_TBA = "TBA"

data class DonateMethod(
    val id: String,       // stable id, used for the segment accessibility id
    val label: String,
    val address: String,
) {
    /** True while [address] is still the TBA placeholder — the UI then hides
     *  the QR/Copy and shows a "coming soon" state instead. */
    val isPlaceholder: Boolean get() = address == DONATE_TBA || address.isBlank()
}

object DonateContent {
    /** Mission line shown at the top of the Support modal, above the methods. */
    val appeal: String get() = platformString("donate_appeal")

    // Real donation addresses (2026-08-25). Lightning was REMOVED as a choice
    // by design — a Lightning invoice/offer is not a static address and
    // would need its own infrastructure. DonateContentTest pins these strings
    // literally: a silent edit to a donation address means lost funds. Method
    // labels ("Monero"/"Bitcoin") and addresses are NOT localized.
    val methods: List<DonateMethod> = listOf(
        DonateMethod(
            "monero", "Monero",
            "47gkTtxs5McJfw1QKyaPMnPwdoWeePYQQZ7WvnDkkBsHWKWwN7e7nxwYRzV7PHwpYqPsjWa5qc5G4Efr8RFreJuwGk889oX",
        ),
        DonateMethod(
            "bitcoin", "Bitcoin",
            "bc1qkh3hgdt408tlcmdeac96l5v79ytul5mrrjupse",
        ),
    )
}

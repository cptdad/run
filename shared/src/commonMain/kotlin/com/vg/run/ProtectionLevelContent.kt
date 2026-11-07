package com.vg.run

// ---------------------------------------------------------------------------
// Content for the "Choose protection level" chooser (onboarding + Settings +
// the post-unlock migration screen).
//
// Kept in commonMain, mirroring AboutContent.kt, so Android (Compose) and iOS
// (SwiftUI) render identical title/labels/taglines/notices — only the slider
// mechanics and the hero morph stay platform-specific. Display names here are
// COSMETIC ONLY: the ProtectionLevel enum and its storageValue
// ("casual"/"private"/"maximum") are unchanged everywhere else (vault
// persistence, a11y ids, e2e) — renaming those would silently orphan every
// provisioned install's level and break the cross suites.
//
// LOCALIZATION: every property below is a `get()` resolving a resource key
// through [platformString] at render time, so a language change is picked up
// without reconstructing anything. Every key referenced here MUST exist in
// `androidApp/src/main/res/values/strings_shared.xml`.
// ---------------------------------------------------------------------------

// Platform term for "the phone's screen lock" — used in the forced-notice
// title and (via DeviceLockPolicy) the "no lock" stop-reason. Android calls it
// a "lock screen"; iOS calls it a "passcode" (actual beside AboutContent's
// screenPrivacyBody).
internal expect val protectionDeviceLockTerm: String

object ProtectionLevelContent {
    val title: String get() = platformString("protection_title")

    /** Detail-panel copy shown before any tier has been picked (bare-forced
     *  onboarding) — verbatim from the pre-rename copy. */
    val emptyState: String get() = platformString("protection_empty_state")

    /** Prefix for the greyed-tier explanation, shown only when the chosen tier is
     *  itself unavailable: "Not possible to select level. <DeviceLockPolicy reason>". */
    val stopReasonPrefix: String get() = platformString("protection_stop_reason_prefix")

    /** Display-only tier name (Decent / Secure / Maximum). Never persisted and
     *  never compared — use [ProtectionLevel.storageValue] / the enum itself
     *  for anything else. */
    fun displayName(level: ProtectionLevel): String = when (level) {
        ProtectionLevel.CASUAL -> platformString("protection_tier_name_casual")
        ProtectionLevel.PRIVATE -> platformString("protection_tier_name_private")
        ProtectionLevel.MAXIMUM -> platformString("protection_tier_name_maximum")
    }

    fun tagline(level: ProtectionLevel): String = when (level) {
        ProtectionLevel.CASUAL -> platformString("protection_tier_tagline_casual")
        ProtectionLevel.PRIVATE -> platformString("protection_tier_tagline_private")
        ProtectionLevel.MAXIMUM -> platformString("protection_tier_tagline_maximum")
    }

    // ---- Storage-string overloads (iOS convenience) ------------------------
    // The SwiftUI side keys tiers by their storageValue ("casual"/"private"/
    // "maximum") — the same strings it passes to the controller's selectability
    // APIs — so it never touches the ProtectionLevel enum (whose `PRIVATE` entry
    // would need keyword-escaping in Swift). These resolve the string the same
    // way ProtectionLevel.fromStorageOrNull does (incl. the retired "hardened"
    // → PRIVATE forward-map); an unknown string can't occur from the fixed
    // levelCards ids, but falls back to the enum default rather than throwing.
    fun displayName(storageValue: String): String =
        displayName(ProtectionLevel.fromStorageOrNull(storageValue) ?: ProtectionLevel.DEFAULT)

    fun tagline(storageValue: String): String =
        tagline(ProtectionLevel.fromStorageOrNull(storageValue) ?: ProtectionLevel.DEFAULT)

    /** Title of the non-dismissable notice shown when DeviceLockPolicy forces a
     *  tier because this phone has no screen lock at all. */
    val forcedNoticeTitle: String get() = platformString("protection_forced_notice_title", protectionDeviceLockTerm)

    /** Body of that same notice — identical wording on both platforms already
     *  (only the title's device-lock term differed), carried over verbatim. */
    val forcedNoticeBody: String get() = platformString("protection_forced_notice_body")
}

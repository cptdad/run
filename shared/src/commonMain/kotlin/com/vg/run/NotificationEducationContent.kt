package com.vg.run

// ---------------------------------------------------------------------------
// Content for the notification opt-in carousel (Tier-1 Android / Tier-2 iOS).
//
// Kept in commonMain — same single-source pattern as AboutContent.kt — so
// Android (Compose) and iOS (SwiftUI) render identical copy. Unified model:
// every page is one statement plus a "Technical details" deep-dive block
// (three pages + the switch since 2026-09-11). Only the platform-specific vendor/service names
// diverge, via expect/actual.
//
// LOCALIZATION: pages hold resource KEYS (titleKey/deepKey), not literal
// English text — resolved through [platformString] at render time. The
// vendor/service/cross-ref fragments are themselves key-resolved (see the
// expect vals below) and substituted positionally (%1$s etc.) via lazily
// evaluated arg lists, so BOTH the page copy and the vendor fragment stay
// reactive to a language change. Every key referenced here MUST exist in
// `androidApp/src/main/res/values/strings_shared.xml`.
// ---------------------------------------------------------------------------

internal expect val notifVendorName: String
internal expect val notifServiceName: String
internal expect val notifCrossRefLabel: String

class NotifEduPage(
    val titleKey: String,
    val deepKey: String? = null,
    val disclosureTag: String? = null,
    private val titleArgs: () -> List<Any?> = { emptyList() },
    private val deepArgs: () -> List<Any?> = { emptyList() },
) {
    val title: String get() = platformString(titleKey, *titleArgs().toTypedArray())
    val deep: String? get() = deepKey?.let { platformString(it, *deepArgs().toTypedArray()) }
}

object NotificationEducationContent {
    // Since 2026-09-11: FOUR pages in total — three of these plus
    // the switch. Each page is one short statement; everything technical lives
    // under its "Technical details" disclosure (deepKey).
    val pages: List<NotifEduPage> = listOf(
        NotifEduPage(
            titleKey = "notif_edu_vendor_title",
            deepKey = "notif_edu_vendor_deep",
            disclosureTag = "vendor_push_disclosure",
            titleArgs = { listOf(notifVendorName) },
            deepArgs = { listOf(notifServiceName, notifVendorName, notifCrossRefLabel) },
        ),
        NotifEduPage(
            titleKey = "notif_edu_timing_title",
            deepKey = "notif_edu_timing_deep",
            titleArgs = { listOf(notifVendorName) },
            deepArgs = { listOf(notifVendorName) },
        ),
        NotifEduPage(
            titleKey = "notif_edu_content_safe_title",
            deepKey = "notif_edu_content_safe_deep",
            titleArgs = { listOf(notifVendorName) },
            deepArgs = { listOf(notifVendorName) },
        ),
    )

    val switchTitle: String get() = platformString("notif_edu_switch_title")
}

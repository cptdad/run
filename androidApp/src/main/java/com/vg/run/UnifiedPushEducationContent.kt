package com.vg.run

import android.content.Context

// ---------------------------------------------------------------------------
// UnifiedPushEducationContent — the opt-in carousel copy for the UnifiedPush
// (Google-free) notification tier.
//
// ANDROID-LOCAL ON PURPOSE. It reuses the shared [NotifEduPage] shape so
// NotificationSettingsModal renders it with the same EduPageView, but it does
// NOT live in commonMain and does NOT touch [NotificationEducationContent]:
// that object renders on iOS too, where UnifiedPush does not and will not
// exist. Editing the shared object to describe distributors would put copy
// about an Android-only transport in front of iOS users.
//
// LOCALIZATION: [pages] hold resource KEYS (titleKey/deepKey), not literal
// English text — [NotifEduPage.title]/[.deep] resolve them through the same
// commonMain [platformString] the shared FCM carousel uses, so every
// notif_edu_up_* key referenced below MUST exist in
// `androidApp/src/main/res/values/strings_shared.xml`. [switchTitle] and the
// no-distributor / unregistered-notice copy are plain Android-local strings
// (never rendered through platformString) and are resolved via a supplied
// [Context] against `strings_settings.xml` instead.
//
// HONESTY RULES for this copy (they are why the wording is what it is):
//  • Name the extra party. FCM has one intermediary; this has TWO — the
//    distributor APP on the device and the push SERVER it talks to. Both learn
//    wake timing. Saying "Google-free" without saying that would be selling a
//    privacy win the user doesn't fully get.
//  • Do not oversell ntfy.sh. The default public ntfy server is a clearnet
//    third party and sees the same timing pattern (plus this device's IP,
//    which Google would also see). It is recommended because it works and is
//    self-hostable, not because it is private by default.
//  • Do not claim the content is protected by the transport alone: say what is
//    actually true — the wake carries nothing, and the messages are fetched
//    over Tor after unlock.
// ---------------------------------------------------------------------------

object UnifiedPushEducationContent {

    /** Recommended distributor (F-Droid listing) — also the target of the
     *  `notif_no_distributor_install_link` action on the no-distributor page. */
    const val NTFY_FDROID_URL = "https://f-droid.org/packages/io.heckel.ntfy/"

    // Since 2026-09-11: three pages + the switch, like the shared
    // FCM carousel; the technical detail lives under each page's disclosure.
    val pages: List<NotifEduPage> = listOf(
        NotifEduPage(
            "notif_edu_up_distributor_title",
            "notif_edu_up_distributor_deep",
            "unified_push_disclosure",
        ),
        NotifEduPage(
            "notif_edu_up_parties_title",
            "notif_edu_up_parties_deep",
        ),
        NotifEduPage(
            "notif_edu_up_content_safe_title",
            "notif_edu_up_content_safe_deep",
        ),
    )

    /** Byte-identical to the shared FCM carousel's switch title — reuses that
     *  compiled string resource rather than duplicating the key. */
    fun switchTitle(context: Context): String =
        context.getString(R.string.notif_edu_switch_title)

    /** Shown on the no-distributor page (a11y `notif_unavailable`), replacing
     *  the old dead "not available" line. */
    fun noDistributorMessage(context: Context): String =
        context.getString(R.string.notif_settings_no_distributor_message)

    /** The tappable line beneath it (a11y `notif_no_distributor_install_link`). */
    fun noDistributorLinkLabel(context: Context): String =
        context.getString(R.string.notif_settings_no_distributor_link_label)

    /** One-shot line after the distributor drops our registration
     *  (a11y `notif_unregistered_notice`). */
    fun unregisteredNotice(context: Context): String =
        context.getString(R.string.notif_settings_unregistered_notice)
}

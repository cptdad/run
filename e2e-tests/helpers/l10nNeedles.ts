/**
 * Localized substrings ("needles") for the few physical-device e2e selectors
 * that must match VISIBLE app text (not an accessibility id).
 *
 * WHY: the iPhone SE and Pixel 7 run the app in Arabic (see `AppLocale.ts` —
 * `ARABIC_TEST_UDIDS` / `resolveDeviceLanguageTag`). A selector hardcoded to
 * English would miss the localized label on those devices.
 *
 * IMPORTANT — always accept English too. Some strings are rendered through the
 * shared-copy bridge / a `context` that does not always carry the per-app
 * language override (observed 2026-09-01: on an Arabic-pinned Pixel the
 * screenshot-notice BODY rendered in English while the timestamp rendered in
 * Arabic). So these matchers OR the device-language needle WITH English rather
 * than betting on one. Assertions that only need to prove "the right kind of
 * element is present" should anchor on its a11y id and NOT on body text at all
 * (see cross-platform.multi.spec.ts screenshot-notice checks, which assert the
 * language-independent "· HH:mm" timestamp instead).
 *
 * Keep needles in sync with the source resources named in the comments.
 */

// androidApp/src/main/res/values{,-ar,-fa}/strings_contact_list.xml : referral_connecting
//   en "Connecting…" / ar "جارٍ الاتصال…" / fa "در حال اتصال…"
// Core word only (drops the ellipsis; case-stable). "اتصال" is shared by ar+fa.
const CONNECTING: Record<string, string> = {
    ar: 'اتصال',
    fa: 'اتصال',
    sv: 'Ansluter',   // defence in depth: the Pixel's system locale (see Device.resetAndroid re-pin)
}

// androidApp/src/main/res/values{,-*}/strings_system.xml : notification_title
// The push notification's TITLE — localized, so a dumpsys `android.title=String
// (…)` assertion must expect the device-language value, NOT the English literal
// (an Arabic-pinned Pixel posts "android.title=String (إشعار)"). This is the
// title text, not a structural token.
const NOTIFICATION_TITLE: Record<string, string> = {
    en: 'Notification',
    sv: 'Notis',
    de: 'Benachrichtigung',
    fr: 'Notification',
    es: 'Notificación',
    nb: 'Varsel',
    da: 'Notifikation',
    fi: 'Ilmoitus',
    ar: 'إشعار',
    fa: 'اعلان',
}

/** The localized push-notification title for [langTag] (the value inside a
 *  dumpsys `android.title=String (…)`). Falls back to English. */
export function notificationTitleNeedle(langTag: string): string {
    return NOTIFICATION_TITLE[langTag] ?? NOTIFICATION_TITLE.en
}

// The referral consent button's two label states — referral_approve (idle) and
// common_retry (after a failed attempt). The RuneDialog uppercases Latin labels;
// Arabic/Persian have no case.
const REFERRAL_APPROVE: Record<string, string> = { en: 'Approve', ar: 'موافقة', fa: 'تأیید', sv: 'Godkänn' }
const REFERRAL_RETRY: Record<string, string> = { en: 'Retry', ar: 'إعادة المحاولة', sv: 'Försök igen' }

/** Labels the referral consent button can show for [langTag] — approve + retry,
 *  each plus the English fallback (some render paths / older builds stay English).
 *  Used by Device.referralApproveOrRetryButton as the FALLBACK half of its
 *  selector (it prefers the stable `referral_approve` a11y id since 2026-09-15);
 *  these needles still carry every pre-id / flattened-dialog binary. */
export function referralApproveRetryLabels(langTag: string): string[] {
    const out = new Set<string>(['Approve', 'Retry'])
    out.add(REFERRAL_APPROVE[langTag] ?? 'Approve')
    out.add(REFERRAL_RETRY[langTag] ?? 'Retry')
    return [...out]
}

/** Acceptable "Connecting…" label fragments for [langTag] — the device language
 *  needle (if any) plus English, which some render paths fall back to. */
export function connectingNeedles(langTag: string): string[] {
    const out = ['Connecting']
    const loc = CONNECTING[langTag]
    if (loc && !out.includes(loc)) out.push(loc)
    return out
}

/** `contains(@text, …)` terms for the referral "Connecting…" label. Compose can
 *  uppercase Latin labels via style, so each Latin needle yields both cases;
 *  Arabic/Persian (no case) yield one term. */
export function connectingXpathTerms(langTag: string): string[] {
    const terms = new Set<string>()
    for (const n of connectingNeedles(langTag)) {
        terms.add(n)
        terms.add(n.toUpperCase())
    }
    return [...terms]
}

// androidApp/src/main/res/values{,-sv,-de,...}/strings_contact_list.xml : nudge_message
// iosApp/iosApp/L10n.swift : nudgeMessage. RuneDialog/RuneDialogMessage render
// this uppercased (Android via `.uppercase()`, iOS via `.uppercased()`) — kept
// lowercase here since every call site lowercases the page source first
// (update-nudge.spec.ts, update-nudge-layout.spec.ts).
const NUDGE_MESSAGE: Record<string, string> = {
    en: 'new version available',
    sv: 'ny version tillgänglig',
    de: 'neue version verfügbar',
}

/** The localized update-nudge body copy for [langTag] (lowercase, matching
 *  the `src.toLowerCase().includes(...)` call sites). Falls back to English —
 *  see this file's header for why every needle here does the same. */
export function nudgeMessageNeedle(langTag: string): string {
    return NUDGE_MESSAGE[langTag] ?? NUDGE_MESSAGE.en
}

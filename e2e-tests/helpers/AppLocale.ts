/**
 * App-language pin for the e2e harness.
 *
 * WHY: the bench devices are not English — the Pixel 7 runs at system locale
 * sv-SE — and Rún is localized (sv/de/fr/es/nb/da/fi). Every spec matches ids
 * first, but a handful still read visible English text ("Connecting…",
 * "New version available", dumpsys `android.title=String (Notification)`), so
 * the app itself is pinned to English PER APP, never by changing the device
 * locale:
 *
 *  - Android, PRIMARY lever: the DEBUG-only `--es test_language <tag>` intent
 *    extra on the launch `am start` (MainActivity → TestHooks.handleTestLanguage
 *    → AppLocale.apply) — the exact sibling of iOS's `--test-language=`. It is
 *    applied AFTER the TEST_WIPE hook in the same onCreate, so the wipe's
 *    locale reset on wipe can no longer un-pin the first frame, and it works on
 *    EVERY supported API level.
 *  - Android, SECONDARY lever: `cmd locale set-app-locales <pkg> --locales
 *    en-US`. API 33+ ONLY. The old header claimed "every bench target is 33+";
 *    that stopped being true when the Samsung A20e (API 30) joined the bench,
 *    and on that phone this lever silently does nothing — which is exactly the
 *    failure this file must never produce quietly (a Swedish phone running an
 *    English-asserting spec makes every text-ABSENCE assertion pass falsely).
 *    Kept as a second lever because it ALSO pins release builds and survives
 *    launches the harness doesn't issue itself.
 *  - iOS: `-AppleLanguages (en)` launch argument plus the DEBUG-only
 *    `--test-language=en` that RunApp persists into AppleLanguages so arg-less
 *    relaunches (Tor recovery, jetsam) stay pinned. Language only — no
 *    `-AppleLocale`, which would flip times to 12-hour.
 *
 * [pinAndroidAppLocale] therefore HARD-FAILS when neither lever could be
 * applied (sub-33 device + a launch that carried no extra). It used to warn and
 * continue; a warning in a 40-minute multiremote log is indistinguishable from
 * success, and the spec that then "passes" proves nothing.
 *
 * `WDIO_APP_LANG=<tag>` overrides the pinned language (default `en`) — used
 * by the localization screenshot sweep (`tests/l10n-sweep.spec.ts`) to drive
 * the real onboarding in another language.
 *
 * The physical-device suite (not published) runs in ENGLISH by
 * default too (see [resolveDeviceLanguageTag]); Arabic/RTL is exercised via
 * single-device runs with `WDIO_APP_LANG=ar` rather than by auto-pinning
 * specific UDIDs, which made the label/text selectors across Device.ts fragile.
 */

const REGION: Record<string, string> = {
    en: 'en-US', sv: 'sv-SE', de: 'de-DE', fr: 'fr-FR',
    es: 'es-ES', nb: 'nb-NO', da: 'da-DK', fi: 'fi-FI',
    // ar/fa are region-agnostic in the app (values-ar/, values-fa/); bare tags
    // are what `cmd locale set-app-locales` and `-AppleLanguages` want.
    ar: 'ar', fa: 'fa',
    // so has no region variant the app cares about; ru/mk take the Play-style region tag.
    so: 'so', ru: 'ru-RU', mk: 'mk-MK',
}

/**
 * Per-device language tag for the multiremote (physical) path.
 *
 * SCOPE DECISION 2026-09-02: the multi-device group/referral cross suites run in
 * ENGLISH by default. Auto-pinning the SE/Pixel to Arabic by UDID made the many
 * label/text-based selectors across Device.ts fragile (referral consent, group
 * join, delete-contact, "Group · admin", …). Arabic/RTL is exercised via
 * single-device runs (`WDIO_APP_LANG=ar`) instead, and the app itself ships
 * ar/fa (verified on device). Set `WDIO_APP_LANG=ar` to opt a whole run into
 * Arabic — the locale-aware selectors/needles (l10nNeedles.ts) then keep it
 * green. `udid` is kept for call-site compatibility but no longer selects a
 * language on its own.
 */
export function resolveDeviceLanguageTag(_udid?: string): string {
    return appLanguageTag()
}

/** BCP-47 language tag the harness pins the app to (default `en`). */
export function appLanguageTag(): string {
    const t = (process.env.WDIO_APP_LANG ?? 'en').trim()
    return REGION[t] ? t : 'en'
}

/** Language-region tag for `cmd locale set-app-locales`. */
export function appLocaleTag(): string {
    return REGION[appLanguageTag()]
}

/** iOS launch arguments that pin the app language (see header).
 *  `WDIO_IOS_APP_LANG` overrides for iOS ONLY (e.g. a Swedish iPhone receiver
 *  in the push suite while the Android peer stays English for its dumpsys
 *  text asserts); otherwise `WDIO_APP_LANG`, otherwise `en`. */
export function iosLanguageArgs(deviceTag?: string): string[] {
    const ios = (process.env.WDIO_IOS_APP_LANG ?? '').trim()
    const t = REGION[ios] ? ios : (deviceTag ?? appLanguageTag())
    return [`--test-language=${t}`, '-AppleLanguages', `(${t})`]
}

/** The intent-extra key MainActivity/TestHooks.handleTestLanguage reads.
 *  Renaming it here alone silently unpins every device — the Android unit
 *  guard (TestLanguageHookSourceTest) pins both ends of that coupling. */
export const ANDROID_LANG_EXTRA = 'test_language'

/** The `--locales` / intent-extra tag for [deviceTag] (or the run default), so
 *  BOTH Android levers always pin the SAME language-region tag. */
export function androidLocaleTagFor(deviceTag?: string): string {
    return deviceTag ? (REGION[deviceTag] ?? appLocaleTag()) : appLocaleTag()
}

/**
 * `am start` extras that pin the app language — the PRIMARY Android lever (see
 * the header). Append these next to `--ez TEST_WIPE true` on every cold launch
 * the harness issues itself; the app consumes the extra one-shot (it relaunches
 * the Activity to apply the language, and the relaunch re-delivers the same
 * Intent).
 *
 * DEBUG builds only, by construction: the release `TestHooks.handleTestLanguage`
 * is a no-op stub, so a release APK ignores the extra entirely. Every e2e suite
 * installs the debug APK.
 */
export function androidLanguageIntentArgs(deviceTag?: string): string[] {
    return ['--es', ANDROID_LANG_EXTRA, androidLocaleTagFor(deviceTag)]
}

/** Same extras as one string, for `appium:optionalIntentArguments` (the
 *  session's OWN launch intent, which the harness never issues by hand). */
export function androidLanguageIntentString(deviceTag?: string): string {
    return androidLanguageIntentArgs(deviceTag).join(' ')
}

export interface AndroidLocalePinOptions {
    /**
     * TRUE when the launch this pin belongs to carries
     * [androidLanguageIntentArgs] (the caller's own `am start`, or the
     * session's `appium:optionalIntentArguments`). That extra is the lever
     * that works below API 33, so it is what keeps this call from hard-failing
     * on the API-30 bench phone.
     */
    viaLaunchExtra?: boolean
}

/** `ro.build.version.sdk`, cached per device — null when unreadable. */
const sdkIntCache = new Map<string, number | null>()

function deviceSerial(driver: WebdriverIO.Browser): string {
    const caps = driver.capabilities as any
    return caps?.['appium:udid'] || caps?.udid || caps?.['appium:deviceName'] || '<unknown device>'
}

async function androidSdkInt(driver: WebdriverIO.Browser): Promise<number | null> {
    const serial = deviceSerial(driver)
    if (sdkIntCache.has(serial)) return sdkIntCache.get(serial) ?? null
    let sdk: number | null = null
    try {
        const out = await driver.execute('mobile: shell',
            { command: 'getprop', args: ['ro.build.version.sdk'] })
        const n = parseInt(String(out ?? '').trim(), 10)
        sdk = Number.isFinite(n) ? n : null
    } catch { /* unreadable — treated as "unknown", see the call site */ }
    sdkIntCache.set(serial, sdk)
    return sdk
}

/**
 * Pin the app's language on ONE Android device.
 *
 * Applies the `cmd locale` lever when the device can have it (API 33+, or an
 * unreadable SDK — try rather than assume), VERIFIES it by reading the override
 * back (a `cmd` that prints an error to stdout does not necessarily throw), and
 * treats the caller's launch extra as the other lever.
 *
 * THROWS when neither lever applied — naming the serial and the SDK, because
 * the two realistic causes are "this phone is below 33" and "a new cold-launch
 * path forgot the extra", and a warn-and-continue here produces a whole suite
 * of falsely-passing text assertions (see the header).
 */
export async function pinAndroidAppLocale(
    driver: WebdriverIO.Browser,
    bundleId = 'com.vg.run',
    deviceTag?: string,
    opts: AndroidLocalePinOptions = {},
): Promise<void> {
    const locale = androidLocaleTagFor(deviceTag)
    const sdk = await androidSdkInt(driver)
    let cmdLocale = false
    if (sdk === null || sdk >= 33) {
        try {
            await driver.execute('mobile: shell', {
                command: 'cmd',
                args: ['locale', 'set-app-locales', bundleId, '--locales', locale],
            })
            const readBack = String(await driver.execute('mobile: shell', {
                command: 'cmd',
                args: ['locale', 'get-app-locales', bundleId],
            }) ?? '')
            cmdLocale = localeReadBackMatches(readBack, locale)
            if (!cmdLocale) {
                console.warn(`pinAndroidAppLocale(${deviceSerial(driver)}): cmd locale set-app-locales `
                    + `did not read back as "${locale}" (got: ${readBack.trim() || '<empty>'})`)
            }
        } catch (e: any) {
            console.warn(`pinAndroidAppLocale(${deviceSerial(driver)}): cmd locale lever failed `
                + `(${e?.message ?? e})`)
        }
    }
    if (cmdLocale || opts.viaLaunchExtra) return
    throw new Error(
        `pinAndroidAppLocale: cannot pin ${bundleId} to "${locale}" on ${deviceSerial(driver)} `
        + `(SDK ${sdk ?? 'unknown'}): the \`cmd locale\` lever is API 33+ and did not apply, and this `
        + `launch carried no \`--es ${ANDROID_LANG_EXTRA}\` extra. Add `
        + `androidLanguageIntentArgs() to the am start (and pass { viaLaunchExtra: true }) — `
        + `refusing to run a localized device against English text assertions, which would pass falsely.`,
    )
}

/**
 * Does `cmd locale get-app-locales` report [locale]? Scoped to the bracketed
 * LocaleList (`… are [en-US]`) so a bare language tag can't accidentally match
 * the surrounding prose — "ar" is a substring of "are" in that very sentence.
 * Exported for the same reason it is a separate function: it is the one piece
 * of this file that is pure and worth reasoning about on its own.
 */
export function localeReadBackMatches(readBack: string, locale: string): boolean {
    const bracketed = readBack.match(/\[([^\]]*)\]/)
    const listed = bracketed ? bracketed[1] : readBack
    const norm = (s: string) => s.toLowerCase().replace(/[^a-z0-9]/g, '')
    return norm(listed).includes(norm(locale))
}

import { Ids, byId } from '../helpers/AccessibilityIds'
import {
    enterPin,
    waitForPinScreen,
    completePinSetup,
    dismissPushPromptIfPresent,
} from '../helpers/PinHelper'
import { resetApp, relaunchApp } from '../helpers/AppReset'

const REAL_PIN = '111111'
const isAndroid = () => process.env.WDIO_PLATFORM === 'android'

/** Opens the cogwheel menu and returns the "Language" row (does NOT tap it). */
async function openSettingsAndFindLanguageRow() {
    const settings = await $(byId(Ids.settingsButton))
    await settings.waitForDisplayed({ timeout: 10_000 })
    await settings.click()
    const row = await $(byId(Ids.menuLanguage))
    await row.waitForDisplayed({ timeout: 5_000 })
    return row
}

/** Visible label of the Language row. On Android the Compose menu item's own
 *  node carries no `text` (it lives on the child Text node), so fall back to
 *  the first descendant that has text. */
async function languageRowText(): Promise<string> {
    const row = await openSettingsAndFindLanguageRow()
    let text = (await row.getText()).trim()
    if (!text && isAndroid()) {
        const child = await $(`//*[@resource-id="${Ids.menuLanguage}"]//*[string-length(@text) > 0]`)
        if (await child.isExisting()) text = (await child.getText()).trim()
    }
    return text
}

/** Android only: opens the picker and taps the given option id. */
async function switchLanguage(optionId: string): Promise<void> {
    const row = await openSettingsAndFindLanguageRow()
    await row.click()
    const picker = await $(byId(Ids.languagePicker))
    await picker.waitForDisplayed({ timeout: 5_000 })
    const option = await $(byId(optionId))
    await option.waitForDisplayed({ timeout: 5_000 })
    await option.click()
}

/**
 * Localization — the in-app language picker.
 *
 * The harness pins the app language to English (per-app locale on Android,
 * -AppleLanguages on iOS) so every other spec runs in English regardless of
 * the device locale. This spec is the one place that deliberately switches
 * language, and it verifies two things a language change could break:
 *
 *  1. The LocaleManager relaunch is recognised as a configuration change —
 *     the vault stays open (no PIN screen, `unlocked_root` survives). The
 *     whole-session teardown in MainActivity.onStop fires only for
 *     NON-config-change stops; a regression there would lock the user out
 *     on every language switch.
 *  2. The UI actually re-renders in the chosen language (the "Language" row
 *     itself reads "Sprache" under de), and switching back to "System
 *     default" restores English (the pinned per-app locale).
 *
 * Runs after `relaunchApp()` so the TEST_WIPE launch extra is gone: a
 * config-change relaunch re-delivers the same Intent, and the debug hook
 * consumes the extra defensively, but the spec must not depend on that.
 *
 * iOS: the row opens Apple's Settings (per-app language) — there is no
 * in-app picker by design, so only the row's presence is checked.
 */
describe('Language picker', () => {

    before(async () => {
        await resetApp()
        await waitForPinScreen()
        await completePinSetup(REAL_PIN)
        await (await $(byId(Ids.unlockedRoot))).waitForDisplayed({ timeout: 30_000 })
        await dismissPushPromptIfPresent()
        // Drop the TEST_WIPE launch extra before any config-change relaunch.
        // A debug cold start on the emulator takes 5–27 s to first frame
        // (ActivityTaskManager "Displayed … +NNs"), so give the PIN screen
        // well beyond the 15 s default.
        await relaunchApp()
        await waitForPinScreen(45_000)
        await enterPin(REAL_PIN)
        await (await $(byId(Ids.unlockedRoot))).waitForDisplayed({ timeout: 30_000 })
        await dismissPushPromptIfPresent()
    })

    it('shows a Language row in the settings menu', async () => {
        const row = await openSettingsAndFindLanguageRow()
        expect(await row.isDisplayed()).toBe(true)
        // Close the menu/sheet again without acting.
        await driver.back().catch(() => undefined)
        if (!isAndroid()) {
            const done = await $(byId('settings_sheet_done'))
            if (await done.isExisting()) await done.click()
        }
    })

    // The in-app switch exists on Android only (iOS hands off to Settings), so
    // the two tests below are REGISTERED only on Android — a runtime
    // `this.skip()` is reported as a failure by the harness's afterTest hook.
    if (!isAndroid()) return

    it('switching to German keeps the vault open and re-renders the UI', async () => {
        await switchLanguage(Ids.languageOption('de'))

        // The LocaleManager relaunch must land back on the unlocked root —
        // never on the PIN screen.
        const root = await $(byId(Ids.unlockedRoot))
        await root.waitForDisplayed({ timeout: 20_000 })
        expect(await (await $(byId(Ids.pinDots))).isExisting()).toBe(false)

        try {
            expect(await languageRowText()).toBe('Sprache')
        } finally {
            await driver.back()   // close the menu even on a failed assertion
        }
    })

    it('switching back to English restores the English UI', async () => {
        // Explicit "en", not "System default": on a Swedish-locale bench phone
        // (the Pixel 7 is sv-SE) "System default" would legitimately render
        // Swedish. The harness's own English pin is a per-app locale too, so
        // selecting "en" here re-establishes exactly the pinned state.
        await switchLanguage(Ids.languageOption('en'))

        const root = await $(byId(Ids.unlockedRoot))
        await root.waitForDisplayed({ timeout: 20_000 })
        expect(await (await $(byId(Ids.pinDots))).isExisting()).toBe(false)

        try {
            expect(await languageRowText()).toBe('Language')
        } finally {
            await driver.back()
        }
    })
})

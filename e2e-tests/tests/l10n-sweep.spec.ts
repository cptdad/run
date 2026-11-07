import { mkdirSync } from 'fs'
import { resolve } from 'path'
import { Ids, byId } from '../helpers/AccessibilityIds'
import {
    waitForPinScreen,
    completePinSetup,
    dismissPushPromptIfPresent,
    dismissPostConnectModalsIfPresent,
} from '../helpers/PinHelper'
import { resetApp } from '../helpers/AppReset'
import { appLanguageTag } from '../helpers/AppLocale'
import * as MockRelay from '../helpers/MockRelay'
import { swipeLeft } from '../helpers/Gestures'

/**
 * Localization screenshot sweep — visual QA for translated builds.
 *
 * NOT a regression test: it walks the screens that carry the most copy and
 * saves a screenshot of each under `e2e-tests/screenshots/l10n/<platform>/<lang>/` so a
 * human (or the orchestrating session) can eyeball overflow, clipping and
 * awkward line breaks. Runs ONLY when `WDIO_L10N_SWEEP=1`; the language comes
 * from `WDIO_APP_LANG` (the harness's per-app language pin), e.g.
 *
 *   WDIO_L10N_SWEEP=1 WDIO_APP_LANG=de WDIO_SPEC=tests/l10n-sweep.spec.ts \
 *     npm run test:emulator:android
 *
 * Every navigation is id-based, so the walk itself is language-independent.
 * Steps are best-effort (a missing screen is logged, never fails the sweep).
 */
const ENABLED = process.env.WDIO_L10N_SWEEP === '1'
const REAL_PIN = '111111'
const isAndroid = () => process.env.WDIO_PLATFORM === 'android'

const outDir = resolve(__dirname, '..', 'screenshots', 'l10n',
    process.env.WDIO_PLATFORM === 'android' ? 'android' : 'ios', appLanguageTag())

async function shot(name: string): Promise<void> {
    try {
        mkdirSync(outDir, { recursive: true })
        await driver.saveScreenshot(resolve(outDir, `${name}.png`))
        console.log(`[l10n-sweep] ${isAndroid() ? 'android' : 'ios'}/${appLanguageTag()}/${name}.png`)
    } catch (e: any) {
        console.warn(`[l10n-sweep] screenshot ${name} failed: ${e?.message ?? e}`)
    }
}

async function step(name: string, fn: () => Promise<void>): Promise<void> {
    try { await fn() } catch (e: any) {
        console.warn(`[l10n-sweep] step ${name} skipped: ${e?.message ?? e}`)
    }
}

async function tapId(id: string, timeout = 8_000): Promise<void> {
    const el = await $(byId(id))
    await el.waitForDisplayed({ timeout })
    await el.click()
}

/** Leave the current screen. Android: system back. iOS has no system back —
 *  tap the screen's own back/cancel control (first id that exists). */
async function goBack(...iosIds: string[]): Promise<void> {
    if (isAndroid()) { await driver.back(); return }
    // 'settings_sheet_done' last: if a disabled menu row (e.g. Add contact
    // while Tor is still bootstrapping) left the sheet open, close it so the
    // next step can reach the cogwheel again.
    for (const id of [...iosIds, 'settings_sheet_done']) {
        const el = await $(byId(id))
        if (await el.isExisting()) { await el.click(); return }
    }
    // Last resort: a navigation-bar back button.
    const nav = await $('-ios predicate string:type == "XCUIElementTypeButton" AND name == "Back"')
    if (await nav.isExisting()) await nav.click()
}

async function openMenuItem(itemId: string): Promise<void> {
    await tapId(Ids.settingsButton)
    try {
        await tapId(itemId)
    } catch (e) {
        await goBack()   // don't leave the menu/sheet open for the next step
        throw e
    }
}

/** Opens the settings menu/sheet, no-op if already open (add_contact_button
 *  existing — enabled or not — is the "menu is open" sentinel, same
 *  convention as Device.openSettingsMenu / settings-relay-gate.spec.ts). */
async function ensureSettingsMenuOpen(): Promise<void> {
    const sentinel = await $(byId(Ids.addContactButton))
    if (await sentinel.isExisting().catch(() => false)) return
    await tapId(Ids.settingsButton)
    await sentinel.waitForExist({ timeout: 5_000 }).catch(() => undefined)
}

/**
 * True iff the settings menu/sheet is open AND add_contact_button reports
 * enabled — NEVER throws, so a `browser.waitUntil` polling this can survive
 * the connect-time push prompt (fires on the FIRST relay answer — exactly
 * the transition this waits for) snatching the menu/sheet mid-poll and just
 * retry the next tick, rather than aborting outright (same shape as
 * settings-relay-gate.spec.ts's addContactButtonEnabledIs). Uses the
 * poll-friendly `dismissPostConnectModalsIfPresent` (bounded probe, no
 * unlocked_root anchor), not the heavier one-shot `dismissPushPromptIfPresent`
 * this spec already calls once at the reveal transition — see that helper's
 * own kdoc on why the one-shot version is "ruinous" inside a tight poll.
 */
async function addContactButtonEnabled(): Promise<boolean> {
    await dismissPostConnectModalsIfPresent(150)
    try { await ensureSettingsMenuOpen() } catch { return false }
    return (await $(byId(Ids.addContactButton))).isEnabled().catch(() => false)
}

async function closeModal(closeId: string): Promise<void> {
    if (isAndroid()) { await tapId(closeId, 5_000); return }
    const btn = await $('-ios predicate string:type == "XCUIElementTypeButton" AND label == "Close"')
    if (await btn.isExisting()) { await btn.click(); return }
    await tapId(closeId, 5_000)
}

describe('Localization screenshot sweep', () => {
    if (!ENABLED) {
        it('is disabled (set WDIO_L10N_SWEEP=1 and WDIO_APP_LANG=<tag>)', () => undefined)
        return
    }

    // 2026-09-11: push_prompt (screenshotted in step 3 below) no longer fires
    // at unlock — it fires on the FIRST RELAY ANSWER, so without a relay this
    // sweep would now NEVER see it (the contact list would sit on
    // contact_list_hidden_until_connected forever — see ContactListHelper.ts).
    // Bring the mock relay up for the whole sweep, same pattern as
    // tests/contact-list-layout.spec.ts / tests/mock-relay.spec.ts; it needs
    // no platform branching (10.0.2.2 from the Android emulator, localhost
    // from the iOS simulator).
    before(async () => { await MockRelay.start() })
    after(async () => { await MockRelay.stop() })

    it(`captures the copy-heavy screens in "${appLanguageTag()}"`, async () => {
        await resetApp()

        // 1. Protection-level chooser (first screen after a wipe), if shown.
        await step('chooser', async () => {
            const casual = await $(byId('level_casual'))
            await casual.waitForDisplayed({ timeout: 20_000 })
            await shot('01-protection-chooser')
        })

        // 2. PIN setup keypad.
        await waitForPinScreen()
        await shot('02-pin-setup')
        await completePinSetup(REAL_PIN)
        await (await $(byId(Ids.unlockedRoot))).waitForDisplayed({ timeout: 30_000 })

        // 3. Wait for the first-reveal gate to open (the mock relay is up —
        //    see the before() hook), THEN screenshot the push prompt if it's
        //    still up — it fires on THIS transition (2026-09-11), not at
        //    unlock, so screenshotting right after unlock (the old step 3)
        //    would now almost always miss it. Best-effort, per this sweep's
        //    convention: a slow/absent relay just skips the screenshot.
        await step('reveal', async () => {
            await (await $(byId(Ids.emptyContactsState))).waitForExist({ timeout: 90_000 })
        })
        await step('push-prompt', async () => {
            const prompt = await $(byId('push_prompt'))
            if (await prompt.isExisting()) await shot('03-push-prompt')
        })
        await dismissPushPromptIfPresent()
        await shot('04-contact-list-empty')

        // 3b. Several settings rows are relay-gated (2026-09-28 directive:
        //     Add contact, Create group, Move to new device,
        //     Notifications/Push settings, Report bug). emptyContactsState
        //     above already implies the relay answered once, but wait for the
        //     GATE ITSELF (add_contact_button enabled) rather than assume —
        //     a tap on a still-disabled row is a silent no-op (Compose/SwiftUI
        //     `.disabled` never fires onClick) that would otherwise screenshot
        //     the settings menu again instead of the target screen. Best-effort
        //     like every other step: a relay that never comes up just skips the
        //     rows below rather than failing the sweep.
        await step('relay-ready', async () => {
            await browser.waitUntil(addContactButtonEnabled, {
                timeout: 60_000,
                interval: 1_000,
                timeoutMsg: 'add_contact_button never enabled — relay-gated screenshots below will be skipped',
            })
            await goBack()   // close the menu the poll opened; the next step re-opens it fresh
        })

        // 4. Settings menu / sheet.
        await step('settings-menu', async () => {
            await tapId(Ids.settingsButton)
            await shot('05-settings-menu')
            if (isAndroid()) await driver.back()
            else await tapId('settings_sheet_done', 3_000)
        })

        // 5. Add contact.
        await step('add-contact', async () => {
            await openMenuItem(Ids.addContactButton)
            await driver.pause(1_500)
            await shot('06-add-contact')
            await goBack('add_contact_cancel', 'add_contact_done')
        })

        // 6. Protection-level settings.
        await step('protection-settings', async () => {
            await openMenuItem('protection_level_menu_button')
            await driver.pause(1_000)
            await shot('07-protection-settings')
            await goBack('protection_level_back')
        })

        // 7. Notification settings / education carousel.
        await step('notifications', async () => {
            await openMenuItem(isAndroid() ? Ids.menuNotifications : 'push_settings_menu_button')
            await driver.pause(800)
            await shot('08-notification-settings')
            if (isAndroid()) await closeModal(Ids.notificationSettingsClose)
            else {
                // iOS carousel: Done only exists on the last page — page forward.
                const done = byId('push_settings_done')
                for (let i = 0; i < 8 && !(await (await $(done)).isExisting()); i++) {
                    await tapId('push_settings_next', 3_000)
                    await driver.pause(400)
                }
                await tapId('push_settings_done', 3_000)
            }
        })

        // 8. About carousel: first page, a middle page, last page.
        await step('about', async () => {
            await openMenuItem(Ids.menuAbout)
            await driver.pause(800)
            await shot('09-about-p01')
            for (let i = 0; i < 12; i++) await swipeLeft()
            await driver.pause(500)
            await shot('10-about-p13')
            await swipeLeft(); await swipeLeft()
            await driver.pause(500)
            await shot('11-about-p15')
            await closeModal(Ids.aboutClose)
        })

        // 9. About info (version / credits) and Support Rún.
        await step('about-info', async () => {
            await openMenuItem(Ids.menuAboutInfo)
            await driver.pause(800)
            await shot('12-about-info')
            await closeModal(Ids.aboutInfoClose)
        })
        await step('donate', async () => {
            await openMenuItem(Ids.menuDonate)
            await driver.pause(800)
            await shot('13-support')
            await closeModal('donate_close')
        })

        // 10. Language picker (Android) — the row labels are native names.
        if (isAndroid()) {
            await step('language-picker', async () => {
                await openMenuItem(Ids.menuLanguage)
                await shot('14-language-picker')
                await driver.back()
            })
        }
    })
})

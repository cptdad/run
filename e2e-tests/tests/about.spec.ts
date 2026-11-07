import { Ids, byId } from '../helpers/AccessibilityIds'
import {
    enterPin,
    waitForKeypad,
    waitForPinScreen,
    completePinSetup,
} from '../helpers/PinHelper'
import { resetApp } from '../helpers/AppReset'
import { swipeLeft } from '../helpers/Gestures'

const REAL_PIN = '111111'

/** Opens the cogwheel dropdown and taps the item with the given id. */
async function openMenuItem(itemId: string): Promise<void> {
    const settings = await $(byId(Ids.settingsButton))
    await settings.waitForDisplayed({ timeout: 10_000 })
    await settings.click()
    const item = await $(byId(itemId))
    await item.waitForDisplayed({ timeout: 5_000 })
    await item.click()
}

/**
 * Dismiss the open modal.
 *  - Android: taps the modal's close button (testTag exposed via resource-id).
 *  - iOS: tap the ✕ button located by its accessibility *label* "Close".
 */
async function dismissModal(closeId: string): Promise<void> {
    if (process.env.WDIO_PLATFORM === 'android') {
        await (await $(byId(closeId))).click()
        return
    }
    // iOS: the modal's outer ZStack carries `.accessibilityIdentifier(...)`,
    // which SwiftUI propagates onto EVERY child — so the close (✕) button, the
    // title, and (in Donate) the tip-tier buttons all share
    // the modal's id as their `name`. The button's own `about_close`/`donate_close`
    // id never surfaces. The one reliable distinguisher is the ✕'s accessibility
    // label "Close" (auto-generated for the xmark SF Symbol), unique within the
    // open modal. This is device-independent, unlike a fixed-fraction coordinate
    // (the ✕ sits at a different y-fraction on a notch device vs a Dynamic-Island
    // one, so a hard coordinate misses). A top-edge swipe-down is also unsafe —
    // it opens Notification Center on iPhone.
    const closeBtn = await $(
        '-ios predicate string:type == "XCUIElementTypeButton" AND label == "Close"',
    )
    await closeBtn.waitForDisplayed({ timeout: 5_000 })
    await closeBtn.click()
}

/**
 * The two cogwheel info modals: "About" (swipeable carousel) and
 * "Support Rún" (donate). Both are static and vault-agnostic; this exercises
 * the vault. Copy lives in commonMain AboutContent/DonateContent and is
 * unit-tested separately (AboutContentTest) — here we verify the UI wiring.
 */
describe('About & Support-Rún modals', () => {

    before(async () => {
        await resetApp()
        await waitForPinScreen()
        await completePinSetup(REAL_PIN)
        // First run opens the vault directly once the PIN is confirmed.
        const root = await $(byId(Ids.unlockedRoot))
        await root.waitForDisplayed({ timeout: 30_000 })
    })

    it('About opens from the cogwheel, swipes through pages, and closes', async () => {
        await openMenuItem(Ids.menuAbout)

        await (await $(byId(Ids.aboutModal))).waitForDisplayed({ timeout: 10_000 })
        // SwiftUI's TabView(.page) does not surface its accessibilityIdentifier
        // to XCUITest, so the pager container is only directly assertable on
        // Android. The swipe loop below verifies the carousel works on both.
        if (process.env.WDIO_PLATFORM === 'android') {
            await (await $(byId(Ids.aboutPager))).waitForDisplayed({ timeout: 5_000 })
        }

        // Swipe forward a few pages (incl. the runestone animation pages) — the
        // carousel must keep working and the modal stay open.
        for (let i = 0; i < 3; i++) {
            await swipeLeft()
            await browser.pause(500)
        }
        if (!(await (await $(byId(Ids.aboutModal))).isDisplayed())) {
            throw new Error('About modal closed unexpectedly while swiping')
        }

        await dismissModal(Ids.aboutClose)
        await (await $(byId(Ids.aboutModal))).waitForDisplayed({ reverse: true, timeout: 5_000 })
    })

    it('About (app info) opens from the cogwheel, shows the version, and closes', async () => {
        await openMenuItem(Ids.menuAboutInfo)
        await (await $(byId(Ids.aboutInfoModal))).waitForDisplayed({ timeout: 10_000 })

        // The version Text's id is only reliably surfaced by XCUITest on
        // Android (same SwiftUI-Text limitation as the donate/about pages),
        // so assert the version string there; iOS still verifies open/close.
        if (process.env.WDIO_PLATFORM === 'android') {
            const version = await $(byId(Ids.aboutInfoVersion))
            await version.waitForDisplayed({ timeout: 5_000 })
            const txt = await version.getText()
            if (!/Version \d/.test(txt)) {
                throw new Error(`about_info_version expected "Version <n>…", got: "${txt}"`)
            }
        }

        await dismissModal(Ids.aboutInfoClose)
        await (await $(byId(Ids.aboutInfoModal))).waitForDisplayed({ reverse: true, timeout: 5_000 })
    })

    it('Support Rún opens, shows the tip jar, and closes', async () => {
        // The Support modal is Android-only (iOS has its own StoreKit Support
        // sheet). It has two tabs — a Play Billing tip jar (default) and a Crypto
        // tab; this test exercises the default Tip tab.
        if (process.env.WDIO_PLATFORM !== 'android') {
            return
        }

        await openMenuItem(Ids.menuDonate)

        await (await $(byId(Ids.donateModal))).waitForDisplayed({ timeout: 10_000 })

        // Tip is the default tab, so its body shows on open. It renders regardless
        // of whether Play has products wired on this device (loading / tiers /
        // unavailable resolve async).
        await (await $(byId(Ids.tipJarBody))).waitForDisplayed({ timeout: 10_000 })

        await dismissModal(Ids.donateClose)
        await (await $(byId(Ids.donateModal))).waitForDisplayed({ reverse: true, timeout: 5_000 })
    })
})

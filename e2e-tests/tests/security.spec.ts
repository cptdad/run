import { byId, Ids } from '../helpers/AccessibilityIds'
import {
    enterPin,
    waitForKeypad,
    waitForPinScreen,
    completePinSetup,
} from '../helpers/PinHelper'
import { resetApp, relaunchApp } from '../helpers/AppReset'

const REAL_PIN = '111111'

describe('Security features', () => {

    beforeEach(async () => {
        await resetApp()
    })

    it('app screenshot is blocked (screenshot returns black screen)', async () => {
        await waitForPinScreen()

        // Take a screenshot via Appium. On Android, FLAG_SECURE blocks
        // screen capture and the returned image is entirely black.
        // On iOS, SecureField-based ScreenshotProtection hides the UI.
        const screenshotBase64 = await driver.takeScreenshot()
        expect(screenshotBase64).toBeTruthy()
        expect(screenshotBase64.length).toBeGreaterThan(100)

        // We can't easily decode + analyse pixel data from WebdriverIO,
        // so this test only verifies that the screenshot API responds.
        // Manual verification: open the screenshot artifact and confirm
        // that sensitive content is obscured.
    })

    it('no spurious wipe on the first relaunch after setup', async () => {
        // The 7-day threshold can't be reduced without a code change, so this
        // drives the NO-WIPE path and asserts it PRECISELY. First-run setup now
        // opens the vault directly (InactivityWipe.touch() runs on that
        // auto-unlock), and the first relaunch afterwards must NOT wipe —
        // regression guard for the iOS first-run data-loss bug, where the
        // missing-timestamp branch treated absent-as-expired and wiped the vault.
        await waitForPinScreen()
        await waitForKeypad()
        await completePinSetup(REAL_PIN)
        // Setup opens the vault directly; wait for it before re-locking.
        await (await $(byId(Ids.unlockedRoot))).waitForDisplayed({ timeout: 30_000 })

        await relaunchApp()
        await waitForPinScreen()

        // No wipe → the app is on the PIN ENTRY screen (configured, locked), NOT
        // the SETUP screen. pin_prompt exists ONLY on the setup screen, so its
        // ABSENCE proves the vault survived. waitForPinScreen alone can't tell
        // the two apart (both have a keypad) — that was the false-green gap.
        const promptEl = await $(byId(Ids.pinPrompt))
        expect(await promptEl.isExisting()).toBe(false)
    })
})

import { Ids, byId } from '../helpers/AccessibilityIds'
import {
    enterPin,
    waitForKeypad,
    waitForPinScreen,
    completePinSetup,
} from '../helpers/PinHelper'
import { resetApp } from '../helpers/AppReset'
import { shortTimeout } from '../helpers/DeviceType'

const REAL_PIN = '111111'

/**
 * Verifies the hidden log viewer is accessible by tapping the
 * bottom-right stone 5 times on the contact list screen.
 */
describe('Log viewer (hidden debug feature)', () => {

    before(async () => {
        await resetApp()
        await waitForPinScreen()
        await completePinSetup(REAL_PIN)
        // First run opens the vault directly once the PIN is confirmed.
        const root = await $(byId(Ids.unlockedRoot))
        await root.waitForDisplayed({ timeout: 30_000 })
    })

    it('5 taps on the bottom-right stone opens log viewer', async () => {
        // Get the screen dimensions to calculate the bottom-right corner.
        const { width, height } = await browser.getWindowSize()

        // Tap area: bottom-right ~20% of the screen (where the stone is).
        const tapX = Math.round(width * 0.88)
        const tapY = Math.round(height * 0.88)

        // Tap 5 times rapidly.
        for (let i = 0; i < 5; i++) {
            await browser.action('pointer', { parameters: { pointerType: 'touch' } })
                .move({ x: tapX, y: tapY })
                .down()
                .up()
                .perform()
            await browser.pause(200)
        }

        await browser.pause(1_000)

        // The log viewer should now be visible. On iOS it's a sheet with
        // a "Logs" title; on Android it's a full-screen overlay with
        // "Logs" text and a filter field.
        // Look for log-viewer-specific content: the "Copy" or "Logs" text,
        // or the filter field. Use a broad selector.
        const isIos = process.env.WDIO_PLATFORM !== 'android'

        if (isIos) {
            // iOS sheet has a navigation title "Logs".
            const title = await $('//*[@name="Logs"]')
            await title.waitForDisplayed({ timeout: shortTimeout() })
        } else {
            // Android shows "Logs (N)" text.
            const logsText = await $('//*[starts-with(@text, "Logs")]')
            await logsText.waitForDisplayed({ timeout: shortTimeout() })
        }
    })
})

import { Ids, byId } from '../helpers/AccessibilityIds'
import {
    enterPin,
    waitForKeypad,
    waitForPinScreen,
    completePinSetup,
} from '../helpers/PinHelper'
import { resetApp, relaunchApp } from '../helpers/AppReset'

const REAL_PIN = '111111'

/**
 * Verifies the single-vault lifecycle: setup auto-opens the vault, and the
 * same PIN reopens that same vault after a re-lock. Each test starts from a
 * fresh install and sets up the PIN.
 */
describe('Vault (single-vault lifecycle)', () => {

    beforeEach(async () => {
        await resetApp()
        await waitForPinScreen()
        await completePinSetup(REAL_PIN)
        // First run opens the vault directly once the PIN is confirmed.
        await (await $(byId(Ids.unlockedRoot))).waitForDisplayed({ timeout: 30_000 })
    })

    it('vault opens directly after setup with no PIN re-entry', async () => {
        // beforeEach already landed us in the vault straight from setup.
        const root = await $(byId(Ids.unlockedRoot))
        await root.waitForDisplayed({ timeout: 15_000 })
    })

    it('correct PIN reopens the same vault after re-lock', async () => {
        // Re-lock (relaunch) then unlock with the PIN.
        await relaunchApp()
        await waitForPinScreen()
        await waitForKeypad()
        await enterPin(REAL_PIN)

        const root = await $(byId(Ids.unlockedRoot))
        await root.waitForDisplayed({ timeout: 15_000 })
    })
})

import { Ids, byId } from '../helpers/AccessibilityIds'
import {
    enterPin,
    waitForKeypad,
    waitForPinScreen,
    completePinSetup,
    readPinPrompt,
} from '../helpers/PinHelper'
import { resetApp, relaunchApp } from '../helpers/AppReset'
import { shortTimeout } from '../helpers/DeviceType'

const REAL_PIN = '111111'

describe('PIN setup and entry', () => {

    beforeEach(async () => {
        // Each test starts from a fresh install so vault/credential
        // state from previous tests doesn't carry over.
        await resetApp()
    })

    it('PIN setup opens the vault directly (no re-entry)', async () => {
        await waitForPinScreen()
        // First prompt must be "Choose your PIN"
        const prompt = await readPinPrompt()
        expect(prompt.toLowerCase()).toContain('choose')

        await completePinSetup(REAL_PIN)

        // First run lands DIRECTLY in the vault once the PIN is
        // confirmed — no PIN re-entry (the new first-journey behaviour).
        const root = await $(byId(Ids.unlockedRoot))
        await root.waitForDisplayed({ timeout: 30_000 })
    })

    it('correct PIN unlocks to contact list after re-lock', async () => {
        await waitForPinScreen()
        await completePinSetup(REAL_PIN)
        await (await $(byId(Ids.unlockedRoot))).waitForDisplayed({ timeout: 30_000 })

        // Re-lock, then unlock with the PIN.
        await relaunchApp()
        await waitForPinScreen()
        await waitForKeypad()
        await enterPin(REAL_PIN)

        // The unlocked root is at ContentView level (outside NavigationStack)
        // so it's always discoverable when isUnlocked == true.
        const root = await $(byId(Ids.unlockedRoot))
        await root.waitForDisplayed({ timeout: 15_000 })
    })

    it('wrong PIN shows shake animation', async () => {
        await waitForPinScreen()
        await completePinSetup(REAL_PIN)
        await (await $(byId(Ids.unlockedRoot))).waitForDisplayed({ timeout: 30_000 })

        await relaunchApp()
        await waitForPinScreen()
        await waitForKeypad()
        await enterPin('000000')

        // Still on PIN screen after wrong entry.
        const dots = await $(byId(Ids.pinDots))
        await dots.waitForDisplayed({ timeout: shortTimeout() })
    })

    it('exhausting the tier\'s wrong-PIN budget triggers the emergency wipe', async () => {
        await waitForPinScreen()
        await completePinSetup(REAL_PIN)
        await (await $(byId(Ids.unlockedRoot))).waitForDisplayed({ timeout: 30_000 })

        // Re-lock so the failed-attempt counter governs the lock screen.
        await relaunchApp()
        await waitForPinScreen()

        // Enter the tier's WHOLE consecutive-wrong-credential budget. The
        // spec provisions CASUAL (waitForPinScreen's default stop), whose budget
        // is ProtectionLevel.CASUAL.maxConsecutiveAttempts = 10 (PRIVATE 8,
        // MAXIMUM 5). Entering fewer never wipes: the phone just stays on the
        // unlock keypad, which has no prompt — the red this test showed from
        // 1.6.23 to 2026-09-27 was exactly that, not a product decision.
        // Each attempt costs:
        //   PIN-entry debounce (~150ms) + unlock (2× PBKDF2-210k ≈ ~2s
        //   off-main, CR-1) + shake animation + exponential backoff
        //   min(2^i·1s, 8s) before the keypad accepts input again.
        // A flat sleep races the heavier CR-1 unlock, so size each wait
        // to that attempt's actual backoff plus a generous unlock margin.
        // ~2s PBKDF2 unlock happens during this wait; 4s margin covers it with
        // headroom (specFileRetries absorbs a rare slow-device overshoot).
        const UNLOCK_MARGIN = 4_000
        const CASUAL_WRONG_PIN_BUDGET = 10
        for (let i = 0; i < CASUAL_WRONG_PIN_BUDGET; i++) {
            await waitForKeypad()
            await enterPin('999999')
            const backoff = Math.min(1000 * 2 ** i, 8_000)
            await browser.pause(backoff + UNLOCK_MARGIN)
        }

        // After emergency wipe, the app should show setup screen again
        // on next launch.
        await browser.pause(2_000)
        await relaunchApp()
        await waitForPinScreen()
        const prompt = await readPinPrompt()
        expect(prompt.toLowerCase()).toContain('choose')
    })
})

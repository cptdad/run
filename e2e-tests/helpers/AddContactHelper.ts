import { Ids, byId } from './AccessibilityIds'

/**
 * Reveals the add-contact wizard's hidden paste (no-camera) exchange.
 *
 * The wizard's first step is a "Show my code / Scan a code" choice; the paste
 * exchange used by the e2e suite (a real two-camera exchange isn't possible on
 * a single device) is hidden behind a 5-taps-within-3s gesture on an invisible
 * target — mirroring the log-viewer's hidden open. This replaces the old Debug
 * tab + 8888 PIN gate.
 *
 * Assumes the add-contact choice step is showing. Returns once the paste code
 * input is visible.
 */
export async function revealPasteExchange(): Promise<void> {
    const target = await $(byId(Ids.addPasteReveal))
    await target.waitForDisplayed({ timeout: 10_000 })
    for (let i = 0; i < 5; i++) {
        await target.click()
        await browser.pause(120)
    }
    await (await $(byId(Ids.debugCodeInput))).waitForDisplayed({ timeout: 10_000 })
}

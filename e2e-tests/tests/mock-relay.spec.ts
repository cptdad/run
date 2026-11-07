// Integration: with the mock relay listening on the host :8080 (which the sim/
// emulator reaches via 10.0.2.2 / localhost), the app should connect to it and
// flip the relay-reachable gate ON — proving the mock speaks the real protocol
// end-to-end, not just in the standalone self-test.
import { Ids, byId } from '../helpers/AccessibilityIds'
import { completePinSetup, waitForPinScreen, dismissPostConnectModalsIfPresent } from '../helpers/PinHelper'
import { resetApp } from '../helpers/AppReset'
import * as MockRelay from '../helpers/MockRelay'

const PIN = '111111'

describe('mock relay — integration', () => {
    // Android-only. The mock listens on the host and is reached at 10.0.2.2 from
    // the Android emulator; a physical iOS device can't see the host loopback and
    // the iOS-sim relay port mapping is unverified, so this integration check
    // stays scoped to the Android emulator where it's proven.
    before(async function () {
        if (!browser.isAndroid) { this.skip(); return }
        await MockRelay.start()
    })
    after(async () => { await MockRelay.stop() })

    it('the app reaches the mock relay (relay-reachable gate lights)', async () => {
        await resetApp()
        await waitForPinScreen()
        await completePinSetup(PIN)
        await (await $(byId(Ids.unlockedRoot))).waitForDisplayed({ timeout: 30_000 })

        // The runestone lit-marker is intentionally NOT e2e-queryable on Android
        // (Compose prunes the bare marker Box — see RunestoneLitMarker.kt). Assert a
        // real, queryable signal instead: the cogwheel's "Add contact" is enabled
        // ONLY when the relay is reachable, so with the mock answering on :8080 it
        // flips enabled within a relay-check cycle (~8-12s) — the SAME relay
        // answer that fires push_prompt (2026-09-11), so race it: on Android an
        // occluding Dialog window would otherwise turn every lookup below into a
        // "no such element" instead of a real enabled/disabled read.
        await dismissPostConnectModalsIfPresent(3_000)
        await (await $(byId(Ids.settingsButton))).click()
        const addBtn = await $(byId(Ids.addContactButton))
        await addBtn.waitForDisplayed({ timeout: 10_000 })
        await browser.waitUntil(async () => {
            await dismissPostConnectModalsIfPresent(150)
            return addBtn.isEnabled().catch(() => false)
        }, {
            timeout: 30_000,
            timeoutMsg: 'Add-contact never enabled — app did not see the mock relay as reachable',
        })
    })
})

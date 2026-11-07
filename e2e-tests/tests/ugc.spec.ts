import { Ids, byId } from '../helpers/AccessibilityIds'
import { waitForPinScreen, completePinSetup, readPinPrompt } from '../helpers/PinHelper'
import { resetApp } from '../helpers/AppReset'
import { expectEulaShown, acceptEula } from '../helpers/EulaHelper'

const REAL_PIN = '111111'

/**
 * App Store Guideline 1.2 (user-generated content) safeguards — iOS only.
 *
 * Two things a SINGLE simulator can verify deterministically:
 *   1. the EULA Terms gate is shown before PIN setup/entry, and accepting it
 *      proceeds to the PIN screen; and
 *   2. the "Blocked contacts" management item is reachable — ALWAYS enabled,
 *      even on a fresh install with nobody blocked (0ae1d2bf, appstore-reply
 *      2026-09-10 discoverability risk #1: a reviewer hunting for the block
 *      feature must not find a greyed-out row; BlockedContactsView already has
 *      its own empty state, `blocked_empty_state`, for that case). Superseded
 *      the older "disabled when nobody is blocked" behaviour this spec used to
 *      assert — see ContactListView.swift's settingsSheet, menu_blocked_contacts row.
 *
 * Blocking / unblocking an ACTUAL contact needs a relay-minted pairing, which
 * one simulator cannot fabricate (that is exactly why the single-device contact
 * tests in contacts.spec.ts are skipped) — so the full block→unblock round trip
 * belongs in the two-device suite, not here.
 */
describe('User safety (Guideline 1.2)', () => {
    // The whole feature set is iOS-only (no EULA / block UI on Android).
    before(function () {
        if (process.env.WDIO_PLATFORM === 'android') this.skip()
    })

    describe('EULA gate', () => {
        before(async () => {
            await resetApp()   // test wipe clears the accepted flag → the gate re-shows
        })

        it('shows the Terms of Use before the PIN screen on first launch', async () => {
            await expectEulaShown()
            // The gate is an EXCLUSIVE branch in ContentView (it replaces, not
            // overlays, the PIN screen), so the keypad must not exist yet.
            const key0 = await $(byId(Ids.key(0)))
            if (await key0.isExisting()) {
                throw new Error('PIN keypad present while the EULA is unaccepted — gate not enforced')
            }
        })

        it('accepting the Terms proceeds to PIN setup', async () => {
            await acceptEula()
            await waitForPinScreen()
            const prompt = await readPinPrompt()
            if (!/pin/i.test(prompt)) {
                throw new Error(`expected a PIN prompt after accepting the EULA, got "${prompt}"`)
            }
        })
    })

    describe('Blocked-contacts management', () => {
        before(async () => {
            await resetApp()
            await waitForPinScreen()        // accepts the EULA, then waits for the keypad
            await completePinSetup(REAL_PIN)
            await (await $(byId(Ids.unlockedRoot))).waitForDisplayed({ timeout: 30_000 })
        })

        it('"Blocked contacts" is enabled even when no one is blocked', async () => {
            const settings = await $(byId(Ids.settingsButton))
            await settings.waitForDisplayed({ timeout: 10_000 })
            await settings.click()

            // iOS Menu items can report visible=false while present (XCUITest
            // quirk on iOS 26), so probe existence, not display, then assert the
            // enabled state — the row stays reachable regardless of whether
            // anything is blocked (0ae1d2bf; see the file header).
            // "Blocked contacts" is the LAST sheet row and the sheet has grown
            // (Protection level / Push notifications / About / Support rows
            // added since this spec was written) — on the sim it sits below the
            // fold and iOS 26's lazy sheet doesn't materialize off-screen rows,
            // so scroll once before asserting existence.
            const item = await $(byId(Ids.menuBlockedContacts))
            if (!(await item.waitForExist({ timeout: 5_000 }).catch(() => false))) {
                await driver.execute('mobile: scroll', { direction: 'down' }).catch(() => { /* Android no-op */ })
            }
            await item.waitForExist({ timeout: 5_000 })
            if (!(await item.isEnabled())) {
                throw new Error('"Blocked contacts" should always be enabled/reachable, even when nobody is blocked (0ae1d2bf)')
            }
        })
    })
})

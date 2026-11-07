import { Ids, byId } from '../helpers/AccessibilityIds'
import {
    enterPin,
    waitForKeypad,
    waitForPinScreen,
    completePinSetup,
} from '../helpers/PinHelper'
import { resetApp } from '../helpers/AppReset'
import { revealPasteExchange } from '../helpers/AddContactHelper'
import { shortTimeout } from '../helpers/DeviceType'
import { waitForEmptyOrPreConnectContactList } from '../helpers/ContactListHelper'

const REAL_PIN = '111111'

describe('Contacts', () => {

    before(async () => {
        await resetApp()
        await waitForPinScreen()
        await completePinSetup(REAL_PIN)
        // First run opens the vault directly once the PIN is confirmed —
        // no PIN re-entry.
        const root = await $(byId(Ids.unlockedRoot))
        await root.waitForDisplayed({ timeout: 30_000 })
    })

    it('contact list shows empty state on fresh install', async () => {
        // Either id proves "fresh vault, no contact rows". This suite never
        // starts the mock relay, so the 2026-09-11 first-reveal gate keeps the
        // screen on contact_list_hidden_until_connected (empty_contacts_state
        // only appears once the relay has answered) — see ContactListHelper.
        await waitForEmptyOrPreConnectContactList(30_000)
    })

    // TODO: un-skip once an emulator run can verify a shared `pairViaMockRelay()` helper
    // (helpers/MockPairing.ts, extracted from tests/relay-loss.spec.ts:60-100).
    // Skipped: this test (and the long-press / delete tests below) assumed a
    // contact already existed in the vault, which the now-skipped paste-add
    // test was providing. Real contacts under the capability protocol only
    // exist after a relay-backed mint, so these flows are covered by the
    // two-device spec instead.
    it.skip('generated alias follows verb+animal format', async function () {
        // Find any contact_name_* element and verify its text
        // contains exactly one space (verb + animal).
        const nameElement = await $(`//*[starts-with(@name, "contact_name_") or starts-with(@resource-id, "contact_name_")]`)
        await nameElement.waitForDisplayed({ timeout: shortTimeout() })
        const text = await nameElement.getText()
        expect(text.split(' ').length).toBe(2)
        expect(text.length).toBeGreaterThan(3)
    })

    it.skip('long press on contact shows Memory and Delete options', async () => {
        const row = await $(`//*[starts-with(@name, "contact_row_") or starts-with(@resource-id, "contact_row_")]`)
        await row.waitForDisplayed()

        if (process.env.WDIO_PLATFORM === 'android') {
            // Android: combinedClickable long-press opens a custom overlay.
            await driver.execute('mobile: longClickGesture', {
                elementId: row.elementId,
                duration: 800,
            })
        } else {
            // iOS: .contextMenu triggered by touchAndHold.
            await driver.execute('mobile: touchAndHold', {
                elementId: row.elementId,
                duration: 1.5,
            })
        }
        await browser.pause(1_000)

        // Delete option should be visible in the context menu.
        const deleteItem = await $('//*[@name="Delete" or @text="Delete" or @label="Delete"]')
        await deleteItem.waitForDisplayed({ timeout: shortTimeout() })

        // Dismiss the menu by tapping the dark backdrop at screen edge.
        // The overlay is a full-screen clickable backdrop behind the
        // centered menu column.
        const { height } = await driver.getWindowSize()
        if (process.env.WDIO_PLATFORM === 'android') {
            await driver.execute('mobile: clickGesture', { x: 10, y: height - 50 })
        } else {
            // iOS: tap outside the context menu to dismiss.
            await driver.execute('mobile: tap', { x: 10, y: height - 50 })
        }
        await browser.pause(1_000)

        // Verify we're still on the contact list.
        const contactList = await $(byId(Ids.contactList))
        await contactList.waitForDisplayed({ timeout: shortTimeout() })
    })

    it.skip('delete contact removes it from list', async () => {
        await browser.pause(1_000)
        const rowSelector = `//*[starts-with(@name, "contact_row_") or starts-with(@resource-id, "contact_row_")]`
        const row = await $(rowSelector)
        await row.waitForDisplayed({ timeout: 10_000 })

        if (process.env.WDIO_PLATFORM === 'android') {
            await driver.execute('mobile: longClickGesture', {
                elementId: row.elementId,
                duration: 800,
            })
        } else {
            await driver.execute('mobile: touchAndHold', {
                elementId: row.elementId,
                duration: 1.5,
            })
        }
        await browser.pause(1_000)

        const deleteItem = await $('//*[@name="Delete" or @text="Delete" or @label="Delete"]')
        await deleteItem.waitForDisplayed({ timeout: shortTimeout() })
        await deleteItem.click()

        // Confirm delete
        const confirm = await $(byId(Ids.deleteConfirmButton))
        await confirm.waitForDisplayed({ timeout: shortTimeout() })
        await confirm.click()

        // Empty state should be visible again (or the pre-connect placeholder,
        // if this run never saw the relay — see the fresh-install test above).
        await waitForEmptyOrPreConnectContactList(shortTimeout())
    })
})

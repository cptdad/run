import { Ids, byId } from '../helpers/AccessibilityIds'
import {
    enterPin,
    waitForKeypad,
    waitForPinScreen,
    completePinSetup,
} from '../helpers/PinHelper'
import { resetApp } from '../helpers/AppReset'
import { revealPasteExchange } from '../helpers/AddContactHelper'
import { isPhysicalDevice, shortTimeout } from '../helpers/DeviceType'
import { waitForEmptyOrPreConnectContactList } from '../helpers/ContactListHelper'

const REAL_PIN = '111111'

/**
 * Single-platform messaging tests.
 *
 * The single-platform configs run against the emulator/simulator, which
 * `RelayConfig` hard-routes to a non-existent localhost listener. Strict
 * `isRelayReachable()` therefore returns false, and the send button must
 * stay disabled. The "send actually delivers a message" path is exercised
 * by the physical-device suite (not published), where two physical devices use the real onion.
 */
describe('Messaging', () => {

    before(async () => {
        await resetApp()
        await waitForPinScreen()
        await completePinSetup(REAL_PIN)
        // First run opens the vault directly once the PIN is confirmed.
        const root = await $(byId(Ids.unlockedRoot))
        await root.waitForDisplayed({ timeout: 30_000 })
    })

    it('empty conversation shows no messages', async () => {
        // With no contacts yet, we can't open a conversation —
        // verify the contact list empty state instead. Either id proves it:
        // this suite never starts the mock relay, so the 2026-09-11
        // first-reveal gate keeps the screen on the pre-connect placeholder
        // (empty_contacts_state only appears once the relay has answered).
        await waitForEmptyOrPreConnectContactList(30_000)
    })

    // Skipped post-capability-protocol migration: this test needed to seed a
    // contact via the paste exchange, which under the new model requires a
    // server-minted inbox + writeCap. The send-disabled gate is now covered
    // by the physical-device suite (not published) where real pairing produces real contacts.
    it.skip('send button is disabled when the relay is unreachable', async function () {
        // This assertion depends on the build-time RelayConfig override
        // that rewrites the relay URL to a localhost endpoint on
        // emulator/simulator targets — where nothing listens, so the
        // gate is always closed. On a physical device the URL is the
        // real .onion; if it's reachable the gate correctly opens and
        // this test's premise no longer holds.
        if (isPhysicalDevice()) {
            this.skip()
        }

        // Add a contact via the Debug tab (now behind the cogwheel menu).
        const settingsButton = await $(byId(Ids.settingsButton))
        await settingsButton.waitForDisplayed({ timeout: 10_000 })
        await settingsButton.click()

        const addButton = await $(byId(Ids.addContactButton))
        await addButton.waitForDisplayed({ timeout: 10_000 })
        await addButton.click()

        // Reveal the hidden no-camera paste exchange (5-tap gesture).
        await revealPasteExchange()

        const json = '{"inbox":"550e8400-e29b-41d4-a716-446655440000","secret":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}'
        const code = Buffer.from(json).toString('base64')

        const input = await $(byId(Ids.debugCodeInput))
        await input.waitForDisplayed()
        await input.setValue(code)

        const addContactBtn = await $(byId(Ids.debugAddContactButton))
        await addContactBtn.click()

        // Both platforms: paste → Add contact → Done step (with QR + optional
        // mnemonic field). No intermediate alias overlay / mnemonic sheet.

        const done = await $(byId(Ids.addContactDone))
        await done.waitForDisplayed({ timeout: 10_000 })
        await done.click()

        // Open the conversation.
        const row = await $(`//*[starts-with(@name, "contact_row_") or starts-with(@resource-id, "contact_row_")]`)
        await row.waitForDisplayed({ timeout: shortTimeout() })
        await row.click()

        // Wait for conversation to load.
        const sendBtn = await $(byId(Ids.sendButton))
        await sendBtn.waitForDisplayed({ timeout: 10_000 })

        // Type a message — non-empty input is one of the gate's two preconditions
        // (the other is relay reachability), so this isolates the relay gate.
        const msgInput = await $(byId(Ids.messageInput))
        await msgInput.setValue('hello world')

        // The relay is unreachable on the emulator/simulator (no listener at
        // the localhost override URL), so the send button must stay disabled.
        // Sample a few times in case the periodic relay check (10 s cycle)
        // is mid-flight when we first read the state.
        for (let i = 0; i < 3; i++) {
            const enabled = await sendBtn.isEnabled()
            if (!enabled) break
            await browser.pause(2_000)
        }
        const enabled = await sendBtn.isEnabled()
        if (enabled) {
            throw new Error('send button is enabled despite relay being unreachable — gate is broken')
        }

        // Clicking a disabled button must not produce a bubble. Try anyway
        // to confirm the gate holds even under user interaction.
        try { await sendBtn.click() } catch { /* disabled buttons may throw */ }
        await browser.pause(1_000)
        const sent = await $(byId(Ids.messageBubbleSent))
        await sent.waitForDisplayed({ reverse: true, timeout: 2_000 })
    })

    // Skipped: piggybacked on the now-skipped "send disabled" test (same
    // contact-seed dependency on the legacy paste exchange).
    it.skip('no message bubble persists after reopening when send was blocked', async function () {
        // This test piggybacks on the previous one's "send was blocked"
        // state — same skip applies on physical devices, where the
        // relay-unreachable premise no longer holds.
        if (isPhysicalDevice()) {
            this.skip()
        }

        // Sent messages are never persisted to the DB. Since the previous
        // test was unable to send (button disabled), there is nothing in
        // the DB and nothing in memory either. Leaving and returning to
        // the conversation must yield an empty thread.
        await driver.back()
        await browser.pause(1_000)

        const row = await $(`//*[starts-with(@name, "contact_row_") or starts-with(@resource-id, "contact_row_")]`)
        await row.waitForDisplayed({ timeout: shortTimeout() })
        await row.click()

        const sendBtn = await $(byId(Ids.sendButton))
        await sendBtn.waitForDisplayed({ timeout: 10_000 })

        const anyBubble = await $(byId(Ids.messageBubbleSent))
        await anyBubble.waitForDisplayed({ reverse: true, timeout: shortTimeout() })
    })
})

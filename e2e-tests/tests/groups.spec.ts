import { Ids, byId } from '../helpers/AccessibilityIds'
import {
    enterPin,
    waitForKeypad,
    waitForPinScreen,
    completePinSetup, dismissPostConnectModalsIfPresent } from '../helpers/PinHelper'
import { resetApp } from '../helpers/AppReset'
import * as MockRelay from '../helpers/MockRelay'

const REAL_PIN = '111111'


/**
 * Opens the cogwheel dropdown and taps the item with the given id, retrying
 * the whole open if the menu doesn't materialise. On a cold iOS simulator the
 * FIRST Menu open after unlock can take longer than the item-wait budget (the
 * menu renders in a separate overlay window XCUITest has to re-snapshot);
 * about.spec gets away without retries because its menu opens happen later in
 * a warmed-up session.
 *
 * The item here is RELAY-GATED ("New group", like "Add contact"): its row is in
 * the tree from the moment the menu opens, yet a tap is a silent no-op until the
 * app's health check has seen the relay answer (~8-12s after MockRelay.start()).
 * So the wait is for ENABLED, not merely displayed — a displayed-then-click taps
 * into the void and fails 10s later on the next screen's marker instead.
 */
async function openSettingsMenuItem(itemId: string): Promise<void> {
    for (let attempt = 1; attempt <= 3; attempt++) {
        // The push prompt fires on the FIRST relay answer — i.e. right after the
        // MockRelay.start() that precedes this call — and on iOS a modal hides the
        // cogwheel from the a11y tree, so clear it BEFORE waiting for the button
        // (2026-11-04 iOS-sim red: "settings_button still not displayed").
        await dismissPostConnectModalsIfPresent(150)
        const settings = await $(byId(Ids.settingsButton))
        const item = await $(byId(itemId))
        try {
            await settings.waitForDisplayed({ timeout: 10_000 })
            await settings.click()
            // waitForExist, not waitForDisplayed: a disabled row is still in the
            // tree, and iOS 26 SwiftUI can report list rows visible=false anyway.
            await item.waitForExist({ timeout: 8_000 })
            await browser.waitUntil(async () => {
                // The first relay answer fires the one-shot push prompt (08c3d446):
                // a modal Dialog over the OPEN menu that no outside-tap dismisses —
                // race it the way relay-loss.spec.ts's analogous wait does.
                await dismissPostConnectModalsIfPresent(150)
                return item.isEnabled()
            }, {
                timeout: 60_000, interval: 500,
                timeoutMsg: `"${itemId}" never became enabled — app did not see the mock relay as reachable`,
            })
            await item.click()
            return
        } catch {
            // Menu didn't open or got dismissed — tap outside to reset state,
            // then retry the full open.
            try {
                await driver.action('pointer')
                    .move({ x: 20, y: 400 }).down().pause(50).up().perform()
            } catch { /* best-effort dismiss */ }
            await browser.pause(1_500)
        }
    }
    throw new Error(`settings menu item "${itemId}" never appeared after 3 attempts`)
}

/** Closes the settings surface: an iOS sheet has a Done button, the Android
 *  DropdownMenu dismisses on an outside tap. */
async function dismissSettingsMenu(): Promise<void> {
    const done = await $(byId('settings_sheet_done'))
    if (await done.isExisting()) { await done.click() }
    else {
        await driver.action('pointer')
            .move({ x: 20, y: 400 }).down().pause(50).up().perform()
    }
    await browser.pause(500)
}

/**
 * Single-device group UI coverage.
 *
 * Real groups need relay-backed contacts (the capability protocol's inbox is
 * server-minted, so contacts cannot be fabricated on one device — same
 * constraint as contacts.spec.ts). Full create/invite/message/membership
 * flows live in the physical-device suite (not published).
 *
 * What IS verifiable on one fresh device:
 *   • the "New group" entry point is DISABLED while the relay is unreachable
 *     (creating a group mints an inbox + fans out invites — same gate as
 *     "Add contact"); the mock relay on host :8080 then lifts it,
 *   • the entry point opens the create screen once the relay answers,
 *   • the create button refuses to create a group with no members
 *     (a memberless "group" would silently degrade to a broken 1:1),
 *   • backing out returns to the contact list with no group row created.
 *
 * Test order is load-bearing: the disabled assertion must run BEFORE
 * MockRelay.start(), which is why the mock comes up mid-suite rather than in
 * `before`.
 */
describe('Groups (single device)', () => {

    before(async () => {
        await resetApp()
        await waitForPinScreen()
        await completePinSetup(REAL_PIN)
        // First run opens the vault directly once the PIN is confirmed.
        const root = await $(byId(Ids.unlockedRoot))
        await root.waitForDisplayed({ timeout: 30_000 })
    })

    after(async () => { await MockRelay.stop() })

    // Creating a group mints its inbox and fans the invites out over the relay,
    // so the entry point is gated on relay reachability exactly like "Add
    // contact". Nothing is listening on the host :8080 yet, so the app has never
    // seen the relay answer — both rows must be present but inert.
    it('"New group" is disabled while the relay is unreachable', async () => {
        const settings = await $(byId(Ids.settingsButton))
        await settings.waitForDisplayed({ timeout: 10_000 })
        await settings.click()

        const newGroup = await $(byId(Ids.createGroupMenuButton))
        // waitForExist, not waitForDisplayed: a disabled row is still in the tree,
        // and iOS 26 SwiftUI can report list rows visible=false regardless.
        await newGroup.waitForExist({ timeout: 10_000 })
        expect(await newGroup.isEnabled()).toBe(false)

        // Parity with the item this gate was modelled on.
        const addContact = await $(byId(Ids.addContactButton))
        await addContact.waitForExist({ timeout: 10_000 })
        expect(await addContact.isEnabled()).toBe(false)

        // A tap while gated is a silent no-op — prove it goes nowhere.
        try { await newGroup.click() } catch { /* disabled on iOS throws — fine */ }
        await browser.pause(1_000)
        expect(await (await $(byId(Ids.groupNameInput))).isExisting()).toBe(false)

        await dismissSettingsMenu()
    })

    it('"New group" in the settings menu opens the create-group screen', async () => {
        // Bring the relay up: the mock listens on the host :8080, which the
        // emulator reaches at 10.0.2.2 and the simulator at localhost (see
        // RelayConfig.{android,ios}.kt). The app's health check flips the gate on
        // within a poll cycle (~8-12s).
        await MockRelay.start()
        await openSettingsMenuItem(Ids.createGroupMenuButton)

        const nameInput = await $(byId(Ids.groupNameInput))
        await nameInput.waitForDisplayed({ timeout: 10_000 })
    })

    it('create is refused with a name but no selected members', async () => {
        const nameInput = await $(byId(Ids.groupNameInput))
        await nameInput.click()
        await nameInput.setValue('crew')

        // Fresh install: zero contacts, so zero selectable members. Tapping
        // the create button must be a no-op — we stay on the create screen.
        // (Click-and-stay instead of isEnabled(): platform-agnostic, and it
        // asserts the actual security-relevant behaviour, not a UI flag.)
        const createBtn = await $(byId(Ids.createGroupButton))
        await createBtn.waitForDisplayed({ timeout: 5_000 })
        try { await createBtn.click() } catch { /* disabled on iOS throws — fine */ }
        await browser.pause(1_000)

        await (await $(byId(Ids.groupNameInput))).waitForDisplayed({ timeout: 5_000 })
    })

    it('backing out creates nothing', async () => {
        await (await $(byId(Ids.createGroupBack))).click()
        await browser.pause(1_000)

        // Back on the unlocked root, and no group row exists.
        await (await $(byId(Ids.unlockedRoot))).waitForDisplayed({ timeout: 10_000 })
        const groupRow = await $(
            `//*[starts-with(@name, "group_row_") or starts-with(@resource-id, "group_row_")]`
        )
        expect(await groupRow.isExisting()).toBe(false)
    })

})

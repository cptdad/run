// Relay-loss recovery (e2e). Pairs a healthy contact against the controllable
// mock relay, then wipes the relay's inboxes (dropAll) and proves the app's
// control-channel poller detects the persistent 404s and flips the contact to
// the "Re-pair required" recovery state — the same user-facing path a real
// relay loss takes (MessageManager.relayLostContacts → ContactListScreen row
// stale flag). The detection logic itself is unit-tested in RelayLossTest; this
// proves it surfaces end-to-end on a device.
import { Ids, byId } from '../helpers/AccessibilityIds'
import { completePinSetup, waitForPinScreen, dismissPostConnectModalsIfPresent } from '../helpers/PinHelper'
import { resetApp } from '../helpers/AppReset'
import { revealPasteExchange } from '../helpers/AddContactHelper'
import { waitOptional } from '../helpers/BestEffort'
import * as MockRelay from '../helpers/MockRelay'

const PIN = '111111'

// A full v7 pairing code (base64 of the pairing JSON). The PEER fields only need
// valid *shape* — they're never dialled here. What matters is that pasting a
// FULL code (not legacy/secret-only) drives the app to MINT its own inbound +
// control inboxes against the mock; those minted inboxes are exactly what
// dropAll() wipes and the relay-loss poller then misses.
//   secret      : 32 bytes (the parser asserts the decoded length == 32)
//   inbox+wcap  : 32-char id + 43-char cap → a real outbound ⇒ contact NOT stale
//   cib+cwcap   : the matching control pair (32-char id + 43-char cap)
function pairingCode(): string {
    const json = JSON.stringify({
        secret: Buffer.alloc(32, 7).toString('base64'),
        inbox: 'A'.repeat(32),
        wcap: 'A'.repeat(43),
        cib: 'B'.repeat(32),
        cwcap: 'B'.repeat(43),
    })
    return Buffer.from(json).toString('base64')
}

// ContactRow tags its "Re-pair required" line `contact_repair_<id>` whenever the
// row is stale/relay-lost. resourceIdMatches lets us assert the flip without
// knowing the app-minted contactId.
const anyContactRow = 'android=new UiSelector().resourceIdMatches("contact_row_.*")'
const anyRepair = 'android=new UiSelector().resourceIdMatches("contact_repair_.*")'

describe('relay-loss recovery — e2e', () => {
    // Android-only. This spec drives the mock relay (reached at 10.0.2.2 from the
    // emulator) and asserts via UiSelector resourceIdMatches — both Android
    // specifics. The host-loopback mock isn't reachable from a physical iOS
    // device, and iOS has no UiSelector. The detection logic itself is unit-
    // tested cross-platform in RelayLossTest.
    before(async function () {
        if (!browser.isAndroid) { this.skip(); return }
        await MockRelay.start()
    })
    after(async () => { await MockRelay.stop() })

    it('a relay inbox wipe flips a paired contact to "Re-pair required"', async function () {
        // Detection needs 4 control-poll 404s (RELAY_LOST_404_STREAK) at the IDLE
        // cadence, 60–90 s jittered since 70bb3930 (Fix 3b; was 25–45 s) ⇒ up to
        // ~360 s, plus PIN + pairing setup. Give this one test explicit headroom.
        this.timeout(600_000)

        await MockRelay.reset()
        await resetApp()
        await waitForPinScreen()
        await completePinSetup(PIN)
        await (await $(byId(Ids.unlockedRoot))).waitForDisplayed({ timeout: 30_000 })

        // Pair via the hidden paste exchange. With the mock answering, the app
        // mints its own inbound + control inboxes for real — the same relay
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
            timeoutMsg: 'Add-contact never enabled — app did not see the mock relay',
        })
        await addBtn.click()
        await revealPasteExchange()
        await (await $(byId(Ids.debugCodeInput))).setValue(pairingCode())
        await (await $(byId(Ids.debugAddContactButton))).click()
        // The full-code paste mints our inboxes (network round-trips to the mock)
        // and then usually shows a "Done" confirmation. Tolerate either that or a
        // flow that drops straight back to the list.
        const done = await $(byId(Ids.addContactDone))
        if (await waitOptional(done.waitForDisplayed({ timeout: 30_000 }))) await done.click()

        // The contact landed and starts HEALTHY — no re-pair tag yet.
        await (await $(anyContactRow)).waitForDisplayed({ timeout: 20_000 })
        expect(await (await $(anyRepair)).isExisting()).toBe(false)

        // The relay loses every inbox; the app's control polls now 404 forever.
        await MockRelay.dropAllInboxes()

        // The poller crosses its 404 streak and flips the contact into re-pair.
        await (await $(anyRepair)).waitForDisplayed({
            timeout: 500_000,
            timeoutMsg: 'Contact never flipped to "Re-pair required" after the relay inbox wipe',
        })
    })
})

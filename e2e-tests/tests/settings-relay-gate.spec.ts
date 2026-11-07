// Settings-menu relay gating (2026-09-28 directive): "all menu items that
// require connection to the relay should be disabled when relay is
// unavailable." Proves the cogwheel's 5 relay-dependent rows — Add contact,
// Create group, Move to new device, Notifications/Push settings, Report bug —
// disable together while the relay is unreachable and re-enable together once
// it answers, using the mock relay to flip reachability deterministically.
// Platform-neutral, run on BOTH Android emulator and iOS simulator, same
// shape as update-nudge.spec.ts: the mock listens on host :8080, reached at
// 10.0.2.2 (Android emulator) / localhost (iOS simulator).
import { Ids, byId } from '../helpers/AccessibilityIds'
import { waitForPinScreen, completePinSetup, dismissPostConnectModalsIfPresent } from '../helpers/PinHelper'
import { resetApp } from '../helpers/AppReset'
import * as MockRelay from '../helpers/MockRelay'

const PIN = '111111'

/** "Notifications" (Android) / "Push settings" (iOS) — same row, different id
 *  per platform (see the 2026-09-28 decision doc). */
const notificationsId = (): string => (browser.isAndroid ? Ids.menuNotifications : 'push_settings_menu_button')

/** The 5 relay-dependent cogwheel rows. Minting needs the relay (Add contact /
 *  Create group / Move export), push registration + opt-out DELETE needs it
 *  (Notifications), and Report bug POSTs to it. */
const relayGatedIds = (): string[] => [
    Ids.addContactButton,
    Ids.createGroupMenuButton,
    Ids.moveToNewDeviceButton,
    notificationsId(),
    Ids.reportBugMenuItem,
]

/** Local rows that must stay enabled regardless of relay reachability. */
const localIds: string[] = [
    Ids.changePinButton,
    Ids.protectionLevelMenuButton,
    Ids.menuLanguage,
    Ids.menuAbout,
]

/** Opens the settings cogwheel. No-op if already open (add_contact_button —
 *  present, whether enabled or disabled — is the "sheet/menu is open"
 *  sentinel, same convention as Device.openSettingsMenu). Retries the tap
 *  (mirrors Device.ts's multi-device openSettingsMenu): a single dropped tap
 *  during the contact list's own nav transition — the FIRST open of this
 *  spec's run races the pre-reveal placeholder settling in — otherwise spins
 *  the whole budget on a sheet that was never asked to present (proven:
 *  2026-09-28 iOS sim run, one single-shot 10s wait timed out and the very
 *  next screenshot shows the sheet fully rendered a beat later). */
async function openSettingsMenu(): Promise<void> {
    const sentinel = await $(byId(Ids.addContactButton))
    if (await sentinel.isExisting().catch(() => false)) return
    const settings = await $(byId(Ids.settingsButton))
    await settings.waitForDisplayed({ timeout: 10_000 })
    for (let attempt = 1; attempt <= 4; attempt++) {
        if (await sentinel.isExisting().catch(() => false)) return
        await settings.click()
        try {
            await sentinel.waitForExist({ timeout: 8_000 })
            return
        } catch { /* dropped tap / slow first present — retry */ }
    }
    throw new Error('settings sheet did not open after 4 attempts')
}

/** Closes the settings dropdown (Android) / sheet (iOS). Android's system
 *  back dismisses the popup; iOS taps its own "Done" button when present,
 *  falling back to back (mirrors language.spec.ts / l10n-sweep.spec.ts). */
async function closeSettingsMenu(): Promise<void> {
    if (browser.isAndroid) {
        await driver.back().catch(() => undefined)
        return
    }
    const done = await $(byId('settings_sheet_done'))
    if (await done.isExisting().catch(() => false)) {
        await done.click()
        return
    }
    await driver.back().catch(() => undefined)
}

/**
 * Locates [id] in the OPEN settings menu/sheet. iOS's lazy List can keep
 * lower rows out of the a11y tree until scrolled (about.spec.ts/ugc.spec.ts/
 * multi/Device.ts's scrollSettingsTo all hit this on a short screen);
 * Android's dropdown is not lazy, so the scroll attempt below is a no-op
 * there (caught and ignored, same as ugc.spec.ts's pattern).
 */
async function findMenuRow(id: string) {
    const el = await $(byId(id))
    for (let attempt = 0; attempt < 6; attempt++) {
        if (await el.waitForExist({ timeout: 2_000 }).then(() => true, () => false)) return el
        await driver.execute('mobile: scroll', { direction: 'down' }).catch(() => { /* Android no-op / already at bottom */ })
    }
    await el.waitForExist({ timeout: 2_000 })
    return el
}

async function assertRowsEnabled(ids: string[], expected: boolean): Promise<void> {
    for (const id of ids) {
        const el = await findMenuRow(id)
        const enabled = await el.isEnabled()
        expect(enabled).toBe(expected)
    }
}

/**
 * True iff the settings menu/sheet is open AND add_contact_button currently
 * reports `expected` for isEnabled(). NEVER throws — every step is
 * best-effort — so a `browser.waitUntil` polling this can survive the
 * connect-time push prompt (it fires on the FIRST relay answer, the very
 * reachability transition this spec races) snatching the dropdown/sheet mid-
 * attempt and simply retry on the next tick, rather than aborting the whole
 * wait on the first collision. `dismissPostConnectModalsIfPresent` clears the
 * prompt (and the update-nudge dialog) if either is currently up; it is a
 * harmless no-op once the one-shot prompt has already fired and been
 * dismissed (the disable-again direction below).
 */
async function addContactButtonEnabledIs(expected: boolean): Promise<boolean> {
    await dismissPostConnectModalsIfPresent(150)
    try { await openSettingsMenu() } catch { return false }
    const enabled = await (await $(byId(Ids.addContactButton))).isEnabled().catch(() => !expected)
    return enabled === expected
}

describe('Settings menu — relay-dependent rows disable when the relay is unreachable', () => {
    before(async function () {
        this.timeout(300_000)
        await resetApp()
        await waitForPinScreen()
        await completePinSetup(PIN)
        await (await $(byId(Ids.unlockedRoot))).waitForDisplayed({ timeout: 30_000 })
    })

    // Best-effort: a failed assertion mid-suite must not leave the mock relay
    // running for whatever spec runs next in the same session.
    after(async () => { await MockRelay.stop().catch(() => undefined) })

    it('disables the 5 relay-dependent rows (and none of the local rows) while the relay is unreachable', async () => {
        // No MockRelay.start() yet — the emulator/simulator relay URL is the
        // host loopback, which is unreachable until the mock is listening.
        await openSettingsMenu()
        await assertRowsEnabled(relayGatedIds(), false)
        await assertRowsEnabled(localIds, true)
        await closeSettingsMenu()
    })

    it('enables the 5 relay-dependent rows once the mock relay answers', async function () {
        this.timeout(120_000)
        await MockRelay.start()
        // addContactButtonEnabledIs opens the menu itself EVERY tick (and
        // never throws), so this survives the connect-time push prompt firing
        // — and snatching the dropdown/sheet — at any point during the poll,
        // not just before it starts.
        await browser.waitUntil(() => addContactButtonEnabledIs(true), {
            timeout: 90_000,
            interval: 1_000,
            timeoutMsg: 'add_contact_button never enabled after MockRelay.start()',
        })
        await assertRowsEnabled(relayGatedIds(), true)
        await closeSettingsMenu()
    })

    it('disables the 5 relay-dependent rows again once the mock relay stops', async function () {
        this.timeout(120_000)
        await MockRelay.stop()
        // No modal expected here — the connect-time push prompt is one-shot
        // per vault and already fired/was dismissed in the previous case —
        // but addContactButtonEnabledIs's dismiss-and-reopen shape costs
        // nothing extra and keeps this resilient to the same class of races.
        // The reachability streak (~24s) plus iOS's 3s litVisible dark-out
        // debounce is the dominant latency, hence the 90s budget.
        await browser.waitUntil(() => addContactButtonEnabledIs(false), {
            timeout: 90_000,
            interval: 1_000,
            timeoutMsg: 'add_contact_button never disabled after MockRelay.stop()',
        })
        await assertRowsEnabled(relayGatedIds(), false)
        await closeSettingsMenu()
    })
})

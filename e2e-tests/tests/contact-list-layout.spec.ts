// Contact-list layout regression (iOS simulator only).
//
// Locks the 2026-09-04 fix for two production symptoms on Dynamic-Island
// iPhones that the physical test phones (notch / SE) never showed: (1) the first
// contact row drawn under the status bar / nav band and (2) rows dimmed
// (relay unreachable) with NO "Connecting…" banner. Root cause was structural:
// ContactListView's runestone background was a fixed-screen-size ZStack CHILD,
// which made the ZStack overflow its container; .safeAreaInset(edge: .bottom)
// then re-centred the oversized composite (every row jumped up by half the
// banner height) and placed the banner below the window bottom. Geometry is
// asserted via a11y element RECTS in points, never pixels.
//
// Seeds 13 rows through AppState.swift's DEBUG-only --test-seed-contacts=<N>
// seam (a cold relaunch of the already-provisioned vault WITH that arg, then a
// re-unlock — the seed fires from AppState.unlock on that process).
//
// Getting into the state under test takes TWO relay steps since the 2026-09-11
// first-reveal gate (ContactListView.listRevealed): the list is not rendered at
// all until the relay answers once per session, so "never started the mock
// relay" would now mean "no rows at all", not "dimmed rows". So: bring the mock
// relay UP to trigger the one reveal this session needs, then take it DOWN
// again. Only the FIRST reveal is gated — the list stays on screen when
// reachability is lost — which is exactly the state these geometry assertions
// need: rows visible, rows dimmed, contacts-present relayTroubleBanner on
// screen.
import { Ids, byId } from '../helpers/AccessibilityIds'
import { enterPin, waitForPinScreen, completePinSetup, dismissPostConnectModalsIfPresent } from '../helpers/PinHelper'
import { resetApp } from '../helpers/AppReset'
import { iosLanguageArgs } from '../helpers/AppLocale'
import * as MockRelay from '../helpers/MockRelay'
import { isSimulatorUdid } from '../wdio.shared.conf'

const PIN = '111111'
const BUNDLE_ID = 'com.vg.run'
const SEED_COUNT = 13
const FIRST_ROW = Ids.contactRow('seedtestcontact01')
const LAST_ROW = Ids.contactRow(`seedtestcontact${String(SEED_COUNT).padStart(2, '0')}`)
// Minimum first-row clearance on ANY iPhone class (ContactListView.topClearance's
// 88pt floor — the tuned rest position on the SE / notch classes).
const MIN_TOP_CLEARANCE = 88

interface Rect { x: number; y: number; width: number; height: number }

async function rectOf(id: string): Promise<Rect | undefined> {
    const el = await $(byId(id))
    if (!(await el.isExisting().catch(() => false))) return undefined
    const r = await driver.getElementRect(await el.elementId).catch(() => undefined)
    return r ? { x: r.x, y: r.y, width: r.width, height: r.height } : undefined
}

describe('contact-list layout — first row clear of the bars, relay banner on screen', () => {
    before(async function () {
        // iOS SIMULATOR-only. iOS because the seed seam is a Swift DEBUG hook
        // and the geometry under test is SwiftUI's (Android's Compose list is
        // covered by its own tests); SIMULATOR because the whole spec drives
        // the LOCAL mock relay (helpers/MockRelay) over localhost — a physical
        // iPhone reaches the relay only over Tor, so on a device this would
        // never leave the first-reveal gate. `isSimulatorUdid` is the same
        // membership check the physical-only guard uses (wdio.shared.conf.ts),
        // just inverted, so the two can never disagree about a UDID.
        if (!browser.isIOS) { this.skip(); return }
        const udid = (browser.capabilities as any)?.['appium:udid'] as string | undefined
        if (!isSimulatorUdid(udid ?? process.env.WDIO_IOS_UDID)) {
            console.log('contact-list-layout: SKIPPING — target is not an iOS Simulator '
                + `(udid=${udid ?? process.env.WDIO_IOS_UDID ?? '(none)'}); this spec needs the local mock relay.`)
            this.skip()
            return
        }
        await resetApp()
        await waitForPinScreen()
        await completePinSetup(PIN)
        await (await $(byId(Ids.unlockedRoot))).waitForExist({ timeout: 60_000 })

        // Cold relaunch WITH the seed arg (mobile: launchApp REPLACES the launch
        // args of a not-running app — the session-level wipe flag does not
        // ride along, and no fresh nonce ⇒ no wipe), then re-unlock.
        try { await driver.terminateApp(BUNDLE_ID) } catch { /* not running */ }
        await browser.pause(800)
        await driver.execute('mobile: launchApp', {
            bundleId: BUNDLE_ID,
            arguments: [`--test-seed-contacts=${SEED_COUNT}`, ...iosLanguageArgs()],
        })
        await browser.pause(800)
        await waitForPinScreen(30_000)
        await enterPin(PIN)
        await (await $(byId(Ids.unlockedRoot))).waitForExist({ timeout: 60_000 })

        // Reveal step 1 — relay UP so the list is drawn at all (first-reveal
        // gate; see the file header). runestone_lit_active is the app's own
        // "relay answered, rows interactive" marker.
        await MockRelay.start()
        // The push-notification prompt fires on the FIRST RELAY ANSWER of the
        // session (2026-09-11), i.e. right as runestone_lit_active appears — race
        // dismissPostConnectModalsIfPresent() into this poll (PinHelper.ts's own
        // header: "every single-device wait for the connected/revealed state
        // should ALSO call" it) rather than a one-shot check after the fact. An
        // undismissed prompt is a full-screen scrim that swallows every later
        // swipe in this spec, leaving the list's pre-scroll rest position exactly
        // where it started and reading as "never scrolled" (proven via screenshot:
        // 2026-09-28 iOS sim run, all three swipes landed on the "Enable push
        // notifications?" alert instead of the ScrollView underneath it).
        await browser.waitUntil(async () => {
            await dismissPostConnectModalsIfPresent()
            return (await $(byId(Ids.runestoneLitActive))).isExisting().catch(() => false)
        }, {
            timeout: 120_000,
            interval: 500,
            timeoutMsg: 'mock relay up but the list never revealed (runestone_lit_active) — first-reveal gate never opened',
        })
        await dismissPostConnectModalsIfPresent()
        await (await $(byId(FIRST_ROW))).waitForExist({ timeout: 30_000 })

        // Reveal step 2 — relay DOWN again. The list must STAY on screen (only
        // the first reveal is gated) while the rows dim and the relay banner
        // appears. AppState.startRelayCheck probes every 8-12 s and needs a
        // miss streak before it flips, so allow a generous window.
        await MockRelay.stop()
        await (await $(byId(Ids.runestoneLitInactive))).waitForExist({
            timeout: 180_000,
            timeoutMsg: 'mock relay stopped but the app never went unreachable (runestone_lit_inactive)',
        })
        await (await $(byId(FIRST_ROW))).waitForExist({
            timeout: 15_000,
            timeoutMsg: 'the revealed list disappeared when the relay went away — only the FIRST reveal may be gated',
        })
    })

    it('first content sits below the status bar and the nav-band cogwheel', async () => {
        const win = await driver.getWindowRect()
        const gear = await rectOf(Ids.settingsButton)
        expect(gear).toBeDefined()
        const gearBottom = gear!.y + gear!.height
        // The seeded rows are stale, so the RepairBanner is the FIRST content;
        // it and the first row must both clear the bars.
        const repair = await rectOf('repair_banner')
        const first = await rectOf(FIRST_ROW)
        expect(first).toBeDefined()
        const topmost = Math.min(repair?.y ?? Number.POSITIVE_INFINITY, first!.y)
        console.log(`[layout] window=${win.width}x${win.height} gearBottom=${gearBottom} repair.y=${repair?.y} firstRow.y=${first!.y}`)
        expect(topmost).toBeGreaterThanOrEqual(MIN_TOP_CLEARANCE)
        expect(topmost).toBeGreaterThanOrEqual(gearBottom)
    })

    it('relay banner is ON SCREEN while the rows are dimmed (relay unreachable)', async () => {
        const win = await driver.getWindowRect()
        // Rows dim on isRelayReachable; the lit marker mirrors it (debounced).
        // If something IS answering on :8080 (an orphaned relay), the rows are
        // not dimmed and there is nothing to assert — say so loudly and pass.
        if (await (await $(byId(Ids.runestoneLitActive))).isExisting().catch(() => false)) {
            console.log('[layout] WARNING: relay reachable on the sim (lit) — banner assertion skipped')
            return
        }
        // Any of the three banner phases counts; the pre-connect caption is the
        // expected one on a sim (direct HTTP ⇒ torState connected, relay down).
        let banner: Rect | undefined
        await browser.waitUntil(async () => {
            banner = await rectOf('tor_progress_caption')
                ?? await rectOf('relay_reconnect_button')
                ?? await rectOf('relay_relaunch_hint')
            return !!banner
        }, { timeout: 10_000, interval: 300, timeoutMsg: 'rows dimmed but no relay banner element in the a11y tree' })
        console.log(`[layout] banner rect=${JSON.stringify(banner)} window.height=${win.height}`)
        expect(banner!.y).toBeGreaterThanOrEqual(0)
        expect(banner!.y + banner!.height).toBeLessThanOrEqual(win.height)
    })

    after(async () => {
        // The flip test below brings the mock relay up; never leave it running
        // for the next spec (MockRelay.start refuses an occupied :8080).
        await MockRelay.stop()
    })

    it('last row scrolls fully into view, clear of the banner', async () => {
        const win = await driver.getWindowRect()
        for (let k = 0; k < 3; k++) {
            await driver.execute('mobile: swipe', { direction: 'up' }).catch(() => {})
            await browser.pause(400)
        }
        await browser.pause(600)
        const last = await rectOf(LAST_ROW)
        expect(last).toBeDefined()
        const lastBottom = last!.y + last!.height
        const caption = await rectOf('tor_progress_caption')
        console.log(`[layout] lastRow=${JSON.stringify(last)} caption=${JSON.stringify(caption)}`)
        expect(lastBottom).toBeLessThanOrEqual(win.height)
        // 12 = the banner's own vertical padding above the caption text.
        if (caption) expect(lastBottom).toBeLessThanOrEqual(caption.y - 12)
    })
    it('rows scrolled while disabled are on screen and tappable once the relay lights', async () => {
        // Bug 3 of runestone-lit-vs-tappable-gap (2026-09-05): rows scrolled
        // while DISABLED (relay unreachable) were not tappable once enabled —
        // the bottom banner's safeAreaInset collapsed in the same update that
        // enabled the rows, shrinking the ScrollView inset and re-clamping the
        // content offset. Static scroll-to-bottom, then flip reachability by
        // starting the mock relay: the last row must stay fully on screen and
        // its tap must land (a stale seeded row opens the Add-Contact sheet).
        const win = await driver.getWindowRect()
        if (await (await $(byId(Ids.runestoneLitActive))).isExisting().catch(() => false)) {
            console.log('[layout] WARNING: relay already reachable — flip assertion skipped')
            return
        }
        const before = await rectOf(LAST_ROW)   // list is at its bottom from the previous test
        expect(before).toBeDefined()
        await MockRelay.start()
        // AppState.startRelayCheck probes every 8–12 s; rows enable 0.8 s after
        // the white R starts its fade (rowsEnabled → runestone_lit_active).
        await (await $(byId(Ids.runestoneLitActive))).waitForExist({
            timeout: 90_000, timeoutMsg: 'rows never enabled after the mock relay came up',
        })
        await browser.pause(1000) // banner collapse (0.4 s) + row fade settle
        const after = await rectOf(LAST_ROW)
        expect(after).toBeDefined()
        console.log(`[layout] lastRow before=${JSON.stringify(before)} after=${JSON.stringify(after)} window.height=${win.height}`)
        expect(after!.y).toBeGreaterThanOrEqual(0)
        expect(after!.y + after!.height).toBeLessThanOrEqual(win.height)
        // Tap it where it is NOW. XCUITest clicks a disabled element silently, so
        // the sheet appearing is the only proof the tap actually landed.
        await (await $(byId(LAST_ROW))).click()
        await (await $(byId(Ids.addContactCancel))).waitForExist({
            timeout: 15_000, timeoutMsg: 'tapping the last row after the relay flip did nothing',
        })
        await (await $(byId(Ids.addContactCancel))).click()
        await (await $(byId(LAST_ROW))).waitForExist({ timeout: 10_000 })
    })
})

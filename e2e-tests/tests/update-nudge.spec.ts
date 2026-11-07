// Update-available nudge (e2e). Behavior under test (docs/update-nudge-plan.md,
// locked decision 6): the client reads the platform's `ios-version` /
// `android-version` header off the FIRST successful relay response of the
// session and, if the relay advertises a version strictly newer than the
// app's own AND the once-per-day-per-version throttle allows it, shows a
// fixed-copy modal (`update_nudge_dialog` / `update_nudge_later_button` /
// `update_nudge_store_button`) on the contact list. `update_nudge_later_button`
// is REUSED for both the dismissible "Later" (store-capable install) and the
// sole "OK" of the info-only variant — on a sideloaded/emulator/simulator
// debug build only the info-only variant can ever render (no store
// installer), so `update_nudge_store_button` must be ABSENT here; the store
// branch itself is out of scope for this harness (unit-tested app-side + a
// manual once-off check on a Play-installed build, per the plan doc).
//
// Platform-neutral, run on BOTH Android emulator and iOS simulator: unlike
// push-prompt.spec.ts this DOES need the mock relay reachable (the header
// rides the relay's very first response), but unlike the pairing-heavy
// mock-relay/relay-loss specs (Android-only — they need a real
// inbox mint round trip and the iOS-sim host-loopback mapping is otherwise
// unverified for that), this feature only needs the plain `GET /` health
// probe every session already opens with. The plan's own Shared section
// calls out the iOS-simulator NSURLSession-direct path specifically ("so the
// iOS sim e2e can never see the header" without it) — i.e. this spec is
// meant to exercise iOS sim too, not just Android.
//
// GUARD-VS-ASSERTION CONFLICT, same shape as push-prompt.spec.ts:
// PinHelper's guards (enterPin / completePinSetup, chained AFTER the
// push-prompt dismiss — see PinHelper.ts) now also dismiss
// update_nudge_dialog, so every OTHER single-device spec gets this guard for
// free. That guard would eat the very modal this spec exists to observe, so
// every unlock here uses the guard-free `*Raw` primitives
// (completePinSetupRaw / enterPinRaw), never completePinSetup / enterPin.
//
// Text assertion note: there is no dedicated a11y id for the nudge's message
// body (only the `update_nudge_dialog` container, per the plan), and
// RuneDialog's `message` Text carries no testTag of its own — so rather than
// guess whether the container's `getText()` aggregates descendant text (a
// Compose-semantics/XCUITest-merge detail this harness can't verify without
// the app-side implementation), the copy assertion below matches against the
// full page source, which always contains every text node regardless of how
// accessibility-merging is configured.
import { Ids, byId } from '../helpers/AccessibilityIds'
import { enterPinRaw, waitForPinScreen, completePinSetupRaw, dismissPushPromptRaw, tapUntilGone } from '../helpers/PinHelper'
import { resetApp, relaunchApp } from '../helpers/AppReset'
import { currentVersion, higherThanCurrent, lowerThanCurrent } from '../helpers/AppVersion'
import { appLanguageTag } from '../helpers/AppLocale'
import { nudgeMessageNeedle } from '../helpers/l10nNeedles'
import * as MockRelay from '../helpers/MockRelay'

const PIN = '111111'

/**
 * Sets the platform-under-test's advertised version, leaving the other
 * platform's key untouched (mirrors how the app itself only ever reads its
 * own header — see docs/update-nudge-plan.md's allowlist-in-the-actuals
 * design). MUST be called BEFORE the vault unlocks: the client latches onto
 * the FIRST successful relay response of the session, so a version set after
 * connect is too late.
 */
async function advertise(version: string | null): Promise<void> {
    if (browser.isAndroid) {
        await MockRelay.setVersions({ android: version })
    } else {
        await MockRelay.setVersions({ ios: version })
    }
}

/**
 * Shared negative-case body: unlock a fresh vault, then wait a bounded time
 * (long enough for the 8-12s health-loop poll that surfaces the nudge — see
 * RunViewModel.kt / AppState.swift — to have had a chance to fire) and assert
 * update_nudge_dialog never appeared.
 */
async function expectNoDialogAfterUnlock(): Promise<void> {
    await waitForPinScreen()
    await completePinSetupRaw(PIN)
    await dismissPushPromptRaw()
    await (await $(byId(Ids.unlockedRoot))).waitForDisplayed({ timeout: 30_000 })

    const dialog = await $(byId(Ids.updateNudgeDialog))
    await browser.pause(15_000)
    expect(await dialog.isExisting()).toBe(false)
}

describe('Update-available nudge', () => {

    before(async () => { await MockRelay.start() })
    after(async () => { await MockRelay.stop() })

    beforeEach(async () => {
        // reset() also clears any previously-advertised version (server-side
        // contract, mock-relay/server.js) — every case starts from "no
        // header" and opts in explicitly via advertise()/setVersions().
        await MockRelay.reset()
    })

    it('shows when the relay advertises a newer version; Later dismisses it; a same-day relaunch does not re-show it', async function () {
        this.timeout(360_000)
        const newer = higherThanCurrent()
        await advertise(newer)
        await resetApp()
        await waitForPinScreen()
        await completePinSetupRaw(PIN)
        await dismissPushPromptRaw()

        const dialog = await $(byId(Ids.updateNudgeDialog))
        await dialog.waitForDisplayed({ timeout: 30_000 })

        // Case-insensitive: RuneDialog renders its message in the runic
        // display style (all caps on Android — "NEW VERSION AVAILABLE").
        // Locale-aware (nudgeMessageNeedle): this spec always runs in English
        // by default (resetApp() never sets WDIO_APP_LANG), but a whole-suite
        // run under WDIO_APP_LANG=sv (or similar) must not falsely fail here —
        // see update-nudge-layout.spec.ts for the dedicated per-locale/variant
        // geometry coverage of this same dialog.
        const src = await browser.getPageSource()
        expect(src.toLowerCase()).toContain(nudgeMessageNeedle(appLanguageTag()))
        expect(await (await $(byId(Ids.updateNudgeStoreButton))).isExisting()).toBe(false)

        await tapUntilGone(Ids.updateNudgeLaterButton, Ids.updateNudgeDialog)
        await dialog.waitForDisplayed({ reverse: true, timeout: 10_000 })
        await (await $(byId(Ids.unlockedRoot))).waitForDisplayed({ timeout: 15_000 })

        // Relaunch — NOT resetApp/activateApp: relaunchApp() (AppReset.ts)
        // terminates + cold-launches with no wipe flag, preserving the vault
        // (and its update_nudge_v1 throttle key) and, since we never touched
        // the mock relay in between, the SAME advertised version. This
        // proves the once-per-day-per-version throttle specifically, not
        // merely "the modal only ever shows once per process".
        await relaunchApp()
        await waitForPinScreen()
        await enterPinRaw(PIN)
        await (await $(byId(Ids.unlockedRoot))).waitForDisplayed({ timeout: 15_000 })

        await browser.pause(15_000)
        expect(await dialog.isExisting()).toBe(false)
    })

    it('does not show when the relay advertises the current version', async function () {
        this.timeout(360_000)
        await advertise(currentVersion())
        await resetApp()
        await expectNoDialogAfterUnlock()
    })

    it('does not show when the relay advertises a lower version', async function () {
        this.timeout(360_000)
        await advertise(lowerThanCurrent())
        await resetApp()
        await expectNoDialogAfterUnlock()
    })

    it('does not show when the relay advertises no version (header absent)', async function () {
        this.timeout(360_000)
        // MockRelay.reset() in beforeEach already leaves the header absent;
        // the explicit clearVersions() call documents the intent at the
        // call site rather than relying silently on beforeEach's side effect.
        await MockRelay.clearVersions()
        await resetApp()
        await expectNoDialogAfterUnlock()
    })

    for (const malformed of ['v9.9.9', '9.9', '9.9.9.9']) {
        it(`does not show when the relay advertises a malformed version ("${malformed}")`, async function () {
            this.timeout(360_000)
            await advertise(malformed)
            await resetApp()
            await expectNoDialogAfterUnlock()
        })
    }
})

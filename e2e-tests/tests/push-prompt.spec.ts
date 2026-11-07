// Push-notification prompt (e2e). Behavior under test: on the FIRST RELAY
// ANSWER of the session — the exact instant `contact_list_hidden_until_connected`
// disappears and the (now-revealed) contact list renders (`empty_contacts_state`
// on a fresh vault; the runestone lights and Add-contact enables at the SAME
// instant) — a modal (`push_prompt` / `push_prompt_yes` / `push_prompt_no`,
// identical ids on both platforms) appears over it. "Yes" opens the
// notification-settings carousel; "No" dismisses with no further action.
// Shown once per vault (a vault-meta flag), so a resetApp wipe re-arms it —
// and a session that never reaches the relay never consumes it.
//
// 2026-09-11 BEHAVIOUR CHANGE: the prompt used to fire at UNLOCK; it now
// fires on the first relay answer instead (the same signal that lights the
// runestone / enables Add-contact / reveals rows — see
// the physical-device suite's dismissPushPromptIfPresent (not published)
// for the multi-device side). This spec therefore needs the mock relay
// UP — without it the reveal never happens and the prompt never fires (see
// tests/contact-list-layout.spec.ts / tests/mock-relay.spec.ts for the same
// MockRelay.start()/stop() pattern; it needs no platform branching — the app
// reaches :8080 at 10.0.2.2 from the Android emulator and at localhost from
// the iOS simulator, both handled by the build's emulator/simulator relay
// override).
//
// Platform-neutral: runs on BOTH Android and iOS, same as pin.spec.ts /
// vault.spec.ts.
//
// GUARD-VS-ASSERTION CONFLICT:
// PinHelper.completePinSetup() dismisses push_prompt itself (now a
// best-effort fallback — see dismissPushPromptIfPresent's kdoc), and every
// single-device wait for the connected/revealed state now races
// dismissPostConnectModalsIfPresent too (ContactListHelper.
// waitForEmptyOrPreConnectContactList). Either would eat the very modal this
// spec exists to observe, so both cases below drive the ENTIRE setup —
// including the confirm stage that triggers provisioning and auto-unlock —
// through completePinSetupRaw (enterPinRaw-based) instead of
// completePinSetup, the later re-unlock (case 1's relaunch) through
// enterPinRaw directly, and poll for the reveal/prompt with RAW existence
// checks instead of any guarded helper.
import { Ids, byId } from '../helpers/AccessibilityIds'
import {
    enterPinRaw,
    waitForKeypad,
    waitForPinScreen,
    completePinSetupRaw,
} from '../helpers/PinHelper'
import { resetApp, relaunchApp } from '../helpers/AppReset'
import * as MockRelay from '../helpers/MockRelay'

const PIN = '111111'

/**
 * Platform-appropriate "the notification carousel opened" sentinel.
 * Android's NotificationSettingsModal (androidApp/.../NotificationSettingsModal.kt)
 * exposes notif_carousel_next on every education page; iOS's PushSettingsView
 * (iosApp/iosApp/ContactListView.swift) renders the same shared-content
 * carousel but under its own id, push_settings_next — the two screens are
 * word-for-word/page-for-page mirrors of each other (see either file's
 * header) but were never given a single shared a11y id.
 */
function carouselNextId(): string {
    return browser.isIOS ? Ids.pushSettingsNext : Ids.notifCarouselNext
}

/** Platform-appropriate "switch page" sentinel — see Device.ts's
 *  enableIosPushTier2 (iOS) / NotificationSettingsModal.kt (Android) for the
 *  respective ids. Lives ONLY on the carousel's LAST page. */
function switchPageId(): string {
    return browser.isIOS ? Ids.pushSettingsToggle : Ids.bgNotificationsToggle
}

/**
 * Close the carousel push_prompt_yes opened, back to the contact list.
 * Android's ✕ (notification_settings_close) sits OUTSIDE the HorizontalPager
 * — present on every page, INCLUDING the no-distributor `notif_unavailable`
 * page (NotificationSettingsModal.kt: the close button lives in the outer
 * Column, not inside the per-state content) — so a single tap closes it from
 * wherever navigation left off. iOS's "Done" (push_settings_done) lives ONLY
 * on the carousel's LAST page (PushSwitchPageView), so reaching it means
 * tapping push_settings_next repeatedly first — mirrors the same navigation
 * loop Device.enableIosPushTier2 already uses for the multi-device suites.
 */
async function closeCarousel(): Promise<void> {
    if (browser.isIOS) {
        const doneSel = byId(Ids.pushSettingsDone)
        for (let i = 0; i < 8 && !(await (await $(doneSel)).isExisting()); i++) {
            await (await $(byId(Ids.pushSettingsNext))).click()
            await browser.pause(400)
        }
        await (await $(doneSel)).click()
    } else {
        await (await $(byId(Ids.notificationSettingsClose))).click()
    }
}

/** Wait (bounded) for the first-reveal gate to open: `empty_contacts_state`
 *  replaces `contact_list_hidden_until_connected` once the mock relay
 *  answers. This is the signal push_prompt is keyed on. */
/**
 * Wait for the first-reveal gate to open. The prompt under test is raised on
 * the SAME relay answer that reveals the list, and on Android its Dialog
 * window occludes the entire a11y tree — so while the prompt is up,
 * `empty_contacts_state` does not exist in the snapshot at all. Either id is
 * therefore proof the relay answered; the caller asserts which one it wanted.
 */
async function waitForReveal(timeout = 90_000): Promise<'empty' | 'prompt'> {
    let seen: 'empty' | 'prompt' | '' = ''
    await browser.waitUntil(async () => {
        if (await (await $(byId(Ids.pushPrompt))).isExisting().catch(() => false)) { seen = 'prompt'; return true }
        if (await (await $(byId(Ids.emptyContactsState))).isExisting().catch(() => false)) { seen = 'empty'; return true }
        return false
    }, {
        timeout,
        interval: 500,
        timeoutMsg: `neither push_prompt nor empty_contacts_state appeared within ${timeout}ms — `
            + 'the mock relay never answered (first-reveal gate never opened)',
    })
    return seen as 'empty' | 'prompt'
}

/**
 * Post-provision landing: `unlocked_root` OR the prompt itself. With the mock
 * relay on loopback the first relay answer lands within ~1 s of the auto-
 * unlock, so the prompt (which occludes the Android a11y tree) can already be
 * up before a plain unlocked_root wait even starts — racing the two is the
 * only order-independent way to get past this point.
 */
async function waitForUnlockedRootOrPrompt(timeout = 30_000): Promise<void> {
    await browser.waitUntil(async () => {
        if (await (await $(byId(Ids.pushPrompt))).isExisting().catch(() => false)) return true
        return (await $(byId(Ids.unlockedRoot))).isDisplayed().catch(() => false)
    }, { timeout, interval: 400, timeoutMsg: `neither unlocked_root nor push_prompt appeared within ${timeout}ms after provisioning` })
}

/**
 * Tap "No" and verify the dialog is gone; re-tap if a tap was swallowed
 * (same verify-until-gone loop Device.dismissPushPromptIfPresent uses). The
 * FIRST tap is expected to work — the loop only reports how many it took,
 * and the assertion below fails if the dialog survives them all.
 */
async function dismissPromptWithNo(prompt: ChainablePromiseElement): Promise<void> {
    let taps = 0
    for (; taps < 4; taps++) {
        await (await $(byId(Ids.pushPromptNo))).click()
        await browser.pause(700)
        if (!(await prompt.isExisting().catch(() => false))) break
    }
    if (taps > 0) console.log(`[push-prompt] WARNING: "No" needed ${taps + 1} tap(s) — the first was swallowed`)
    await prompt.waitForDisplayed({ reverse: true, timeout: 10_000 })
}

describe('Push-notification prompt', () => {

    before(async () => { await MockRelay.start() })
    after(async () => { await MockRelay.stop() })

    beforeEach(async () => {
        // Each test starts from a fresh install/vault so the once-per-vault
        // flag is re-armed and the prompt is guaranteed to fire again; reset()
        // also clears any relay-side state left by a previous case.
        await MockRelay.reset()
        await resetApp()
    })

    it('shows on the first relay answer (not at unlock); "No" dismisses it and it never reappears on this vault', async function () {
        this.timeout(360_000)
        await waitForPinScreen()
        // Guard-free: observe the app's raw post-provisioning state, before
        // anything (including PinHelper's own guards) could dismiss the
        // prompt or race ahead of the reveal.
        await completePinSetupRaw(PIN)

        const unlockedRootEl = await $(byId(Ids.unlockedRoot))
        await waitForUnlockedRootOrPrompt()

        const prompt = await $(byId(Ids.pushPrompt))
        // Bounded, best-effort: assert the prompt has NOT fired while the
        // pre-connect placeholder is still up — but only if we actually catch
        // that window. The mock relay can answer fast enough that the reveal
        // (and the prompt) already landed by the time we look here; that is
        // success too; skip the sub-assertion rather than fail on a race.
        if (await (await $(byId(Ids.contactListHiddenUntilConnected))).isExisting().catch(() => false)) {
            expect(await prompt.isExisting()).toBe(false)
        }

        // Wait for the reveal itself, then assert the prompt appears within
        // 10s of it (it renders a beat after the reveal — a separate
        // @Published/state raise, not the same frame).
        await waitForReveal()
        await prompt.waitForDisplayed({ timeout: 10_000 })

        await dismissPromptWithNo(prompt)

        await unlockedRootEl.waitForDisplayed({ timeout: 15_000 })
        // With the dialog gone the revealed list is visible — proves the prompt
        // rode the same relay answer that opened the gate.
        await (await $(byId(Ids.emptyContactsState))).waitForExist({ timeout: 10_000 })

        // Relaunch (no wipe — same vault) and unlock again with the
        // guard-free primitive: this must be a genuine "the prompt never
        // rendered a second time" check, not "some guard cleaned it up
        // before the assertion ran". The mock relay is still up, so this
        // fresh process gets its own first-reveal gate (per-SESSION) even
        // though push_prompt itself must not re-fire (per-VAULT).
        await relaunchApp()
        await waitForPinScreen()
        await waitForKeypad()
        await enterPinRaw(PIN)

        await waitForUnlockedRootOrPrompt()
        expect(await waitForReveal()).toBe('empty')
        await unlockedRootEl.waitForDisplayed({ timeout: 15_000 })
        await prompt.waitForDisplayed({ reverse: true, timeout: 5_000 })
    })

    it('"Yes" opens the notification carousel (3 education pages + the switch page); closing it returns to the contact list', async function () {
        this.timeout(360_000)
        await waitForPinScreen()
        await completePinSetupRaw(PIN)
        await waitForUnlockedRootOrPrompt()

        await waitForReveal()

        const prompt = await $(byId(Ids.pushPrompt))
        await prompt.waitForDisplayed({ timeout: 10_000 })

        await (await $(byId(Ids.pushPromptYes))).click()

        // Existence, not displayed: iOS-26 SwiftUI intermittently reports
        // freshly-rendered, perfectly usable elements as visible=false in the
        // a11y snapshot (documented throughout Device.ts / helpers) —
        // existence in the tree is the robust signal the carousel actually
        // opened. Race the two possible openings: the real carousel (Next
        // control present) or — Android emulator with neither Play Services
        // nor a UnifiedPush distributor installed — the single
        // `notif_unavailable` page instead.
        const nextSel = byId(carouselNextId())
        const unavailableSel = byId(Ids.notifUnavailable)
        await browser.waitUntil(async () => {
            return (await (await $(nextSel)).isExisting()) || (await (await $(unavailableSel)).isExisting())
        }, {
            timeout: 15_000,
            interval: 500,
            timeoutMsg: 'neither the carousel Next control nor notif_unavailable appeared after tapping "Yes"',
        })

        if (await (await $(unavailableSel)).isExisting()) {
            // No delivery mechanism on this emulator — the 4-page-shape
            // assertion doesn't apply (there IS no carousel to page through).
            // Just close it and move on.
            console.log('[push-prompt] notif_unavailable shown (no FCM/distributor) — skipping the page-count assertion')
        } else {
            const switchSel = byId(switchPageId())
            // Page 0 (the intro/first education page): the switch is NOT yet
            // present.
            expect(await (await $(switchSel)).isExisting()).toBe(false)
            // Exactly 3 Next taps reach the switch page (3 education pages,
            // 0-indexed, ahead of it).
            for (let i = 0; i < 3; i++) {
                await (await $(nextSel)).click()
                await browser.pause(400)
            }
            await (await $(switchSel)).waitForExist({ timeout: 10_000 })
        }

        await closeCarousel()

        await (await $(byId(Ids.unlockedRoot))).waitForDisplayed({ timeout: 15_000 })
    })
})

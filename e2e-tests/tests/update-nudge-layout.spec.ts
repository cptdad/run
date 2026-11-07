// Update-nudge dialog LAYOUT / geometry review (2026-09-29 follow-up to
// c9794b12: RuneActionRow now measures labels and STACKS the buttons when a
// label doesn't fit its half at the 14sp/pt floor; iOS RuneDialogOverlay's
// ScrollView is now `.fixedSize` so the card hugs its content instead of
// stretching to `maxBodyHeight`).
//
// update-nudge.spec.ts already covers the FUNCTIONAL contract (throttle,
// version comparison, store-button absence on this harness's builds). This
// spec is the dedicated "does it look good" contract: it forces BOTH the
// one-button (info-only) and two-button (store) variants — via a NEW
// DEBUG-only e2e hook, since neither platform's real installer-of-record
// check can ever be satisfied on a sideloaded emulator/simulator build — in
// English, Swedish (the locale whose "Öppna Google Play" clipped before the
// fix) and German (a second long locale, "Google Play öffnen"), and asserts
// on-screen element RECTS rather than just presence/absence.
//
// THE DEBUG HOOK: `--ez TEST_FORCE_STORE_INSTALL true` (Android,
// TestHooks.handleTestForceStoreInstall) / `--test-force-store-install` (iOS,
// RunApp.swift -> StoreInstall.debugForceStoreInstall). Both are compiled out
// of / hard no-ops in release — see those files' kdoc — so this spec can only
// ever run against a debug build, exactly like every other lever in
// AppReset.ts's ResetAppArgs.
//
// GUARD-VS-ASSERTION CONFLICT (same shape as update-nudge.spec.ts): every
// unlock here uses the guard-free `*Raw` primitives and PinHelper's shared
// `dismissPushPromptRaw`/`tapUntilGone` pair (NOT PinHelper's guarded
// enterPin/completePinSetup, which also dismiss update_nudge_dialog) so the
// push prompt can be cleared without ever touching the nudge itself. See
// update-nudge.spec.ts's header for the full rationale.
import { Ids, byId } from '../helpers/AccessibilityIds'
import { waitForPinScreen, completePinSetupRaw, dismissPushPromptRaw } from '../helpers/PinHelper'
import { resetAppWithArgs } from '../helpers/AppReset'
import { higherThanCurrent } from '../helpers/AppVersion'
import { nudgeMessageNeedle } from '../helpers/l10nNeedles'
import * as MockRelay from '../helpers/MockRelay'
import { mkdirSync } from 'fs'
import { resolve } from 'path'

const PIN = '111111'

// Swedish is the locale whose store-button label ("Öppna Google Play")
// actually clipped pre-fix (c9794b12's own commit message); German is the
// "at least one long locale" case ("Google Play öffnen", comparable length).
const LOCALES = ['en', 'sv', 'de'] as const
type Locale = (typeof LOCALES)[number]
type Variant = 'solo' | 'store'
const VARIANTS: Variant[] = ['solo', 'store']

interface Rect {
    x: number
    y: number
    width: number
    height: number
    top: number
    bottom: number
    left: number
    right: number
}

// Structural (not nominal) element type: WebdriverIO's `$()` return type is
// `ChainablePromiseElement`, which does not itself satisfy `WebdriverIO.Element`
// under TS's structural checks even after `await` — accepting anything with
// these two methods sidesteps that mismatch without an `any`.
interface LocatedElement {
    getLocation(): Promise<{ x: number; y: number }>
    getSize(): Promise<{ width: number; height: number }>
}

async function rectOf(el: LocatedElement): Promise<Rect> {
    const loc = await el.getLocation()
    const size = await el.getSize()
    return {
        x: loc.x, y: loc.y, width: size.width, height: size.height,
        top: loc.y, bottom: loc.y + size.height,
        left: loc.x, right: loc.x + size.width,
    }
}

/**
 * The rendered LABEL text's own rect for the button carrying [buttonId] —
 * distinct from the button CELL's rect, so a clipped or illegibly-shrunk
 * label can be caught even when the button cell itself is sized correctly.
 * Same `${buttonId}_label` id convention on both platforms:
 *
 *   - Android: RuneDialog.kt's RuneActionCell tags the label Text itself — a
 *     bare Text testTag survives Compose's clickable-ancestor merge as its
 *     own queryable node (same precedent as ContactListScreen.kt's
 *     `contact_name_${id}`).
 *   - iOS: a plain SwiftUI `Button` is otherwise always a single LEAF
 *     accessibility element — empirically confirmed here (a `.//
 *     XCUIElementTypeStaticText` relative lookup found nothing; the page
 *     source shows the button as a self-closing element with no children at
 *     all). `RuneDialogAction.labelA11yId` (UIComponents.swift) is the opt-in
 *     that marks the button as an a11y CONTAINER so its label becomes its
 *     own element with its own id/rect; update_nudge's actions
 *     (ContactListView.swift) pass `${id}_label` for exactly this button.
 */
async function labelRectFor(buttonId: string): Promise<Rect> {
    return rectOf(await $(byId(`${buttonId}_label`)))
}

/** Sets the platform-under-test's advertised version — mirrors
 *  update-nudge.spec.ts's identically-named helper. Must be called BEFORE the
 *  vault unlocks (the client latches onto the FIRST successful relay response
 *  of the session). */
async function advertise(version: string): Promise<void> {
    if (browser.isAndroid) {
        await MockRelay.setVersions({ android: version })
    } else {
        await MockRelay.setVersions({ ios: version })
    }
}

const platformDir = () => (process.env.WDIO_PLATFORM === 'android' ? 'android' : 'ios')

/** Named screenshot per (variant × locale), for a human to review — same
 *  `driver.saveScreenshot()` + `screenshots/<suite>/...` idiom as
 *  tests/l10n-sweep.spec.ts's `shot()`. */
async function shot(locale: Locale, variant: Variant): Promise<void> {
    const dir = resolve(__dirname, '..', 'screenshots', 'update-nudge-layout', platformDir(), locale)
    try {
        mkdirSync(dir, { recursive: true })
        const file = resolve(dir, `${variant}.png`)
        await driver.saveScreenshot(file)
        console.log(`[update-nudge-layout] ${platformDir()}/${locale}/${variant}.png`)
    } catch (e: any) {
        console.warn(`[update-nudge-layout] screenshot ${locale}/${variant} failed: ${e?.message ?? e}`)
    }
}

describe('Update-nudge dialog layout (geometry review)', () => {
    const originalLang = process.env.WDIO_APP_LANG

    before(async () => { await MockRelay.start() })
    after(async () => {
        await MockRelay.stop()
        // Restore whatever the outer run had set — this spec mutates
        // WDIO_APP_LANG per-case (see the AppLocale.ts header: every reader
        // of it is a plain function call, re-read fresh each time, which is
        // exactly what makes an in-process locale sweep possible here), and
        // must not leak a pinned locale into whatever spec runs next in the
        // same worker.
        if (originalLang === undefined) delete process.env.WDIO_APP_LANG
        else process.env.WDIO_APP_LANG = originalLang
    })

    beforeEach(async () => {
        // MockRelay.reset() also clears any previously-advertised version
        // (server-side contract, mock-relay/server.js) — every case starts
        // clean and opts in explicitly via advertise().
        await MockRelay.reset()
    })

    for (const locale of LOCALES) {
        for (const variant of VARIANTS) {
            const label = variant === 'store' ? 'two-button store variant' : 'one-button info variant'

            it(`${label} looks correct in "${locale}"`, async function () {
                this.timeout(360_000)
                process.env.WDIO_APP_LANG = locale

                await advertise(higherThanCurrent())
                await resetAppWithArgs({ forceStoreInstall: variant === 'store' })
                await waitForPinScreen()
                await completePinSetupRaw(PIN)
                await dismissPushPromptRaw()

                const dialog = await $(byId(Ids.updateNudgeDialog))
                await dialog.waitForDisplayed({ timeout: 30_000 })

                // Sanity before the geometry checks: right copy, right variant.
                const src = await browser.getPageSource()
                expect(src.toLowerCase()).toContain(nudgeMessageNeedle(locale))
                const storeButtonEl = await $(byId(Ids.updateNudgeStoreButton))
                const hasStoreButton = await storeButtonEl.isExisting()
                expect(hasStoreButton).toBe(variant === 'store')

                // Named screenshot BEFORE any dismissal, so a human can review
                // the exact state the assertions below are checking.
                await shot(locale, variant)

                // --- GEOMETRY ("looks good" contract) ---
                const { width: screenW, height: screenH } = await driver.getWindowSize()
                const dialogRect = await rectOf(dialog)
                const messageRect = await rectOf(await $(byId(Ids.updateNudgeMessage)))
                const laterRect = await rectOf(await $(byId(Ids.updateNudgeLaterButton)))
                const laterLabelRect = await labelRectFor(Ids.updateNudgeLaterButton)

                // (a) The dialog hugs its content: not a tall near-full-screen
                // card, and the message-to-first-button gap is tight (no huge
                // empty space above the action row — the exact pre-fix iOS
                // regression, RuneDialogOverlay's ScrollView greedily filling
                // maxBodyHeight).
                expect(dialogRect.height).toBeLessThanOrEqual(screenH * 0.45)
                const gap = laterRect.top - messageRect.bottom
                expect(gap).toBeGreaterThanOrEqual(0)
                expect(gap).toBeLessThanOrEqual(dialogRect.height * 0.20)

                // (b) Horizontally inside the screen, with real margins on
                // both sides (not edge-to-edge).
                expect(dialogRect.left).toBeGreaterThan(4)
                expect(screenW - dialogRect.right).toBeGreaterThan(4)
                expect(dialogRect.width).toBeLessThan(screenW)

                // (c) The "Later" label is never clipped by its own button,
                // regardless of variant/locale/layout.
                expect(laterLabelRect.left).toBeGreaterThanOrEqual(laterRect.left)
                expect(laterLabelRect.right).toBeLessThanOrEqual(laterRect.right)

                if (hasStoreButton) {
                    const storeRect = await rectOf(storeButtonEl)
                    const storeLabelRect = await labelRectFor(Ids.updateNudgeStoreButton)

                    // (c, continued) same clipping check for the store label,
                    // plus: neither label may be shrunk to illegibility
                    // relative to its sibling (catches the iOS "squeezed
                    // Öppna App Store" regression, where autosize/
                    // minimumScaleFactor let one label shrink far more than
                    // the other inside the same-height row).
                    expect(storeLabelRect.left).toBeGreaterThanOrEqual(storeRect.left)
                    expect(storeLabelRect.right).toBeLessThanOrEqual(storeRect.right)
                    const shorterLabel = Math.min(laterLabelRect.height, storeLabelRect.height)
                    const tallerLabel = Math.max(laterLabelRect.height, storeLabelRect.height)
                    expect(shorterLabel / tallerLabel).toBeGreaterThanOrEqual(0.8)

                    // (d) Swedish specifically: this is the locale that used
                    // to clip, and RuneActionRow's fix stacks it — assert the
                    // STACKED shape explicitly (tops differ, each button
                    // spans ~the full dialog width, "Later" — the safe reflex
                    // slot — on top).
                    if (locale === 'sv') {
                        expect(laterRect.top).toBeLessThan(storeRect.top)
                        expect(storeRect.top - laterRect.top).toBeGreaterThan(4)
                        expect(laterRect.width).toBeGreaterThanOrEqual(dialogRect.width * 0.9)
                        expect(storeRect.width).toBeGreaterThanOrEqual(dialogRect.width * 0.9)
                    }
                }
            })
        }
    }
})

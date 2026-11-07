// Connect-log inline panel (triple-tap on tor_progress_caption) — Tor-
// independent, like every other single-device spec.
//
// The mock relay is deliberately NEVER started here, mirroring the technique
// contact-list-layout.spec.ts uses to keep the pre-connect status on screen:
// on an emulator/simulator build the relay URL is rewritten to an
// unreachable host-loopback override (RelayConfig.android.kt's
// "http://10.0.2.2:8080" / the iOS sim's localhost equivalent) with nothing
// listening, so isRelayReachable never flips true. That build class also has
// isTorRequired == false (non-.onion override), and RunViewModel/AppState
// only arm the Connecting → Stalled escalation (startRelayStallWatch /
// its iOS twin) when isTorRequired is true — so on a sim/emulator the
// caption sits in RelayConnectPhase.Connecting, showing the paced
// "Connecting to Relay… N%" status line (torConnected trivially true, no
// real Tor bootstrap to wait on), for as long as the test needs it. This is
// the "existing mechanism the layout spec uses" for making the caption
// observable without racing a real connection.
import { Ids, byId } from '../helpers/AccessibilityIds'
import { waitForPinScreen, completePinSetup } from '../helpers/PinHelper'
import { resetApp } from '../helpers/AppReset'

const PIN = '111111'

// RelayConnectHints.kt / AppState's connectStatusLine format since 2026-09-16:
// "Connecting to Tor…" / "Connecting to Relay…" followed by three literal dots
// whose INACTIVE ones are drawn transparent (Android connectCaptionWithDots /
// iOS RelayConnectingCaption). The dots animate visually every 600 ms but the
// accessible text is deliberately stable, and it never carries a percentage.
const DIGIT_RE = /\d/
const TRAILING_DOTS_RE = /\.\.\.$/
// MessageManager.kt's INBOX_ID_REGEX shape: base64url-no-pad, 32 chars.
const INBOX_ID_RE = /[A-Za-z0-9_-]{32}/
const ONION_RE = /\.onion/i

/**
 * A real triple-tap gesture on [id]'s center — one W3C pointer-action chain
 * (not three independent Appium round trips) so the three taps land close
 * together in time, the way a native tap-count gesture recognizer expects.
 */
async function tripleTap(id: string): Promise<void> {
    const el = await $(byId(id))
    await el.waitForDisplayed({ timeout: 15_000 })
    const rect = await driver.getElementRect(await el.elementId)
    const x = Math.round(rect.x + rect.width / 2)
    const y = Math.round(rect.y + rect.height / 2)
    await driver.action('pointer', { parameters: { pointerType: 'touch' } })
        .move({ x, y })
        .down().pause(70).up()
        .pause(120)
        .down().pause(70).up()
        .pause(120)
        .down().pause(70).up()
        .perform()
}

/** Current text of tor_progress_caption, or undefined if it isn't on screen. */
async function captionText(): Promise<string | undefined> {
    const cap = await $(byId(Ids.torProgressCaption))
    if (!(await cap.isExisting().catch(() => false))) return undefined
    return (await cap.getText().catch(() => undefined)) ?? undefined
}

describe('connect log panel — triple-tap toggle on the connecting caption', () => {
    before(async function () {
        this.timeout(300_000)
        // Never start MockRelay — see header. A fresh vault has zero
        // contacts/groups by construction, which is what keeps the pre-
        // connect placeholder (and therefore the caption) on screen at all.
        await resetApp()
        await waitForPinScreen()
        await completePinSetup(PIN)
        await (await $(byId(Ids.unlockedRoot))).waitForExist({ timeout: 60_000 })
    })

    it('the log panel does not exist before any tap, while the pre-connect hint is up', async () => {
        const hint = await $(byId(Ids.connectRelayHint))
        let hintVisible = false
        const deadline = Date.now() + 10_000
        while (Date.now() < deadline) {
            if (await hint.isDisplayed().catch(() => false)) { hintVisible = true; break }
            await browser.pause(300)
        }
        if (!hintVisible) {
            // Relay already reachable (an orphaned relay on the host, or a
            // build where the override doesn't apply) — nothing to assert.
            console.log('[connect-log] connect_relay_hint never appeared — relay already reachable? skipping this assertion')
            return
        }
        const panel = await $(byId(Ids.connectLogPanel))
        expect(await panel.isExisting()).toBe(false)
    })

    it('triple-tap on the caption expands the panel with inbox-safe log lines', async function () {
        const caption = await $(byId(Ids.torProgressCaption))
        if (!(await caption.isExisting().catch(() => false))) {
            console.log('[connect-log] tor_progress_caption absent — relay already reachable? skipping expand test')
            this.skip()
            return
        }
        await tripleTap(Ids.torProgressCaption)

        const panel = await $(byId(Ids.connectLogPanel))
        await panel.waitForExist({
            timeout: 5_000,
            timeoutMsg: 'connect_log_panel did not appear within 5s of the triple-tap',
        })

        const lines = await $$(byId(Ids.connectLogLine))
        expect(lines.length).toBeGreaterThanOrEqual(1)

        for (const line of lines) {
            const text = (await line.getText().catch(() => '')) ?? ''
            expect(text).not.toMatch(INBOX_ID_RE)
            expect(text).not.toMatch(ONION_RE)
        }
    })

    it('triple-tap again collapses the panel', async function () {
        const caption = await $(byId(Ids.torProgressCaption))
        if (!(await caption.isExisting().catch(() => false))) {
            console.log('[connect-log] tor_progress_caption absent — relay already reachable? skipping collapse test')
            this.skip()
            return
        }
        await tripleTap(Ids.torProgressCaption)

        await browser.waitUntil(async () => {
            const panel = await $(byId(Ids.connectLogPanel))
            return !(await panel.isExisting().catch(() => false))
        }, {
            timeout: 5_000,
            interval: 300,
            timeoutMsg: 'connect_log_panel still present 5s after the second triple-tap',
        })
    })

    it('the caption carries no percentage and keeps a stable three-dot tail while connecting', async function () {
        this.timeout(20_000)
        const first = await captionText()
        if (!first || !TRAILING_DOTS_RE.test(first)) {
            console.log(`[connect-log] caption not in the connecting form (${JSON.stringify(first)}) — relay reachable or a pre-caption tick; skipping`)
            this.skip()
            return
        }
        expect(first).not.toMatch(DIGIT_RE)

        // Two dot-animation periods later the accessible text must be byte-identical:
        // the animation is visual only (transparent dots), never a text change that
        // would chatter through a screen reader.
        await browser.pause(1_500)

        const second = await captionText()
        if (!second || !TRAILING_DOTS_RE.test(second)) {
            console.log(`[connect-log] caption left the connecting form on the resample (${JSON.stringify(second)}) — relay likely connected mid-test; skipping`)
            this.skip()
            return
        }
        console.log(`[connect-log] caption samples: t0=${JSON.stringify(first)} t+1.5s=${JSON.stringify(second)}`)
        expect(second).not.toMatch(DIGIT_RE)
        expect(second).toBe(first)
    })
})

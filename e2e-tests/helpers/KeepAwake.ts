// ---------------------------------------------------------------------------
// Lever-C keep-alive — keeps the screen "continuously tapped" for the duration
// of a run, so the foreground idle auto-lock never fires mid-suite.
//
// WHY IT EXISTS: Lever C measures pure TOUCH-idle, and UI automation produces
// none — UiAutomator2 and XCUITest drive the app through the accessibility
// layer, which generates no user-interaction events at all. A multi-minute
// no-touch wait (Tor bootstrap, mint, message delivery) therefore reads as "the
// user walked away", and the app locks itself: Android finishAndRemoveTask(),
// iOS lockAndResetNavigation(). Both platforms sidestep that today by skipping
// Lever C entirely in DEBUG builds (MainActivity.onResume `if (!BuildConfig
// .DEBUG)`, ContentView `#if !DEBUG`). This poker is what removes the need for
// that skip, and it is REQUIRED for any run against a RELEASE build, where the
// auto-lock is live — including MAXIMUM's 60 s window, which is the tier a
// passcode-less phone is forced to.
//
// THE POKE MUST NOT TOUCH REAL UI. The two platforms get there differently:
//
//   Android — `adb shell input keyevent 0` (KEYCODE_UNKNOWN).
//     Activity.dispatchKeyEvent() calls onUserInteraction() for EVERY key
//     event, so the idle clock resets without injecting a touch at all: no
//     coordinate to get wrong, no dialog to dismiss, nothing for Compose to
//     handle. It runs out-of-band over adb, so it adds zero traffic to the
//     Appium session, and it needs no testTag — which matters, because a
//     release APK exposes none (testTagsAsResourceId is BuildConfig.DEBUG).
//
//   iOS — a tap on `keepalive_poke`, a 6 pt transparent DEBUG-only target
//     pinned to the trailing edge of ContentView's root. There is no
//     out-of-band touch injection for a physical iPhone, so this one goes
//     through the session. It is ELEMENT-based and never a coordinate tap on
//     purpose: XCUITest refuses to tap a non-hittable element, so while a
//     RuneDialogOverlay scrim covers the screen the poke fails harmlessly and
//     is swallowed — whereas a blind coordinate tap would land on that scrim,
//     whose onTapGesture can DISMISS the dialog out from under the test.
//
// Env: WDIO_KEEPALIVE=0 disables; WDIO_KEEPALIVE_MS overrides the cadence
// (default 15 s — a 4x margin under the tightest tier's 60 s).
//
// DOES NOT DEFEAT THE PERIODIC RE-AUTH AT MAXIMUM (docs/periodic-reauth-
// design.md). That timer is deliberately TOUCH-INDEPENDENT — "since unlock",
// not "since idle" — so unlike Lever C, no amount of poking (real or
// synthetic) can postpone it; this is why a debuggable build must ship the
// timer OFF by default (ReauthPolicy.isEnabled) rather than relying on
// KeepAwake the way Lever C does. reauth.spec.ts arms a short, deterministic
// override via TestHooks/RunApp instead of trying to out-poke it.
// ---------------------------------------------------------------------------

import { spawn } from 'child_process'
import { browser, multiremotebrowser } from '@wdio/globals'
import { adbPath, adbArgs } from './Adb'
import { Ids } from './AccessibilityIds'

const DEFAULT_POKE_MS = 15_000

let timers: NodeJS.Timeout[] = []

function pokeIntervalMs(): number {
    const raw = Number(process.env.WDIO_KEEPALIVE_MS)
    return Number.isFinite(raw) && raw >= 1_000 ? raw : DEFAULT_POKE_MS
}

interface Seat {
    name: string
    drv: WebdriverIO.Browser
}

/**
 * Every seat of the session, multiremote or single-device. Both @wdio/globals
 * proxies THROW on any property access when their global was never registered
 * (the same trap terminateAppOnAllSeats documents), so each access is guarded.
 */
function seats(): Seat[] {
    try {
        const mb = multiremotebrowser as unknown as {
            instances?: string[]
            getInstance(name: string): WebdriverIO.Browser
        }
        const names = mb.instances ?? []
        if (names.length) return names.map((name) => ({ name, drv: mb.getInstance(name) }))
    } catch {
        // Not a multiremote run — fall through to the single-device global.
    }
    try {
        return [{ name: 'device', drv: browser as unknown as WebdriverIO.Browser }]
    } catch {
        return []
    }
}

/** The device's udid, preferring the session's own capabilities. Appium echoes
 *  it back unprefixed, so check both spellings before the env fallback. */
function udidOf(drv: WebdriverIO.Browser): string | undefined {
    const caps = ((drv as unknown as { capabilities?: Record<string, unknown> }).capabilities ?? {})
    return (caps['appium:udid'] as string | undefined)
        ?? (caps.udid as string | undefined)
        ?? (caps.deviceUDID as string | undefined)
        ?? process.env.WDIO_ANDROID_UDID
}

function pokeAndroid(udid: string | undefined): void {
    const proc = spawn(adbPath(), adbArgs(udid, ['shell', 'input', 'keyevent', '0']), { stdio: 'ignore' })
    // adb missing, device unplugged mid-run — never take the suite down for it.
    proc.on('error', () => { /* the next tick retries */ })
}

/**
 * UIKit presentations that a stray background tap DISMISSES. The poke target is
 * an overlay on the root view, so while one of these is up the tap lands
 * *outside* the presentation and closes it.
 *
 * This is not hypothetical: it cost two full multi4 runs. A long-press opens the
 * contact context menu, `AdditionalDimmingOverlay` appears while its items are
 * still being populated, the poker taps 15 s later, the menu closes, and
 * `tap(menu_introduce)` times out on a contact list that looks perfectly healthy.
 * The forced-tier dialog hit the same hazard (fixed there by making it a
 * non-dismissible consent gate — an option a system context menu doesn't have).
 *
 * So the poker YIELDS whenever a transient presentation is on screen. Skipping a
 * poke is free — Lever C's window is 60 s at the tightest tier and the next tick
 * is 15 s away — whereas a mis-landed tap destroys the test's own UI state.
 */
const TRANSIENT_PRESENTATION_IDS = [
    'AdditionalDimmingOverlay',   // context menu / action sheet scrim
    'PopoverDismissRegion',       // popover backdrop
]

async function pokeIos(drv: WebdriverIO.Browser): Promise<void> {
    try {
        for (const id of TRANSIENT_PRESENTATION_IDS) {
            if (await (await drv.$(`~${id}`)).isExisting()) return
        }
        const el = await drv.$(`~${Ids.keepAlivePoke}`)
        if (await el.isExisting()) await el.click()
    } catch {
        // Covered by a modal scrim, mid-transition, or the seat is busy with the
        // test's own command — all fine, the next tick retries.
    }
}

/**
 * Start poking every seat. Idempotent: an existing poker set is stopped first,
 * so a re-entrant `before` hook can't stack timers.
 */
export function startKeepAwake(): void {
    // OPT-IN, and off by default. Lever C is compiled OUT of debug builds on both
    // platforms (`if (!BuildConfig.DEBUG)` / `#if !DEBUG`) and every suite here
    // runs a debug build — so on these runs the poker prevents nothing and only
    // adds a recurring synthetic tap.
    //
    // That is not a theoretical cost. The iOS poke target is an overlay on the
    // ROOT view, so a tap lands OUTSIDE any transient presentation and dismisses
    // it. It closed the forced-tier dialog (masked as "the dialog never
    // appeared"), and it closed the contact context menu mid-referral — three
    // pokes landed between the long-press and the `menu_introduce` lookup, which
    // read as a 20 s element-not-found on a contact list that looked perfectly
    // healthy. Two multi4 runs, ~105 minutes of device time, chasing a tap I had
    // added myself.
    //
    // Set WDIO_KEEPALIVE=1 for the case it exists for: a RELEASE-build run, where
    // the auto-lock is live and a no-touch Tor wait really would lock the app.
    if (process.env.WDIO_KEEPALIVE !== '1') {
        console.log('[keepalive] off (debug builds compile Lever C out; set WDIO_KEEPALIVE=1 for release-build runs)')
        return
    }
    stopKeepAwake()
    const every = pokeIntervalMs()
    for (const { name, drv } of seats()) {
        const isAndroid = !!(drv as unknown as { isAndroid?: boolean }).isAndroid
        const udid = isAndroid ? udidOf(drv) : undefined
        let busy = false
        const timer = setInterval(() => {
            if (isAndroid) {
                pokeAndroid(udid)
                return
            }
            // One outstanding poke per seat: WDIO serializes commands per
            // session, and a queued backlog would delay the test's own calls.
            if (busy) return
            busy = true
            void pokeIos(drv).finally(() => { busy = false })
        }, every)
        // Never let a poker hold the runner alive at teardown.
        timer.unref?.()
        timers.push(timer)
        console.log(`[keepalive] ${name}: poking every ${every / 1000}s `
            + `(${isAndroid ? 'adb keyevent' : `tap ~${Ids.keepAlivePoke}`})`)
    }
}

/** Stop every poker. Safe to call when none are running. */
export function stopKeepAwake(): void {
    for (const t of timers) clearInterval(t)
    timers = []
}

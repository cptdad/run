import { browser, multiremotebrowser } from '@wdio/globals'
import { mkdirSync, readdirSync, statSync, unlinkSync } from 'fs'
import { join, resolve } from 'path'

// ---------------------------------------------------------------------------
// Per-phase screenshot capture across the WHOLE devices of a suite.
//
// Wired into the shared WDIO `afterTest` hook (wdio.shared.conf.ts) — which
// fires once per Mocha `it` (≈ one phase/step) and is INHERITED by every conf
// (none override afterTest). For each phase it grabs one screenshot from EVERY
// device session in play, so a run is visually reviewable frame-by-frame —
// especially the upcoming Arabic/RTL rendering, where a glance at the actual
// pixels is worth more than any assertion.
//
//   - Multiremote (cross:* suites): iterates the multiremote instances and
//     captures each named seat separately (ios / android / iosRcv / …).
//   - Single-device (emulator/sim suites): captures the one session, labelled
//     by platformName (android / ios).
//
// Capture is `driver.saveScreenshot()` (WDA on iOS, UiAutomator2 on Android) —
// cross-platform, needs no DDI, unlike idevicescreenshot (whose DDI can
// mismatch the iOS version and fail). Mirrors the video-recording feature's
// conventions (helpers/multi/recording.ts): env opt-out, newest-first byte
// budget prune, one output tree under e2e-tests/.
//
// ENABLED by default. Set WDIO_SCREENSHOT_EACH_PHASE=0 to disable a run.
// ---------------------------------------------------------------------------

/** Output root — the same screenshots/ dir the adhoc + l10n sweeps already use.
 *  Per-phase shots nest under screenshots/<suite>/<device>/, and pruning only
 *  ever touches files carrying OWNED_SUFFIX, so those existing outputs are safe. */
const SCREENSHOT_ROOT = resolve(__dirname, '..', 'screenshots')

// Every file THIS helper writes ends in `__PASS.png` / `__FAIL.png`. Pruning is
// scoped to exactly this signature, so the adhoc screenshots (seed13-*.png) and
// the l10n sweep outputs (screenshots/l10n/**) the test phones already writes are
// NEVER deleted, regardless of where they sit under screenshots/.
const OWNED_SUFFIX = /__(?:PASS|FAIL)\.png$/i

// Newest-first byte budget for OUR screenshots, mirroring recording.ts's video
// budget. Full-res device screenshots are a few MB each and a long cross run
// across three devices with dozens of phases adds up, so cap the footprint;
// before the first capture of a run, delete the OLDEST owned shots until the
// set fits. 2 GiB keeps roughly the last several runs. Override with
// WDIO_SCREENSHOT_BUDGET_BYTES.
const BUDGET_BYTES = Number(process.env.WDIO_SCREENSHOT_BUDGET_BYTES) > 0
    ? Number(process.env.WDIO_SCREENSHOT_BUDGET_BYTES)
    : 2 * 1024 * 1024 * 1024

/** Opt-OUT toggle (default ON), mirroring recordingEnabled()'s style. */
export function screenshotEachPhaseEnabled(): boolean {
    return process.env.WDIO_SCREENSHOT_EACH_PHASE !== '0'
}

interface Seat {
    name: string
    drv: WebdriverIO.Browser
}

/**
 * Every device session in play — multiremote or single-device. Both
 * @wdio/globals proxies THROW on any property access when their global was
 * never registered (the trap terminateAppOnAllSeats / KeepAwake.seats()
 * document), so each access is guarded and a missing session just yields [].
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
        const drv = browser as unknown as WebdriverIO.Browser
        if (drv) return [{ name: singleDeviceLabel(drv), drv }]
    } catch {
        // No session registered at all (session-create death) — nothing to grab.
    }
    return []
}

/** Label for the lone seat of a single-device suite: its platform (android/ios). */
function singleDeviceLabel(drv: WebdriverIO.Browser): string {
    const caps = ((drv as unknown as { capabilities?: Record<string, unknown> }).capabilities ?? {})
    const platform = String(caps.platformName ?? '').toLowerCase()
    return platform || 'device'
}

/**
 * The suite name for the output path. Prefers an explicit WDIO_SUITE_NAME, then
 * the npm script that launched the run (npm exports npm_lifecycle_event to every
 * child process — the wdio launcher AND its workers — so it survives into
 * afterTest, where the config/conf path is not available), then the conf name
 * parsed from argv, then a constant. `test:device:` / `test:emulator:` prefixes
 * are stripped so e.g. `test:device:cross:multi3` → `cross-multi3`.
 */
function suiteName(): string {
    const raw = process.env.WDIO_SUITE_NAME
        || process.env.npm_lifecycle_event
        || confFromArgv()
        || 'suite'
    return dirSanitize(raw.replace(/^test[:-](?:emulator|device)[:-]/, ''))
}

function confFromArgv(): string | undefined {
    const m = process.argv.join(' ').match(/wdio\.([\w.-]+?)\.conf(?:\.ts)?/)
    return m ? m[1] : undefined
}

/** Lower-kebab for path segments (suite dir + test title). */
function dirSanitize(s: string, max = 60): string {
    return s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, max) || 'x'
}

/** Filesystem-safe device label — keeps camelCase seat names (iosRcv, iosAdmin)
 *  legible, only scrubbing path-unsafe characters. */
function deviceSanitize(s: string, max = 40): string {
    return s.replace(/[^A-Za-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, max) || 'device'
}

// Per-device phase counter, keyed by `${suite}/${device}`. Module-level so it
// climbs across a spec's phases (and across a specFileRetries re-run, which
// keeps every attempt's frames rather than overwriting them). Zero-padded so
// lexical order == capture order.
const counters = new Map<string, number>()

let pruned = false

interface OwnedFile { path: string; mtime: number; size: number }

/** Recursively collect ONLY the files this helper owns (OWNED_SUFFIX). */
function collectOwned(dir: string): OwnedFile[] {
    const out: OwnedFile[] = []
    let entries: import('fs').Dirent[]
    try {
        entries = readdirSync(dir, { withFileTypes: true })
    } catch {
        return out // dir absent (first run) — nothing to collect
    }
    for (const e of entries) {
        const p = join(dir, e.name)
        if (e.isDirectory()) {
            out.push(...collectOwned(p))
        } else if (e.isFile() && OWNED_SUFFIX.test(e.name)) {
            try {
                const st = statSync(p)
                out.push({ path: p, mtime: st.mtimeMs, size: st.size })
            } catch { /* raced deletion — skip */ }
        }
    }
    return out
}

/** Delete oldest owned screenshots until the set fits the byte budget. Runs
 *  once per worker, best-effort — a prune failure never blocks a capture. */
function pruneOnce(): void {
    if (pruned) return
    pruned = true
    let files: OwnedFile[]
    try {
        files = collectOwned(SCREENSHOT_ROOT)
    } catch {
        return
    }
    files.sort((a, b) => b.mtime - a.mtime) // newest first
    let total = 0
    for (const f of files) {
        total += f.size
        if (total <= BUDGET_BYTES) continue
        try {
            unlinkSync(f.path)
            console.log(`[screenshot] pruned (over ${Math.round(BUDGET_BYTES / 2 ** 30)} GiB budget): ${f.path}`)
        } catch (e) {
            console.log(`[screenshot] prune failed for ${f.path}: ${(e as Error).message}`)
        }
    }
}

/**
 * Capture one screenshot per device for the just-finished phase. Called from
 * the shared afterTest hook. Best-effort + non-fatal: EVERY capture is wrapped
 * so a dead session / WDA hiccup only logs a warning — it must never fail or
 * wedge the suite. [test] is the Mocha test object, [result] its WDIO result
 * ({ passed } drives the PASS/FAIL tag in the filename).
 *
 * Output: screenshots/<suite>/<device>/<NN>-<sanitized-title>__<PASS|FAIL>.png
 */
export async function captureEachPhase(test: unknown, result: unknown): Promise<void> {
    if (!screenshotEachPhaseEnabled()) return
    pruneOnce()

    const t = test as { title?: string; fullTitle?: string } | undefined
    const passed = (result as { passed?: boolean } | undefined)?.passed === false ? 'FAIL' : 'PASS'
    const title = dirSanitize(t?.title ?? t?.fullTitle ?? 'phase')
    const suite = suiteName()

    for (const { name, drv } of seats()) {
        const device = deviceSanitize(name)
        const key = `${suite}/${device}`
        const n = (counters.get(key) ?? 0) + 1
        counters.set(key, n)
        const nn = String(n).padStart(2, '0')
        const rel = `${suite}/${device}/${nn}-${title}__${passed}.png`
        const file = join(SCREENSHOT_ROOT, suite, device, `${nn}-${title}__${passed}.png`)
        try {
            mkdirSync(join(SCREENSHOT_ROOT, suite, device), { recursive: true })
            await drv.saveScreenshot(file)
            console.log(`[screenshot] ${rel}`)
        } catch (e) {
            console.log(`[screenshot] capture failed for ${name} @ "${title}": ${(e as Error).message}`)
        }
    }
}

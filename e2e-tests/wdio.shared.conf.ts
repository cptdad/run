import type { Options } from '@wdio/types'
import { resolve } from 'path'
import { startKeepAwake, stopKeepAwake } from './helpers/KeepAwake'
import { classifyFailure, describeError, infraFaultSignature } from './helpers/infraFaults'
import { captureEachPhase } from './helpers/screenshotEachPhase'

/**
 * Shared WebdriverIO configuration — values common to iOS and Android.
 * Platform-specific configs spread this and add `capabilities`.
 *
 * Also re-exports (from wdio.physical-devices.ts) the helpers the PHYSICAL cross suites share (prebuilt-WDA
 * seeding, the physical-iPhone guard + iOS capability shape, and the
 * close-apps-after-suite teardown), so the multi/multi3/push/referral
 * confs don't each carry a divergent copy.
 */
// Appium server port. Parameterized so the Android and iOS suites can run
// concurrently (different devices) on separate Appium servers — set
// WDIO_APPIUM_PORT per suite (e.g. 4723 for Android, 4724 for iOS).
//
// Read LAZILY (a function, and getters on `sharedConfig` below), never as an
// import-time constant: the device pool's `allocateForConf()` assigns the port
// slot and exports WDIO_APPIUM_PORT AFTER this module has been imported by the
// suite conf, and `{ ...sharedConfig }` in that conf evaluates the getters at
// spread time, i.e. after the lease. Frozen at import, every non-first all-phones run
// lane silently piggybacked on lane 0's Appium server (found 2026-09-15).
function appiumPort(): number {
    return process.env.WDIO_APPIUM_PORT ? Number(process.env.WDIO_APPIUM_PORT) : 4723
}

/**
 * Emit ONE classified failure line so a red run is legible at a glance and the
 * infra faults are visibly separated from the product ones:
 *   [INFRA-FAULT]  = the automation transport died (dropped WebDriver session,
 *                    Appium/WDA torn down, "socket hang up"). NOT a product bug —
 *                    specFileRetries reruns the whole spec file (incl. hooks) in
 *                    a fresh session to recover it.
 *   [TEST-FAILURE] = a genuine assertion / product failure. A red here, in
 *                    principle, means a bug.
 * Single source of truth for the distinction: helpers/infraFaults.ts. Fires
 * from afterHook (setup/before-hook deaths surface here) and afterTest.
 */
function logClassifiedFailure(
    kind: 'hook' | 'test',
    title: string | undefined,
    error: unknown,
    attempt?: number,
): void {
    if (classifyFailure(error) === 'infra') {
        console.log(
            `[INFRA-FAULT] ${kind} "${title ?? '?'}" — transport death `
            + `(${infraFaultSignature(error) || 'unclassified'}); a spec-file retry will recover it: `
            + describeError(error),
        )
    } else {
        const a = attempt !== undefined && attempt >= 0 ? ` [attempt ${attempt + 1}]` : ''
        console.log(
            `[TEST-FAILURE] ${kind} "${title ?? '?'}"${a} — product/assertion failure `
            + `(a red here means a bug): ` + describeError(error),
        )
    }
}

export const sharedConfig: Partial<Options.Testrunner> = {
    runner: 'local',

    tsConfigPath: './tsconfig.json',

    specs: ['./tests/**/*.spec.ts'],

    maxInstances: 1,

    logLevel: 'info',

    bail: 0,

    waitforTimeout: 10_000,
    connectionRetryTimeout: 120_000,
    connectionRetryCount: 3,

    framework: 'mocha',
    mochaOpts: {
        ui: 'bdd',
        timeout: 120_000,
    },

    reporters: ['spec'],

    get services(): Options.Testrunner['services'] { return [
        ['appium', {
            args: {
                address: '127.0.0.1',
                port: appiumPort(),
                relaxedSecurity: true,
                // Env-gated diagnostics: set WDIO_APPIUM_LOG (file) and
                // WDIO_APPIUM_LOGLEVEL (e.g. debug) to capture the full Appium
                // log — incl. the WDA xcodebuild command + stderr — to a file.
                ...(process.env.WDIO_APPIUM_LOG ? { log: process.env.WDIO_APPIUM_LOG } : {}),
                ...(process.env.WDIO_APPIUM_LOGLEVEL ? { logLevel: process.env.WDIO_APPIUM_LOGLEVEL } : {}),
            },
            // Guard wrapper around the locally-installed appium binary: kills
            // an ORPHANED listener on our port (a leftover server from a dead
            // suite gets silently adopted via "Continue..." and then vanishes
            // mid-run), aborts loudly if the holder is a live concurrent
            // suite. See scripts/appium-guarded.sh.
            command: resolve(__dirname, 'scripts', 'appium-guarded.sh'),
            // Appium 3 + the two drivers take longer to announce themselves under
            // load: the 30 s default cost the test phones a suite on 2026-09-17 (lane 0
            // reused 5 s after release while an emulator run was building).
            appiumStartTimeout: 120_000,
        }] as any,
    ] },

    hostname: '127.0.0.1',
    get port() { return appiumPort() },
    path: '/',

    // Lever-C keep-alive for the single-device suites: UI automation generates
    // no touches, so an idle app auto-locks mid-suite (helpers/KeepAwake.ts).
    // The cross confs declare their own before/after (recordings + close-apps
    // teardown), which REPLACE these — they call the same pair themselves.
    before() {
        startKeepAwake()
    },
    after() {
        stopKeepAwake()
    },

    // Classify every failure (infra transport-death vs. real product/assertion
    // failure) so a red run is legible and the infra ones are visibly the ones
    // specFileRetries recovers. Inherited by the cross confs — they override
    // before/after (recordings + teardown) but NOT afterHook/afterTest.
    // See helpers/infraFaults.ts.
    afterHook(test: any, _context: any, result: any) {
        if (result?.error) {
            logClassifiedFailure('hook', test?.title ?? test?.parent?.title, result.error)
        }
    },
    // afterTest fires once per Mocha `it` (≈ one phase/step) and is INHERITED by
    // every conf (none override it), so this is the single wiring point for the
    // per-phase, whole-device screenshot capture (helpers/screenshotEachPhase.ts).
    // The capture is best-effort + non-fatal and swallows its own errors, so it
    // never affects the failure classification below or the suite result.
    async afterTest(test: any, _context: any, result: any) {
        await captureEachPhase(test, result)
        if (result && result.passed === false) {
            const attempt = typeof result.retries === 'number'
                ? result.retries
                : (typeof result.retries?.attempts === 'number' ? result.retries.attempts : undefined)
            logClassifiedFailure('test', test?.title, result.error, attempt)
        }
    },
}

// Physical-device helpers (prebuilt WDA, capability shapes, teardown) live in
// wdio.physical-devices.ts; re-exported so conf importers need no change.
export * from './wdio.physical-devices'

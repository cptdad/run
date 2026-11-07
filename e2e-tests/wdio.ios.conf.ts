import type { Options } from '@wdio/types'
import { resolve } from 'path'
import { execFileSync } from 'child_process'
import { sharedConfig, killIosAppViaDevicectl } from './wdio.shared.conf'
import { rebootIfRequested } from './helpers/RebootDevice'
import { iosLanguageArgs } from './helpers/AppLocale'

/**
 * iOS-specific config. Expects a .app bundle built for the iOS simulator
 * via Xcode. Default path is the Xcode DerivedData location for the
 * Debug-iphonesimulator configuration of the Run scheme.
 *
 * Override with WDIO_IOS_APP_PATH if your build output lives elsewhere.
 */
const defaultAppPath = resolve(
    __dirname,
    '..',
    'iosApp',
    'build',
    'Run.app'
)

// WDA strategy. `useNewWDA: true` rebuilds+reinstalls WebDriverAgent on every
// session — on a physical device a 7-spec suite then does 7 WDA installs and the
// device degrades into `socket hang up` failures mid-run. If WDIO_IOS_PREBUILT_WDA
// points at a prebuilt WDA derivedDataPath (see feedback_cross_multi_needs_prebuilt_wda),
// reuse it across the whole run instead (one install, like wdio.cross.multi.conf.ts).
const prebuiltWda = process.env.WDIO_IOS_PREBUILT_WDA
const wdaBundle = process.env.WDIO_IOS_WDA_BUNDLE_ID
const wdaCaps = prebuiltWda
    ? {
        'appium:useNewWDA': false,
        'appium:usePrebuiltWDA': true,
        'appium:derivedDataPath': prebuiltWda,
        // Host-side WDA port. Env-overridable so a solo-iPhone run of this conf
        // can run CONCURRENTLY with a multi-iPhone suite (multi3 uses 8100/8101)
        // without a host-port collision — see run-all-devices-parallel.sh.
        'appium:wdaLocalPort': Number(process.env.WDIO_IOS_WDA_PORT) || 8100,
        // Match wdio.cross.multi.conf.ts: don't force a WDA bundle id in prebuilt
        // mode (use the prebuilt one) unless explicitly overridden.
        ...(wdaBundle ? { 'appium:updatedWDABundleId': wdaBundle } : {}),
    }
    : {
        'appium:useNewWDA': true,
        'appium:updatedWDABundleId': wdaBundle || 'com.vg.WebDriverAgentRunner',
    }

export const config: Options.Testrunner = {
    ...sharedConfig,
    specs: ['./tests/*.spec.ts'],
    // First-run WDA build + launch (esp. on a cold simulator or a slower
    // device) can exceed the shared 120s session-create budget. Match
    // wdio.android.conf.ts and wdio.cross.multi.conf.ts.
    connectionRetryTimeout: 300_000,
    // setup/unlock hooks run PBKDF2-210k + SQLCipher create/seed for the
    // single vault, which can exceed the shared 120s mocha hook budget and
    // trip contacts' before / vault's beforeEach even when the flow is healthy.
    // Give iOS hooks more room.
    // 600 s, not 300 s: WDIO 9's mocha framework enforces THIS value as a bare
    // `Error: Timeout` per test and ignores a spec's own `this.timeout(...)`, so
    // the ceiling must cover the slowest single-device flow — relay-loss detection
    // is 4 control-poll 404s at the 60–90 s idle cadence (~360 s) plus setup.
    mochaOpts: { ...sharedConfig.mochaOpts, timeout: 600_000 },
    capabilities: [
        {
            platformName: 'iOS',
            'appium:platformVersion': process.env.WDIO_IOS_VERSION || '18.6',
            'appium:deviceName': process.env.WDIO_IOS_DEVICE || 'iPhone 16',
            'appium:udid': process.env.WDIO_IOS_UDID,
            'appium:automationName': 'XCUITest',
            // Run the simulator without its window (2026-09-29). Xcode 27 replaced
            // Simulator.app with DeviceHub.app; appium-ios-simulator still looks for a
            // running "Simulator.app" process and otherwise `open -Fn`s a NEW UI
            // instance, so every spec-file session stacked another DeviceHub window
            // (18 after one night) on a memory-tight Mac. Headless needs no window:
            // screenshots, gestures and the a11y tree are unaffected.
            // WDIO_IOS_SIM_UI=1 shows the window again for watching a run.
            'appium:isHeadless': process.env.WDIO_IOS_SIM_UI !== '1',
            'appium:app': process.env.WDIO_IOS_APP_PATH || defaultAppPath,
            'appium:bundleId': 'com.vg.run',
            // Specs call resetApp() themselves via the AppReset helper —
            // don't let Appium auto-reset on session start.
            'appium:noReset': true,
            'appium:fullReset': false,
            'appium:newCommandTimeout': 240,
            ...wdaCaps,
            'appium:xcodeOrgId': process.env.WDIO_IOS_TEAM_ID || 'YOUR_TEAM_ID',
            'appium:xcodeSigningId': 'Apple Development',
            'appium:showXcodeLog': true,
            'appium:processArguments': {
                // English pin (PHASE 0 localization) — language only, NO
                // -AppleLocale (that would flip time formatting to 12-hour).
                args: ['--test-wipe-on-launch', ...iosLanguageArgs()],
            },
        },
    ],
    async onPrepare() {
        // Opt-in (WDIO_REBOOT_BEFORE_RUN): reboot the physical iPhone first to
        // clear accumulated WDA/app degradation before a full run.
        await rebootIfRequested('ios')
    },
    onComplete() {
        // WDIO_IOS_KEEP_SIM=1 leaves the sim booted after the run — used when
        // screen-recording a run (so the recorder can stop cleanly) or for
        // post-run debugging.
        if (process.env.WDIO_IOS_KEEP_SIM === '1') return
        const udid = process.env.WDIO_IOS_UDID
        if (udid) {
            try { execFileSync('xcrun', ['simctl', 'terminate', udid, 'com.vg.run']) } catch {}
            try { execFileSync('xcrun', ['simctl', 'shutdown', udid]) } catch {}
            // Physical iPhone (hardware UDIDs are never 36-char UUIDs — sim
            // UDIDs always are): the simctl calls above are silent no-ops
            // there, so close the app via devicectl instead
            // (close-apps-after-suite; bounded + best-effort).
            const isSimUuid = /^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$/i.test(udid)
            if (!isSimUuid) killIosAppViaDevicectl(udid)
        }
    },
} as Options.Testrunner

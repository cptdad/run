import { join } from 'path'
import { cpSync, existsSync, readFileSync, rmSync, statSync, unlinkSync } from 'fs'
import { tmpdir } from 'os'
import { execFileSync } from 'child_process'
import { multiremotebrowser } from '@wdio/globals'
import { androidLanguageIntentString } from './helpers/AppLocale'

/**
 * Physical-device (maintainer lab) helpers shared by the cross-suite confs:
 * prebuilt-WDA seeding, the physical-iPhone guard + iOS/Android capability
 * shapes, the device-pool seat env, and the close-apps-after-suite teardown.
 * Split out of wdio.shared.conf.ts (which re-exports everything here, so every
 * existing `from './wdio.shared.conf'` import keeps working).
 */

// ---------------------------------------------------------------------------
// Cross-suite shared helpers (physical devices)
// ---------------------------------------------------------------------------

/** App id, shared by the cross confs' capabilities AND their teardown hooks.
 *  (helpers/multi/Device.ts and helpers/AppReset.ts keep private copies —
 *  neither exports it.) */
export const APP_BUNDLE_ID = 'com.vg.run'

/** The prebuilt WDA derivedData the cross suites are built around: built ONCE
 *  here, and the per-device copies the multi3 confs use are seeded from
 *  it (ensurePrebuiltWdaSeeded below). */
export const PREBUILT_WDA_BASE = '/tmp/wda-cross-ios'

/**
 * RETRY POLICY of every physical cross conf (2026-09-30): THREE attempts per
 * spec file, ALL fresh-session (specFileRetries), NO in-session Mocha retry.
 *
 * Why, measured over every device run 2026-09-15 → 2026-09-30 (`RUNNING in`
 * + `RETRY #` markers against summary.txt):
 *   - attempt 2 and attempt 3 rescue suites regularly (attempt 3 alone: multi3 ×3,
 *     ios2ios ×4, multi ×1);
 *   - attempt 4 — the Mocha retry INSIDE the fresh-session retry that the old
 *     "1 mocha × 1 spec-file" layering produced — rescued 0 of 6 and held THREE
 *     phones for 35–146 min each time (multi3 76m/61m/35m/146m, move-a2a 34m,
 *     bugreport 10m).
 * A device pass is device-bound (wall ≈ Android device-minutes ÷ attached
 * Androids — scripts/run-fleet.mjs prints that floor), so a doomed attempt is
 * paid for by every suite queued behind it, not just by the one that fails.
 *
 * A fresh-session retry is a strict superset of a Mocha retry: it reruns
 * before() and opens a new Appium/WDA session, and the specs' own RETRY re-wipe
 * did the same work minus the session. Cost of losing the in-session layer:
 * ~1 extra minute per rescued attempt. Cost of keeping it: the 4th attempt.
 *
 * WDIO_SPEC_RETRIES / WDIO_SPEC_FILE_RETRIES still override both (e.g. both =0
 * for a single no-retry attempt while bisecting a flake, or =1/=1 to reproduce
 * the old layering). wdio.cross.chain3.conf.ts keeps its own policy (0 × 0,
 * WDIO_SPEC_FILE_RETRIES opt-in): a chain is two specs long and its head
 * refuses in-session retries by design.
 */
export const MOCHA_RETRIES = process.env.WDIO_SPEC_RETRIES !== undefined ? Number(process.env.WDIO_SPEC_RETRIES) : 0
export const SPEC_FILE_RETRIES = process.env.WDIO_SPEC_FILE_RETRIES !== undefined ? Number(process.env.WDIO_SPEC_FILE_RETRIES) : 2

// What "a built WDA lives at <derivedDataPath>" concretely means: with
// usePrebuiltWDA:true, xcodebuild runs ONLY `test-without-building` against
// that path — no fallback build — and loads the runner app from
// Build/Products/Debug-iphoneos (layout verified against this machine's
// /tmp/wda-cross-ios*). macOS purges /tmp at boot and reaps files >3 days old
// while LEAVING dir skeletons, so "the directory exists" proves nothing —
// check the runner BINARY (a gutted skeleton fails session-create as
// "xcodebuild code 65: Unable to determine the executable path").
const WDA_RUNNER_BINARY = join(
    'Build', 'Products', 'Debug-iphoneos',
    'WebDriverAgentRunner-Runner.app', 'WebDriverAgentRunner-Runner',
)

// The one-time base build (the -Wno-error flags are required on Xcode 26 —
// WebDriverAgent trips -Wreserved-identifier as an error without them;
// IPHONEOS_DEPLOYMENT_TARGET=16.0 is required on Xcode 27, which rejects the
// deployment target WebDriverAgent pins itself — harmless on 26).
//
// ALSO rebuild the base after an appium-xcuitest-driver bump: the driver ships
// its OWN appium-webdriveragent (node_modules/appium-xcuitest-driver/
// node_modules/appium-webdriveragent) and talks to the runner over a
// version-coupled protocol, while `usePrebuiltWDA` never rebuilds. The
// 2026-09-16 toolchain bump (driver 7.35.1 -> 12.12.4) moved WDA 8.12.0 ->
// 16.12.8, i.e. a prebuilt from before that bump is unusable. The driver does
// not hard-gate on the mismatch — it only warns — so a stale base surfaces as
// a confusing session-create failure, not as "wrong WDA version".
const WDA_SEED_COMMAND = `cd e2e-tests && xcodebuild build-for-testing \\
  -project node_modules/appium-xcuitest-driver/node_modules/appium-webdriveragent/WebDriverAgent.xcodeproj \\
  -scheme WebDriverAgentRunner -destination generic/platform=iOS \\
  -derivedDataPath ${PREBUILT_WDA_BASE} -allowProvisioningUpdates \\
  DEVELOPMENT_TEAM=YOUR_TEAM_ID PRODUCT_BUNDLE_IDENTIFIER=com.vg.run.WebDriverAgentRunner \\
  IPHONEOS_DEPLOYMENT_TARGET=16.0 \\
  GCC_TREAT_WARNINGS_AS_ERRORS=NO 'OTHER_CFLAGS=$(inherited) -Wno-error=reserved-identifier -Wno-reserved-identifier'`

/**
 * Fail-fast / auto-seed gate for the prebuilt-WDA derivedData paths, called at
 * config load (next to the physical-device asserts). For each path that lacks
 * a built WDA: if the base prebuilt has one, seed the path by copying it
 * (loudly); otherwise throw with the exact build command — WITHOUT this, the
 * first run after a reboot (/tmp purged) dies at session create with an error
 * that reads as a WDA/signing problem. ALSO refreshes per-device copies that
 * went STALE: after the base is rebuilt (appium-webdriveragent upgrade, new
 * Xcode), presence alone would silently keep the old copies and multi3
 * would run a version-mismatched WDA with confusing session errors.
 *
 * Freshness marker: the runner BINARY's mtime. cpSync WITHOUT
 * preserveTimestamps stamps the copy at SEED time — always after the base's
 * build time — so `copy mtime < base mtime` holds exactly when the base was
 * rebuilt after the copy was seeded, and a re-seed reads fresh again.
 * Verified on this machine (node 22 + 26). Do NOT switch the copy to
 * preserveTimestamps:true: node 26's utimes round-trip lands the copied mtime
 * fractionally BELOW the base's (observed −0.24 µs), which a strict compare
 * reads as forever-stale → reseed loop on every config load.
 */
export function ensurePrebuiltWdaSeeded(derivedDataPaths: string[]): void {
    const runnerBinary = (root: string) => join(root, WDA_RUNNER_BINARY)
    const hasBuiltWda = (root: string) => existsSync(runnerBinary(root))
    const wdaMtime = (root: string) => statSync(runnerBinary(root)).mtime
    const baseBuilt = hasBuiltWda(PREBUILT_WDA_BASE)

    const missing = derivedDataPaths.filter((p) => !hasBuiltWda(p))
    // Staleness needs a built base to compare against; the base itself is
    // excluded (it can never be its own stale copy — and must never be rm'd).
    const stale = baseBuilt
        ? derivedDataPaths.filter((p) => p !== PREBUILT_WDA_BASE && hasBuiltWda(p)
            && wdaMtime(p).getTime() < wdaMtime(PREBUILT_WDA_BASE).getTime())
        : []
    if (missing.length === 0 && stale.length === 0) return
    if (!baseBuilt) {
        throw new Error(
            `No built WebDriverAgent at: ${missing.join(', ')} — and the seed source ` +
            `${PREBUILT_WDA_BASE} has none either (macOS purges /tmp at boot and reaps ` +
            'files >3 days old, leaving dir skeletons). usePrebuiltWDA runs xcodebuild ' +
            '`test-without-building` ONLY, so nothing rebuilds it implicitly. Build the ' +
            `base once, then re-run — the conf seeds the per-device copies itself:\n${WDA_SEED_COMMAND}`,
        )
    }
    const seed = (p: string, why: string) => {
        console.log(`[wda-seed] ${p}: ${why} — seeding from the prebuilt ${PREBUILT_WDA_BASE}...`)
        // Never layer over old contents — remove the whole tree, then copy fresh.
        rmSync(p, { recursive: true, force: true })
        cpSync(PREBUILT_WDA_BASE, p, { recursive: true })
        console.log(`[wda-seed] ${p}: seeded (copied ${PREBUILT_WDA_BASE} — WDA will test-without-building against it)`)
    }
    for (const p of missing) {
        // p === PREBUILT_WDA_BASE can't reach here (it would have thrown above).
        seed(p, 'no built WDA')
    }
    for (const p of stale) {
        seed(p, `built WDA is STALE (runner ${wdaMtime(p).toISOString()} predates the base's `
            + `${wdaMtime(PREBUILT_WDA_BASE).toISOString()} — the base was rebuilt since this copy was seeded)`)
    }
}

/**
 * Is `udid` a CREATED iOS Simulator (as opposed to a physical device)?
 *
 * `simctl list devices` prints every created simulator's UDID; a physical
 * device's UDID never appears in that output, so membership is the test. Both
 * the physical-only guard below and the simulator-only specs key off this one
 * check so they can never disagree about what a UDID is.
 *
 * FAILS OPEN (`false`) when `xcrun`/`simctl` is unavailable (non-mac CI) or
 * when no UDID was given: we cannot positively identify a simulator, so the
 * physical guard must not block and a sim-only spec must not claim the target
 * is one.
 */
export function isSimulatorUdid(udid: string | undefined): boolean {
    if (!udid) return false
    let simList = ''
    try {
        simList = execFileSync('xcrun', ['simctl', 'list', 'devices'], { encoding: 'utf8' })
    } catch {
        return false
    }
    // Compare case-insensitively — simctl and the env vars disagree on case.
    return simList.toLowerCase().includes(udid.toLowerCase())
}

/**
 * Refuse to run an iOS leg against a simulator. The cross suites exercise the
 * REAL send-over-Tor flow, which only works on a physical iPhone — the iOS
 * Simulator cannot reach the .onion relay over the app's embedded Tor (it
 * fails at inbox-mint with "Could not reach the relay") — so refuse to start
 * and fail fast with a clear reason instead of timing out minutes later at
 * the mint step.
 *
 * Call at MODULE LOAD (each cross conf does, right after resolving its env),
 * BEFORE wdio initializes the runner or the Appium service: a throw there
 * aborts config loading outright (fail-fast) instead of being swallowed as a
 * non-fatal onPrepare hook error, which wdio v9 logs but then continues past —
 * wasting minutes on WDA launch.
 *
 * `suite` names the caller in the default error text (e.g. 'cross:multi3');
 * `label` is the env var the UDID came from. `wording` lets a suite keep its
 * own error text (cross:push adds the APNs reasoning; cross:multi keeps its
 * original phrasing) — each override replaces the WHOLE message.
 */
export function assertIosTargetIsPhysical(
    suite: string,
    label: string,
    udid: string | undefined,
    wording?: {
        missingUdid?: (label: string) => string
        knownSimulator?: (label: string, udid: string) => string
    },
): void {
    if (!udid) {
        throw new Error(wording?.missingUdid?.(label) ?? (
            `${suite} is physical-device only: set ${label} to a real iPhone UDID ` +
            '(see `xcrun devicectl list devices`). Refusing to start — the iOS Simulator ' +
            'cannot reach the Tor relay.'
        ))
    }
    if (isSimulatorUdid(udid)) {
        throw new Error(wording?.knownSimulator?.(label, udid) ?? (
            `${suite} refuses to run against a simulator (${label}=${udid} is a known ` +
            'iOS Simulator). This suite needs the real .onion relay over Tor.'
        ))
    }
}

/**
 * ONE shape for the physical-iPhone capability block every cross suite uses —
 * previously hand-copied per conf (multi/multi3/push/referral) and
 * already drifting. The values that have LEGITIMATELY diverged per suite are
 * the suite-level options; everything else is identical by design. Returns the
 * same `iosCaps(udid, deviceName, wdaPort, mjpegPort, derivedDataPath)` helper
 * the confs used to define locally, so the capability call sites read
 * unchanged. Each conf keeps its own derivation comment next to the option
 * value it passes — the budgets differ per suite by DESIGN.
 */
export function makeIosCaps(suite: {
    /** Device-signed .app bundle path (each conf's WDIO_IOS_APP_PATH default). */
    appPath: string
    /** appium:platformVersion (each conf's WDIO_IOS_VERSION default, '18.6'). */
    platformVersion: string
    /** SECONDS — the per-suite idle budget. A seat's LEGAL idle is bounded by
     *  the ATTEMPT budget, not by any single step; too small and Appium reaps
     *  an idle seat RETRY-PROOF (multiremote never recreates a session
     *  mid-run; observed at 240s on multi3, "session is either terminated or
     *  not started"). Each conf derives + documents its own value at the call. */
    newCommandTimeout: number
    /** MILLISECONDS (Appium default 60s): a contended/cold WDA launch on a
     *  real device needs room; the tests' own waitFor deadlines still bound
     *  real hangs. NOTE: a wedged WDA must NOT be "fixed" by rebooting the
     *  phone — that requires manual input. */
    wdaLaunchTimeout: number
}) {
    return function iosCaps(
        udid: string | undefined, deviceName: string, wdaPort: number, mjpegPort: number,
        derivedDataPath: string,
    ) {
        return {
            capabilities: {
                platformName: 'iOS',
                'appium:platformVersion': suite.platformVersion,
                'appium:deviceName': deviceName,
                'appium:udid': udid,
                'appium:automationName': 'XCUITest',
                'appium:app': suite.appPath,
                'appium:bundleId': APP_BUNDLE_ID,
                'appium:noReset': true,
                'appium:fullReset': false,
                // A FRESH install (new device, CI,
                // or a manual devicectl reinstall) re-triggers the SpringBoard
                // "Allow local network" prompt, which renders on top of the
                // in-app Terms screen and silently swallows the Agree taps
                // ("EULA gate did not dismiss"). The app itself uses no system
                // alerts (PIN is a custom keypad, EULA is in-app SwiftUI), so
                // auto-accepting is safe and only unblocks first-run.
                'appium:autoAcceptAlerts': true,
                'appium:newCommandTimeout': suite.newCommandTimeout,
                'appium:useNewWDA': false,
                'appium:usePrebuiltWDA': true,
                'appium:wdaLocalPort': wdaPort,
                'appium:mjpegServerPort': mjpegPort,
                // PER-DEVICE derivedData (2026-07-13, root-caused on cross:multi3).
                // Suites with several iPhones launch WDA CONCURRENTLY, and when they
                // shared ONE derivedDataPath the `xcodebuild test-without-building`
                // runs clobbered each other: first symptom was "xcodebuild failed
                // with code 65" + a 60s /status miss that blew all 3 Appium retries
                // and aborted the session before any test ran; with a longer launch
                // timeout it instead surfaced later as "xcodebuild exited with code
                // 75" — one WDA DIES MID-RUN, its appium session goes invalid, and
                // because isExisting() swallows "Session does not exist" the
                // relay-warm gate spins a full 240s on a dead session before failing
                // with a confusing activateApp error. Separate paths remove the
                // contention entirely; each is auto-seeded from the prebuilt
                // /tmp/wda-cross-ios at config load (ensurePrebuiltWdaSeeded) so no
                // rebuild is needed (see the README's prebuilt-WDA section). The
                // single-iPhone cross:multi passes the prebuilt base itself.
                'appium:derivedDataPath': derivedDataPath,
                'appium:wdaLaunchTimeout': suite.wdaLaunchTimeout,
                'appium:showXcodeLog': true,
                'appium:xcodeOrgId': process.env.WDIO_IOS_TEAM_ID || 'YOUR_TEAM_ID',
                'appium:xcodeSigningId': process.env.WDIO_IOS_SIGNING_ID || 'Apple Development',
                ...(process.env.WDIO_IOS_WDA_BUNDLE_ID
                    ? { 'appium:updatedWDABundleId': process.env.WDIO_IOS_WDA_BUNDLE_ID }
                    : {}),
                // NO session-level --test-wipe-on-launch: it would be inherited by
                // every activateApp cold-relaunch (Tor recovery / iOS jetsam of the
                // backgrounded app), re-wiping the provisioned vault mid-attempt.
                // resetIos() launches the wipe explicitly with a per-reset nonce
                // instead (see Device.resetIos + RunApp's nonce gate, 2026-07-15).
            },
        }
    }
}

/**
 * Per-suite, per-seat, per-SLOT derivedData path for the prebuilt WDA.
 *
 * `xcodebuild test-without-building` writes into its derivedDataPath, so two
 * WDA launches that SHARE one path clobber each other (the code-65 / code-75
 * class documented in makeIosCaps below). Per-seat paths fixed that WITHIN a
 * suite; the remaining hole is two runs of the SAME suite at once — today
 * cross:multi3 and cross:multi4 both hard-code `/tmp/wda-cross-ios-{admin,
 * member}`, so a second concurrent run `rmSync`/`cpSync`s under the first's
 * live WDA (ensurePrebuiltWdaSeeded). The `-s<slot>` suffix closes it: the
 * port-slot a run holds is unique across concurrent runs, so the paths are too.
 *
 * `WDIO_POOL_SLOT` is unset today ⇒ every path ends `-s0`, which is stable and
 * self-consistent (one re-seed from the base the first time each is used).
 */
export function wdaDerivedDataPath(suite: string, seat: string): string {
    const slug = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '')
    const slot = process.env.WDIO_POOL_SLOT ?? 0
    return `/tmp/wda-${slug(suite)}-${slug(seat)}-s${slot}`
}

/** Default device lock-screen PIN on the physical test Androids — NOT the app
 *  vault PIN. Every Android conf hard-coded this literal before it moved here. */
export const DEFAULT_ANDROID_LOCK_PIN = '1111'

/**
 * The device lock-screen PIN for an Android seat, as `makeAndroidCaps` wants it.
 *
 * Unset env var ⇒ the test phones default ('1111'), i.e. exactly what every conf
 * hard-coded before. Set-but-EMPTY ⇒ `null` = "this phone has no device PIN",
 * which makes the caps block omit `unlockType`/`unlockKey` entirely (passing a
 * PIN to a phone that has none makes UiAutomator2's unlock attempt fail).
 *
 * `WDIO_ANDROID_LOCK_PIN2` is the second Android seat's (cross:move-a2a).
 */
export function androidLockPin(
    envVar: 'WDIO_ANDROID_LOCK_PIN' | 'WDIO_ANDROID_LOCK_PIN2' = 'WDIO_ANDROID_LOCK_PIN',
): string | null {
    const raw = process.env[envVar]
    if (raw === undefined) return DEFAULT_ANDROID_LOCK_PIN
    const pin = raw.trim()
    return pin === '' ? null : pin
}

/**
 * The per-seat env vars for the Nth **iOS** / Nth **Android** seat of a conf, counted in
 * ROLE DECLARATION ORDER — the index a conf can only compute at ALLOCATION time once it
 * has an `'any'` seat that may land on either platform.
 *
 * The coupling these two encode (and the reason they live here rather than being
 * re-derived in five confs): the device pool fills `WDIO_ANDROID_LOCK_PIN` for the FIRST
 * android role it drew and `…_LOCK_PIN2` for the second, and a lease's port slot fills
 * `WDIO_ANDROID_SYSTEM_PORT` / `…_SYSTEM_PORT2` and `WDIO_IOS_WDA_PORT{,2,3}` /
 * `WDIO_IOS_MJPEG_PORT{,2,3}` the same way (helpers/devicePool.js `portEnvForSlot`).
 * Two seats that end up on the same platform MUST therefore take different indices, or
 * they collide on one host port — the UiAutomator2 "port #82xx busy" cascade, and on iOS
 * the shared-derivedData xcodebuild code-65/75 class.
 *
 * `fallback` is what the conf used before the pool existed (the un-leased default).
 */
export function androidSeatEnv(index: number, fallbackPort: number): { systemPort: number; lockPin: string | null } {
    const portVar = index === 0 ? 'WDIO_ANDROID_SYSTEM_PORT' : `WDIO_ANDROID_SYSTEM_PORT${index + 1}`
    const raw = process.env[portVar]
    return {
        systemPort: Number(raw) || fallbackPort,
        lockPin: androidLockPin(index === 0 ? 'WDIO_ANDROID_LOCK_PIN' : 'WDIO_ANDROID_LOCK_PIN2'),
    }
}

/** The Nth iOS seat's WDA + MJPEG host ports (same declaration-order rule as above). */
export function iosSeatEnv(index: number, fallbackWda: number, fallbackMjpeg: number): { wdaPort: number; mjpegPort: number } {
    const suffix = index === 0 ? '' : String(index + 1)
    return {
        wdaPort: Number(process.env[`WDIO_IOS_WDA_PORT${suffix}`]) || fallbackWda,
        mjpegPort: Number(process.env[`WDIO_IOS_MJPEG_PORT${suffix}`]) || fallbackMjpeg,
    }
}

/**
 * ONE shape for the physical-Android capability block every cross/push suite
 * uses — the Android counterpart of `makeIosCaps`, and the bigger reuse gap of
 * the two: this block was hand-copied into 16 confs with no factory at all, so
 * every UiAutomator2 fix had to be applied 16 times (and the constants HAD
 * already drifted in formatting, if not in value).
 *
 * INVARIANT across every conf (this factory owns them): automationName,
 * appPackage/appActivity, autoGrantPermissions, noReset/fullReset,
 * adbExecTimeout 60000, uiautomator2ServerInstallTimeout 120000,
 * disableIdLocatorAutocompletion.
 *
 * PARAMETERIZED, because confs legitimately differ:
 *   - `newCommandTimeout` — the per-suite idle budget (same derivation as the
 *     iOS side: an Android seat that idles through the iPhones' whole leg must
 *     not be reaped). Each conf documents its own value at the call.
 *   - `wipeOnLaunch` — `false` drops the TEST_WIPE extra so the session's
 *     launch intent carries NO `--ez TEST_WIPE true`, for a suite that runs ON
 *     TOP of vault/pairing/push-opt-in state something else left behind. NO conf
 *     passes it today: its only user was badge:verify, which is now the tail of
 *     cross:push INSIDE that suite's own session (so the session's single launch
 *     legitimately wipes, and the badge spec inherits the push leg's state
 *     in-session). Kept for the next suite that needs to inherit device state.
 *     It does NOT drop the language extra: pinning the app's language is not a
 *     state reset, and a state-inheriting suite needs it just as much.
 *   - `deviceName`, `systemPort`, `lockPin` — per seat (see the params).
 */
export function makeAndroidCaps(suite: {
    /** Debug APK path (each conf's WDIO_ANDROID_APP_PATH default). */
    appPath: string
    /** SECONDS — the per-suite idle budget; see makeIosCaps's identical note.
     *  Each conf derives + documents its own value at the call site. */
    newCommandTimeout: number
    /** Send `--ez TEST_WIPE true` in the session's launch intent (default true).
     *  `false` = this suite inherits on-device state and must NOT wipe. */
    wipeOnLaunch?: boolean
}) {
    return function androidCaps(
        udid: string | undefined,
        deviceName: string,
        systemPort: number,
        /** Device lock-screen PIN (NOT the app vault PIN). UiAutomator2 types it
         *  itself, so an idle auto-lock mid-run doesn't wedge the session — which
         *  matters most on the seat that idles through another seat's whole leg.
         *  (iOS has no equivalent cap — WDA cannot type a device passcode; the
         *  iPhones rely on Auto-Lock=Never instead.) `null`/omitted ⇒ the unlock
         *  caps are left out entirely, for a phone with no device PIN. */
        lockPin?: string | null,
    ) {
        return {
            capabilities: {
                platformName: 'Android',
                'appium:deviceName': deviceName,
                'appium:udid': udid,
                'appium:automationName': 'UiAutomator2',
                'appium:app': suite.appPath,
                'appium:appPackage': APP_BUNDLE_ID,
                'appium:appActivity': `${APP_BUNDLE_ID}.MainActivity`,
                'appium:autoGrantPermissions': true,
                ...(lockPin ? { 'appium:unlockType': 'pin', 'appium:unlockKey': lockPin } : {}),
                'appium:noReset': true,
                'appium:fullReset': false,
                'appium:newCommandTimeout': suite.newCommandTimeout,
                'appium:adbExecTimeout': 60000,
                'appium:uiautomator2ServerInstallTimeout': 120000,
                // Compose testTagsAsResourceId exposes the bare test tag as the
                // resource-id, so UiAutomator2 must NOT auto-prepend
                // `com.vg.run:id/` to an `id=`/resourceId() locator.
                // This is a UiAutomator2 SETTING, not a driver capability (it is
                // absent from the driver's constraint list in BOTH 3.x and 8.x),
                // and it works because unrecognized `appium:` caps are forwarded
                // verbatim to the UiAutomator2 server, which applies them as
                // settings. Appium therefore logs it under "capabilities were not
                // recognized by this driver" — expected, NOT a bug to fix. If it
                // ever stops being forwarded, the documented equivalent is
                // `'appium:settings[disableIdLocatorAutocompletion]': true`
                // (appium/lib/helpers/capability.js `pullSettings`).
                'appium:disableIdLocatorAutocompletion': true,
                // Host-side adb-forward port for the UiAutomator2 server. DISTINCT
                // per Android seat and per concurrent run — two UiAutomator2
                // sessions on one host need two systemPorts (Appium scopes every
                // `adb -s <udid>` forward it issues to the session's own port
                // automatically; nothing else to wire here).
                'appium:systemPort': systemPort,
                // Language pin rides the SESSION's own launch intent too (the
                // one launch the harness never issues by hand) — the PRIMARY
                // Android lever, and the only one that exists below API 33.
                // See helpers/AppLocale.ts's header; unconditional, because a
                // wipe-less session still needs its language pinned.
                'appium:optionalIntentArguments': [
                    ...(suite.wipeOnLaunch === false ? [] : ['--ez TEST_WIPE true']),
                    androidLanguageIntentString(),
                ].join(' '),
            },
        }
    }
}

/**
 * Close-apps-after-suite, primary path: terminate the app on EVERY seat of the
 * multiremote session while the sessions are still alive (worker `after` hook,
 * after the recordings are saved — terminate discards an in-flight recording).
 * Under noReset:true the drivers leave the app FOREGROUNDED at session end
 * (XCUITest's shouldTerminateApp defaults false), stranding Rún running
 * embedded Tor on every physical device. terminateApp works on both platforms.
 * Best-effort and bounded: a dead seat logs and falls through to the
 * onComplete shell backstop; it never fails or hangs the run.
 */
export async function terminateAppOnAllSeats(): Promise<void> {
    const mb = multiremotebrowser as unknown as {
        instances?: string[]
        getInstance(name: string): WebdriverIO.Browser
    }
    let seats: string[]
    try {
        // The @wdio/globals proxy throws on ANY property access when the
        // multiremote global was never registered — and wdio v9 still runs the
        // `after` hook when session CREATION failed (WDA code 65, device
        // disconnected). Nothing to terminate then; the onComplete shell
        // backstop covers the devices.
        seats = mb.instances ?? []
    } catch {
        console.log('[teardown] no multiremote session registered — skipping (onComplete backstop covers the devices)')
        return
    }
    for (const name of seats) {
        let timer: NodeJS.Timeout | undefined
        try {
            const drv = mb.getInstance(name)
            // attach a catch to
            // the terminateApp promise itself. When the 15 s timer wins the race,
            // the still-pending terminateApp can reject LATER with nobody
            // listening — an unhandled rejection that, on Node ≥15, can take the
            // runner down during teardown and mask the real result. Swallow it:
            // the timeout branch already logged, and onComplete is the backstop.
            const terminate = (drv as any).terminateApp(APP_BUNDLE_ID) as Promise<unknown>
            terminate.catch(() => { /* logged by the race below / handled by onComplete */ })
            await Promise.race([
                terminate,
                new Promise((_, reject) => {
                    timer = setTimeout(() => reject(new Error('terminateApp timed out after 15s')), 15_000)
                }),
            ])
            console.log(`[teardown] ${name}: ${APP_BUNDLE_ID} terminated`)
        } catch (e) {
            console.log(`[teardown] ${name}: terminateApp failed (${(e as Error).message}) — the onComplete backstop will retry`)
        } finally {
            if (timer) clearTimeout(timer)
        }
        // LOCK THE iPHONE'S SCREEN when the suite is done (user ask 2026-10-07). The test
        // iPhones keep Auto-Lock = Never (a suite may leave a phone untouched for more
        // than iPhone's longest finite setting, 5 min), so the screen would otherwise
        // stay lit until the next suite. Verified on one iPhone SE: a new Appium session
        // on a LOCKED passcode-less iPhone unlocks it by itself at app launch (isLocked
        // false, app foreground, first screen visible) — so nothing is needed at start.
        // Androids keep their own keyguard handling (wakeAndroid) and are left alone.
        try {
            const drv = mb.getInstance(name) as any
            if (drv?.isIOS) {
                await Promise.race([
                    drv.execute('mobile: lock'),
                    new Promise((_, reject) => setTimeout(() => reject(new Error('mobile: lock timed out after 10s')), 10_000)),
                ])
                console.log(`[teardown] ${name}: screen locked`)
            }
        } catch (e) {
            console.log(`[teardown] ${name}: screen lock skipped (${(e as Error).message.split('\n')[0]})`)
        }
    }
}

/**
 * Close-apps-after-suite, onComplete shell backstop for a PHYSICAL iPhone —
 * covers seats whose session was already dead when terminateAppOnAllSeats ran.
 * This Xcode's devicectl has NO app-terminate subcommand (`device process`
 * offers only launch/resume/sendMemoryWarning/signal/suspend — verified
 * 2026-07-14 via `xcrun devicectl --help`), so the route is: bundle id →
 * installed-app URL (`device info apps`) → main-binary pid (`device info
 * processes`) → `device process signal --signal SIGKILL`. JSON via
 * --json-output files (devicectl's only supported script interface; field
 * shapes verified against a live device). Every step is bounded and
 * best-effort: a disconnected phone, a simulator UDID (CoreDevice doesn't know
 * those), or an app that isn't running all log-and-return — never throw, never
 * hang the run's exit.
 */
export function killIosAppViaDevicectl(udid: string): void {
    const tmp = join(tmpdir(), `devicectl-${process.pid}-${Math.random().toString(36).slice(2)}.json`)
    const query = (args: string[]): any => {
        try {
            execFileSync('xcrun', [
                'devicectl', ...args, '--device', udid,
                '--timeout', '20', '--quiet', '--json-output', tmp,
            ], { stdio: 'ignore', timeout: 30_000 })
            return JSON.parse(readFileSync(tmp, 'utf8'))
        } finally {
            try { unlinkSync(tmp) } catch { /* never written */ }
        }
    }
    try {
        const apps: any[] = query(['device', 'info', 'apps'])?.result?.apps ?? []
        const url: string | undefined =
            apps.find((a) => a?.bundleIdentifier === APP_BUNDLE_ID)?.url
        if (!url) return   // app not installed → nothing to kill
        const procs: any[] = query(['device', 'info', 'processes'])?.result?.runningProcesses ?? []
        // The MAIN binary sits directly under the .app dir; anything deeper
        // (PlugIns/*.appex) is an extension, not the app process.
        const proc = procs.find((p) => typeof p?.executable === 'string'
            && p.executable.startsWith(url)
            && !p.executable.slice(url.length).includes('/'))
        if (!proc) return  // app not running → already closed (e.g. by the after() hook)
        execFileSync('xcrun', [
            'devicectl', 'device', 'process', 'signal',
            '--device', udid, '--pid', String(proc.processIdentifier),
            '--signal', 'SIGKILL', '--timeout', '20', '--quiet',
        ], { stdio: 'ignore', timeout: 30_000 })
        console.log(`[teardown] ${udid}: SIGKILLed ${APP_BUNDLE_ID} (pid ${proc.processIdentifier}) via devicectl`)
    } catch (e) {
        console.log(`[teardown] ${udid}: devicectl backstop skipped (${(e as Error).message})`)
    }
}

/** Close-apps-after-suite, onComplete backstop for the Android seat (bounded,
 *  best-effort; targets the UDID when given so a multi-device adb can't balk). */
export function forceStopAndroidApp(udid?: string): void {
    const adb = process.env.ANDROID_HOME
        ? `${process.env.ANDROID_HOME}/platform-tools/adb`
        : `${process.env.HOME}/Library/Android/sdk/platform-tools/adb`
    const target = udid ? ['-s', udid] : []
    try {
        execFileSync(adb, [...target, 'shell', 'am', 'force-stop', APP_BUNDLE_ID], { timeout: 15_000 })
    } catch { /* device gone / adb missing — best-effort */ }
}

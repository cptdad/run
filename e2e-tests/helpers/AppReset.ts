/**
 * Helpers for resetting the app between tests.
 *
 * The app has persistent state (Keychain, UserDefaults, encrypted DB).
 * Instead of removeApp + installApp (which on iOS revokes the Local
 * Network privacy grant and re-triggers the user-facing prompt), we
 * terminate + relaunch with `--test-wipe-on-launch` (iOS) /
 * `--ez TEST_WIPE true` (Android). The app's TestHooks wipes its own
 * persisted state on startup before any vault loads.
 */

import { pinAndroidAppLocale, iosLanguageArgs, androidLanguageIntentArgs } from './AppLocale'

const BUNDLE_ID = 'com.vg.run'

function platform(): 'ios' | 'android' {
    const p = ((driver.capabilities as any).platformName as string | undefined) ?? ''
    return p.toLowerCase() === 'android' ? 'android' : 'ios'
}

/** Extra platform launch args [resetAppWithArgs] can append on top of the
 *  test-wipe flag. See docs/periodic-reauth-design.md §3.12. */
export interface ResetAppArgs {
    /**
     * Arms a FIXED periodic re-auth interval (ms) for e2e determinism — see
     * docs/periodic-reauth-design.md. A debug build is OFF by default; this
     * is the only way to turn the touch-independent timer on in a debuggable
     * binary (no equivalent path exists in a release build). Floored at
     * 1000 ms by ReauthPolicy.setTestIntervalOverrideMs itself.
     *
     * On Android this rides `am start`'s intent extras, which do NOT survive
     * a later `activateApp`/`relaunchApp` — never call those after arming;
     * re-run `resetAppWithArgs` instead. On iOS the launch argument is
     * inherited across an `activateApp` cold-relaunch (same as
     * `--test-wipe-on-launch`).
     */
    reauthIntervalMs?: number

    /**
     * DEBUG-only: forces the update-nudge dialog's Play-Store/App-Store
     * two-button variant to render, even on this sideloaded emulator/
     * simulator build which has no real store installer/receipt
     * (RunViewModel.isPlayInstall / StoreInstall.isAppStoreInstall — both
     * fail closed to the info-only one-button variant otherwise). Rides
     * `--ez TEST_FORCE_STORE_INSTALL true` (Android, TestHooks.kt) /
     * `--test-force-store-install` (iOS, RunApp.swift) — same "no-op in a
     * release binary" shape as [reauthIntervalMs]. See
     * update-nudge-layout.spec.ts.
     */
    forceStoreInstall?: boolean
}

/**
 * Fully reset the app to first-install state — terminate, then launch
 * with the test-wipe flag (and any extra [args]) so the app clears its
 * persisted state before any UI renders. Does NOT uninstall the app.
 */
export async function resetAppWithArgs(args: ResetAppArgs): Promise<void> {
    // terminateApp is in the wdio v9 driver typings now; the old
    // expect-error suppression itself became a tsc error (TS2578).
    try { await driver.terminateApp(BUNDLE_ID) } catch { /* not running */ }
    await browser.pause(500)

    if (platform() === 'ios') {
        // The wipe flag MUST carry a fresh per-reset nonce (mirrors
        // Device.resetIos): RunApp wipes only when the nonce differs from the
        // last one consumed (92a5251 — a bare flag maps to the constant
        // "legacy" nonce, so it wipes ONCE per install and silently preserves
        // the vault on every later reset, breaking test isolation).
        const wipeNonce = `${Date.now()}-${Math.floor(Math.random() * 1e9)}`
        // English pin (PHASE 0 localization): keep every e2e run on English
        // regardless of the device/simulator's system language — see
        // AppLocale.ts's header for the Android-side equivalent and why.
        const launchArgs = [`--test-wipe-on-launch=${wipeNonce}`, ...iosLanguageArgs()]
        if (args.reauthIntervalMs != null) {
            launchArgs.push(`--test-reauth-interval-ms=${args.reauthIntervalMs}`)
        }
        if (args.forceStoreInstall) {
            launchArgs.push('--test-force-store-install')
        }
        await driver.execute('mobile: launchApp', { bundleId: BUNDLE_ID, arguments: launchArgs })
    } else {
        const shellArgs: string[] = [
            'start', '-n', `${BUNDLE_ID}/.MainActivity`,
            '--ez', 'TEST_WIPE', 'true',
            // English pin, PRIMARY lever (see AppLocale.ts header): applied by
            // the app AFTER its TEST_WIPE hook in the same onCreate, so the
            // wipe's locale reset can't un-pin it, and it works below API 33
            // where `cmd locale` does not exist at all.
            ...androidLanguageIntentArgs(),
        ]
        if (args.reauthIntervalMs != null) {
            shellArgs.push('--el', 'TEST_REAUTH_INTERVAL_MS', String(args.reauthIntervalMs))
        }
        if (args.forceStoreInstall) {
            shellArgs.push('--ez', 'TEST_FORCE_STORE_INSTALL', 'true')
        }
        // Secondary lever (API 33+), before am start — see AppLocale.ts header.
        // viaLaunchExtra: the launch below carries the extra, so a sub-33 phone
        // is pinned even though this call can't apply `cmd locale` there.
        await pinAndroidAppLocale(driver, BUNDLE_ID, undefined, { viaLaunchExtra: true })
        await driver.execute('mobile: shell', { command: 'am', args: shellArgs })
        // The TEST_WIPE launch resets the per-app locale
        // to follow-system as wipe residue. The launch extra above already
        // re-pins in-process (it runs after the wipe), so this second pass is
        // now only the 33+ belt-and-braces for the OS-owned LocaleManager record.
        await browser.pause(2_000)
        await pinAndroidAppLocale(driver, BUNDLE_ID, undefined, { viaLaunchExtra: true })
    }

    await browser.pause(1500)

    // Android 16+ (API 37+) may show a "16 KB compatibility" system
    // dialog on first launch. Dismiss it so tests can reach the app UI.
    if (platform() === 'android') {
        await dismissAndroidCompatDialog()
    }
}

/**
 * Fully reset the app to first-install state — terminate, then launch
 * with the test-wipe flag so the app clears its persisted state before
 * any UI renders. Does NOT uninstall the app.
 *
 * Thin wrapper over [resetAppWithArgs] (docs/periodic-reauth-design.md §3.12)
 * so the 14 existing single-device specs, which all call this plain form,
 * are untouched by construction.
 */
export async function resetApp(): Promise<void> {
    await resetAppWithArgs({})
}

/**
 * Dismiss the Android "App Compatibility" dialog if present. The dialog
 * (PageSizeMismatchDialog on Android 15+/16) can take a few seconds to
 * appear after launch on physical devices and on freshly installed APKs;
 * poll for ~10 s and dismiss whenever it shows.
 */
async function dismissAndroidCompatDialog(): Promise<void> {
    const deadline = Date.now() + 10_000
    while (Date.now() < deadline) {
        try {
            const ok = await $('android=new UiSelector().resourceId("android:id/button1")')
            if (await ok.isDisplayed()) {
                await ok.click()
                await browser.pause(500)
                return
            }
        } catch { /* not present yet */ }
        await browser.pause(500)
    }
}

/**
 * Terminate + reactivate the app without wiping state.
 * Preserves vault state but re-triggers the PIN screen.
 */
export async function relaunchApp(): Promise<void> {
    await driver.terminateApp(BUNDLE_ID)
    if (platform() === 'ios') {
        // English pin (PHASE 0 localization), same as resetAppWithArgs above.
        await driver.execute('mobile: launchApp', { bundleId: BUNDLE_ID, arguments: iosLanguageArgs() })
    } else {
        // No TEST_WIPE here (state is preserved), but the language extra rides
        // along: a relaunch is a fresh process, and on a sub-33 phone the extra
        // is the ONLY lever — cheap insurance that costs nothing when the app
        // is already pinned (TestHooks skips the relaunch when the tag matches).
        const shellArgs = ['start', '-n', `${BUNDLE_ID}/.MainActivity`, ...androidLanguageIntentArgs()]
        // English pin, secondary lever (API 33+), before am start.
        await pinAndroidAppLocale(driver, BUNDLE_ID, undefined, { viaLaunchExtra: true })
        await driver.execute('mobile: shell', { command: 'am', args: shellArgs })
    }
}

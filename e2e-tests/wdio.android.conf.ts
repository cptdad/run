import type { Options } from '@wdio/types'
import { resolve } from 'path'
import { accessSync } from 'fs'
import { execFileSync } from 'child_process'
import { sharedConfig } from './wdio.shared.conf'
import { rebootIfRequested } from './helpers/RebootDevice'
import { adbPath, adbArgs } from './helpers/Adb'
import { androidLanguageIntentString } from './helpers/AppLocale'

// Signal to AccessibilityIds.byId() to use `id=` instead of `~`.
process.env.WDIO_PLATFORM = 'android'

// Ensure ANDROID_HOME is set so Appium can find adb.
if (!process.env.ANDROID_HOME) {
    const guess = `${process.env.HOME}/Library/Android/sdk`
    try { accessSync(`${guess}/platform-tools/adb`); process.env.ANDROID_HOME = guess } catch {}
}

/**
 * Android-specific config. Points at the debug APK produced by
 * `./gradlew :androidApp:assembleDebug` (the single universal build since
 * the 2026-08-04 flavor collapse — both push transports, runtime-selected).
 *
 * Device: the first connected Android device or emulator. Set
 * WDIO_ANDROID_UDID to pin a specific device.
 */
export const config: Options.Testrunner = {
    ...sharedConfig,
    // UiAutomator2 server install + APK deploy is slow on software-
    // rendered emulators — give the session more time to start.
    connectionRetryTimeout: 300_000,
    // Match wdio.ios.conf: the 5-wrong-PIN wipe spec (5 entries + exponential
    // lockout backoffs + per-tap verification) exceeds the shared 120s hook
    // budget on a physical device.
    // 600 s, not 300 s: WDIO 9's mocha framework enforces THIS value as a bare
    // `Error: Timeout` per test and ignores a spec's own `this.timeout(...)`, so
    // the ceiling must cover the slowest single-device flow — relay-loss detection
    // is 4 control-poll 404s at the 60–90 s idle cadence (~360 s) plus setup.
    mochaOpts: { ...sharedConfig.mochaOpts, timeout: 600_000 },
    specs: ['./tests/*.spec.ts'],
    capabilities: [
        {
            platformName: 'Android',
            'appium:deviceName': process.env.WDIO_ANDROID_DEVICE || 'Android Emulator',
            'appium:udid': process.env.WDIO_ANDROID_UDID,
            'appium:automationName': 'UiAutomator2',
            'appium:app': process.env.WDIO_ANDROID_APP_PATH || resolve(
                __dirname,
                '..',
                'androidApp',
                'build',
                'outputs',
                'apk',
                'debug',
                'androidApp-debug.apk'
            ),
            'appium:appPackage': 'com.vg.run',
            'appium:appActivity': 'com.vg.run.MainActivity',
            'appium:autoGrantPermissions': true,
            // The emulator now carries a lock PIN (run-android-emu.sh sets it):
            // DeviceLockPolicy forces MAXIMUM on a device with NO lock screen, and
            // this suite is PIN-only. Harmless on the physical Pixel, which already
            // has the same PIN.
            'appium:unlockType': 'pin',
            'appium:unlockKey': '1111',
            // Specs call resetApp() themselves — don't let Appium
            // auto-reset on session start.
            'appium:noReset': true,
            'appium:fullReset': false,
            'appium:newCommandTimeout': 240,
            // Software-rendered emulators are slow — give adb more time.
            'appium:adbExecTimeout': 60000,
            'appium:uiautomator2ServerInstallTimeout': 120000,
            // Compose testTagsAsResourceId sets resource-id without the
            // package prefix. Prevent Appium from auto-prepending it.
            'appium:disableIdLocatorAutocompletion': true,
            // Launch emulator with a visible window (not headless).
            'appium:isHeadless': false,
            // TEST_WIPE + the English language pin (`--es test_language`,
            // the primary Android lever — see helpers/AppLocale.ts).
            'appium:optionalIntentArguments': `--ez TEST_WIPE true ${androidLanguageIntentString()}`,
        },
    ],
    async onPrepare() {
        // Opt-in (WDIO_REBOOT_BEFORE_RUN): reboot the physical device first to
        // clear accumulated uiautomator2/app degradation before a full run.
        await rebootIfRequested('android')
    },
    onComplete() {
        // Terminate the app but keep the emulator running — cold-booting
        // an emulator with software rendering takes a long time.
        // target the device explicitly. Without `-s`, an
        // un-targeted adb command fails with "more than one device/emulator" the
        // moment a phone is plugged in next to the emulator — or force-stops the
        // app on the WRONG device (e.g. mid-run in another session's suite).
        try {
            execFileSync(adbPath(), adbArgs(process.env.WDIO_ANDROID_UDID,
                ['shell', 'am', 'force-stop', 'com.vg.run']))
        } catch {}
    },
} as Options.Testrunner

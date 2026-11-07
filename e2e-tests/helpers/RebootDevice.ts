import { execFileSync } from 'child_process'
import { adbPath } from './Adb'

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

/**
 * Reboot the physical device before a full run to clear accumulated
 * uiautomator2 / WDA / app degradation (the cause of late-spec hangs on long
 * Tor-on suites — see the vault.spec / socket-hang-up findings).
 *
 * Opt-in: only runs when WDIO_REBOOT_BEFORE_RUN is set AND the relevant device
 * UDID is provided (so quick `--spec` iterations don't pay the reboot cost, and
 * simulators are left alone). Waits for the device to come back and settle
 * before the Appium session starts — for iOS that means waiting on lockdownd,
 * else you get "Connection refused to port 62078" instant-fails.
 */
export async function rebootIfRequested(platform: 'ios' | 'android'): Promise<void> {
    if (!process.env.WDIO_REBOOT_BEFORE_RUN) return

    if (platform === 'android') {
        const udid = process.env.WDIO_ANDROID_UDID
        if (!udid) return
        console.log(`[reboot] Android ${udid} — rebooting before run...`)
        try { execFileSync(adbPath(), ['-s', udid, 'reboot']) } catch { /* may drop connection */ }
        try { execFileSync(adbPath(), ['-s', udid, 'wait-for-device'], { timeout: 180_000 }) } catch {}
        // Wait for the boot to actually complete (not just adbd up).
        for (let i = 0; i < 60; i++) {
            try {
                const out = execFileSync(adbPath(), ['-s', udid, 'shell', 'getprop', 'sys.boot_completed'])
                    .toString().trim()
                if (out === '1') break
            } catch { /* still booting */ }
            await sleep(2_000)
        }
        await sleep(3_000)
        try {
            execFileSync(adbPath(), ['-s', udid, 'shell', 'input', 'keyevent', 'KEYCODE_WAKEUP'])
            execFileSync(adbPath(), ['-s', udid, 'shell', 'wm', 'dismiss-keyguard'])
            execFileSync(adbPath(), ['-s', udid, 'shell', 'svc', 'power', 'stayon', 'true'])
        } catch {}
        console.log('[reboot] Android ready')
        return
    }

    const udid = process.env.WDIO_IOS_UDID
    if (!udid) return
    console.log(`[reboot] iOS ${udid} — rebooting before run...`)
    try { execFileSync('xcrun', ['devicectl', 'device', 'reboot', '--device', udid]) } catch {}
    // Wait until lockdownd answers again before letting Appium connect.
    let up = false
    for (let i = 0; i < 48; i++) {
        try { execFileSync('ideviceinfo', ['-u', udid, '-k', 'ProductVersion'], { stdio: 'ignore' }); up = true; break }
        catch { await sleep(5_000) }
    }
    await sleep(15_000) // extra settle for springboard/services
    console.log(`[reboot] iOS ${up ? 'ready' : 'lockdownd not confirmed — continuing'}`)
}

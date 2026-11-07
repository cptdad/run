import { Ids, byId } from '../helpers/AccessibilityIds'
import { resetApp } from '../helpers/AppReset'
import { passEulaIfPresent, passPasscodeWarningIfPresent } from '../helpers/EulaHelper'

/**
 * "Move to new device" — the CAMERA path on the new phone (docs/device-move.md).
 *
 * Reproduces the 2026-09-27 GrapheneOS report: every camera scan of a move
 * code killed the app with
 *   IllegalStateException: Method setCurrentState must be called on the main thread
 * from the CameraX analysis thread (`pool-N-thread-1`). MoveFromDeviceScreen's
 * decode callback NAVIGATES (`navController.navigate("setup_pin")`), which is
 * main-thread-only, and QrCameraScanner invoked it inline on the analyzer. The
 * cross-move suites paste the handle (main thread), so they never saw it.
 *
 * No camera on an emulator: the DEBUG-only scanner-injection row
 * (`scan_inject_field` / `scan_inject_submit`, rendered by QrCameraScanner for
 * every caller) feeds the text in ON THE ANALYSIS THREAD, the exact route a
 * decoded frame takes, so this spec exercises the real thread hand-off. The
 * handle is a syntactically valid fake — the import itself would fail later
 * against nothing, but the crash point is the navigation right after the scan.
 *
 * Android-only: the iOS scanner already delivers on the main queue
 * (AVCaptureMetadataOutput delegate on DispatchQueue.main), and this spec runs
 * in the single-device emulator conf.
 */

// Shape-valid per MoveHandleCodec.parse: v "1", 32-char inbox id, 43-char cap,
// 32 CROCKFORD Base32 symbols (20 bytes; no I/L/O/U) code, 16-char bundle id.
const FAKE_HANDLE = JSON.stringify({
    v: '1',
    inbox: 'MoveScanSpecInboxIdAAAAAAAAAAAAA',
    rcap: 'MoveScanSpecReadCapAAAAAAAAAAAAAAAAAAAAAAAA',
    code: '0123456789ABCDEFGHJKMNPQRSTVWXYZ',
    bid: 'MoveScanSpecBidA',
})

describe('Move to new device — camera scan path', () => {

    before(function () {
        if (!browser.isAndroid) this.skip()
    })

    beforeEach(async () => {
        await resetApp()
    })

    it('scanning a move code advances to PIN setup instead of crashing', async () => {
        await passEulaIfPresent()
        const chooseMove = await $(byId(Ids.setupChooseMove))
        await chooseMove.waitForDisplayed({ timeout: 30_000 })
        await chooseMove.click()

        // The runtime CAMERA dialog may cover the screen on first render; the
        // injection row is drivable with the permission granted OR denied.
        await acceptRuntimePermissionIfPresent()

        const field = await $(byId(Ids.scanInjectField))
        await field.waitForExist({ timeout: 20_000 })
        await field.setValue(Buffer.from(FAKE_HANDLE, 'utf8').toString('base64'))
        await (await $(byId(Ids.scanInjectSubmit))).click()

        // The accepted handle navigates to setup_pin: the passcode warning (a
        // lock-less emulator) or the protection chooser or the keypad is the
        // next screen. A crash relaunches to the setup CHOOSER instead — or
        // nothing at all.
        const nextScreen = await waitForAny(
            [Ids.passcodeWarning, Ids.protectionLevelTitle, Ids.pinDots],
            20_000,
        )
        expect(nextScreen).not.toBeNull()
        expect(await (await $(byId(Ids.setupChooseMove))).isExisting()).toBe(false)

        // And the app is alive and still on the setup flow (not the crash
        // relaunch): the PIN keypad is reachable from here.
        await passPasscodeWarningIfPresent()
        const gotKeypadOrChooser = await waitForAny([Ids.protectionLevelTitle, Ids.pinDots], 20_000)
        expect(gotKeypadOrChooser).not.toBeNull()
    })
})

async function waitForAny(ids: string[], timeoutMs: number): Promise<string | null> {
    const deadline = Date.now() + timeoutMs
    while (Date.now() < deadline) {
        for (const id of ids) {
            if (await (await $(byId(id))).isExisting()) return id
        }
        await browser.pause(300)
    }
    return null
}

/** Android runtime-permission dialog (CAMERA here): tap Allow if it is up. */
async function acceptRuntimePermissionIfPresent(): Promise<void> {
    const candidates = [
        'com.android.permissioncontroller:id/permission_allow_foreground_only_button',
        'com.android.permissioncontroller:id/permission_allow_button',
        'com.android.permissioncontroller:id/permission_allow_one_time_button',
    ]
    for (let attempt = 0; attempt < 3; attempt++) {
        for (const rid of candidates) {
            const btn = await $(`id=${rid}`)
            if (await btn.isExisting()) {
                await btn.click()
                await browser.pause(500)
                return
            }
        }
        await browser.pause(500)
    }
}

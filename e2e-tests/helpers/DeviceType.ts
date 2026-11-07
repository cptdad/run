/**
 * Detect whether the current Appium session is targeting an emulator /
 * simulator or a physical device.
 *
 * Some single-platform specs hard-code assumptions about the build-time
 * RelayConfig override — on emulator/simulator the relay URL is rewritten
 * to a localhost endpoint where nothing is listening, so the relay is
 * always unreachable. On a physical device the URL is the real .onion
 * which may or may not be reachable, so those specs must skip themselves.
 *
 * Detection heuristics:
 *   - Android emulators expose their UDID as `emulator-NNNN`. Physical
 *     devices have alphanumeric serials (e.g. Pixel 7 → `27271FDH2000BZ`).
 *   - iOS Simulator UDIDs follow the UUID v4 format `8-4-4-4-12` hex.
 *     Physical iOS UDIDs are 40-char hex (pre-iOS 17) or `8-16` hex with
 *     a single hyphen (iOS 17+, e.g. `00008140-000000000000001C`).
 */
/**
 * Default timeout for `waitForDisplayed` and similar "short-wait" checks.
 *
 * 5 s is fine on simulator/emulator but bites the iPad (iPad6,11 hardware
 * + a busier accessibility tree) — e.g. the delete-contact-confirm dialog
 * takes >5 s to appear, intermittently. 15 s on physical keeps the tests
 * reliable without slowing simulator runs.
 *
 * Call this at the point of use (after the session is up), not at module
 * load — `browser.capabilities` is not populated until then.
 */
export function shortTimeout(): number {
    return isPhysicalDevice() ? 15_000 : 5_000
}

export function isPhysicalDevice(): boolean {
    const caps = browser.capabilities as any
    const platform = ((caps.platformName as string | undefined) || '').toLowerCase()
    const udid = (
        (caps['appium:udid'] as string | undefined) ||
        (caps.udid as string | undefined) ||
        (caps.deviceUDID as string | undefined) ||
        ''
    )

    if (platform === 'android') {
        return udid !== '' && !udid.startsWith('emulator-')
    }

    // iOS
    const simulatorUuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
    if (simulatorUuid.test(udid)) return false
    // Empty UDID — Appium picked a simulator by deviceName; treat as sim.
    if (!udid) return false
    return true
}

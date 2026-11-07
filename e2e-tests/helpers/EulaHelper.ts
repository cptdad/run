import { Ids, byId } from './AccessibilityIds'

/**
 * The App Store Guideline 1.2 Terms-of-Use (EULA) gate (iOS only).
 *
 * ContentView renders `EulaView` as an EXCLUSIVE branch above the whole vault
 * flow, so it must be accepted before PIN setup or entry is reachable. A test
 * wipe (resetApp / --test-wipe-on-launch) clears the accepted-version key, so a
 * fresh launch always shows it again.
 *
 * iOS quirk (localization PHASE 0 fix): `EulaView`'s root ZStack used to carry
 * a bare `.accessibilityIdentifier("eula_screen")`, which SwiftUI propagates
 * onto every child — so the Agree button's own `eula_agree_button` id was
 * shadowed and never surfaced to XCUITest (the same behaviour documented for
 * the About/Donate modals in about.spec.ts). The root now uses
 * `.containerA11yId` (UIComponents.swift) instead, so the id-first path below
 * works; the old visible-*label* match is kept as a fallback for one deploy
 * cycle (widen, never narrow) in case a session runs against a pre-deploy
 * binary. Android matches by testTag throughout (Compose has no propagation).
 */

const isAndroid = (): boolean => process.env.WDIO_PLATFORM === 'android'

/**
 * The "I Agree & Continue" button, located per-platform (see file header).
 *
 * iOS localization PHASE 0: EulaView's root now uses `.containerA11yId`
 * (UIComponents.swift), so `eula_agree_button` surfaces instead of being
 * shadowed — try the id FIRST (short existence wait so a stale build without
 * the container fix doesn't eat the whole timeout), falling back to the old
 * label predicate for one deploy cycle (WIDEN, never narrow — other sessions
 * may run against pre-deploy binaries; see PinHelper.ts's convention comment).
 * The label match stays valid under the English pin regardless.
 */
async function agreeButton() {
    if (isAndroid()) return $(byId(Ids.eulaAgreeButton))
    const byIdEl = await $(byId(Ids.eulaAgreeButton))
    if (await byIdEl.isExisting()) return byIdEl
    return $('-ios predicate string:type == "XCUIElementTypeButton" AND label == "I Agree & Continue"')
}

/** True iff the EULA gate is currently on screen. Detected via the root
 *  container id, which DOES surface on both platforms. */
export async function isEulaShown(timeoutMs = 1_500): Promise<boolean> {
    try {
        await (await $(byId(Ids.eulaScreen))).waitForDisplayed({ timeout: timeoutMs })
        return true
    } catch {
        return false
    }
}

/** Asserts the EULA gate is shown (root container + the Agree button). */
export async function expectEulaShown(timeoutMs = 15_000): Promise<void> {
    await (await $(byId(Ids.eulaScreen))).waitForDisplayed({ timeout: timeoutMs })
    await (await agreeButton()).waitForDisplayed({ timeout: 5_000 })
}

/** Taps "I Agree & Continue" and waits for the gate to disappear. */
export async function acceptEula(): Promise<void> {
    const agree = await agreeButton()
    await agree.waitForDisplayed({ timeout: 15_000 })
    await agree.click()
    await browser.waitUntil(async () => !(await isEulaShown(500)), {
        timeout: 10_000,
        interval: 200,
        timeoutMsg: 'EULA gate did not dismiss after tapping Agree',
    })
}

/**
 * Accept the EULA iff it is currently shown; otherwise a no-op. Called from
 * `waitForPinScreen` so every spec gets past the gate after a wiped launch
 * without each having to know about it. No-op on Android (the gate is iOS-only)
 * and when the gate is absent (e.g. a relaunch without wipe).
 */
export async function passEulaIfPresent(): Promise<void> {
    if (isAndroid()) return
    await browser.pause(500)               // let a freshly-launched UI settle
    if (!(await isEulaShown(1_500))) return
    await acceptEula()
}

/**
 * Dismiss the first-run "No device passcode" warning gate (iOS only)
 * by tapping "Continue anyway". ContentView renders it above first-run PinSetupView when
 * the device has no passcode (the simulator + the physical test iPhones don't). Called
 * from waitForPinScreen right after passEulaIfPresent (the gate sits just below the EULA
 * in ContentView's branch chain). localization PHASE 0: the gate ZStack now carries
 * `.containerA11yId("passcode_warning")` (ContentView.swift) so `passcode_warning_continue`
 * surfaces — matched id-first, with the old LABEL predicate kept as a fallback for one
 * deploy cycle. No-op on Android, on unlock, and when a passcode is set.
 */
export async function passPasscodeWarningIfPresent(): Promise<void> {
    if (isAndroid()) return
    const CONTINUE = '-ios predicate string:type == "XCUIElementTypeButton" AND label == "Continue anyway"'
    await browser.pause(400)               // let the freshly-launched UI settle
    // id-first (ContentView.swift now roots this gate in .containerA11yId, so
    // passcode_warning_continue surfaces), falling back to the label predicate
    // for one deploy cycle — WIDEN, never narrow (see agreeButton() above).
    let btn = await $(byId(Ids.passcodeWarningContinue))
    if (!(await btn.isExisting())) btn = await $(CONTINUE)
    if (!(await btn.isExisting())) return
    await btn.click()
    try {
        await browser.waitUntil(async () => {
            const stillById = await (await $(byId(Ids.passcodeWarningContinue))).isExisting()
            const stillByLabel = await (await $(CONTINUE)).isExisting()
            return !stillById && !stillByLabel
        }, { timeout: 10_000, interval: 200 })
    } catch { /* best-effort — the pin-dots wait in waitForPinScreen is the real sync point */ }
}

/** Best-effort scroll of the chooser's "Continue" button into view (see below). */
async function scrollChooserConfirmIntoView(): Promise<void> {
    try {
        if (isAndroid()) {
            await $('android=new UiScrollable(new UiSelector().scrollable(true).instance(0))'
                + `.scrollIntoView(new UiSelector().resourceId("${Ids.protectionLevelConfirm}"))`)
        } else {
            await browser.execute('mobile: scroll', { direction: 'down' })
        }
    } catch { /* already visible / gesture unsupported → tap as-is */ }
}

/**
 * The first-run "Set up as new / Move from another phone" chooser
 * (docs/device-move.md). Renders on BOTH platforms, right after the iOS EULA
 * gate (passEulaIfPresent) and before everything else waitForPinScreen /
 * waitForPassphraseScreen already drive (passcode warning / protection
 * chooser / PIN or passphrase screen). Every single-device spec wants the
 * OLD PinSetup flow, so tap `setup_choose_new` here when it is present.
 *
 * WIDE, never narrow (e2e-helpers-are-cross-session-state): races the
 * chooser's existence against [firstPinScreenId] — the element the CALLING
 * helper's own first blocking wait targets (pin_dots for waitForPinScreen,
 * passphrase_field for waitForPassphraseScreen) — over a short bounded
 * window. Neither showing within the window is NOT an error: it means an
 * OLDER APK with no chooser at all, or a returning-user unlock where
 * neither screen applies — either way this falls through and the caller's
 * own gates run exactly as before, so this keeps working unchanged for one
 * deploy cycle against a pre-chooser binary.
 */
export async function passSetupChooserIfPresent(firstPinScreenId: string): Promise<void> {
    const chooser = await $(byId(Ids.setupChooseNew))
    const firstPinScreenEl = await $(byId(firstPinScreenId))
    const deadline = Date.now() + 3_000
    let sawChooser = false
    while (Date.now() < deadline) {
        if (await chooser.isExisting().catch(() => false)) { sawChooser = true; break }
        if (await firstPinScreenEl.isExisting().catch(() => false)) return
        await browser.pause(150)
    }
    if (!sawChooser) return
    await chooser.click()
    try {
        await browser.waitUntil(async () => !(await chooser.isExisting()), { timeout: 5_000, interval: 200 })
    } catch { /* best-effort — the caller's own subsequent waits are the real sync point */ }
}

/**
 * Threat-level slider (docs/threat-level-slider-spec.md): first-run onboarding now opens on
 * the "Choose your protection" chooser BEFORE the PIN keypad (SetupPhase.CHOOSE_LEVEL) — there
 * is no PIN screen until a level is picked. Unlike the EULA/passcode gates this shows on BOTH
 * platforms. Defaults to CASUAL: the only fully-automatable level — a plain 6-digit PIN with NO
 * Lever B (Private/Hardened trigger a hardware biometric step) and NO passphrase (Maximum needs
 * a ≥70-bit passphrase, not a numeric PIN). That reproduces the pre-feature plain-PIN
 * provisioning the specs expect, and every existing single-device spec relies on this default —
 * do NOT change it. Called from waitForPinScreen after the passcode gate. No-op when the
 * chooser isn't showing (returning-user unlock / already provisioned).
 *
 * [level] (docs/periodic-reauth-design.md §3.12): pass 'maximum' for the passphrase tier —
 * reauth.spec.ts is the one caller today. The PIN-only single-device specs stay CASUAL.
 */
export async function passProtectionChooserIfPresent(level: string = 'casual'): Promise<void> {
    await browser.pause(400)               // let the freshly-launched onboarding settle
    if (!(await (await $(byId(Ids.protectionLevelTitle))).isExisting())) return
    // Select the requested level first — the confirm button is disabled until one is chosen.
    const stop = await $(byId(Ids.protectionLevel(level)))
    await stop.waitForExist({ timeout: 10_000 })
    await stop.click()
    // "Continue" sits below a tall device-baseline panel in a scroll view. Scroll it into
    // view + tap; re-scroll/re-tap if the chooser is still up (dropped mid-transition tap).
    const deadline = Date.now() + 25_000
    while (Date.now() < deadline) {
        if (!(await (await $(byId(Ids.protectionLevelTitle))).isExisting())) return
        await scrollChooserConfirmIntoView()
        try { await (await $(byId(Ids.protectionLevelConfirm))).click() } catch { /* detached mid-transition */ }
        // Device-lock floor (shared DeviceLockPolicy, 2026-07-21): a device with no
        // lock screen can only run at MAXIMUM — its device key is readable at any
        // AFU, so a 6-digit PIN would be brute-forceable offline. These
        // single-device suites are PIN-only (PinHelper has no passphrase path), so
        // this is a hard stop rather than something to acknowledge past. Emulators
        // ship WITHOUT a lock screen: `adb shell locksettings set-pin 1111` on the
        // emulator restores the plain-PIN provisioning these specs are built on.
        if (await (await $(byId(Ids.protectionForcedNotice))).isExisting()) {
            throw new Error(
                'this device has NO LOCK SCREEN, so the app forces the MAXIMUM tier (a ≥70-bit '
                + 'passphrase) and the PIN-only single-device suites cannot provision on it. Set a '
                + 'device lock — on an emulator: `adb -s <udid> shell locksettings set-pin 1111`.')
        }
        try {
            await (await $(byId(Ids.protectionLevelTitle))).waitForExist({ timeout: 2_000, reverse: true })
            return
        } catch { /* still on the chooser → loop, re-scroll and re-tap */ }
    }
    throw new Error('protection-level chooser did not advance to PIN setup within 25s')
}

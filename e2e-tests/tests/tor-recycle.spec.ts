import { byId, Ids } from '../helpers/AccessibilityIds'
import {
    enterPin,
    waitForKeypad,
    waitForPinScreen,
    completePinSetup,
} from '../helpers/PinHelper'
import { resetApp } from '../helpers/AppReset'
import { isSimulatorUdid } from '../wdio.shared.conf'

const BUNDLE_ID = 'com.vg.run'
const REAL_PIN = '111111'
const WRONG_PIN = '222222'

// Backoff after a denied unlock is 1/2/4/8/8 s (CredentialPolicy.unlockBackoffMs);
// wait out the cap between attempts so every enterPin lands on a live keypad and
// each loop iteration is guaranteed to be a REAL counted attempt.
const BACKOFF_CAP_MS = 9_000

function isIos(): boolean {
    const p = ((driver.capabilities as any).platformName as string | undefined) ?? ''
    return p.toLowerCase() !== 'android'
}

describe('Dead-Tor process recycle (iOS)', () => {

    // Regression guard for the relaunch-required latch (97d0f5c): iOS Tor
    // (tor_main) is once-per-process, so after TorManager.stop() — here reached
    // organically via the 5-wrong-PIN emergency wipe — the process can never
    // run Tor again. The fix must exit(0) on the next backgrounding so the
    // following activation gets a FRESH process. The wipe conveniently makes
    // that observable without instrumentation: an in-session wipe holds a black
    // deniability screen that ONLY a process relaunch clears — so seeing
    // first-run SETUP after background+activate proves the recycle fired, while
    // a surviving process would still be black and time the wait out.
    it('wrong-PIN wipe latches relaunch-required; backgrounding recycles the process', async function () {
        if (!isIos()) return (this as any).skip()   // Android restarts its Tor child process; no recycle exists
        // PHYSICAL DEVICE ONLY: RelayConfig.ios.kt hard-codes the simulator to
        // direct HTTP to localhost ("Tor cannot run inside the iOS simulator"),
        // so `isTorRequired` is false and `AppState.startTorOrDirect`/
        // `startSpeculativeTor` never call `TorManager.shared.start()` at all —
        // `threadEverCreated` stays false for the life of the process. TorManager
        // .stop()'s `if threadEverCreated { noteRelaunchRequired() }` guard (see
        // TorManager.swift) therefore can NEVER latch on a simulator, no matter
        // how many wrong PINs wipe the vault, and ContentView's exit(0) recycle
        // never fires — the black wiped_cover screen just sits there forever
        // (proven: 2026-09-28 iOS sim run, screenshot showed a plain black
        // screen where first-run setup should have appeared). This regression
        // guard is only meaningful where Tor genuinely runs.
        const udid = (browser.capabilities as any)?.['appium:udid'] as string | undefined
        if (isSimulatorUdid(udid ?? process.env.WDIO_IOS_UDID)) {
            console.log('tor-recycle: SKIPPING — target is an iOS Simulator, which never starts Tor '
                + '(direct HTTP override); the relaunch-required latch can never engage there.')
            return (this as any).skip()
        }

        await resetApp()
        await waitForPinScreen()
        await waitForKeypad()
        await completePinSetup(REAL_PIN)
        // Vault open → startTorOrDirect() creates the once-per-process Tor
        // thread; from here on, any stop() latches relaunchRequired.
        await (await $(byId(Ids.unlockedRoot))).waitForDisplayed({ timeout: 30_000 })
        await browser.pause(3_000)

        // Background→foreground with a HEALTHY Tor locks the vault WITHOUT
        // killing the process (the recycle must not fire — negative control).
        // KNOWN APP QUIRK: a resume can transiently read isConfigured()==false
        // (keybag transition) and route to the SETUP screen on a provisioned
        // vault (see ios-vault-wiped-on-relaunch — product fix deferred). The
        // cross suites recover with a cold relaunch; do the same here, then
        // re-unlock so the Tor thread exists in whichever process we end up in,
        // and try the in-process lock again.
        let locked = false
        for (let attempt = 0; attempt < 3 && !locked; attempt++) {
            await driver.background(3)
            await waitForPinScreen()
            await waitForKeypad()
            if (!(await (await $(byId(Ids.pinPrompt))).isExisting())) {
                locked = true   // PIN ENTRY in the SAME process — what we need
                break
            }
            // Transient setup screen: never type into it. Cold-relaunch to
            // recompute isConfigured, then unlock to restart Tor in the new
            // process before retrying the in-process lock.
            try { await driver.terminateApp(BUNDLE_ID) } catch { /* dead */ }
            await browser.pause(500)
            await driver.execute('mobile: activateApp', { bundleId: BUNDLE_ID })
            await waitForPinScreen()
            await waitForKeypad()
            await enterPin(REAL_PIN)
            await (await $(byId(Ids.unlockedRoot))).waitForDisplayed({ timeout: 30_000 })
            await browser.pause(3_000)
        }
        expect(locked).toBe(true)

        // Burn the whole wrong-PIN budget. The budget is TIER-dependent (the
        // e2e protection chooser picks CASUAL = 10 consecutive attempts; the
        // legacy default is 5; the 24h window cap can also trip first) — so
        // drive until the keypad leaves the tree instead of counting to a
        // constant. The final denial fires emergencyWipe() → TorManager.stop()
        // → relaunchRequired latch + the black wiped_cover.
        let wipeFired = false
        for (let i = 0; i < 12 && !wipeFired; i++) {
            await enterPin(WRONG_PIN)
            await browser.pause(BACKOFF_CAP_MS)
            wipeFired = !(await (await $(byId(Ids.key('1')))).isExisting())
        }
        expect(wipeFired).toBe(true)
        // The wiped state REPLACES the UI with the black deniability cover.
        await (await $(byId('wiped_cover'))).waitForExist({ timeout: 10_000 })

        // Background with the latch set → exit(0); the re-activation launches a
        // fresh process. If the exit did NOT fire, the old process is still
        // showing the black wipedThisSession screen and the setup wait below
        // fails the test.
        try {
            await driver.background(3)
        } catch {
            // The session app died on cue mid-background; bring it back by hand.
            await driver.execute('mobile: activateApp', { bundleId: BUNDLE_ID })
        }
        await browser.pause(2_000)

        // Fresh process on a wiped install → EULA (handled inside
        // waitForPinScreen) then first-run SETUP: pin_prompt EXISTS only there.
        await waitForPinScreen()
        await waitForKeypad()
        expect(await (await $(byId(Ids.pinPrompt))).isExisting()).toBe(true)
    })
})

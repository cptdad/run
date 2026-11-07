// Periodic random re-authentication at MAXIMUM (e2e). Behavior under test
// (docs/periodic-reauth-design.md): on the MAXIMUM protection level the vault
// re-locks after a random interval — drawn fresh at every unlock — REGARDLESS
// of activity, in addition to (and independent of) the idle Lever-C auto-lock.
// A debug build ships this OFF by default (KeepAwake cannot defeat a
// touch-independent timer, and the device suites run iOS seats on MAXIMUM for
// multi-minute Tor waits); `resetAppWithArgs({ reauthIntervalMs })` arms a
// FIXED, deterministic interval via the debug-only TestHook
// (`--el TEST_REAUTH_INTERVAL_MS` / `--test-reauth-interval-ms=<n>`), which is
// the only way to observe the feature from a debuggable single-device build.
//
// Platform-neutral, like pin.spec.ts / push-prompt.spec.ts: no pairing, no
// relay, so this runs on BOTH Android and iOS (`test:emulator:android` /
// `test:emulator:ios`).
//
// The fired lock is IN-PROCESS on both platforms (RunViewModel.lockForReauth /
// ContentView's lockAndResetNavigation) — unlike the Lever-C background lock,
// no relaunch/foreground-return is needed to observe it: the app transitions
// to the passphrase prompt on its own while the spec just waits.
//
// Never call relaunchApp() after arming reauthIntervalMs: on Android `am
// start`'s intent extras do NOT survive a later `activateApp`, silently
// disarming the override for the rest of the session (see AppReset.ts). Every
// case below stays inside ONE continuous foreground session for exactly this
// reason; the one relaunchApp() call (case 2, after the wipe) happens only
// once the interval no longer matters.
import { Ids, byId } from '../helpers/AccessibilityIds'
import {
    enterPassphrase,
    waitForPassphraseScreen,
    waitForPassphraseField,
    completePassphraseSetup,
    readPinPrompt,
    waitForPinScreen,
    completePinSetup,
} from '../helpers/PinHelper'
import { resetAppWithArgs, relaunchApp } from '../helpers/AppReset'

// >=70-bit passphrase (CredentialPolicy.meetsFloor) — the same known-good
// constant the physical-device suite (not published) uses,
// reused here rather than re-deriving an entropy estimate.
// Six random diceware-style words: CredentialPolicy.estimateBits scores a single
// same-class token with the SDD-8 run discount, so a one-word string never clears
// the 70-bit MAXIMUM floor and passphrase_continue stays disabled (that is how the
// first run of this spec failed). A genuine multi-word phrase takes the word model.
const PASSPHRASE = 'velvet harbor quantum sparrow lantern mosaic'
const WRONG_PASSPHRASE = 'this is definitely not the right passphrase at all'
const CASUAL_PIN = '111111'

/** Waits until unlocked_root is gone (the re-auth fired and the app is back
 *  on the credential prompt) within [timeoutMs] of arming. */
async function waitForReauthFire(timeoutMs: number): Promise<void> {
    await browser.waitUntil(
        async () => !(await (await $(byId(Ids.unlockedRoot))).isExisting().catch(() => false)),
        { timeout: timeoutMs, interval: 500, timeoutMsg: `periodic re-auth did not fire within ${timeoutMs}ms` },
    )
}

// Interval budget: first-run setup (~15 s) + the first-unlock push-prompt dismissal
// (≤ ~10 s) must complete BEFORE the armed interval elapses, or the re-auth fires
// while the helpers are still driving onboarding. 45 s leaves that headroom.
describe('Periodic random re-auth at MAXIMUM', () => {

    it('fires within the armed interval (and not before it) at MAXIMUM, dropping unlocked_root', async () => {
        const REAUTH_MS = 45_000
        await resetAppWithArgs({ reauthIntervalMs: REAUTH_MS })
        await waitForPassphraseScreen()
        const prompt = await readPinPrompt()
        expect(prompt.toLowerCase()).toContain('choose')
        await completePassphraseSetup(PASSPHRASE)
        await (await $(byId(Ids.unlockedRoot))).waitForDisplayed({ timeout: 30_000 })

        // Floor sanity: must NOT fire before the armed interval has even
        // mostly elapsed — a much-earlier fire would be a wiring bug (e.g.
        // Lever C's own — much shorter in a real release — timeout leaking
        // into a debug build, which must never happen per the design's
        // debug-off-by-default rule for Lever C too).
        await browser.pause(10_000)
        expect(await (await $(byId(Ids.unlockedRoot))).isExisting()).toBe(true)

        // Fires by ~REAUTH_MS (+ margin for the coarse-then-fine cadence and
        // CI scheduling jitter).
        await waitForReauthFire(REAUTH_MS - 10_000 + 20_000)

        // Lands back on the passphrase prompt — the SAME unlock screen, not a
        // new/different one (reuses pin_prompt/passphrase_field/unlock_button).
        await waitForPassphraseField()
    })

    it('5 wrong passphrases at the re-auth prompt trigger an emergency wipe', async () => {
        const REAUTH_MS = 45_000
        await resetAppWithArgs({ reauthIntervalMs: REAUTH_MS })
        await waitForPassphraseScreen()
        await completePassphraseSetup(PASSPHRASE)
        await (await $(byId(Ids.unlockedRoot))).waitForDisplayed({ timeout: 30_000 })

        // Let the re-auth actually fire — proves the WIPE BUDGET below is
        // exercised through the re-auth-triggered lock screen specifically,
        // not just an ordinary relock (the design's "full lock, same
        // PinAttemptsStore" decision is the thing under test here).
        await waitForReauthFire(REAUTH_MS + 20_000)
        await waitForPassphraseField()

        // Same shape as pin.spec.ts's "5 wrong PINs triggers emergency wipe":
        // each attempt costs entry debounce + unlock (Argon2id, debug-weak
        // cost) + shake + exponential backoff before the field re-enables.
        const UNLOCK_MARGIN = 4_000
        for (let i = 0; i < 5; i++) {
            await waitForPassphraseField()
            await enterPassphrase(WRONG_PASSPHRASE)
            const backoff = Math.min(1000 * 2 ** i, 8_000)
            await browser.pause(backoff + UNLOCK_MARGIN)
        }

        // After the emergency wipe, the next launch re-provisions from
        // scratch. relaunchApp() is safe here — the interval override no
        // longer matters, we're done observing timing.
        await browser.pause(2_000)
        await relaunchApp()
        await waitForPassphraseScreen()
        const prompt = await readPinPrompt()
        expect(prompt.toLowerCase()).toContain('choose')
    })

    it('a correct passphrase re-arms the deadline for another cycle', async () => {
        const REAUTH_MS = 45_000
        await resetAppWithArgs({ reauthIntervalMs: REAUTH_MS })
        await waitForPassphraseScreen()
        await completePassphraseSetup(PASSPHRASE)
        await (await $(byId(Ids.unlockedRoot))).waitForDisplayed({ timeout: 30_000 })

        // First cycle.
        await waitForReauthFire(REAUTH_MS + 20_000)
        await waitForPassphraseField()

        // Correct passphrase re-opens the vault — a fresh unlock, so a fresh
        // deadline (docs/periodic-reauth-design.md: "drawn fresh at every
        // vault open").
        await enterPassphrase(PASSPHRASE)
        await (await $(byId(Ids.unlockedRoot))).waitForDisplayed({ timeout: 30_000 })

        // Second cycle — proves the deadline was actually RE-ARMED, not a
        // one-shot that silently never fires again.
        await waitForReauthFire(REAUTH_MS + 20_000)
        await waitForPassphraseField()
    })

    it('never fires at CASUAL, even with an interval armed', async () => {
        const REAUTH_MS = 45_000
        await resetAppWithArgs({ reauthIntervalMs: REAUTH_MS })
        // Default level ('casual') — the tier gate (ReauthPolicy.appliesTo)
        // must keep the feature off regardless of the armed override.
        await waitForPinScreen()
        await completePinSetup(CASUAL_PIN)
        await (await $(byId(Ids.unlockedRoot))).waitForDisplayed({ timeout: 30_000 })

        await browser.pause(REAUTH_MS + 15_000)
        expect(await (await $(byId(Ids.unlockedRoot))).isExisting()).toBe(true)
    })
})

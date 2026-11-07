import { Ids, byId } from './AccessibilityIds'
import { passEulaIfPresent, passSetupChooserIfPresent, passPasscodeWarningIfPresent, passProtectionChooserIfPresent } from './EulaHelper'

/**
 * Helper for interacting with the Rún PIN keypad and PIN screens.
 *
 * Both the setup and entry screens use a custom keypad with
 * accessibility IDs `key_0` .. `key_9` and `key_delete`. Because the
 * app explicitly avoids the system keyboard (anti-clipboard, anti-
 * autocomplete), we can't use `setValue` — we must tap each digit.
 */

/**
 * Reads how many PIN digits are currently entered, from the count the app
 * exposes on the pin_dots element (Android content-desc / iOS accessibility
 * value). Returns null if the dots aren't on screen — e.g. the screen
 * transitioned away after the final digit submitted the PIN.
 */
async function pinDotCount(): Promise<number | null> {
    try {
        // The app exposes the entered-digit count as the (invisible) pin_count
        // element's text on both platforms. pin_count absent → not on a PIN
        // screen (the final digit submitted and the screen transitioned).
        const el = await $(byId('pin_count'))
        if (!(await el.isExisting())) return null
        const n = parseInt((await el.getText()) ?? '', 10)
        return Number.isNaN(n) ? null : n
    } catch {
        return null
    }
}

/**
 * Taps each digit in `pin`, verifying after every tap that the entered-digit
 * count actually advanced — and re-tapping a dropped tap. This makes PIN entry
 * deterministic: no digit-drop flakiness (the root cause of intermittent
 * unlock-denied / "unlocked_root never appeared" failures). The final digit
 * submits the PIN, so the dots may vanish as the screen transitions; that is
 * accepted as success. Works on both platforms (accessibility IDs match).
 *
 * This is the RAW tap primitive — it has no side effects beyond typing the
 * PIN. `enterPin` below wraps it with the post-unlock modal dismiss guards;
 * use `enterPinRaw` directly only when a spec needs to OBSERVE the app's
 * immediate post-unlock UI itself (e.g. push-prompt.spec.ts asserting the
 * prompt), where the guard would eat the very thing under test.
 */
export async function enterPinRaw(pin: string): Promise<void> {
    if (!/^\d+$/.test(pin)) {
        throw new Error(`enterPin: expected a digits-only string, got ${JSON.stringify(pin)}`)
    }
    // Deterministic without paying the a11y-update latency on every digit: tap
    // the whole PIN (lightly spaced to avoid drops), then verify the count ONCE.
    // A count stuck at 1..len-1 means a digit dropped — and since the PIN wasn't
    // submitted (no wasted unlock attempt), we just clear the partial and retry.
    // Success = submitted/transitioned (null), reset for the next stage (0), or
    // all digits entered (>= len). All-digits-dropped (still 0) is effectively
    // impossible and the caller's post-condition would catch it anyway.
    for (let attempt = 0; attempt < 4; attempt++) {
        for (const digit of pin) {
            const key = await $(byId(Ids.key(digit)))
            await key.waitForDisplayed({ timeout: 5_000 })
            await key.click()
            await browser.pause(50)
        }
        await browser.pause(400)   // let the entry settle / submit / transition
        const c = await pinDotCount()
        if (c === null || c === 0 || c >= pin.length) return
        // A digit dropped — clear the partial entry and re-enter.
        await deleteDigits(c)
        await browser.pause(200)
    }
    throw new Error(`enterPin: PIN did not fully register after retries`)
}

/**
 * Dismiss the push-notification prompt iff it is currently showing —
 * tapping ONLY "No" (push_prompt_yes opens the notification carousel and
 * would block every caller downstream expecting the contact list, since the
 * carousel is a further modal on top). Shown once per vault (a vault-meta
 * flag; a resetApp wipe re-arms it). A short
 * existence wait, tap No if present, never fails if absent.
 *
 * 2026-09-11: the prompt no longer fires at UNLOCK — it fires on the FIRST
 * RELAY ANSWER of the session (see dismissPostConnectModalsIfPresent's kdoc
 * below for the full story), so this function's unlock-anchored probe is
 * now a best-effort fallback (catches a relay that answers unusually fast,
 * or a stale binary) rather than the primary chokepoint. Every wait for the
 * connected/revealed state should also call dismissPostConnectModalsIfPresent.
 */
export async function dismissPushPromptIfPresent(): Promise<void> {
    // Mid-setup short-circuit: enterPin also drives the CHOOSE/CONFIRM setup
    // stages, where the PIN screen is still up and no prompt can exist —
    // anchoring to unlocked_root there would stall 30s per stage for nothing.
    if (await (await $(byId(Ids.pinDots))).isExisting().catch(() => false)) return
    // Same short-circuit, MAXIMUM's passphrase equivalent of pin_dots
    // (reauth.spec.ts): a WRONG passphrase at the re-auth/unlock screen (or
    // either passphrase setup stage) leaves passphrase_field on screen — no
    // push prompt can exist there either (it only ever renders alongside
    // unlocked_root), and without this guard the 30s unlockedRoot.waitForExist
    // below burns needlessly on every wrong-passphrase attempt: enterPassphrase
    // always calls this helper, including from a failed unlock, and
    // passphrase_field has no equivalent of pin_dots's own short-circuit.
    if (await (await $(byId(Ids.passphraseField))).isExisting().catch(() => false)) return
    // Anchor to unlocked_root FIRST: the prompt lives on the contact list, and
    // on iOS first-run the protection chooser precedes the PIN, so this guard
    // can be called seconds before ContactListView even composes — a probe
    // window that starts too early expires with the prompt "absent" and the
    // NEXT tap gets scrim-swallowed (proven: ugc.spec on the sim, twice).
    // But on Android the prompt is a Dialog WINDOW: while it is up, unlocked_root is
    // occluded from the a11y tree, so the 30s anchor below always burns out when the
    // prompt IS present. Probe the prompt itself first (short) and only anchor when
    // it is absent — otherwise a timed flow (reauth.spec's test interval) expires
    // inside this helper. When absent the behaviour is exactly the old one.
    const early = await $(byId(Ids.pushPrompt))
    const earlyDeadline = Date.now() + 5_000
    let earlyPresent = false
    while (Date.now() < earlyDeadline) {
        if (await early.isExisting().catch(() => false)) { earlyPresent = true; break }
        await browser.pause(250)
    }
    if (!earlyPresent) {
        await (await $(byId(Ids.unlockedRoot))).waitForExist({ timeout: 30_000 }).catch(() => { /* caller's problem */ })
    }
    // Then a recheck loop, not a single probe: the @Published raise can render
    // a beat after the root first exists.
    const modal = await $(byId(Ids.pushPrompt))
    const probeDeadline = Date.now() + 3_000
    let present = false
    while (Date.now() < probeDeadline) {
        await browser.pause(300)
        if (await modal.isExisting()) { present = true; break }
    }
    if (!present) return
    // VERIFY-UNTIL-GONE (cross:multi3 2026-08-13): an iOS tap landing during
    // the dialog's entrance animation is reported delivered but the SwiftUI
    // action never fires — the prompt then stays latched and its scrim
    // silently swallows later taps. Tap, confirm the container left the
    // tree, retap while it hasn't (bounded); log loudly if it never clears.
    try {
        for (let i = 0; i < 6; i++) {
            const no = await $(byId(Ids.pushPromptNo))
            if (await no.isExisting()) { await no.click() }
            else if (!browser.isAndroid) {
                // Deploy-cycle fallback (2026-08-13): binaries built before the
                // OptionalContainerA11yId fix flatten the title-less dialog, so the
                // buttons carry the CONTAINER's id — match NO by label instead.
                const merged = await $(`-ios predicate string:name == 'push_prompt' AND label == 'NO'`)
                if (await merged.isExisting()) { await merged.click() }
            }
            await browser.pause(700)
            if (!(await modal.isExisting().catch(() => false))) {
                if (i > 0) console.log(`[guard] push prompt confirmed gone after ${i + 1} dismissal tap(s)`)
                return
            }
        }
        console.log('[guard] WARNING: push prompt still present after 6 dismissal taps — '
            + 'dialog latched; the next scrim-swallowed tap failure is THIS, not the spec')
    } catch { /* best-effort */ }
    try {
        await browser.waitUntil(async () => !(await modal.isExisting()), { timeout: 2_000, interval: 200 })
    } catch { /* best-effort — the caller's own waits are the real sync point */ }
}

/**
 * POLL-FRIENDLY probe + dismiss for push_prompt then update_nudge_dialog
 * (checked in that order — the nudge is itself UI-gated behind the prompt,
 * so it can only ever render after the prompt is gone). This is the pair a
 * caller now needs when waiting for the CONNECTED state rather than the
 * unlock moment.
 *
 * 2026-09-11 behaviour change: push_prompt no longer fires at unlock — it
 * fires on the FIRST RELAY ANSWER of the session, the exact instant
 * `contact_list_hidden_until_connected` disappears and rows /
 * `empty_contacts_state` render (still once per vault; a resetApp wipe
 * re-arms it). On the emulator/simulator against the mock relay that answer
 * can land just seconds after unlock — i.e. AFTER `completePinSetup`'s
 * trailing `dismissPushPromptIfPresent()` call has already returned, so that
 * guard now misses it more often than it catches it. `dismissPushPromptIfPresent()`
 * / `dismissUpdateNudgeIfPresent()` above stay in place as harmless
 * fallbacks (a relay that answers unusually fast, or a stale binary) — every
 * single-device wait for the connected/revealed state should ALSO call
 * (i.e. race, on every poll) THIS function.
 *
 * Deliberately NOT built on dismissPushPromptIfPresent/dismissUpdateNudgeIfPresent
 * above: those are sized for a ONE-TIME call right after unlock and each
 * cost several seconds even when nothing is present (a 5s existence probe +
 * a 3s recheck for the prompt; a 3s recheck for the nudge) — fine once, but
 * ruinous called every iteration of a `browser.waitUntil` poll (typically
 * ~500ms interval). This version bounds the existence probe to `probeMs`
 * (mirrors the physical-device suite's dismissPushPromptIfPresent, not published) and
 * skips the unlocked_root anchor entirely — a caller polling for the
 * connected/revealed state is by definition already past unlock.
 */
export async function dismissPostConnectModalsIfPresent(probeMs = 250): Promise<void> {
    const prompt = await $(byId(Ids.pushPrompt))
    const deadline = Date.now() + probeMs
    let promptPresent = false
    while (Date.now() < deadline) {
        if (await prompt.isExisting().catch(() => false)) { promptPresent = true; break }
        await browser.pause(Math.min(100, Math.max(0, deadline - Date.now())))
    }
    if (promptPresent) {
        console.log('[guard] push prompt present (post-connect poll) — dismissing (No)')
        // VERIFY-UNTIL-GONE, same discipline as dismissPushPromptIfPresent above.
        for (let i = 0; i < 6; i++) {
            const no = await $(byId(Ids.pushPromptNo))
            if (await no.isExisting().catch(() => false)) {
                await no.click().catch(() => { /* raced its own dismissal */ })
            } else if (!browser.isAndroid) {
                // Deploy-cycle fallback (2026-08-13): pre-OptionalContainerA11yId
                // binaries flatten the title-less dialog — address NO by label.
                const merged = await $(`-ios predicate string:name == 'push_prompt' AND label == 'NO'`)
                if (await merged.isExisting().catch(() => false)) {
                    await merged.click().catch(() => { /* raced its own dismissal */ })
                }
            }
            await browser.pause(500)
            if (!(await prompt.isExisting().catch(() => false))) {
                if (i > 0) console.log(`[guard] push prompt confirmed gone after ${i + 1} dismissal tap(s)`)
                break
            }
        }
    }
    const nudge = await $(byId(Ids.updateNudgeDialog))
    if (await nudge.isExisting().catch(() => false)) {
        console.log('[guard] update-nudge present (post-connect poll) — dismissing (Later/OK)')
        for (let i = 0; i < 6; i++) {
            const later = await $(byId(Ids.updateNudgeLaterButton))
            if (await later.isExisting().catch(() => false)) {
                await later.click().catch(() => { /* raced its own dismissal */ })
            }
            await browser.pause(500)
            if (!(await nudge.isExisting().catch(() => false))) {
                if (i > 0) console.log(`[guard] update nudge confirmed gone after ${i + 1} dismissal tap(s)`)
                break
            }
        }
    }
}

/**
 * Dismiss the update-available nudge iff it is currently showing —
 * tapping `update_nudge_later_button`, which is REUSED for both the
 * dismissible "Later" (store-capable install) and the sole "OK" of the
 * info-only variant (the info-only variant reuses this id), so this
 * guard needs no store-vs-info branching. Shown at most once per calendar
 * day per advertised version (a vault-meta throttle key, `update_nudge_v1`;
 * a resetApp wipe re-arms it), on the contact list, after the FIRST
 * successful relay response of the session. Exact twin of
 * dismissPushPromptIfPresent (same early short-circuits, same anchor-then-
 * recheck-then-verify-until-gone shape) — see that function's comments for
 * the rationale of each step; the only structural difference is there is no
 * "Yes" branch to avoid (Later/OK is the ONLY action), so there is no
 * iOS pre-fix merged-id fallback to carry over either — the update-nudge
 * dialog is new, so no pre-OptionalContainerA11yId binary of it exists.
 */
export async function dismissUpdateNudgeIfPresent(): Promise<void> {
    // Mid-setup short-circuit: enterPin also drives the CHOOSE/CONFIRM setup
    // stages, where the PIN screen is still up and no nudge can exist —
    // anchoring to unlocked_root there would stall 30s per stage for nothing.
    if (await (await $(byId(Ids.pinDots))).isExisting().catch(() => false)) return
    // Same short-circuit, MAXIMUM's passphrase equivalent of pin_dots.
    if (await (await $(byId(Ids.passphraseField))).isExisting().catch(() => false)) return
    // Anchor to unlocked_root FIRST (see dismissPushPromptIfPresent's header
    // for the full rationale): probe the nudge itself first (short) and only
    // anchor to unlocked_root when it's absent, so a timed flow's own
    // interval can't expire inside this helper.
    // No early probe / unlocked_root anchor here: every caller chains this
    // right after dismissPushPromptIfPresent, which has already anchored to
    // unlocked_root — the 3s recheck below is the whole (cheap) cost when the
    // nudge is absent, which is the common case.
    // Then a recheck loop, not a single probe: the nudge can render a beat
    // after the root first exists.
    const modal = await $(byId(Ids.updateNudgeDialog))
    const probeDeadline = Date.now() + 3_000
    let present = false
    while (Date.now() < probeDeadline) {
        await browser.pause(300)
        if (await modal.isExisting()) { present = true; break }
    }
    if (!present) return
    // VERIFY-UNTIL-GONE (mirrors dismissPushPromptIfPresent, same rationale:
    // a tap landing during the dialog's entrance animation can be reported
    // delivered while the underlying action never fires): tap, confirm the
    // container left the tree, retap while it hasn't — never fire-and-forget.
    try {
        for (let i = 0; i < 6; i++) {
            const later = await $(byId(Ids.updateNudgeLaterButton))
            if (await later.isExisting()) { await later.click() }
            await browser.pause(700)
            if (!(await modal.isExisting().catch(() => false))) {
                if (i > 0) console.log(`[guard] update nudge confirmed gone after ${i + 1} dismissal tap(s)`)
                return
            }
        }
        console.log('[guard] WARNING: update nudge still present after 6 dismissal taps — '
            + 'dialog latched; the next scrim-swallowed tap failure is THIS, not the spec')
    } catch { /* best-effort */ }
    try {
        await browser.waitUntil(async () => !(await modal.isExisting()), { timeout: 2_000, interval: 200 })
    } catch { /* best-effort — the caller's own waits are the real sync point */ }
}

/**
 * enterPinRaw + the push-prompt (and update-nudge) dismiss guards. Every
 * single-device spec's real unlock chokepoint funnels through here (setup's
 * Choose/Confirm stages call it too, where they are safe no-ops — the
 * push-prompt guard here fires too early to ever see the prompt anyway; see
 * completePinSetup's own trailing guard call below for why THAT is the real
 * chokepoint for setup), so every spec gets both guards for free with no
 * call-site changes. Unconditional and cheap (a ~300ms settle pause plus one
 * existence check when a modal is absent), matching the existing EulaHelper
 * gates' convention of calling their dismiss-if-present check unconditionally
 * rather than trying to predict when it's needed.
 */
export async function enterPin(pin: string): Promise<void> {
    await enterPinRaw(pin)
    await dismissPushPromptIfPresent()
    await dismissUpdateNudgeIfPresent()
}

/**
 * Taps the backspace key `count` times.
 */
export async function deleteDigits(count: number = 1): Promise<void> {
    for (let i = 0; i < count; i++) {
        const del = await $(byId(Ids.keyDelete))
        await del.click()
    }
}

/**
 * Waits until the app is showing a PIN screen (setup or entry).
 * Detected via the pin_dots element and the key_0 button — both
 * are present on every PIN screen, setup or entry. There is no
 * "Rún" title element in the UI (only a runestone image).
 */
export async function waitForPinScreen(timeoutMs = 15_000): Promise<void> {
    // The Guideline 1.2 Terms gate (iOS) renders above the PIN screen after a
    // wiped launch; accept it first so every spec reaches the keypad. No-op on
    // Android and when the gate is absent (e.g. a relaunch without wipe).
    await passEulaIfPresent()
    // Setup chooser (docs/device-move.md): "Set up as new" vs "Move from
    // another phone". Every single-device spec wants the OLD PinSetup flow —
    // tap "new" when the chooser is present, WIDE/no-op otherwise.
    await passSetupChooserIfPresent(Ids.pinDots)
    // A no-passcode warning renders above first-run PinSetup on a
    // device without a passcode (the simulator doesn't have one). No-op otherwise.
    await passPasscodeWarningIfPresent()
    // Threat-level slider: first-run onboarding opens on the protection-level chooser
    // before the PIN keypad — pick a level to reach it. No-op on unlock / provisioned.
    await passProtectionChooserIfPresent()
    const dots = await $(byId(Ids.pinDots))
    await dots.waitForDisplayed({ timeout: timeoutMs })
    const key0 = await $(byId(Ids.key(0)))
    await key0.waitForDisplayed({ timeout: timeoutMs })
}

/**
 * MAXIMUM tier's (docs/periodic-reauth-design.md §3.12) equivalent of
 * waitForPinScreen: passes the same EULA/passcode/chooser gates but selects
 * the 'maximum' stop and waits for the passphrase_field text field instead of
 * pin_dots/key_0 (MAXIMUM has no digit keypad). reauth.spec.ts is the only
 * caller today; every other spec stays on waitForPinScreen's default CASUAL.
 */
export async function waitForPassphraseScreen(timeoutMs = 15_000): Promise<void> {
    await passEulaIfPresent()
    // Setup chooser (docs/device-move.md) — same rationale as waitForPinScreen
    // above, raced against passphrase_field (this helper's own first blocking wait).
    await passSetupChooserIfPresent(Ids.passphraseField)
    await passPasscodeWarningIfPresent()
    await passProtectionChooserIfPresent('maximum')
    await waitForPassphraseField(timeoutMs)
}

/** Waits for the passphrase text field to be displayed. 20s default, matching
 *  waitForKeypad's rationale (Argon2id/backoff can gate re-display). */
export async function waitForPassphraseField(timeoutMs = 20_000): Promise<void> {
    const field = await $(byId(Ids.passphraseField))
    await field.waitForDisplayed({ timeout: timeoutMs })
}

/**
 * Types [phrase] into the passphrase field and taps [buttonId] ("unlock_button"
 * at entry, "passphrase_continue" at setup) once it's enabled.
 *
 * Hardened per the physical-device suite's `enterCredential` lesson (not published) (2026-07-22,
 * took cross:multi down 3/3): on iOS the SecureField's `setValue` is RACY (it
 * can land before the field is ready, leaving the button disabled) AND
 * `clearValue` SILENTLY NO-OPS there — so a naive retry-on-disabled APPENDS a
 * second copy of the phrase; the doubled string still clears the >=70-bit
 * floor, so setup COMMITS the doubled value and the confirm stage (typed once)
 * mismatches forever. Clear ONLY via backspaces, and ONLY on a retry pass
 * (backspacing an empty field on the FIRST pass disturbs its focus).
 */
async function submitPassphrase(phrase: string, buttonId: string): Promise<void> {
    const field = await $(byId(Ids.passphraseField))
    await field.waitForDisplayed({ timeout: 10_000 })
    const btn = await $(byId(buttonId))
    for (let attempt = 0; attempt < 4; attempt++) {
        await field.click()
        for (let k = 0; k < 12; k++) {
            if (await browser.isKeyboardShown().catch(() => true)) break
            await browser.pause(250)
        }
        if (attempt > 0) {
            try { await field.addValue('\uE003'.repeat(phrase.length * 2 + 16)) } catch { /* not focusable */ }
        }
        await field.setValue(phrase)
        await browser.pause(400)
        // Android: the soft keyboard covers the continue button and UiAutomator then
        // reports it as absent (findElements → []) even though it is enabled. Dismiss
        // the keyboard before probing; iOS keeps the button above the keyboard.
        if (browser.isAndroid) { await browser.hideKeyboard().catch(() => { /* already hidden */ }); await browser.pause(300) }
        if (await btn.isExisting() && await btn.isEnabled()) {
            await btn.click()
            return
        }
        await browser.pause(300)
    }
    throw new Error(`submitPassphrase: ${buttonId} never enabled after 4 entries`)
}

/**
 * MAXIMUM tier's (docs/periodic-reauth-design.md §3.12) setup twin of
 * completePinSetup: Choose → Confirm passphrase, same provisioning-complete
 * detection (pin_prompt vanishing) as the PIN path.
 */
export async function completePassphraseSetup(phrase: string): Promise<void> {
    const PROVISION_TIMEOUT = 240_000
    const STAGE_TIMEOUT     = 15_000

    await waitForPassphraseField()
    let prompt = await readPinPrompt()   // "Choose a passphrase"

    await submitPassphrase(phrase, Ids.passphraseContinue)
    prompt = await waitForPromptChange(prompt, STAGE_TIMEOUT)   // → "Confirm your passphrase"

    await submitPassphrase(phrase, Ids.passphraseContinue)
    await browser.waitUntil(async () => {
        const el = await $(byId(Ids.pinPrompt))
        return !(await el.isExisting()) || !(await el.isDisplayed())
    }, { timeout: PROVISION_TIMEOUT, interval: 300,
         timeoutMsg: `Passphrase setup did not complete (pin_prompt still shown) within ${PROVISION_TIMEOUT}ms` })
    await dismissPushPromptIfPresent()
    await dismissUpdateNudgeIfPresent()
}

/**
 * MAXIMUM tier's unlock twin of enterPin: types [phrase] into the passphrase
 * field and taps "unlock_button", then applies the same push-prompt
 * dismiss guards as enterPin.
 */
export async function enterPassphrase(phrase: string): Promise<void> {
    await submitPassphrase(phrase, Ids.unlockButton)
    await dismissPushPromptIfPresent()
    await dismissUpdateNudgeIfPresent()
}

/**
 * Waits for the keypad to be displayed (key_0 visible).
 *
 * 20s default (not 10s): between wrong-PIN attempts the keypad only re-enables
 * after the exponential backoff (up to 8s) PLUS the unlock PBKDF2 (210k iters,
 * slow on the x86_64 simulator) PLUS the per-attempt counter crypto (consecutive
 * + the rolling-window cap). 10s was marginal and tipped over once the window
 * counter was added — see the PIN-helper crypto-cost desync note.
 */
export async function waitForKeypad(timeoutMs = 20_000): Promise<void> {
    const key0 = await $(byId(Ids.key(0)))
    await key0.waitForDisplayed({ timeout: timeoutMs })
}

/**
 * Returns the current prompt text on the PIN screen
 * (e.g. "Choose your PIN", "Enter your PIN").
 */
export async function readPinPrompt(): Promise<string> {
    const prompt = await $(byId(Ids.pinPrompt))
    await prompt.waitForDisplayed()
    return prompt.getText()
}

/**
 * Waits until the PIN prompt text differs from [previous] (and is
 * non-empty). A stage transition only completes once that stage's work
 * finishes — for the confirm stage this includes CR-1 vault provisioning
 * (PBKDF2 + SQLCipher create), which can take several seconds. Polling the
 * prompt is the reliable sync point; fixed sleeps race ahead of provisioning
 * and drop digits onto stale UI.
 */
async function waitForPromptChange(previous: string, timeoutMs: number): Promise<string> {
    let current = previous
    await browser.waitUntil(async () => {
        try {
            const t = await readPinPrompt()
            if (t && t !== previous) { current = t; return true }
        } catch { /* prompt momentarily absent during transition */ }
        return false
    }, { timeout: timeoutMs, interval: 300,
         timeoutMsg: `PIN prompt did not advance from "${previous}" within ${timeoutMs}ms` })
    return current
}

/**
 * Complete first-run PIN setup: choose PIN → confirm. Between stages we wait
 * for the prompt to actually advance rather than sleeping a fixed interval —
 * the confirm stage triggers synchronous vault provisioning (CR-1) whose
 * duration is variable, then auto-opens the vault.
 *
 * The optional second argument is a no-op, retained so existing call sites that
 * still pass a (now-removed) decoy PIN keep working. The decoy vault feature
 * was removed; setup creates one vault.
 */
export async function completePinSetup(realPin: string, _unusedDecoyPin?: string): Promise<void> {
    // Provisioning budget for the confirm (PBKDF2 + DB create) stage.
    // Argon2id provisioning on a DEBUG build runs interpreted on the first call of
    // a fresh process (debuggable APK → no ART AOT), 100-160s on a mid-range device
    // until the JIT warms it (~5s after). Release AOT-compiles to ~2s; this budget
    // only covers the debug-harness cold-start (60s was too tight post-reinstall).
    const PROVISION_TIMEOUT = 240_000
    const STAGE_TIMEOUT     = 15_000

    await waitForKeypad()
    let prompt = await readPinPrompt()           // "Choose your PIN"

    await enterPin(realPin)
    prompt = await waitForPromptChange(prompt, STAGE_TIMEOUT)      // → confirm

    await enterPin(realPin)
    // Provisioned + auto-unlocked → app leaves PinSetupScreen for the contact
    // list (PinEntryScreen/contact list has NO pin_prompt element). Detect
    // completion by the setup prompt disappearing, not by a text change.
    await browser.waitUntil(async () => {
        const el = await $(byId(Ids.pinPrompt))
        return !(await el.isExisting()) || !(await el.isDisplayed())
    }, { timeout: PROVISION_TIMEOUT, interval: 300,
         timeoutMsg: `Setup did not complete (pin_prompt still shown) within ${PROVISION_TIMEOUT}ms` })
    // enterPin's own push-prompt guard (chained above, on every digit entry)
    // fires ~300ms after the CONFIRM digits are tapped — long before
    // provisioning (up to PROVISION_TIMEOUT) actually finishes and the screen
    // transitions, so it can never see the first-unlock push_prompt (it isn't
    // rendered yet at that instant). Re-check HERE instead, now that
    // pin_prompt is confirmed gone (== provisioning + auto-unlock is done)
    // and BEFORE returning control to the caller — every single-device spec's
    // setup flow immediately waits on unlocked_root next, which is exactly
    // the chokepoint the Android modal-occlusion lesson warns about (a Dialog
    // window occludes unlocked_root entirely while the modal is up, so a
    // guard placed after that wait could never run).
    await dismissPushPromptIfPresent()
    await dismissUpdateNudgeIfPresent()
}

/**
 * completePinSetup's GUARD-FREE twin: the identical Choose→Confirm flow and
 * the same provisioning-complete detection (pin_prompt vanishing), but built
 * on enterPinRaw instead of enterPin — so it never dismisses whatever the app
 * shows the instant the vault auto-unlocks. Exists for specs that need to
 * OBSERVE that instant, e.g. push-prompt.spec.ts asserting the first-unlock
 * push_prompt itself — the guarded completePinSetup above would eat it (see
 * its trailing dismissPushPromptIfPresent() call). Mirrors why enterPinRaw
 * exists alongside enterPin.
 */
export async function completePinSetupRaw(realPin: string): Promise<void> {
    const PROVISION_TIMEOUT = 240_000
    const STAGE_TIMEOUT     = 15_000

    await waitForKeypad()
    let prompt = await readPinPrompt()

    await enterPinRaw(realPin)
    prompt = await waitForPromptChange(prompt, STAGE_TIMEOUT)

    await enterPinRaw(realPin)
    await browser.waitUntil(async () => {
        const el = await $(byId(Ids.pinPrompt))
        return !(await el.isExisting()) || !(await el.isDisplayed())
    }, { timeout: PROVISION_TIMEOUT, interval: 300,
         timeoutMsg: `Setup did not complete (pin_prompt still shown) within ${PROVISION_TIMEOUT}ms` })
}

/**
 * The FIRST unlock of a fresh vault shows the push-notification prompt
 * (PushPromptOnboarding.kt, one-shot per vault), and the update nudge is
 * deliberately gated BEHIND it (push prompt wins — ContactListScreen.kt /
 * ContactListView.swift). The guard-free *Raw unlock helpers used here never
 * dismiss it, so every case must clear it explicitly before it can say
 * anything about the nudge — otherwise a "no dialog" assertion is vacuously
 * true (the nudge is merely occluded) and the positive case never sees it.
 */
export async function dismissPushPromptRaw(): Promise<void> {
    const prompt = await $(byId(Ids.pushPrompt))
    if (await prompt.waitForExist({ timeout: 10_000 }).then(() => true, () => false)) {
        await tapUntilGone(Ids.pushPromptNo, Ids.pushPrompt)
    }
}

/**
 * VERIFY-UNTIL-GONE tap (same discipline as PinHelper's dismiss guards): on the
 * iOS 26 simulator a single XCUITest tap on a RuneDialog button can land on the
 * a11y double-exposure and "succeed" without dismissing anything (push-prompt.spec
 * shows exactly this on committed HEAD — pre-existing, not this feature), so tap,
 * verify the container is gone, and re-tap a bounded number of times.
 */
export async function tapUntilGone(buttonId: string, containerId: string): Promise<void> {
    const container = await $(byId(containerId))
    for (let attempt = 0; attempt < 6; attempt++) {
        const button = await $(byId(buttonId))
        if (await button.isExisting().catch(() => false)) {
            await button.click().catch(() => { /* re-probed below */ })
        }
        const gone = await container.waitForExist({ reverse: true, timeout: 2_500 }).then(() => true, () => false)
        if (gone) return
    }
    await container.waitForExist({ reverse: true, timeout: 2_500 })
}

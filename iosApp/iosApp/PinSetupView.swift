import SwiftUI
import shared

// ---------------------------------------------------------------------------
// PinSetupView — first-run onboarding with the threat-level slider.
//
// Flow: choose level (bare-forced) → PIN (Casual/Private) or passphrase
// (Maximum, floor-gated) → provision with the level → (Private) enable Lever B
// + show the recovery code → unlock into the app.
// isConfigured is NOT flipped until the closing unlock, so the recovery step
// stays visible instead of ContentView routing to the lock screen mid-flow.
// ---------------------------------------------------------------------------

private enum SetupPhase {
    case chooseLevel, enterCred, confirmCred, showRecovery
}

struct PinSetupView: View {
    @EnvironmentObject private var appState: AppState
    @Environment(\.scenePhase) private var scenePhase

    @State private var phase: SetupPhase = .chooseLevel
    @State private var level = "casual"
    @State private var pin = ""
    @State private var chosen = ""
    @State private var phrase = ""
    @State private var chosenPhrase = ""
    @State private var chosenCredential = ""
    // The SECOND independent full-vault-decrypt path
    // (docs/vault-relay-internals.md), equal in power to the credential — gets the
    // same lifetime discipline as chosenCredential above: dropped as soon as it's
    // used (RecoveryCodeView's onDone, below) and again on .onDisappear in case the
    // user backs out without reaching "Continue" (backgrounding also unmounts this
    // phase via the scenePhase handler below, so .onDisappear catches that path
    // too). NOTE: Swift String is copy-on-write but still can't be zeroed in place —
    // clearing this only drops the reference and shortens the window, it does not
    // remove the value from memory (same known limitation (an unwipeable immutable String)
    // as ProtectionLevelSettingsView's recoveryCode; a [UInt8]-backed
    // holder would close that gap but is a separate refactor, not undertaken here).
    @State private var recoveryCode = ""
    @State private var shakeAmount = 0.0
    @State private var dotsError = false
    @State private var processing = false
    /// Set when a chosen PRIVATE tier could not get its Lever B hardware key:
    /// the vault is completed at the honest base tier and we tell the user,
    /// rather than silently finishing as "Private" over a plain key (mirrors
    /// Android's leverBFailedNotice, PinSetupScreen.kt).
    @State private var leverBFailedNotice = false
    /// Set when provisioning returned false because the device key (Keychain)
    /// was transiently unavailable — see AppState.provisionFailedDueToDeviceKey.
    /// Without this the generic failure branch below shakes the dots and resets
    /// to .enterCred with no explanation, and since the device key stays
    /// unavailable until the phone is locked and unlocked again, that repeats
    /// forever on every retry (mirrors Android's deviceKeyBusyNotice,
    /// PinSetupScreen.kt).
    @State private var deviceKeyBusyNotice = false

    private let pinLength = Int(CredentialPolicy.shared.PIN_LENGTH)

    private var usesPassphrase: Bool { level == "maximum" }
    private var usesLeverB: Bool { level == "private" }

    var body: some View {
        Group {
            switch phase {
            case .chooseLevel:
                ProtectionLevelView(
                    hardwareSupported: appState.biometricUnlockAvailable,
                    currentLevel: nil,
                    confirmLabel: L10n.commonContinue,
                    onConfirm: { chosenLevel in level = chosenLevel; phase = .enterCred }
                )
            case .showRecovery:
                RecoveryCodeView(code: recoveryCode, onDone: {
                    // Code acknowledged: commit the prepared auth-bound key + promote to
                    // the chosen (PRIVATE) tier atomically (finalizeLeverB), THEN open the
                    // vault. A finalize failure leaves a working base PIN vault — proceed
                    // either way (re-hardenable from Settings).
                    //
                    // Clear AFTER finalize
                    // settles, not before — clearing first blanked the code on screen
                    // while the async finalize was still in flight. finalizeLeverB
                    // proceeds to unlock() either way (see comment above), so the code
                    // is genuinely no longer needed by the time this runs.
                    appState.finalizeLeverB(level) { _ in
                        recoveryCode = ""
                        appState.unlock(pin: chosenCredential) { _ in chosenCredential = "" }
                    }
                })
                .onDisappear { recoveryCode = "" }
            case .enterCred, .confirmCred:
                if usesPassphrase { passphraseBody } else { pinBody }
            }
        }
        .onChange(of: scenePhase) { newPhase in
            // Gate the reset on a GENUINE background, not the
            // transient .inactive (Control Center pull-down, a notification, Face ID).
            // Firing on .inactive during .showRecovery replaced the one-time
            // recovery-code screen — on an ALREADY-provisioned Lever B vault — with the
            // level chooser, silently invalidating the code the user was copying down.
            // Same .inactive-vs-.background class as the fixed Lever-B re-lock bug.
            if newPhase == .background {
                pin = ""; chosen = ""; phrase = ""; chosenPhrase = ""; chosenCredential = ""
                leverBFailedNotice = false
                deviceKeyBusyNotice = false
                phase = .chooseLevel
            }
        }
        // Device key transiently unavailable mid-provision — see
        // deviceKeyBusyNotice's declaration and provisionAndFinish below. Nothing
        // was written, and dismissing (scrim tap or the button) just returns to
        // .enterCred, already set before this flag went up — so, unlike the
        // Lever-B notice above, a scrim dismissal is safe here.
        .runeDialog(
            isPresented: $deviceKeyBusyNotice,
            title: L10n.pinDeviceKeyBusyTitle,
            message: L10n.pinDeviceKeyBusyMessage,
            a11yId: "device_key_busy_notice",
            actions: [
                RuneDialogAction(L10n.commonOk, a11yId: "device_key_busy_dismiss") {
                    deviceKeyBusyNotice = false
                },
            ]
        )
        // Lever B enable failed at onboarding:
        // the vault is already open at the honest base tier (provisionAndFinish
        // persisted it before attempting the enable) — this just tells the user
        // before handing off into the app. Consent-gated (no scrim dismissal):
        // the "Continue" tap is what actually unlocks into the app, so a
        // scrim-tap dismissal must not silently strand the flow.
        .runeDialog(
            isPresented: $leverBFailedNotice,
            title: L10n.pinHardwareLockNotEnabledTitle,
            message: L10n.pinHardwareLockNotEnabledMessage,
            a11yId: "lever_b_failed_notice",
            dismissable: false,
            actions: [
                RuneDialogAction(L10n.commonContinue, a11yId: "lever_b_failed_continue") {
                    appState.unlock(pin: chosenCredential) { _ in chosenCredential = "" }
                },
            ]
        )
    }

    // MARK: - PIN body (Casual / Private)

    private var pinBody: some View {
        ZStack {
            GeometryReader { geo in
                Image(runestoneAsset("runestone_dim", level: level)).resizable().scaledToFill()
                    .frame(width: geo.size.width, height: geo.size.height).clipped()
            }.ignoresSafeArea()
            Color.black.opacity(0.7).ignoresSafeArea()

            VStack(spacing: 0) {
                Spacer().frame(height: 80)
                Text(phase == .confirmCred ? L10n.pinSetupConfirmPin : L10n.pinSetupChoosePin)
                    .font(.runeBody).foregroundColor(Color.runTextPrimary)
                    .accessibilityIdentifier("pin_prompt")
                Spacer().frame(height: 28)
                PinDots(filled: pin.count, total: pinLength, error: dotsError)
                    .modifier(ShakeModifier(amount: shakeAmount))
                Spacer()
                PinKeypad(
                    onDigit: { digit in
                        guard pin.count < pinLength, !processing else { return }
                        pin += digit
                        if pin.count == pinLength { handlePinComplete() }
                    },
                    onDelete: {
                        guard !pin.isEmpty, !processing else { return }
                        pin.removeLast()
                    }
                )
                Spacer().frame(height: 36)
            }
        }
    }

    private func handlePinComplete() {
        processing = true
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.15) {
            switch phase {
            case .enterCred:
                chosen = pin; pin = ""; phase = .confirmCred; processing = false
            case .confirmCred:
                if pin == chosen {
                    provisionAndFinish(pin)
                } else {
                    triggerError { phase = .enterCred }
                    processing = false
                }
            default:
                processing = false
            }
        }
    }

    // MARK: - Passphrase body (Maximum)

    private var passphraseBody: some View {
        let confirming = phase == .confirmCred
        let canSubmit = confirming ? !phrase.isEmpty : CredentialPolicy.shared.meetsFloor(passphrase: phrase)
        return ZStack {
            Color.runBackground.ignoresSafeArea()
            VStack(spacing: 14) {
                Spacer().frame(height: 40)
                Text(confirming ? L10n.pinSetupConfirmPassphrase : L10n.pinSetupChoosePassphrase)
                    .font(.runeTitle2).fontWeight(.semibold)
                    .foregroundColor(.runTextPrimary)
                    .accessibilityIdentifier("pin_prompt")
                Text(L10n.pinSetupPassphraseHint)
                    .font(.runeFootnote).foregroundColor(.runTextSecondary).multilineTextAlignment(.center)
                PassphraseField(placeholder: confirming ? L10n.pinPassphrasePlaceholderReenter : L10n.pinPassphrasePlaceholder,
                                text: $phrase, identifier: "passphrase_field",
                                disabled: processing, onSubmit: { if canSubmit { submitPassphrase() } })
                if !confirming { PassphraseStrengthMeter(passphrase: phrase) }
                Spacer()
                Button(action: submitPassphrase) {
                    // ONE line, never a mid-word break (2026-09-11): shrink to fit instead.
                    Text(confirming ? L10n.pinConfirmButton : L10n.commonContinue)
                        .lineLimit(1)
                        .minimumScaleFactor(0.5)
                        .fontWeight(.semibold).frame(maxWidth: .infinity).padding()
                        .background(canSubmit && !processing ? Color.runTextPrimary : Color.runSurface)
                        .foregroundColor(canSubmit && !processing ? .runBackground : .runTextSecondary)
                        .clipShape(RoundedRectangle(cornerRadius: 12))
                }
                .disabled(!canSubmit || processing)
                .accessibilityIdentifier("passphrase_continue")
            }
            .padding(.horizontal, 28).padding(.bottom, 24)
        }
    }

    private func submitPassphrase() {
        if phase == .enterCred {
            chosenPhrase = phrase; phrase = ""; phase = .confirmCred
        } else if phrase == chosenPhrase {
            processing = true
            provisionAndFinish(chosenPhrase)
        } else {
            phrase = ""; phase = .enterCred
        }
    }

    // MARK: - Shared provisioning

    private func provisionAndFinish(_ credential: String) {
        chosenCredential = credential
        // Tier atomicity (mirrors Android's
        // honestPersistedLevel in PinSetupScreen.kt): a hardened tier
        // (PRIVATE ⇒ Lever B) is honest ONLY once the auth-bound key actually
        // engages. Provision at the honest BASE the plain key backs — PRIVATE
        // becomes CASUAL, MAXIMUM/CASUAL are unchanged — and advance to the
        // chosen tier only after the Lever B enable below succeeds, so a
        // cancelled biometric or a failed enable can never leave "PRIVATE
        // persisted + plain key". See honestPersistedLevel (ProtectionLevelView.swift).
        let baseLevel = honestPersistedLevel(level, leverBEnabled: false)
        appState.setRealCredentialWithLevel(credential, passphraseMode: usesPassphrase, level: baseLevel) { ok in
            guard ok else {
                // PROVISION-1: `ok == false` covers BOTH a retryable provisioning
                // failure and the provision guard refusing because a vault database
                // is already there. Only the first is worth shaking-and-retrying —
                // retrying against the guard loops forever, so send that user to
                // unlock (which is also where the explicit "Erase and start over"
                // escape hatch lives). Mirrors Android PinSetupScreen.
                if appState.routeToUnlockIfVaultPresent() {
                    pin = ""; chosen = ""; phrase = ""; chosenPhrase = ""
                    chosenCredential = ""
                    processing = false
                    return
                }
                // The device key (Keychain) was transiently unavailable mid-
                // provision — nothing was written, so this is still the pure
                // DEFER it always was, never a tamper/wipe signal. But it does
                // not self-resolve on a bare retry (the key only reloads after a
                // lock/unlock cycle), so the generic silent shake-and-reset below
                // looped this user forever with no explanation. Mirrors Android
                // PinSetupScreen's lastProvisionWasDeviceKeyUnavailable check.
                if appState.provisionFailedDueToDeviceKey() {
                    pin = ""; chosen = ""; phrase = ""; chosenPhrase = ""
                    chosenCredential = ""
                    processing = false
                    deviceKeyBusyNotice = true
                    phase = .enterCred
                    return
                }
                triggerError { phase = .enterCred }
                processing = false
                return
            }
            if usesLeverB {
                // Always attempt — enableLeverBWithRecovery itself reports
                // "unsupported" (no hardware) as a plain failure below, same as
                // a cancelled/failed round-trip, so every non-engaged case lands
                // on the same honest-base + notice path (mirrors Android, which
                // does not gate the attempt on hardware support either).
                appState.enableLeverBWithRecovery(credential) { code in
                    if let code = code {
                        // Two-phase: the strict key is only PREPARED (held; DB
                        // key still plain). Leave the vault at the honest BASE tier it
                        // was provisioned at; promote to the chosen (PRIVATE) tier
                        // atomically only when the user acknowledges the code
                        // (finalizeLeverB, .showRecovery onDone) — never PRIVATE-over-plain.
                        recoveryCode = code
                        pin = ""; chosen = ""; phrase = ""; chosenPhrase = ""
                        processing = false
                        phase = .showRecovery
                    } else {
                        // Lever B failed (cancelled Face ID, unsupported
                        // hardware, or a transient SE error) — the vault stays
                        // honest at baseLevel (already persisted above, plain-
                        // wrapped key). Finish setup only after the user
                        // acknowledges that, via the leverBFailedNotice dialog —
                        // never a silent "Private" over a plain key.
                        pin = ""; chosen = ""; phrase = ""; chosenPhrase = ""
                        processing = false
                        leverBFailedNotice = true
                    }
                }
            } else {
                appState.unlock(pin: credential) { _ in
                    chosenCredential = ""; pin = ""; chosen = ""; phrase = ""; chosenPhrase = ""
                    processing = false
                }
            }
        }
    }

    private func triggerError(then next: @escaping () -> Void) {
        dotsError = true
        withAnimation(.default.repeatCount(3, autoreverses: true)) { shakeAmount = 8 }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
            shakeAmount = 0; dotsError = false
            pin = ""; chosen = ""; phrase = ""; chosenPhrase = ""
            next()
        }
    }
}

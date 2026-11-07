import SwiftUI
import shared

// ---------------------------------------------------------------------------
// ChangeCredentialView — rotate the credential of the currently-unlocked
// vault, optionally switching its MODE (PIN ↔ passphrase, Lever A
// "high-risk mode"). `ChangePinView` remains the same-mode entry
// point used by the settings sheet.
//
// Three steps: enter current credential → choose new → confirm new. The
// current step renders in the CURRENT mode's input (keypad or secure field);
// the new steps render in the TARGET mode's, with the shared entropy floor
// (CredentialPolicy) enforced wherever a NEW passphrase is chosen. The
// current credential authorizes the change — the shared VaultSelector
// verifies it the same way unlock() does. A wrong current credential is
// rejected silently and does NOT count toward the auto-wipe budget (the user
// is already inside); the daily change-PIN abuse cap bounds probing instead.
// ---------------------------------------------------------------------------

/// What the credential should be after the rotation (mirrors Android's
/// CredentialChangeTarget).
enum CredentialChangeTarget {
    case same           // plain rotation, keep the mode
    case toPassphrase   // enable high-risk mode
    case toPin          // disable high-risk mode (warn before entering)
}

private enum ChangeStep {
    case enterCurrent, chooseNew, confirmNew
}

/// Back-compat entry point for the settings sheet's same-mode rotation.
struct ChangePinView: View {
    let onDone:   () -> Void
    let onCancel: () -> Void
    var body: some View {
        ChangeCredentialView(target: .same, onDone: onDone, onCancel: onCancel)
    }
}

struct ChangeCredentialView: View {
    @EnvironmentObject private var appState: AppState
    @Environment(\.scenePhase) private var scenePhase
    let target: CredentialChangeTarget
    let onDone:   () -> Void
    let onCancel: () -> Void
    // Invoked with the freshly-set plaintext credential on a successful rotation,
    // immediately BEFORE onDone — lets the Settings level-change chain a Lever B
    // recovery-enable that needs the final credential. Optional (mirrors Android).
    var onCredentialSet: ((String) -> Void)? = nil
    /// Parity (mirrors Android `ChangeCredentialScreen`'s
    /// `cancellable`): `false` hides Cancel entirely. The one caller that passes
    /// `false` is the FORCED protection migration (`ProtectionLevelSettingsView`
    /// with `forced = true`), where this view IS the gate a passcode-less device
    /// is held to — the vault's only remaining factor is the credential, so one
    /// Cancel tap here left the phone on a ~20-bit PIN. Not a trap: iOS has no
    /// back gesture on this screen, the gate is a plain conditional branch in
    /// `ContentView` that re-evaluates the policy, and the chooser behind it
    /// carries the "set a device passcode" escape. Every other caller keeps its
    /// Cancel, with the `change_pin_cancel` identifier unchanged.
    var cancellable: Bool = true

    @State private var step: ChangeStep = .enterCurrent
    @State private var pin = ""            // keypad buffer (PIN steps)
    @State private var phrase = ""         // secure-field buffer (passphrase steps)
    @State private var currentCredential = ""
    @State private var newCredential = ""
    @State private var shakeAmount = 0.0
    @State private var dotsError = false
    @State private var processing = false
    @State private var currentIsPassphrase = false

    private let pinLength = Int(CredentialPolicy.shared.PIN_LENGTH)  // B6a: single-sourced

    private var newIsPassphrase: Bool {
        switch target {
        case .same:         return currentIsPassphrase
        case .toPassphrase: return true
        case .toPin:        return false
        }
    }

    private var stepIsPassphrase: Bool {
        step == .enterCurrent ? currentIsPassphrase : newIsPassphrase
    }

    private var prompt: String {
        switch step {
        case .enterCurrent: return currentIsPassphrase ? L10n.pinChangeEnterCurrentPassphrase : L10n.pinChangeEnterCurrentPin
        case .chooseNew:    return newIsPassphrase ? L10n.pinSetupChoosePassphrase : L10n.pinChangeChooseNewPin
        case .confirmNew:   return newIsPassphrase ? L10n.pinChangeConfirmPassphrase : L10n.pinChangeConfirmNewPin
        }
    }

    var body: some View {
        ZStack {
            GeometryReader { geo in
                Image(runestoneAsset("runestone_dim", level: appState.controller.displayProtectionLevel()))
                    .resizable()
                    .scaledToFill()
                    .frame(width: geo.size.width, height: geo.size.height)
                    .clipped()
            }
            .ignoresSafeArea()

            Color.black.opacity(0.7)
                .ignoresSafeArea()

            VStack(spacing: 0) {
                HStack {
                    // NOT RENDERED on the forced protection migration:
                    // there this view is the gate itself. Deliberately absent
                    // rather than disabled-but-present, so nothing carries the
                    // `change_pin_cancel` identifier that a test (or a user)
                    // could take for a live escape. The row then collapses to
                    // its padding, exactly as Android's does.
                    if cancellable {
                        Button(L10n.commonCancel) { if !processing { onCancel() } }
                            .foregroundColor(Color.runTextSecondary)
                            .accessibilityIdentifier("change_pin_cancel")
                    }
                    Spacer()
                }
                .padding(.horizontal, 24)
                .padding(.top, 16)

                Spacer().frame(height: 48)

                Text(prompt)
                    .font(.runeBody)
                    .foregroundColor(Color.runTextPrimary)
                    .accessibilityIdentifier("pin_prompt")

                Spacer().frame(height: 28)

                if stepIsPassphrase {
                    PassphraseField(
                        placeholder: L10n.pinPassphrasePlaceholder,
                        text: $phrase,
                        identifier: "passphrase_field",
                        disabled: processing
                    )
                    .modifier(ShakeModifier(amount: shakeAmount))
                    .overlay(
                        RoundedRectangle(cornerRadius: 10)
                            .stroke(dotsError ? Color.runError : Color.clear, lineWidth: 1)
                    )
                    .padding(.horizontal, 32)

                    // Meter + enforced floor only where a NEW passphrase is
                    // chosen; verify/confirm steps take what was typed.
                    if step == .chooseNew {
                        Spacer().frame(height: 16)
                        PassphraseStrengthMeter(passphrase: phrase)
                    }

                    Spacer().frame(height: 20)

                    let floorOk = step != .chooseNew ||
                        CredentialPolicy.shared.meetsFloor(passphrase: phrase)
                    Button(action: { submitPhrase() }) {
                        Text(L10n.commonContinue)
                            .foregroundColor(phrase.isEmpty || !floorOk || processing
                                             ? Color.runTextSecondary : Color.runTextPrimary)
                    }
                    .disabled(phrase.isEmpty || !floorOk || processing)
                    .accessibilityIdentifier("credential_continue")

                    Spacer()
                } else {
                    PinDots(filled: pin.count, total: pinLength, error: dotsError)
                        .modifier(ShakeModifier(amount: shakeAmount))

                    Spacer()

                    PinKeypad(
                        onDigit: { digit in
                            guard pin.count < pinLength, !processing else { return }
                            pin += digit
                            if pin.count == pinLength { handleComplete(submitted: pin) }
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
        .onAppear { currentIsPassphrase = appState.controller.isPassphraseMode() }
        .onChange(of: scenePhase) { phase in
            // Clear all plaintext credential buffers on leaving
            // the foreground so a live-memory capture of a seized device can't recover
            // the current/new PIN or passphrase from the heap.
            if phase != .active { pin = ""; phrase = ""; currentCredential = ""; newCredential = "" }
        }
    }

    private func submitPhrase() {
        guard !phrase.isEmpty, !processing else { return }
        handleComplete(submitted: phrase)
    }

    private func handleComplete(submitted: String) {
        processing = true
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.15) {
            switch step {
            case .enterCurrent:
                // verifyCurrentPin records the daily change-PIN abuse counter
                // before checking — bounds credential probing via this flow.
                appState.verifyCurrentPin(submitted) { ok in
                    if ok {
                        currentCredential = submitted
                        pin = ""; phrase = ""
                        step = .chooseNew
                        processing = false
                    } else {
                        triggerError { step = .enterCurrent }
                        processing = false
                    }
                }
            case .chooseNew:
                newCredential = submitted
                pin = ""; phrase = ""
                step = .confirmNew
                processing = false
            case .confirmNew:
                if submitted == newCredential {
                    let completion: (ChangePinOutcome) -> Void = { outcome in
                        switch outcome {
                        case .success:
                            let cred = newCredential
                            currentCredential = ""; newCredential = ""
                            pin = ""; phrase = ""
                            onCredentialSet?(cred)
                            onDone()
                            // `processing` stays true: the view can remain mounted
                            // after onDone (the Settings level-change keeps showing
                            // it while chaining the Lever B enable). Re-enabled
                            // input here re-presents "Confirm new PIN" and feeds
                            // anything typed into this stale confirm step against a
                            // cleared newCredential — a second rotation racing the
                            // enable.
                            return
                        case .wrongCurrent:
                            // Shouldn't happen (current was verified) — restart.
                            currentCredential = ""; newCredential = ""
                            triggerError { step = .enterCurrent }
                        }
                        processing = false
                    }
                    if target == .same {
                        appState.changePin(current: currentCredential, new: newCredential,
                                           completion: completion)
                    } else {
                        appState.changeCredentialAndMode(current: currentCredential,
                                                         new: newCredential,
                                                         passphraseMode: newIsPassphrase,
                                                         completion: completion)
                    }
                } else {
                    triggerError { step = .chooseNew }
                    processing = false
                }
            }
        }
    }

    private func triggerError(then next: @escaping () -> Void) {
        dotsError = true
        withAnimation(.default.repeatCount(3, autoreverses: true)) {
            shakeAmount = 8
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
            shakeAmount = 0; dotsError = false
            pin = ""; phrase = ""
            next()
        }
    }
}

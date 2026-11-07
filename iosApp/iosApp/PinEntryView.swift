import SwiftUI
import UIKit
import shared

// ---------------------------------------------------------------------------
// PinEntryView — PIN unlock screen.
//
// Security:
//   • "Rún" title in serif font at top.
//   • Shake animation + exponential backoff on wrong PIN.
//   • Emergency wipe after 5 failed attempts (all vault data destroyed).
//   • Blank black screen after wipe — indistinguishable from powered off.
//   • Runestone background with dark overlay.
// ---------------------------------------------------------------------------

// Wrong-tries wipe threshold is now PER-LEVEL (threat-level slider) — see the
// `maxAttempts` computed property inside PinEntryView. pinLength stays constant,
// single-sourced from commonMain CredentialPolicy so Android + iOS agree.
private let pinLength   = Int(CredentialPolicy.shared.PIN_LENGTH)

struct PinEntryView: View {
    @EnvironmentObject private var appState: AppState
    @Environment(\.scenePhase) private var scenePhase

    // Per-level wrong-tries wipe threshold (threat-level slider); a legacy vault
    // with no chosen level falls back to the current CredentialPolicy default.
    private var maxAttempts: Int { Int(appState.controller.maxConsecutiveAttempts()) }

    // Threshold for the LAUNCH-TIME interrupted-wipe re-trigger in readAttempts()
    // — NOT for a new attempt. `maxAttempts` is allowed to shrink retroactively
    // (an unauthenticated tier or a damaged blob falls to MAXIMUM's 5), and
    // firing the entry-time wipe on a counter accumulated under the OLD, larger
    // budget destroys a vault whose owner entered nothing wrong — a legacy
    // cleartext CASUAL vault stranded at 5–9 failures would go up on the first
    // launch after the upgrade. This falls back to the most lenient tier's budget
    // wherever the read can't prove the budget didn't shrink, so it can only ever
    // DELAY the re-trigger. Shared decision with Android
    // (PinEntryScreen.interruptedWipeAttempts).
    private var interruptedWipeAttempts: Int {
        Int(appState.controller.vaultSelector.maxConsecutiveAttemptsForInterruptedWipe())
    }

    // High-risk mode (Lever A): a passphrase credential renders
    // a secure text field instead of the 6-digit keypad. Evaluation, attempt
    // counting, backoff and wipe logic are IDENTICAL for both — the credential
    // is just a string to the shared VaultSelector. Read once per appearance;
    // the view is recreated on every lock so mode changes are always seen.
    @State private var passphraseMode = false

    @State private var pin         = ""
    @State private var failedCount = 0
    @State private var isWiped     = false
    @State private var shakeAmount = 0.0
    @State private var dotsError   = false
    @State private var processing  = false
    // Wrong-attempt backoff gate, seeded in onAppear from the DURABLE count so a
    // force-quit + relaunch re-serves the wait. Monotonic clock, nothing persisted.
    // Android sibling: UnlockBackoff.kt / PinEntryScreen `backoff`.
    @State private var backoff = UnlockBackoffGate()
    private let backoffTick = Timer.publish(every: 0.25, on: .main, in: .common).autoconnect()
    // Set when readAttempts() could not read the durable count because
    // the device key was transiently unavailable (failedCount then reflects 0, not
    // the real durable value). While deferred, the pre-evaluation persist is
    // SKIPPED so a transient-key window can't overwrite a real count of e.g. 4
    // with 1 (mirrors Android PinEntryScreen.counterDeferred).
    @State private var counterDeferred = false
    // Lever B recovery escape hatch — only offered when a recovery code exists.
    @State private var showRecovery = false
    /// Latched once an unlock returns `.recoveryRequired` — correct credential,
    /// permanently invalidated Secure Enclave key, so only the recovery code works.
    @State private var permanentKeyLoss = false
    /// A vault file with no credential stored for it — see the notice in the
    /// bottom overlay. Set once in onAppear, never re-evaluated mid-session.
    @State private var orphanedVault = false
    @State private var confirmErase = false

    var body: some View {
        ZStack {
            if isWiped {
                // Blank screen after wipe — indistinguishable from normal lock.
                Color.black.ignoresSafeArea()
            } else {
                // Runestone background — dim art matching the protection level
                // (the level marker is device-key readable pre-unlock).
                GeometryReader { geo in
                    Image(runestoneAsset("runestone_dim", level: appState.controller.displayProtectionLevel()))
                        .resizable()
                        .scaledToFill()
                        .frame(width: geo.size.width, height: geo.size.height)
                        .clipped()
                }
                .ignoresSafeArea()

                // Dark overlay for readability
                Color.black.opacity(0.7)
                    .ignoresSafeArea()

                if passphraseMode {
                    VStack(spacing: 0) {
                        Spacer().frame(height: 120)

                        Text(L10n.pinPromptPassphrase)
                            .font(.runeBody)
                            .foregroundColor(Color.runTextPrimary)
                            .accessibilityIdentifier("pin_prompt")

                        Spacer().frame(height: 24)

                        PassphraseField(
                            placeholder: L10n.pinPassphrasePlaceholder,
                            text: $pin,
                            identifier: "passphrase_field",
                            disabled: processing || backoff.active,
                            onSubmit: { submitPassphrase() }
                        )
                        .modifier(ShakeModifier(amount: shakeAmount))
                        .overlay(
                            RoundedRectangle(cornerRadius: 10)
                                .stroke(dotsError ? Color.runError : Color.clear, lineWidth: 1)
                        )
                        .padding(.horizontal, 32)

                        Spacer().frame(height: 20)

                        Button(action: { submitPassphrase() }) {
                            Text(L10n.pinUnlockButton)
                                .foregroundColor(pin.isEmpty || processing || backoff.active ? Color.runTextSecondary : Color.runTextPrimary)
                        }
                        .disabled(pin.isEmpty || processing || backoff.active)
                        .accessibilityIdentifier("unlock_button")

                        Spacer()
                    }
                } else {
                    VStack(spacing: 0) {
                        Spacer()

                        PinDots(filled: pin.count, total: pinLength, error: dotsError)
                            .modifier(ShakeModifier(amount: shakeAmount))

                        Spacer()

                        PinKeypad(
                            onDigit: { digit in
                                guard pin.count < pinLength, !processing, !backoff.active else { return }
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
        }
        .overlay(alignment: .bottom) { unlockFooterNotices }
        // Named consequence, not an implied one: this is the single place the app
        // deletes a vault on a plain tap, so the alert says "permanently".
        .alert(L10n.pinEraseVaultTitle, isPresented: $confirmErase) {
            Button(L10n.commonCancel, role: .cancel) { }
                .accessibilityIdentifier("erase_orphaned_vault_cancel")
            Button(L10n.pinEraseVaultConfirm, role: .destructive) {
                LogBuffer.shared.append(level: "W", tag: "Vault",
                                        message: "user erased an orphaned vault from the unlock screen")
                appState.eraseOrphanedVault()
            }
            .accessibilityIdentifier("erase_orphaned_vault_confirm")
        } message: {
            Text(L10n.pinEraseVaultMessage)
        }
        .fullScreenCover(isPresented: $showRecovery) {
            RecoveryEntryView(
                onRecovered: { showRecovery = false },
                onCancel: { showRecovery = false }
            )
            .environmentObject(appState)
            // Covers don't reliably inherit the root's forced dark scheme.
            .preferredColorScheme(.dark)
        }
        .onAppear {
            passphraseMode = appState.controller.isPassphraseMode()
            failedCount = readAttempts()
            if !isWiped {
                backoff.start(ms: CredentialPolicy.shared.launchBackoffMs(persistedFailedAttempts: Int32(failedCount)))
            }
            // Computed once on entry, and only with protected data available —
            // the same gate the launch security checks use. A locked-storage read
            // makes the credential look absent for a perfectly healthy vault, and
            // offering an erase button there would recreate the data loss the
            // provision guard just closed.
            orphanedVault = UIApplication.shared.isProtectedDataAvailable
                && appState.controller.orphanedVaultFile()
        }
        .onReceive(backoffTick) { _ in
            if backoff.active { backoff.refresh() }
        }
        .onChange(of: scenePhase) { phase in
            // Drop the entered credential (PIN or passphrase —
            // `pin` holds both) the moment we leave the foreground, so a live-memory
            // capture of a backgrounded/seized device can't recover it from the heap.
            if phase != .active { pin = "" }
        }
    }

    /// The notices and escape hatches pinned to the bottom of the unlock screen:
    /// backoff hint, permanent-key-loss notice, recovery-code entry, orphaned-vault erase.
    private var unlockFooterNotices: some View {
        VStack(spacing: 8) {
            if backoff.active && !isWiped {
                Text(L10n.pinBackoffHint(backoff.secondsLeft))
                    .font(.runeFootnote)
                    .foregroundColor(.runTextSecondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 32)
                    .accessibilityIdentifier("pin_backoff_hint")
            }
            // The credential was right but the Secure Enclave key is gone for
            // good. Say so — the old behaviour reported a generic transient error,
            // leaving the user to retry a correct PIN forever with no hint that
            // the recovery code is the only way back in.
            if permanentKeyLoss && !isWiped {
                Text(appState.hasRecoveryCode
                     ? L10n.pinPermanentKeyLossPasscodeHasRecovery
                     : L10n.pinPermanentKeyLossPasscodeNoRecovery)
                    .font(.runeFootnote)
                    .foregroundColor(.runTextSecondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 32)
                    .accessibilityIdentifier("permanent_key_loss_notice")
            }
            if appState.hasRecoveryCode && !isWiped {
                Button(permanentKeyLoss ? L10n.pinUseRecoveryCode : L10n.pinUseRecoveryCodePrompt) {
                    showRecovery = true
                }
                .font(.runeFootnote)
                .foregroundColor(.runTextSecondary)
                .accessibilityIdentifier("use_recovery_code_button")
            }
            // Dead-end escape hatch: a vault FILE with no credential stored for
            // it. The provision guard sends this user to unlock rather than
            // letting setup destroy the file, so this screen owes them a way
            // out — otherwise the app is a prompt that rejects every entry
            // forever. See VaultSelector.orphanedVaultFile for why this cannot
            // appear for a merely-unreadable store.
            if orphanedVault && !isWiped {
                Text(L10n.pinOrphanedVaultNotice)
                    .font(.runeFootnote)
                    .foregroundColor(.runTextSecondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 32)
                    .accessibilityIdentifier("orphaned_vault_notice")
                Button(L10n.pinEraseStartOver) { confirmErase = true }
                    .font(.runeFootnote)
                    .foregroundColor(.runeDanger)
                    .accessibilityIdentifier("erase_orphaned_vault_button")
            }
        }
        .padding(.bottom, 28)
    }

    private func submitPassphrase() {
        guard !pin.isEmpty, !processing, !backoff.active else { return }
        handlePinComplete()
    }

    /// Reads the encrypted attempts counter. The PinEntryView is shown
    /// after lock() has wiped the CryptoProvider's in-memory key, so we
    /// must reload it before any decrypt — otherwise read() throws
    /// "key has been wiped" and the catch below would treat it as AEAD
    /// tampering and wipe all user data.
    ///
    /// The attempt counter is encrypted with the unlocked-device-required
    /// key. While the device is locked that key is unreadable; reading then
    /// and treating the failure as tamper would wipe the vault. Defer
    /// instead.
    private func readAttempts() -> Int {
        counterDeferred = false
        guard UIApplication.shared.isProtectedDataAvailable else { counterDeferred = true; return 0 }
        appState.controller.reloadCryptoIfWiped()
        let persisted: Int
        do {
            // readOrNullOnTamper splits the two failure modes at the Kotlin
            // boundary so a bare Swift catch can no
            // longer conflate them:
            //   • throws  → device key transiently unavailable → DEFER, never wipe
            //   • returns nil → genuine AEAD tamper / key rotation → wipe
            guard let count = try appState.controller.pinAttempts.readOrNullOnTamper() else {
                LogBuffer.shared.append(level: "E", tag: "PinEntryView", message: "pin-attempts ciphertext failed AEAD verification — wiping")
                wipeDiag("PinEntryView.readOrNullOnTamper==nil (AEAD tamper / key rotation)")
                appState.emergencyWipe()
                isWiped = true
                return 0
            }
            persisted = count.intValue
        } catch {
            // KeyUnavailableException — the device key was transiently unresolvable
            // (locked keybag / errSecAuthFailed), even on an unlocked device. This
            // is NOT tamper: DEFER without wiping. The durable count is intact and
            // re-read once the key is available.
            LogBuffer.shared.append(level: "W", tag: "PinEntryView", message: "pin-attempts key unavailable (transient) — deferring, not wiping")
            counterDeferred = true
            return 0
        }
        // A persisted count already at the budget means a previous wipe
        // was interrupted (force-quit after the pre-evaluation write but before the
        // wipe finished). Re-trigger the wipe and never show the keypad — closes
        // the force-quit-mid-wipe brute-force loop. Compared against
        // `interruptedWipeAttempts`, never `maxAttempts`: the counter was
        // accumulated under whatever budget was in force AT THE TIME, so a budget
        // that shrank since must not condemn it retroactively. Identical
        // rule and identical shared source as Android PinEntryScreen.
        if persisted >= interruptedWipeAttempts {
            wipeDiag("PinEntryView.persisted>=maxAttempts at launch (interrupted-wipe retrigger)")
            appState.emergencyWipe()
            isWiped = true
            return persisted
        }
        // Also re-check the 24h wrong-PIN WINDOW cap at launch —
        // parity with Android. The 1-correct/4-wrong evasion keeps the
        // consecutive counter low, so a force-quit that stranded an already-maxed
        // window (count == MAX_WRONG_PER_DAY, written durably BEFORE the wipe) would
        // otherwise grant a free guess on relaunch. Defer on a transient key error
        // exactly like the consecutive-counter read above (never wipe on transient).
        do {
            if try appState.controller.pinAttempts.windowLimitReached() {
                LogBuffer.shared.append(level: "W", tag: "PinEntryView", message: "wrong-PIN 24h window cap already reached at launch — wiping")
                wipeDiag("PinEntryView.windowLimitReached at launch")
                appState.emergencyWipe()
                isWiped = true
            }
        } catch {
            LogBuffer.shared.append(level: "W", tag: "PinEntryView", message: "window-cap launch check: key unavailable (transient) — deferring, not wiping")
        }
        return persisted
    }

    private func resetAttempts() {
        appState.controller.pinAttempts.reset()
    }

    private func handlePinComplete() {
        processing = true
        Task { @MainActor in
            // Brief pause so the 6th PIN dot paints before evaluation.
            try? await Task.sleep(nanoseconds: 150_000_000)

            // Re-read the durable
            // counter FRESH here instead of trusting the onAppear-cached
            // failedCount. RecoveryEntryView shares this exact durable store
            // (appState.controller.pinAttempts) and can advance it while this
            // screen sits underneath its presented fullScreenCover — dismissing
            // that cover does NOT re-fire this view's onAppear, so the cached
            // value would go stale and an absolute tryWrite below would roll
            // the durable counter back down. readAttempts() re-runs the same
            // tamper-vs-transient distinction as the initial onAppear call
            // (nil → genuine AEAD tamper → wipe; throws → transient key
            // unavailable → defer, never wipe) and re-checks the launch-time
            // invariants (interrupted-wipe retrigger, 24h window cap); both are
            // idempotent to repeat and closes exactly the gap the stale cache
            // opened. If it just wiped (tamper or an already-exhausted budget
            // advanced by the recovery screen), stop here — there is nothing
            // left to evaluate.
            failedCount = readAttempts()
            guard !isWiped else { processing = false; return }

            // Persist the incremented counter *before* evaluating the
            // PIN. unlock() runs PBKDF2 off-thread (CR-1); writing after would
            // let an attacker force-quit during evaluation so the attempt is
            // never recorded — unlimited brute force. The write is durable
            // (synchronize()) and completes before unlock dispatches its PBKDF2.
            let attempt = failedCount + 1
            failedCount = attempt
            let enteredPin = pin
            // Skip the durable pre-eval write while counterDeferred —
            // failedCount is 0-based (the real durable count couldn't be read), so
            // writing it would roll a genuine count of e.g. 4 back to 1. unlock()
            // needs the same key, so it fails closed this session anyway and the
            // count is re-read once the key returns. tryWrite (best-effort) also
            // avoids a KeyUnavailableException → SIGABRT across the non-@Throws
            // boundary if the key drops between read and here. Mirrors Android.
            if !counterDeferred {
                _ = appState.controller.pinAttempts.tryWrite(count: Int32(attempt))
            }

            // unlock() runs PBKDF2 off the main thread; its completion is
            // delivered back on the main actor.
            appState.unlock(pin: enteredPin) { outcome in
                switch outcome {
                case .opened:
                    // Correct PIN within budget (incl. the MAX-th attempt) —
                    // clear the counter and open.
                    resetAttempts()
                    processing = false

                case .error:
                    // Transient failure to OPEN the matched vault (corrupt/locked
                    // SQLCipher file or sidecar, I/O) — the credential was
                    // CORRECT, so this is NOT a wrong-PIN attempt. Roll back the
                    // durable increment written above (so transient I/O can't
                    // drift the counter toward the launch-time wipe) and let the
                    // user retry; never count it toward either budget, never wipe.
                    // Mirrors Android's UnlockResult.Error branch.
                    let rolledBack = attempt - 1
                    failedCount = rolledBack
                    // Best-effort: .error can now be caused by device-key
                    // unavailability in which case this rollback
                    // write cannot encrypt. tryWrite skips it rather than raising
                    // KeyUnavailableException across the non-@Throws boundary
                    // (SIGABRT). The durable count keeps its prior value; a stale
                    // increment is re-evaluated on next launch by readAttempts().
                    // Guard on counterDeferred exactly like the
                    // pre-eval write at :155. When deferred, the pre-eval increment
                    // was SKIPPED, so there is nothing to roll back — writing
                    // `rolledBack` (0 when the durable count couldn't be read) would
                    // CLOBBER a genuine durable count (e.g. 4→0) if the key became
                    // available during the unlock() window and resolved to .error.
                    if !counterDeferred {
                        _ = appState.controller.pinAttempts.tryWrite(count: Int32(rolledBack))
                    }
                    dotsError = true
                    withAnimation(.default.repeatCount(3, autoreverses: true)) {
                        shakeAmount = 8
                    }
                    Task { @MainActor in
                        try? await Task.sleep(nanoseconds: 500_000_000)
                        shakeAmount = 0; dotsError = false; pin = ""; processing = false
                    }

                case .recoveryRequired:
                    // The PIN was CORRECT but the Secure Enclave key wrapping the
                    // DB key is permanently gone (the device passcode was removed).
                    // Roll the counter back exactly like .error — a right PIN must
                    // never burn budget — but latch a message instead of inviting
                    // another identical attempt that can never succeed.
                    let rolledBack = attempt - 1
                    failedCount = rolledBack
                    if !counterDeferred {
                        _ = appState.controller.pinAttempts.tryWrite(count: Int32(rolledBack))
                    }
                    permanentKeyLoss = true
                    pin = ""
                    processing = false

                case .denied:
                    // A successful unlock resets the 5-consecutive
                    // budget, so also enforce a rolling-24h cap on total wrong
                    // entries that no unlock can reset. Either cap trips the
                    // wipe.
                    let windowExhausted = appState.controller.pinAttempts.recordWrongAttemptInWindowAndCheckLimit()
                    if attempt >= maxAttempts || windowExhausted {
                        wipeDiag("PinEntryView.wrong-PIN budget exhausted (attempt=\(attempt) windowExhausted=\(windowExhausted))")
                        // Budget exhausted. Counter is already durably at >= MAX,
                        // so an interrupted wipe is re-triggered by readAttempts()
                        // on next launch.
                        appState.emergencyWipe()
                        isWiped = true
                        processing = false
                        return
                    }
                    dotsError = true
                    withAnimation(.default.repeatCount(3, autoreverses: true)) {
                        shakeAmount = 8
                    }
                    // B6a: exponential backoff single-sourced from commonMain (ms → s).
                    let backoffMs = CredentialPolicy.shared.unlockBackoffMs(failedAttempts: Int32(attempt))
                    backoff.start(ms: backoffMs)
                    let backoffSeconds = Double(backoffMs) / 1000.0
                    Task { @MainActor in
                        try? await Task.sleep(nanoseconds: UInt64(backoffSeconds * 1_000_000_000))
                        shakeAmount = 0; dotsError = false; pin = ""; processing = false
                    }
                }
            }
        }
    }
}

/// Monotonic wrong-credential backoff gate (ProcessInfo.systemUptime), shared by the
/// lock screen and the recovery-code screen. The wait comes from the DURABLE failed
/// count (CredentialPolicy.launchBackoffMs) and is re-applied every time the screen
/// opens; no wall-clock timestamp is persisted, so a clock change can neither skip
/// nor stretch it. Android sibling: UnlockBackoff.kt.
struct UnlockBackoffGate {
    private var until: TimeInterval = 0
    private(set) var secondsLeft = 0
    var active: Bool { secondsLeft > 0 }

    /// Start (or extend, never shorten) a wait of `ms` from now.
    mutating func start(ms: Int64) {
        until = max(until, ProcessInfo.processInfo.systemUptime + Double(ms) / 1000.0)
        refresh()
    }

    mutating func refresh() {
        let remainingMs = Int64(max(0, (until - ProcessInfo.processInfo.systemUptime) * 1000))
        secondsLeft = Int(CredentialPolicy.shared.backoffSecondsLeft(remainingMs: remainingMs))
    }
}

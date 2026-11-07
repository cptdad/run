import SwiftUI
import UIKit
import CoreImage.CIFilterBuiltins
import shared

// ---------------------------------------------------------------------------
// MoveToNewDeviceView — the OLD phone's half of "Move to new device"
// (docs/device-move.md; read it before changing anything here).
//
// Two entry points, one view:
//   1. Settings → "Move to new device" (`move_to_new_device_button`) presents this
//      as a fullScreenCover with `onClose` set. The explain page runs first.
//   2. ContentView renders it as the ROOT, with `onClose == nil`, on EVERY unlock
//      while the vault carries `mig_frozen` (AppState.isMoveFrozen). The contact
//      list is unreachable in that state by construction — this IS the frozen
//      screen, so the explain page is skipped and the state view shows directly.
//
// The state machine itself lives in commonMain (MoveManager); this view only
// renders `IosAppController.moveExportStateKind()` and drives the four operations.
// Nothing here decides anything security-relevant:
//   • the vault is frozen by MoveManager BEFORE anything is uploaded, so closing
//     this screen (or the app dying) never leaves a half-moved phone that still
//     polls — the commonMain freeze gate in createSessionManagers holds regardless;
//   • `Moved` is a HINT, not proof. The relay answers 404 both when the new phone
//     drained the bundle AND when the 30-minute transfer TTL simply expired, so the
//     copy sends the user to the NEW phone to confirm their contacts are there
//     before the irreversible wipe, and "Keep it off" stays available forever;
//   • the wipe is local and user-confirmed — never relay-triggered.
//
// The one-time code lives ONLY in the Kotlin `Ready` state and in this view's
// `handleText` while it is on screen. `.background` (never `.inactive` — the
// Lever-B re-lock lesson) drops both: ContentView's background handler locks the
// vault, AppState.lock() calls `moveScrubExportCode()`, and `.onChange(of:
// scenePhase)` below clears the local copy.
// ---------------------------------------------------------------------------

struct MoveToNewDeviceView: View {
    @EnvironmentObject private var appState: AppState
    @Environment(\.scenePhase) private var scenePhase

    /// nil ⇒ this is the unlock-time frozen screen: there is nowhere to go back to.
    let onClose: (() -> Void)?

    /// Explicit (rather than memberwise): every other stored property here is a
    /// `private` property wrapper, and this keeps the initializer's access level
    /// unambiguous for the two call sites in ContentView / ContactListView.
    init(onClose: (() -> Void)? = nil) {
        self.onClose = onClose
    }

    /// The explain page is the only thing before `beginExport`. Skipped entirely on
    /// an already-frozen vault (entry point 2, and a re-open of entry point 1 after
    /// the export already started).
    @State private var pastExplain = false
    /// Between the explainer and the export sits a fresh
    /// credential check (see `credentialBody`); Kotlin refuses the export without it.
    @State private var askingCredential = false
    @State private var credPin = ""
    @State private var credPhrase = ""
    @State private var credVerifying = false
    @State private var credError = false
    @State private var credShake = 0.0
    @State private var credIsPassphrase = false
    /// The credential prompt was opened by "Show again" / "Retry" (a RE-ISSUE),
    /// not by the explainer's Continue: on "ok" it re-issues instead of beginning
    /// a first export. A re-issue mints a fresh one-time code for the WHOLE vault,
    /// so it passes the SAME fresh-credential gate as the first export (Android
    /// sibling: MoveToNewDeviceScreen's re-issue prompt).
    @State private var credForReissue = false
    /// Set by "Keep it off" — a terminal, non-destructive resting state that still
    /// offers the wipe. Local only; the durable state is `mig_frozen` in the vault.
    @State private var keptOff = false
    @State private var showHandleText = false
    @State private var copied = false
    /// An operation is in flight — suppresses the 10 s peek and double taps (the
    /// manager also refuses re-entry on its own, this just keeps the UI honest).
    @State private var busy = false

    // Mirror of the Kotlin export state, refreshed by the tick below. Kotlin sealed
    // classes deliberately do NOT cross the bridge — IosAppController projects them
    // into these plain values (moveExportStateKind/Step/HandleText/ErrorName).
    @State private var kind = "idle"
    @State private var step = ""
    @State private var handleText = ""
    @State private var errorName = ""

    /// Result of a refused cancel — the two cases are NOT the same and must not
    /// share one generic error (see the dialog below).
    private enum CancelRefusal { case alreadyPickedUp, couldNotConfirm }
    @State private var cancelRefusal: CancelRefusal? = nil
    /// A cancel that came back "already picked up" also proves the bundle is gone:
    /// hide the cancel affordance rather than leave a button that can only fail.
    @State private var cancelUnavailable = false

    /// One timer drives everything: a cheap state re-read every 0.5 s, and the
    /// `peek` of the transfer inbox every 20th tick (10 s, per docs/device-move.md
    /// Protocol 2e). @State so the publisher survives the frequent struct re-inits
    /// any AppState @Published change causes (the lesson from ContentView).
    @State private var tick = Timer.publish(every: 0.5, on: .main, in: .common).autoconnect()
    @State private var ticksSincePeek = 0

    private static let peekEveryTicks = 20   // 20 × 0.5 s = 10 s

    var body: some View {
        ZStack {
            Color.runBackground.ignoresSafeArea()
            VStack(spacing: 0) {
                header
                ScrollView {
                    VStack(spacing: 18) {
                        // The credential gate first: before the first export (from
                        // the explainer) AND before every re-issue (requestReissue).
                        if askingCredential {
                            credentialBody
                        } else if !pastExplain {
                            explainBody
                        } else if keptOff {
                            keptOffBody
                        } else {
                            stateBody
                        }
                    }
                    .padding(.horizontal, 24)
                    .padding(.bottom, 32)
                }
            }
        }
        .onAppear {
            // An already-frozen vault has passed the explain page by definition —
            // whether we got here from the settings row or as the frozen root.
            if appState.isMoveFrozen { pastExplain = true }
            syncState()
        }
        .onReceive(tick) { _ in
            syncState()
            guard kind == "ready", !busy else { return }
            ticksSincePeek += 1
            if ticksSincePeek >= Self.peekEveryTicks {
                ticksSincePeek = 0
                peekTransfer()
            }
        }
        .onChange(of: scenePhase) { newPhase in
            // `.background` ONLY — never the transient `.inactive` (Face ID, Control
            // Center, a call banner). The documented re-lock bug this rule exists for
            // is the same class of mistake here: a Face-ID prompt must not wipe the
            // code off a screen the user is mid-way through reading to another phone.
            // AppState.lock() (driven from ContentView's own `.background` handler)
            // scrubs the Kotlin side; this drops the local copy.
            if newPhase == .background {
                clearCredentialEntry()
                handleText = ""
                showHandleText = false
                copied = false
            }
        }
        // Refused cancel. Titled on purpose: a title-less RuneDialog flattens its
        // button ids out of the a11y tree (known iOS-26 gotcha).
        .runeDialog(
            isPresented: Binding(get: { cancelRefusal != nil }, set: { if !$0 { cancelRefusal = nil } }),
            title: L10n.moveMenuItem,
            message: cancelRefusal == .alreadyPickedUp ? L10n.moveCancelRefused : L10n.moveCancelUnconfirmed,
            a11yId: "move_cancel_refused",
            actions: [
                RuneDialogAction(L10n.commonOk, a11yId: "move_cancel_refused_ok") { cancelRefusal = nil },
            ]
        )
    }

    // MARK: - Header

    @ViewBuilder
    private var header: some View {
        HStack {
            Text(L10n.moveMenuItem)
                .font(.runeTitle3)
                .foregroundColor(.runTextPrimary)
            Spacer()
            if onClose != nil {
                Button(L10n.commonClose) { closeScreen() }
                    .font(.runeFootnote)
                    .foregroundColor(.runAccent)
                    .accessibilityIdentifier("move_back")
            }
        }
        .padding(.horizontal, 24)
        .padding(.top, 20)
        .padding(.bottom, 12)
    }

    // MARK: - Explain page

    private var explainBody: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(L10n.moveExplainTitle)
                .font(.runeTitle2).fontWeight(.semibold)
                .foregroundColor(.runTextPrimary)
            Text(L10n.moveExplainBody)
                .font(.runeBody).foregroundColor(.runTextSecondary)
            sectionCard(title: L10n.moveExplainMovesTitle, body: L10n.moveExplainMovesBody)
            // The Secure tier's hardware lock and its recovery code are re-created on
            // the new phone, never moved (docs/device-move.md D8).
            sectionCard(title: L10n.moveExplainStaysTitle,
                        body: L10n.moveExplainStaysBody(L10n.protectionTierNamePrivate))
            Text(L10n.moveExplainWarning)
                .font(.runeFootnote).foregroundColor(.runError)
            primaryButton(L10n.moveExplainContinueLabel, id: "move_explain_continue", enabled: !busy) {
                openCredentialPrompt(reissue: false)
            }
            Spacer().frame(height: 8)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    // MARK: - Fresh-credential gate

    /// Same ids as the change-PIN current-credential step (pin_prompt,
    /// passphrase_field, credential_continue, the keypad) so existing helpers
    /// drive it unchanged. Android sibling: MoveCredentialPage.
    private var credentialBody: some View {
        VStack(spacing: 20) {
            Text(credIsPassphrase ? L10n.pinChangeEnterCurrentPassphrase : L10n.pinChangeEnterCurrentPin)
                .font(.runeBody)
                .foregroundColor(.runTextPrimary)
                .accessibilityIdentifier("pin_prompt")
            if credIsPassphrase {
                PassphraseField(
                    placeholder: L10n.pinPassphrasePlaceholder,
                    text: $credPhrase,
                    identifier: "passphrase_field",
                    disabled: credVerifying
                )
                .modifier(ShakeModifier(amount: credShake))
                .overlay(
                    RoundedRectangle(cornerRadius: 10)
                        .stroke(credError ? Color.runError : Color.clear, lineWidth: 1)
                )
                Button(action: { submitCredential(credPhrase) }) {
                    Text(L10n.commonContinue)
                        .foregroundColor(credPhrase.isEmpty || credVerifying ? Color.runTextSecondary : Color.runTextPrimary)
                }
                .disabled(credPhrase.isEmpty || credVerifying)
                .accessibilityIdentifier("credential_continue")
            } else {
                let pinLength = Int(CredentialPolicy.shared.PIN_LENGTH)
                PinDots(filled: credPin.count, total: pinLength, error: credError)
                    .modifier(ShakeModifier(amount: credShake))
                PinKeypad(
                    onDigit: { digit in
                        guard credPin.count < pinLength, !credVerifying else { return }
                        credPin += digit
                        if credPin.count == pinLength { submitCredential(credPin) }
                    },
                    onDelete: {
                        guard !credPin.isEmpty, !credVerifying else { return }
                        credPin.removeLast()
                    }
                )
            }
            Button(L10n.commonCancel) {
                guard !credVerifying else { return }
                clearCredentialEntry()
                askingCredential = false
                credForReissue = false
            }
            .foregroundColor(.runTextSecondary)
            .accessibilityIdentifier("move_credential_cancel")
        }
        .frame(maxWidth: .infinity)
    }

    private func submitCredential(_ credential: String) {
        guard !credVerifying, !credential.isEmpty else { return }
        credVerifying = true
        appState.verifyMoveExportAuth(credential) { outcome in
            switch outcome {
            case "ok":
                clearCredentialEntry()
                credVerifying = false
                askingCredential = false
                let reissue = credForReissue
                credForReissue = false
                if reissue { keptOff = false }
                pastExplain = true
                startExport(reissue: reissue)
            case "wipe":
                // AppState already ran the emergency wipe; nothing more to render.
                clearCredentialEntry()
            default:
                // "wrong" and "deferred" (outage / cancelled biometric) both read as
                // a rejected entry; nothing was granted or wiped.
                credError = true
                withAnimation(.default.repeatCount(3, autoreverses: true)) { credShake = 8 }
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
                    credShake = 0; credError = false
                    clearCredentialEntry()
                    credVerifying = false
                }
            }
        }
    }

    // MARK: - State-driven body

    @ViewBuilder
    private var stateBody: some View {
        switch kind {
        case "ready":
            readyBody
        case "moved":
            movedBody
        case "frozen_no_code":
            frozenBody
        case "failed":
            failedBody
        default:
            // "idle" and "preparing" both render the same status line: after the
            // explain page "idle" only ever lasts until the first state publish.
            preparingBody
        }
    }

    private var preparingBody: some View {
        VStack(spacing: 14) {
            ProgressView().tint(.runAccent)
            Text(preparingLine)
                .font(.runeBody).foregroundColor(.runTextPrimary)
                .multilineTextAlignment(.center)
                // Same id as the Ready page's line (and same choice Android made):
                // ONE "what is happening" element for this screen whichever phase it
                // is in. Deliberately NOT move_progress_status — that id belongs to
                // the NEW phone's import progress, which the e2e waits to DISAPPEAR.
                .accessibilityIdentifier("move_waiting_status")
        }
        .frame(maxWidth: .infinity)
        .padding(.top, 40)
    }

    private var preparingLine: String {
        switch step {
        case "unregister_push": return L10n.moveStepUnregister
        case "freeze":          return L10n.moveStepFreeze
        case "mint":            return L10n.moveStepMint
        case "upload":          return L10n.moveStepUpload
        default:                return L10n.moveStepMint
        }
    }

    private var readyBody: some View {
        VStack(spacing: 16) {
            Text(L10n.moveQrTitle)
                .font(.runeTitle3).fontWeight(.semibold)
                .foregroundColor(.runTextPrimary)
                .multilineTextAlignment(.center)
            Text(L10n.moveQrBody)
                .font(.runeFootnote).foregroundColor(.runTextSecondary)
                .multilineTextAlignment(.center)

            if let qr = generateQRCode(from: handleText) {
                Image(uiImage: qr)
                    .interpolation(.none)
                    .resizable()
                    .scaledToFit()
                    .frame(width: 240, height: 240)
                    .padding(10)
                    .background(Color.white)
                    .cornerRadius(12)
                    // A SwiftUI Image with no label is decorative and never enters the
                    // a11y tree, so the identifier alone would not surface: make it an
                    // element explicitly. (The e2e's waitForAny also accepts
                    // move_show_text_toggle, but this id is in the test contract.)
                    .accessibilityElement()
                    .accessibilityAddTraits(.isImage)
                    .accessibilityIdentifier("move_qr_image")
            }

            Button(showHandleText ? L10n.moveHideTextLabel : L10n.moveShowTextLabel) {
                showHandleText.toggle()
            }
            .font(.runeFootnote)
            .foregroundColor(.runAccent)
            .accessibilityIdentifier("move_show_text_toggle")

            if showHandleText {
                VStack(spacing: 8) {
                    // The handle JSON verbatim. `accessibilityValue` is set explicitly
                    // (on top of the label a Text already publishes) because the e2e
                    // reads `value` first on iOS — the same value→text→getText chain
                    // Device.readMyCode uses for `debug_my_code`, which this mirrors.
                    Text(handleText)
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundColor(.runTextPrimary)
                        .padding(10)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(Color.runSurface)
                        .cornerRadius(8)
                        // Deliberately NOT selectable.
                        // `.textSelection(.enabled)` put the system Copy action on a
                        // string that is a full vault-export credential (read
                        // capability + one-time code), and that path writes a plain
                        // UIPasteboard item — no `.localOnly`, so Universal Clipboard
                        // can carry it to every Mac/iPad on the Apple ID, and no
                        // expiration or timed clear. [copyHandle] below is the only
                        // copy affordance and sets all three. Reading is unaffected:
                        // the e2e reads `accessibilityValue`, set just below.
                        .accessibilityValue(handleText)
                        .accessibilityIdentifier("move_handle_text")
                    Text(L10n.moveHandleCaption)
                        .font(.runeCaption2).foregroundColor(.runTextSecondary)
                        .multilineTextAlignment(.center)
                    Button(copied ? L10n.commonCopied : L10n.commonCopy) { copyHandle() }
                        .font(.runeFootnote)
                        .foregroundColor(.runAccent)
                        .accessibilityIdentifier("move_copy_button")
                }
            }

            Text(L10n.moveQrWarning)
                .font(.runeCaption2).foregroundColor(.runError)
                .multilineTextAlignment(.center)

            Text(L10n.moveWaiting)
                .font(.runeBody).foregroundColor(.runTextPrimary)
                .accessibilityIdentifier("move_waiting_status")
            Text(L10n.moveExpiryNote)
                .font(.runeCaption2).foregroundColor(.runTextSecondary)
                .multilineTextAlignment(.center)

            if !cancelUnavailable {
                secondaryButton(L10n.moveCancelLabel, id: "move_cancel_button", enabled: !busy) {
                    cancelExport()
                }
            }
        }
    }

    private var movedBody: some View {
        VStack(spacing: 16) {
            Text(L10n.moveDoneTitle)
                .font(.runeTitle3).fontWeight(.semibold)
                .foregroundColor(.runTextPrimary)
                .multilineTextAlignment(.center)
            // CONFIRM-ON-THE-NEW-PHONE copy: an EXPIRED transfer inbox answers 404
            // exactly like a drained one, so "Moved" can only ever be a hint.
            Text(L10n.moveDoneBody)
                .font(.runeBody).foregroundColor(.runTextSecondary)
                .multilineTextAlignment(.center)
            Text(L10n.moveDoneExpiredHint)
                .font(.runeCaption2).foregroundColor(.runTextSecondary)
                .multilineTextAlignment(.center)
            // Destructive LAST (RuneDialogAction's ordering rule, applied to a screen):
            // "Keep it off" is the safe choice and takes the leading position.
            secondaryButton(L10n.moveDoneKeepLabel, id: "move_done_keep_button", enabled: !busy) {
                keptOff = true
            }
            dangerButton(L10n.moveDoneWipeLabel, id: "move_done_wipe_button", enabled: !busy) {
                wipeThisPhone()
            }
        }
    }

    private var keptOffBody: some View {
        VStack(spacing: 16) {
            Text(L10n.moveKeptOffTitle)
                .font(.runeTitle3).fontWeight(.semibold)
                .foregroundColor(.runTextPrimary)
            Text(L10n.moveKeptOffBody)
                .font(.runeBody).foregroundColor(.runTextSecondary)
                .multilineTextAlignment(.center)
            // The wipe stays reachable from here forever — "Keep it off" is a resting
            // state, not a dead end.
            dangerButton(L10n.moveDoneWipeLabel, id: "move_done_wipe_button", enabled: !busy) {
                wipeThisPhone()
            }
            // ...and so does a fresh code: a "kept off" phone whose new phone never
            // actually got the bundle must be able to re-issue.
            secondaryButton(L10n.moveFrozenShowAgainLabel, id: "move_error_retry", enabled: !busy) {
                requestReissue()
            }
        }
        .padding(.top, 24)
    }

    private var frozenBody: some View {
        VStack(spacing: 16) {
            Text(L10n.moveFrozenTitle)
                .font(.runeTitle3).fontWeight(.semibold)
                .foregroundColor(.runTextPrimary)
            Text(L10n.moveFrozenBody)
                .font(.runeBody).foregroundColor(.runTextSecondary)
                .multilineTextAlignment(.center)
            // Re-issue (a fresh inbox, a fresh code, a fresh bundle) — the RAM-only
            // code died with the last process, so showing "the same" code is
            // impossible by construction.
            primaryButton(L10n.moveFrozenShowAgainLabel, id: "move_error_retry", enabled: !busy) {
                requestReissue()
            }
            if !cancelUnavailable {
                secondaryButton(L10n.moveCancelLabel, id: "move_cancel_button", enabled: !busy) {
                    cancelExport()
                }
            }
            dangerButton(L10n.moveDoneWipeLabel, id: "move_done_wipe_button", enabled: !busy) {
                wipeThisPhone()
            }
        }
        .padding(.top, 16)
    }

    private var failedBody: some View {
        VStack(spacing: 16) {
            Text(exportErrorMessage)
                .font(.runeBody).foregroundColor(.runError)
                .multilineTextAlignment(.center)
                .accessibilityIdentifier("move_error_text")
            primaryButton(L10n.moveFrozenShowAgainLabel, id: "move_error_retry", enabled: !busy) {
                requestReissue()
            }
            // A failed export still froze the vault (everything after step 3 does),
            // so the same two escape hatches must be here as on the frozen screen.
            if !cancelUnavailable {
                secondaryButton(L10n.moveCancelLabel, id: "move_cancel_button", enabled: !busy) {
                    cancelExport()
                }
            }
            dangerButton(L10n.moveDoneWipeLabel, id: "move_done_wipe_button", enabled: !busy) {
                wipeThisPhone()
            }
        }
        .padding(.top, 24)
    }

    /// MoveError → copy. Unknown/unmapped errors fall back to the generic line
    /// rather than surfacing an enum name.
    private var exportErrorMessage: String {
        switch errorName {
        case "RELAY_UNREACHABLE": return L10n.moveErrorRelay
        case "MINT_FAILED":       return L10n.moveErrorMint
        case "UPLOAD_FAILED":     return L10n.moveErrorUpload
        case "TOO_LARGE":         return L10n.moveErrorTooLarge
        case "NOT_UNLOCKED":      return L10n.moveErrorLocked
        default:                  return L10n.moveErrorGeneric
        }
    }

    // MARK: - Operations

    /// Cheap by design: everything but the `mig_frozen` probe is an in-RAM read of
    /// the Kotlin StateFlow's current value, so this can run twice a second. The one
    /// vault read (moveIsFrozen) is done ONLY on a state TRANSITION — the freeze is
    /// durable and monotonic within a session, so re-probing it every tick would be
    /// a `_meta` SELECT twice a second for nothing.
    private func syncState() {
        let c = appState.controller
        let newKind = c.moveExportStateKind()
        let newStep = c.moveExportStep()
        let transitioned = (newKind != kind) || (newStep != step)
        if newKind != kind { kind = newKind }
        if newStep != step { step = newStep }
        let newError = c.moveExportErrorName()
        if newError != errorName { errorName = newError }
        // Only ever non-empty while Ready — so this also clears the local copy the
        // moment the Kotlin side scrubs the RAM-only code.
        let text = c.moveExportHandleText()
        if handleText != text { handleText = text }
        _ = transitioned
    }

    /// The ONLY exit. `appState.isMoveFrozen` is refreshed HERE rather than on every
    /// tick, and that is deliberate: flipping it mid-export would re-route
    /// ContentView's root out from under a live fullScreenCover (the presenter
    /// disappearing under its own presentation is a SwiftUI wart, and it would put a
    /// second copy of this screen's a11y ids on screen). Nothing is lost by waiting —
    /// the freeze is DURABLE (`mig_frozen` in the vault), so a background/lock, a
    /// force-quit or a crash all land on the frozen screen at the next unlock via
    /// AppState.refreshMoveFrozen(), and while this cover is up the contact list is
    /// unreachable anyway.
    private func closeScreen() {
        appState.refreshMoveFrozen()
        onClose?()
    }

    /// "Show again" / "Retry": run the SAME fresh-credential prompt the first
    /// export uses (credentialBody → verifyMoveExportAuth), and re-issue only on
    /// "ok" (submitCredential). Kotlin refuses a re-issue without that token too.
    /// `keptOff` is left set until "ok", so a Cancel returns to where it was.
    private func requestReissue() {
        guard !busy, !credVerifying else { return }
        openCredentialPrompt(reissue: true)
    }

    /// Opens the fresh-credential prompt (credentialBody) — the explainer's
    /// Continue (`reissue: false`) and "Show again" / "Retry" (`reissue: true`).
    /// `credForReissue` tells submitCredential's "ok" which export to start.
    private func openCredentialPrompt(reissue: Bool) {
        clearCredentialEntry()
        credIsPassphrase = appState.controller.isPassphraseMode()
        credForReissue = reissue
        askingCredential = true
    }

    /// Drops whatever was typed into the credential prompt.
    private func clearCredentialEntry() {
        credPin = ""; credPhrase = ""
    }

    private func startExport(reissue: Bool) {
        guard !busy else { return }
        busy = true
        cancelUnavailable = false
        showHandleText = false
        let done: () -> Void = {
            DispatchQueue.main.async {
                busy = false
                syncState()
            }
        }
        if reissue {
            appState.controller.moveReissueExport(onDone: done)
        } else {
            appState.controller.moveBeginExport(onDone: done)
        }
    }

    private func peekTransfer() {
        busy = true
        appState.controller.moveRefreshTransferState {
            DispatchQueue.main.async {
                busy = false
                syncState()
            }
        }
    }

    private func cancelExport() {
        guard !busy else { return }
        busy = true
        appState.controller.moveCancelExport { ok in
            // Boxed by the ObjC export (KotlinBoolean, an NSNumber) because it is a
            // FUNCTION-TYPE argument — same gotcha as primeUnreadCounts' KotlinInt.
            let unfroze = ok.boolValue
            DispatchQueue.main.async {
                busy = false
                syncState()
                if unfroze {
                    // Unfrozen and resumed (MoveManager called session.resume(), which
                    // restarts the poll loops through AppState's onMoveResume hook).
                    closeScreen()
                    return
                }
                // REFUSED — two very different reasons (the manager distinguishes them
                // by moving to `Moved` only when the relay POSITIVELY said the bundle
                // is gone; an unreachable relay leaves the state untouched).
                if kind == "moved" {
                    cancelUnavailable = true
                    cancelRefusal = .alreadyPickedUp
                } else {
                    cancelRefusal = .couldNotConfirm
                }
            }
        }
    }

    private func wipeThisPhone() {
        // deniable: false — this is a deliberate, user-chosen erase that must land on
        // the setup screen, not the black powered-off-looking cover (the deniability latch is
        // for the panic wipe). Same argument as "Erase and start over".
        LogBuffer.shared.append(level: "W", tag: "Move", message: "user confirmed the post-move wipe")
        appState.emergencyWipe(deniable: false)
        closeScreen()
    }

    private func copyHandle() {
        guard !handleText.isEmpty else { return }
        // Same clipboard discipline as the pairing code (#20): localOnly keeps it off
        // Universal Clipboard / Handoff, the expiration is the backstop if the app
        // dies before the timed clear, and the clear itself only fires if OUR value is
        // still there.
        SensitivePasteboard.copy(handleText, expiresAfter: 120, clearAfter: 60)
        copied = true
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { copied = false }
    }

    // MARK: - Pieces

    private func sectionCard(title: String, body: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title)
                .font(.runeCaption).foregroundColor(.runTextSecondary)
            Text(body)
                .font(.runeFootnote).foregroundColor(.runTextPrimary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(12)
        .background(Color.runSurface)
        .cornerRadius(8)
    }

    private func primaryButton(_ title: String, id: String, enabled: Bool,
                               _ action: @escaping () -> Void) -> some View {
        Button(action: action) {
            // ONE line, never a mid-word break (2026-09-11):
            // shrink to fit instead.
            Text(title)
                .lineLimit(1)
                .minimumScaleFactor(0.5)
                .fontWeight(.semibold).frame(maxWidth: .infinity).padding()
                .background(enabled ? Color.runTextPrimary : Color.runSurface)
                .foregroundColor(enabled ? .runBackground : .runTextSecondary)
                .clipShape(RoundedRectangle(cornerRadius: 12))
        }
        .disabled(!enabled)
        .accessibilityIdentifier(id)
    }

    private func secondaryButton(_ title: String, id: String, enabled: Bool,
                                 _ action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Text(title)
                .lineLimit(1)
                .minimumScaleFactor(0.5)
                .frame(maxWidth: .infinity).padding()
                .background(Color.runSurface)
                .foregroundColor(enabled ? .runTextPrimary : .runTextSecondary)
                .clipShape(RoundedRectangle(cornerRadius: 12))
        }
        .disabled(!enabled)
        .accessibilityIdentifier(id)
    }

    private func dangerButton(_ title: String, id: String, enabled: Bool,
                              _ action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Text(title)
                .lineLimit(1)
                .minimumScaleFactor(0.5)
                .fontWeight(.semibold).frame(maxWidth: .infinity).padding()
                .background(Color.runSurface)
                .foregroundColor(enabled ? .runeDanger : .runTextSecondary)
                .clipShape(RoundedRectangle(cornerRadius: 12))
        }
        .disabled(!enabled)
        .accessibilityIdentifier(id)
    }

    /// Local copy of AddContactView's generator (that one is a private method on
    /// that view). Same filter, same correction level, same 10× scale.
    private func generateQRCode(from string: String) -> UIImage? {
        guard !string.isEmpty else { return nil }
        let context = CIContext()
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(string.utf8)
        filter.correctionLevel = "M"
        guard let outputImage = filter.outputImage else { return nil }
        let scaled = outputImage.transformed(by: CGAffineTransform(scaleX: 10, y: 10))
        guard let cgImage = context.createCGImage(scaled, from: scaled.extent) else { return nil }
        return UIImage(cgImage: cgImage)
    }
}

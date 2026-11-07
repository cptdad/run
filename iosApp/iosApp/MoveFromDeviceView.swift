import SwiftUI
import UIKit
import shared

// ---------------------------------------------------------------------------
// The NEW phone's half of "Move to new device" (docs/device-move.md, Protocol
// phone B). Three small screens, all first-run:
//
//   SetupChooserView    — "Set up as new" / "Move from another phone", the first
//                         thing a fresh install shows after the Terms gate.
//   MoveFromDeviceView  — scan the old phone's QR (or paste its text), parse it
//                         into RAM, and hand off to the UNCHANGED PIN/passphrase
//                         onboarding. Nothing is written anywhere at this point.
//   MoveImportView      — the post-unlock "Fetching → Importing → Securing"
//                         progress, run once against the handle held in RAM.
//
// The handle carries the one-time code and is NEVER persisted: parse into RAM
// only, no persistence, process death means rescan. It lives in
// AppState.pendingMoveHandle for the length of onboarding and is dropped by the
// import (success or "continue without it") and by any wipe.
//
// Failure discipline (docs/device-move.md §Failure handling): the relay drain is
// DESTRUCTIVE and MoveManager assembles + authenticates the whole bundle in RAM
// before it writes a row, so a failure here is never a half-imported vault. The
// recovery is always the same: the old phone is still frozen and intact, and
// re-issues. That is why the error copy points back at the old phone rather than
// offering a retry that cannot help, and why "Continue without it" exists — a new
// phone must be usable even if the move never completes.
// ---------------------------------------------------------------------------

// MARK: - Setup chooser

struct SetupChooserView: View {
    let onSetUpAsNew: () -> Void
    let onMoveFromOtherPhone: () -> Void

    var body: some View {
        ZStack {
            Color.runBackground.ignoresSafeArea()
            VStack(spacing: 18) {
                Spacer()
                Text(L10n.setupChooseTitle)
                    .font(.runeTitle).foregroundColor(.runTextPrimary)
                Text(L10n.setupChooseBody)
                    .font(.runeFootnote).foregroundColor(.runTextSecondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 12)
                Spacer()
                Button(action: onSetUpAsNew) {
                    // ONE line, never a mid-word break (2026-09-11): shrink to fit instead.
                    Text(L10n.setupChooseNewLabel)
                        .lineLimit(1)
                        .minimumScaleFactor(0.5)
                        .fontWeight(.semibold).frame(maxWidth: .infinity).padding()
                        .background(Color.runTextPrimary)
                        .foregroundColor(.runBackground)
                        .clipShape(RoundedRectangle(cornerRadius: 12))
                }
                .accessibilityIdentifier("setup_choose_new")
                Button(action: onMoveFromOtherPhone) {
                    Text(L10n.setupChooseMoveLabel)
                        .lineLimit(1)
                        .minimumScaleFactor(0.5)
                        .frame(maxWidth: .infinity).padding()
                        .background(Color.runSurface)
                        .foregroundColor(.runTextPrimary)
                        .clipShape(RoundedRectangle(cornerRadius: 12))
                }
                .accessibilityIdentifier("setup_choose_move")
                Spacer().frame(height: 24)
            }
            .padding(.horizontal, 28)
        }
    }
}

// MARK: - Scan / paste the handle

struct MoveFromDeviceView: View {
    /// Called with a PARSED handle. The caller stores it in AppState and continues
    /// into the untouched PinSetupView path.
    let onHandle: (MoveHandle) -> Void
    let onBack: () -> Void

    @State private var scannedCode: String? = nil
    @State private var pasted = ""
    @State private var errorMessage: String? = nil

    var body: some View {
        ZStack {
            Color.runBackground.ignoresSafeArea()
            ScrollView {
                VStack(spacing: 16) {
                    HStack {
                        Button(L10n.commonBack) { onBack() }
                            .font(.runeFootnote).foregroundColor(.runAccent)
                            .accessibilityIdentifier("move_back")
                        Spacer()
                    }
                    Text(L10n.moveFromTitle)
                        .font(.runeTitle3).fontWeight(.semibold)
                        .foregroundColor(.runTextPrimary)
                    Text(L10n.moveFromBody)
                        .font(.runeFootnote).foregroundColor(.runTextSecondary)
                        .multilineTextAlignment(.center)

                    // 220pt, not the AddContact tab's 300: the paste path sits BELOW
                    // it and must stay above the fold on the shortest supported screen
                    // (the e2e drives that field — camera scanning is not automatable).
                    QRScannerView(scannedCode: $scannedCode)
                        .frame(height: 220)
                        .cornerRadius(12)
                        // UIViewControllerRepresentable publishes no identifier of its
                        // own; make the hosting view an a11y CONTAINER so the id
                        // surfaces without shadowing anything below it.
                        .accessibilityElement(children: .contain)
                        .accessibilityIdentifier("move_scan_view")

                    Divider().background(Color.runDivider)

                    VStack(alignment: .leading, spacing: 6) {
                        Text(L10n.movePasteLabel)
                            .font(.runeCaption).foregroundColor(.runTextSecondary)
                        // PLAIN TextField on purpose: a SecureField's clearValue() is a
                        // no-op under XCUITest (the doubled-passphrase lesson), and the
                        // e2e drives this field with clearValue()+setValue(). Never
                        // autocorrect and never capitalize — the handle is exact JSON
                        // with base64url/Base32 fields.
                        TextField(L10n.movePastePlaceholder, text: $pasted)
                            .font(.system(.caption2, design: .monospaced))
                            .foregroundColor(.runTextPrimary)
                            .tint(Color.runAccent)
                            .autocorrectionDisabled(true)
                            .textInputAutocapitalization(.never)
                            .keyboardType(.asciiCapable)
                            .padding(10)
                            .background(Color.runSurface)
                            .cornerRadius(8)
                            .accessibilityIdentifier("move_paste_field")
                    }

                    if let errorMessage {
                        Text(errorMessage)
                            .font(.runeFootnote).foregroundColor(.runError)
                            .multilineTextAlignment(.center)
                            .accessibilityIdentifier("move_error_text")
                    }

                    Button(action: { submit(pasted) }) {
                        // ONE line, never a mid-word break (2026-09-11): shrink to fit instead.
                        Text(L10n.movePasteSubmitLabel)
                            .lineLimit(1)
                            .minimumScaleFactor(0.5)
                            .fontWeight(.semibold).frame(maxWidth: .infinity).padding()
                            .background(Color.runTextPrimary)
                            .foregroundColor(.runBackground)
                            .clipShape(RoundedRectangle(cornerRadius: 12))
                    }
                    .accessibilityIdentifier("move_paste_submit")
                    Spacer().frame(height: 24)
                }
                .padding(.horizontal, 24)
                .padding(.top, 16)
            }
        }
        .onChange(of: scannedCode) { code in
            guard let code else { return }
            submit(code)
        }
    }

    private func submit(_ text: String) {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            errorMessage = L10n.movePasteInvalid
            return
        }
        // The shared codec is the ONLY parser: it validates the version, the inbox
        // id, the read capability, the bundle id and the 32-symbol Base32 code, and
        // returns the canonical code form. Never throws.
        guard let handle = MoveHandleCodec.shared.parse(text: trimmed) else {
            errorMessage = L10n.movePasteInvalid
            // Let the camera re-fire on the same code if the user re-aims.
            scannedCode = nil
            return
        }
        errorMessage = nil
        // Fixed phrase only — never interpolate the handle: MoveHandle's generated
        // toString() would print the cap and the code, and even the redacted form
        // carries inbox / bundle-id prefixes (no identifier, prefixes included).
        LogBuffer.shared.append(level: "D", tag: "Move", message: "parsed a transfer handle")
        onHandle(handle)
    }
}

// MARK: - Post-unlock import progress

struct MoveImportView: View {
    @EnvironmentObject private var appState: AppState

    let handle: MoveHandle
    /// Drops the handle and lets ContentView fall through to the contact list.
    let onFinished: () -> Void

    @State private var stage = "fetching"
    @State private var failure: String? = nil
    @State private var running = false
    /// OWNED, so it dies with this screen. The task
    /// captures [handle] — the inbox read capability plus the one-time code, i.e.
    /// a full vault-export credential — and an unowned one outlived a lock.
    @State private var importTask: Task<Void, Never>? = nil

    var body: some View {
        ZStack {
            Color.runBackground.ignoresSafeArea()
            VStack(spacing: 18) {
                Spacer()
                Text(L10n.moveProgressTitle)
                    .font(.runeTitle3).fontWeight(.semibold)
                    .foregroundColor(.runTextPrimary)
                if let failure {
                    Text(failure)
                        .font(.runeBody).foregroundColor(.runError)
                        .multilineTextAlignment(.center)
                        .accessibilityIdentifier("move_error_text")
                    Button(action: { startImport() }) {
                        // ONE line, never a mid-word break (2026-09-11): shrink to fit instead.
                        Text(L10n.commonRetry)
                            .lineLimit(1)
                            .minimumScaleFactor(0.5)
                            .fontWeight(.semibold).frame(maxWidth: .infinity).padding()
                            .background(Color.runTextPrimary)
                            .foregroundColor(.runBackground)
                            .clipShape(RoundedRectangle(cornerRadius: 12))
                    }
                    .accessibilityIdentifier("move_error_retry")
                    // A new phone must never be BRICKED by a move that will not
                    // complete: dropping the handle lands on the (empty but working)
                    // contact list. The old phone is still frozen and intact, so the
                    // user can re-issue and try again later.
                    Button(L10n.moveImportSkipLabel) { onFinished() }
                        .font(.runeFootnote).foregroundColor(.runTextSecondary)
                        .accessibilityIdentifier("move_import_skip")
                } else {
                    ProgressView().tint(.runAccent)
                    Text(stageLine)
                        .font(.runeBody).foregroundColor(.runTextPrimary)
                        .multilineTextAlignment(.center)
                        .accessibilityIdentifier("move_progress_status")
                    Text(L10n.moveProgressHint)
                        .font(.runeCaption2).foregroundColor(.runTextSecondary)
                        .multilineTextAlignment(.center)
                }
                Spacer()
            }
            .padding(.horizontal, 28)
        }
        .onAppear { startImport() }
        .onDisappear {
            // This screen leaves on exactly three events — the import
            // succeeded, "Continue without it", or the session locked/wiped (which
            // drops `pendingMoveHandle` and re-routes). In the last case the Kotlin
            // side is already cancelled with `moveScope`; dropping the task here
            // closes the Swift half so no queued main-actor continuation can reach
            // a handle this process is supposed to have forgotten.
            importTask?.cancel()
            importTask = nil
            running = false
        }
    }

    private var stageLine: String {
        switch stage {
        case "importing": return L10n.moveProgressImporting
        case "securing":  return L10n.moveProgressSecuring
        default:          return L10n.moveProgressFetching
        }
    }

    private func startImport() {
        guard !running else { return }
        running = true
        failure = nil
        stage = "fetching"
        importTask = Task { @MainActor in
            // The bounded wait for a live transport
            // used to run HERE, in an unowned Task, with `messageManager == nil`
            // as its only loop condition — and a lock is precisely what makes that
            // nil, so the loop (and the captured handle) survived a lock for the
            // whole 300 s budget. It now runs inside
            // `IosAppController.moveImportFromHandle`, on `moveScope`, which both
            // `lock()` and `emergencyWipe()` cancel. Same budget, same honest
            // "fetching" line while it waits, and a timeout still surfaces as the
            // ordinary RELAY_UNREACHABLE copy with retry/skip.
            //
            // This task is main-actor ENQUEUED, not immediate, so re-check the
            // session before handing the handle across the bridge: a lock landing
            // between startImport() and this line has already dropped
            // `pendingMoveHandle`, and starting an import off a stale capture is
            // exactly what this guards against.
            guard !Task.isCancelled, appState.isUnlocked else {
                running = false
                return
            }
            appState.controller.moveImportFromHandle(
                handle: handle,
                onProgress: { step in
                    // Kotlin coroutine thread — hop to main before touching state.
                    DispatchQueue.main.async { stage = step }
                },
                onDone: { ok, error in
                    // Kotlin FUNCTION-TYPE arguments box their primitives in the ObjC
                    // export, so this arrives as KotlinBoolean (an NSNumber), not Bool
                    // — same gotcha as primeUnreadCounts' `Int(truncating: n)`.
                    let succeeded = ok.boolValue
                    DispatchQueue.main.async {
                        running = false
                        if succeeded {
                            LogBuffer.shared.append(level: "D", tag: "Move", message: "import complete")
                            onFinished()
                        } else {
                            failure = Self.importErrorMessage(error)
                        }
                    }
                }
            )
        }
    }

    /// MoveError → copy. Unknown values fall back to the generic import line rather
    /// than surfacing an enum name.
    private static func importErrorMessage(_ error: String) -> String {
        switch error {
        case "RELAY_UNREACHABLE": return L10n.moveErrorRelay
        case "BUNDLE_GONE":       return L10n.moveErrorBundleGone
        case "BAD_CODE":          return L10n.moveErrorBadCode
        case "BUNDLE_CORRUPT":    return L10n.moveErrorCorrupt
        case "SCHEMA_TOO_NEW":    return L10n.moveErrorSchema
        case "ALREADY_IMPORTED":  return L10n.moveErrorAlreadyImported
        case "NOT_UNLOCKED":      return L10n.moveErrorLocked
        default:                  return L10n.moveErrorImport
        }
    }
}

import SwiftUI
import CoreImage.CIFilterBuiltins
import AVFoundation
import Vision
import Foundation
import shared

// ---------------------------------------------------------------------------
// AddContactView — sheet for adding a new contact via code exchange.
//
// Two visible paths plus a hidden fallback:
//   1. "Show My Code" — displays QR code with this device's inbox ID + secret
//   2. "Scan Code" — camera QR scanner
//   • Hidden no-camera paste exchange (AddStep.paste), revealed by a 5-taps-
//     within-3s gesture on the header (accessibilityIdentifier add_paste_reveal).
//     It performs the SAME validated copy/paste code exchange as the QR flow —
//     there is no separate "Debug" tab and no PIN gate. (used by e2e + dev)
//
// Contact exchange flow (matching Android):
//   1. Each device generates a random 32-byte secret and a UUID inbox ID.
//   2. QR payload is JSON: {"inbox":"<uuid>","secret":"<base64>"}
//   3. On scan, both secrets are combined via deriveSharedSecret (lexicographic
//      sort + SHA-256) to produce a shared secret known to both devices.
//   4. Two inbox records are created:
//      - Outbound: the scanned peer's inbox ID (where we send TO them)
//      - Inbound:  our own inbox ID (where they send TO us, and we poll)
//   5. A random alias (verb + animal) is generated.
//   6. The user is prompted for a mnemonic (personal memory aid).
// ---------------------------------------------------------------------------

/// PowAbort token shared between the SwiftUI lifecycle and the Kotlin mint
/// call. The Kotlin side polls `shouldAbort()` every ~16k inner-loop hashes;
/// flipping `cancelled = true` from the main thread is sufficient to exit
/// the solve promptly. Class (not struct) so the Kotlin side sees mutations
/// through the same reference.
final class MintCancelToken: PowAbort {
    var cancelled: Bool = false
    func shouldAbort() -> Bool { return cancelled }
}

/// Outcome of the background mint call. Drives UI between the "Setting up
/// inbox…" placeholder and the QR display.
enum MintState {
    case waitingForRelay
    case solving
    // (text inbox, CONTROL inbox, GROUP-text inbox). The secret half and the one-time
    // key live in the shared PairingSession (`AddContactView.pairing`), never here.
    // The control inbox (v7) is drained by the background poller so group
    // invites and announces reach this device without a conversation being
    // open; the group inbox (§1.6) is where a peer's group texts land, kept
    // separate so a /peek on the text inbox never lights the contact dot for
    // one.
    //
    // The GROUP inbox is OPTIONAL and `nil` is a fully supported pairing — the
    // same state every pairing made before it existed is in. `mintInboxPair`
    // returns the pair with `grp = null` when only the third grind failed
    // (failing a whole IRL pairing over an optional optimisation would be
    // strictly worse), the QR then carries no `gib`/`gwcap`, group texts ride
    // the text inbox, and the §1.6 backfill converges it on a later control
    // sweep. Keep this in lockstep with Android's AddContactScreen.kt.
    case ready(MintedInbox, MintedInbox, MintedInbox?)
    case failed(String)
}

/// Lifetime of one add-contact pairing session's secret half (G3). See
/// `AddContactView.pairingSession`; Android sibling: AddContactSessionViewModel.
enum PairingSessionPhase {
    /// No half yet (the view has not appeared).
    case notStarted
    /// The half is live: the Show QR, the mint snapshot and the save use it.
    case active
    /// A real leave wiped the half. Unusable; the next appear starts a new session.
    case ended
}

/// What `.onAppear` does with the current pairing session.
enum PairingSessionAppearAction: Equatable {
    /// First appear — generate the session's half.
    case startFirstSession
    /// Session still live (a duplicate appear) — keep the half the peer may have scanned.
    case keepSession
    /// The previous session ended (its half is wiped) — reset and start a new one.
    case startNewSession
}

struct AddContactView: View {
    @EnvironmentObject private var appState: AppState
    @Environment(\.displayScale) private var displayScale
    let onDismiss: () -> Void

    @State private var step: AddStep = .choice
    @State private var errorMessage: String? = nil

    // Mint pipeline. The pairing session (secret half + one-time key) is created once
    // per PAIRING SESSION (see `pairingSession`); the (inboxId, writeCap) come back
    // from the relay via mintInbox().
    //
    // `pairing` is the shared commonMain PairingSession: it OWNS the secret half and
    // the one-time keypair (Kotlin memory, wiped in place by `end()`), builds both
    // code shapes, parses the peer's code and runs the save. No half is held in Swift
    // any more, so there is no Data copy-on-write alias to chase.
    @State private var pairing: PairingSession? = nil
    // One pairing session = one secret half + one one-time key (ratchet-bootstrap plan,
    // phase 0 G3 + phase 2). The phase makes an ended session unusable:
    // .onDisappear (a real leave) ends the session, and an .onAppear on an ENDED
    // session starts a NEW one (fresh half, wizard back at .choice) — never reused
    // key material, and never a new half spliced into the old session's progress.
    // An .onAppear while .active (a duplicate appear, no disappear in between)
    // keeps the half the peer may already have scanned. Android sibling:
    // AddContactSessionViewModel (AddContactSessionViewModel.kt).
    @State private var pairingSession: PairingSessionPhase = .notStarted
    @State private var mintState: MintState = .waitingForRelay
    // @State so the token SURVIVES a parent re-render. A plain
    // `let` was recreated when ContactListView re-rendered mid-mint (Tor state / unread
    // poll); the running solve had captured the OLD token while teardown flipped the
    // NEW one, so backing out could no longer abort the PoW grind (10–160 s of wasted CPU).
    @State private var mintAbort = MintCancelToken()
    @State private var copied = false
    // Smooth time-estimate of the inbox mint (proof-of-work grind) for the
    // progress snackbar — driven by mintPhaseTag, NOT a literal attempt counter.
    @State private var mintProgress: Double = 0.06

    // Exchange progress — the swap is mutual (each device shows AND scans), so
    // we track which halves are done and save once both are.
    @State private var shown = false
    @State private var scannedCode: String? = nil
    @State private var peerInbox: String? = nil
    // The peer's parsed code, exactly as the shared parse returned it (inbox + caps,
    // control and group pairs, secret half, `rv`, one-time key `ek`). Handed to
    // PairingSession.save unchanged. nil = nothing scanned yet.
    @State private var peerScan: PairingScan? = nil
    // Key confirmation failed on the scan-first side ("pairing failed — start again").
    // NOT terminal: the 1 Hz poll keeps running and clears it again if the pairing
    // completes after all; only the user's "Start again" tap deletes anything.
    @State private var pairingFailed = false

    // Hidden 5-taps-within-3s gesture that reveals the no-camera paste exchange.
    @State private var pasteTapCount = 0
    @State private var lastPasteTap = Date.distantPast

    // Mnemonic (entered inline on the Done screen; written by saveMnemonicAndDismiss)
    @State private var pendingContactId: String? = nil
    @State private var mnemonic = ""
    @State private var pendingAlias = ""

    // The peer's in-band announce landed while this screen is still open, so a
    // half-done pairing completed under the user's eyes (see [scanBackNeeded]).
    @State private var peerInboxArrived = false
    /// The "[done] awaiting…" line is logged once per scan-back wait, not at 1 Hz.
    @State private var scanBackWaitLogged = false
    // "Cancel pairing" confirm gate — the ONLY way out of the scan-back state.
    @State private var showCancelPairing = false

    /// Wizard steps. The exchange is mutual: "Show"/"Scan" only choose which half
    /// comes first; `.finishing` is the scanned-but-mint-still-running wait;
    /// `.paste` is the hidden no-camera fallback.
    private enum AddStep { case choice, show, scan, finishing, done, paste }

    // Helpers to read the mint pipeline.
    private var myInboxId: String? {
        if case .ready(let m, _, _) = mintState { return m.inboxId }
        return nil
    }
    /// SECRET-ONLY payload for the Show step — renders INSTANTLY, before the
    /// mint. The peer saves us as a pending contact; our inbox reaches them
    /// in-band afterwards (sendInboxAnnounce). This removes the "Setting up
    /// inbox…" wait while two people stand next to each other.
    private var myShowPayload: String? {
        guard pairingSession == .active else { return nil }
        // The session builds it (shared codec, identical wire format on both platforms;
        // the one-time key `ek` rides along). nil once the session has ended.
        return pairing?.secretOnlyCode()
    }
    /// FULL payload (inbox + writeCap + secret) for the Done step and the
    /// paste exchange — mint-gated: the Done-step code is the one the peer
    /// scans back, so it must carry the inbox.
    private var myPayload: String? {
        guard pairingSession == .active, let pairing = pairing,
              case .ready(let m, let ctl, let grp) = mintState else { return nil }
        // gib/gwcap appended LAST — Kotlin default args don't bridge, so every
        // parameter is explicit (§1.4). BOTH-OR-NEITHER: with no group inbox the
        // code is byte-identical to a pre-§1.4 one, which is exactly what an old
        // build emits and what `PairingPayload.parse` reads back as `grp = null`.
        return pairing.fullCode(
            inboxId: m.inboxId, writeCap: m.writeCapability,
            ctlInboxId: ctl.inboxId, ctlWriteCap: ctl.writeCapability,
            grpInboxId: grp?.inboxId, grpWriteCap: grp?.writeCapability)
    }

    /// The pairing is only HALF done: we scanned their instant SECRET-ONLY code,
    /// so THEY still have to scan our full code (the one that carries our inbox),
    /// and that second scan is the only thing that produces an inbox announce.
    ///
    /// App Store 2.1(a) rejection of 1.6.13 ("both devices stuck on waiting after
    /// scanned code"): this step used to claim "✓ Contact added" and offer Done
    /// right after the FIRST scan, so both reviewers tapped Done on both phones.
    /// Done tears down the transient inbox write capability + secret half (never
    /// persisted, and they must never be), leaving a permanently
    /// un-completable "Waiting for their inbox…" contact on each device and no
    /// POST on the relay. So the screen now stays put in this state until the
    /// peer's announce lands or the user explicitly abandons the pairing.
    ///
    /// Android sibling: `addContactDoneState` + `scanBackNeeded` in
    /// AddContactScreen.kt — same two inputs, same order; keep them in lockstep.
    /// (`peerInbox` is the peer inbox recorded at SAVE time, which the paste path
    /// also sets — see addContactFromPastedCode.)
    private var scanBackNeeded: Bool {
        step == .done && peerInbox == nil && !peerInboxArrived
    }

    /// Equatable phase tag so .onChange can drive the mint progress snackbar.
    private var mintPhaseTag: Int {
        switch mintState {
        case .waitingForRelay: return 0
        case .solving:         return 1
        case .ready:           return 2
        case .failed:          return 3
        }
    }
    private var mintStatusLine: String {
        switch mintState {
        case .waitingForRelay: return waitingForRelayLine
        case .solving:         return L10n.addContactSolvingPow
        case .ready:           return L10n.addContactMintReady
        case .failed:          return ""
        }
    }

    /// The pre-connect wait line. `.waitingForRelay` stays NON-TERMINAL in every
    /// variant below — no auto-transition to `.failed`, no Retry (that would
    /// double-mint); only the wording gets honest.
    ///
    /// App Store review 2.1 rejected 0.8.159 because this was the literal string
    /// "Reaching the relay…" for 15+ minutes: Tor never bootstrapped in the review
    /// lab and nothing on screen ever admitted it.
    private var waitingForRelayLine: String {
        // .relaunchRequired outranks the stall hint (AppState clears the stall flag
        // when that latch trips, but order the checks so this holds regardless):
        // Tor is dead for this process, so "try another network" is bad advice.
        if appState.relayConnectPhase == .relaunchRequired {
            return "Can’t reach the relay in this session. Close and reopen Rún to try again."
        }
        // TIER 1 (240 s of continuous bootstrapping this session) outranks the
        // Tier-0 network hint: "try different Wi-Fi" stops being the best advice
        // once the connection has had four minutes. iOS cannot restart Tor
        // in-process, so the actionable step is a relaunch — same wording pattern
        // as the .relaunchRequired line above.
        if appState.torBootstrapStalledLong {
            return "Still can’t connect. Close Rún completely and open it again — that starts a fresh private connection."
                + AddContactView.rebootHintSuffix(appState)
        }
        if appState.torBootstrapStalled {
            return "Still connecting… This network may be blocking the private connection. Try different Wi-Fi or mobile data — we’ll keep trying."
                + AddContactView.rebootHintSuffix(appState)
        }
        // Two-phase status line — mirrors ContactListView / Android's
        // RelayConnectHints.connectStatusLine (byte-identical wording):
        // "Connecting to Tor…" while Tor bootstraps, then "Connecting to
        // Relay…" once Tor is connected but our own mint hasn't
        // started/landed yet (this screen's analog of "relay not yet
        // reachable" is "mint still .waitingForRelay"). No percent parameter
        // any more (2026-09-16: the digits moved to an animated dots cadence
        // on the ContactListView sibling only — this screen's mint snackbar
        // already has its own moving progress bar, so it doesn't need one
        // too).
        return AppState.connectStatusLine(torConnected: appState.torState == .connected,
                                          externalProxy: appState.extProxyStatus.isExternal)
    }

    /// TIER 2 (AppState.torRebootHintWarranted): several failed bootstrap sessions
    /// across launches, read once at Tor start from the Keychain breadcrumb
    /// (shared `TorBootstrapSelfHeal.shouldSuggestReboot`). APPENDED to whichever
    /// stall line is showing rather than replacing it — this is one snackbar line,
    /// and the tier's own advice ("close and reopen") is still the first thing to
    /// try. Reachable from BOTH stall tiers, i.e. from any stuck shape.
    private static func rebootHintSuffix(_ appState: AppState) -> String {
        appState.torRebootHintWarranted
            ? " If closing and reopening hasn’t helped, restart your iPhone."
            : ""
    }

    /// Stable, branch-free accessibility id for the snackbar status line: which
    /// honest state is showing is expressed by the VALUE, so the identifier never
    /// appears/disappears (which would change the view's identity mid-wait).
    ///
    /// The Tier-2 reboot suffix deliberately gets NO id of its own here (unlike
    /// ContactListView, where it is a separate line): it is appended text inside
    /// this single status line, so it is expressed by the VALUE — exactly the rule
    /// above. Tier 1 does get one, following the existing `add_mint_*` pattern.
    private var mintStatusAccessibilityId: String {
        guard case .waitingForRelay = mintState else { return "mint_status_line" }
        if appState.relayConnectPhase == .relaunchRequired { return "add_mint_relaunch" }
        if appState.torBootstrapStalledLong { return "add_mint_stalled_long" }
        if appState.torBootstrapStalled { return "add_mint_stalled" }
        return "mint_status_line"
    }

    var body: some View {
        NavigationStack {
            ZStack {
                Color.runBackground.ignoresSafeArea()

                VStack(spacing: 0) {
                    switch step {
                    case .choice:    choiceStep
                    case .show:      showStep
                    case .scan:      scanCodeTab
                    case .finishing: finishingStep
                    case .done:
                        if pairingFailed { pairingFailedStep } else { doneStep }
                    case .paste:     codeExchangeForm
                    }

                    Spacer()
                }
            }
            .navigationTitle(L10n.addContactNavTitle)
            .navigationBarTitleDisplayMode(.inline)
            .runNavigationBarChrome()
            .toolbar { addContactToolbar }
            .onAppear {
                // One stable session (secret half + one-time key) per PAIRING
                // SESSION — the instant Show QR carries it, so it must NOT rotate
                // while the peer may already have scanned it. Keyed on the session
                // phase (see `pairingSession`). Every transient event this sheet sees today
                // (the system camera-permission alert, Face ID, Control Center,
                // rotation, the keyboard, the paste/debug step — a `step` switch
                // inside this same ZStack) fires NO .onDisappear, so the half
                // stays as is across them.
                if AddContactView.pairingSessionOnAppear(pairingSession) == .startNewSession {
                    resetForNewPairingSession()
                }
                if pairingSession == .notStarted {
                    pairing = PairingSession.companion.start()
                    pairingSession = .active
                }
                startMint()
            }
            .onDisappear {
                // Flip the abort flag so the background solve exits promptly
                // when the user backs out mid-pairing.
                mintAbort.cancelled = true
                // End the pairing session on EVERY exit from this screen, not only a
                // completed save — the backstop for Back/Cancel mid-flow. Safe
                // unconditionally: the screen is going away, so no retry is left.
                // `end()` zeroes the secret half and the one-time private key in
                // Kotlin memory, in place; the session is unusable afterwards. Ending
                // it here also makes a later .onAppear on this instance start a NEW
                // one (see `pairingSession`).
                pairing?.end()
                pairing = nil
                pairingSession = .ended
                peerScan = nil
                dropMintSnapshot()
            }
            // Tor on a physical device can take 60–180s to bootstrap from a
            // cold launch. If the user opens AddContact before then,
            // controller.messageManager is still nil and the initial
            // startMint() call bails into .waitingForRelay.
            //
            // This is an EDGE trigger only. torState comes from AppState's
            // torCancellable, which is independent of the port/unlock wiring that
            // creates the transport, so messageManager can still be nil when
            // .connected lands here (startMint then parks in .waitingForRelay
            // again). The 1 Hz re-arm below (rearmMintIfTransportReturned) covers
            // that case.
            .onReceive(appState.transport.$torState) { newState in
                if case .connected = newState, mintWaitingForRelay {
                    startMint()
                }
            }
            .onChange(of: mintPhaseTag) { tag in
                // Progress snackbar easing: glide toward ~90% across a typical PoW
                // solve, then snap to 100% the moment the mint lands. A time-
                // estimate, not real attempts (the parallel solver doesn't surface
                // per-attempt counts).
                switch tag {
                case 1:  withAnimation(.easeOut(duration: 9)) { mintProgress = 0.9 }
                case 2:  withAnimation(.easeOut(duration: 0.3)) { mintProgress = 1.0 }
                default: mintProgress = 0.06
                }
            }
            .onChange(of: scannedCode) { code in
                if let code = code {
                    handleScannedCode(code)
                    scannedCode = nil
                }
            }
            // The screen's 1 Hz tick: drives the pre-connect percent pacer
            // (waitingForRelayLine), the off-screen pairing check, and the mint
            // re-arm. Android sibling: AddContactScreen's `LaunchedEffect(Unit)`
            // pacer ticker + its `LaunchedEffect(mintWaitingForRelay,
            // mintTransportReady)` re-arm.
            .onReceive(Timer.publish(every: 1, on: .main, in: .common).autoconnect()) { _ in
                onPairingTick()
            }
        }
        // A swipe-down on the sheet is a dismiss, and a dismiss while the pairing is
        // half done is exactly the destructive action the confirm exists for — so
        // disable the interactive dismiss and let the toolbar Cancel (which routes
        // through that confirm) be the only exit. On the NavigationStack, not the
        // inner ZStack, so the scrim below also covers the navigation bar. Android
        // sibling: the BackHandler in AddContactScreen.kt.
        .interactiveDismissDisabled(scanBackNeeded)
        // Consent gate for the irreversible exit. Titled (a title-less RuneDialog
        // card flattens its children in the a11y tree, hiding the button ids), and
        // the destructive action is LAST per the ordering safety rule in
        // UIComponents.swift so the reflex tap keeps the pairing.
        .runeDialog(
            isPresented: $showCancelPairing,
            title: L10n.addContactCancelPairingTitle,
            message: L10n.addContactCancelPairingMessage,
            a11yId: "add_contact_cancel_pairing_dialog",
            actions: [
                RuneDialogAction.secondary(L10n.addContactKeepWaiting,
                                           a11yId: "add_contact_cancel_pairing_keep") { },
                RuneDialogAction(L10n.commonDelete, color: .runeDanger,
                                 a11yId: "add_contact_cancel_pairing_confirm") {
                    cancelPairingAndLeave()
                },
            ]
        )
    }

    /// Leading Done (paired) or Cancel / Back (every other step).
    @ToolbarContentBuilder
    private var addContactToolbar: some ToolbarContent {
        ToolbarItem(placement: .navigationBarLeading) {
            // No Done while the pairing is half done — see [scanBackNeeded].
            // That state falls through to the Cancel branch below, which
            // routes through the confirm instead of dismissing.
            if step == .done && !scanBackNeeded {
                Button(L10n.commonDone) {
                    // Writes the mnemonic to the contact (if non-empty),
                    // then dismisses. The function name predates the
                    // sheet removal — kept for the persisted side effect.
                    saveMnemonicAndDismiss()
                    NotificationCenter.default.post(name: .contactsChanged, object: nil)
                    onDismiss()
                }
                .foregroundColor(Color.runAccent)
                .fontWeight(.semibold)
                .accessibilityIdentifier("add_contact_done")
            } else {
                Button(step == .choice || scanBackNeeded ? L10n.commonCancel : L10n.commonBack) {
                    if scanBackNeeded {
                        // Leaving deletes the half-finished contact, so it
                        // is confirmed — same gate as the body's "Cancel
                        // pairing" and as the interactive sheet dismiss.
                        showCancelPairing = true
                    } else if step == .choice {
                        onDismiss()
                    } else {
                        step = .choice
                        shown = false
                        peerInbox = nil
                        // The discarded scan (and its `rv` / `ek` markers) must not
                        // leak into a later scan.
                        peerScan = nil
                        errorMessage = nil
                    }
                }
                .foregroundColor(Color.runTextPrimary)
                .accessibilityIdentifier("add_contact_cancel")
            }
        }
    }

    // MARK: - Step: choose how to start

    private var choiceStep: some View {
        ZStack(alignment: .bottom) {
            VStack(spacing: 16) {
                Spacer()
                Text(L10n.addContactChoiceHeading)
                    .font(.runeTitle2)
                    .foregroundColor(Color.runTextPrimary)
                Text(L10n.addContactChoiceSubtitle)
                    .font(.runeFootnote)
                    .foregroundColor(Color.runTextSecondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 32)
                if let err = errorMessage {
                    // A "start again" reason (the save could not complete) lands here,
                    // on the fresh wizard. Same id as the other surfaces.
                    Text(err)
                        .font(.runeFootnote)
                        .foregroundColor(Color.runError)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 32)
                        .accessibilityIdentifier("add_contact_error")
                }
                Spacer().frame(height: 24)
                choiceButton(title: L10n.addContactChoiceShow, id: "add_choice_show") { errorMessage = nil; step = .show }
                choiceButton(title: L10n.addContactChoiceScan, id: "add_choice_scan") { errorMessage = nil; step = .scan }
                Spacer()
            }
            .padding()

            // Hidden 5-taps-within-3s gesture reveals the no-camera paste exchange.
            // A Button (vs a bare Color.clear) reliably surfaces to XCUITest as a
            // queryable, tappable element while staying visually invisible.
            //
            // The reveal is #if DEBUG-gated so a shipped
            // build cannot put the pairing code (half the shared secret + inbox
            // write cap) on the pasteboard via this undocumented gesture. Parity
            // with Android (AddContactScreen.kt gates the identical surface behind
            // BuildConfig.DEBUG). The invisible button stays in
            // the tree for XCUITest, but its tap is inert outside DEBUG.
            Button {
                #if DEBUG
                let now = Date()
                if now.timeIntervalSince(lastPasteTap) > 3 { pasteTapCount = 0 }
                lastPasteTap = now
                pasteTapCount += 1
                if pasteTapCount >= 5 { pasteTapCount = 0; step = .paste }
                #endif
            } label: {
                Color.clear
                    .frame(width: 160, height: 90)
                    .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityIdentifier("add_paste_reveal")
            .padding(.bottom, 24)
        }
    }

    private func choiceButton(title: String, id: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Text(title)
                .font(.runeBody)
                .foregroundColor(Color.runTextPrimary)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 18)
                .background(Color.runSurface)
                .cornerRadius(12)
        }
        .accessibilityIdentifier(id)
        .padding(.horizontal)
    }

    // MARK: - Step: show my code

    private var showStep: some View {
        VStack(spacing: 16) {
            Spacer().frame(height: 16)

            // Instant secret-only QR — no mint gate. The inbox setup overlaps
            // the human QR-exchange instead of preceding it.
            Text(L10n.addContactShowHeading)
                .font(.runeFootnote)
                .foregroundColor(Color.runTextSecondary)

            if let payload = myShowPayload, let qr = CrispQR.make(from: payload, tilePoints: 252, displayScale: displayScale) {
                CrispQRView(qr: qr)
                    // The identifier sits on the WHITE padded tile (quiet zone
                    // included), so an element screenshot is directly scannable
                    // (e2e camera specs). A decorative Image is not an accessibility
                    // element by default, so make it a leaf first. Android sibling:
                    // add_show_qr in ShowStep (AddContactScreen.kt).
                    .accessibilityElement()
                    .accessibilityIdentifier("add_show_qr")
            }

            // #if DEBUG: the instant secret-only payload as text, so the e2e
            // harness can feed the peer's scanner what the camera would have read
            // off the QR above (a simulator has no camera). Same encoding and same
            // gating as the paste tab's `debug_my_code`; Android sibling:
            // `debug_instant_code` in ShowStep (AddContactScreen.kt).
            #if DEBUG
            if let b64 = myShowCodeBase64 {
                Text(b64)
                    .font(.system(.caption2, design: .monospaced))
                    .foregroundColor(Color.runTextSecondary)
                    .lineLimit(4)
                    .padding(.horizontal)
                    .accessibilityIdentifier("debug_instant_code")
            }
            #endif

            Text(peerInbox != nil ? L10n.addContactShowHintScanned
                                  : L10n.addContactShowHintPending)
                .font(.runeCaption)
                .foregroundColor(Color.runTextSecondary.opacity(0.7))
                .multilineTextAlignment(.center)
                .padding(.horizontal)

            Button {
                LogBuffer.shared.append(level: "D", tag: "AddContact",
                    message: "[show] Next tapped: prevShown=\(shown) peerInboxSet=\(peerInbox != nil)")
                shown = true
                if peerScan != nil { completeSaveOrWait() } else { step = .scan }
            } label: {
                Text(peerScan != nil ? L10n.addContactNext : L10n.addContactShowFirstIos)
                    .font(.runeBody)
                    .foregroundColor(.black)
                    .padding(.horizontal, 32)
                    .padding(.vertical, 12)
                    .background(Color.runTextPrimary)
                    .cornerRadius(8)
            }
            .accessibilityIdentifier("add_show_next")

            Spacer()
        }
    }

    // MARK: - Step: scanned, waiting for our own mint

    /// Where the old Show-step "Setting up inbox…" wait moved when the Show
    /// QR became instant. Only visible if the mint is slower than the
    /// scanning dance; completes automatically when the mint lands.
    private var finishingStep: some View {
        VStack(spacing: 16) {
            Spacer().frame(height: 32)

            if case .failed(let reason) = mintState {
                Text(reason)
                    .font(.runeFootnote)
                    .foregroundColor(Color.runTextSecondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal)
                    .accessibilityIdentifier("add_mint_failed")

                Button {
                    startMint()
                } label: {
                    Text(L10n.commonRetry)
                        .font(.runeBody)
                        .foregroundColor(.black)
                        .padding(.horizontal, 32)
                        .padding(.vertical, 12)
                        .background(Color.runTextPrimary)
                        .cornerRadius(8)
                }
                .accessibilityIdentifier("add_mint_retry")
                Spacer()
            } else if let err = errorMessage {
                // The scan landed before the mint, so the save ran from here —
                // and the vault can now REFUSE it (an inbox id already owned). Without
                // this the user would sit on "Setting up inbox…" forever after a
                // refusal. Same identifier as the scan/paste surfaces; only one step
                // renders at a time.
                Text(err)
                    .font(.runeFootnote)
                    .foregroundColor(Color.runError)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal)
                    .accessibilityIdentifier("add_contact_error")
                Spacer()
            } else {
                // Keep the screen-reader cue QA keys on, but render the visible
                // feedback as the bottom progress snackbar below.
                Text(L10n.addContactSettingUpInbox)
                    .font(.runeFootnote)
                    .foregroundColor(Color.runTextSecondary)
                    .accessibilityIdentifier("add_mint_pending")
                Spacer()
                mintProgressSnackbar
            }
        }
    }

    /// Bottom-anchored progress snackbar for the inbox mint. The bar is a smooth
    /// TIME-ESTIMATE of the proof-of-work grind (the relay hands out a difficulty
    /// challenge the device brute-forces) — it eases toward ~90% over a typical
    /// solve and snaps to 100% when the mint lands. Not a literal attempt counter;
    /// the parallel solver doesn't surface per-attempt counts.
    private var mintProgressSnackbar: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Image(systemName: "hexagon")
                    .font(.runeFootnote)
                    .foregroundColor(Color(red: 0.86, green: 0.71, blue: 0.46))
                Text(mintStatusLine)
                    .font(.runeFootnote)
                    .foregroundColor(Color.runTextPrimary)
                    // The honest stall/relaunch variants are multi-sentence — let the
                    // line wrap inside the snackbar instead of truncating.
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityIdentifier(mintStatusAccessibilityId)
                Spacer()
            }
            ProgressView(value: mintProgress)
                .tint(Color(red: 0.75, green: 0.22, blue: 0.15))
        }
        .padding(14)
        .background(Color.runSurface)
        .cornerRadius(12)
        .padding(.horizontal, 16)
        // 32 not 16: keep the status line ("Reaching the relay…") clearly off
        // the screen bottom — visual parity with ContactListView's banner.
        .padding(.bottom, 32)
        .accessibilityIdentifier("mint_snackbar")
    }

    // MARK: - Step: done
    //
    // TWO states, see [scanBackNeeded]:
    //
    //   half done ("Almost there") — we scanned their instant secret-only code, so
    //     OUR full code still has to be scanned by them. No success claim, no Done
    //     button; the screen stays until the announce lands or the user cancels.
    //   complete ("✓ Contact added") — nothing further owed; Done as before.
    //
    // Android sibling: DoneStep in AddContactScreen.kt.

    private var doneStep: some View {
        ScrollView {
            VStack(spacing: 12) {
                Spacer().frame(height: 4)
                // The heading IS the state.
                if scanBackNeeded {
                    Text(L10n.addContactScanBackTitle)
                        .font(.runeHeadline)
                        .foregroundColor(Color.runTextPrimary)
                        .accessibilityIdentifier("add_contact_scan_back_title")
                } else {
                    Text(L10n.addContactDoneHeading)
                        .font(.runeHeadline)
                        .foregroundColor(Color.runTextPrimary)
                }
                if !pendingAlias.isEmpty {
                    Text(L10n.addContactSavedAs(pendingAlias))
                        .font(.runeFootnote)
                        .foregroundColor(Color.runTextPrimary.opacity(0.85))
                        .accessibilityIdentifier("add_done_alias")
                }
                if scanBackNeeded {
                    // Scan-first role: we scanned their secret-only code, so
                    // OUR full code (below) carries our inbox — them scanning
                    // it back is what completes the pairing.
                    Text(L10n.addContactScanBackHint)
                        .font(.runeFootnote)
                        .foregroundColor(Color.runTextSecondary)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal)
                        .accessibilityIdentifier("add_contact_scan_back_hint")
                    if let payload = myPayload, let qr = CrispQR.make(from: payload, tilePoints: 216, displayScale: displayScale) {
                        CrispQRView(qr: qr)
                            // A decorative Image is not an accessibility element by
                            // default, so make it a leaf before naming it — otherwise
                            // the identifier never reaches the XCUITest tree.
                            .accessibilityElement()
                            .accessibilityIdentifier("add_contact_scan_back_qr")
                        // #if DEBUG: the same FULL payload as text — this is the code
                        // the peer must scan BACK to finish the pairing, and the only
                        // way an e2e run can deliver it without a camera. Android
                        // sibling: `debug_scanback_code` in DoneStep.
                        #if DEBUG
                        if let b64 = myCodeBase64 {
                            Text(b64)
                                .font(.system(.caption2, design: .monospaced))
                                .foregroundColor(Color.runTextSecondary)
                                .lineLimit(4)
                                .padding(.horizontal)
                                .accessibilityIdentifier("debug_scanback_code")
                        }
                        #endif
                    } else {
                        // Never leave "have them scan this" pointing at nothing:
                        // myPayload is nil whenever mintState is not .ready. Parity
                        // with Android's DoneStep `add_done_qr_pending` fallback.
                        Text(L10n.addContactQrPreparing)
                            .font(.runeFootnote)
                            .foregroundColor(Color.runTextSecondary)
                            .multilineTextAlignment(.center)
                            .padding(.horizontal)
                            .accessibilityIdentifier("add_done_qr_pending")
                    }
                } else if peerInbox != nil {
                    // Show-first role: the peer gets our inbox in-band. Deliberately
                    // NOT shown when the pairing completed via the peer's scan-back
                    // (peerInbox nil + peerInboxArrived): we never announced there,
                    // so "your inbox is delivered automatically" would be untrue.
                    Text(L10n.addContactAnnounceHint)
                        .font(.runeFootnote)
                        .foregroundColor(Color.runTextSecondary)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal)
                }
                // Inline mnemonic field — a personal memory aid that helps the
                // user remember WHO this contact is. Saved (if non-empty) when
                // they tap Done in the toolbar. Hidden while the pairing is half
                // done: there is no Done button in that state, so anything typed
                // here would be silently dropped.
                if !scanBackNeeded {
                    VStack(alignment: .leading, spacing: 6) {
                        Text(L10n.addContactMnemonicLabel)
                            .font(.runeCaption)
                            .foregroundColor(Color.runTextSecondary)
                        TextField(L10n.addContactMnemonicPlaceholder,
                                  text: $mnemonic, axis: .vertical)
                            .lineLimit(1...3)
                            .font(.runeFootnote)
                            .foregroundColor(Color.runTextPrimary)
                            .tint(Color.runAccent)
                            // autocorrectionType=.no
                            // alone suppresses inline correction UI only — it does NOT
                            // keep this field's text out of the QuickType keyboard
                            // lexicon, which lives outside the app sandbox and survives
                            // an app wipe. .password is the recognized secure contentType
                            // that actually excludes the field from learning (matches
                            // Android's KeyboardType.Password on this identical field).
                            .autocorrectionDisabled(true)
                            .textContentType(.password)
                            .padding(10)
                            .background(Color.runSurface)
                            .cornerRadius(8)
                            .accessibilityIdentifier("add_done_mnemonic")
                    }
                    .padding(.horizontal)
                } else {
                    // PRIMARY = stay. A deliberate no-op: the pairing finishes on the
                    // PEER's tap, so the only honest thing this screen can offer is to
                    // keep holding the code up. It occupies the reflex position so the
                    // irreversible action can never be the one muscle memory hits.
                    Button { /* stay on this screen — see comment above */ } label: {
                        Text(L10n.addContactKeepWaiting)
                            .font(.runeBody)
                            .foregroundColor(.black)
                            .padding(.horizontal, 32)
                            .padding(.vertical, 12)
                            .background(Color.runTextPrimary)
                            .cornerRadius(8)
                    }
                    .accessibilityIdentifier("add_contact_keep_waiting")
                    // SECONDARY = the only way out, and it is confirmed + destructive.
                    Button { showCancelPairing = true } label: {
                        Text(L10n.addContactCancelPairing)
                            .font(.runeFootnote)
                            .foregroundColor(Color.runTextSecondary)
                            .padding(.horizontal, 24)
                            .padding(.vertical, 10)
                    }
                    .accessibilityIdentifier("add_contact_cancel_pairing")
                }
                Spacer().frame(height: 8)
            }
            .padding(.bottom, 16)
        }
    }

    // MARK: - Step: pairing failed (key confirmation)

    /// The scan-first side's key confirmation failed: the two phones did not end up
    /// with the same secure channel. A plain notice and ONE action. Not terminal — the
    /// 1 Hz poll keeps running and removes this if the pairing completes after all.
    /// Android sibling: PairingFailedStep in AddContactScreen.kt, same ids.
    private var pairingFailedStep: some View {
        VStack(spacing: 24) {
            Spacer().frame(height: 32)
            Text(L10n.addContactPairingFailed)
                .font(.runeFootnote)
                .foregroundColor(Color.runError)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 24)
                .accessibilityIdentifier("pairing_failed_notice")
            Button { startAgainAfterFailure() } label: {
                Text(L10n.addContactPairingFailedAction)
                    .font(.runeBody)
                    .foregroundColor(.black)
                    .padding(.horizontal, 32)
                    .padding(.vertical, 12)
                    .background(Color.runTextPrimary)
                    .cornerRadius(8)
            }
            .accessibilityIdentifier("pairing_failed_start_again")
            Spacer()
        }
    }

    // MARK: - Scan Code tab

    private var scanCodeTab: some View {
        VStack(spacing: 16) {
            Text(L10n.addContactScanHeading)
                .font(.runeFootnote)
                .foregroundColor(Color.runTextSecondary)
                .padding(.top, 4)

            scanInjectRow
            scanInjectImageRow

            QRScannerView(scannedCode: $scannedCode)
                .frame(height: 300)
                .cornerRadius(12)
                .padding()

            if let err = errorMessage {
                Text(err)
                    .font(.runeFootnote)
                    .foregroundColor(Color.runError)
                    .padding(.horizontal)
                    .accessibilityIdentifier("add_contact_error")
            }
        }
    }

    // MARK: - Scanner injection seam (#if DEBUG — the simulator has no camera)
    //
    // The two-scan camera dance (instant secret-only code out, full code scanned
    // back) has NO automatable surface: the paste exchange always trades FULL
    // codes on both sides, so `scanBackNeeded` is unreachable from the e2e suite
    // and the scan-back screen's completion path was never covered. This routes a
    // harness-supplied payload through the EXACT camera path — it writes
    // `scannedCode`, which is the binding QRScannerView's coordinator writes, so
    // the same .onChange → handleScannedCode runs with the same full/secret-only
    // detection and the same `shown` deadlock guard.
    //
    // Same gating model as the paste exchange above (see above): compiled out of
    // release entirely by #if DEBUG, so no release build carries the field, the
    // button or the decode. Android sibling: the `BuildConfig.DEBUG` inject row in
    // ScanCodeTab (AddContactScreen.kt) — same two ids, same base64-of-JSON input.
    //
    // Input is base64-of-JSON (identical encoding to the paste tab's
    // `debug_my_code`), not raw JSON: the harness types this through
    // Appium/WDA setValue, and restricting it to the base64 alphabet keeps braces
    // and quotes out of the keyboard path on both platforms. The QR itself
    // carries the RAW JSON, which is what lands in `scannedCode` after the decode.
    @State private var injectedScanCode = ""

    @ViewBuilder
    private var scanInjectRow: some View {
        #if DEBUG
        HStack(spacing: 8) {
            TextField("payload b64", text: $injectedScanCode)
                .font(.system(.caption2, design: .monospaced))
                .foregroundColor(Color.runTextPrimary)
                .autocorrectionDisabled(true)
                .textInputAutocapitalization(.never)
                .padding(8)
                .background(Color.runSurface)
                .cornerRadius(8)
                .accessibilityIdentifier("scan_inject_field")

            Button {
                let trimmed = injectedScanCode.trimmingCharacters(in: .whitespacesAndNewlines)
                guard let json = Data(base64Encoded: trimmed),
                      let raw = String(data: json, encoding: .utf8) else {
                    errorMessage = L10n.addContactInvalidCode
                    return
                }
                injectedScanCode = ""
                // The camera's own write target — one code path from here on.
                scannedCode = raw
            } label: {
                Text("inject")
                    .font(.runeCaption)
                    .foregroundColor(.black)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 8)
                    .background(Color.runTextPrimary)
                    .cornerRadius(8)
            }
            .accessibilityIdentifier("scan_inject_submit")
        }
        .padding(.horizontal)
        #endif
    }

    // MARK: - Scanner IMAGE seam (#if DEBUG, SIMULATOR only)
    //
    // The simulator has no camera, so the cross-platform e2e camera spec feeds
    // this scan step an IMAGE of the peer's QR instead: the harness copies a PNG
    // to NSTemporaryDirectory()/scan-inject.png inside this app's own container,
    // the button decodes it with Vision (QR only) and hands the decoded string to
    // `scannedCode` — the binding QRScannerView's coordinator writes on a camera
    // detection, so the same .onChange -> handleScannedCode runs (not the paste
    // path). If nothing decodes, the existing invalid-QR error surface shows and
    // the step stays put.
    //
    // HONEST SCOPE: this exercises Apple's QR decoder on a RENDERED image and our
    // handling of the result. It does NOT exercise the camera, optics, focus, or
    // AVCaptureMetadataOutput. Compiled out of release builds AND off devices by
    // the double gate below. Result readout for the harness: `scan_inject_image_result`
    // reads "decoded" or "no code: <reason>" ("idle" before the first press).
    #if DEBUG && targetEnvironment(simulator)
    @State private var injectImageResult = "idle"

    private func decodeInjectedImage() {
        let url = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("scan-inject.png")
        func fail(_ why: String) {
            // "no code" + a reason, so a harness failure says WHERE it stopped.
            injectImageResult = "no code: " + why
            errorMessage = L10n.addContactInvalidQr
        }
        guard let data = try? Data(contentsOf: url) else { return fail("file unreadable") }
        guard let cg = UIImage(data: data)?.cgImage else { return fail("not an image") }
        // The newest barcode revision (3) is ML-backed and fails on the simulator
        // with com.apple.Vision error 9; revision 1 (deprecated, still present) is the classic detector. Try
        // revision 3 first, then revision 1, so the seam keeps working on a device-like
        // runtime too.
        var results: [VNBarcodeObservation] = []
        var lastError: NSError? = nil
        for revision in [VNDetectBarcodesRequestRevision3, VNDetectBarcodesRequestRevision1] {
            let request = VNDetectBarcodesRequest()
            request.revision = revision
            request.symbologies = [.qr]
            do {
                try VNImageRequestHandler(cgImage: cg, options: [:]).perform([request])
                results = request.results ?? []
                lastError = nil
            } catch {
                lastError = error as NSError
                continue
            }
            if !results.isEmpty { break }
        }
        if let e = lastError, results.isEmpty { return fail("vision error \(e.domain) \(e.code)") }
        guard let payload = results.compactMap({ $0.payloadStringValue }).first else {
            return fail("vision found \(results.count) barcode(s), no payload")
        }
        injectImageResult = "decoded"
        // The camera's own write target — one code path from here on.
        scannedCode = payload
    }
    #endif

    @ViewBuilder
    private var scanInjectImageRow: some View {
        #if DEBUG && targetEnvironment(simulator)
        HStack(spacing: 8) {
            Button { decodeInjectedImage() } label: {
                Text("inject image")
                    .font(.runeCaption)
                    .foregroundColor(.black)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 8)
                    .background(Color.runTextPrimary)
                    .cornerRadius(8)
            }
            .accessibilityIdentifier("scan_inject_image")

            Text(injectImageResult)
                .font(.system(.caption2, design: .monospaced))
                .foregroundColor(Color.runTextSecondary)
                .accessibilityIdentifier("scan_inject_image_result")
        }
        .padding(.horizontal)
        #endif
    }

    // MARK: - Paste exchange (no-camera, reached via the hidden 5-tap gesture)

    @State private var pastedCode = ""

    private var codeExchangeForm: some View {
        ScrollView {
            VStack(spacing: 16) {
                // Your code (read-only, tap to copy)
                VStack(alignment: .leading, spacing: 6) {
                    Text(L10n.addContactYourCode)
                        .font(.runeFootnote)
                        .foregroundColor(Color(hex: 0x888888))

                    Text(myCodeBase64 ?? mintPlaceholder)
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundColor(Color.runTextPrimary)
                        .padding(10)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(Color.runSurface)
                        .cornerRadius(8)
                        .lineLimit(4)
                        .accessibilityIdentifier("debug_my_code")
                        .onTapGesture {
                            guard let code = myCodeBase64 else { return }
                            // #20: the 2 s clear is long enough to switch to the
                            // recipient app and paste, short enough that a
                            // foreground harvester has a tight window. The 20 s
                            // expiry is the backstop if the app is killed before
                            // the timer fires.
                            SensitivePasteboard.copy(code, expiresAfter: 20, clearAfter: 2)
                            copied = true
                            DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { copied = false }
                        }

                    if copied {
                        Text(L10n.addContactCopiedBang)
                            .font(.runeCaption2)
                            .foregroundColor(Color.runAccent)
                    }
                }
                .padding(.horizontal)

                Divider().background(Color.runDivider).padding(.horizontal)

                // Their code (paste field)
                VStack(alignment: .leading, spacing: 6) {
                    Text(L10n.addContactTheirCode)
                        .font(.runeFootnote)
                        .foregroundColor(Color(hex: 0x888888))

                    TextField(L10n.addContactPastePlaceholder, text: $pastedCode)
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundColor(Color.runTextPrimary)
                        .tint(Color.runAccent)
                        .autocorrectionDisabled(true)
                        .textInputAutocapitalization(.never)
                        .padding(10)
                        .background(Color.runSurface)
                        .cornerRadius(8)
                        .accessibilityIdentifier("debug_code_input")
                }
                .padding(.horizontal)

                if let err = errorMessage {
                    Text(err)
                        .font(.runeFootnote)
                        .foregroundColor(Color.runError)
                        .padding(.horizontal)
                        .accessibilityIdentifier("add_contact_error")
                }

                Button { addContactFromPastedCode() } label: {
                    Text(L10n.addContactTitle)
                        .font(.runeBody)
                        .foregroundColor(.white)
                        .frame(maxWidth: .infinity)
                        .padding()
                        .background(pastedCode.trimmingCharacters(in: .whitespaces).isEmpty
                                    ? Color(hex: 0x333333) : Color.runAccent)
                        .cornerRadius(12)
                }
                .disabled(pastedCode.trimmingCharacters(in: .whitespaces).isEmpty)
                .padding(.horizontal)
                .accessibilityIdentifier("debug_add_contact_button")
            }
            .padding(.top, 8)
        }
    }

    /// Base64-encoded version of myPayload for copy/paste exchange. Nil
    /// until mint completes; the paste tab shows [mintPlaceholder] until then.
    private var myCodeBase64: String? {
        guard let payload = myPayload else { return nil }
        return Data(payload.utf8).base64EncodedString()
    }

    /// Base64 of the INSTANT secret-only payload (`myShowPayload`) — the e2e
    /// scanner-injection seam's counterpart to [myCodeBase64], read off the Show
    /// step via `debug_instant_code`. Not mint-gated (nor is the QR it mirrors).
    private var myShowCodeBase64: String? {
        guard let payload = myShowPayload else { return nil }
        return Data(payload.utf8).base64EncodedString()
    }

    /// Placeholder shown in the paste tab's "Your code" block while mint is
    /// still running or has failed.
    private var mintPlaceholder: String {
        switch mintState {
        case .failed(let reason): return L10n.addContactMintFailedPrefix(reason)
        default: return L10n.addContactSettingUpInbox
        }
    }

    // MARK: - Logic

    /// The 1 Hz tick's work (see the `.onReceive(Timer…)` in body).
    private func onPairingTick() {
        pollScanBackPairing()
        rearmMintIfTransportReturned()
    }

    private func pollScanBackPairing() {
        // App Store 2.1(a) (1.6.13): while the Done step is in the
        // scan-back state the pairing completes OFF-SCREEN — the peer
        // scans our full code and their inbox reaches us as an in-band
        // announce applied by the background control sweep. Nothing pushes
        // that into this view, so ask the vault. POSITIVE evidence only
        // (contactFullyPaired = healthy AND sendable), never
        // !contactAwaitingPeerInbox, which also goes true on a stale row.
        // Two indexed lookups, and only while that one state is showing.
        // Android sibling: the announce-watch LaunchedEffect in
        // AddContactScreen.kt.
        if scanBackNeeded, let cid = pendingContactId, let vault = appState.vault,
           MessageManagerKt.contactFullyPaired(vault: vault, contactId: cid) {
            LogBuffer.shared.append(level: "D", tag: "AddContact",
                message: "[done] peer inbox arrived — pairing complete")
            // Success always wins over a failure notice shown earlier.
            pairingFailed = false
            peerInboxArrived = true
        } else if scanBackNeeded {
            // Key confirmation (one-time-bootstrap pairings): if the announce never
            // decrypts, say so and offer a fresh start. NOT terminal and deletes
            // nothing: this poll keeps running, so a later real message that decrypts
            // clears the notice and the success path above runs; the contact is
            // deleted only by the user's "Start again" tap. Positive evidence only;
            // false for a legacy contact. Android sibling: the waiting loop in
            // AddContactScreen.kt.
            if let cid = pendingContactId, let vault = appState.vault {
                let failedNow = MessageManagerKt.contactPairingFailed(vault: vault, contactId: cid)
                if failedNow != pairingFailed {
                    LogBuffer.shared.append(level: "D", tag: "AddContact",
                        message: "[done] pairing key confirmation failed=\(failedNow)")
                    pairingFailed = failedNow
                }
            }
            if !scanBackWaitLogged {
                scanBackWaitLogged = true
                LogBuffer.shared.append(level: "D", tag: "AddContact",
                    message: "[done] awaiting the peer's announce (scan-back)")
            }
            // The announce is applied by the background control sweep,
            // whose idle cadence is 60–90 s. Tick the convergence arm every
            // second while this state shows so the sweep runs FAST (and a
            // loop already asleep wakes) — measured 69 s → seconds
            // (2026-09-27, pairing-two-scan spec). Bounded per visit inside
            // MessageManager. Android sibling: the announce-watch
            // LaunchedEffect in AddContactScreen.kt.
            // Named: the sweep peeks THIS contact first (2026-10-26). Android sibling:
            // the announce-watch LaunchedEffect in AddContactScreen.kt.
            appState.controller.messageManager?.notePairingAwaitingPeer(contactId: pendingContactId)
        }
    }

    private func rearmMintIfTransportReturned() {
        if case .connected = appState.torState, mintWaitingForRelay {
            // RE-ARM (App Store 2.1(a), 1.6.13 "stuck on waiting"). The mint
            // has exactly TWO triggers: .onAppear and the torState EDGE in the
            // .onReceive above. Both are EDGES, and startMint's own bail —
            // `guard let mgr = controller.messageManager else { … =
            // .waitingForRelay }` — is reachable while torState is ALREADY
            // .connected (a relock/Tor-recycle drops the transport without a
            // state change; the @Published replay races the transport wiring at
            // view-appear). With no edge left to come, the screen parks on
            // "Setting up your inbox…" FOREVER: no pair, so no saveContact, no
            // announce POST and no contact row to poll — one device stuck on the
            // mint wait while the peer sits on "Waiting for their inbox…".
            //
            // Gated on the transport actually being back, so this is a level
            // trigger, not a spin: nothing happens on the tick that observes the
            // same nil. startMint() is idempotent (it returns immediately while
            // .solving/.ready), so it can never double-mint. Android's sibling is
            // AddContactScreen's `LaunchedEffect(torConnectedNow,
            // mintWaitingForRelay)` ticker, which bumps mintAttempt the same way.
            if appState.controller.messageManager != nil { startMint() }
        }
    }

    /// The mint is parked waiting for a relay transport.
    /// Android sibling: AddContactScreen's `mintWaitingForRelay`.
    private var mintWaitingForRelay: Bool {
        if case .waitingForRelay = mintState { return true }
        return false
    }

    /// The scan finished before the mint did (the finishing step is showing) and
    /// the contact has not been saved yet.
    private var readyToSaveContact: Bool {
        peerScan != nil && pendingContactId == nil && step == .finishing
    }

    /// Kicks off the background mint. Safe to call repeatedly (the previous
    /// solve, if any, is signalled via [mintAbort]). Never touches the
    /// secret half: it belongs to the pairing session and is NOT
    /// replaced on retry (see the note inside).
    private func startMint() {
        // Guard against re-entry. .onAppear and .onReceive(appState.transport.$torState)
        // can both fire in quick succession when AppState's torState happens
        // to already be .connected at view-appear time (the @Published
        // replays its current value on subscribe). Without this guard, two
        // detached Tasks race and double-mint.
        if case .solving = mintState { return }
        if case .ready = mintState { return }
        // A mint belongs to a live session — never an ended (wiped) one (G3).
        guard pairingSession == .active, pairing != nil else { return }

        mintAbort.cancelled = false
        // The session's half is NOT rotated here: it is created once per pairing
        // session (onAppear) because the instant secret-only Show QR carries
        // it — a mint retry must not invalidate a code the peer already
        // scanned. (The old per-attempt rotation predates the instant QR.)
        mintState = .solving

        // Capture appState's controller for use off the main thread. We can't
        // capture the Kotlin MessageManager directly because mintState may
        // be re-checked from the main actor; controller is immutable and
        // marked nonisolated(unsafe), see AppState.swift.
        let controller = appState.controller
        let token = mintAbort
        Task.detached(priority: .userInitiated) {
            guard let mgr = controller.messageManager else {
                await MainActor.run {
                    if case .solving = mintState { mintState = .waitingForRelay }
                }
                return
            }
            // Kotlin default args don't bridge — pass abort explicitly. The
            // relay now dictates difficulty via its challenge, so there is no
            // client-side bits argument.
            // TWO mints per pairing: text inbox + control inbox (v7), minted
            // SEQUENTIALLY in shared code (MessageManager.mintInboxPair) so iOS
            // and Android behave identically — one full-speed PoW grind at a
            // time. try? flattens the bridged suspend's optional/throws into a
            // single MintedInboxPair?.
            let pair: MintedInboxPair? = try? await mgr.mintInboxPair(abort: token)
            await MainActor.run {
                guard !token.cancelled else { return }
                // A nil `pair.grp` is a SUCCESSFUL pairing, not a failure: only the
                // optional third mint fell over, and the pairing then behaves
                // exactly like every one made before the group inbox existed until
                // the §1.6 backfill converges it. Failing here would throw away two
                // good inboxes, two completed grinds and the user's IRL moment.
                // Android does the same (AddContactScreen.kt) — keep them in step.
                if let pair = pair {
                    mintState = .ready(pair.main, pair.ctl, pair.grp)
                    // Scan finished before the mint did (the finishing step is
                    // showing) — complete the save now.
                    if readyToSaveContact {
                        completeSaveOrWait()
                    }
                } else {
                    mintState = .failed(L10n.addContactMintFailedRelay)
                }
            }
        }
    }

    private func handleScannedCode(_ code: String) {
        // The session (shared commonMain code) runs the IDENTICAL parse + validation as
        // Android: 32-byte secret, echo checks (our half, our inbox, our one-time key),
        // inbox/wcap + ctl pair shape, cap/inbox-id validity, a low-order `ek`. This
        // handler keeps only the iOS-specific UI bits: the secret-only deadlock guard.
        guard pairingSession == .active, let pairing = pairing,
              let scan = pairing.parsePeerCode(raw: code, myInboxId: myInboxId, requireFull: false) else {
            errorMessage = L10n.addContactInvalidQr
            return
        }
        // Deadlock guard: if we already showed our (secret-only) code and they
        // scanned back another secret-only code, two halves can't exchange inboxes.
        if scan.inboxId == nil && shown {
            errorMessage = L10n.addContactScanDeadlock
            return
        }
        errorMessage = nil
        LogBuffer.shared.append(level: "D", tag: "AddContact",
            message: "[scan] handleScannedCode received scan (full=\(scan.inboxId != nil))")
        peerInbox = scan.inboxId
        peerScan = scan
        completeSaveOrWait()
    }

    /// Saves if our mint is ready; otherwise parks on the finishing step —
    /// startMint's completion calls back here the moment .ready lands.
    private func completeSaveOrWait() {
        guard let scan = peerScan else { return }
        if case .ready(_, _, _) = mintState {
            saveContact(scan: scan, alias: "")
        } else {
            step = .finishing
        }
    }

    private func addContactFromPastedCode() {
        errorMessage = nil
        let trimmed = pastedCode.trimmingCharacters(in: .whitespaces)

        // The pasted code is base64-of-JSON (double-encoded); decode the outer
        // layer, then the session's parse does the validation. requireFull
        // rejects a secret-only code — the paste path always needs the inbox.
        guard pairingSession == .active, let pairing = pairing,
              let jsonData = Data(base64Encoded: trimmed),
              let jsonStr = String(data: jsonData, encoding: .utf8),
              let scan = pairing.parsePeerCode(raw: jsonStr, myInboxId: myInboxId, requireFull: true),
              scan.inboxId != nil, scan.writeCap != nil else {
            errorMessage = L10n.addContactInvalidCode
            return
        }
        guard case .ready(_, _, _) = mintState else {
            errorMessage = L10n.addContactPasteNotReady
            return
        }
        // Record the peer's parse in @State exactly as handleScannedCode does —
        // Android keeps ONE `scannedData` for both entry points and reads it back
        // for the Done step's role (`scanBackNeeded = scannedData?.inboxId == null`).
        // Without peerInbox set here the Done step would render the SCAN-BACK role
        // for a code exchange that had already announced in-band.
        peerInbox = scan.inboxId
        peerScan = scan
        saveContact(scan: scan, alias: "")
    }

    private func saveContact(scan: PairingScan, alias: String) {
        LogBuffer.shared.append(level: "D", tag: "AddContact",
            message: "[save] saveContact called: step=\(step)")
        guard let vault = appState.vault else { return }
        guard case .ready(let minted, let ctlMinted, let grpMinted) = mintState else { return }
        guard pendingContactId == nil else { return }  // idempotency latch (parity with Android)
        // Never pair from an ended session.
        guard pairingSession == .active, let pairing = pairing else { return }

        let contactId = UUID().uuidString
        let finalAlias = alias.isEmpty ? ContactNameGenerator.generate() : alias
        pendingAlias = finalAlias

        // ONE shared save: the session derives the pairing secret from both halves and
        // runs the one-time-bootstrap transaction iff the peer's code carried `ek`,
        // else the legacy one. It never throws and wipes its own derived copies; our
        // half and `scan` stay ours (a retry after INBOX_IN_USE reuses them). Kotlin
        // default arguments are not bridged, so every parameter is explicit; the group
        // pair is absent when the optional third mint failed (the supported legacy
        // shape the later backfill converges).
        let outcome = pairing.save(
            vault: vault,
            contactId: contactId,
            peer: scan,
            myInboxId: minted.inboxId,
            myReadCap: minted.readCapability,
            myCtlInboxId: ctlMinted.inboxId,
            myCtlReadCap: ctlMinted.readCapability,
            alias: finalAlias,
            mnemonic: "",
            myGrpInboxId: grpMinted?.inboxId,
            myGrpReadCap: grpMinted?.readCapability)

        if outcome == PairingSaveOutcome.inboxInUse {
            // The vault REFUSED the add: one of the peer's inbox ids is already owned
            // by a contact we hold. Nothing was written; the scan is kept for a retry.
            LogBuffer.shared.append(level: "W", tag: "Contacts",
                message: "add refused — an inbox id in the peer's code is already owned here")
            errorMessage = L10n.addContactInboxInUse
            return
        }
        if outcome == PairingSaveOutcome.invalidCode {
            // The peer's code is unusable: drop the scan and say so, instead of
            // leaving the wizard on a wait that cannot end.
            LogBuffer.shared.append(level: "W", tag: "Contacts", message: "add refused — the peer's code is unusable")
            peerScan = nil
            peerInbox = nil
            errorMessage = L10n.addContactInvalidCode
            if step == .finishing { step = .scan }
            return
        }
        if outcome == PairingSaveOutcome.startAgain {
            // Nothing was saved and this session cannot complete (its one-time key is
            // spent, or the write failed): a NEW session, with the reason shown.
            LogBuffer.shared.append(level: "E", tag: "Contacts", message: "failed to persist new contact — starting again")
            restartPairing(error: L10n.addContactStartAgainError)
            return
        }
        // savedV3 / savedLegacy: the success path.
        LogBuffer.shared.append(level: "D", tag: "Contacts", message: "contact added")

        // We scanned their FULL code, so we have a send channel — deliver our
        // own inbox in-band (they only saw our secret-only QR). Idempotent on
        // the receiving side; runs on AppState so it survives this sheet.
        if scan.inboxId != nil {
            appState.announceInbox(
                contactId: contactId,
                myInboxId: minted.inboxId,
                peerWriteCap: minted.writeCapability,
                myCtlInboxId: ctlMinted.inboxId,
                peerCtlWriteCap: ctlMinted.writeCapability,
                // Both nil when the optional third mint failed — `sendInboxAnnounce`
                // is both-or-neither per pair and simply omits `gib`/`gwc`.
                myGrpInboxId: grpMinted?.inboxId,
                peerGrpWriteCap: grpMinted?.writeCapability
            )
        }

        pendingContactId = contactId
        step = .done
        // The contact list only re-queries the vault on .contactsChanged, and the
        // only post used to be the Done BUTTON (ContentView) — so a second pairing
        // saved while the sheet is still up left the list behind it showing the OLD
        // row count. Post it at the moment the vault write commits instead; the Done
        // button still posts it too (that one also carries the mnemonic write).
        NotificationCenter.default.post(name: .contactsChanged, object: nil)
        // The session stays alive until the screen leaves: the scan-first Done step
        // still builds OUR full code from it for the peer to scan back, and its half
        // and one-time key are wiped in place by `end()` in .onDisappear. The parsed
        // scan is only text now; drop our reference. show-first: the mint snapshot
        // (read caps) is dead already — drop it to shrink the live window.
        peerScan = nil
        if scan.inboxId != nil { dropMintSnapshot() }
    }

    /// "Start again" after a failed key confirmation: delete the half-made contact
    /// through the shared purge path (local delete first, then a best-effort relay
    /// DELETE of both inbound inboxes), then begin a NEW pairing session in this same
    /// screen. Runs ONLY from the user's tap. Android sibling: startAgainAfterFailure.
    private func startAgainAfterFailure() {
        if let cid = pendingContactId {
            Task { @MainActor in
                _ = await appState.deleteContactPurgingRelay(contactId: cid)
                NotificationCenter.default.post(name: .contactsChanged, object: nil)
            }
        }
        restartPairing(error: nil)
    }

    /// A real end of this session and a NEW one in the same screen (fresh half, fresh
    /// one-time key, wizard back at .choice); [error] is shown afterwards.
    private func restartPairing(error: String?) {
        resetForNewPairingSession()
        pairing = PairingSession.companion.start()
        pairingSession = .active
        startMint()
        errorMessage = error
    }

    /// The deliberate way out of the scan-back state (App Store 2.1(a), 1.6.13):
    /// delete the half-finished contact — shared path, so the LOCAL delete is
    /// the gate and both inbound inboxes are then best-effort DELETEd on the relay
    /// — and leave. Without it, abandoning the pairing would strand exactly the
    /// permanently un-completable "Waiting for their inbox…" row this whole change
    /// exists to prevent.
    ///
    /// The delete runs in an UNSTRUCTURED Task so it survives this sheet going
    /// away (the relay round-trips go over Tor and can take seconds); the contact
    /// list refreshes on the `.contactsChanged` post when it lands. Android pops
    /// from `deleteContactInBackground`'s local-delete callback instead — that
    /// hook is not exposed across the Swift bridge, so the row can linger for a
    /// moment here. Same outcome, same shared purge.
    private func cancelPairingAndLeave() {
        guard let cid = pendingContactId else { onDismiss(); return }
        pendingContactId = nil
        Task { @MainActor in
            _ = await appState.deleteContactPurgingRelay(contactId: cid)
            NotificationCenter.default.post(name: .contactsChanged, object: nil)
        }
        onDismiss()
    }

    private func saveMnemonicAndDismiss() {
        LogBuffer.shared.append(level: "D", tag: "AddContact",
            message: "[save] saveMnemonicAndDismiss → step=.done")
        if let vault = appState.vault,
           let contactId = pendingContactId,
           !mnemonic.trimmingCharacters(in: .whitespaces).isEmpty {
            // Shared read-modify-write in commonMain (ContactEdits) preserves
            // the shared secret + anti-replay state — no hand-copied fields.
            ContactEdits.shared.updateMnemonic(vault: vault, contactId: contactId, mnemonic: mnemonic)
        }
        mnemonic = ""
        pendingContactId = nil
        step = .done
    }

    // MARK: - Helpers

    // (the write-cap validity check moved to the shared PairingPayload.isValidCap
    // in commonMain — one validator for both platforms; the local copy is gone.)

    /// Drops the mint snapshot (our inbox read caps) once it is no longer needed.
    /// `.failed("")` is chosen over `.waitingForRelay` so it can never re-trigger
    /// startMint() via the torState .onReceive.
    private func dropMintSnapshot() {
        guard case .ready = mintState else { return }
        mintState = .failed("")
    }

    /// G3's appear rule, as a pure function of the phase. Never "regenerate when
    /// empty": a wiped half is 32 zero bytes, and a half regenerated into a live
    /// session would differ from the one the peer may already have scanned.
    static func pairingSessionOnAppear(_ phase: PairingSessionPhase) -> PairingSessionAppearAction {
        switch phase {
        case .notStarted: return .startFirstSession
        case .active:     return .keepSession
        case .ended:      return .startNewSession
        }
    }

    /// An .onAppear on this instance AFTER a real leave ended its session: the old
    /// half is gone, so nothing of that session may carry over into the new one —
    /// not its wizard step, its scanned peer half, its saved-contact latch, nor its
    /// mint (a fresh token, so the old detached Task's result is dropped by its
    /// `guard !token.cancelled`; .solving/.failed("") from the leave are cleared so
    /// startMint runs again). The wizard visibly restarts at .choice. Leaves
    /// `pairingSession == .notStarted`; .onAppear then generates the new half.
    private func resetForNewPairingSession() {
        mintAbort.cancelled = true
        mintAbort = MintCancelToken()
        // Ends the old session (zeroes its half and one-time key in place).
        pairing?.end()
        pairing = nil
        peerScan = nil
        pairingFailed = false
        mintState = .waitingForRelay
        mintProgress = 0.06
        step = .choice
        errorMessage = nil
        copied = false
        shown = false
        scannedCode = nil
        peerInbox = nil
        pasteTapCount = 0
        pendingContactId = nil
        mnemonic = ""
        pendingAlias = ""
        peerInboxArrived = false
        scanBackWaitLogged = false
        showCancelPairing = false
        injectedScanCode = ""
        pastedCode = ""
        pairingSession = .notStarted
    }
}


// MARK: - QR Scanner View

/// Internal (was file-private): "Move to new device" reuses the SAME scanner on
/// the new phone's MoveFromDeviceView — one camera/AVFoundation path for both QR
/// flows rather than a second copy that could drift.
struct QRScannerView: UIViewControllerRepresentable {
    @Binding var scannedCode: String?

    func makeUIViewController(context: Context) -> QRScannerViewController {
        let controller = QRScannerViewController()
        controller.delegate = context.coordinator
        return controller
    }

    func updateUIViewController(_ uiViewController: QRScannerViewController, context: Context) {}

    func makeCoordinator() -> Coordinator {
        Coordinator(scannedCode: $scannedCode)
    }

    class Coordinator: NSObject, QRScannerDelegate {
        @Binding var scannedCode: String?

        init(scannedCode: Binding<String?>) {
            _scannedCode = scannedCode
        }

        func didScanCode(_ code: String) {
            scannedCode = code
        }
    }
}

protocol QRScannerDelegate: AnyObject {
    func didScanCode(_ code: String)
}

class QRScannerViewController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    weak var delegate: QRScannerDelegate?
    private var captureSession: AVCaptureSession?
    private var previewLayer: AVCaptureVideoPreviewLayer?

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = UIColor(red: 0.05, green: 0.05, blue: 0.05, alpha: 1)
        checkCameraPermission()
    }

    private func checkCameraPermission() {
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized:
            setupCamera()
        case .notDetermined:
            AVCaptureDevice.requestAccess(for: .video) { [weak self] granted in
                DispatchQueue.main.async {
                    if granted { self?.setupCamera() }
                }
            }
        default:
            break
        }
    }

    private func setupCamera() {
        captureSession = AVCaptureSession()

        guard let videoCaptureDevice = AVCaptureDevice.default(for: .video) else { return }

        do {
            let videoInput = try AVCaptureDeviceInput(device: videoCaptureDevice)
            if captureSession?.canAddInput(videoInput) == true {
                captureSession?.addInput(videoInput)
            } else { return }
        } catch { return }

        let metadataOutput = AVCaptureMetadataOutput()

        if captureSession?.canAddOutput(metadataOutput) == true {
            captureSession?.addOutput(metadataOutput)
            metadataOutput.setMetadataObjectsDelegate(self, queue: DispatchQueue.main)
            metadataOutput.metadataObjectTypes = [.qr]
        } else { return }

        guard let session = captureSession else { return }
        let layer = AVCaptureVideoPreviewLayer(session: session)
        layer.frame = view.layer.bounds
        layer.videoGravity = .resizeAspectFill
        previewLayer = layer
        view.layer.addSublayer(layer)

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            self?.captureSession?.startRunning()
        }
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        previewLayer?.frame = view.layer.bounds
    }

    private var lastScannedCode: String?

    func metadataOutput(_ output: AVCaptureMetadataOutput, didOutput metadataObjects: [AVMetadataObject], from connection: AVCaptureConnection) {
        // Do NOT stop the session on every detected QR. A
        // rejected code (a random URL/WiFi QR, or the peer's secret-only code at the
        // wrong step) used to freeze the preview permanently — re-aiming did nothing
        // until Back→Scan rebuilt the VC. Keep scanning; dedupe by value so a held
        // code fires once, and let viewWillDisappear stop the session when an
        // ACCEPTED scan navigates away.
        guard let metadataObject = metadataObjects.first,
              let readableObject = metadataObject as? AVMetadataMachineReadableCodeObject,
              let stringValue = readableObject.stringValue,
              stringValue != lastScannedCode else { return }
        lastScannedCode = stringValue
        AudioServicesPlaySystemSound(SystemSoundID(kSystemSoundID_Vibrate))
        delegate?.didScanCode(stringValue)
    }

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        if captureSession?.isRunning == true {
            captureSession?.stopRunning()
        }
    }
}


// MARK: - Crisp QR tiles
//
// CoreImage makes the code at ONE pixel per module. The old tiles scaled it 10x and let
// SwiftUI draw that at 220/200 pt, i.e. a non-integer number of device pixels per module:
// hard edges (interpolation .none) but uneven module widths, which a camera has to undo.
// Here every module is a whole number of DEVICE pixels: the image keeps 1 px per module and
// is drawn at exactly `modules x pxPerModule` device pixels. The white quiet zone is brought
// up to 4 modules on every side (CoreImage's own margin counts), also in whole pixels.
// Android sibling: QrBitmap.kt (renderQrPixels / CrispQrImage).
struct CrispQR {
    let image: UIImage
    /// Drawn side of the code image, in points (a whole number of device pixels).
    let imagePoints: CGFloat
    /// White padding on every side, in points (a whole number of device pixels).
    let padPoints: CGFloat

    /// The largest crisp tile (code + quiet zone) that fits `tilePoints`.
    static func make(from string: String, tilePoints: CGFloat, displayScale: CGFloat, quietModules: Int = 4) -> CrispQR? {
        guard !string.isEmpty else { return nil }
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(string.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage,
              let cg = CIContext().createCGImage(output, from: output.extent) else { return nil }
        let modules = cg.width
        let extra = max(0, quietModules - firstDarkOffset(cg))
        let totalModules = modules + 2 * extra
        let scale = max(displayScale, 1)
        let pxPerModule = max(1, Int((tilePoints * scale / CGFloat(totalModules)).rounded(.down)))
        return CrispQR(
            image: UIImage(cgImage: cg, scale: 1, orientation: .up),
            imagePoints: CGFloat(modules * pxPerModule) / scale,
            padPoints: CGFloat(extra * pxPerModule) / scale)
    }

    /// Light margin the generator itself leaves around the code, in modules.
    private static func firstDarkOffset(_ cg: CGImage) -> Int {
        let w = cg.width, h = cg.height
        var data = [UInt8](repeating: 255, count: w * h)
        guard let ctx = CGContext(data: &data, width: w, height: h, bitsPerComponent: 8, bytesPerRow: w,
                                  space: CGColorSpaceCreateDeviceGray(), bitmapInfo: CGImageAlphaInfo.none.rawValue) else { return 0 }
        ctx.draw(cg, in: CGRect(x: 0, y: 0, width: w, height: h))
        var offset = min(w, h)
        for y in 0..<h {
            for x in 0..<w where data[y * w + x] < 128 {
                offset = min(offset, min(x, y))
                break
            }
        }
        return offset
    }
}

/// White rounded tile with the code drawn unfiltered at whole pixels per module.
struct CrispQRView: View {
    let qr: CrispQR
    var body: some View {
        Image(uiImage: qr.image)
            .interpolation(.none)
            .resizable()
            .frame(width: qr.imagePoints, height: qr.imagePoints)
            .padding(qr.padPoints)
            .background(Color.white)
            .cornerRadius(12)
    }
}

import SwiftUI
import CoreImage.CIFilterBuiltins
import AVFoundation
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
    // (text inbox, CONTROL inbox, GROUP-text inbox, our 32-byte secret half).
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
    case ready(MintedInbox, MintedInbox, MintedInbox?, Data)
    case failed(String)
}

struct AddContactView: View {
    @EnvironmentObject private var appState: AppState
    let onDismiss: () -> Void

    @State private var step: AddStep = .choice
    @State private var errorMessage: String? = nil

    // Mint pipeline. mySecret is regenerated once per screen open; the
    // (inboxId, writeCap) come back from the relay via mintInbox().
    @State private var mySecret: Data = Data()
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
    @State private var peerWriteCap: String? = nil
    @State private var peerCtlInbox: String? = nil
    @State private var peerCtlWriteCap: String? = nil
    @State private var peerGrpInbox: String? = nil
    @State private var peerGrpWriteCap: String? = nil
    @State private var peerSecret: Data? = nil
    // The scanned/pasted code carried `"rv":"2"`, i.e. the peer runs
    // the secret-order ratchet-role rule. Recorded here so saveContact can persist
    // the role inputs in the pairing transaction; false (a pre-A peer, or a scan
    // that never set it) keeps BOTH devices on the legacy id-order rule.
    @State private var peerRoleRuleV2 = false

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
        if case .ready(let m, _, _, _) = mintState { return m.inboxId }
        return nil
    }
    /// SECRET-ONLY payload for the Show step — renders INSTANTLY, before the
    /// mint. The peer saves us as a pending contact; our inbox reaches them
    /// in-band afterwards (sendInboxAnnounce). This removes the "Setting up
    /// inbox…" wait while two people stand next to each other.
    private var myShowPayload: String? {
        guard !mySecret.isEmpty else { return nil }
        // Shared codec (PairingPayload) — both platforms build the identical wire format.
        return PairingPayload.shared.buildSecretOnly(secretB64: mySecret.base64EncodedString())
    }
    /// FULL payload (inbox + writeCap + secret) for the Done step and the
    /// paste exchange — mint-gated: the Done-step code is the one the peer
    /// scans back, so it must carry the inbox.
    private var myPayload: String? {
        guard case .ready(let m, let ctl, let grp, let secret) = mintState else { return nil }
        // gib/gwcap appended LAST — Kotlin default args don't bridge, so every
        // parameter is explicit (§1.4). BOTH-OR-NEITHER: with no group inbox the
        // code is byte-identical to a pre-§1.4 one, which is exactly what an old
        // build emits and what `PairingPayload.parse` reads back as `grp = null`.
        return PairingPayload.shared.buildFull(
            inboxId: m.inboxId, writeCap: m.writeCapability,
            ctlInboxId: ctl.inboxId, ctlWriteCap: ctl.writeCapability,
            secretB64: secret.base64EncodedString(),
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
                    case .done:      doneStep
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
                // One stable secret per screen session — the instant Show QR
                // carries it, so it must NOT rotate while the peer may already
                // have scanned it (the old per-mint-retry rotation predates the
                // secret-only QR).
                if mySecret.isEmpty { mySecret = generateRandomBytes(count: 32) }
                startMint()
            }
            .onDisappear {
                // Flip the abort flag so the background solve exits promptly
                // when the user backs out mid-pairing.
                mintAbort.cancelled = true
                // Zero the pairing secret
                // originals on EVERY exit from this screen, not only a completed
                // save — this is the backstop for Back/Cancel mid-flow (a
                // successful save already zeroes them itself, see saveContact()).
                // Safe unconditionally here: the screen is going away, so there is
                // no retry left that could still need the original bytes.
                secureZero(&mySecret)
                peerSecret?.withUnsafeMutableBytes { buf in
                    _ = memset_s(buf.baseAddress, buf.count, 0, buf.count)
                }
                peerSecret = nil
                // mySecret's zero above only forks
                // OUR alias; mintState.ready still owns the original buffer (kept
                // live for the scan-first role's Done QR). The screen is leaving,
                // so that snapshot is done — zero it now. MUST run AFTER
                // secureZero(&mySecret) so wipeMintSecret's local is sole owner.
                wipeMintSecret()
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
                        peerSecret = nil
                        // The peer's role-rule marker belongs to
                        // the scan being discarded — a later scan of an OLD
                        // build's code must not inherit this one's `rv:2`.
                        peerRoleRuleV2 = false
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
                Spacer().frame(height: 24)
                choiceButton(title: L10n.addContactChoiceShow, id: "add_choice_show") { step = .show }
                choiceButton(title: L10n.addContactChoiceScan, id: "add_choice_scan") { step = .scan }
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

            if let payload = myShowPayload, let qrImage = generateQRCode(from: payload) {
                Image(uiImage: qrImage)
                    .interpolation(.none)
                    .resizable()
                    .scaledToFit()
                    .frame(width: 220, height: 220)
                    .padding()
                    .background(Color.white)
                    .cornerRadius(12)
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
                if peerSecret != nil { completeSaveOrWait() } else { step = .scan }
            } label: {
                Text(peerSecret != nil ? L10n.addContactNext : L10n.addContactShowFirstIos)
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
                    if let payload = myPayload, let qrImage = generateQRCode(from: payload) {
                        Image(uiImage: qrImage)
                            .interpolation(.none)
                            .resizable()
                            .scaledToFit()
                            .frame(width: 200, height: 200)
                            .padding(8)
                            .background(Color.white)
                            .cornerRadius(12)
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

    // MARK: - Scan Code tab

    private var scanCodeTab: some View {
        VStack(spacing: 16) {
            Text(L10n.addContactScanHeading)
                .font(.runeFootnote)
                .foregroundColor(Color.runTextSecondary)
                .padding(.top, 4)

            scanInjectRow

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
            peerInboxArrived = true
        } else if scanBackNeeded {
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
        peerSecret != nil && pendingContactId == nil && step == .finishing
    }

    /// Kicks off the background mint. Safe to call repeatedly (the previous
    /// solve, if any, is signalled via [mintAbort]). Generates a fresh
    /// 32-byte secret per attempt — the mySecret half is intentionally
    /// epoch-bound to this pairing session and is replaced on retry.
    private func startMint() {
        // Guard against re-entry. .onAppear and .onReceive(appState.transport.$torState)
        // can both fire in quick succession when AppState's torState happens
        // to already be .connected at view-appear time (the @Published
        // replays its current value on subscribe). Without this guard, two
        // detached Tasks race and double-mint.
        if case .solving = mintState { return }
        if case .ready = mintState { return }

        mintAbort.cancelled = false
        // mySecret is NOT rotated here: it is generated once per screen
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
                    mintState = .ready(pair.main, pair.ctl, pair.grp, mySecret)
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
        // The shared codec (PairingPayload, commonMain) runs the IDENTICAL
        // parse + validation as Android (32-byte secret, echo checks, inbox/wcap +
        // ctl pair shape, cap/inbox-id validity). This handler keeps only the
        // iOS-specific UI bits: the secret-only deadlock guard + peer-field wiring.
        guard let scan = PairingPayload.shared.parse(
                  raw: code, myInboxId: myInboxId,
                  mySecretB64: mySecret.base64EncodedString(), requireFull: false),
              let secret = Data(base64Encoded: scan.secretB64) else {
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
        peerWriteCap = scan.writeCap
        peerCtlInbox = scan.ctlInboxId
        peerCtlWriteCap = scan.ctlWriteCap
        peerGrpInbox = scan.grpInboxId
        peerGrpWriteCap = scan.grpWriteCap
        peerSecret = secret
        peerRoleRuleV2 = scan.roleRuleV2
        completeSaveOrWait()
    }

    /// Saves if our mint is ready; otherwise parks on the finishing step —
    /// startMint's completion calls back here the moment .ready lands.
    private func completeSaveOrWait() {
        guard let secret = peerSecret else { return }
        if case .ready(_, _, _, _) = mintState {
            saveContact(peerInboxId: peerInbox, peerWriteCap: peerWriteCap,
                        peerCtlInboxId: peerCtlInbox, peerCtlWriteCap: peerCtlWriteCap,
                        peerGrpInboxId: peerGrpInbox, peerGrpWriteCap: peerGrpWriteCap,
                        peerSecret: secret, alias: "")
        } else {
            step = .finishing
        }
    }

    private func addContactFromPastedCode() {
        errorMessage = nil
        let trimmed = pastedCode.trimmingCharacters(in: .whitespaces)

        // The pasted code is base64-of-JSON (double-encoded); decode the outer
        // layer, then B3's shared codec does the parse + validation. requireFull
        // rejects a secret-only code — the paste path always needs the inbox.
        guard let jsonData = Data(base64Encoded: trimmed),
              let jsonStr = String(data: jsonData, encoding: .utf8),
              let scan = PairingPayload.shared.parse(
                  raw: jsonStr, myInboxId: myInboxId,
                  mySecretB64: mySecret.base64EncodedString(), requireFull: true),
              let scannedInbox = scan.inboxId,
              let scannedWriteCap = scan.writeCap,
              let scannedSecret = Data(base64Encoded: scan.secretB64) else {
            errorMessage = L10n.addContactInvalidCode
            return
        }
        guard case .ready(_, _, _, _) = mintState else {
            errorMessage = L10n.addContactPasteNotReady
            return
        }
        // Record the peer halves in @State exactly as handleScannedCode does —
        // Android keeps ONE `scannedData` for both entry points and reads it back
        // for the Done step's role (`scanBackNeeded = scannedData?.inboxId == null`).
        // These used to be shadowed by the guard's locals, so the paste path left
        // @State peerInbox nil and the Done step rendered the SCAN-BACK role ("Have
        // your contact scan this…") for a code exchange that had already announced
        // in-band — and, because that role's QR reads mintState, which saveContact
        // wipes on this very path, it rendered that instruction over a BLANK space.
        peerInbox = scannedInbox
        peerWriteCap = scannedWriteCap
        peerCtlInbox = scan.ctlInboxId
        peerCtlWriteCap = scan.ctlWriteCap
        peerGrpInbox = scan.grpInboxId
        peerGrpWriteCap = scan.grpWriteCap
        peerSecret = scannedSecret
        peerRoleRuleV2 = scan.roleRuleV2
        saveContact(peerInboxId: scannedInbox, peerWriteCap: scannedWriteCap,
                    peerCtlInboxId: scan.ctlInboxId, peerCtlWriteCap: scan.ctlWriteCap,
                    peerGrpInboxId: scan.grpInboxId, peerGrpWriteCap: scan.grpWriteCap,
                    peerSecret: scannedSecret, alias: "")
    }

    private func saveContact(peerInboxId: String?, peerWriteCap: String?,
                             peerCtlInboxId: String?, peerCtlWriteCap: String?,
                             peerGrpInboxId: String?, peerGrpWriteCap: String?,
                             peerSecret: Data, alias: String) {
        LogBuffer.shared.append(level: "D", tag: "AddContact",
            message: "[save] saveContact called: step=\(step)")
        guard let vault = appState.vault else { return }
        guard case .ready(let minted, let ctlMinted, let grpMinted, _) = mintState else { return }
        guard pendingContactId == nil else { return }  // idempotency latch (parity with Android)

        let contactId = UUID().uuidString
        let finalAlias = alias.isEmpty ? ContactNameGenerator.generate() : alias
        pendingAlias = finalAlias

        // Derive shared secret from both parties' secrets (lexicographic sort + SHA-256)
        let mySecretArray = kotlinByteArray(from: mySecret)
        let peerSecretArray = kotlinByteArray(from: peerSecret)
        let sharedSecret = PlatformCryptoKt.deriveSharedSecret(
            secretA: mySecretArray,
            secretB: peerSecretArray
        )
        // These three are pure derived
        // work buffers rebuilt fresh from mySecret/peerSecret on every call, so
        // it's safe to wipe them unconditionally on exit — success OR a failed
        // vault write (defer runs either way). secureWipe() is the same
        // commonMain fill(0) used at every other key-teardown site (RatchetManager,
        // VaultSelector, DoubleRatchet, ...).
        //
        // The peer pairing secret itself is NOT wiped in this defer: the
        // failure path must keep it live for a retry, and the earlier
        // secureZero(&peerSecret) was in any case a COW no-op (it forked a throwaway
        // copy — see the success-path wipe below). It is zeroed only on the
        // committed-write success path, at its shared backing store.
        defer {
            mySecretArray.secureWipe()
            peerSecretArray.secureWipe()
            sharedSecret.secureWipe()
        }

        // The whole vault transaction (contact + 4 inbox rows + ratchet
        // marker, reading VaultSeedDefaults for trustLevel/lifetime — no more
        // hardcoded 0 / 86_400_000*365) runs in commonMain. @Throws bridges to a
        // Swift `try`; a write failure aborts the add fail-closed.
        do {
            try PairingVault.shared.savePairedContact(
                vault: vault,
                contactId: contactId,
                sharedSecret: sharedSecret,
                peerInboxId: peerInboxId,
                peerWriteCap: peerWriteCap,
                peerCtlInboxId: peerCtlInboxId,
                peerCtlWriteCap: peerCtlWriteCap,
                myInboxId: minted.inboxId,
                myReadCap: minted.readCapability,
                myCtlInboxId: ctlMinted.inboxId,
                myCtlReadCap: ctlMinted.readCapability,
                alias: finalAlias,
                mnemonic: "",
                // The two pairing-secret halves + the peer's `rv:2`
                // marker. savePairedContact uses them ONCE, inside the same
                // transaction, to persist a single ordering bit that fixes the
                // ratchet role immutably — neither half is stored, and the defer
                // above still owns the wipe of these Kotlin-side copies. Kotlin
                // default arguments are not bridged, so every parameter is explicit.
                mySecretHalf: mySecretArray,
                peerSecretHalf: peerSecretArray,
                peerRoleRuleV2: peerRoleRuleV2,
                // The GROUP-text inbox pair (§2.1) — appended LAST, same
                // both-or-neither rule as the ctl pair above. Kotlin default
                // arguments are not bridged, so every parameter is explicit.
                peerGrpInboxId: peerGrpInboxId,
                peerGrpWriteCap: peerGrpWriteCap,
                // Absent when the optional third mint failed: `savePairedContact`
                // then writes no inbound-grp row, which is the supported legacy
                // shape the §1.6 backfill converges later.
                myGrpInboxId: grpMinted?.inboxId,
                myGrpReadCap: grpMinted?.readCapability)
        } catch {
            // A Kotlin @Throws bridges as an NSError carrying the original
            // KotlinThrowable under "KotlinException". InboxInUseException means the
            // vault REFUSED the add because one of the peer's inbox ids is already
            // owned by a contact we hold (`inbox_ids` is keyed by inboxId with
            // replace-on-conflict, so accepting would have destroyed that route).
            // Nothing was written. Surface it instead of dead-ending silently; every
            // other write failure keeps the previous log-and-return behaviour.
            //
            // The peer secret is deliberately NOT wiped on this path — same rule as
            // the comment below: a failed write keeps it live for a retry.
            if (error as NSError).userInfo["KotlinException"] is InboxInUseException {
                LogBuffer.shared.append(level: "W", tag: "Contacts",
                    message: "add refused — an inbox id in the peer's code is already owned here")
                errorMessage = L10n.addContactInboxInUse
            } else {
                LogBuffer.shared.append(level: "E", tag: "Contacts", message: "failed to persist new contact — add aborted")
            }
            return
        }
        LogBuffer.shared.append(level: "D", tag: "Contacts", message: "contact added")

        // We scanned their FULL code, so we have a send channel — deliver our
        // own inbox in-band (they only saw our secret-only QR). Idempotent on
        // the receiving side; runs on AppState so it survives this sheet.
        if peerInboxId != nil {
            appState.announceInbox(
                contactId: contactId,
                myInboxId: minted.inboxId,
                peerWriteCap: minted.writeCapability,
                myCtlInboxId: ctlMinted.inboxId,
                peerCtlWriteCap: ctlMinted.writeCapability,
                // Both nil when the optional third mint failed — `sendInboxAnnounce`
                // is both-or-neither per pair and simply omits `gib`/`gwc`, which is
                // the announce an old build sends and the one the §1.6 backfill
                // replaces later.
                myGrpInboxId: grpMinted?.inboxId,
                peerGrpWriteCap: grpMinted?.writeCapability
            )
        }

        pendingContactId = contactId
        step = .done
        // The contact list only re-queries the vault on .contactsChanged, and the
        // only post used to be the Done BUTTON (ContentView) — so a second pairing
        // saved while the sheet is still up left the list behind it showing the OLD
        // row count, which reads exactly like "the add was dropped" (it was not: a
        // re-pair is a second, independent ContactRecord by design — see
        // PairingVault.savePairedContact + RepairWhileAlreadyPairedTest). Post it at
        // the moment the vault write commits instead; the Done button still posts it
        // too (that one also carries the mnemonic write).
        NotificationCenter.default.post(name: .contactsChanged, object: nil)
        // The vault write landed, so
        // mySecret/peerSecret have done their job for this screen — once
        // step == .done the toolbar swaps to "Done" (no Back), and none of
        // showStep/scanCodeTab/codeExchangeForm (the only readers of these two)
        // render again. Zero them now rather than waiting for dismissal.
        //
        // mintState's own COW snapshot of mySecret (captured in startMint) is a
        // SEPARATE alias of the same buffer: because Data is copy-on-write,
        // secureZero(&mySecret) below forks OUR @State reference and leaves
        // mintState's original buffer holding the live secret. Round 3's comment
        // wrongly claimed .onDisappear closed that; it now actually does, via
        // wipeMintSecret() (COW-safe: it drops mintState's reference so its own
        // local is the sole owner before zeroing).
        //
        // Whether we can also wipe it HERE depends on the role:
        //   - show-first (peerInboxId != nil): the Done screen delivers our inbox
        //     in-band and never renders myPayload, so mintState's secret is dead
        //     already — wipe it now to shrink the live window (done below).
        //   - scan-first (peerInboxId == nil): the Done screen renders OUR full
        //     code (myPayload, which reads mintState's secret) for the peer to
        //     scan back, so the snapshot MUST stay live until the screen leaves;
        //     .onDisappear's wipeMintSecret() zeros it then.
        //
        // A fully alias-proof wipe of every transient Swift `Data` copy along this
        // call chain (handleScannedCode's/completeSaveOrWait's short-lived locals)
        // isn't achievable without a single-owner mutable buffer type — out of
        // scope, same accepted limitation as TorManager's "best-effort wipe". (The
        // `first + second` concat inside commonMain's deriveSharedSecret is a plain
        // Kotlin ByteArray and IS wiped there.) Deliberately NOT done on the catch-and-return failure path above:
        // a failed write leaves these intact so a retry can regenerate them.
        secureZero(&mySecret)
        // Zero the peer pairing secret's REAL backing store.
        // `peerSecret` (the parameter) is a copy-on-write ALIAS of the caller's buffer —
        // @State self.peerSecret plus the completeSaveOrWait/handleScannedCode stack
        // locals on the scan path, or addContactFromPastedCode's freshly-decoded local on
        // the debug paste path (where self.peerSecret is nil, so the earlier self.peerSecret
        // wipe was a total no-op). withUnsafeMutableBytes / secureZero(&) FORK a throwaway
        // copy whenever the storage is non-unique — which it always is here, with live
        // aliases up the call stack — and zero that fork, leaving the real secret resident.
        // secureZeroSharedStorage takes a READ-ONLY withUnsafeBytes view (no COW fork) and
        // memsets the ONE shared buffer every alias points at, so the secret leaves RAM for
        // all of them. Success path only (the failure path returned earlier, preserving the
        // secret for retry); none of these aliases is read again on success.
        secureZeroSharedStorage(peerSecret)
        self.peerSecret = nil
        // show-first only — see role note above. MUST run AFTER secureZero(&mySecret)
        // so wipeMintSecret's local is the sole owner of the shared buffer.
        if peerInboxId != nil { wipeMintSecret() }
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

    // MARK: - QR Code generation

    private func generateQRCode(from string: String) -> UIImage? {
        let context = CIContext()
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(string.utf8)
        filter.correctionLevel = "M"

        guard let outputImage = filter.outputImage else { return nil }
        let scaledImage = outputImage.transformed(by: CGAffineTransform(scaleX: 10, y: 10))
        guard let cgImage = context.createCGImage(scaledImage, from: scaledImage.extent) else { return nil }
        return UIImage(cgImage: cgImage)
    }

    // MARK: - Helpers

    // (the write-cap validity check moved to the shared PairingPayload.isValidCap
    // in commonMain — one validator for both platforms; the local copy is gone.)

    private func generateRandomBytes(count: Int) -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        let status = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        // Fail CLOSED: never return the zero buffer as a pairing secret — a
        // SecRandomCopyBytes failure would yield a predictable shared secret.
        // Abort instead (parity with the Kotlin generateSecureRandom fix).
        precondition(status == errSecSuccess, "SecRandomCopyBytes failed (status=\(status))")
        return Data(bytes)
    }

    /// Zeroizes [data]'s bytes IN PLACE via memset_s — not a plain loop, since a
    /// store to a buffer that's never read again is a dead store the optimizer
    /// can strip under -O, leaving the plaintext resident. Same idiom as
    /// SwiftDatabaseBridge's PRAGMA-key wipe.
    /// Only erases the actual original bytes when [data] is the SOLE live
    /// reference to its storage — Swift's Data is copy-on-write, so a still-live
    /// alias elsewhere forks a fresh buffer to zero instead; see callers for
    /// where that is a known limitation and why.
    private func secureZero(_ data: inout Data) {
        data.withUnsafeMutableBytes { buf in
            _ = memset_s(buf.baseAddress, buf.count, 0, buf.count)
        }
    }

    /// Zeroes a Data's ACTUAL backing store even when it is shared with other live
    /// copy-on-write aliases. `secureZero(inout Data)` mutates through
    /// `withUnsafeMutableBytes`, which forks a fresh buffer whenever the storage is
    /// NOT uniquely referenced — zeroing a throwaway copy and leaving the real
    /// secret resident. `withUnsafeBytes` gives a
    /// READ-ONLY view that never triggers copy-on-write, so its base pointer is the
    /// single buffer every alias references; memset_s through it (not a plain loop —
    /// that would be a strippable dead store) erases the secret for all of them at
    /// once. Only call when no alias will be READ again — every read after this
    /// would observe zeros.
    private func secureZeroSharedStorage(_ data: Data) {
        data.withUnsafeBytes { raw in
            guard let base = raw.baseAddress, raw.count > 0 else { return }
            _ = memset_s(UnsafeMutableRawPointer(mutating: base), raw.count, 0, raw.count)
        }
    }

    /// COW-safe wipe of the 32-byte pairing secret snapshotted inside
    /// `mintState.ready` (the incomplete-fix
    /// follow-up to the earlier mySecret wipe). The `.ready` case captured `mySecret` at mint
    /// time (startMint); because Swift `Data` is copy-on-write that
    /// snapshot SHARES @State `mySecret`'s buffer. Zeroing `mySecret` later
    /// therefore forks a fresh buffer and leaves THIS snapshot's ORIGINAL buffer
    /// holding the live secret — the residue an earlier comment wrongly believed
    /// `.onDisappear` closed.
    ///
    /// To actually zero that buffer we must make our local the SOLE owner before
    /// mutating: bind the payload as `var`, drop `mintState`'s reference by
    /// reassigning to a non-secret-bearing case, then `secureZero`. This works
    /// ONLY once every OTHER live alias (the @State `mySecret`) has already been
    /// forked away — so callers MUST have run `secureZero(&mySecret)` first;
    /// otherwise `s` is not uniquely referenced and secureZero forks instead of
    /// zeroing the real buffer. `.failed("")` is chosen over `.waitingForRelay`
    /// so it can never re-trigger startMint() via the torState .onReceive.
    private func wipeMintSecret() {
        guard case .ready(_, _, _, var s) = mintState else { return }
        mintState = .failed("")   // drop the enum's reference → `s` becomes sole owner
        secureZero(&s)
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

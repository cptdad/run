import SwiftUI
import UIKit
import StoreKit
import CoreImage.CIFilterBuiltins
import shared

// CHANGE 1 (transparent carousel sheets): a clear `.sheet` presentation
// background so the now-transparent About / Push-settings carousel content
// floats over the presenting view's scrim instead of the system sheet's
// opaque chrome. `presentationBackground` is iOS 16.4+; the project's
// deployment target is 16.0 (project.yml / pbxproj), so this is a no-op
// below 16.4 rather than an unavailable-API build failure.
private extension View {
    @ViewBuilder
    func translucentSheetBackground() -> some View {
        if #available(iOS 16.4, *) {
            self.presentationBackground(.regularMaterial)
        } else {
            self
        }
    }
}

// A STABLE, deterministic avatar-colour index. Swift's
// String.hashValue is per-process seeded (a different colour every cold launch),
// and abs(Int.min) TRAPS — a rare crash on a pure display path. FNV-1a over the
// UTF-8 bytes is stable across launches and never negative.
func avatarColorIndex(_ s: String, count: Int) -> Int {
    guard count > 0 else { return 0 }
    var h: UInt64 = 1469598103934665603
    for b in s.utf8 { h = (h ^ UInt64(b)) &* 1099511628211 }
    return Int(h % UInt64(count))
}

/// Wraps a peer-supplied string in Unicode bidi isolation (FSI…PDI, U+2068 /
/// U+2069) before it is interpolated into a template sentence.
/// `GroupManager` already strips actual bidi CONTROL characters out of a group
/// name at ingest (`ContactAliasGenerator.sanitizeDisplayName`), but an
/// ordinary legitimate RTL name (real Arabic/Persian/Hebrew letters, no
/// override needed) still carries inherent strong directionality under the
/// Unicode Bidirectional Algorithm — isolating it keeps the surrounding
/// sentence's own direction (and trailing punctuation/clauses) from being
/// reordered by it. Android mirrors this in ContactListScreen.kt.
func bidiIsolate(_ s: String) -> String { "\u{2068}\(s)\u{2069}" }

// ---------------------------------------------------------------------------
// ContactListView — list of all vault contacts.
//
// Features matching Android:
//   • Runestone dim/bright background crossfade driven by Tor state
//   • Colored avatar circles with first letter of alias
//   • Long-press context menu: View Mnemonic / Delete
//   • FAB-style add button
//   • Empty state when no contacts
// ---------------------------------------------------------------------------

/// A referral offer lifted into a Swift Identifiable for SwiftUI presentation.
private struct RefOffer: Identifiable {
    let id: String              // introId
    let introducerAlias: String
    let peerAlias: String
}

/// A parked group invite lifted into a Swift Identifiable for presentation.
private struct GroupInviteItem: Identifiable {
    let id: String              // groupId
    let inviterAlias: String
    let groupName: String
    // This device previously held this group under a DIFFERENT
    // admin — warn so the user isn't silently eclipsed by a re-invite.
    let adminMismatch: Bool
    let priorAdminAlias: String?
}

/// GROUP-1 consent gate dialog, factored into its own ViewModifier so the
/// ContactListView body's modifier chain stays inside the SwiftUI type-checker's
/// complexity budget (a second inline presentation overran it). Join persists
/// the group + fans out our tag; Decline drops the invite. Both off the main
/// thread inside AppState. RuneDialogOverlay (not .alert) for the shared modal
/// chrome. NOT a hard gate: Later (button or scrim tap) closes it without
/// deciding and the list shows the invite as a row (GroupInvitePresentation.kt).
private struct GroupInviteAlert: ViewModifier {
    @EnvironmentObject private var appState: AppState
    @Binding var invite: GroupInviteItem?
    @Binding var busy: Bool
    let onChanged: () -> Void
    /// Fired after "Later" (button or scrim tap) so the list re-derives its rows now.
    let onDeferred: () -> Void

    func body(content: Content) -> some View {
        content.overlay {
            if let inv = invite {
                // "Later" = close WITHOUT deciding; the scrim tap means the same.
                // Ignored while a join is in flight, like the button.
                let later: () -> Void = {
                    guard !busy else { return }
                    appState.deferGroupInvite(groupId: inv.id)
                    invite = nil
                    onDeferred()
                }
                // Loud consent warning — a different contact than the
                // group's original admin is inviting you (a re-invite eclipse).
                // Bidi-isolate the peer-supplied group name at the
                // interpolation point — see bidiIsolate's doc comment below.
                let isolatedGroupName = bidiIsolate(inv.groupName)
                let message: String = {
                    if inv.adminMismatch {
                        if let prior = inv.priorAdminAlias {
                            return L10n.contactListGroupInviteMismatchWithPrior(inv.inviterAlias, isolatedGroupName, prior)
                        }
                        return L10n.contactListGroupInviteMismatch(inv.inviterAlias, isolatedGroupName)
                    }
                    return L10n.contactListGroupInviteMessage(inv.inviterAlias, isolatedGroupName)
                }()
                RuneDialogOverlay(
                    title: L10n.contactListGroupInviteTitle,
                    message: message,
                    a11yId: "group_invite_dialog",
                    onScrimTap: later,
                    actions: [
                        RuneDialogAction(busy ? L10n.contactListGroupInviteJoining : L10n.contactListGroupInviteJoin, enabled: !busy,
                                         a11yId: "group_invite_join") {
                            let gid = inv.id
                            invite = nil
                            busy = true
                            Task {
                                _ = await appState.acceptGroupInvite(groupId: gid)
                                busy = false
                                onChanged()
                            }
                        },
                        RuneDialogAction(L10n.nudgeLater, color: .runeAsh, enabled: !busy, a11yId: "group_invite_later") { later() },
                        .secondary(L10n.commonDecline, a11yId: "group_invite_decline") {
                            appState.declineGroupInvite(groupId: inv.id)
                            invite = nil
                        },
                    ]
                )
            }
        }
    }
}

/// Referral consent dialog — same extraction rationale + chrome as
/// GroupInviteAlert above. NOT a hard gate: Later (button or scrim tap) closes it
/// without deciding and the list shows the offer as a row (GroupInvitePresentation.kt).
private struct ReferralOfferAlert: ViewModifier {
    @EnvironmentObject private var appState: AppState
    @Binding var offer: RefOffer?
    @Binding var busy: Bool
    @Binding var acceptFailed: Bool
    let onChanged: () -> Void
    /// Fired after "Later" so the list re-derives its rows now.
    let onDeferred: () -> Void

    func body(content: Content) -> some View {
        content.overlay {
            if let o = offer {
                // Ignored while an accept is in flight, like the button.
                let later: () -> Void = {
                    guard !busy else { return }
                    appState.deferReferralOffer(introId: o.id)
                    offer = nil
                    onDeferred()
                }
                RuneDialogOverlay(
                    title: L10n.referralOfferTitle,
                    message: L10n.referralOfferMessage(o.introducerAlias, o.peerAlias),
                    a11yId: "referral_offer_dialog",
                    onScrimTap: later,
                    actions: [
                        RuneDialogAction(busy ? L10n.referralConnecting : (acceptFailed ? L10n.commonRetry : L10n.referralApprove),
                                         enabled: !busy, a11yId: "referral_approve") {
                            let id = o.id
                            // Un-defer first: a failed accept re-presents as Retry.
                            appState.undeferReferralOffer(introId: id)
                            offer = nil
                            busy = true
                            acceptFailed = false
                            Task {
                                let ok = await appState.acceptReferral(introId: id)
                                busy = false
                                // On failure the offer stays pending; the poller
                                // re-presents it and this flag flips the label to Retry.
                                acceptFailed = !ok
                                onChanged()
                            }
                        },
                        RuneDialogAction(L10n.nudgeLater, color: .runeAsh, enabled: !busy, a11yId: "referral_offer_later") { later() },
                        .secondary(L10n.commonDecline, a11yId: "referral_decline") {
                            appState.declineReferral(introId: o.id)
                            offer = nil
                            acceptFailed = false
                        },
                    ]
                )
            }
        }
    }
}

/// The multi-line free-text field of the report-bug
/// dialog, as a `UITextView` instead of SwiftUI's `TextEditor`.
///
/// WHY a representable at all: this codebase's own rule, stated on the
/// conversation composer (`ConversationView.inputBar`) and applied to every
/// other free-text field, is that `autocorrectionDisabled` +
/// `textInputAutocapitalization(.never)` suppress the inline correction UI ONLY
/// — they do NOT stop the system keyboard's QuickType engine from learning
/// typed words into its on-device lexicon, which lives outside the app sandbox
/// and survives an app wipe. `.textContentType(.password)` is the one modifier
/// that excludes a field from that learning, and `TextEditor` is the one
/// text-entry view that does not reliably honour it — so the report-bug field,
/// where a user types free prose about their own usage of this app, was the
/// only field still feeding the lexicon. A `UITextView` takes `textContentType`
/// directly, which gives it the same guarantee the composer, `PassphraseField`
/// and the `GroupViews` sibling field already have.
///
/// Deliberately NOT `isSecureTextEntry`: the field must stay readable (it is a
/// bug report, not a credential) — `.password` alone is what excludes it from
/// learning. The smart-substitution flags are off for the same reason
/// autocorrect is: nothing may rewrite what the user typed.
private struct NoLearningTextEditor: UIViewRepresentable {
    @Binding var text: String
    let isEditable: Bool
    let a11yId: String

    func makeUIView(context: Context) -> UITextView {
        let view = UITextView()
        view.delegate = context.coordinator
        // The one line this type exists for.
        view.textContentType = .password
        view.autocorrectionType = .no
        view.autocapitalizationType = .none
        view.spellCheckingType = .no
        view.smartQuotesType = .no
        view.smartDashesType = .no
        view.smartInsertDeleteType = .no
        // Matches the TextEditor this replaced: transparent (the RuneCard's own
        // surface shows through), Metamorphous 13 scaled by Dynamic Type, and the
        // STOCK text-container insets (5 pt horizontal / 8 pt vertical) — which is
        // exactly the padding ReportBugAlert's placeholder overlay uses, so the
        // placeholder and the first typed character still sit on the same spot.
        view.backgroundColor = .clear
        view.font = Self.runeBodyFont()
        view.textColor = UIColor(Color.runTextPrimary)
        view.tintColor = UIColor(Color.runAccent)
        view.adjustsFontForContentSizeCategory = true
        // Set on the UITextView itself, not via SwiftUI's .accessibilityIdentifier:
        // that modifier would label the representable's HOST view, leaving the
        // XCUITest element the e2e helper types into unidentified. Same id as
        // before — `report_bug_text_field`.
        view.accessibilityIdentifier = a11yId
        return view
    }

    func updateUIView(_ view: UITextView, context: Context) {
        // Never overwrite a multi-stage (CJK / emoji) composition in progress.
        if view.markedTextRange == nil && view.text != text { view.text = text }
        view.isEditable = isEditable
        view.font = Self.runeBodyFont()
    }

    func makeCoordinator() -> Coordinator { Coordinator(text: $text) }

    final class Coordinator: NSObject, UITextViewDelegate {
        private let text: Binding<String>
        init(text: Binding<String>) { self.text = text }
        func textViewDidChange(_ textView: UITextView) {
            // Publish upward only. The length cap lives in the parent's
            // .onChange, which writes the truncated value back through this
            // binding and reaches the view via updateUIView — assigning here too
            // would fight that round trip.
            if text.wrappedValue != textView.text { text.wrappedValue = textView.text }
        }
    }

    /// `Font.rune(13, relativeTo: .body)`'s UIKit twin, with the system face as
    /// the fallback if the bundled Metamorphous is ever missing.
    private static func runeBodyFont() -> UIFont {
        let base = UIFont(name: "Metamorphous", size: 13) ?? UIFont.systemFont(ofSize: 13)
        return UIFontMetrics(forTextStyle: .body).scaledFont(for: base)
    }
}

/// Anonymous "Report bug" (BugReportSender.kt, commonMain) — custom overlay,
/// NOT RuneDialogOverlay/.runeDialog (neither has a content slot for a
/// free-text field). Built from the SAME chrome primitives
/// (RuneCard/RuneDialogTitle/RuneActionRow) so it matches every other modal;
/// mirrors Android's RuneDialog `content` slot usage in ContactListScreen.kt.
/// `.containerA11yId` on the card keeps Send/Cancel individually exposed to
/// XCUITest — see UIComponents.swift's OptionalContainerA11yId kdoc
/// (push_prompt is the discovering case; this dialog has a title, which
/// already kept the subtree complex enough even before that fix, but the
/// container id is applied unconditionally regardless).
///
/// Dismissible via Cancel/tap-outside EXCEPT while a send is in flight, so a
/// background success/failure callback never lands on a screen the user
/// thinks they already left mid-tap. State (text/sending/error) lives in the
/// parent (ContactListView) — same shape as GroupInviteAlert/ReferralOfferAlert
/// above — so `pick(.reportBug)` can reset it on open.
private struct ReportBugAlert: ViewModifier {
    @EnvironmentObject private var appState: AppState
    @Binding var isPresented: Bool
    @Binding var text: String
    @Binding var sending: Bool
    @Binding var errorMessage: String?
    let onSuccess: () -> Void

    private var canSend: Bool {
        !sending && !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    func body(content: Content) -> some View {
        content.overlay {
            if isPresented {
                ZStack {
                    Color.black.opacity(0.8)
                        .ignoresSafeArea()
                        .onTapGesture { if !sending { isPresented = false } }
                    RuneCard {
                        VStack(spacing: 14) {
                            RuneDialogTitle(L10n.reportBugTitle)
                            ZStack(alignment: .topLeading) {
                                if text.isEmpty {
                                    Text(L10n.reportBugPlaceholder)
                                        .font(.rune(13, relativeTo: .body))
                                        .foregroundColor(Color.runTextSecondary)
                                        .padding(.horizontal, 5)
                                        .padding(.vertical, 8)
                                        .allowsHitTesting(false)
                                }
                                // Client-side ceiling mirrors the shared Kotlin
                                // constant (BugReportSender.MAX_TEXT_CHARS) —
                                // same cross-platform-mirror pattern PassphraseField
                                // uses for CredentialPolicy.MAX_PASSPHRASE_LENGTH.
                                // A UITextView, not a
                                // TextEditor — see NoLearningTextEditor. The old
                                // comment here claimed autocorrect+autocapitalization
                                // kept this prose out of the QuickType lexicon; per
                                // this codebase's own rule (ConversationView's
                                // inputBar) they do NOT, only .password does, and
                                // TextEditor does not reliably honour it.
                                NoLearningTextEditor(
                                    text: $text,
                                    isEditable: !sending,
                                    a11yId: "report_bug_text_field"
                                )
                                    .frame(height: 120)
                                    .onChange(of: text) { value in
                                        let cap = Int(BugReportSender.shared.MAX_TEXT_CHARS)
                                        if value.count > cap { text = String(value.prefix(cap)) }
                                        errorMessage = nil
                                    }
                            }
                            .padding(8)
                            .background(Color.runSurface.opacity(0.6))
                            .cornerRadius(10)
                            if let errorMessage {
                                Text(errorMessage)
                                    .font(.runeCaption)
                                    .foregroundColor(.runeDanger)
                                    .multilineTextAlignment(.center)
                                    .accessibilityIdentifier("report_bug_error")
                            }
                        }
                        .padding(.horizontal, 24)
                        .padding(.vertical, 26)
                        .frame(maxWidth: .infinity)
                        RuneActionRow(actions: [
                            .secondary(L10n.commonCancel, a11yId: "report_bug_cancel_button") {
                                if !sending { isPresented = false }
                            },
                            RuneDialogAction(L10n.reportBugSend, enabled: canSend, a11yId: "report_bug_send_button") {
                                sending = true
                                errorMessage = nil
                                let toSend = text
                                Task {
                                    let ok = await appState.sendBugReport(text: toSend)
                                    sending = false
                                    if ok {
                                        isPresented = false
                                        text = ""
                                        onSuccess()
                                    } else {
                                        errorMessage = L10n.reportBugFailed
                                    }
                                }
                            },
                        ])
                    }
                    .padding(.horizontal, 32)
                    .containerA11yId("report_bug_dialog")
                }
            }
        }
    }
}

struct ContactListView: View {
    @EnvironmentObject private var appState: AppState
    // In-app update nudge's store button (StoreInstall.appStoreURL) — same
    // openURL idiom AboutInfoView uses.
    @Environment(\.openURL) private var openURL
    // In-app store-review nudge (ReviewPromptPolicy.kt in commonMain decides
    // WHEN; this is only the StoreKit call). iOS 16+ SwiftUI environment
    // action — the project's deployment target is already 16.0 (see the
    // translucentSheetBackground note above), so no #available guard needed.
    @Environment(\.requestReview) private var requestReview
    let onContactTapped: (String) -> Void
    let onAddContact:    () -> Void
    let onChangePin:     () -> Void
    let onGroupTapped:   (String) -> Void
    let onCreateGroup:   () -> Void

    @State private var contacts: [ContactItem] = []
    @State private var groups: [GroupItem] = []
    @State private var showLeaveGroupAlert = false
    @State private var pendingLeaveGroupId: String? = nil
    @State private var pendingLeaveGroupIsAdmin = false
    // Debug log viewer — 5-tap on the bottom-left stone. TEMPORARY.
    // DEBUG-only: the tap target itself (stoneTapRect) is an always-on-top
    // overlay, so outside DEBUG it must not exist at all — a Release build
    // with only the *action* gated still renders an invisible-but-tappable
    // rectangle over the bottom-right, blocking taps on the bottom contact
    // row once the list fills the screen.
    #if DEBUG
    @State private var stoneTapCount = 0
    @State private var lastStoneTap = Date.distantPast
    @State private var showLogViewer = false
    #endif

    @State private var showDeleteAlert = false
    @State private var pendingDeleteId: String? = nil
    @State private var showEditMnemonic = false
    @State private var editingContactId: String? = nil
    @State private var editingMnemonic = ""
    // Long-press contact menu — a custom overlay matching Android's layout
    // (memory on the left, Add/Edit + Remove buttons on the right, Delete
    // below) rather than the native iOS context menu.
    @State private var menuContact: ContactItem? = nil
    // About modals (cogwheel menu). Static, vault-agnostic.
    @State private var showAbout  = false
    @State private var showAboutInfo = false
    // Support Rún — StoreKit 2 tip jar (cogwheel menu).
    @State private var showSupport = false
    // Referral/vouching (referral.md): introduce contacts + an incoming offer
    // awaiting consent. Referred contacts are trusted transitively (no
    // verification step). introduceSelected holds the multi-select recipients;
    // introduceMnemonic shows a contact's memory on long-press.
    @State private var introduceFrom: ContactItem? = nil
    @State private var pendingOffer: RefOffer? = nil
    @State private var introduceSelected: Set<String> = []
    @State private var introduceMnemonic: String? = nil
    // F2: shown only when startReferrals reports a nil result for at least one
    // recipient (no transport / invalid) — the picker has already closed by
    // then, so this is a standalone dismissible alert. Same two-state shape as
    // showResetRelayResult/resetRelayResult below.
    @State private var showIntroduceError = false
    @State private var introduceError = ""
    @State private var referralBusy = false
    // The last accept attempt failed (e.g. the inbox mint timed out over a
    // flaky Tor circuit) — re-present the offer as a Retry rather than silently
    // reverting to "Approve".
    @State private var referralAcceptFailed = false
    // GROUP-1 consent gate: a parked group invite awaiting accept/decline.
    @State private var pendingGroupInvite: GroupInviteItem? = nil
    @State private var groupInviteBusy = false
    // Pending invites closed with "Later" (and not in the dialog now): listed as
    // "Invitation: ..." rows in the groups area. See syncGroupInvites().
    @State private var groupInviteRows: [GroupInviteItem] = []
    // Same for referral offers closed with "Later": "Introduction: ..." rows. See syncReferralOffers().
    @State private var referralOfferRows: [RefOffer] = []
    // Guideline 1.2 — block / report a contact.
    @State private var showBlockConfirm = false
    @State private var pendingBlockId: String? = nil
    @State private var pendingBlockAlias = ""
    @State private var showPostBlockReport = false
    @State private var reportedId = ""
    @State private var reportedAlias = ""
    // Block filters the SEND fan-out
    // (GroupManager.kt) but never touches group membership — a blocked contact
    // stays a member of any group they share with the user. Warn at block time
    // rather than silently leaving the victim believing the group is safe too;
    // "Leave" per shared group is offered, never forced (block stays reversible).
    @State private var showBlockGroupWarning = false
    @State private var pendingBlockSharedGroups: [GroupItem] = []
    // The contact-menu "Report" item now confirms
    // before handing off to AbuseReport.compose — see the disclosure dialog
    // below (menu_report stays the same a11y id; only its action changes).
    @State private var showReportConfirm = false
    @State private var pendingReportId: String? = nil
    @State private var pendingReportAlias = ""
    @State private var showBlockedContacts = false
    // H-1 "Reset relay access" — re-key this contact's relay inboxes. Not
    // destructive (nothing is deleted, the peer is unaffected), so it is styled as
    // an ordinary action; it IS a relay round-trip, so the menu entry is gated on
    // the same debounced reachability signal "Add contact" uses.
    @State private var showResetRelayConfirm = false
    @State private var pendingResetRelayId: String? = nil
    @State private var pendingResetRelayAlias = ""
    @State private var resetRelayBusy = false
    @State private var showResetRelayResult = false
    @State private var resetRelayResult = ""
    // Settings actions live in a SHEET (a List of buttons), not a SwiftUI `Menu`.
    // On physical iPhones @ iOS 26.5.x a `Menu`'s items intermittently fail to
    // surface in the XCUITest accessibility tree (the settings actions become
    // untappable to automation, and occasionally to VoiceOver), so the cogwheel
    // now opens a sheet whose buttons are ordinary views that always publish
    // their identifiers. Actions that present their OWN sheet are deferred to the
    // settings sheet's onDismiss (`pendingSettingsAction`) so the next sheet
    // presents only after this one has fully dismissed.
    @State private var showSettingsSheet = false
    @State private var settingsSheetDetent: PresentationDetent = .large
    @State private var pendingSettingsAction: SettingsAction? = nil

    /// One menu action, run AFTER the settings sheet finishes dismissing.
    private enum SettingsAction { case addContact, createGroup, changePin, protectionLevel, moveToNewDevice, about, aboutInfo, termsContact, support, blocked, pushSettings, language, reportBug, debugMode, extProxy }
    // External SOCKS proxy settings (ExternalProxySettingsView.swift).
    @State private var showExtProxySettings = false
    // Opt-in push (docs/RELAY_SPEC.md): Tier 0 (default) / Tier 2 toggle.
    @State private var showPushSettings = false
    // Threat-level slider: change the protection tier after onboarding.
    @State private var showProtectionLevel = false
    // Live connection-log panel (ConnectionLogPanel.swift): hidden until the
    // user triple-taps the "Connecting to…" caption. Android sibling:
    // ContactListScreen.kt's `showConnectLog`.
    @State private var showConnectLog = false
    // "Move to new device" (docs/device-move.md). Full-screen like the protection
    // flow: it renders a QR that IS the transfer secret, so it must be covered from
    // app-switcher snapshots in its own presentation layer (IOS-SEC-2). Dismissing
    // it after the export has started lands on ContentView's frozen screen, since
    // the vault now carries `mig_frozen`.
    @State private var showMoveToNewDevice = false
    // In-app language picker (parity with Android's LanguagePickerModal) —
    // see LanguagePickerView below.
    @State private var showLanguagePicker = false
    // Anonymous "Report bug" (BugReportSender, commonMain — see ReportBugAlert
    // below). No draft persistence by design — reopening starts blank.
    @State private var showReportBug = false
    @State private var reportBugText = ""
    @State private var reportBugSending = false
    @State private var reportBugError: String? = nil
    @State private var showReportBugThanks = false
    // Debug mode (settings row) — opt-in upload of the rolling log buffer to
    // the relay for support triage (AppState.setDebugMode / DebugMode.kt in
    // commonMain). The confirm dialog is title-having (see the kdoc on
    // ReportBugAlert's OptionalContainerA11yId note re: title-less RuneDialogs
    // flattening button ids) and reads appState.debugMode fresh each time it
    // opens, so its message always describes the CURRENT state, not the
    // state at settings-sheet-open time.
    @State private var showDebugModeDialog = false
    // Guideline 1.2 bullet 8: read-only Terms of Use + support contact,
    // reachable at any time (TermsContactView, UserSafety.swift-adjacent).
    @State private var showTermsContact = false
    // Whether any contact is currently blocked. No longer gates the "Blocked
    // contacts" row's enabled state (appstore-reply 2026-09-10: a reviewer
    // hunting for the block feature should never see a greyed-out row) — kept
    // for whatever future UI wants to know at a glance. Refreshed by
    // loadContacts() (which already reads the block set) and on block/unblock.
    @State private var hasBlockedContacts = false
    // Mirrors appState.isRelayReachable, but snaps off instantly when the
    // relay becomes unreachable so the lit runestone is NEVER visible while
    // the relay is down. Fade-in is still animated.
    @State private var litVisible: Bool = false
    // Drives the pulsating red ring while Tor is connecting (the bright runestone
    // is only visible before the relay lights, so the pulse shows during connect).
    // The red ring goes SOLID the instant the relay answers (RingPulse.kt in
    // commonMain: pulse harder and harder with the paced percent → solid →
    // hold RingPulse.SOLID_HOLD_MS → the white R lights). Separate from
    // litVisible, which lights the R after that hold.
    @State private var ringSolid: Bool = false
    @State private var litKick: DispatchWorkItem? = nil
    // The red ring goes SOLID (stops pulsing) the instant TOR reaches 100%
    // (transport ready) — separate from litVisible (relay reachability), which
    // is what lights the WHITE R. Tor-connected is stable (no flap), so this
    // needs no debounce.
    // Rows (and the e2e relay-warm marker) go live only once the white R has
    // FINISHED fading in ("the R lights the instant
    // before the contacts become tappable"). Scheduled litFadeDuration after
    // the reachable→true transition; snaps false the instant reachability is
    // lost. Both this and litVisible follow isRelayReachable — never torState —
    // so the stone can no longer light seconds before the rows do (the 09-01
    // ring change had moved the lit image onto Tor 100%, which put the white R
    // up to a full cold relay-probe budget ahead of the rows).
    @State private var rowsEnabled: Bool = false
    @State private var rowsEnableKick: DispatchWorkItem? = nil
    // FIRST-REVEAL GATE (2026-09-11). The contact list — every
    // row (contacts, groups, pending/awaiting-inbox, referred), the unread
    // badges, the repair banner AND the empty-contacts copy — is not on screen
    // AT ALL until the relay has actually answered once this session. Until
    // then the main screen shows only the runestone, the paced connect caption
    // and the connect hint (plus the cogwheel and Add contact, unchanged).
    // The gate signal is appState.contactsReady (relay answered AND unread prime settled) — the same `done` the
    // shared BootstrapProgressPacer is fed and the same signal that lights the
    // runestone (litVisible) — so the list arrives WITH the lit stone instead
    // of sitting there greyed out over a "Connecting…" caption.
    //
    // ONLY THE FIRST REVEAL IS GATED. Once revealed the list STAYS visible
    // even if reachability is later lost (the .stalled / grey-out phases): the
    // ask was "not visible until connected", NOT "hidden whenever
    // disconnected" — yanking a populated list mid-session would lose scroll
    // position and read as data loss, and the rows already dim + disable
    // (rowsEnabled) plus get the relayTroubleBanner in that state.
    //
    // Deliberately NOT gated on litVisible: that flag carries a 3 s dark-out
    // debounce, which is the right thing for an asset crossfade and the wrong
    // thing for a one-way latch. Set from the raw reachability subscription
    // (and re-seeded from the current value on appear / foreground return, so
    // an already-connected session never flashes the placeholder).
    // Android sibling: ContactListScreen.kt's `listRevealed` +
    // contactListRevealed/contactListSurface (which carry the JVM tests).
    @State private var listRevealed: Bool = false
    /// Fade-in of the lit stone; rows enable when it completes.
    private static let litFadeDuration: TimeInterval = 0.8
    /// Height of the empty state's top spacer so its first control sits on the
    /// stone's foot (RunestoneGeometry.stoneBottomY over the full screen, minus
    /// the top safe-area inset the VStack already starts below).
    private static var belowStoneSpacer: CGFloat {
        let screen = UIScreen.main.bounds.size
        let foot = CGFloat(RunestoneGeometry.shared.stoneBottomY(
            viewportW: Float(screen.width), viewportH: Float(screen.height), fillWidth: false))
        let safeTop = UIApplication.shared.connectedScenes
            .compactMap { ($0 as? UIWindowScene)?.keyWindow?.safeAreaInsets.top }.first ?? 0
        return max(0, foot - safeTop - 44 - CGFloat(RunestoneGeometry.shared.belowStoneGap()))
    }
    /// Height of the spacer that lands the connect caption block at
    /// RunestoneGeometry.captionTopY — well BELOW the blue ring's bottom edge
    /// (2026-09-12). Accounts for the VStack's 14 pt spacing on
    /// both sides of the spacer and for the Add button (≈44 pt + spacing) when
    /// it is rendered above the caption.
    private static func belowRingSpacer(buttonShown: Bool) -> CGFloat {
        let screen = UIScreen.main.bounds.size
        let captionTop = CGFloat(RunestoneGeometry.shared.captionTopY(
            viewportW: Float(screen.width), viewportH: Float(screen.height), fillWidth: false))
        let safeTop = UIApplication.shared.connectedScenes
            .compactMap { ($0 as? UIWindowScene)?.keyWindow?.safeAreaInsets.top }.first ?? 0
        let yRel = belowStoneSpacer + (buttonShown ? 14 + 44 : 0)
        return max(0, captionTop - safeTop - yRel - 28)
    }
    /// Solid-red beat between the relay's first answer and the R lighting (RingPulse.SOLID_HOLD_MS).
    private static let ringSolidHold: TimeInterval = Double(RingPulse.shared.solidHoldMs()) / 1000.0
    /// Opacity of the red-ring layer for one frame of the connecting pulse (RingPulse.kt, shared with Android).
    private func ringPulseOpacity(at date: Date) -> Double {
        let nowMs = Int64(date.timeIntervalSince1970 * 1000)
        let phase = RingPulse.shared.phaseAt(nowMs: nowMs)
        return Double(RingPulse.shared.opacity(p: Float(connectPercent) / 100.0, phase: phase))
    }
    // Debounce for the lit-runestone dark-out (see the isRelayReachable
    // subscription): swallows transient reachability flaps so the runestone never
    // snaps bright↔lit — the "zoom only after a contact".
    @State private var litFalseDebounce: Task<Void, Never>? = nil

    /// Sets the connect-reveal state from `contactsReady` in a no-animation
    /// transaction, on appear and on every foreground return, so the lit runestone
    /// never crossfades in (a crossfade there reads as a zoom). The ring pulse is a
    /// TimelineView driven by RingPulse, so nothing needs re-kicking afterwards.
    /// Re-seeds (never clears) the first-reveal latch: this view can appear on an
    /// already-connected session (popping back from a conversation, a foreground
    /// return) and must not flash the placeholder before the first publish lands.
    private func resyncLitStateInstantly() {
        var t = Transaction(); t.disablesAnimations = true
        withTransaction(t) {
            litVisible = appState.contactsReady
            // Instant snapshot (no fade to wait for): rows follow the flag as-is.
            rowsEnableKick?.cancel(); rowsEnableKick = nil
            rowsEnabled = appState.contactsReady
            ringSolid = appState.contactsReady
            if appState.contactsReady { listRevealed = true }
        }
    }
    // Paces the pre-connect percent for BOTH phases — see the shared
    // BootstrapProgressPacer (App Store review 2.1 on 1.6.15: the old numbers
    // sat still, at Tor's 95% circuit-build park and at the phase-two curve's
    // 95 cap, and a frozen number reads as "loads indefinitely"). Fed once a
    // second by the .onReceive Timer below; `connectPercent` is the rendered
    // value (a plain computed property wouldn't advance between appState
    // publishes). systemUptime is boot-relative, immune to wall-clock changes.
    // Android sibling: ContactListScreen's `connectPacer` / `connectPercent`.
    @State private var connectPacer = BootstrapProgressPacer(nowMs: {
        KotlinLong(value: Int64(ProcessInfo.processInfo.systemUptime * 1000))
    })
    @State private var connectPercent: Int = 0
    // Container's top safe-area inset as SwiftUI reports it (status bar + nav
    // band), read reactively in `body` — a floor for topClearance, never the
    // sole input (0 until the first layout pass; see topClearance).
    @State private var containerSafeTop: CGFloat = 0
    @Environment(\.scenePhase) private var scenePhase

    struct ContactItem: Identifiable {
        let id:       String   // contactId
        let alias:    String
        let mnemonic: String
        let stale:    Bool     // pre-capability-protocol — surface re-pair UX
        let pending:  Bool     // awaiting the peer's in-band inbox announce
        // Referral (referral.md): added via an introducer. Usable immediately
        // (transitive trust); this flag only drives the "Introduced" provenance
        // badge.
        var referred: Bool = false
        // Alias of the voucher (introducer), if resolvable — shown as
        // "Introduced by <alias>", the trust signal that matters in the
        // transitive-trust model.
        var introducerAlias: String? = nil
        // Maximum shield: the contact reported Maximum and THIS device is at MAXIMUM.
        var maximumShield: Bool = false
    }

    struct GroupItem: Identifiable {
        let id:      String    // groupId
        let name:    String
        let isAdmin: Bool
    }

    var body: some View {
        // Split into chained private builders (type-checker budget + readability);
        // the application order is EXACTLY the original single chain:
        // content → connect chrome → contact dialogs → settings presentations →
        // consent prompts → the trailing debug dialog / blocked sheet / scenePhase.
        consentPrompts(settingsPresentations(contactDialogs(connectChrome(listContent))))
        // Debug mode confirm — WITH a title: a title-less RuneDialog flattens
        // its button ids (see ReportBugAlert's container-id note above), and
        // this dialog needs both debug_mode_confirm and debug_mode_cancel
        // individually exposed to XCUITest.
        .runeDialog(isPresented: $showDebugModeDialog,
                    title: L10n.debugModeTitle,
                    message: appState.debugMode ? L10n.debugModeMessageOff : L10n.debugModeMessage,
                    a11yId: "debug_mode_dialog",
                    actions: [
                        .secondary(L10n.commonCancel, a11yId: "debug_mode_cancel") { },
                        RuneDialogAction(appState.debugMode ? L10n.debugModeTurnOff : L10n.debugModeTurnOn,
                                         a11yId: "debug_mode_confirm") {
                            appState.setDebugMode(!appState.debugMode)
                        },
                    ])
        .sheet(isPresented: $showBlockedContacts) {
            BlockedContactsView(onClose: { showBlockedContacts = false })
                .privacyCovered()
        }
        .onChange(of: scenePhase) { phase in
            if phase == .active {
                // Returning to the foreground: re-sync the lit state instantly.
                resyncLitStateInstantly()
            } else {
                // IOS-SEC-2: keep the plaintext mnemonic out of the app-switcher
                // snapshot — dismiss the EditMnemonic sheet as the app leaves the
                // foreground (it is also covered via .privacyCovered() above).
                showEditMnemonic = false
                // The referral offer + group-invite alerts show
                // contact/introducer aliases and have no overlay hook either — dismiss
                // them too so they can't land in the app-switcher snapshot.
                pendingOffer = nil
                pendingGroupInvite = nil
            }
        }
    }

    /// The placeholder / empty state / list switch at the root of `body`.
    private var listContent: some View {
        ZStack {
            if !listRevealed {
                // Pre-connect placeholder (see listRevealed). emptyState IS
                // already exactly what this state must show — runestone +
                // Add-contact + the paced caption/hint/stall content — but it
                // renders under a DIFFERENT container id: a vault WITH contacts
                // must never report `empty_contacts_state` just because the
                // relay hasn't answered yet (the e2e freshness/empty-vault
                // probes key on that id), and a fresh vault must not flash "no
                // contacts" before the relay answers. Android sibling:
                // ContactListScreen.kt's ContactListSurface branch.
                emptyState
                    .containerA11yId("contact_list_hidden_until_connected")
            } else if contacts.isEmpty && groups.isEmpty {
                emptyState
                    // containerA11yId (children: .contain), matching EulaView /
                    // passcode_warning: a bare .accessibilityIdentifier here
                    // SHADOWED every descendant's own id, so tor_progress_caption
                    // and empty_add_contact_button were unreachable by id lookup
                    // (the connect caption read as "missing" to e2e).
                    .containerA11yId("empty_contacts_state")
            } else {
                contactsList
            }
        }
    }

    /// Layout, background, connect banner / pacer, toolbar and list refresh.
    private func connectChrome(_ content: some View) -> some View {
        content
        // Fill the container so the empty state's Spacers and the list always
        // get the whole safe region, whatever the content.
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        // The runestone is a BACKGROUND, not a ZStack child (2026-09-04 layout
        // bug, sim-measured on iPhone 17 Pro / iOS 26.5): runestoneBackground is
        // hard-framed to UIScreen.main.bounds (874pt) + .ignoresSafeArea(), and a
        // ZStack takes its tallest child's size — so the ZStack reported the FULL
        // screen height instead of the container's safe region (792pt) and was
        // centred over it, overflowing 41pt at BOTH ends: the list's content
        // started under the status bar/nav band (this is why the historic flat
        // 44pt / "88 - inset" top spacers happened to read right), the bottom
        // 41pt of the list were unreachable, and when relayTroubleBanner
        // appeared, .safeAreaInset(edge: .bottom) grew the rigid 874 to 961,
        // re-centred it (every row jumped UP by half the banner height, the
        // first row into the status bar) and placed the banner at y≈879 in an
        // 874pt window — invisible. A background never contributes to the
        // modified view's size (same recipe ConversationView already uses), so
        // the ZStack now sizes to its container and the bottom inset behaves.
        .background(runestoneBackground)
        // Read of the container's top safe-area inset (status bar + whatever
        // the nav bar contributes), fed into contactsList's top clearance as a
        // FLOOR only (see topClearance). Sourced from the key window
        // (topSafeAreaInset), NOT from a GeometryReader's
        // `geo.safeAreaInsets`: on iOS 27.0 (24A437) reading the SwiftUI
        // proxy's safe-area insets from an .onAppear inside an
        // .ignoresSafeArea(.top) reader null-derefs in
        // SwiftUICore SafeAreaInsets.adjust(cornerAdaptation:) on Dynamic
        // Island phones — a 100 % launch crash loop on the iPhone 16 Pro
        // (1.6.20, five identical .ips 2026-09-15). The notch/SE test phones never
        // hit it. Re-read on scene activation so an inset that settles late
        // (NavigationStack root during the unlock transition) is still picked
        // up; the window read is the same source the rest of this file uses.
        .onAppear { containerSafeTop = topSafeAreaInset }
        .onReceive(NotificationCenter.default.publisher(
            for: UIApplication.didBecomeActiveNotification)) { _ in
            containerSafeTop = topSafeAreaInset
        }
        #if DEBUG
        .overlay(alignment: .bottomTrailing) {
            stoneTapRect
        }
        #endif
        // safeAreaInset (not .overlay) — this must both pin the banner at the
        // bottom AND grow contactsList's bottom scroll-content inset by the
        // banner's height, so the last contact/group row can scroll fully
        // clear of it. An .overlay draws on top of the ScrollView without the
        // ScrollView knowing to reserve room, which covered/clipped the last
        // row (untappable) whenever the relay was unreachable on a
        // screen-filling contact list.
        .safeAreaInset(edge: .bottom) {
            // Animated (not snapped) collapse: the banner leaves in the SAME
            // update that flips isRelayReachable, and an abrupt inset removal
            // re-clamps a scrolled list's contentOffset under the user's
            // finger. Rows enable only after this has settled (rowsEnabled
            // trails the flip by litFadeDuration > 0.4 s).
            relayTroubleBanner
                .animation(.easeInOut(duration: 0.4), value: appState.contactsReady)
        }
        .overlay {
            contactMenuOverlay
        }
        // Feeds the pacer the REAL state once a second, across the WHOLE
        // pre-connect window — the previous tick only ran once Tor was already
        // connected, so phase one moved only when Tor itself emitted (and sat
        // perfectly still through the long 95% circuit build). UNGATED on
        // purpose: the pacer is monotone and cheap, `done` (relay reachable)
        // pins it at 100, and the assign-if-changed below means a settled
        // connection re-renders nothing. Android sibling: ContactListScreen's
        // `LaunchedEffect(Unit)` pacer ticker.
        .onReceive(Timer.publish(every: 1, on: .main, in: .common).autoconnect()) { _ in
            connectPacer.observe(
                realPercent: BootstrapProgressPacer.companion.realTarget(
                    torConnected: appState.torState == .connected,
                    torPercent: Int32(torProgressPercent)
                ),
                // Relay REACHABILITY is the true 100% (the same signal that
                // lights the runestone and enables the rows), not Tor's 100%.
                // …and since 2026-09-14 ALSO the unread prime: contactsReady is
                // reachability + every "message waiting" dot already known.
                done: appState.contactsReady
            )
            let paced = Int(connectPacer.displayed())
            if paced != connectPercent { connectPercent = paced }
        }
        .navigationTitle("")
        .navigationBarTitleDisplayMode(.inline)
        .runNavigationBarChrome()
        .toolbar {
            ToolbarItem(placement: .principal) {
                EmptyView()
            }
            // Top-right cogwheel → settings sheet (Add contact / New group /
            // Change pin code / About / Support / Blocked). A sheet — not a
            // `Menu` — because Menu items don't reliably surface in the a11y
            // tree on physical iPhones @ iOS 26.5.x (see showSettingsSheet).
            ToolbarItem(placement: .navigationBarTrailing) {
                Button { showSettingsSheet = true } label: {
                    Image(systemName: "gearshape")
                        .foregroundColor(Color.runTextPrimary)
                }
                .accessibilityIdentifier("settings_button")
            }
        }
        .onAppear { loadContacts() }
        .onReceive(NotificationCenter.default.publisher(for: .contactsChanged)) { _ in
            loadContacts()
        }
    }

    /// The contact / group action dialogs, push prompt, update nudge, review request,
    /// in three ordered layers (the modifier order is today's: actions, then the
    /// session prompts, then the safety dialogs).
    private func contactDialogs(_ content: some View) -> some View {
        safetyDialogs(sessionPromptDialogs(contactActionDialogs(content)))
    }

    /// Delete, reset relay access (confirm + result), introduce error.
    private func contactActionDialogs(_ content: some View) -> some View {
        content
        .runeDialog(isPresented: $showDeleteAlert, title: L10n.contactListDeleteContactTitle,
                    message: L10n.contactListDeleteContactMessage,
                    // Destructive LAST (safety rule — see RuneDialog in UIComponents).
                    actions: [
                        .secondary(L10n.commonCancel) { pendingDeleteId = nil },
                        RuneDialogAction(L10n.commonDelete, color: .runeDanger, a11yId: "delete_confirm_button") {
                            if let id = pendingDeleteId {
                                deleteContact(contactId: id)
                            }
                            pendingDeleteId = nil
                        },
                    ])
        // Re-key the relay side of this conversation. Honest copy — it cannot
        // un-read anything already taken, which is why it points at delete +
        // re-pair for a phone that really was seized. Identical wording on Android
        // (ContactListScreen.kt). NOT destructive, so no red action.
        .runeDialog(isPresented: $showResetRelayConfirm, title: L10n.contactListResetRelayTitle,
                    message: L10n.contactListResetRelayMessage(pendingResetRelayAlias),
                    a11yId: "reset_relay_alert",
                    actions: [
                        .secondary(L10n.commonCancel) { pendingResetRelayId = nil },
                        RuneDialogAction(L10n.contactListResetButton, a11yId: "reset_relay_confirm_button") {
                            if let id = pendingResetRelayId { resetRelayAccess(contactId: id) }
                        },
                    ])
        .runeDialog(isPresented: $showResetRelayResult,
                    message: resetRelayResult,
                    a11yId: "reset_relay_result",
                    actions: [
                        RuneDialogAction(L10n.commonOk, a11yId: "reset_relay_result_ok") { },
                    ])
        // F2: startReferrals reported a nil result for at least one recipient
        // (no transport / invalid) — the picker has already closed.
        .runeDialog(isPresented: $showIntroduceError,
                    message: introduceError,
                    a11yId: "introduce_error_dialog",
                    actions: [
                        RuneDialogAction(L10n.commonOk) { },
                    ])
    }

    /// Push prompt, update nudge, StoreKit review request.
    private func sessionPromptDialogs(_ content: some View) -> some View {
        content
        // First-open push-notification prompt (onboard_push_prompt_v1, one-shot
        // per vault — see PushPromptOnboarding.kt in commonMain, set at both
        // AppState unlock paths).
        // Neither button is destructive, so "Yes" (affirmative) takes the safe
        // reflex-tap slot per UIComponents.swift's ordering rule, "No" the
        // secondary slot — mirrors Android ContactListScreen.kt.
        .runeDialog(
            isPresented: $appState.showPushPrompt,
            message: L10n.pushPromptMessage,
            a11yId: "push_prompt",
            dismissable: false,
            actions: [
                RuneDialogAction(L10n.commonYes, a11yId: "push_prompt_yes") {
                    showPushSettings = true
                },
                .secondary(L10n.commonNo, a11yId: "push_prompt_no") { },
            ]
        )
        // In-app update nudge (update-nudge-plan.md; UpdateNudge.kt /
        // UpdateCheck.kt in commonMain, evaluated once per session by
        // AppState.checkRelayReachability). Lowest priority of the
        // contact-list dialogs — gated on `!showPushPrompt` so no two Dialog
        // windows ever stack (there is no priority queue) — parity with Android's ContactListScreen.kt
        // gating. "Later" takes the safe reflex-tap slot (UIComponents.swift's
        // ordering rule): unlike the usual affirmative-first case, "Open App
        // Store" triggers a real clearnet egress at a relay-chosen moment
        // (update-nudge S-1), so it is treated like a dialog's destructive
        // action for slot purposes even though it isn't colored as one. The
        // info-only OK REUSES `update_nudge_later_button` (one e2e selector for
        // both variants — the physical test phones, sideloaded, can only ever render
        // this branch).
        .runeDialog(
            isPresented: Binding(
                get: { updateNudgeVisible },
                set: { if !$0 { appState.showUpdateNudge = nil } }
            ),
            message: L10n.nudgeMessage,
            a11yId: "update_nudge_dialog",
            messageA11yId: "update_nudge_message",
            dismissable: false,
            actions: StoreInstall.isAppStoreInstall
                ? [
                    RuneDialogAction(L10n.nudgeLater, a11yId: "update_nudge_later_button",
                                      labelA11yId: "update_nudge_later_button_label") {
                        appState.showUpdateNudge = nil
                    },
                    RuneDialogAction(L10n.nudgeOpenAppStore, a11yId: "update_nudge_store_button",
                                      labelA11yId: "update_nudge_store_button_label") {
                        appState.showUpdateNudge = nil
                        openURL(StoreInstall.appStoreURL)
                    },
                ]
                : [
                    RuneDialogAction(L10n.commonOk, a11yId: "update_nudge_later_button",
                                      labelA11yId: "update_nudge_later_button_label") {
                        appState.showUpdateNudge = nil
                    },
                ]
        )
        // Privacy-respecting in-app store-review nudge (ReviewPromptPolicy.kt,
        // commonMain — decides WHEN; this is only the StoreKit call). Not a
        // RuneDialog: the ordering rule against the push prompt / update
        // nudge above is already enforced inside
        // AppState.checkRelayReachability (ReviewPromptPolicy gates), so
        // `requestReviewFlow` firing true here means "go ahead". Any failure
        // (not eligible per Apple's own internal throttling, no App Store
        // context) is handled entirely inside StoreKit — `requestReview()`
        // silently no-ops, never a custom dialog, never a Safari fallback.
        .onChange(of: appState.requestReviewFlow) { shouldRequest in
            guard shouldRequest else { return }
            appState.consumeRequestReviewFlow()
            requestReview()
        }
    }

    /// Block, block-with-shared-groups warning, post-block report, report confirm,
    /// leave group.
    private func safetyDialogs(_ content: some View) -> some View {
        content
        .runeDialog(isPresented: $showBlockConfirm, title: L10n.contactListBlockContactTitle,
                    message: L10n.contactListBlockContactMessage(pendingBlockAlias),
                    // Destructive LAST (safety rule — see RuneDialog in UIComponents).
                    actions: [
                        .secondary(L10n.commonCancel) { pendingBlockId = nil },
                        RuneDialogAction(L10n.conversationBlockAction, color: .runeDanger, a11yId: "block_confirm_button") {
                            // confirmBlock routes through showBlockGroupWarning when a
                            // shared group exists instead of blocking immediately; either
                            // way it (or blockContact within it) owns clearing pendingBlockId.
                            if let id = pendingBlockId { confirmBlock(contactId: id) }
                        },
                    ])
        // Block never touches group membership —
        // a shared group means the blocked contact keeps receiving the victim's
        // messages there from every OTHER member, invisibly. Offer "Leave <group>"
        // per shared group (never automatic — block stays reversible) or "Block
        // Anyway"; either way the block itself still proceeds.
        .runeDialog(isPresented: $showBlockGroupWarning, title: L10n.contactListBlockSharedGroupsTitle,
                    message: L10n.contactListBlockSharedGroupsMessage(pendingBlockAlias),
                    actions: blockGroupWarningActions)
        // Reporter disclosure: the report is a mailto from
        // the user's own mail account, so it reveals their email address to us —
        // AND the draft it creates lands outside Rún's sandbox, unencrypted, and
        // survives a Rún wipe. Say so before they send.
        .runeDialog(isPresented: $showPostBlockReport, title: L10n.contactListContactBlockedTitle,
                    message: L10n.contactListPostBlockReportMessage,
                    actions: [
                        RuneDialogAction(L10n.conversationReportConfirmButton, a11yId: "post_block_report_button") {
                            AbuseReport.compose(contactAlias: reportedAlias, contactId: reportedId)
                        },
                        .secondary(L10n.commonNotNow) { },
                    ])
        // Reporter disclosure: same consequences as the
        // post-block dialog above — confirm before AbuseReport.compose opens
        // the mailto draft (menu_report entry point, contact-menu "Report").
        .runeDialog(isPresented: $showReportConfirm, title: L10n.conversationReportConfirmTitle,
                    message: L10n.conversationReportConfirmMessage,
                    actions: [
                        RuneDialogAction(L10n.conversationReportConfirmButton, a11yId: "report_confirm_button") {
                            if let id = pendingReportId {
                                AbuseReport.compose(contactAlias: pendingReportAlias, contactId: id)
                            }
                            pendingReportId = nil
                        },
                        .secondary(L10n.commonCancel) { pendingReportId = nil },
                    ])
        // The non-admin path can actually leave, so it carries the unread warning:
        // a member who has not read our texts yet drops them on arrival once the
        // leave notice removed us from their roster (the admin path only steers
        // to the handoff and leaves nothing).
        .runeDialog(isPresented: $showLeaveGroupAlert, title: L10n.groupInfoLeaveConfirmTitleIos,
                    message: pendingLeaveGroupIsAdmin
                        ? L10n.contactListLeaveGroupAdminMessageIos
                        : L10n.groupInfoLeaveConfirmMessage + "\n\n" + L10n.groupInfoLeaveUnreadWarning,
                    actions: pendingLeaveGroupIsAdmin
                        ? [
                            // The admin must hand the role to a chosen member before
                            // leaving; that picker (with each member's mnemonic) lives
                            // in the group's info screen. Steer them there rather than
                            // leaving admin-less.
                            RuneDialogAction(L10n.commonOk) { pendingLeaveGroupId = nil },
                        ]
                        // Destructive LAST (safety rule — see RuneDialog in UIComponents).
                        : [
                            .secondary(L10n.commonCancel) { pendingLeaveGroupId = nil },
                            RuneDialogAction(L10n.groupInfoLeaveConfirmAction, color: .runeDanger, a11yId: "leave_group_confirm_button") {
                                if let id = pendingLeaveGroupId {
                                    let gid = id
                                    Task { @MainActor in
                                        await appState.leaveGroup(groupId: gid)
                                        loadContacts()
                                    }
                                }
                                pendingLeaveGroupId = nil
                            },
                        ])
    }

    /// The settings sheet and every sheet / full-screen cover it opens.
    private func settingsPresentations(_ content: some View) -> some View {
        content
        .sheet(isPresented: $showSettingsSheet, onDismiss: runPendingSettingsAction) {
            settingsSheet
                // Sheets don't reliably inherit the root's forced dark scheme —
                // re-assert or this can render with system-light (white) chrome.
                .preferredColorScheme(.dark)
        }
        // Protection level (the single security control): full-screen like ChangePin
        // — it hosts the credential-rotation keypad/passphrase flows inline, which
        // must be covered from app-switcher snapshots the same way (IOS-SEC-2).
        .fullScreenCover(isPresented: $showProtectionLevel) {
            ProtectionLevelSettingsView(onDismiss: { showProtectionLevel = false })
                .environmentObject(appState)
                .coveredDarkSheet()
        }
        // "Move to new device" — see showMoveToNewDevice's declaration for why this
        // is a fullScreenCover with its own privacy cover.
        .fullScreenCover(isPresented: $showMoveToNewDevice) {
            MoveToNewDeviceView(onClose: { showMoveToNewDevice = false })
                .environmentObject(appState)
                .coveredDarkSheet()
        }
        .sheet(isPresented: $showEditMnemonic) {
            EditMnemonicView(
                mnemonic: $editingMnemonic,
                onSave: {
                    if let id = editingContactId {
                        saveMnemonic(contactId: id, mnemonic: editingMnemonic)
                    }
                    showEditMnemonic = false
                    editingContactId = nil
                    editingMnemonic = ""
                },
                onCancel: {
                    showEditMnemonic = false
                    editingContactId = nil
                    editingMnemonic = ""
                }
            )
            .coveredDarkSheet()
        }
        .sheet(isPresented: $showAbout) {
            AboutView { showAbout = false }
                .translucentSheetBackground()
        }
        .sheet(isPresented: $showAboutInfo) {
            AboutInfoView { showAboutInfo = false }
        }
        .sheet(isPresented: $showTermsContact) {
            TermsContactView { showTermsContact = false }
        }
        .sheet(isPresented: $showSupport) {
            SupportView { showSupport = false }
        }
        .sheet(isPresented: $showPushSettings) {
            PushSettingsView(onClose: { showPushSettings = false })
                .environmentObject(appState)
                .preferredColorScheme(.dark)
                .translucentSheetBackground()
        }
        .sheet(isPresented: $showExtProxySettings) {
            ExternalProxySettingsView(onClose: { showExtProxySettings = false })
                .coveredDarkSheet()
        }
        .sheet(isPresented: $showLanguagePicker) {
            LanguagePickerView(onClose: { showLanguagePicker = false })
                .environmentObject(appState)
                // Sheets don't reliably inherit the root's forced dark scheme —
                // same reassertion showSettingsSheet needs above.
                .preferredColorScheme(.dark)
        }
    }

    /// Referral / group-invite consent surfaces and the bug-report alerts.
    private func consentPrompts(_ content: some View) -> some View {
        content
        // --- Referral / vouching (referral.md) ---
        .task {
            // Surface the next incoming referral offer for consent AND dismiss it
            // once consumed. After a successful accept the offer leaves
            // pendingReferralOffers, so the alert must clear — otherwise it
            // lingers on an already-accepted offer. Don't touch it mid-accept
            // (referralBusy) so "Connecting…" stays put.
            while !Task.isCancelled {
                if introduceFrom == nil {
                    syncReferralOffers()
                    // Group invites share the consent surface — present one only
                    // when no referral prompt is up (a single prompt at a time).
                    syncGroupInvites()
                }
                try? await Task.sleep(nanoseconds: 4_000_000_000)
            }
        }
        .sheet(item: $introduceFrom) { from in
            // Covered like the other sheets: this picker lists contact aliases,
            // which would otherwise appear in the app-switcher snapshot.
            introducePickerSheet(from)
                .privacyCovered()
        }
        // Referral consent gate — extracted into a ViewModifier (see
        // ReferralOfferAlert) both for the shared Rune chrome and to keep this
        // modifier chain inside the SwiftUI type-checker budget.
        .modifier(ReferralOfferAlert(
            offer: $pendingOffer,
            busy: $referralBusy,
            acceptFailed: $referralAcceptFailed,
            onChanged: { loadContacts() },
            onDeferred: { syncReferralOffers(); syncGroupInvites() },
        ))
        // Introducer-side "your intro got relayed" info modal
        // (ReferralManager.onIntroRelayed, wired in AppState at both
        // unlock/recoverWithCode sites). Not a consent gate — info only, one
        // OK button — so it uses `.runeDialog` directly rather than a
        // ViewModifier extraction like the two gates above/below. Gated on
        // `pendingOffer == nil`: a referral OFFER consent gate always wins
        // over this purely informational one when both are pending. Must
        // carry a title (title-less RuneDialog flattens its button a11y ids
        // on iOS — see UIComponents.swift's OptionalContainerA11yId).
        .runeDialog(
            isPresented: Binding(
                get: { referralRelayDialogVisible },
                set: { if !$0 { appState.dismissReferralRelayEvent() } }
            ),
            title: referralRelayDialogTitle,
            message: referralRelayDialogMessage,
            a11yId: "referral_relayed_dialog",
            actions: [
                RuneDialogAction(L10n.commonOk, a11yId: "referral_relayed_ok") { },
            ]
        )
        // GROUP-1 consent gate: join a group only on explicit accept. Extracted
        // into a ViewModifier — inlining a second presentation here overran the
        // SwiftUI type-checker ("unable to type-check in reasonable time").
        .modifier(GroupInviteAlert(
            invite: $pendingGroupInvite,
            busy: $groupInviteBusy,
            onChanged: { loadContacts() },
            onDeferred: { syncGroupInvites() },
        ))
        // Anonymous "Report bug" — extracted the same way as the two consent
        // gates above (RuneDialogOverlay has no content slot for the free-text
        // field, and inlining a custom overlay here risks the same type-checker
        // budget the two above already document).
        .modifier(ReportBugAlert(
            isPresented: $showReportBug,
            text: $reportBugText,
            sending: $reportBugSending,
            errorMessage: $reportBugError,
            onSuccess: { showReportBugThanks = true },
        ))
        .runeDialog(isPresented: $showReportBugThanks,
                    message: L10n.reportBugThanks,
                    a11yId: "report_bug_thanks_dialog",
                    actions: [
                        RuneDialogAction(L10n.commonOk, a11yId: "report_bug_thanks_ok_button") { },
                    ])
    }

    private func saveMnemonic(contactId: String, mnemonic: String) {
        guard let vault = appState.vault else { return }
        // The read-modify-write lives in commonMain (ContactEdits) so iOS runs
        // the IDENTICAL persist that preserves the shared secret + anti-replay
        // counters/epoch — no more hand-copying all ContactRecord fields.
        ContactEdits.shared.updateMnemonic(vault: vault, contactId: contactId, mnemonic: mnemonic)
        loadContacts()
    }

    /// Rolls a fresh random alias for the contact and persists it. The alias is
    /// a vault-local pseudonym (never sent anywhere), so this is purely
    /// cosmetic; like saveMnemonic it rebuilds the full record to preserve the
    /// shared secret + anti-replay state. Updates `menuContact` in place so the
    /// open menu's title refreshes and the user can tap to cycle names. A draw
    /// equal to the current alias is re-rolled so the button always does
    /// something visible.
    private func rollAlias(contactId: String) {
        guard let vault = appState.vault,
              // B5: shared roll+persist in commonMain (ContactEdits) — preserves
              // the shared secret + anti-replay state, re-rolls a duplicate draw,
              // and returns the updated record (nil only if the contact is gone).
              let updated = ContactEdits.shared.rollAlias(vault: vault, contactId: contactId) else { return }
        // Refresh the open menu's title in place.
        if let m = menuContact, m.id == contactId {
            menuContact = ContactItem(id: m.id, alias: updated.alias, mnemonic: m.mnemonic, stale: m.stale, pending: m.pending)
        }
        // `updated` is a full ContactRecord (rollAlias
        // preserves every field, including sharedSecret) — only `.alias` is read
        // above, so wipe now before it goes out of scope. Mirrors Android's
        // ContactListScreen.kt rollAlias().
        updated.sharedSecret.secureWipe()
        loadContacts()
    }

    // MARK: - Runestone background

    private var runestoneBackground: some View {
        let artLevel = appState.controller.displayProtectionLevel()
        // FIXED screen-sized frame — captured once. The "zoom/bounce" was NOT an
        // asset-size mismatch (runestone_dim/_bright/_bright_and_lit are all the
        // SAME 624×1254). It was geometry: .scaledToFill() + .frame(maxWidth/
        // maxHeight: .infinity) re-resolves its box on every contact-list layout
        // pass (each poll mutates the list), and scaledToFill re-fits the whole
        // image to that changed box → the stone scales. With no contact the list
        // never changes, so it looked right. A constant CGSize can't re-measure,
        // so the crossfade below is pure opacity — no geometry, no zoom. (Same
        // zoom-free recipe as AboutPageView.runestoneStack: fixed frame + opacity.)
        let screen = UIScreen.main.bounds.size
        return ZStack {
            Color.runBackground

            // Base dim stone — always present, never fades out.
            Image(runestoneAsset("runestone_dim", level: artLevel))
                .resizable()
                .scaledToFill()
                .frame(width: screen.width, height: screen.height)
                .clipped()

            // Red-ring "connecting" stone — pulsing while Tor bootstraps, SOLID
            // from Tor 100% (torLit) until the relay answers (litVisible), then
            // hidden under the lit stone below. OPACITY only — the fixed frame
            // guarantees the pulse can never become a scale.
            // Red ring: breathes harder as the paced percent climbs (RingPulse),
            // solid the instant the relay answers, hidden once the R is lit.
            // TimelineView redraws only while the pulse is actually visible.
            TimelineView(.animation(minimumInterval: 1.0 / 30.0, paused: litVisible || ringSolid)) { ctx in
                Image(runestoneAsset("runestone_bright", level: artLevel))
                    .resizable()
                    .scaledToFill()
                    .frame(width: screen.width, height: screen.height)
                    .clipped()
                    .opacity(litVisible ? 0 : (ringSolid ? 1 : ringPulseOpacity(at: ctx.date)))
            }
            .animation(.easeInOut(duration: 0.25), value: ringSolid)
            .animation(.easeInOut(duration: 0.5), value: litVisible)

            // Lit stone (the white R) — fades in the instant the relay answers
            // (litVisible), NOT at Tor 100%: the rows enable when this fade
            // completes (rowsEnabled), so the R is lit the moment before the
            // contacts become tappable. Opacity-only.
            Image(runestoneAsset("runestone_bright_and_lit", level: artLevel))
                .resizable()
                .scaledToFill()
                .frame(width: screen.width, height: screen.height)
                .clipped()
                .opacity(litVisible ? 1 : 0)
                .animation(.easeInOut(duration: Self.litFadeDuration), value: litVisible)

            // Test-only marker — reflects rowsEnabled (relay reachable AND the
            // lit fade finished), i.e. "the contact list is interactive": the
            // e2e suites tap rows right after this marker appears.
            runestoneLitMarker(active: rowsEnabled)

            // Static dark overlay so the list stays readable.
            Color.black.opacity(0.45)
        }
        .frame(width: screen.width, height: screen.height)
        .ignoresSafeArea()
        // The runestone has NO container animation. Animating the whole stack on
        // torProgress OR on litVisible makes it breathe/zoom. The litVisible one
        // looked "one-time", but once a CONTACT exists the control-poll drives
        // frequent relay-reachability probes that FLAP litVisible around the
        // connecting boundary, re-firing the crossfade repeatedly — the "zoom in/
        // out … only after a contact" report. So the lit runestone now snaps in
        // instantly; the only thing that animates is the red ring's opacity pulse,
        // scoped to the bright image above.
        .onAppear { resyncLitStateInstantly() }
        .onDisappear { litKick?.cancel(); litKick = nil }
        // Combine subscription (vs .onChange) — delivers every published
        // value, including transitions that happen while this view is
        // covered by a sheet. With .onChange the lit asset stayed dark
        // on iPad because the reach-true transition fired during the
        // Add-Contact sheet and was never seen here.
        // The connect TRANSITION (ring solid → lit → list → rows) follows
        // contactsReady — reachability AND the unread prime — so the dots are in
        // the list the frame it appears (user requirement 2026-09-14). The raw
        // isRelayReachable stays for the outage banner + row dimming below.
        .onReceive(appState.$contactsReady) { reachable in
            if reachable {
                // Light immediately; cancel any pending dark-out.
                litFalseDebounce?.cancel(); litFalseDebounce = nil
                // Solid red first, the R after RingPulse.SOLID_HOLD_MS (see
                // RingPulse.kt). A reachability flap inside the hold cancels
                // the kick; an already-lit session (foreground return) keeps it.
                ringSolid = true
                if !litVisible && litKick == nil {
                    let lk = DispatchWorkItem {
                        if appState.contactsReady { litVisible = true }
                        litKick = nil
                    }
                    litKick = lk
                    DispatchQueue.main.asyncAfter(deadline: .now() + Self.ringSolidHold, execute: lk)
                }
                // FIRST REVEAL: the relay has answered, so the list may exist
                // from now on for the rest of this session. One-way — the
                // unreachable branch below deliberately does NOT clear it.
                listRevealed = true
                // Rows follow once the white R has finished fading in — never
                // before it (see rowsEnabled). No-op if already enabled.
                if !rowsEnabled && rowsEnableKick == nil {
                    let kick = DispatchWorkItem {
                        // A drop during the fade cancels this kick; guard anyway
                        // so a stale kick can never enable rows against a relay
                        // that is unreachable again.
                        if appState.contactsReady { rowsEnabled = true }
                        rowsEnableKick = nil
                    }
                    rowsEnableKick = kick
                    DispatchQueue.main.asyncAfter(deadline: .now() + Self.ringSolidHold + Self.litFadeDuration, execute: kick)
                }
            } else {
                // Rows snap off the instant reachability is lost (raw flag, no
                // debounce — a tap must never open a conversation the relay
                // can't serve); the stone's dark-out below is the only debounce.
                rowsEnableKick?.cancel(); rowsEnableKick = nil
                rowsEnabled = false
                litKick?.cancel(); litKick = nil
                ringSolid = false
                // DEBOUNCE the dark-out (3 s). Once a contact exists, the relay-
                // reachability probe briefly flaps false around connecting; setting
                // litVisible=false on each flap snapped the runestone bright↔lit —
                // the "zoom" seen ONLY with a contact (with none, no probe, no flap,
                // and it looks right). Only go dark after sustained unreachability;
                // a flap that recovers cancels the pending dark-out.
                litFalseDebounce?.cancel()
                litFalseDebounce = Task { @MainActor in
                    try? await Task.sleep(nanoseconds: 3_000_000_000)
                    guard !Task.isCancelled else { return }
                    var t = Transaction(); t.disablesAnimations = true
                    withTransaction(t) { litVisible = false }
                    litFalseDebounce = nil
                }
            }
        }
    }

    // Invisible tap target over the bottom-right stone.
    // 5 taps within 3 seconds opens the debug log viewer.
    // TEMPORARY: remove when beta testing is complete.
    // Just the tappable rectangle — added as an overlay on the body
    // ZStack so only the rectangle itself intercepts taps.
    // Long-press contact menu, laid out like Android: a centered card with
    // MARK: - Settings sheet (replaces the cogwheel Menu)

    /// The cogwheel's actions as a sheet of ordinary buttons. Each button stamps
    /// [pendingSettingsAction] and dismisses; the action fires from the sheet's
    /// onDismiss so any follow-on sheet (About/Support/Blocked) presents only
    /// after this one is gone. Keeps every accessibilityIdentifier the old Menu
    /// items carried, so the e2e helpers and VoiceOver are unchanged.
    private var settingsSheet: some View {
        NavigationStack {
            ZStack {
                Color.runBackground.ignoresSafeArea()
                List {
                    settingsRow(L10n.addContactTitle, "person.badge.plus", "add_contact_button",
                                // Pairing mints an inbox on the relay, so gate the
                                // entry point until the relay is reachable — else the
                                // Add-Contact screen just parks on "Setting up inbox…".
                                // Gate on litVisible (the SAME debounced signal the
                                // runestone `runestone_lit_active` marker uses), NOT
                                // the raw appState.isRelayReachable: under a flapping
                                // circuit the raw flag toggles every 8-12s check while
                                // litVisible's 3s dark-out debounce holds steady, so
                                // the two used to DISAGREE — the runestone lit but this
                                // button greyed out (a real "why can't I add a contact
                                // when it says connected?" UX bug, and the cross:multi3
                                // failure where waitForRelayWarm passed on the marker
                                // yet add_contact_button never enabled).
                                // Gate on rowsEnabled — the SAME flag the list rows and the
                                // runestone_lit_active marker follow — not litVisible, whose
                                // lighting is animation-coupled (solid-hold kick, 3 s dark-out
                                // debounce) and can lag or miss a contactsReady flip after an
                                // unlock: the device run of 2026-10-02 had the stone lit, the list
                                // interactive and every menu row disabled for 180 s (2026-10-02).
                                disabled: !rowsEnabled) { pick(.addContact) }
                    // Creating a group mints its inbox and sends the invites over
                    // the relay, so gate it on the same debounced [litVisible]
                    // signal "Add contact" uses (see the note above for why the
                    // raw appState.isRelayReachable is the wrong flag here).
                    settingsRow(L10n.createGroupTitle, "person.3", "create_group_menu_button",
                                disabled: !rowsEnabled) { pick(.createGroup) }
                    // Label follows the credential mode (Lever A): the same route
                    // hosts the mode-aware ChangeCredentialView.
                    settingsRow(appState.controller.isPassphraseMode() ? L10n.contactListChangePassphrase : L10n.contactListChangePin,
                                "lock.rotation", "change_pin_button") { pick(.changePin) }
                    settingsRow(L10n.contactListProtectionLevel, "slider.horizontal.3", "protection_level_menu_button") { pick(.protectionLevel) }
                    // "Move to new device" (docs/device-move.md). Relay-dependent
                    // row: a row that's tappable while the relay is unavailable
                    // leads to a flow that can only fail or wait, and the
                    // runestone already tells the user the relay isn't answering
                    // — this row follows it, same debounced [litVisible] signal
                    // as Add-Contact/Create-Group above. The export needs the
                    // relay for its upload.
                    settingsRow(L10n.moveMenuItem, "iphone.and.arrow.forward", "move_to_new_device_button",
                                disabled: !rowsEnabled) { pick(.moveToNewDevice) }
                    // Notification settings register the push token with (and
                    // the opt-out DELETEs to) the relay, so gate it the same way.
                    settingsRow(L10n.contactListPushNotifications, "bell", "push_settings_menu_button",
                                disabled: !rowsEnabled) { pick(.pushSettings) }
                    // Localization: in-app language picker (LanguagePickerView,
                    // below), at parity with Android's LanguagePickerModal.
                    // Replaced the old deep-link to iOS Settings' per-app
                    // "Preferred Language" row — that row only appears once the
                    // device already has 2+ preferred languages, so it was
                    // effectively undiscoverable for most users. See
                    // runPendingSettingsAction for the deferred-open.
                    settingsRow(L10n.settingsLanguage, "globe", "menu_language") { pick(.language) }
                    settingsRow(L10n.contactListHowItWorks, "info.circle", "menu_about") { pick(.about) }
                    // Guideline 1.2 bullet 8: re-readable Terms of Use + our
                    // contact address, at any time, not just at first launch.
                    settingsRow(L10n.menuTermsContact, "doc.text", "menu_terms_contact") { pick(.termsContact) }
                    settingsRow(L10n.contactListAbout, "questionmark.circle", "menu_about_info") { pick(.aboutInfo) }
                    settingsRow(L10n.donateTitle, "heart", "menu_support") { pick(.support) }
                    // Anonymous "Report bug" — parity with Android's
                    // ContactListScreen settings dropdown (ReportBugAlert below).
                    // Sending it is an onion round-trip like Add-Contact/Create-Group
                    // above, so gate on the same debounced [litVisible] signal those
                    // rows use (NOT the raw appState.isRelayReachable — see the note
                    // above add_contact_button for why).
                    settingsRow(L10n.settingsReportBug, "ladybug", "report_bug_menu_item",
                                disabled: !rowsEnabled) { pick(.reportBug) }
                    // Debug mode — opt-in upload of the rolling log buffer to the
                    // relay for support triage (DebugMode.kt, commonMain). NOT
                    // gated on litVisible like the row above: toggling it is a
                    // local Keychain write, not a relay round trip at tap time —
                    // the resulting uploads are fire-and-forget background
                    // triggers (AppState's debugLog* code), and it must stay
                    // switchable OFF even while the relay is unavailable.
                    settingsRow(appState.debugMode ? L10n.settingsDebugModeOn : L10n.settingsDebugMode,
                                "ladybug.fill", "settings_debug_mode") { pick(.debugMode) }
                    // External SOCKS proxy mode (docs/external-socks-proxy.md). NOT
                    // relay-gated: it is a local Keychain write that applies at the
                    // next launch, and it must stay reachable exactly when the relay
                    // is not (a dead proxy is the case the user needs to fix here).
                    // Hidden on iOS for now (ExternalProxyMode.settingsAvailable).
                    if ExternalProxyMode.settingsAvailable {
                        settingsRow(ExtProxyText.title, "network", "settings_ext_proxy") { pick(.extProxy) }
                    }
                    // Guideline 1.2: always enabled, even with nobody blocked yet —
                    // BlockedContactsView already has an empty state
                    // (blocked_empty_state), so a reviewer hunting for the block
                    // feature no longer finds a greyed-out row (appstore-reply
                    // 2026-09-10, discoverability risk #1).
                    settingsRow(L10n.contactListBlockedContacts, "hand.raised", "menu_blocked_contacts") { pick(.blocked) }
                }
                .scrollContentBackground(.hidden)
                .listStyle(.insetGrouped)
            }
            .navigationTitle(L10n.commonSettings)
            .navigationBarTitleDisplayMode(.inline)
            .runNavigationBarChrome()
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button(L10n.commonDone) { showSettingsSheet = false }
                        .foregroundColor(Color.runAccent)
                        .accessibilityIdentifier("settings_sheet_done")
                }
            }
        }
        // Opens at .large: the sheet gained a "Language" row with the
        // localization work, and at .medium the lower rows ("About",
        // "Support Rún", "Blocked contacts") fall below the fold on a
        // 6.1"-class iPhone — invisible to the user and to the e2e suite
        // (about.spec's `menu_about_info` went red at .medium). Medium stays
        // available by dragging down.
        .presentationDetents([.medium, .large], selection: $settingsSheetDetent)
        .privacyCovered()
    }

    private func settingsRow(
        _ title: String, _ icon: String, _ id: String,
        disabled: Bool = false, _ action: @escaping () -> Void
    ) -> some View {
        Button(action: action) {
            Label(title, systemImage: icon)
                .foregroundColor(disabled ? Color.runTextSecondary : Color.runTextPrimary)
        }
        .disabled(disabled)
        .listRowBackground(Color.runSurface)
        .accessibilityIdentifier(id)
    }

    /// Stamp the chosen action and dismiss the sheet; [runPendingSettingsAction]
    /// runs it once the sheet is fully gone.
    private func pick(_ action: SettingsAction) {
        pendingSettingsAction = action
        showSettingsSheet = false
    }

    private func runPendingSettingsAction() {
        guard let action = pendingSettingsAction else { return }
        pendingSettingsAction = nil
        switch action {
        case .addContact:  onAddContact()
        case .createGroup: onCreateGroup()
        case .changePin:   onChangePin()
        case .protectionLevel: showProtectionLevel = true
        case .moveToNewDevice: showMoveToNewDevice = true
        case .pushSettings: showPushSettings = true
        case .about:       showAbout = true
        case .aboutInfo:   showAboutInfo = true
        case .termsContact: showTermsContact = true
        case .support:     showSupport = true
        case .blocked:     showBlockedContacts = true
        case .language:
            // Deferred until the settings sheet has fully dismissed, same as
            // every other action here — presenting a sheet while our own is
            // still animating out has intermittently failed to present on
            // physical devices, the same class of issue `pick`/`onDismiss`
            // exists to avoid for About/Support/Blocked.
            showLanguagePicker = true
        case .reportBug:
            // Always start blank — no draft persistence by design.
            reportBugText = ""
            reportBugError = nil
            showReportBug = true
        case .debugMode:
            showDebugModeDialog = true
        case .extProxy:
            showExtProxySettings = true
        }
    }

    // the memory on the left and Add/Edit + Remove buttons on the right, and
    // Delete below. Replaces the native iOS context menu.
    @ViewBuilder
    private var contactMenuOverlay: some View {
        if let c = menuContact {
            ZStack {
                Color.runBackground.opacity(0.8)
                    .ignoresSafeArea()
                    .onTapGesture { menuContact = nil }

                VStack(alignment: .leading, spacing: 8) {
                    Text(c.alias)
                        .font(.runeHeadline)
                        .foregroundColor(.runTextPrimary)
                        .lineLimit(1)
                        .truncationMode(.tail)
                        .padding(.horizontal, 20)
                        .padding(.top, 12)

                    contactMenuMemorySection(c)

                    contactMenuActions(c)
                }
                .padding(.vertical, 8)
                .background(Color.runeCardFill)
                .clipShape(RoundedRectangle(cornerRadius: 22))
                .overlay(
                    RoundedRectangle(cornerRadius: 22)
                        .strokeBorder(
                            LinearGradient(colors: [.runeBorderBright, .runeBorderDim],
                                           startPoint: .top, endPoint: .bottom),
                            lineWidth: 2
                        )
                )
                .padding(36)
            }
        }
    }

    /// The contact menu's memory row: memory text, Add/Edit, Remove.
    @ViewBuilder
    private func contactMenuMemorySection(_ c: ContactItem) -> some View {
        HStack(alignment: .center, spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text(L10n.contactListMemoryLabel)
                    .font(.runeCaption2)
                    .foregroundColor(.runTextSecondary)
                Text(c.mnemonic.isEmpty ? L10n.contactListNoMemoryYet : c.mnemonic)
                    .font(.runeSubheadline)
                    .foregroundColor(c.mnemonic.isEmpty ? .runTextSecondary : .runTextPrimary)
                    .lineLimit(3)
                    .accessibilityIdentifier("menu_memory_text")
            }
            .frame(maxWidth: .infinity, alignment: .leading)

            Button {
                editingContactId = c.id
                editingMnemonic = c.mnemonic
                menuContact = nil
                showEditMnemonic = true
            } label: {
                Text(c.mnemonic.isEmpty ? L10n.contactListAddMemoryButton : L10n.contactListEditMemoryButton)
                    .foregroundColor(.runTextPrimary)
                    .lineLimit(1)
                    .padding(.horizontal, 14)
                    .padding(.vertical, 10)
                    .background(Color.runBackground)
                    .clipShape(RoundedRectangle(cornerRadius: 8))
            }
            .accessibilityIdentifier("menu_memory")

            if !c.mnemonic.isEmpty {
                Button {
                    // Saving "" deletes the memory; the helper
                    // preserves the anti-replay counters.
                    saveMnemonic(contactId: c.id, mnemonic: "")
                    menuContact = nil
                } label: {
                    Text(L10n.contactListRemoveMemoryButton)
                        .foregroundColor(.runError)
                        .lineLimit(1)
                        .padding(.horizontal, 14)
                        .padding(.vertical, 10)
                        .background(Color.runBackground)
                        .clipShape(RoundedRectangle(cornerRadius: 8))
                }
                .accessibilityIdentifier("menu_memory_remove")
            }
        }
        .padding(.horizontal, 20)
    }

    /// The contact menu's action rows, top to bottom: introduce, new name, reset
    /// relay access, report, block, delete.
    @ViewBuilder
    private func contactMenuActions(_ c: ContactItem) -> some View {
        // Referral: introduce this contact to others of yours. F5:
        // gated on the same debounced [litVisible] signal
        // "Reset relay access" below uses — it is a relay
        // round-trip (two blocking Tor sends), so it must not even
        // open the picker when there is no transport to send over.
        Button {
            introduceSelected = []
            introduceFrom = c
            menuContact = nil
        } label: {
            Text(L10n.contactListIntroduceToButton)
                .foregroundColor(litVisible ? .runTextPrimary : .runTextSecondary)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 20)
                .padding(.vertical, 14)
        }
        .disabled(!litVisible)
        .accessibilityIdentifier("menu_introduce")

        // Re-roll the vault-local pseudonym. Stays open and updates
        // the title in place so the user can tap to cycle names.
        Button {
            rollAlias(contactId: c.id)
        } label: {
            Text(L10n.contactListNewNameButton)
                .foregroundColor(.runTextPrimary)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 20)
                .padding(.vertical, 14)
        }
        .accessibilityIdentifier("menu_new_name")

        // Re-key this conversation's relay inboxes. NOT destructive
        // (nothing is deleted and the peer is unaffected), so it is styled
        // as an ordinary action and sits ABOVE the red block — but it IS a
        // relay round-trip, so it is gated on the same debounced
        // [litVisible] signal "Add contact" uses (see the settings sheet
        // for why the raw isRelayReachable flag is the wrong one here).
        Button {
            pendingResetRelayId = c.id
            pendingResetRelayAlias = c.alias
            menuContact = nil
            showResetRelayConfirm = true
        } label: {
            Text(resetRelayBusy ? L10n.contactListResetRelayInProgress : L10n.contactListResetRelayButton)
                .foregroundColor(litVisible && !resetRelayBusy ? .runTextPrimary : .runTextSecondary)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 20)
                .padding(.vertical, 14)
        }
        .disabled(!litVisible || resetRelayBusy)
        .accessibilityIdentifier("menu_reset_relay_access")

        // Guideline 1.2 — flag objectionable content / behaviour.
        // Confirm first — AbuseReport.compose
        // hands off to a mailto draft that lands outside Rún's sandbox,
        // unencrypted, and survives a Rún wipe. See the disclosure
        // dialog below (mirrors the post-block one at showPostBlockReport).
        Button {
            pendingReportId = c.id
            pendingReportAlias = c.alias
            menuContact = nil
            showReportConfirm = true
        } label: {
            Text(L10n.conversationReportAction)
                .foregroundColor(.runTextPrimary)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 20)
                .padding(.vertical, 14)
        }
        .accessibilityIdentifier("menu_report")

        // Guideline 1.2 — block an abusive contact.
        Button {
            pendingBlockId = c.id
            pendingBlockAlias = c.alias
            menuContact = nil
            showBlockConfirm = true
        } label: {
            Text(L10n.conversationBlockAction)
                .foregroundColor(.runError)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 20)
                .padding(.vertical, 14)
        }
        .accessibilityIdentifier("menu_block")

        Button {
            pendingDeleteId = c.id
            menuContact = nil
            showDeleteAlert = true
        } label: {
            Text(L10n.contactListDeleteContactButton)
                .foregroundColor(.runError)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 20)
                .padding(.vertical, 14)
        }
    }

    #if DEBUG
    private var stoneTapRect: some View {
        Rectangle()
            .fill(Color.black.opacity(0.001))
            .frame(width: 120, height: 160)
            .contentShape(Rectangle())
            .padding(.bottom, 20)
            .padding(.trailing, 10)
            .onTapGesture {
                let now = Date()
                if now.timeIntervalSince(lastStoneTap) > 3.0 {
                    stoneTapCount = 0
                }
                lastStoneTap = now
                stoneTapCount += 1
                if stoneTapCount >= 5 {
                    stoneTapCount = 0
                    showLogViewer = true
                }
            }
            .sheet(isPresented: $showLogViewer) {
                // The log buffer holds contact-id prefixes, vault-state
                // transitions, and Tor metadata. The sheet presents in its own
                // layer above the root, so the root's privacyCovered() does not
                // reach it — cover it explicitly for snapshot/capture parity with
                // the other sensitive sheets. (DEBUG-gated trigger, so Release
                // exposure is nil regardless; this is for DEBUG/TestFlight builds.)
                LogViewerView()
                    .privacyCovered()
            }
    }
    #endif

    // MARK: - Empty state

    /// Pre-connect bootstrap-stall copy, shared by the empty state and the
    /// contacts-present banner so the two surfaces can never drift. Deliberately
    /// non-terminal ("we'll keep trying") — Tor is still bootstrapping and may
    /// land minutes later, and iOS cannot restart it in-process anyway.
    private static let torStalledHint = L10n.connectTorStalledHint

    /// TIER 1 (AppState.torBootstrapStalledLong, 240 s of continuous
    /// bootstrapping): the actionable ceiling. Tor cannot be restarted in-process
    /// — tor_main runs once per process — so the only honest in-app advice is to
    /// close and reopen, deliberately worded like the `.relaunchRequired` hint
    /// above rather than offering a button that could not work.
    private static let torStalledLongHint = L10n.connectTorStalledLongHint

    /// TIER 2 (AppState.torRebootHintWarranted): appended below whichever stall
    /// hint is showing, after several failed bootstrap sessions across launches.
    /// Its own line + id so the stall copy above stays byte-identical.
    private static let torRebootHint = L10n.connectTorRebootHint

    /// The stall hint, tiered. Shared by the empty state and the contacts-present
    /// banner so the two surfaces can never drift — the same reason the strings
    /// above are statics.
    ///
    /// A11y: Tier 0 keeps the existing `tor_stalled_hint` identifier unchanged;
    /// Tier 1 renders under `tor_stalled_long_hint`, and the Tier-2 sentence is a
    /// separate `tor_reboot_hint` line. Only one of the two layouts renders at a
    /// time (same invariant the surrounding hints already rely on), so the ids
    /// stay unique.
    @ViewBuilder
    private var torStallHint: some View {
        VStack(spacing: 6) {
            if appState.torBootstrapStalledLong {
                Text(ContactListView.torStalledLongHint)
                    .font(.runeCaption)
                    .foregroundColor(Color.runTextSecondary)
                    .multilineTextAlignment(.center)
                    .accessibilityIdentifier("tor_stalled_long_hint")
            } else {
                Text(ContactListView.torStalledHint)
                    .font(.runeCaption)
                    .foregroundColor(Color.runTextSecondary)
                    .multilineTextAlignment(.center)
                    .accessibilityIdentifier("tor_stalled_hint")
            }
            if appState.torRebootHintWarranted {
                Text(ContactListView.torRebootHint)
                    .font(.runeCaption)
                    .foregroundColor(Color.runTextSecondary)
                    .multilineTextAlignment(.center)
                    .accessibilityIdentifier("tor_reboot_hint")
            }
        }
    }

    /// Real Tor bootstrap percent — the pacer's PHASE-ONE input. Ignored once
    /// torState is .connected (BootstrapProgressPacer.realTarget switches to
    /// its phase-two target then). 0% before bootstrap starts, never
    /// suppressed (a frozen-looking caption read as "did not load" to App
    /// Store review).
    private var torProgressPercent: Int {
        switch appState.torState {
        case .bootstrapping(let p): return p
        case .connected, .disconnected: return 0
        }
    }

    /// The two-phase pre-connect status line, shared verbatim by BOTH render
    /// sites below (empty state + relayTroubleBanner) — see AppState.
    /// connectStatusLine for the wording (byte-identical to Android's
    /// RelayConnectHints.connectStatusLine). No percent parameter any more
    /// (2026-09-16): `connectPercent` is still computed above and still
    /// drives `ringPulseOpacity`/ConnectionLog — [RelayConnectingCaption]
    /// below renders its own animated-dots suffix instead, purely visual.
    private var connectStatusLine: String {
        AppState.connectStatusLine(torConnected: appState.torState == .connected,
                                   externalProxy: appState.extProxyStatus.isExternal)
    }

    private var emptyState: some View {
        // Visible first-run content: App Store review flagged a blank/transparent
        // empty state as "the app did not load any contents", so an empty vault
        // shows a clear next action — the Add button — rather than a blank screen.
        VStack(spacing: 14) {
            // Fixed top spacer sized to the stone's foot (RunestoneGeometry,
            // shared with Android) so the button sits on it, not the old 2:1
            // weighted guess (2026-09-11). The trailing Spacer
            // below still centres the content on very tall screens.
            Spacer().frame(height: Self.belowStoneSpacer)
            // Not rendered at all until the relay has answered once (2026-09-11)
            // — the pre-connect placeholder shows only the
            // runestone + caption. After the first reveal a reachability flap
            // keeps it on screen, disabled. Android sibling: ContactListScreen.
            if listRevealed {
                Button {
                    onAddContact()
                } label: {
                    Text(L10n.addContactTitle)
                        .fontWeight(.semibold)
                        .foregroundColor(Color.runBackground)
                        .padding(.horizontal, 24)
                        .padding(.vertical, 12)
                        .background(litVisible
                                    ? Color.runTextPrimary.opacity(0.85)
                                    : Color.runTextPrimary.opacity(0.4))
                        .clipShape(Capsule())
                }
                // Minting needs the relay; keep the button inert until it answers.
                // Gate on litVisible (same debounced signal as the runestone marker
                // + the settings-sheet Add-contact row) so the button, the stone, and
                // the "Connecting…" caption never disagree during a flapping circuit.
                .disabled(!litVisible)
                .accessibilityIdentifier("empty_add_contact_button")
            }
            if !litVisible {
                Spacer().frame(height: Self.belowRingSpacer(buttonShown: listRevealed))
                switch appState.relayConnectPhase {
                case .relaunchRequired:
                    // Tor is dead for this process (once-per-process tor_main) —
                    // Reconnect/NEWNYM can't help, so don't offer them. Honest
                    // hint only; leaving the app also auto-recycles the process
                    // (ContentView exits on .background), so following this hint
                    // — or just going home and coming back — both work.
                    Text(L10n.connectRelayRelaunchHint)
                        .font(.runeCaption)
                        .foregroundColor(Color.runTextSecondary)
                        .multilineTextAlignment(.center)
                        .accessibilityIdentifier("relay_relaunch_hint")
                case .stalled:
                    // Self-heal (NEWNYM) exhausted (QA #1): honest status + a manual
                    // Reconnect (another circuit kick) and a relaunch hint — iOS can't
                    // restart Tor in-process, so a dead Tor thread needs a reopen.
                    VStack(spacing: 10) {
                        Text(L10n.connectRelayStalledReopenHint)
                            .font(.runeCaption)
                            .foregroundColor(Color.runTextSecondary)
                            .multilineTextAlignment(.center)
                        Button { appState.reconnectRelay() } label: {
                            Text(L10n.connectReconnectButton)
                                .font(.runeCallout)
                                .foregroundColor(Color.runTextPrimary)
                                .padding(.horizontal, 20).padding(.vertical, 10)
                                .background(Color.runTextPrimary.opacity(0.12))
                                .clipShape(Capsule())
                        }
                        .accessibilityIdentifier("relay_reconnect_button")
                    }
                case .connecting:
                    if appState.torBootstrapStalled, appState.torState != .connected {
                        // Pre-connect bootstrap stall (App Store review 2.1): Tor has
                        // been starting for 90s+ without landing — the single most
                        // likely cause is a network that blocks it. NON-TERMINAL:
                        // bootstrap is still running and this retracts itself if it
                        // succeeds. Escalates to the close-and-reopen wording at
                        // 240 s, and gains the restart-your-iPhone line after
                        // several failed sessions across launches — see torStallHint.
                        torStallHint
                            .padding(.horizontal, 24)
                    } else {
                        // Animated dots + delayed hint escalation (user
                        // directive 2026-09-16) — see RelayConnectingCaption.
                        RelayConnectingCaption(
                            statusLine: connectStatusLine,
                            wrapInHorizontalPadding: true,
                            onTripleTap: { showConnectLog.toggle() }
                        )
                    }
                }
                // External SOCKS proxy mode: always say whose proxy is in use and
                // whether it answers, in every pre-connect phase. Renders nothing
                // when the embedded Tor is the transport.
                ExternalProxyStatusLine()
                    .padding(.horizontal, 24)
            }
            // Connection-log panel, OUTSIDE the !litVisible block: once opened
            // (triple-tap on the caption) it stays until the user taps it
            // closed — it must NOT vanish when the relay is reached (user
            // directive 2026-09-12). Renders nothing while collapsed.
            // Android sibling: ContactListScreen's empty-contacts column.
            ConnectionLogPanel(expanded: showConnectLog)
                .onTapGesture { showConnectLog = false }
                .padding(.horizontal, 24)
            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        // NOTE: the first-run how-to prompt is driven once from loadContacts() via the
        // durable vault meta — NOT from an emptyState.onAppear, which re-fired on every
        // relaunch AND could fire for a contacts-having vault during the async load race.
    }

    // MARK: - Relay trouble banner (contacts-present sibling of the emptyState hints)

    // With contacts present the ONLY relay-trouble signal used to be the unlit
    // runestone — the stalled Reconnect and the relaunch hint rendered
    // exclusively in emptyState, so paired users (the ones actually waiting on
    // messages) never saw either. Same phase gating as emptyState, pinned as a
    // compact banner; only one of the two layouts renders at a time, so the
    // shared accessibility ids stay unique.
    //
    // Gated on the RAW appState.isRelayReachable — the SAME flag that dims and
    // disables the rows below (Android parity: ContactListScreen gates both its
    // rows and its connect hint on isRelayReachable). litVisible is the 3 s
    // dark-out debounce for the runestone/buttons; gating the banner on it gave
    // a deterministic ≥3 s "rows dimmed, no banner" window after every
    // reachable→unreachable transition.
    // Also gated on `listRevealed`: before the first reveal the pre-connect
    // placeholder (emptyState) is already rendering the caption/hint/Reconnect
    // for this exact phase, so a banner here would DUPLICATE
    // tor_progress_caption / relay_reconnect_button in the a11y tree — the two
    // must never render at once (that is what makes the shared ids unique).
    private var showsRelayTroubleBanner: Bool {
        listRevealed && !(contacts.isEmpty && groups.isEmpty)
            && (!appState.isRelayReachable || showConnectLog)
    }

    /// The update nudge never stacks on the push prompt (no dialog priority queue).
    private var updateNudgeVisible: Bool {
        appState.showUpdateNudge != nil && !appState.showPushPrompt
    }

    /// A referral OFFER consent gate (and the debug-mode dialog) always win over
    /// this purely informational dialog when both are pending.
    private var referralRelayDialogVisible: Bool {
        pendingOffer == nil && !showDebugModeDialog && !appState.referralRelayEvents.isEmpty
    }

    @ViewBuilder
    private var relayTroubleBanner: some View {
        // Also kept on screen while the connection-log panel is open — the log
        // must not vanish when the relay is reached
        // (2026-09-12); only the status content is gated on reachability.
        if showsRelayTroubleBanner {
            VStack(spacing: 10) {
                if appState.isRelayReachable {
                    // Log-only banner after the relay answered.
                    EmptyView()
                } else if appState.relayConnectPhase == .relaunchRequired {
                    Text(L10n.connectRelayRelaunchHint)
                        .font(.runeCaption)
                        .foregroundColor(Color.runTextSecondary)
                        .multilineTextAlignment(.center)
                        .accessibilityIdentifier("relay_relaunch_hint")
                } else if appState.relayConnectPhase == .connecting {
                    if appState.torBootstrapStalled {
                        // PRE-connect bootstrap stall — paired users used to get nothing
                        // at all here (the banner only rendered for the post-connect
                        // phases), so a blocked network looked identical to a healthy
                        // one. No Reconnect button: NEWNYM needs a bootstrapped Tor.
                        // Same tiered copy as the empty state (see torStallHint).
                        torStallHint
                    } else {
                        // Plain pre-connect wait, not yet stalled: paired users used
                        // to see NOTHING here (the banner was gated off entirely for
                        // this case) even though the runestone was unlit — the
                        // percent line makes the wait visible instead of silent. Same
                        // two-phase status line as the empty state above (the e2e
                        // "Connecting" XPath that used to force these two sites to
                        // differ in wording is now scoped to the referral dialog —
                        // see e2e-tests/helpers/Device.ts). Animated dots + delayed
                        // hint escalation: see the empty-state sibling above and
                        // RelayConnectingCaption for the full rationale.
                        RelayConnectingCaption(
                            statusLine: connectStatusLine,
                            captionCentered: true,
                            onTripleTap: { showConnectLog.toggle() }
                        )
                    }
                } else {
                    Text(L10n.connectRelayStalled)
                        .font(.runeCaption)
                        .foregroundColor(Color.runTextSecondary)
                        .multilineTextAlignment(.center)
                    Button { appState.reconnectRelay() } label: {
                        Text(L10n.connectReconnectButton)
                            .font(.runeCallout)
                            .foregroundColor(Color.runTextPrimary)
                            .padding(.horizontal, 20).padding(.vertical, 10)
                            .background(Color.runTextPrimary.opacity(0.12))
                            .clipShape(Capsule())
                    }
                    .accessibilityIdentifier("relay_reconnect_button")
                }
                // External SOCKS proxy mode status (see the empty-state sibling).
                // Never at the same time as that one: the banner needs
                // listRevealed + contacts, the placeholder renders only before.
                if !appState.isRelayReachable {
                    ExternalProxyStatusLine()
                }
                // Same placement rule as the placeholder: directly under the
                // status content; outlives it once opened (see the gate above).
                ConnectionLogPanel(expanded: showConnectLog)
                    .onTapGesture { showConnectLog = false }
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
            .background(Color.runBackground.opacity(0.92))
            .clipShape(RoundedRectangle(cornerRadius: 14))
            // 40 not 24: the banner floats above the home indicator; at 24 the
            // "Reaching the relay…" line read as glued to the screen bottom.
            .padding(.bottom, 40)
        }
    }

    // MARK: - List

    /// Device's real top safe-area inset (status bar / notch / Dynamic
    /// Island height — 20 / 44–48 / 59–62pt), read directly from the key
    /// window rather than trusted through SwiftUI's own safe-area
    /// propagation (the window's insets are settled long before this view
    /// exists — the PIN screen precedes it). Mirrors the keyWindow() helper
    /// in ScreenshotProtection.swift. Falls back to 44 (a notched device's
    /// inset) if no window is resolvable. One input to topClearance.
    private var topSafeAreaInset: CGFloat {
        let scene = UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .first
        let window = scene?.windows.first { $0.isKeyWindow } ?? scene?.windows.first
        return window?.safeAreaInsets.top ?? 44
    }

    /// Absolute distance from the WINDOW top to the first row's top edge. The
    /// scroll view below ignores the top safe area, so this spacer alone
    /// positions the first row — nothing depends on SwiftUI's automatic inset
    /// propagation, which is what made the pre-2026-09-04 layout drift (see
    /// the body comment). Three floors, the largest wins:
    ///   * 88pt — the tuned rest position on the 44pt-notch (11 Pro Max) and
    ///     SE (20pt) classes, preserved exactly (2026-09-02 on-device tuning;
    ///     47–48pt notches land ≤4pt lower via the next floor);
    ///   * key-window inset + 44pt — the status bar / Dynamic Island plus the
    ///     inline nav-bar band, so on a 62pt Dynamic Island device the row
    ///     (106pt) clears the floating cogwheel (its 36pt button rect ends at
    ///     102pt; sim-measured iPhone 17 Pro / iOS 26.5) instead of sliding
    ///     under it;
    ///   * the container's own reported top inset (containerSafeTop), reactive,
    ///     in case a future OS makes the nav band taller than 44pt.
    private var topClearance: CGFloat {
        max(88, topSafeAreaInset + 44, containerSafeTop)
    }

    private var contactsList: some View {
        ScrollView {
            LazyVStack(spacing: 0) {
                // Top clearance — see topClearance. Sized in WINDOW coordinates
                // because the ScrollView ignores the top safe area below.
                Color.clear.frame(height: topClearance)
                if contacts.contains(where: { $0.stale }) {
                    RepairBanner(staleCount: contacts.filter { $0.stale }.count,
                                 onTap: onAddContact)
                }
                // Pending invitations closed with "Later": not a conversation;
                // tapping reopens the invitation dialog (Join / Later / Decline).
                ForEach(referralOfferRows) { off in
                    Button {
                        pendingOffer = off
                        syncReferralOffers()
                        syncGroupInvites()
                    } label: {
                        ReferralOfferListRow(offer: off)
                    }
                    .accessibilityIdentifier("referral_offer_row_\(off.id)")
                }
                ForEach(groupInviteRows) { inv in
                    Button {
                        pendingGroupInvite = inv
                        syncGroupInvites()
                    } label: {
                        GroupInviteListRow(invite: inv)
                    }
                    .accessibilityIdentifier("group_invite_row_\(inv.id)")
                }
                ForEach(groups) { group in
                    Button {
                        appState.markGroupRead(group.id)
                        onGroupTapped(group.id)
                    } label: {
                        GroupListRow(group: group, unreadCount: appState.groupUnreadCounts[group.id] ?? 0)
                    }
                    .accessibilityIdentifier("group_row_\(group.id)")
                    // Grey out + disable until rowsEnabled: relay reachable AND
                    // the white R's fade-in complete, so the tap-disable lifts the
                    // moment AFTER the runestone lights (never before it) and
                    // snaps back the instant reachability is lost. Only the
                    // opacity fade is animated; Button already no-ops its action
                    // while disabled.
                    .opacity(rowsEnabled ? 1 : 0.4)
                    .animation(.easeInOut(duration: 0.4), value: rowsEnabled)
                    .disabled(!rowsEnabled)
                    .contextMenu {
                        Button(role: .destructive) {
                            guard rowsEnabled else { return }
                            pendingLeaveGroupId = group.id
                            pendingLeaveGroupIsAdmin = group.isAdmin
                            showLeaveGroupAlert = true
                        } label: {
                            Label(L10n.groupInfoLeaveGroup, systemImage: "rectangle.portrait.and.arrow.right")
                        }
                    }
                }
                ForEach(contacts) { contact in
                    Button {
                        if contact.stale { onAddContact() }
                        else {
                            appState.markContactRead(contact.id)
                            onContactTapped(contact.id)
                        }
                    } label: {
                        ContactRow(contact: contact, unreadCount: appState.unreadCounts[contact.id] ?? 0)
                    }
                    .accessibilityIdentifier("contact_row_\(contact.id)")
                    // Same dim+disable treatment as the group row above.
                    .opacity(rowsEnabled ? 1 : 0.4)
                    .animation(.easeInOut(duration: 0.4), value: rowsEnabled)
                    .disabled(!rowsEnabled)
                    // highPriority (not simultaneous): a recognized long press shows
                    // the menu and SUPPRESSES the row's tap. A quick tap still opens it.
                    // Guarded the same way — long-press is a row interaction too.
                    .highPriorityGesture(
                        LongPressGesture(minimumDuration: 0.4)
                            .onEnded { _ in if rowsEnabled { menuContact = contact } }
                    )
                }
                // Baseline breathing room below the last row, mirroring the
                // 44pt top spacer — without it the last row's bottom edge sits
                // exactly on the safe-area/home-indicator line with zero
                // margin, which reads as clipped even when technically
                // scrolled fully into view. Additive with the safeAreaInset
                // reserved for relayTroubleBanner above (that inset is on the
                // ScrollView itself; this spacer is inside its content).
                Color.clear.frame(height: 24)
            }
        }
        .accessibilityIdentifier("contact_list")
        // Deterministic top edge: the scroll view starts at the window top and
        // the explicit spacer above positions the first row (content still
        // scrolls under the transparent nav bar as before). The BOTTOM edge
        // keeps honouring the safe area — that is what makes the
        // .safeAreaInset(edge: .bottom) banner reserve room so the last row
        // scrolls fully clear of it.
        .ignoresSafeArea(edges: .top)
    }

    // MARK: - Referral sheets

    @ViewBuilder
    private func introducePickerSheet(_ from: ContactItem) -> some View {
        let candidates = contacts.filter { $0.id != from.id && !$0.stale }
        NavigationStack {
            ZStack {
                Color.runBackground.ignoresSafeArea()
                VStack(spacing: 8) {
                    Text(L10n.referralIntroduceBody(from.alias))
                        .font(.runeCaption).foregroundColor(Color.runTextSecondary)
                        .multilineTextAlignment(.center).padding(.horizontal).padding(.top, 12)
                    if candidates.isEmpty {
                        Spacer()
                        Text(L10n.referralNoCandidates)
                            .foregroundColor(Color.runTextSecondary)
                        Spacer()
                    } else {
                        // Centered, scrollable, multi-select recipient buttons.
                        // Tap toggles; long-press reveals that contact's memory.
                        ScrollView {
                            LazyVStack(spacing: 8) {
                                ForEach(candidates) { other in
                                    let isSelected = introduceSelected.contains(other.id)
                                    HStack {
                                        Spacer()
                                        Text((isSelected ? "✓  " : "") + other.alias)
                                            .foregroundColor(isSelected ? Color.runBackground : Color.runTextPrimary)
                                            .lineLimit(1).truncationMode(.tail)
                                        Spacer()
                                    }
                                    .padding(.horizontal, 16).padding(.vertical, 14)
                                    .frame(maxWidth: .infinity)
                                    .background(isSelected ? Color.runTextPrimary : Color.runSurface)
                                    .clipShape(RoundedRectangle(cornerRadius: 12))
                                    .contentShape(Rectangle())
                                    .accessibilityIdentifier("introduce_pick_\(other.id)")
                                    .onTapGesture {
                                        if isSelected { introduceSelected.remove(other.id) }
                                        else { introduceSelected.insert(other.id) }
                                    }
                                    .onLongPressGesture {
                                        introduceMnemonic = other.mnemonic.isEmpty ? L10n.contactListNoMemoryYet : other.mnemonic
                                    }
                                }
                            }
                            .padding(.horizontal, 16)
                        }
                    }
                }
            }
            .navigationTitle(L10n.referralIntroduceTitle(from.alias))
            .navigationBarTitleDisplayMode(.inline)
            .runNavigationBarChrome()
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button(L10n.commonCancel) { introduceFrom = nil }.foregroundColor(Color.runTextPrimary)
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    // F5: relay reachability can drop WHILE this sheet is open (the
                    // menu-item gate only covers opening it) — same "Connecting…"
                    // label swap the referral-accept dialog already uses.
                    Button(!litVisible ? L10n.referralConnecting : (introduceSelected.isEmpty ? L10n.referralIntroduceButton : L10n.referralIntroduceButtonCount(introduceSelected.count))) {
                        // Fan out off the main actor (blocking Tor sends).
                        appState.startReferrals(fromContactId: from.id, toContactIds: Array(introduceSelected)) { allStarted in
                            // F2: nil result (no transport / invalid) is the only
                            // outcome worth surfacing — a send that started but
                            // failed to deliver is a durable, redriven obligation
                            // core-side, so success never needs a confirmation here.
                            if !allStarted {
                                introduceError = L10n.referralIntroduceError
                                showIntroduceError = true
                            }
                        }
                        introduceFrom = nil
                    }
                    .disabled(introduceSelected.isEmpty || !litVisible)
                    .foregroundColor(introduceSelected.isEmpty || !litVisible ? Color.runTextSecondary : Color.runTextPrimary)
                    .accessibilityIdentifier("introduce_confirm")
                }
            }
            // Long-press a recipient → show their memory.
            .overlay {
                if let memo = introduceMnemonic {
                    RuneDialogOverlay(
                        message: memo,
                        onScrimTap: { introduceMnemonic = nil },
                        actions: [RuneDialogAction(L10n.commonOk) { introduceMnemonic = nil }]
                    )
                }
            }
        }
        .preferredColorScheme(.dark)
    }

    // MARK: - Helpers

    /// Which referral offer's dialog is up and which show as rows. The decision is
    /// GroupInvitePresentation.kt (commonMain), the rule Android's consentToShow /
    /// referralOfferRows call too. busy=false for the dialog on purpose: an accept in
    /// flight keeps / re-adopts the "Connecting…" dialog (Approve un-defers first);
    /// the real busy flag only hides the rows.
    private func syncReferralOffers() {
        let pending = appState.pendingReferralOffers()
        let pendingIds = pending.map { $0.introId }
        appState.pruneDeferredReferralOffers(pendingIds: pendingIds)
        let deferred = Array(appState.deferredReferralOfferIds)
        func item(_ id: String) -> RefOffer? {
            pending.first(where: { $0.introId == id }).map {
                RefOffer(id: $0.introId, introducerAlias: $0.introducerAlias, peerAlias: $0.peerAlias)
            }
        }
        if pendingIds.isEmpty {
            if !referralBusy { pendingOffer = nil }   // consumed (accepted) → dismiss
        } else {
            let shownId = pendingOffer?.id
            let id = GroupInvitePresentation.shared.toAutoPresent(
                pendingIds: pendingIds, deferredIds: deferred, shownId: shownId, busy: false)
            if let id {
                if id != shownId, let next = item(id) { pendingOffer = next }
            } else if pendingOffer != nil {
                pendingOffer = nil
            }
        }
        let rowIds = GroupInvitePresentation.shared.rowIds(
            pendingIds: pendingIds, deferredIds: deferred, shownId: pendingOffer?.id, busy: referralBusy)
        referralOfferRows = rowIds.compactMap(item)
    }

    /// Which group invite's dialog is up and which show as rows. The decision is
    /// GroupInvitePresentation.kt (commonMain), the rule Android's consentToShow /
    /// groupInviteRows call too; this only maps ids to the Swift items.
    /// A referral offer on screen outranks the invite dialog (one prompt at a
    /// time): the invite dialog is cleared unless a join is in flight.
    private func syncGroupInvites() {
        let pending = appState.pendingGroupInvites()
        let pendingIds = pending.map { $0.groupId }
        appState.pruneDeferredGroupInvites(pendingIds: pendingIds)
        let deferred = Array(appState.deferredGroupInviteIds)
        func item(_ id: String) -> GroupInviteItem? {
            pending.first(where: { $0.groupId == id }).map {
                GroupInviteItem(id: $0.groupId, inviterAlias: $0.inviterAlias, groupName: $0.groupName,
                                adminMismatch: $0.adminMismatch, priorAdminAlias: $0.priorAdminAlias)
            }
        }
        if pendingOffer != nil {
            if !groupInviteBusy { pendingGroupInvite = nil }
        } else {
            let shownId = pendingGroupInvite?.id
            let id = GroupInvitePresentation.shared.toAutoPresent(
                pendingIds: pendingIds, deferredIds: deferred, shownId: shownId, busy: groupInviteBusy)
            if let id {
                if id != shownId, let next = item(id) { pendingGroupInvite = next }
            } else if pendingGroupInvite != nil {
                pendingGroupInvite = nil   // accepted/declined → dismiss
            }
        }
        let rowIds = GroupInvitePresentation.shared.rowIds(
            pendingIds: pendingIds, deferredIds: deferred, shownId: pendingGroupInvite?.id, busy: groupInviteBusy)
        groupInviteRows = rowIds.compactMap(item)
    }

    private func loadContacts() {
        guard let vault = appState.vault else { return }
        // Guideline 1.2: blocked contacts are removed from the feed instantly
        // and never reappear — filter them out of the list on every load.
        let blockedIds = BlockStore.blocked()
        hasBlockedContacts = !blockedIds.isEmpty
        let allContacts = vault.getAllContacts().filter { !blockedIds.contains($0.contactId) }
        // Maximum shield ids (empty unless this device is provably at MAXIMUM).
        let maximumIds = appState.maximumShieldContactIds()
        contacts = allContacts.map { contact in
            // Resolve the voucher's alias (if the introducer is still a contact)
            // so the row can name who introduced this contact.
            let introducerAlias = contact.vouchedByContactId.flatMap { vid in
                allContacts.first { $0.contactId == vid }?.alias
            }
            return ContactItem(
                id: contact.contactId,
                alias: contact.alias,
                mnemonic: contact.mnemonic,
                stale: MessageManagerKt.contactNeedsRepair(vault: vault, contactId: contact.contactId)
                    || appState.relayLostContacts.contains(contact.contactId),
                pending: MessageManagerKt.contactAwaitingPeerInbox(vault: vault, contactId: contact.contactId),
                referred: contact.vouchedByContactId != nil,
                introducerAlias: introducerAlias,
                maximumShield: maximumIds.contains(contact.contactId)
            )
        }
        // getAllContacts() returns full ContactRecords,
        // each carrying a live 32-byte sharedSecret (the legacy-envelope key
        // pre-image). Only the secret-free ContactItem projection above is
        // retained, so wipe every source record now that the last use (the
        // introducerAlias lookup inside the map above) is done. Mirrors
        // Android's ContactListScreen.kt / GroupInfoScreen.kt shape.
        for contact in allContacts { contact.sharedSecret.secureWipe() }
        groups = vault.getAllGroups().map { group in
            GroupItem(id: group.groupId, name: group.name, isAdmin: group.isAdmin)
        }
    }

    private func deleteContact(contactId: String) {
        // Only drop the row if the DB delete actually ran. When
        // vault == nil the delete no-ops, so removing the row anyway made the contact
        // reappear on the next loadContacts().
        guard appState.vault != nil else { return }
        // Local delete + best-effort relay DELETE of both inbound inboxes
        // (shared commonMain path — identical set to Android). The row disappears
        // immediately; only the network cleanup is detached, and it runs ONLY if the
        // local delete actually succeeded (the Kotlin side gates on that).
        contacts.removeAll { $0.id == contactId }
        Task { @MainActor in
            let ok = await appState.deleteContactPurgingRelay(contactId: contactId)
            // The local delete failed (vault gone mid-tap) — put the row back rather
            // than showing a contact that still exists as deleted.
            if !ok { loadContacts() }
        }
    }

    /// H-1 "Reset relay access": re-key both of this contact's inbound relay
    /// inboxes. Non-destructive, so no row changes; only the result dialog.
    private func resetRelayAccess(contactId: String) {
        resetRelayBusy = true
        Task { @MainActor in
            let ok = await appState.resetRelayAccess(contactId: contactId)
            resetRelayBusy = false
            pendingResetRelayId = nil
            // The failure copy is literally true: the pending marker is durable and
            // the control-poll reconcile finishes the rotation on its own.
            resetRelayResult = ok
                ? L10n.contactListResetRelaySuccess
                : L10n.contactListResetRelayFailure
            showResetRelayResult = true
        }
    }

    /// Block filters GroupManager's SEND
    /// fan-out but never touches group membership — a blocked contact stays a
    /// member of any group shared with the user, and (before this check) the
    /// victim had no signal that other members' messages still reach them
    /// there. Groups this user shares WITH [contactId], read fresh at
    /// block-confirm time (not cached — membership can change between list
    /// loads).
    private func sharedGroups(withContactId contactId: String) -> [GroupItem] {
        guard let vault = appState.vault else { return [] }
        return groups.filter { g in
            vault.getGroupMembers(groupId: g.id).contains { $0.contactId == contactId }
        }
    }

    /// Block-confirm's primary action. A shared group routes through the
    /// warning dialog (showBlockGroupWarning) instead of blocking immediately;
    /// with none shared this is exactly the pre-fix behaviour.
    private func confirmBlock(contactId: String) {
        let shared = sharedGroups(withContactId: contactId)
        guard !shared.isEmpty else {
            blockContact(contactId: contactId)
            return
        }
        pendingBlockSharedGroups = shared
        showBlockGroupWarning = true
    }

    /// Guideline 1.2: block a contact — instantly hides them and their messages
    /// from the UI (BlockStore filters them on every load) AND excludes their inbox
    /// from the shared text/control poll (best-effort; see UserSafety.BlockStore).
    /// Then offers to report them so the developer is notified.
    ///
    /// Block is deliberately NEVER paired with an automatic group leave here —
    /// see showBlockGroupWarning: leaving is always the user's own separate
    /// choice, offered but never forced, so block stays reversible.
    private func blockContact(contactId: String) {
        let alias = contacts.first { $0.id == contactId }?.alias ?? "this contact"
        BlockStore.block(contactId)
        hasBlockedContacts = true
        contacts.removeAll { $0.id == contactId }
        reportedId = contactId
        reportedAlias = alias
        pendingBlockId = nil
        pendingBlockSharedGroups = []
        showPostBlockReport = true
    }

    /// Actions for showBlockGroupWarning: Cancel, up to 3 "Leave <group>"
    /// offers (real IRL-paired overlap between two people is rarely more than
    /// that — "Block Anyway" still covers the rest, and any group can still be
    /// left from its own screen), then the destructive catch-all LAST (safety
    /// rule — see RuneDialog in UIComponents).
    private var blockGroupWarningActions: [RuneDialogAction] {
        var actions: [RuneDialogAction] = [
            .secondary(L10n.commonCancel, a11yId: "block_shared_groups_cancel_button") {
                pendingBlockId = nil
                pendingBlockSharedGroups = []
            },
        ]
        for (idx, g) in pendingBlockSharedGroups.prefix(3).enumerated() {
            actions.append(
                RuneDialogAction(L10n.contactListBlockSharedGroupsLeaveButton(g.name),
                                  a11yId: "block_shared_groups_leave_button_\(idx)") {
                    pendingLeaveGroupId = g.id
                    pendingLeaveGroupIsAdmin = g.isAdmin
                    showLeaveGroupAlert = true
                    if let id = pendingBlockId { blockContact(contactId: id) }
                }
            )
        }
        actions.append(
            RuneDialogAction(L10n.contactListBlockSharedGroupsAnywayButton, color: .runeDanger,
                              a11yId: "block_shared_groups_anyway_button") {
                if let id = pendingBlockId { blockContact(contactId: id) }
            }
        )
        return actions
    }

    // Introducer-side info modal (referral relay) — title/message derived from
    // the HEAD of appState.referralRelayEvents (a FIFO; see AppState). Variant
    // selection per the shared contract: `complete` (both accepts relayed) >
    // `relayed` (this is the first of the two) > queued (relay unreachable,
    // will redrive automatically). A computed var (not stored) so it always
    // reflects whichever event is currently at the head.
    private var referralRelayDialogTitle: String {
        guard let e = appState.referralRelayEvents.first else { return "" }
        return e.complete ? L10n.referralRelayedCompleteTitle : L10n.referralRelayedTitle
    }

    private var referralRelayDialogMessage: String {
        guard let e = appState.referralRelayEvents.first else { return "" }
        if e.complete {
            return L10n.referralRelayedComplete(e.acceptedByAlias, e.otherAlias)
        } else if e.relayed {
            return L10n.referralRelayedFirst(e.acceptedByAlias, e.otherAlias)
        } else {
            return L10n.referralRelayedQueued(e.acceptedByAlias, e.otherAlias)
        }
    }
}

// MARK: - Relay connecting caption (animated dots + delayed hint)

/// The pre-connect caption (`tor_progress_caption`) + its delayed hint
/// (`connect_relay_hint`), shared verbatim by BOTH render sites in
/// [ContactListView] (`emptyState` + `relayTroubleBanner`). A dedicated View
/// struct — not a computed property — so `.task` below can host both clocks
/// as `@State`: SwiftUI cancels an in-flight `.task` and drops `@State` the
/// instant the enclosing `if`/`switch` branch stops rendering this struct,
/// which is exactly the mechanism that resets both clocks on re-entry with
/// no explicit "stop" call (Compose sibling: ContactListScreen.kt's
/// `rememberConnectDotsStep` / `rememberConnectHintStage`, which rely on the
/// same "a dropped branch discards its remembered state" behaviour).
///
/// The bootstrap percent no longer renders here at all (2026-09-16 user
/// directive) — replaced by a fixed-width, always-present three-dot slot
/// that cycles "." → ".." → "..." every 600 ms. Built as ONE concatenated
/// [Text] (dots differ only by `.foregroundColor`, never by literal
/// character) so `tor_progress_caption`'s own accessibility text/VoiceOver
/// label stays a STABLE "…" — three literal dot characters, always — instead
/// of the string length changing as the animation cycles; that stability is
/// also what keeps e2e `getText()` lookups on this id unaffected by the
/// animation phase.
///
/// [captionCentered] and [wrapInHorizontalPadding] preserve each render
/// site's pre-existing layout quirk (the empty-state site wraps the whole
/// caption+hint pair in 24pt horizontal padding but never centers the
/// caption's own multiline alignment; the banner site centers the caption
/// but adds no extra padding of its own, since the banner box already pads
/// itself) rather than unifying them — neither was reported as a visual bug.
private struct RelayConnectingCaption: View {
    let statusLine: String
    var captionCentered: Bool = false
    var wrapInHorizontalPadding: Bool = false
    let onTripleTap: () -> Void

    /// 0, 1, or 2 opaque dots out of the fixed 3-glyph slot; steps every
    /// 600 ms while [runDots] runs, restarting at 0 after the third step —
    /// "." → ".." → "..." → "." (never null: this struct only exists while
    /// the caption itself is visible, so there is no "not started yet" case
    /// to represent, unlike the old percent's optional pacer input).
    @State private var dotStep = 0
    /// 0 = no hint, 1 = [L10n.connectRelayFirstTimeHint] (10–30 s), 2 =
    /// [L10n.connectRelaySlowHint] REPLACING it (30 s+). See [runHint].
    @State private var hintStage = 0

    private var captionWithDots: Text {
        var dots = Text("")
        for i in 0..<3 {
            dots = dots + Text(".").foregroundColor(i <= dotStep ? Color.runTextSecondary : .clear)
        }
        return Text(statusLine) + dots
    }

    var body: some View {
        Group {
            if wrapInHorizontalPadding {
                captionAndHint.padding(.horizontal, 24)
            } else {
                captionAndHint
            }
        }
        .task {
            async let dots: Void = runDots()
            async let hint: Void = runHint()
            _ = await (dots, hint)
        }
    }

    private var captionAndHint: some View {
        VStack(spacing: 4) {
            captionWithDots
                .font(.runeCallout)
                .foregroundColor(Color.runTextSecondary)
                .multilineTextAlignment(captionCentered ? .center : .leading)
                .accessibilityIdentifier("tor_progress_caption")
                // Additive gesture only: the caption keeps its
                // accessibilityIdentifier (the e2e suite keys on
                // `tor_progress_caption`) and had no tap behaviour of its
                // own to interfere with.
                .tripleTapToggle { onTripleTap() }
            if hintStage > 0 {
                Text(hintStage == 1 ? L10n.connectRelayFirstTimeHint : L10n.connectRelaySlowHint)
                    .font(.runeCaption)
                    .foregroundColor(Color.runTextSecondary)
                    .multilineTextAlignment(.center)
                    // The slow-network hint is a full sentence: let it wrap (a parent
                    // lineLimit(1) truncated it to "…det är p…" on an iPhone 11, 2026-09-17).
                    .lineLimit(3)
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityIdentifier("connect_relay_hint")
            }
        }
    }

    /// Cancelled by SwiftUI the moment this struct leaves the hierarchy (see
    /// the type doc) — no explicit stop condition needed here.
    private func runDots() async {
        while !Task.isCancelled {
            try? await Task.sleep(nanoseconds: 600_000_000)
            if Task.isCancelled { return }
            dotStep = (dotStep + 1) % 3
        }
    }

    /// Same cancellation story as [runDots]. 10 s of silence, then the
    /// first-connection hint for 20 more seconds, then the slow-network hint
    /// REPLACES it (never appends) for as long as the caption stays visible.
    private func runHint() async {
        try? await Task.sleep(nanoseconds: 10_000_000_000)
        if Task.isCancelled { return }
        hintStage = 1
        try? await Task.sleep(nanoseconds: 20_000_000_000)
        if Task.isCancelled { return }
        hintStage = 2
    }
}

// MARK: - Contact row

private struct ContactRow: View {
    let contact: ContactListView.ContactItem
    var unreadCount: Int = 0

    private static let avatarColors: [Color] = [
        Color(hex: 0x5C6BC0), // indigo
        Color(hex: 0x26A69A), // teal
        Color(hex: 0xEF5350), // red
        Color(hex: 0xAB47BC), // purple
        Color(hex: 0x42A5F5), // blue
        Color(hex: 0xFF7043), // deep orange
        Color(hex: 0x66BB6A), // green
        Color(hex: 0xEC407A), // pink
        Color(hex: 0x8D6E63), // brown
        Color(hex: 0x78909C), // blue-grey
    ]

    var body: some View {
        HStack(spacing: 12) {
            ZStack {
                Circle()
                    .fill(avatarColor)
                    .frame(width: 44, height: 44)
                Text(contact.alias.prefix(1).uppercased())
                    .font(.runeHeadline)
                    .foregroundColor(.white)
            }
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(contact.alias)
                        .font(.runeBody)
                        .foregroundColor(contact.stale ? Color.runTextSecondary : Color.runTextPrimary)
                        .lineLimit(1)
                        .truncationMode(.tail)
                        .accessibilityIdentifier("contact_name_\(contact.id)")
                    if contact.maximumShield {
                        // Maximum shield (MaximumShield.kt) — right after the name.
                        Image(systemName: "shield.fill")
                            .font(.system(size: 13))
                            .foregroundColor(Color.runTextSecondary)
                            .accessibilityLabel(L10n.contactMaximumShieldDescription)
                            .accessibilityIdentifier("contact_maximum_shield_\(contact.id)")
                    }
                }
                if contact.stale {
                    Text(L10n.contactListRepairRequired)
                        .font(.runeCaption2)
                        .foregroundColor(Color.runTextSecondary)
                        .accessibilityIdentifier("contact_repair_\(contact.id)")
                } else if contact.pending {
                    Text(L10n.contactListWaitingForInbox)
                        .font(.runeCaption2)
                        .foregroundColor(Color.runTextSecondary)
                        .accessibilityIdentifier("contact_pending_\(contact.id)")
                } else if contact.referred {
                    // Informational provenance only — usable immediately.
                    Text(contact.introducerAlias.map { L10n.contactListIntroducedBy($0) } ?? L10n.contactListIntroduced)
                        .font(.runeCaption2)
                        .foregroundColor(Color.runTextSecondary)
                        .accessibilityIdentifier("contact_referred_\(contact.id)")
                }
            }
            Spacer()
            if contact.stale {
                Text(L10n.contactListRepairChip)
                    .font(.runeCaption)
                    .foregroundColor(Color.runTextPrimary)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 4)
                    .background(Color.runSurface)
                    .cornerRadius(6)
                    .accessibilityIdentifier("contact_repair_chip_\(contact.id)")
            } else if unreadCount > 0 {
                // A big, hard-to-miss unread dot in the accent red — the same
                // "●" glyph at the same size as Android, so the two platforms
                // render an identical badge.
                Text(verbatim: "●")
                    .font(.system(size: 22))
                    .foregroundColor(.runError)
                    .accessibilityIdentifier("contact_unread_\(contact.id)")
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
        .contentShape(Rectangle())
    }

    private var avatarColor: Color {
        let idx = avatarColorIndex(contact.id, count: Self.avatarColors.count)
        return Self.avatarColors[idx]
    }
}

// MARK: - Group row

/// A pending group invitation row (closed with "Later"): dashed gold outline avatar,
/// primary title and a "Tap to answer" hint, so it reads as "not yet a group" yet
/// is noticed as tappable. Android sibling: GroupInviteRow in ContactListScreen.kt.
private struct GroupInviteListRow: View {
    let invite: GroupInviteItem

    var body: some View {
        PendingAnswerRowBody(title: L10n.contactListGroupInviteRow(bidiIsolate(invite.groupName)))
    }
}

/// A pending introduction row (closed with "Later"): same look as GroupInviteListRow.
/// Android sibling: ReferralOfferRow in ContactListScreen.kt.
private struct ReferralOfferListRow: View {
    let offer: RefOffer

    var body: some View {
        PendingAnswerRowBody(title: L10n.contactListReferralOfferRow(bidiIsolate(offer.peerAlias)))
    }
}

/// Shared body of the two pending-answer rows. The enclosing Button (with the
/// `group_invite_row_` / `referral_offer_row_` identifier) is the single a11y element.
/// Android sibling: PendingAnswerRow.
private struct PendingAnswerRowBody: View {
    let title: String

    var body: some View {
        HStack(spacing: 12) {
            ZStack {
                RoundedRectangle(cornerRadius: 12)
                    .strokeBorder(Color.runeGold, style: StrokeStyle(lineWidth: 1, dash: [4, 3]))
                    .frame(width: 44, height: 44)
                Text(verbatim: "?")
                    .font(.runeHeadline)
                    .foregroundColor(Color.runeGold)
            }
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.runeBody)
                    .foregroundColor(Color.runTextPrimary)
                    .lineLimit(1)
                    .truncationMode(.tail)
                Text(L10n.contactListPendingRowHint)
                    .font(.runeCaption)
                    .foregroundColor(Color.runTextSecondary)
                    .lineLimit(1)
                    .truncationMode(.tail)
            }
            Spacer()
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
        .contentShape(Rectangle())
    }
}

private struct GroupListRow: View {
    let group: ContactListView.GroupItem
    var unreadCount: Int = 0

    private static let avatarColors: [Color] = [
        Color(hex: 0x5C6BC0), Color(hex: 0x26A69A), Color(hex: 0xEF5350),
        Color(hex: 0xAB47BC), Color(hex: 0x42A5F5), Color(hex: 0xFF7043),
        Color(hex: 0x66BB6A), Color(hex: 0xEC407A), Color(hex: 0x8D6E63),
        Color(hex: 0x78909C),
    ]

    var body: some View {
        HStack(spacing: 12) {
            ZStack {
                // Square-ish avatar distinguishes groups from contact circles.
                RoundedRectangle(cornerRadius: 12)
                    .fill(avatarColor)
                    .frame(width: 44, height: 44)
                Text(group.name.prefix(1).uppercased())
                    .font(.runeHeadline)
                    .foregroundColor(.white)
            }
            VStack(alignment: .leading, spacing: 2) {
                Text(group.name)
                    .font(.runeBody)
                    .foregroundColor(Color.runTextPrimary)
                    .lineLimit(1)
                    .truncationMode(.tail)
                    .accessibilityIdentifier("group_name_\(group.id)")
                Text(group.isAdmin ? L10n.contactListGroupAdminLabel : L10n.contactListGroupLabel)
                    .font(.runeCaption2)
                    .foregroundColor(Color.runTextSecondary)
            }
            Spacer()
            if unreadCount > 0 {
                // Same accent-red "●" badge as ContactRow, so groups and 1:1s
                // render an identical unread indicator.
                Text(verbatim: "●")
                    .font(.system(size: 22))
                    .foregroundColor(.runError)
                    .accessibilityIdentifier("group_unread_\(group.id)")
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
        .contentShape(Rectangle())
    }

    private var avatarColor: Color {
        let idx = avatarColorIndex(group.id, count: Self.avatarColors.count)
        return Self.avatarColors[idx]
    }
}

// MARK: - Re-pair banner

private struct RepairBanner: View {
    let staleCount: Int
    let onTap: () -> Void

    var body: some View {
        Button(action: onTap) {
            Text(L10n.contactListRepairBanner(staleCount))
                .font(.runeFootnote)
                .foregroundColor(Color.runTextPrimary)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 14)
                .padding(.vertical, 12)
                .background(Color.runSurface)
                .cornerRadius(10)
                .padding(.horizontal, 16)
                .padding(.vertical, 8)
        }
        .accessibilityIdentifier("repair_banner")
    }
}

// MARK: - Edit Mnemonic Sheet

private struct EditMnemonicView: View {
    @Binding var mnemonic: String
    let onSave: () -> Void
    let onCancel: () -> Void

    var body: some View {
        NavigationStack {
            ZStack {
                Color.runBackground.ignoresSafeArea()

                VStack(spacing: 20) {
                    Text(L10n.contactListMemoryDialogTitle)
                        .font(.runeHeadline)
                        .foregroundColor(Color.runTextPrimary)

                    Text(L10n.contactListMemoryDialogSubtitle)
                        .font(.runeFootnote)
                        .foregroundColor(Color.runTextSecondary)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal)

                    TextField(L10n.contactListMemoryPlaceholderIos, text: $mnemonic)
                        .foregroundColor(Color.runTextPrimary)
                        .tint(Color.runAccent)
                        // Autocorrection +
                        // autocapitalization OFF suppress inline correction UI only —
                        // they do NOT stop the system keyboard's QuickType engine from
                        // learning typed words into its on-device lexicon (which lives
                        // outside the app sandbox and survives an app wipe). .password
                        // is the recognized secure contentType that actually excludes
                        // the field from learning (matches Android's
                        // KeyboardType.Password on this identical edit field).
                        .autocorrectionDisabled(true)
                        .textInputAutocapitalization(.never)
                        .textContentType(.password)
                        .padding()
                        .background(Color.runSurface)
                        .cornerRadius(8)
                        .padding(.horizontal)

                    Spacer()
                }
                .padding(.top, 40)
            }
            .navigationBarTitleDisplayMode(.inline)
            .runNavigationBarChrome()
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button(L10n.commonCancel) { onCancel() }
                        .foregroundColor(Color.runTextPrimary)
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button(L10n.commonSave) { onSave() }
                        .foregroundColor(Color.runAccent)
                        .fontWeight(.semibold)
                }
            }
        }
        .presentationDetents([.medium])
    }
}

// MARK: - About modal
//
// Swipeable carousel ("pager") over the shared AboutContent pages. All copy is
// rendered from the KMP shared module (`AboutContent.shared.pages`) so Android
// and iOS stay identical — nothing is duplicated here. Static content.

struct AboutView: View {
    let onClose: () -> Void

    // Kotlin `object` → Swift singleton; pages are bridged as [AboutPage].
    private let pages: [AboutPage] = AboutContent.shared.pages
    @State private var selection = 0

    var body: some View {
        ZStack(alignment: .topTrailing) {
            Color.clear.ignoresSafeArea()

            TabView(selection: $selection) {
                ForEach(Array(pages.enumerated()), id: \.offset) { idx, page in
                    AboutPageView(page: page, isActive: selection == idx)
                        .tag(idx)
                        .padding(.horizontal, 28)
                }
            }
            .tabViewStyle(.page(indexDisplayMode: .always))
            .indexViewStyle(.page(backgroundDisplayMode: .always))
            .accessibilityIdentifier("about_pager")

            Button(action: onClose) {
                Image(systemName: "xmark")
                    .font(.system(size: 17, weight: .semibold))
                    .foregroundColor(Color.runTextPrimary)
                    .padding(12)
            }
            .accessibilityIdentifier("about_close")
            .padding(.top, 8)
            .padding(.trailing, 8)
        }
        .accessibilityIdentifier("about_modal")
        .preferredColorScheme(.dark)
    }
}

// The classic "About" box: app name, the runic mark, the installed version, a
// one-line description, the bundled Tor version, and open-source
// acknowledgements. (The swipeable feature carousel is AboutView, surfaced as
// "How Rún works".) Static and vault-agnostic. Also the client source link and
// the bundled licence texts (LicencesView, loaded only when opened). Android
// sibling: AboutInfoModal.kt (+ LicencesScreen.kt). No signing-certificate line
// here: an App Store binary is re-signed by Apple, so there is nothing to match.
struct AboutInfoView: View {
    let onClose: () -> Void
    // A clearnet link behind the confirmation dialog: `host` fills the
    // message's placeholder, `url` is what opens in the external browser.
    struct ClearnetLink {
        let host: String
        let url: String
        static let maker = ClearnetLink(host: "vgab.eu", url: "https://vgab.eu")
        static let source = ClearnetLink(host: "github.com", url: "https://github.com/cptdad/run")
    }
    @State private var showClearnetConfirm = false
    // Not cleared on dismiss, so the message doesn't flip mid-dismiss animation.
    @State private var clearnetTarget = ClearnetLink.maker
    @State private var showLicences = false
    @Environment(\.openURL) private var openURL

    private var version: String {
        let v = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "?"
        let b = Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "?"
        return L10n.aboutInfoVersionLabel(v, b)
    }

    var body: some View {
        ZStack(alignment: .topTrailing) {
            Color.runBackground.ignoresSafeArea()

            ScrollView {
                VStack(spacing: 12) {
                    Spacer(minLength: 56)
                    Text(verbatim: "ᚱ")
                        .font(.system(size: 56, design: .serif))
                        .foregroundColor(Color.runTextPrimary)
                    Text(verbatim: "Rún")
                        .font(.system(.largeTitle, design: .serif))
                        .fontWeight(.bold)
                        .foregroundColor(Color.runTextPrimary)
                    Text(version)
                        .font(.runeSubheadline)
                        .foregroundColor(.secondary)
                        .accessibilityIdentifier("about_info_version")
                    Text(L10n.aboutInfoTagline)
                        .font(.runeSubheadline)
                        .foregroundColor(Color.runTextPrimary)
                        .multilineTextAlignment(.center)
                        .padding(.top, 4)
                    Text(L10n.aboutInfoTorVersion(AboutContent.shared.torVersion))
                        .font(.runeFootnote)
                        .foregroundColor(.secondary)
                        .accessibilityIdentifier("about_info_tor_version")

                    Text(L10n.aboutInfoOpenSourceHeading)
                        .font(.runeSubheadline).fontWeight(.semibold)
                        .foregroundColor(Color.runTextPrimary)
                        .padding(.top, 16)
                    ForEach(Array(AboutContent.shared.credits.enumerated()), id: \.offset) { _, c in
                        Text("\(c.name) — \(c.license)")
                            .font(.runeCaption)
                            .foregroundColor(.secondary)
                    }

                    // Client source — same clearnet gate as the maker link below.
                    Text(L10n.aboutInfoSourceHeading)
                        .font(.runeSubheadline).fontWeight(.semibold)
                        .foregroundColor(Color.runTextPrimary)
                        .padding(.top, 12)
                    Button {
                        clearnetTarget = .source
                        showClearnetConfirm = true
                    } label: {
                        Text(verbatim: "github.com/cptdad/run ↗")
                            .font(.system(.subheadline, design: .serif))
                            .foregroundColor(Color(red: 0.86, green: 0.71, blue: 0.46))
                    }
                    .accessibilityIdentifier("about_info_source")
                    Button {
                        showLicences = true
                    } label: {
                        Text(L10n.aboutInfoLicences)
                            .font(.system(.subheadline, design: .serif))
                            .foregroundColor(Color(red: 0.86, green: 0.71, blue: 0.46))
                    }
                    .accessibilityIdentifier("about_info_licences")

                    // Maker — opens the company site in the EXTERNAL browser over
                    // the clearnet (not Tor), which reveals the device IP to the
                    // site and any on-path observer. Gate it behind an explicit
                    // confirmation so a Tor-messenger user isn't one accidental
                    // tap away from a clearnet IP↔Rún correlation.
                    Text(verbatim: "Vikstrom Group AB")
                        .font(.runeSubheadline)
                        .foregroundColor(Color.runTextPrimary)
                        .padding(.top, 18)
                    Button {
                        clearnetTarget = .maker
                        showClearnetConfirm = true
                    } label: {
                        Text(verbatim: "vgab.eu ↗")
                            .font(.system(.subheadline, design: .serif))
                            .foregroundColor(Color(red: 0.86, green: 0.71, blue: 0.46))
                    }
                    .accessibilityIdentifier("about_info_website")

                    Spacer(minLength: 40)
                }
                .frame(maxWidth: .infinity)
                .padding(.horizontal, 28)
            }
            .runeDialog(isPresented: $showClearnetConfirm, title: L10n.aboutInfoClearnetTitle,
                        message: L10n.aboutInfoClearnetMessage(clearnetTarget.host),
                        actions: [
                            RuneDialogAction(L10n.commonOpen, a11yId: "clearnet_open_confirm") {
                                if let url = URL(string: clearnetTarget.url) { openURL(url) }
                            },
                            .secondary(L10n.commonCancel) { },
                        ])

            Button(action: onClose) {
                Image(systemName: "xmark")
                    .font(.system(size: 17, weight: .semibold))
                    .foregroundColor(Color.runTextPrimary)
                    .padding(12)
            }
            .accessibilityIdentifier("about_info_close")
            .padding(.top, 8)
            .padding(.trailing, 8)
        }
        .accessibilityIdentifier("about_info_modal")
        .preferredColorScheme(.dark)
        .fullScreenCover(isPresented: $showLicences) {
            LicencesView { showLicences = false }
                .coveredDarkSheet()
        }
    }
}

// "Licences and notices" — the full texts the app is published under. The four
// files are COMMITTED byte-for-byte copies of the repo-root files in the
// `Licences` folder reference (scripts/sync-licence-bundle.sh; pinned by
// LicenceBundleTest on the JVM side, which also pins this file order to
// Android's LicencesScreen.kt). Read off the main actor only when this view
// appears — never when the About box opens (~65 KB of text).
struct LicencesView: View {
    let onClose: () -> Void
    static let files = ["LICENSE-EXCEPTION", "LICENSE", "THIRD_PARTY_NOTICES.md", "OFL.txt"]
    @State private var texts: [(name: String, body: String)] = []

    // One file's text, or nil if missing/unreadable (the view then skips it).
    private static func load(_ name: String) -> String? {
        let ns = name as NSString
        let ext = ns.pathExtension.isEmpty ? nil : ns.pathExtension
        guard let url = Bundle.main.url(forResource: ns.deletingPathExtension, withExtension: ext,
                                        subdirectory: "Licences"),
              let data = try? Data(contentsOf: url) else { return nil }
        return String(decoding: data, as: UTF8.self)
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text(L10n.aboutInfoLicencesTitle)
                    .font(.system(.title3, design: .serif)).fontWeight(.bold)
                    .foregroundColor(Color.runTextPrimary)
                Spacer()
                Button(action: onClose) {
                    Image(systemName: "xmark")
                        .font(.system(size: 17, weight: .semibold))
                        .foregroundColor(Color.runTextPrimary)
                        .padding(12)
                }
                .accessibilityIdentifier("about_info_licences_close")
            }
            .padding(.leading, 20)
            .padding(.trailing, 8)
            .padding(.vertical, 4)
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    ForEach(Array(texts.enumerated()), id: \.offset) { i, t in
                        if i > 0 { Divider().padding(.vertical, 8) }
                        Text(verbatim: t.name)
                            .font(.system(size: 13, weight: .bold, design: .monospaced))
                            .foregroundColor(Color.runTextPrimary)
                        Text(verbatim: t.body)
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundColor(Color.runTextPrimary.opacity(0.85))
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 12)
            }
        }
        .background(Color.runBackground.ignoresSafeArea())
        .accessibilityIdentifier("about_info_licences_screen")
        .task {
            let loaded = await Task.detached(priority: .userInitiated) { () -> [(name: String, body: String)] in
                LicencesView.files.compactMap { name in LicencesView.load(name).map { (name: name, body: $0) } }
            }.value
            texts = loaded
        }
    }
}

// ---------------------------------------------------------------------------
// Opt-in push (docs/RELAY_SPEC.md). Tier 0 (default — Rún only checks
// for new messages while it's open / in a live background session) vs Tier 2
// (opt-in): a CONTENTLESS remote push wakes the app to check the relay over
// Tor — the push payload itself never carries message text, sender, or any
// plaintext. Turning it on does tell Apple this device runs Rún and roughly
// WHEN messages arrive (wake timing); the copy below discloses that before
// the OS permission prompt ever appears (setPushEnabled requests it).
//
// Rendered as a swipeable CAROUSEL over the shared commonMain
// NotificationEducationContent (`AboutContent`'s single-source pattern) so
// this mirrors Android's NotificationSettingsModal page-for-page and word-
// for-word: intro → one privacy trade-off per info page (with an expandable
// "Technical details" block) → the actual on/off switch.
// ---------------------------------------------------------------------------
struct PushSettingsView: View {
    let onClose: () -> Void

    // Kotlin `object` → Swift singleton; pages are bridged as [NotifEduPage].
    // Unified page model: page 0 is the intro (title-only, `deep == nil`),
    // followed by one page per privacy trade-off, rendered through the same
    // PushInfoPageView — mirrors Android's single-list page dispatch.
    private let pages: [NotifEduPage] = NotificationEducationContent.shared.pages
    @State private var selection = 0

    // 0..<pages.count = one page per NotifEduPage, last = the on/off switch.
    private var lastIndex: Int { pages.count }

    var body: some View {
        ZStack {
            Color.clear.ignoresSafeArea()

            VStack(spacing: 8) {
                TabView(selection: $selection) {
                    ForEach(Array(pages.enumerated()), id: \.offset) { idx, page in
                        PushInfoPageView(page: page)
                            .tag(idx)
                            .padding(.horizontal, 28)
                    }

                    PushSwitchPageView(onClose: onClose)
                        .tag(lastIndex)
                        .padding(.horizontal, 28)
                }
                .tabViewStyle(.page(indexDisplayMode: .always))
                .indexViewStyle(.page(backgroundDisplayMode: .always))

                // Back / Next navigation below the pager, mirroring Android's
                // NotificationSettingsModal (notif_carousel_back / notif_carousel_next).
                HStack {
                    if selection > 0 {
                        Button(action: { selection -= 1 }) {
                            Text(L10n.notifSettingsCarouselBack)
                                .font(.runeSubheadline)
                                .foregroundColor(.runTextSecondary)
                        }
                        .accessibilityIdentifier("push_settings_back")
                    } else {
                        Spacer().frame(width: 1)
                    }
                    Spacer()
                    if selection < lastIndex {
                        Button(action: { selection += 1 }) {
                            Text(L10n.notifSettingsCarouselNext)
                                .font(.runeSubheadline).fontWeight(.semibold)
                                .foregroundColor(.runTextPrimary)
                        }
                        .accessibilityIdentifier("push_settings_next")
                    } else {
                        Spacer().frame(width: 1)
                    }
                }
                .padding(.horizontal, 28)
                .padding(.bottom, 20)
            }
            .padding(.top, 28)
        }
        .preferredColorScheme(.dark)
    }

    #if DEBUG
    /// The recent push-relevant LogBuffer lines, flattened for an a11y read-out.
    /// Covers every discriminator: `Push` (auth denied / token dropped / registered
    /// N inbox(es) / APNs registration failed), `PushRegistration` (register → CODE
    /// / failed / refused), and IosAppController's register count line.
    static func recentPushLog() -> String {
        let relevant = LogBuffer.shared.getAll().filter { e in
            e.tag == "Push" || e.tag == "PushRegistration" ||
            e.message.lowercased().contains("push") || e.message.lowercased().contains("apns") ||
            (e.tag == "IosAppController" && e.message.contains("register"))
        }
        return relevant.suffix(24)
            .map { "\($0.level)/\($0.tag): \($0.message)" }
            .joined(separator: " ‖ ")
    }
    #endif
}

// Unified page: a prominent title (tagged vendor_push_disclosure on the
// vendor-delivery page) plus — only when the page has technical depth to
// show (`deep != nil`) — an expandable "Technical details" block. The intro
// (page 0) and the metadata page have `deep == nil`, so they render as
// title-only, mirroring Android's single InfoPageView.
private struct PushInfoPageView: View {
    let page: NotifEduPage
    @State private var expanded = false

    var body: some View {
        VStack(alignment: .center, spacing: 14) {
            Text(page.title)
                .font(.runeSubheadline).fontWeight(.bold)
                .foregroundColor(.runTextPrimary)
                .multilineTextAlignment(.center)
                .accessibilityIdentifier(
                    page.disclosureTag == "vendor_push_disclosure" ? "vendor_push_disclosure" : "")

            if let deep = page.deep {
                Button(action: { expanded.toggle() }) {
                    HStack(spacing: 4) {
                        Text(verbatim: expanded ? "▾" : "▸")
                        Text(L10n.notifSettingsTechnicalDetails).fontWeight(.semibold)
                    }
                    .font(.runeCaption)
                    .foregroundColor(.runTextPrimary)
                }
                .accessibilityIdentifier("push_info_expand")

                if expanded {
                    Text(deep)
                        .font(.runeCaption2)
                        .foregroundColor(.runTextSecondary)
                        .multilineTextAlignment(.center)
                        .accessibilityIdentifier("push_info_deep")
                }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .center)
        .padding(.horizontal, 8)
    }
}

// Last page — the actual on/off Switch, straight from the shared content
// object; keeps push_settings_toggle / push_settings_done / (DEBUG)
// push_debug_log so they stay readable right after the toggle flips.
private struct PushSwitchPageView: View {
    @EnvironmentObject private var appState: AppState
    let onClose: () -> Void
    #if DEBUG
    // DEBUG-only e2e diagnostic: mirror the recent push-relevant LogBuffer lines
    // into an a11y-readable element (push_debug_log) so the cross:multi3 push spec
    // can self-diagnose an on-device registration failure WITHOUT the hidden
    // 5-tap LogViewer gesture (which automation can't reach). Refreshed on a 1s
    // timer so it reflects the async token/registration lines that land seconds
    // after the toggle flip. TEMPORARY — remove with the LogViewer beta surface.
    @State private var pushDebugText: String = ""
    #endif

    var body: some View {
        VStack(alignment: .center, spacing: 18) {
            Text(NotificationEducationContent.shared.switchTitle)
                .font(.runeSubheadline).fontWeight(.bold)
                .foregroundColor(.runTextPrimary)
                .multilineTextAlignment(.center)

            Toggle("", isOn: Binding(
                get: { appState.pushEnabled },
                set: { appState.setPushEnabled($0) }
            ))
            .labelsHidden()
            .tint(Color(hex: 0xD4463A))
            .accessibilityIdentifier("push_settings_toggle")

            // Sound / banner style / Focus behaviour belong to iOS Settings,
            // not to us — the sibling of Android's notif_system_settings row.
            // AppState.postLocalNotification only picks `.default` sound and
            // leaves interruptionLevel alone, so whatever the user sets here
            // wins. Shown only while alerts are on, when tuning them matters.
            if appState.pushEnabled {
                VStack(spacing: 6) {
                    Button(action: {
                        if let url = URL(string: UIApplication.openSettingsURLString) {
                            UIApplication.shared.open(url)
                        }
                    }) {
                        Text(L10n.notifSettingsSoundAndAlerts)
                            .font(.runeSubheadline)
                            .foregroundColor(.runTextPrimary)
                    }
                    .accessibilityIdentifier("notif_system_settings")

                    Text(L10n.notifSettingsSoundHint)
                        .font(.runeFootnote)
                        .foregroundColor(.gray)
                        .multilineTextAlignment(.center)
                        .accessibilityIdentifier("notif_system_settings_hint")
                }
            }

            Button(action: onClose) {
                Text(L10n.commonDone)
                    .fontWeight(.semibold)
                    .frame(maxWidth: .infinity).padding()
                    .background(Color.runTextPrimary)
                    .foregroundColor(.runBackground)
                    .clipShape(RoundedRectangle(cornerRadius: 12))
            }
            .accessibilityIdentifier("push_settings_done")
            .padding(.top, 8)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .center)
        .padding(.horizontal, 8)
        #if DEBUG
        // Invisible (foregroundColor .clear) but kept in the a11y tree so the
        // cross:push spec can still read push_debug_log; a zero-layout bottom
        // overlay so it neither shows to the user nor shifts the centered content.
        .overlay(alignment: .bottom) {
            Text(pushDebugText)
                .font(.system(size: 8, design: .monospaced))
                .foregroundColor(.clear)
                .lineLimit(8)
                .accessibilityIdentifier("push_debug_log")
                .onAppear { pushDebugText = PushSettingsView.recentPushLog() }
                .onReceive(Timer.publish(every: 1, on: .main, in: .common).autoconnect()) { _ in
                    pushDebugText = PushSettingsView.recentPushLog()
                }
        }
        #endif
    }
}

// A single About page. TEXT pages show a glyph; the two runestone pages play
// an opacity-crossfade animation when the page becomes active (and re-play
// when swiped back to).
private struct AboutPageView: View {
    let page: AboutPage
    let isActive: Bool

    var body: some View {
        // Scrollable so a long page body doesn't clip, while still centering
        // short pages: the content is pinned to at least the page height
        // (minHeight) so the spacers expand to center it when it fits, and it
        // scrolls once it's taller than the page.
        GeometryReader { geo in
            ScrollView(.vertical, showsIndicators: false) {
                VStack(spacing: 24) {
                    Spacer(minLength: 40)

                    header

                    Text(page.title)
                        .font(.system(.title, design: .serif))
                        .fontWeight(.bold)
                        .foregroundColor(Color.runTextPrimary)
                        .multilineTextAlignment(.center)

                    Text(page.body)
                        .font(.runeBody)
                        .foregroundColor(Color.runTextPrimary)
                        .multilineTextAlignment(.center)
                        .fixedSize(horizontal: false, vertical: true)

                    Spacer(minLength: 60)
                }
                .frame(maxWidth: .infinity, minHeight: geo.size.height)
            }
        }
    }

    @ViewBuilder
    private var header: some View {
        if page.kind == AboutPageKind.runestoneTor {
            // Dark → red: crossfade runestone_dim into runestone_bright.
            runestoneStack(litCentre: false)
        } else if page.kind == AboutPageKind.runestoneRelay {
            // Red with the white centre ᚱ fading in on top of the bright stone.
            runestoneStack(litCentre: true)
        } else if page.kind == AboutPageKind.forcefield {
            // The full blue forcefield around the lit runestone — the visual for
            // the Forensic-safe page (a static image, sized like the runestone pages).
            Image("runestone_bright_and_lit_forcefield")
                .resizable()
                .scaledToFit()
                .frame(maxWidth: .infinity)
                .frame(height: 300)
        } else {
            Text(page.glyph)
                .font(.system(size: 72))
        }
    }

    // Reused layering from ContactListView/ConversationView: runestone_dim →
    // runestone_bright (and, for the relay page, runestone_bright_and_lit).
    //
    // The crossfade is driven declaratively off `isActive` (the Android analog of
    // animateFloatAsState(isCurrent)): TabView(.page) preloads the adjacent page,
    // so swiping onto a runestone page flips isActive false→true on a live view
    // and `.animation(value: isActive)` crossfades dim→bright. (An imperative
    // withAnimation from onAppear/onChange did NOT animate inside the pager.)
    private func runestoneStack(litCentre: Bool) -> some View {
        ZStack {
            Image("runestone_dim")
                .resizable()
                .scaledToFit()
                .opacity(isActive ? 0 : 1)

            Image("runestone_bright")
                .resizable()
                .scaledToFit()
                .opacity(isActive ? 1 : 0)

            if litCentre {
                Image("runestone_bright_and_lit")
                    .resizable()
                    .scaledToFit()
                    .opacity(isActive ? 1 : 0)
            }
        }
        // Fill the modal width (matching Android) — the 140pt cap made the
        // stone tiny on device.
        .frame(maxWidth: .infinity)
        .frame(height: 300)
        .animation(.easeInOut(duration: 1.6), value: isActive)
    }
}

// MARK: - Language picker

/// BCP-47 tags this build offers in-app. Mirrors Android's
/// `AppLocale.SUPPORTED` (androidApp/.../AppLocale.kt) — keep the two lists in
/// sync by hand; there is no shared commonMain source for it.
enum AppLanguages {
    static let supported = ["en", "sv", "de", "fr", "es", "nb", "da", "fi", "ar", "fa", "so", "ru", "mk"]
}

/// In-app per-app language override — parity with Android's
/// LanguagePickerModal (see AppLocale.kt there). Supersedes the old deep-link
/// to iOS Settings' per-app "Preferred Language" row, which only appears once
/// the device already carries 2+ preferred languages and was otherwise
/// undiscoverable. Writes the SAME "AppleLanguages" UserDefaults key the
/// DEBUG-only `--test-language=` e2e harness (RunApp.swift) already uses, so
/// a fresh launch honors it exactly the way that path always has.
///
/// iOS cannot hot-swap `NSLocalizedString` lookups mid-process the way
/// Android's `LocaleManager` + `Activity.recreate()` reloads resources in the
/// SAME process — a real relaunch is required. That makes this heavier than
/// Android's immediate-apply-and-dismiss (which never touches the vault), so
/// — unlike Android — this view confirms with the user first (a RuneDialog)
/// before locking the vault and calling `exit(0)`: the same clean teardown
/// ContentView already runs before its own dead-Tor self-recycle on
/// `.background`, just invoked directly here since this is an explicit,
/// user-confirmed action rather than an automatic recovery. iOS hands the
/// next tap a fresh process that reads the new override on launch.
struct LanguagePickerView: View {
    @EnvironmentObject private var appState: AppState
    let onClose: () -> Void

    /// "" stands in for "System default" (no override) throughout this view —
    /// it is never written to UserDefaults literally; see `applyPendingAndRestart`.
    private static let systemDefaultMarker = ""

    @State private var currentTag: String = LanguagePickerView.readCurrentTag()
    @State private var pendingTag: String? = nil
    @State private var showRestartConfirm = false

    private static func readCurrentTag() -> String {
        UserDefaults.standard.stringArray(forKey: "AppleLanguages")?.first ?? systemDefaultMarker
    }

    /// Native (autonym) display name, e.g. "Deutsch" for "de" — same
    /// derivation as Android's `Locale.forLanguageTag(tag).getDisplayName(that
    /// same locale)`: ask the TARGET locale to name itself in its own
    /// language, then uppercase only the first character (not a blanket
    /// `.capitalized`, which would also title-case a second word like the
    /// "bokmål" in "norsk bokmål").
    private static func nativeName(for tag: String) -> String {
        let locale = Locale(identifier: tag)
        // Swift's `Locale` (unlike `NSLocale`) has no `forLanguageIdentifier:`
        // label — `forIdentifier:` is the equivalent for a bare BCP-47 tag
        // like ours (no region/script/variant to disambiguate).
        let raw = locale.localizedString(forIdentifier: tag) ?? tag
        guard !raw.isEmpty else { return raw }
        return raw.prefix(1).uppercased() + raw.dropFirst()
    }

    private var pendingLabel: String {
        guard let tag = pendingTag else { return "" }
        return tag == LanguagePickerView.systemDefaultMarker
            ? L10n.languageOptionSystem : LanguagePickerView.nativeName(for: tag)
    }

    var body: some View {
        NavigationStack {
            ZStack {
                Color.runBackground.ignoresSafeArea()
                List {
                    languageRow(label: L10n.languageOptionSystem,
                                tag: LanguagePickerView.systemDefaultMarker,
                                a11yId: "language_row_system")
                    ForEach(AppLanguages.supported, id: \.self) { tag in
                        languageRow(label: LanguagePickerView.nativeName(for: tag),
                                    tag: tag, a11yId: "language_row_\(tag)")
                    }
                }
                .scrollContentBackground(.hidden)
                .listStyle(.insetGrouped)
            }
            .navigationTitle(L10n.settingsLanguage)
            .navigationBarTitleDisplayMode(.inline)
            .runNavigationBarChrome()
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button(L10n.commonDone) { onClose() }
                        .foregroundColor(Color.runAccent)
                        .accessibilityIdentifier("language_picker_done")
                }
            }
        }
        .accessibilityIdentifier("language_picker")
        // Restart confirm — see the type doc above for why iOS needs this and
        // Android doesn't. dismissable: false so a scrim tap can't slip past
        // the confirmation into an unconfirmed exit(0).
        .runeDialog(isPresented: $showRestartConfirm,
                    title: L10n.settingsLanguageRestartTitle,
                    message: L10n.settingsLanguageRestartMessage(pendingLabel),
                    a11yId: "language_restart_confirm",
                    dismissable: false,
                    actions: [
                        .secondary(L10n.commonCancel, a11yId: "language_restart_cancel") { pendingTag = nil },
                        RuneDialogAction(L10n.commonContinue, a11yId: "language_restart_confirm_button") {
                            applyPendingAndRestart()
                        },
                    ])
    }

    private func languageRow(label: String, tag: String, a11yId: String) -> some View {
        Button {
            select(tag)
        } label: {
            HStack {
                Text(label)
                    .foregroundColor(.runTextPrimary)
                Spacer()
                if currentTag == tag {
                    Image(systemName: "checkmark")
                        .foregroundColor(.runAccent)
                }
            }
        }
        .listRowBackground(Color.runSurface)
        .accessibilityIdentifier(a11yId)
    }

    /// Same-selection taps are a deliberate no-op (unlike Android, which just
    /// re-applies and re-recreates even for a no-change pick) — iOS's "apply"
    /// is a full process exit, so a tap that changes nothing shouldn't pay
    /// that cost or interrupt the user with a confirmation for no reason.
    private func select(_ tag: String) {
        guard tag != currentTag else { return }
        pendingTag = tag
        showRestartConfirm = true
    }

    private func applyPendingAndRestart() {
        guard let tag = pendingTag else { return }
        if tag == LanguagePickerView.systemDefaultMarker {
            UserDefaults.standard.removeObject(forKey: "AppleLanguages")
        } else {
            UserDefaults.standard.set([tag], forKey: "AppleLanguages")
        }
        pendingTag = nil
        // Same clean teardown ContentView runs ahead of its own exit(0)
        // self-recycle (close the vault, wipe keys, stop Tor) — invoked
        // directly rather than waiting for scenePhase == .background, since
        // this exit is an explicit user-confirmed action, not the automatic
        // dead-Tor recovery path.
        if appState.isUnlocked { appState.lock() }
        // lock() stops Tor only when the app is NOT `.active` (so a foreground idle
        // auto-lock does not kill a live daemon) — and this restart IS active, so
        // without this call tor_main would be killed by exit(0) below with no HALT,
        // no tor_cleanup() and therefore no or_state_save(): the language restart
        // silently threw away the session's entry-guard state. Bounded by
        // TorManager.stopConfirmTimeoutSec. Idempotent if lock() already stopped it.
        TorManager.shared.stop()
        exit(0)
    }
}

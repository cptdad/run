import SwiftUI
import UIKit
import shared

// ---------------------------------------------------------------------------
// ConversationView — message thread with a single contact.
//
// Matches Android implementation:
//   • Runestone dim/bright background crossfade driven by Tor state
//   • Sent messages right-aligned (#2A2A2A bubble)
//   • Received messages left-aligned (#1E1E1E bubble) with burn indicator
//   • No timestamps visible
//   • Polling on a JITTERED ~0.5–1.2 s loop while open (snappy, but per-cycle
//     randomised so it isn't a fixed-period timing beacon). KNOWN LIMITATION:
//     the inbound text inbox is drained only while
//     the conversation is open, so the relay can still infer the active contact
//     from which inbox is read. (The 1–5 s delay elsewhere is the send-retry
//     backoff, not the poll.)
//   • Messages are never persisted — they live in memory only and are gone
//     when the user leaves the conversation
//   • No autocomplete or clipboard hints on text input
//   • Send button pulses while Tor bootstrapping, disabled until ready
// ---------------------------------------------------------------------------

struct ConversationView: View {
    @EnvironmentObject private var appState: AppState
    @Environment(\.dismiss) private var dismiss
    let contactId: String
    /// NO-PARK (2026-10-06): a GROUP_ECHO bubble's "Open group" — navigates to the
    /// group the way the contact list does (ContentView replaces this screen).
    var onOpenGroup: (String) -> Void = { _ in }

    @State private var messages:  [ChatMessage] = []
    @State private var inputText  = ""
    @State private var isSending  = false
    @State private var pollTask:  Task<Void, Never>? = nil
    // Discreet, runestone-flavoured feedback shown during the first fetch on open,
    // then faded out: "Consulting the runes…" → "The runes whisper" / "are silent".
    @State private var runeWhisper: String? = nil
    @State private var sendTasks: [Task<Void, Never>] = []
    @State private var sendButtonOpacity: Double = 1.0
    // Instant-QR pairing: until the peer's inbox announce lands, we can
    // receive but not send. Re-checked after every poll (the announce is
    // applied by pollMessages), so the send button unlocks on its own.
    @State private var hasOutbound: Bool = true
    // Mirrors appState.isRelayReachable, but snaps off instantly when the
    // relay becomes unreachable so the lit runestone is NEVER visible while
    // the relay is down. Fade-in is still animated.
    @State private var litVisible: Bool = false
    // One-time burn-on-read onboarding (first conversation ever opened per
    // vault; durable vault-meta latch): the concept alert.
    @State private var showBurnNotice = false
    // Report / block actions presented as a SHEET, not a `Menu` (see
    // conversationActionsSheet for why). The chosen action is stamped in
    // `pendingConversationAction` and run in the sheet's onDismiss.
    @State private var showConversationActions = false
    @State private var pendingConversationAction: ConversationAction? = nil
    // "Report" in the ellipsis sheet now confirms
    // before handing off to AbuseReport.compose — see the disclosure dialog
    // in the body's modifier chain (conversation_report stays the same
    // a11y id on the sheet row; only its downstream action changes).
    @State private var showReportConfirm = false
    // CONVERSATION-SCOPED "I took a screenshot" sender. Distinct from
    // ScreenshotProtection's app-wide banner (kept, unchanged) — that one has
    // no notion of which conversation is open, so it never sends; this one
    // exists only to send, and is registered/removed symmetrically with
    // onAppear/onDisappear so it is armed only while THIS conversation is the
    // foreground screen.
    @State private var screenshotObserver: NSObjectProtocol? = nil

    struct ChatMessage: Identifiable {
        let id:        String
        let text:      String
        let isSent:    Bool    // true = outbound (right), false = inbound (left) — layout auto-mirrors under RTL (leading/trailing are reading-relative)
        let delivered: Bool    // true = relay accepted
        // A permanently-failed send (all retries exhausted) must
        // NOT look identical to a still-in-flight one — both were `delivered:false`,
        // rendering the same "·". `failed` splits the two so the bubble can be honest.
        let failed:    Bool    // true = gave up after retries (distinct from pending)
        let timestamp: Int64   // millis since epoch, 0 = no timestamp
        // "X may have taken a screenshot" notice — centered/muted, no bubble,
        // never counted as a real message. PERSISTED for 24 h now (docs/
        // screenshot-notice-persistence-design.md) — loaded on open from
        // AppState.loadScreenshotNotices and appended live from
        // AppState.drainScreenshotNotices.
        var isNotice:  Bool = false
        // Local wall-clock deadline (ScreenshotNotice.expiresAt) past which
        // this row is dropped on the next poll tick without a vault read.
        // Non-notice rows never expire.
        var expiresAt: Int64 = Int64.max
        // NO-PARK (2026-10-06): non-nil = a GROUP_ECHO row — a text of this group
        // that this screen's poll fetched. Shown marked, never a 1:1 message.
        var echoGroupId: String? = nil
        var echoGroupName: String = ""
    }

    // MARK: - Body

    var body: some View {
        ZStack {
            VStack(spacing: 0) {
                // Forward-secrecy-stalled notice — a SIGNAL,
                // never a send gate (MessageManager.forwardSecrecyStalled's KDoc).
                // Non-modal, at the top of the message list; same muted-row visual
                // family as conversationPendingBanner below, not a new banner style.
                // 1:1 conversations only — this view is never used for groups.
                //
                // P1-1 step B: ratchetRefused takes PRECEDENCE when both would show
                // — it is the strictly worse (send-blocking) escalation of the
                // advisory above, so showing both would be redundant.
                if appState.ratchetRefused[contactId] == true {
                    ratchetRefusedNotice
                } else if appState.forwardSecrecyStalled[contactId] == true {
                    forwardSecrecyStalledNotice
                }
                messageList
                Divider().background(Color.runDivider)
                if !hasOutbound {
                    Text(L10n.conversationPendingBanner)
                        .font(.runeCaption)
                        .foregroundColor(Color.runTextSecondary)
                        .multilineTextAlignment(.center)
                        .frame(maxWidth: .infinity)
                        .padding(.horizontal, 16)
                        .padding(.vertical, 6)
                        .background(Color.runSurface)
                        .accessibilityIdentifier("conversation_pending_banner")
                }
                inputBar
            }

            // Discreet, runestone-flavoured fetch feedback (fades on its own).
            if let whisper = runeWhisper {
                // Lower third — sits BELOW the rune (was pinned to the top, above
                // it). Two spacers above to one below ⇒ ~2/3 down the screen,
                // clear of both the rune and the input bar.
                VStack {
                    Spacer()
                    Spacer()
                    Text(ConversationRunes.shared.label(state: whisper))
                        .font(.rune(15, relativeTo: .subheadline))
                        .italic()
                        .tracking(3.5)
                        .foregroundColor(Color(red: 0.86, green: 0.71, blue: 0.46).opacity(0.72))
                        .shadow(color: Color(red: 0.75, green: 0.22, blue: 0.15).opacity(0.3), radius: 10)
                        .transition(.opacity)
                        .accessibilityIdentifier("rune_whisper")
                        .id(whisper)
                    Spacer()
                }
                .allowsHitTesting(false)
            }
        }
        // Runestone as a BACKGROUND (full-bleed, ignoresSafeArea) rather than a
        // ZStack sibling: its fixed screen-sized frame (the zoom-proofing) would
        // otherwise force the ZStack full-screen and defeat keyboard avoidance,
        // leaving the input bar behind the on-screen keyboard on a physical
        // device (the cross:multi send failure). As a background it doesn't drive
        // the content's layout, so the input bar rides above the keyboard.
        .background(runestoneBackground)
        // Note: do NOT put an accessibilityIdentifier on this ZStack — it
        // collapses the subtree and hides message_input / send_button /
        // message bubbles from XCUITest. Detect the screen via send_button.
        .navigationBarTitleDisplayMode(.inline)
        .navigationBarBackButtonHidden(true)
        .runNavigationBarChrome()
        .toolbar { conversationToolbar }
        .onAppear  {
            LogBuffer.shared.append(level: "D", tag: "Chat", message: "conversation opened torConnected=\(appState.isTorConnected) relayReachable=\(appState.isRelayReachable)")
            refreshHasOutbound()
            // Evaluate forwardSecrecyStalled on open. The
            // other evaluation point is after every completed send (see
            // sendMessage below); there is no polling loop for this flag.
            appState.refreshForwardSecrecyStalled(contactId: contactId)
            // P1-1 step B: evaluate ratchetRefused on open too — also re-read on
            // every poll tick inside startPolling (unlike forwardSecrecyStalled,
            // this signal is cleared by an INBOUND ratchet blob, not only by this
            // device's own send landing).
            appState.refreshRatchetRefused(contactId: contactId)
            startPolling()
            // First-conversation-ever burn-on-read notice (shared helper below,
            // reused by GroupConversationView — same vault-meta latch).
            if let vault = appState.vault { showBurnNotice = consumeBurnNoticeOnce(vault) }
            // Screenshot-taken notice: best-effort, fire-and-forget, off-main —
            // a failed send is silent (MessageManager.sendScreenshotNotice never
            // throws; its Boolean is for logs only). Armed only while this
            // conversation is on screen — removed in onDisappear below.
            screenshotObserver = NotificationCenter.default.addObserver(
                forName: UIApplication.userDidTakeScreenshotNotification, object: nil, queue: .main
            ) { _ in
                let mgr = appState.controller.messageManager
                DispatchQueue.global(qos: .utility).async {
                    // Root-caused prod bug (docs/screenshot-notice-persistence-design.md
                    // §0): this send's result used to be discarded unlogged, so a
                    // silent failure here (e.g. no transport yet) left nothing in the
                    // logs to distinguish "peer never got the notice" from "peer got
                    // it but never opened the conversation before the RAM buffer was
                    // scrubbed". sendScreenshotNotice() itself never throws.
                    if let sent = mgr?.sendScreenshotNotice(contactId: contactId) {
                        LogBuffer.shared.append(level: sent ? "D" : "W", tag: "Chat",
                            message: "screenshot notice send \(sent ? "ok" : "FAILED")")
                    } else {
                        LogBuffer.shared.append(level: "W", tag: "Chat",
                            message: "screenshot notice not sent — no messageManager (no transport yet)")
                    }
                }
            }
        }
        .burnOnReadNotice(isPresented: $showBurnNotice)
        .sheet(isPresented: $showConversationActions, onDismiss: runPendingConversationAction) {
            conversationActionsSheet
        }
        // Reporter disclosure: same consequences as
        // ContactListView's report dialogs — confirm before AbuseReport.compose
        // opens the mailto draft.
        .runeDialog(isPresented: $showReportConfirm, title: L10n.conversationReportConfirmTitle,
                    message: L10n.conversationReportConfirmMessage,
                    actions: [
                        RuneDialogAction(L10n.conversationReportConfirmButton, a11yId: "conversation_report_confirm_button") {
                            AbuseReport.compose(contactAlias: contactAlias(), contactId: contactId)
                        },
                        .secondary(L10n.commonCancel) { },
                    ])
        .onDisappear {
            if let obs = screenshotObserver {
                NotificationCenter.default.removeObserver(obs)
                screenshotObserver = nil
            }
            pollTask?.cancel()
            // Do NOT cancel in-flight SEND tasks: a send must survive leaving the
            // conversation. Cancelling the task cancelled the awaited POST mid-flight,
            // so under a slow/contended circuit the message was silently lost (never
            // reached the relay → the peer never received it). They finish on their own;
            // just drop our references (a completed task is retained by the runtime,
            // not this disappearing view).
            sendTasks.removeAll()
            let count = messages.count
            messages.removeAll()
            LogBuffer.shared.append(level: "D", tag: "Chat", message: "conversation closed, \(count) message(s) erased from memory")
        }
    }

    // MARK: - Toolbar

    /// Back chevron (leaves immediately), title + provenance, report/block menu.
    @ToolbarContentBuilder
    private var conversationToolbar: some ToolbarContent {
        // Custom back button (body hides the system back). Leaving is
        // IMMEDIATE (retrieve-ack): the chevron and the edge-swipe-back both pop
        // at once; a drain not yet shown is abandoned on disappear.
        ToolbarItem(placement: .navigationBarLeading) {
            Button { dismiss() } label: {
                // chevron.backward (not chevron.left): an auto-mirroring semantic
                // SF Symbol that points toward reading-start under RTL (ar/fa)
                // instead of a fixed left-pointing glyph.
                Image(systemName: "chevron.backward")
                    .foregroundColor(Color.runTextPrimary)
                    .transaction { $0.animation = nil }  // never animate this control
            }
            .accessibilityIdentifier("conversation_back")
        }
        ToolbarItem(placement: .principal) {
            VStack(spacing: 2) {
                Text(contactAlias())
                    .font(.runeHeadline)
                    .foregroundColor(Color.runTextPrimary)
                    .lineLimit(1)
                    .truncationMode(.tail)
                    .accessibilityIdentifier("conversation_title")
                if vouchedByContactId() != nil {
                    // Same provenance signal + style
                    // family as ContactListView's "Introduced by X" subtitle —
                    // informational only, referred contacts are usable
                    // immediately (transitive trust).
                    Text(introducerAlias().map { L10n.contactListIntroducedBy($0) } ?? L10n.contactListIntroduced)
                        .font(.runeCaption2)
                        .foregroundColor(Color.runTextSecondary)
                        .lineLimit(1)
                        .truncationMode(.tail)
                        .accessibilityIdentifier("conversation_provenance")
                }
            }
        }
        // Guideline 1.2 — report / block the contact from the conversation.
        ToolbarItem(placement: .navigationBarTrailing) {
            Button {
                showConversationActions = true
            } label: {
                Image(systemName: "ellipsis.circle")
                    .foregroundColor(Color.runTextPrimary)
            }
            .accessibilityIdentifier("conversation_menu")
        }
    }

    // MARK: - Runestone background

    private var runestoneBackground: some View {
        // FIXED screen-sized frame (see ContactListView for the full rationale):
        // the "zoom" was geometry, not an asset-size mismatch — .scaledToFill() +
        // .frame(maxWidth/maxHeight: .infinity) re-resolved its box on every
        // message-list layout pass and re-fit the image. A constant CGSize can't
        // re-measure, so the lit glow below is pure opacity — no zoom.
        let screen = UIScreen.main.bounds.size
        let artLevel = appState.controller.displayProtectionLevel()
        return ZStack {
            Color.runBackground

            // Base dim stone — always present, never fades out.
            Image(runestoneAsset("runestone_dim", level: artLevel))
                .resizable()
                .scaledToFill()
                .frame(width: screen.width, height: screen.height)
                .clipped()

            // Lit stone — the chat is only reachable once Tor is up, so this is
            // normally shown; fade it on litVisible. Opacity-only, fixed frame.
            Image(runestoneAsset("runestone_bright_and_lit", level: artLevel))
                .resizable()
                .scaledToFill()
                .frame(width: screen.width, height: screen.height)
                .clipped()
                .opacity(litVisible ? 1 : 0)
                .animation(.easeInOut(duration: 0.6), value: litVisible)

            // Test-only marker — reflects litVisible (see ContactListView).
            runestoneLitMarker(active: litVisible)

            // STATIC dark overlay — fixed.
            Color.black.opacity(0.45)
        }
        .frame(width: screen.width, height: screen.height)
        .ignoresSafeArea()
        // No container animation here: the only animated layer is the lit stone's
        // explicit 0.6 s opacity fade on litVisible above (fixed frame, so no zoom).
        // A transport-back re-drive landed a parked send of THIS conversation
        // (AppState.redrivenMessageIds, delivered on main): flip the bubble to
        // delivered. Idempotent and NOT consuming — the send loop that owns the
        // id still reads the set (duplicate guard) and removes it when it ends.
        // Android sibling: the re-drive callback's deliveredIds[id] = true.
        .onReceive(appState.$redrivenMessageIds) { ids in
            guard !ids.isEmpty else { return }
            for idx in messages.indices where messages[idx].isSent && !messages[idx].delivered && ids.contains(messages[idx].id) {
                let m = messages[idx]
                messages[idx] = ChatMessage(id: m.id, text: m.text, isSent: true, delivered: true, failed: false, timestamp: m.timestamp)
            }
        }
        .onAppear { litVisible = appState.isRelayReachable }
        // See ContactListView for why this is .onReceive and not .onChange.
        .onReceive(appState.$isRelayReachable) { reachable in
            if reachable {
                litVisible = true
            } else {
                // Instant — bypass the easeInOut so the lit asset is never
                // shown while the relay is unreachable.
                var t = Transaction(); t.disablesAnimations = true
                withTransaction(t) { litVisible = false }
            }
        }
    }

    // MARK: - Forward-secrecy-stalled notice

    /// Same muted-row visual family as conversationPendingBanner (full-width
    /// runSurface background, centered small text) rather than a new banner
    /// style: a compact, non-modal advisory that a healthy conversation clears
    /// on its own once the peer's first ratchet reply lands (MessageManager
    /// clears the underlying counter on that first landed ratchet send — no
    /// reset here).
    private var forwardSecrecyStalledNotice: some View {
        VStack(spacing: 2) {
            Text(L10n.conversationFsStalledTitle)
                .font(.runeCaption.weight(.semibold))
                .foregroundColor(Color.runTextPrimary)
                .multilineTextAlignment(.center)
            Text(L10n.conversationFsStalledBody)
                .font(.runeCaption2)
                .foregroundColor(Color.runTextSecondary)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity)
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
        .background(Color.runSurface)
        .accessibilityIdentifier("fs_stalled_notice")
    }

    // MARK: - Ratchet-refused notice

    /// Same muted-row visual family as forwardSecrecyStalledNotice above,
    /// title-less: this state is the send-blocking escalation of the advisory
    /// above, so it takes precedence rather than stacking with it. Clears on its
    /// own once an inbound ratchet blob decrypts (MessageManager clears the
    /// underlying latch) — no reset here.
    private var ratchetRefusedNotice: some View {
        Text(L10n.conversationRatchetRefusedBody)
            .font(.runeCaption2)
            .foregroundColor(Color.runTextSecondary)
            .multilineTextAlignment(.center)
            .frame(maxWidth: .infinity)
            .padding(.horizontal, 16)
            .padding(.vertical, 8)
            .background(Color.runSurface)
            .accessibilityIdentifier("ratchet_refused_notice")
    }

    // MARK: - Message list

    private var messageList: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(spacing: 8) {
                    ForEach(messages) { msg in
                        if let echoGroupId = msg.echoGroupId {
                            GroupEchoBubbleView(
                                groupName: msg.echoGroupName,
                                senderAlias: nil,
                                text: msg.text,
                                timestamp: msg.timestamp,
                                onOpenGroup: { onOpenGroup(echoGroupId) },
                                bubbleId: "conversation_group_echo_bubble",
                                labelId: "conversation_group_echo_label",
                                openId: "conversation_group_echo_open"
                            )
                            .id(msg.id)
                        } else {
                            MessageBubble(message: msg)
                                .id(msg.id)
                        }
                    }
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
            }
            .accessibilityIdentifier("message_list")
            .onChange(of: messages.count) { _ in
                guard let last = messages.last else { return }
                withAnimation { proxy.scrollTo(last.id, anchor: .bottom) }
            }
        }
    }

    // MARK: - Input bar

    private var inputBar: some View {
        // iOS keeps the no-learning composer at EVERY tier (2026-09-21, reverting the
        // 2026-09-20 tier split for iOS only): the
        // password content type is the ONLY modifier that keeps this field out
        // of QuickType's learned vocabulary, and unlike Gboard the iOS keyboard
        // keeps its emoji key in that mode, so there is no emoji cost to pay
        // here. The tier split stays on Android (ComposerKeyboardPolicy /
        // RunViewModel.strictComposerKeyboard), where password mode removes the
        // emoji key — the Protection taglines describe the Android trade only.
        return HStack(spacing: 8) {
            TextField(L10n.commonMessagePlaceholder, text: $inputText)
                .noLearningComposerStyle()
                .onSubmit { sendMessage() }
                .accessibilityIdentifier("message_input")

            Button { sendMessage() } label: {
                Image(systemName: "arrow.up.circle.fill")
                    .font(.system(size: 32))
                    .foregroundColor(sendButtonColor)
                    .opacity(sendButtonPulseOpacity)
            }
            .disabled(!canSend)
            .accessibilityIdentifier("send_button")
        }
        .transaction { $0.animation = nil }  // never animate the input bar
        .padding(.horizontal, 12)
        .padding(.vertical, 10)
        .background(Color.runBackground)
    }

    /// The composer holds something other than whitespace.
    private var hasDraft: Bool { !inputText.trimmingCharacters(in: .whitespaces).isEmpty }

    /// Tor (when required) is up AND the relay answered — a send can go out now.
    private var transportReady: Bool { appState.isTorConnected && appState.isRelayReachable }

    private var canSend: Bool {
        hasDraft && !isSending && transportReady && hasOutbound
    }

    private func refreshHasOutbound() {
        guard let vault = appState.vault else { return }
        hasOutbound = vault.getInboxIdForContact(contactId: contactId, direction: "outbound") != nil
    }

    private var sendButtonColor: Color {
        if !hasDraft {
            return Color(hex: 0x333333)
        }
        return transportReady ? Color.runTextPrimary : Color.runTextPrimary.opacity(0.4)
    }

    private var sendButtonPulseOpacity: Double {
        if !transportReady && hasDraft {
            // Pulse effect during Tor bootstrap or relay unreachable
            return 0.4
        }
        return 1.0
    }

    // MARK: - Logic

    private func contactAlias() -> String {
        guard let vault = appState.vault else { return L10n.conversationContactFallback }
        // getContact() carries a raw sharedSecret;
        // project the alias then wipe before it goes out of scope.
        let record = vault.getContact(contactId: contactId)
        let alias = record?.alias ?? L10n.conversationContactFallback
        record?.sharedSecret.secureWipe()
        return alias
    }

    /// Non-nil only for a contact added via a
    /// referral — mirrors ContactListView's `contact.vouchedByContactId`.
    private func vouchedByContactId() -> String? {
        guard let vault = appState.vault else { return nil }
        // Same project-then-wipe shape as contactAlias() above.
        let record = vault.getContact(contactId: contactId)
        let vouchedBy = record?.vouchedByContactId
        record?.sharedSecret.secureWipe()
        return vouchedBy
    }

    /// The introducer's CURRENT alias, resolved fresh (not cached from the
    /// referral itself) so a renamed introducer's alias stays current —
    /// mirrors ContactListView's `loadContacts()` introducerAlias lookup.
    private func introducerAlias() -> String? {
        guard let vault = appState.vault, let vid = vouchedByContactId() else { return nil }
        // Same project-then-wipe shape as contactAlias() above.
        let record = vault.getContact(contactId: vid)
        let alias = record?.alias
        record?.sharedSecret.secureWipe()
        return alias
    }

    /// Guideline 1.2: block this contact and leave the conversation. The
    /// in-memory thread is erased immediately, BlockStore filters them out of
    /// the list, and we pop back so they vanish from the feed instantly.
    private func blockFromConversation() {
        BlockStore.block(contactId)
        pollTask?.cancel()
        for t in sendTasks { t.cancel() }
        sendTasks.removeAll()
        messages.removeAll()
        NotificationCenter.default.post(name: .contactsChanged, object: nil)
        dismiss()
    }

    // MARK: - Report / block action sheet (iOS-26 a11y-safe replacement for a Menu)

    private enum ConversationAction { case report, block }

    /// Stamp the chosen action and dismiss the sheet; [runPendingConversationAction]
    /// runs it once the sheet is fully gone — critical for `.block`, whose
    /// `dismiss()` pops the whole conversation and would otherwise race a still-
    /// presented sheet.
    private func pickConversationAction(_ action: ConversationAction) {
        pendingConversationAction = action
        showConversationActions = false
    }

    private func runPendingConversationAction() {
        guard let action = pendingConversationAction else { return }
        pendingConversationAction = nil
        switch action {
        // Don't hand off to AbuseReport.compose here —
        // confirm first (showReportConfirm dialog below in the body). The
        // mailto draft it opens lives outside Rún's sandbox, unencrypted, and
        // survives a Rún wipe.
        case .report: showReportConfirm = true
        case .block:  blockFromConversation()
        }
    }

    /// Report / block presented as a SHEET rather than a SwiftUI `Menu`: Menu
    /// items intermittently fail to surface in the a11y tree on physical iPhones
    /// @ iOS 26 (the same hazard that forced the settings cogwheel Menu → sheet,
    /// and that stalled the cross:multi block step). Same a11y ids as before
    /// (`conversation_report` / `conversation_block`) so nothing downstream changes.
    private var conversationActionsSheet: some View {
        NavigationStack {
            ZStack {
                Color.runBackground.ignoresSafeArea()
                List {
                    Button { pickConversationAction(.report) } label: {
                        Label(L10n.conversationReportAction, systemImage: "exclamationmark.bubble")
                            .foregroundColor(Color.runTextPrimary)
                    }
                    .listRowBackground(Color.runSurface)
                    .accessibilityIdentifier("conversation_report")

                    Button(role: .destructive) { pickConversationAction(.block) } label: {
                        Label(L10n.conversationBlockAction, systemImage: "hand.raised")
                            .foregroundColor(.red)
                    }
                    .listRowBackground(Color.runSurface)
                    .accessibilityIdentifier("conversation_block")
                }
                .scrollContentBackground(.hidden)
                .listStyle(.insetGrouped)
            }
            .navigationTitle(contactAlias())
            .navigationBarTitleDisplayMode(.inline)
            .runNavigationBarChrome()
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button(L10n.commonDone) { showConversationActions = false }
                        .foregroundColor(Color.runAccent)
                        .accessibilityIdentifier("conversation_actions_done")
                }
            }
        }
        .presentationDetents([.medium])
    }

    private func sendMessage() {
        let text = inputText.trimmingCharacters(in: .whitespaces)
        guard !text.isEmpty, appState.isTorConnected else { return }
        inputText = ""
        isSending = true

        // Sent messages are never persisted to the DB — they live in this
        // in-memory list only and disappear when the user leaves the view.
        let msgId = UUID().uuidString
        messages.append(ChatMessage(id: msgId, text: text, isSent: true, delivered: false, failed: false, timestamp: Int64(Date().timeIntervalSince1970 * 1000)))
        LogBuffer.shared.append(level: "D", tag: "Chat", message: "displayed sent message (pending relay)")

        // The session this send belongs to, captured at tap time. The send Task is
        // NOT cancelled on disappear (see .onDisappear: a send must survive leaving
        // the conversation), so it can outlive a lock or a wipe. What stops it there
        // is this epoch plus isUnlocked, checked before every attempt and before the
        // epilogue's contactId-keyed writes: a send that straddles a lock is never
        // re-parked or re-planted after the lock's scrub (Android: sessionStillCurrent).
        let sendEpoch = TransportFailedSends.companion.shared.sessionEpoch
        let task = Task { @MainActor in
            // The shared 1:1 delivery loop (AppState.runDirectSendLoop): the P1-1
            // ratchet-refusal gate first (zero HTTP), then up to 3 jittered attempts.
            // The bubble id is the re-drive token: a transport-class failure parks
            // this text for the transport-back re-drive, and the bubble flips through
            // appState.redrivenMessageIds (onReceive below) if the re-drive lands it.
            let result = await appState.runDirectSendLoop(contactId: contactId, text: text, redriveToken: msgId,
                                                          sessionEpoch: sendEpoch, logTag: "Chat", what: "send")
            if result == .cancelled { return }
            if result == .sessionEnded { isSending = false; return }
            let success = result == .delivered
            if Task.isCancelled { return }
            // The session ended while the loop ran (lock / wipe): write nothing back —
            // no flag refresh under this contactId, no bubble or re-drive-set update.
            guard appState.isSendSessionCurrent(sendEpoch) else { isSending = false; return }
            if success {
                LogBuffer.shared.append(level: "D", tag: "Chat", message: "sent message delivered")
            } else {
                LogBuffer.shared.append(level: "E", tag: "Chat",
                    message: "message failed after \(AppState.directSendMaxAttempts) attempts")
            }
            // Re-check the forward-secrecy-stalled signal once the whole
            // retry sequence has concluded — success or exhausted — never per
            // attempt. Already on the MainActor here (this Task's context).
            appState.refreshForwardSecrecyStalled(contactId: contactId)
            // P1-1 step B: re-check the refusal signal too — cleared by an inbound
            // ratchet blob, independent of anything this send did.
            appState.refreshRatchetRefused(contactId: contactId)
            // Update delivery status in memory. Never DOWNGRADE: a transport-back
            // re-drive may have flipped this bubble to delivered (onReceive above)
            // while the last attempt was still in flight.
            if let idx = messages.firstIndex(where: { $0.id == msgId }) {
                let landed = success || messages[idx].delivered || appState.redrivenMessageIds.contains(msgId)
                messages[idx] = ChatMessage(
                    id: msgId,
                    text: text,
                    isSent: true,
                    delivered: landed,
                    failed: !landed,   // L6: retries exhausted → mark failed, not pending
                    timestamp: messages[idx].timestamp
                )
            }
            // This loop owned the id's duplicate guard; a re-drive landing AFTER this
            // point re-inserts it for the onReceive flip (lock() clears the set).
            appState.redrivenMessageIds.remove(msgId)
            isSending = false
        }
        sendTasks.append(task)
    }

    private func startPolling() {
        pollTask?.cancel()   // Cancel any prior loop before reassigning
        pollTask = Task { @MainActor in
            var verdictShown = false
            // Announce the fetch the instant the conversation opens (drifts in) —
            // but only when the relay is actually reachable; with no relay there
            // are no runes to consult.
            let openedAt = Date()
            if appState.isRelayReachable {
                withAnimation(.easeIn(duration: 1.3)) { runeWhisper = ConversationRunes.shared.CONSULTING }
            }
            // Load-on-open: every UNEXPIRED persisted notice for this
            // conversation, oldest first — the persistence fix for the
            // production bug where a notice drained by the background sweep
            // while this screen was closed used to be lost forever (docs/
            // screenshot-notice-persistence-design.md §0). Runs ONCE, before
            // the loop below; the loop only ever APPENDS newly arrived
            // notices from here on. Dedupe id keys on receivedAt (the
            // store's stable ordering key), matching the per-tick drain.
            let persistedNotices = await appState.loadScreenshotNotices(conversationId: contactId)
            for n in persistedNotices {
                let stableId = "ss-\(n.senderContactId)-\(n.receivedAt)"
                if messages.contains(where: { $0.id == stableId }) { continue }
                messages.append(ChatMessage(
                    id: stableId,
                    text: L10n.commonScreenshotNotice(n.senderAlias) + " · " + formatNoticeTime(n.timestamp),
                    isSent: false,
                    delivered: true,
                    failed: false,
                    timestamp: n.timestamp,
                    isNotice: true,
                    expiresAt: n.expiresAt
                ))
            }
            while !Task.isCancelled {
                // NO per-iteration checkRelayReachability() here (Android parity):
                // AppState.startRelayCheck's 8–12 s health loop owns reachability —
                // and everything that rides along with it (the update nudge, the
                // review prompt, the miss-streak/NEWNYM ladder, relayConnectPhase,
                // relayHandshakeComplete). This screen only READS
                // `appState.isRelayReachable` (whisper, runestone, send gate) and
                // that loop keeps it current. Probing from here put a full onion
                // round-trip — up to the probe's own multi-attempt budget — in
                // front of every ~1 s poll, and so in front of every back tap.
                // RETRIEVE-ACK: poll UNCOMMITTED (decrypt only), append to the list, THEN
                // commit (persist ratchet / anti-replay state + fire-and-forget ack).
                // Leaving is immediate: this task is cancelled on disappear, and a drain
                // that was not yet shown is abandoned (dropping it is also safe — the
                // relay re-delivers after its lease). awaitDrain returns nil only when
                // this task is cancelled; a drain that lands after that is abandoned by
                // the closure itself. Parked items come first in `messages` and leave
                // the buffer only on commit.
                let drained = await awaitDrain { () -> PendingDrain<DirectItem>? in
                    let d = await appState.pollDirectPending(contactId: contactId)
                    if Task.isCancelled, let d { appState.abandonDrain(d); return nil }
                    return d
                }
                guard let drainOpt = drained, !Task.isCancelled else {
                    if let d = drained ?? nil { appState.abandonDrain(d) }
                    break
                }
                let drain = drainOpt
                let items = (drain?.messages ?? []) as [DirectItem]
                appState.noteShownDirectEchoes(items)
                let receivedCount = items.count
                if receivedCount > 0 {
                    LogBuffer.shared.append(level: "D", tag: "Chat", message: "displaying \(receivedCount) received message(s)")
                }
                // Stable id from the sender's monotonic counter: a real
                // dedupe key, and skips a blob the relay re-serves. T1: dedupeId is
                // channel-namespaced (rx-/dr-). A GROUP_ECHO row is namespaced by its
                // group so it can never collide with a 1:1 id.
                let rows: [ChatMessage] =
                    items.map { item in
                        ChatMessage(
                            id: item.isGroupEcho ? "ge-\(item.groupId)-\(item.dedupeId)" : item.dedupeId,
                            text: item.text, isSent: false, delivered: true, failed: false,
                            timestamp: item.timestamp,
                            echoGroupId: item.isGroupEcho ? item.groupId : nil,
                            echoGroupName: item.groupName
                        )
                    }
                for msg in rows {
                    if messages.contains(where: { $0.id == msg.id }) { continue }
                    messages.append(msg)
                }
                // "Screenshot taken" notices: collected automatically inside the
                // poll above (pollDirect/pollAllControls), drained here — same
                // background context, never main (it resolves the alias from
                // the vault). The RAM buffer drain is destructive (rendered
                // once here), but the notice was ALSO already persisted, so
                // it still shows on the next open via the load-on-open block
                // above. Dedupe id keys on receivedAt (the store's stable
                // ordering key) so it matches the load-on-open id.
                let noticesRS = await appState.drainScreenshotNotices(conversationId: contactId)
                for n in noticesRS {
                    let stableId = "ss-\(n.senderContactId)-\(n.receivedAt)"
                    if messages.contains(where: { $0.id == stableId }) { continue }
                    messages.append(ChatMessage(
                        id: stableId,
                        text: L10n.commonScreenshotNotice(n.senderAlias) + " · " + formatNoticeTime(n.timestamp),
                        isSent: false,
                        delivered: true,
                        failed: false,
                        timestamp: n.timestamp,
                        isNotice: true,
                        expiresAt: n.expiresAt
                    ))
                }
                // Everything is on screen (the @State list holds the items): COMMIT, off
                // main, and finish it before the next poll of this conversation starts.
                // NEVER commit from a scenePhase/teardown path — an uncommitted drain
                // is what protects the message across a lock.
                if let drain, !drain.isEmpty { await appState.commitDrain(drain) }
                // P1-1 step B: re-read ratchetRefused on every poll tick, not just
                // on open/after-send — an inbound ratchet blob (possibly one that
                // carries no visible text, e.g. a control-channel announce) is what
                // clears the refusal, and this is where those land.
                appState.refreshRatchetRefused(contactId: contactId)
                // The poll may have applied an in-band inbox announce —
                // unlock the send button without re-entering the screen.
                if !hasOutbound { refreshHasOutbound() }
                if !verdictShown && appState.isRelayReachable {
                    verdictShown = true
                    let foundAny = !messages.isEmpty
                    // Keep "Consulting…" up long enough to read (and to let its slow
                    // fade-in finish) before crossfading to the verdict; then it
                    // lingers and fades out — all unhurried, for a mystic feel.
                    let elapsed = Date().timeIntervalSince(openedAt)
                    Task { @MainActor in
                        if elapsed < 1.6 {
                            try? await Task.sleep(nanoseconds: UInt64((1.6 - elapsed) * 1_000_000_000))
                        }
                        withAnimation(.easeInOut(duration: 1.2)) {
                            runeWhisper = ConversationRunes.shared.verdict(hasMessages: foundAny)
                        }
                        try? await Task.sleep(nanoseconds: 2_600_000_000)
                        // Clear only if it's still a transient verdict — a leave/consult
                        // state set meanwhile must survive (shared rule; matches group).
                        if ConversationRunes.shared.isTransientVerdict(whisper: runeWhisper) {
                            withAnimation(.easeOut(duration: 1.5)) { runeWhisper = nil }
                        }
                    }
                }
                // Hide any notice row whose TTL passed since it was rendered —
                // cheap (in-memory only), no vault read per tick; the vault-side
                // rows are pruned separately (GroupManager.pruneExpiredScreenshot-
                // Notices on the background control sweep, and ScreenshotNotice-
                // Store on write/read).
                let nowMs = Int64(Date().timeIntervalSince1970 * 1000)
                messages.removeAll { $0.isNotice && $0.expiresAt <= nowMs }
                // Poll on a JITTERED ~0.5–1.2 s interval while open (no fixed-period
                // beacon); the first fetch above is immediate. Leaving cancels this
                // task, so back is never delayed by the cadence.
                try? await Task.sleep(nanoseconds: UInt64.random(in: 500...1200) * 1_000_000)
            }
        }
    }

}

// MARK: - Message bubble

private struct MessageBubble: View {
    let message: ConversationView.ChatMessage

    var body: some View {
        if message.isNotice {
            // Centered, muted ephemeral notice — no bubble, no delivery marks.
            // Mirrors the group screen's system-notice style (GroupBubble).
            Text(message.text)
                .font(.runeCaption)
                .foregroundColor(Color.runTextSecondary)
                .frame(maxWidth: .infinity, alignment: .center)
                .padding(.vertical, 4)
                .accessibilityIdentifier("screenshot_notice")
        } else {
            bubble
        }
    }

    private var bubble: some View {
        HStack {
            if message.isSent { Spacer(minLength: 60) }

            VStack(alignment: message.isSent ? .trailing : .leading, spacing: 4) {
                Text(message.text)
                    .font(.runeBody)
                    .foregroundColor(.white)
                    .padding(.horizontal, 14)
                    .padding(.vertical, 10)
                    .background(message.isSent ? Color.runSentBubble : Color.runReceivedBubble)
                    .clipShape(RoundedRectangle(cornerRadius: 18))
                    .accessibilityIdentifier(message.isSent ? "message_bubble_sent" : "message_bubble_received")

                HStack(spacing: 4) {
                    if message.timestamp > 0 {
                        Text(Self.formatTime(message.timestamp))
                            .font(.system(size: 9))
                            .foregroundColor(Color(hex: 0x666666))
                    }
                    if message.isSent {
                        // L6: ✓ delivered · in-flight ✗ failed (red) — the failed state
                        // is no longer indistinguishable from a still-pending send.
                        if message.failed {
                            Text("✗")
                                .font(.runeCaption2)
                                .foregroundColor(.red)
                                .accessibilityIdentifier("message_failed")
                        } else {
                            Text(message.delivered ? "✓" : "·")
                                .font(.runeCaption2)
                                .foregroundColor(Color.runTextSecondary)
                        }
                    }
                }
                .padding(.horizontal, 4)
            }

            if !message.isSent { Spacer(minLength: 60) }
        }
    }

    // Locale- and device-24h-setting-aware (timeStyle .short), not a hardcoded
    // "HH:mm" — respects the user's system time format preference (matches
    // Android's android.text.format.DateFormat.getTimeFormat).
    private static func formatTime(_ millis: Int64) -> String {
        let date = Date(timeIntervalSince1970: Double(millis) / 1000.0)
        let fmt = DateFormatter()
        fmt.timeStyle = .short
        fmt.dateStyle = .none
        return fmt.string(from: date)
    }
}

// MARK: - NO-PARK marked bubbles (2026-10-06)
//
// Every message a conversation poll fetches is shown in THAT screen — the relay
// burned it at fetch, and parking it in RAM for "its" conversation lost it on every
// lock/relaunch. A group text fetched by a 1:1 poll (or another group's poll) is a
// GROUP_ECHO; a 1:1 text fetched by a group poll is a PRIVATE item (GroupViews.swift).
// Module-level (not a new file) so it needs no Xcode project-membership edit. The
// Android siblings live in MarkedBubbles.kt — keep the colour families in step.

extension Color {
    static let runPrivateBubble     = Color(hex: 0x2A2238)
    static let runPrivateBubbleSent = Color(hex: 0x3A2E50)
    static let runPrivateAccent     = Color(hex: 0xC4B2EA)
    static let runEchoBubble        = Color(hex: 0x1B2C30)
    static let runEchoAccent        = Color(hex: 0x8FC9D3)
}

/// A GROUP_ECHO bubble: received side, distinct colour, group glyph, "Group message
/// in <group>", and an "Open group" action. [senderAlias] is shown in a GROUP screen
/// (several senders); a 1:1 screen passes nil (the sender is that chat's contact).
/// Not replyable.
struct GroupEchoBubbleView: View {
    let groupName: String
    let senderAlias: String?
    let text: String
    let timestamp: Int64
    let onOpenGroup: () -> Void
    let bubbleId: String
    let labelId: String
    let openId: String

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 5) {
                    Image(systemName: "person.2.fill")
                        .font(.system(size: 10))
                        .foregroundColor(Color.runEchoAccent)
                    Text(L10n.conversationGroupEchoLabel(groupName))
                        .font(.runeCaption2)
                        .foregroundColor(Color.runEchoAccent)
                        .accessibilityIdentifier(labelId)
                }
                if let senderAlias {
                    Text(senderAlias)
                        .font(.runeCaption2)
                        .foregroundColor(Color.runTextSecondary)
                }
                Text(text)
                    .font(.runeBody)
                    .foregroundColor(.white)
                HStack(spacing: 8) {
                    Button(action: onOpenGroup) {
                        Text(L10n.conversationGroupEchoOpen)
                            .font(.runeCaption)
                            .foregroundColor(Color.runEchoAccent)
                    }
                    .buttonStyle(.plain)
                    .accessibilityIdentifier(openId)
                    if timestamp > 0 {
                        Spacer(minLength: 0)
                        Text(markedBubbleTime(timestamp))
                            .font(.system(size: 9))
                            .foregroundColor(Color(hex: 0x666666))
                    }
                }
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 10)
            .background(Color.runEchoBubble)
            .clipShape(RoundedRectangle(cornerRadius: 18))
            .accessibilityElement(children: .contain)
            .accessibilityIdentifier(bubbleId)
            Spacer(minLength: 60)
        }
    }
}

/// Locale/24h-aware short time for the marked bubbles (same format as MessageBubble).
func markedBubbleTime(_ millis: Int64) -> String {
    let fmt = DateFormatter()
    fmt.timeStyle = .short
    fmt.dateStyle = .none
    return fmt.string(from: Date(timeIntervalSince1970: Double(millis) / 1000.0))
}

// Screenshot-notice display time: locale time for a capture today, "Yesterday
// <time>" when the calendar day differs — the notice's 24h TTL means "differs"
// can only ever mean yesterday, never further back. File-scope (not nested in
// MessageBubble) so ConversationView.startPolling() can precompute the full
// notice string once, on append — mirrors ConversationScreen.kt.
fileprivate func formatNoticeTime(_ millis: Int64) -> String {
    let date = Date(timeIntervalSince1970: Double(millis) / 1000.0)
    let fmt = DateFormatter()
    fmt.timeStyle = .short
    fmt.dateStyle = .none
    let sameDay = Calendar.current.isDate(date, inSameDayAs: Date())
    let time = fmt.string(from: date)
    return sameDay ? time : L10n.commonTimeYesterday(time)
}

// MARK: - Burn-on-read onboarding (shared by 1:1 + group conversations)
//
// Lives here (not a standalone file) so it needs no Xcode project-membership
// edit — Swift makes these module-level declarations visible to
// GroupConversationView too. Shown on the FIRST conversation ever opened per
// vault (whichever type opens first), keyed on a durable vault-meta latch so it
// fires once total. Android mirrors this copy in a Compose AlertDialog
// (BurnOnReadNotice.kt).

private let burnNoticeMetaKey = "onboard_burn_notice_v1"

/// Returns true exactly once per vault: the first call finds the meta absent,
/// writes it, and returns true; later calls (this vault) return false. Durable
/// across relaunch/lock, cleared with the vault on wipe. putMeta is @Throws;
/// try? so a failed write just re-offers the notice next open (fail-safe)
/// rather than crossing the bridge. Mirrors the add-contacts prompt latch.
func consumeBurnNoticeOnce(_ vault: VaultDatabase) -> Bool {
    guard vault.getMeta(key: burnNoticeMetaKey) == nil else { return false }
    try? vault.putMeta(key: burnNoticeMetaKey, value: "1")
    return true
}

extension View {
    /// The first-open onboarding: the burn-on-read CONCEPT. Simple,
    /// pedagogical, no jargon — messages show once and are never stored.
    func burnOnReadNotice(isPresented: Binding<Bool>) -> some View {
        overlay {
            if isPresented.wrappedValue {
                RuneDialogOverlay(
                    title: L10n.burnNoticeTitle,
                    message: L10n.burnNoticeMessage,
                    a11yId: "burn_notice",
                    // Scrim tap = "Got it", matching Android's onDismissRequest.
                    onScrimTap: { isPresented.wrappedValue = false },
                    actions: [
                        RuneDialogAction(L10n.commonGotIt, a11yId: "burn_notice_ok") {
                            isPresented.wrappedValue = false
                        },
                    ]
                )
            }
        }
    }
}

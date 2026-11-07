import SwiftUI
import UIKit
import shared

// ---------------------------------------------------------------------------
// GroupViews — CreateGroupView (sheet) + GroupConversationView (push).
//
// Group chat is pairwise fan-out: a group message is N ordinary 1:1 sends
// into the members' existing inboxes, with all group routing sealed inside
// the AES-GCM envelope. It is NOT indistinguishable from 1:1 traffic on the
// wire: the fan-out is k POSTs into k distinct
// inboxes in one window plus an equal-cardinality control burst, and the
// group poll loop re-drains those same k inboxes every few seconds. Content,
// group name and member-list contents are protected; group existence and
// size are not. All protocol logic lives in the shared GroupManager; these
// views are thin SwiftUI mirrors of the Android screens.
//
// Security notes carried into the UI:
//   • Messages are never persisted — in-memory only, erased on dismissal.
//   • Sender attribution on bubbles comes from the pairwise channel the
//     message decrypted on; other members cannot spoof it.
//   • A "member list differs" marker is shown when the sender's membership
//     hash mismatches ours (splitting detection) — shown, never hidden.
//   • Fan-out delivery is not atomic; partial delivery is surfaced honestly
//     ("3/4") instead of a fake single checkmark.
// ---------------------------------------------------------------------------

// MARK: - Create group

struct CreateGroupView: View {
    @EnvironmentObject private var appState: AppState
    let onDismiss: () -> Void
    let onCreated: (String) -> Void

    @State private var groupName = ""
    @State private var selectedIds: Set<String> = []
    @State private var eligible: [MemberCandidate] = []
    @State private var creating = false
    @State private var createFailed = false

    struct MemberCandidate: Identifiable {
        let id: String      // contactId
        let alias: String
    }

    private var canCreate: Bool {
        !groupName.trimmingCharacters(in: .whitespaces).isEmpty &&
            !selectedIds.isEmpty && !creating
    }

    var body: some View {
        NavigationStack {
            ZStack {
                Color.runBackground.ignoresSafeArea()

                VStack(spacing: 12) {
                    TextField(L10n.createGroupNamePlaceholder, text: $groupName)
                        .foregroundColor(Color.runTextPrimary)
                        .tint(Color.runAccent)
                        .autocorrectionDisabled(true)
                        .textInputAutocapitalization(.never)
                        // Autocorrection-off alone
                        // suppresses inline correction UI only — it does NOT stop the
                        // system keyboard's QuickType engine from learning this word
                        // into its on-device lexicon (which outlives an app wipe).
                        // .password excludes the field from that learning, matching
                        // Android's KeyboardType.Password on the identical field
                        // (CreateGroupScreen.kt) — a group name can name a real circle.
                        .textContentType(.password)
                        .padding()
                        .background(Color.runSurface)
                        .cornerRadius(8)
                        .padding(.horizontal)
                        .accessibilityIdentifier("group_name_input")
                        .onChange(of: groupName) { value in
                            if value.count > Int(GroupManager.companion.MAX_GROUP_NAME_CHARS) {
                                groupName = String(value.prefix(Int(GroupManager.companion.MAX_GROUP_NAME_CHARS)))
                            }
                        }

                    // The IRL precondition — stated because it cannot be
                    // enforced (no global identities, by design).
                    Text(L10n.createGroupPrecondition)
                        .font(.runeCaption)
                        .foregroundColor(Color.runTextSecondary)
                        .multilineTextAlignment(.leading)
                        .padding(.horizontal)

                    ScrollView {
                        LazyVStack(spacing: 0) {
                            ForEach(eligible) { candidate in
                                Button {
                                    if selectedIds.contains(candidate.id) {
                                        selectedIds.remove(candidate.id)
                                    } else if selectedIds.count + 2 <= Int(GroupManager.companion.MAX_GROUP_MEMBERS) {
                                        selectedIds.insert(candidate.id)
                                    }
                                } label: {
                                    HStack(spacing: 12) {
                                        Text(candidate.alias)
                                            .font(.runeBody)
                                            .foregroundColor(Color.runTextPrimary)
                                            .lineLimit(1)
                                            .truncationMode(.tail)
                                        Spacer()
                                        Image(systemName: selectedIds.contains(candidate.id)
                                              ? "checkmark.circle.fill" : "circle")
                                            .foregroundColor(selectedIds.contains(candidate.id)
                                                             ? Color.runAccent : Color.runTextSecondary)
                                    }
                                    .padding(.horizontal, 16)
                                    .padding(.vertical, 12)
                                    .contentShape(Rectangle())
                                }
                                .accessibilityIdentifier("group_member_row_\(candidate.id)")
                            }
                        }
                    }
                    .accessibilityIdentifier("group_member_list")

                    if createFailed {
                        Text(L10n.createGroupFailed)
                            .font(.runeCaption)
                            .foregroundColor(.red)
                            .padding(.horizontal)
                    }

                    Button {
                        createGroup()
                    } label: {
                        Text(creating ? L10n.createGroupCreating
                             : selectedIds.isEmpty ? L10n.createGroupSelectMembers
                             : L10n.createGroupButtonLabel(selectedIds.count + 1))
                            .font(.runeHeadline)
                            .foregroundColor(canCreate ? Color.black : Color.runTextSecondary)
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 14)
                            .background(canCreate ? Color.runTextPrimary : Color.runSurface)
                            .cornerRadius(12)
                            .padding(.horizontal)
                    }
                    .disabled(!canCreate)
                    .accessibilityIdentifier("create_group_button")
                    .padding(.bottom, 12)
                }
                .padding(.top, 16)
            }
            .navigationTitle(L10n.createGroupTitle)
            .navigationBarTitleDisplayMode(.inline)
            .runNavigationBarChrome()
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button(L10n.commonCancel) { onDismiss() }
                        .foregroundColor(Color.runTextPrimary)
                        .accessibilityIdentifier("create_group_back")
                }
            }
            .onAppear { loadEligibleContacts() }
        }
        .preferredColorScheme(.dark)
    }

    /// Only FULLY paired contacts are offered — a pending one (awaiting their
    /// inbox announce) can't receive the invite; a stale one can't be
    /// messaged at all.
    private func loadEligibleContacts() {
        guard let vault = appState.vault else { return }
        // getAllContacts() carries a live
        // sharedSecret per record; wipe the UNFILTERED source list — the
        // filtered-out (not-yet-paired) records must not keep an un-zeroed
        // secret either. Mirrors CreateGroupScreen.kt.
        let allContacts = vault.getAllContacts()
        eligible = allContacts
            .filter { MessageManagerKt.contactFullyPaired(vault: vault, contactId: $0.contactId) }
            .map { MemberCandidate(id: $0.contactId, alias: $0.alias) }
        for contact in allContacts { contact.sharedSecret.secureWipe() }
    }

    private func createGroup() {
        creating = true
        createFailed = false
        let name = groupName.trimmingCharacters(in: .whitespaces)
        let members = Array(selectedIds)
        Task { @MainActor in
            let groupId = await appState.createGroup(name: name, memberContactIds: members)
            creating = false
            if let groupId { onCreated(groupId) } else { createFailed = true }
        }
    }
}

// MARK: - Group conversation

struct GroupConversationView: View {
    @EnvironmentObject private var appState: AppState
    let groupId: String
    /// NO-PARK (2026-10-06): another group's GROUP_ECHO "Open group".
    var onOpenGroup: (String) -> Void = { _ in }
    // NO-PARK private-reply mode: the 1:1 counterpart, or nil. Entered from a
    // PRIVATE bubble's "Reply privately"; it STAYS until the user closes the chip,
    // so a follow-up line is never accidentally sent to the group.
    @State private var privateReplyTo: (contactId: String, alias: String)? = nil

    @State private var messages: [GroupChatMessage] = []
    @State private var inputText = ""
    @State private var pollTask: Task<Void, Never>? = nil
    @State private var sendTasks: [Task<Void, Never>] = []
    // The "did not reach N" system note is posted once per DISTINCT N in this
    // screen session (mirrors Android's undeliveredNoticed).
    @State private var undeliveredNoticed: Int32 = -1
    @State private var groupName = ""
    @State private var subtitle = ""
    @State private var showInfo = false
    // Long-press on a received bubble: VIEW the sender's personal memory —
    // read-only here; editing lives in the contact list.
    @State private var memoryPopup: (alias: String, mnemonic: String)? = nil
    @State private var showMemoryAlert = false
    // Discreet runestone-flavoured feedback (mirrors the 1:1 screen): the first
    // fetch on open ("Consulting the runes…" → verdict).
    @State private var runeWhisper: String? = nil
    // One-time burn-on-read notice (shared with the 1:1 view via the vault-meta
    // latch); first conversation ever opened per vault.
    @State private var showBurnNotice = false
    // CONVERSATION-SCOPED "I took a screenshot" sender — mirrors ConversationView's
    // observer exactly (see its kdoc). Armed only while THIS group is on screen.
    @State private var screenshotObserver: NSObjectProtocol? = nil
    @Environment(\.dismiss) private var dismiss
    @Environment(\.scenePhase) private var scenePhase

    struct GroupChatMessage: Identifiable {
        let id: String
        let text: String
        let isSent: Bool    // true = outbound (right), false = inbound (left) — layout auto-mirrors under RTL (leading/trailing are reading-relative)
        let senderAlias: String
        let senderContactId: String
        let timestamp: Int64
        let membershipOk: Bool
        // System notice (e.g. "X left the group") — centered/muted, no bubble.
        var isSystem: Bool = false
        // "X may have taken a screenshot" notice — same centered/muted
        // rendering as isSystem, but a DISTINCT a11y id (screenshot_notice_group)
        // so e2e can target it specifically. PERSISTED for 24 h now (docs/
        // screenshot-notice-persistence-design.md) — loaded on open from
        // AppState.loadScreenshotNotices and appended live from
        // AppState.drainScreenshotNotices.
        var isScreenshotNotice: Bool = false
        // Local wall-clock deadline (ScreenshotNotice.expiresAt) past which
        // this row is dropped on the next poll tick without a vault read.
        // Non-notice rows never expire.
        var expiresAt: Int64 = Int64.max
        // nil = pending; (delivered, total, unreachable) once the fan-out finished.
        // unreachable = members on the roster with no resolved contact on this
        // phone; they got no copy and there is no later delivery.
        var delivered: Int32? = nil
        var total: Int32? = nil
        var unreachable: Int32? = nil
        // NO-PARK (2026-10-06): PRIVATE / PRIVATE_SENT carry the 1:1 counterpart in
        // senderContactId/senderAlias; GROUP_ECHO names ANOTHER group.
        var kind: RowKind = .group
        var echoGroupId: String = ""
        var echoGroupName: String = ""
    }

    enum RowKind { case group, privateReceived, privateSent, groupEcho }

    // Captured once so the runestone frame is a constant CGSize and can never
    // re-measure (the zoom-free guarantee — see ContactListView).
    private var screenSize: CGSize { UIScreen.main.bounds.size }

    // Full-bleed runestone, used as a .background so it never drives the
    // content's layout (keyboard avoidance stays intact). Fixed CGSize frame =
    // zoom-proof; ignoresSafeArea = full-bleed.
    private var groupRunestoneBackground: some View {
        let artLevel = appState.controller.displayProtectionLevel()
        return ZStack {
            Color.runBackground
            Image(runestoneAsset("runestone_dim", level: artLevel))
                .resizable().scaledToFill()
                .frame(width: screenSize.width, height: screenSize.height)
                .clipped()
            Image(runestoneAsset("runestone_bright_and_lit", level: artLevel))
                .resizable().scaledToFill()
                .frame(width: screenSize.width, height: screenSize.height)
                .clipped()
                .opacity(appState.isRelayReachable ? 1 : 0)
                .animation(.easeInOut(duration: 0.6), value: appState.isRelayReachable)
            Color.black.opacity(0.55)
        }
        .ignoresSafeArea()
    }

    var body: some View {
        VStack(spacing: 0) {
            messageList
            Divider().background(Color.runDivider)
            inputBar
        }
        // Discreet, runestone-flavoured fetch/leave feedback (fades on its own),
        // overlaid in the lower third so it never reflows the message list.
        .overlay {
            if let whisper = runeWhisper {
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
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        // Runestone as a BACKGROUND, not a ZStack sibling: its fixed screen-sized
        // frame (zoom-proofing) would otherwise force the stack full-screen and
        // defeat keyboard avoidance, leaving the input bar behind the on-screen
        // keyboard on a physical device. As a background it stays full-bleed +
        // zoom-proof without driving the content layout. (Mirrors ConversationView.)
        .background(groupRunestoneBackground)
        .navigationBarTitleDisplayMode(.inline)
        .navigationBarBackButtonHidden(true)
        .runNavigationBarChrome()
        .toolbar { groupToolbar }
        .sheet(isPresented: $showInfo) {
            GroupInfoView(
                groupId: groupId,
                onDismiss: { showInfo = false },
                onLeft: {
                    showInfo = false
                    dismiss()
                }
            )
            .privacyCovered()
        }
        // View-only memory popup (alias + the user's private memory).
        .overlay {
            if showMemoryAlert, let pop = memoryPopup {
                RuneDialogOverlay(
                    title: pop.alias,
                    message: pop.mnemonic.isEmpty ? L10n.contactListNoMemoryYet : pop.mnemonic,
                    a11yId: "group_memory_alert",
                    onScrimTap: { showMemoryAlert = false; memoryPopup = nil },
                    actions: [RuneDialogAction(L10n.commonOk) { showMemoryAlert = false; memoryPopup = nil }]
                )
            }
        }
        .onChange(of: scenePhase) { phase in
            // IOS-SEC-2 parity with ContactListView: keep the plaintext memory
            // out of the app-switcher snapshot — alerts have no overlay hook.
            if phase != .active {
                showMemoryAlert = false
                memoryPopup = nil
            }
        }
        .onAppear {
            refreshHeader()
            startPolling()
            LogBuffer.shared.append(level: "D", tag: "GroupChat", message: "group conversation opened")
            // Fourth FAST control-cadence condition (2026-10-01): while this group
            // conversation is on screen — GroupInfoView is a sheet over it, so it is
            // covered too — the background control sweep polls at the fast cadence,
            // per cycle only. Ends with the screen. Android sibling:
            // GroupConversationScreen / GroupInfoScreen DisposableEffect.
            appState.controller.setGroupConversationForeground(screenKey: "conv:\(groupId)", open: true)
            // First-conversation-ever burn-on-read notice (shared helper in
            // ConversationView.swift — same vault-meta latch as the 1:1 view, so
            // it shows once total whichever conversation type opens first).
            if let vault = appState.vault { showBurnNotice = consumeBurnNoticeOnce(vault) }
            // Screenshot-taken notice: best-effort, fire-and-forget, off-main —
            // mirrors ConversationView's observer exactly (see its kdoc). Armed
            // only while this group is on screen — removed in onDisappear below.
            screenshotObserver = NotificationCenter.default.addObserver(
                forName: UIApplication.userDidTakeScreenshotNotification, object: nil, queue: .main
            ) { _ in
                let gm = appState.controller.groupManager
                DispatchQueue.global(qos: .utility).async {
                    gm?.sendGroupScreenshotNotice(groupId: groupId)
                }
            }
        }
        .burnOnReadNotice(isPresented: $showBurnNotice)
        // A transport-back re-drive landed a parked PRIVATE reply sent from this
        // screen: flip its row to delivered. Idempotent, not consuming — see the
        // 1:1 twin in ConversationView for the ownership rule.
        .onReceive(appState.$redrivenMessageIds) { ids in
            guard !ids.isEmpty else { return }
            for idx in messages.indices where messages[idx].kind == .privateSent && ids.contains(messages[idx].id) {
                messages[idx].delivered = 1
                messages[idx].total = 1
            }
        }
        .onDisappear {
            appState.controller.setGroupConversationForeground(screenKey: "conv:\(groupId)", open: false)
            if let obs = screenshotObserver {
                NotificationCenter.default.removeObserver(obs)
                screenshotObserver = nil
            }
            pollTask?.cancel()
            // Do NOT cancel in-flight SEND tasks — a group send must survive leaving
            // the conversation (same silent-loss bug as the 1:1 send). They finish on
            // their own; just drop our references.
            sendTasks.removeAll()
            let count = messages.count
            messages.removeAll()
            LogBuffer.shared.append(level: "D", tag: "GroupChat", message: "group conversation closed, \(count) message(s) erased from memory")
        }
    }

    /// Back chevron (leaves immediately), group name + subtitle, group-info button.
    @ToolbarContentBuilder
    private var groupToolbar: some ToolbarContent {
        ToolbarItem(placement: .navigationBarLeading) {
            Button { dismiss() } label: {
                // chevron.backward (not chevron.left): an auto-mirroring semantic
                // SF Symbol that points toward reading-start under RTL (ar/fa)
                // instead of a fixed left-pointing glyph.
                Image(systemName: "chevron.backward")
                    .foregroundColor(Color.runTextPrimary)
                    .transaction { $0.animation = nil }  // never animate this control
            }
            // Leaving is IMMEDIATE (retrieve-ack): chevron and edge-swipe pop at
            // once; a drain not yet shown is abandoned on disappear.
            .accessibilityIdentifier("group_conversation_back")
        }
        ToolbarItem(placement: .principal) {
            VStack(spacing: 1) {
                Text(groupName)
                    .font(.runeHeadline)
                    .foregroundColor(Color.runTextPrimary)
                    .lineLimit(1)
                    .truncationMode(.tail)
                    .accessibilityIdentifier("group_conversation_title")
                Text(subtitle)
                    .font(.runeCaption2)
                    .foregroundColor(Color.runTextSecondary)
                    .lineLimit(1)
                    .truncationMode(.tail)
            }
        }
        ToolbarItem(placement: .navigationBarTrailing) {
            Button { showInfo = true } label: {
                Image(systemName: "info.circle")
                    .foregroundColor(Color.runTextPrimary)
            }
            .accessibilityIdentifier("group_info_button")
        }
    }

    // MARK: - Subviews

    private var messageList: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(spacing: 8) {
                    ForEach(messages) { msg in
                        if msg.kind == .groupEcho {
                            GroupEchoBubbleView(
                                groupName: msg.echoGroupName,
                                senderAlias: msg.senderAlias,
                                text: msg.text,
                                timestamp: msg.timestamp,
                                onOpenGroup: { onOpenGroup(msg.echoGroupId) },
                                bubbleId: "group_echo_bubble",
                                labelId: "group_echo_label",
                                openId: "group_echo_open"
                            )
                            .id(msg.id)
                        } else if msg.kind == .privateReceived || msg.kind == .privateSent {
                            PrivateBubble(message: msg) {
                                privateReplyTo = (msg.senderContactId, msg.senderAlias)
                            }
                            .id(msg.id)
                        } else {
                            GroupBubble(message: msg)
                                .id(msg.id)
                                .onLongPressGesture {
                                    guard !msg.isSent, !msg.isSystem, !msg.isScreenshotNotice, !msg.senderContactId.isEmpty else { return }
                                    // getContact() carries a raw
                                    // sharedSecret; project the mnemonic then wipe.
                                    let senderRecord = appState.vault?.getContact(contactId: msg.senderContactId)
                                    let mnemonic = senderRecord?.mnemonic ?? ""
                                    senderRecord?.sharedSecret.secureWipe()
                                    memoryPopup = (msg.senderAlias, mnemonic)
                                    showMemoryAlert = true
                                }
                        }
                    }
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
            }
            .accessibilityIdentifier("group_message_list")
            .onChange(of: messages.count) { _ in
                guard let last = messages.last else { return }
                withAnimation { proxy.scrollTo(last.id, anchor: .bottom) }
            }
        }
    }

    private var inputBar: some View {
        // iOS keeps the no-learning composer at EVERY tier (2026-09-21, reverting the
        // 2026-09-20 tier split for iOS only): the
        // password content type is the ONLY modifier that keeps this field out
        // of QuickType's learned vocabulary, and unlike Gboard the iOS keyboard
        // keeps its emoji key in that mode, so there is no emoji cost to pay
        // here. The tier split stays on Android (ComposerKeyboardPolicy /
        // RunViewModel.strictComposerKeyboard), where password mode removes the
        // emoji key — the Protection taglines describe the Android trade only.
        return VStack(alignment: .leading, spacing: 8) {
            // Private-reply chip (NO-PARK): while shown, Send goes to that contact's 1:1
            // channel. Explicit exit only — the × closes it.
            if let target = privateReplyTo {
                HStack(spacing: 6) {
                    Image(systemName: "lock.fill")
                        .font(.system(size: 10))
                        .foregroundColor(Color.runPrivateAccent)
                    Text(L10n.groupPrivateReplyChip(target.alias))
                        .font(.runeCaption)
                        .foregroundColor(Color.runPrivateAccent)
                        .lineLimit(1)
                        .truncationMode(.tail)
                    Button { privateReplyTo = nil } label: {
                        Image(systemName: "xmark")
                            .font(.system(size: 11, weight: .semibold))
                            .foregroundColor(Color.runPrivateAccent)
                            .padding(.horizontal, 6)
                            .padding(.vertical, 4)
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel(L10n.groupPrivateReplyChipClose)
                    .accessibilityIdentifier("composer_private_chip_close")
                }
                .padding(.leading, 10)
                .padding(.trailing, 4)
                .padding(.vertical, 4)
                .background(Color.runPrivateBubble)
                .clipShape(Capsule())
                .accessibilityElement(children: .contain)
                .accessibilityIdentifier("composer_private_chip")
            }
            HStack(spacing: 8) {
                TextField(L10n.commonMessagePlaceholder, text: $inputText)
                    .noLearningComposerStyle()
                    .onSubmit { sendMessage() }
                    .accessibilityIdentifier("group_message_input")

                Button { sendMessage() } label: {
                    Image(systemName: "arrow.up.circle.fill")
                        .font(.system(size: 32))
                        .foregroundColor(canSend ? Color.runTextPrimary : Color(hex: 0x333333))
                }
                .disabled(!canSend)
                .accessibilityIdentifier("group_send_button")
            }
        }
        .transaction { $0.animation = nil }    // never animate the input bar
        .padding(.horizontal, 12)
        .padding(.vertical, 10)
        .background(Color.runBackground)
    }

    /// The composer holds something other than whitespace.
    private var hasDraft: Bool { !inputText.trimmingCharacters(in: .whitespaces).isEmpty }

    /// Tor (when required) is up AND the relay answered — a send can go out now.
    private var transportReady: Bool { appState.isTorConnected && appState.isRelayReachable }

    private var canSend: Bool {
        hasDraft && transportReady
    }

    // MARK: - Logic

    private func refreshHeader() {
        guard let vault = appState.vault else { return }
        let gid = groupId
        // Read the header rows OFF the main actor — this runs after
        // EVERY 3–8 s poll and does 2 SQLCipher decrypts. pollGroup already reads/writes the
        // vault off-main, so a detached read is safe; state + dismiss hop back to main.
        Task.detached(priority: .userInitiated) {
            let group = vault.getGroup(groupId: gid)
            let members = vault.getGroupMembers(groupId: gid)
            await MainActor.run {
                guard let group else {
                    dismiss()   // admin removed us (roster applied during some poll)
                    return
                }
                groupName = group.name
                let resolved = members.filter { $0.contactId != nil }.count + 1   // self
                if resolved < members.count {
                    subtitle = L10n.groupInfoMembers(members.count) + " · " + L10n.groupInfoNotReachableSuffix(members.count - resolved)
                } else {
                    subtitle = L10n.groupInfoMembers(members.count) + (group.isAdmin ? " · " + L10n.groupInfoAdminSuffix : "")
                }
            }
        }
    }

    // Keep the list ordered by timestamp. Group traffic merges
    // from N pairwise inboxes (shuffled shared-side), so a slower inbox can deliver an
    // OLDER message in a later poll; a plain append placed it BELOW a newer one and the
    // visible HH:mm made the inversion obvious. Insert at the sorted position instead
    // (small in-memory list); `.last` stays the newest so autoscroll is unaffected.
    private func insertByTimestamp(_ msg: GroupChatMessage) {
        let idx = messages.firstIndex { ($0.timestamp, $0.id) > (msg.timestamp, msg.id) } ?? messages.count
        messages.insert(msg, at: idx)
    }

    private func sendMessage() {
        let text = inputText.trimmingCharacters(in: .whitespaces)
        guard !text.isEmpty, appState.isTorConnected else { return }
        inputText = ""

        let msgId = UUID().uuidString
        if let target = privateReplyTo {
            // NO-PARK private reply: the EXISTING 1:1 send path to that contact (no
            // new wire format), shown inline as PRIVATE_SENT — see
            // AppState.sendPrivateReply. Like the group send it survives leaving.
            insertByTimestamp(GroupChatMessage(
                id: msgId, text: text, isSent: true,
                senderAlias: target.alias, senderContactId: target.contactId,
                timestamp: Int64(Date().timeIntervalSince1970 * 1000),
                membershipOk: true, kind: .privateSent
            ))
            let cid = target.contactId
            // Captured at tap time: the reply's attempts run under this session only
            // (AppState.sendPrivateReply re-checks it before every attempt).
            let sendEpoch = TransportFailedSends.companion.shared.sessionEpoch
            let task = Task { @MainActor in
                // msgId doubles as the re-drive token (see AppState.sendMessage).
                let success = await appState.sendPrivateReply(contactId: cid, text: text, redriveToken: msgId, sessionEpoch: sendEpoch)
                // The session ended meanwhile (lock / wipe): write nothing back.
                guard appState.isSendSessionCurrent(sendEpoch) else { return }
                if success, let idx = messages.firstIndex(where: { $0.id == msgId }) {
                    messages[idx].delivered = 1
                    messages[idx].total = 1
                }
                // Same ownership rule as ConversationView's send loop.
                appState.redrivenMessageIds.remove(msgId)
            }
            sendTasks.append(task)
            return
        }
        insertByTimestamp(GroupChatMessage(
            id: msgId, text: text, isSent: true,
            senderAlias: "", senderContactId: "",
            timestamp: Int64(Date().timeIntervalSince1970 * 1000),
            membershipOk: true
        ))

        let task = Task { @MainActor in
            // Fan-out (shuffled + jittered) happens inside GroupManager.
            let result = await appState.sendGroupMessage(groupId: groupId, text: text)
            if Task.isCancelled { return }
            if let idx = messages.firstIndex(where: { $0.id == msgId }) {
                messages[idx].delivered = result?.delivered ?? 0
                messages[idx].total = result?.total ?? 0
                messages[idx].unreachable = result?.unreachable ?? 0
            }
            // Explain the mark once per DISTINCT count (mirrors Android): who got
            // nothing and why, and that there is no later delivery (no backfill).
            let undelivered = result?.undelivered ?? 0
            if undelivered > 0 && undelivered != undeliveredNoticed {
                undeliveredNoticed = undelivered
                let now = Int64(Date().timeIntervalSince1970 * 1000)
                insertByTimestamp(GroupChatMessage(
                    id: "g-sys-local-undelivered-\(now)",
                    text: L10n.groupNoticeNotDelivered(Int(undelivered)),
                    isSent: false, senderAlias: "", senderContactId: "",
                    timestamp: now, membershipOk: true, isSystem: true
                ))
            }
        }
        sendTasks.append(task)
    }

    private func startPolling() {
        pollTask?.cancel()   // Cancel any prior loop before reassigning
        pollTask = Task { @MainActor in
            var verdictShown = false
            let openedAt = Date()
            var firstPoll = true
            // Announce the fetch on open — only when the relay is reachable; with
            // no relay there are no runes to consult.
            if appState.isRelayReachable {
                withAnimation(.easeIn(duration: 1.3)) { runeWhisper = ConversationRunes.shared.CONSULTING }
            }
            // Load-on-open: every UNEXPIRED persisted notice for this group,
            // oldest first — mirrors ConversationView's load-on-open (docs/
            // screenshot-notice-persistence-design.md §0). Runs ONCE, before
            // the loop below; the loop only ever APPENDS newly arrived
            // notices from here on. Dedupe id keys on receivedAt (the
            // store's stable ordering key), matching the per-tick drain.
            let persistedNotices = await appState.loadScreenshotNotices(conversationId: groupId)
            for n in persistedNotices {
                let stableId = "g-sys-ss-\(n.senderContactId)-\(n.receivedAt)"
                if messages.contains(where: { $0.id == stableId }) { continue }
                insertByTimestamp(GroupChatMessage(
                    id: stableId,
                    text: "\(L10n.commonScreenshotNotice(n.senderAlias)) · \(formatNoticeTime(n.timestamp))",
                    isSent: false,
                    senderAlias: n.senderAlias,
                    senderContactId: n.senderContactId,
                    timestamp: n.timestamp,
                    membershipOk: true,
                    isScreenshotNotice: true,
                    expiresAt: n.expiresAt
                ))
            }
            while !Task.isCancelled {
                // Cadence (3–8 s; each cycle polls N member inboxes, shuffled inside
                // GroupManager). Skipped before the FIRST poll so the open fetch is
                // immediate (matches the 1:1 screen). Leaving cancels this task, so
                // back is never delayed by it.
                if !firstPoll {
                    try? await Task.sleep(nanoseconds: UInt64(Double.random(in: 3.0...8.0) * 1_000_000_000))
                }
                firstPoll = false
                guard !Task.isCancelled else { break }
                // NO per-iteration checkRelayReachability() here (Android parity):
                // AppState.startRelayCheck's 8–12 s health loop owns reachability —
                // and everything that rides along with it (the update nudge, the
                // review prompt, the miss-streak/NEWNYM ladder, relayConnectPhase,
                // relayHandshakeComplete). This screen only READS
                // `appState.isRelayReachable` (whisper, runestone, send gate) and
                // that loop keeps it current. Probing from here put a full onion
                // round-trip in front of every poll, and so in front of every
                // back tap — on top of the fan-out this loop already does.
                // RETRIEVE-ACK: poll UNCOMMITTED (decrypt only), append to the list, THEN
                // commit (persist ratchet / anti-replay state + fire-and-forget ack).
                // Leaving is immediate: this task is cancelled on disappear, and a drain
                // that was not yet shown is abandoned (dropping it is also safe — the
                // relay re-delivers after its lease). awaitDrain returns nil only when
                // this task is cancelled; a drain that lands after that is abandoned by
                // the closure itself. The members' GETs run concurrently (GROUP-FANOUT).
                // Parked items come first in `messages` and leave the buffer only on commit.
                let drained = await awaitDrain { () -> PendingDrain<GroupMessage>? in
                    let d = await appState.pollGroupPending(groupId: groupId)
                    if Task.isCancelled, let d { appState.abandonDrain(d); return nil }
                    return d
                }
                guard let drainOpt = drained, !Task.isCancelled else {
                    if let d = drained ?? nil { appState.abandonDrain(d) }
                    break
                }
                let drain = drainOpt
                let received = (drain?.messages ?? []) as [GroupMessage]
                appState.noteShownGroupEchoes(received)
                for gm in received {
                    // Stable dedupe key: pairwise channel + sender counter. System
                    // notices share counter 0, so key those by timestamp instead.
                    // NO-PARK: PRIVATE / GROUP_ECHO rows get their own namespaces.
                    let stableId: String
                    let kind: RowKind
                    if gm.isSystem {
                        stableId = "g-sys-\(gm.senderContactId)-\(gm.timestamp)"; kind = .group
                    } else if gm.isPrivate {
                        stableId = "gp-\(gm.senderContactId)-\(gm.dedupeId)"; kind = .privateReceived
                    } else if gm.isGroupEcho {
                        stableId = "ge-\(gm.groupId)-\(gm.senderContactId)-\(gm.dedupeId)"; kind = .groupEcho
                    } else {
                        stableId = "g-\(gm.senderContactId)-\(gm.dedupeId)"; kind = .group   // T1: dedupeId is rx-/dr- namespaced
                    }
                    if messages.contains(where: { $0.id == stableId }) { continue }
                    insertByTimestamp(GroupChatMessage(
                        id: stableId,
                        text: gm.text,
                        isSent: false,
                        senderAlias: gm.senderAlias,
                        senderContactId: gm.senderContactId,
                        timestamp: gm.timestamp,
                        membershipOk: gm.membershipOk,
                        isSystem: gm.isSystem,
                        kind: kind,
                        echoGroupId: gm.isGroupEcho ? gm.groupId : "",
                        echoGroupName: gm.isGroupEcho ? gm.groupName : ""
                    ))
                }
                // "Screenshot taken" notices: collected automatically inside the
                // poll above (pollGroup/pollAllControls), drained here — same
                // background context, never main (it resolves the alias from
                // the vault). The RAM buffer drain is destructive (rendered
                // once here), but the notice was ALSO already persisted, so it
                // still shows on the next open via the load-on-open block
                // above. Dedupe id keys on receivedAt (the store's stable
                // ordering key) so it matches the load-on-open id.
                let noticesRS = await appState.drainScreenshotNotices(conversationId: groupId)
                for n in noticesRS {
                    let stableId = "g-sys-ss-\(n.senderContactId)-\(n.receivedAt)"
                    if messages.contains(where: { $0.id == stableId }) { continue }
                    insertByTimestamp(GroupChatMessage(
                        id: stableId,
                        text: "\(L10n.commonScreenshotNotice(n.senderAlias)) · \(formatNoticeTime(n.timestamp))",
                        isSent: false,
                        senderAlias: n.senderAlias,
                        senderContactId: n.senderContactId,
                        timestamp: n.timestamp,
                        membershipOk: true,
                        isScreenshotNotice: true,
                        expiresAt: n.expiresAt
                    ))
                }
                // Everything is on screen (the @State list holds the items): COMMIT, off
                // main, and finish it before the next poll of this group starts. NEVER
                // commit from a scenePhase/teardown path — an uncommitted drain is what
                // protects the message across a lock.
                if let drain, !drain.isEmpty { await appState.commitDrain(drain) }
                // Rosters may have been applied during the poll.
                refreshHeader()
                // First successful fetch: hold "Consulting…" then reveal the
                // verdict (mirrors the 1:1 screen). Only when the relay is up.
                if !verdictShown && appState.isRelayReachable {
                    verdictShown = true
                    let foundAny = !messages.isEmpty
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
                        // state set meanwhile must survive (shared rule; matches 1:1).
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
                messages.removeAll { $0.isScreenshotNotice && $0.expiresAt <= nowMs }
            }
        }
    }
}

// MARK: - Group info (member list + admin membership management)

struct GroupInfoView: View {
    @EnvironmentObject private var appState: AppState
    let groupId: String
    let onDismiss: () -> Void
    let onLeft: () -> Void

    @State private var groupName = ""
    @State private var isAdmin = false
    @State private var members: [MemberDisplay] = []
    @State private var eligibleToAdd: [Candidate] = []
    @State private var working = false
    @State private var showAddPicker = false
    @State private var showLeaveConfirm = false
    @State private var showChooseAdmin = false
    @State private var actionMember: MemberDisplay? = nil
    // Surfaced when the admin-handoff write fails
    // so we do NOT leave into a permanently unmanageable (no-admin) group.
    @State private var transferFailed = false

    struct MemberDisplay: Identifiable {
        let id: String          // memberId
        let contactId: String?
        let alias: String
        let mnemonic: String    // the user's PRIVATE memory of who this is ("" if none)
        let isSelf: Bool
        let isAdmin: Bool
        let resolved: Bool
    }

    struct Candidate: Identifiable {
        let id: String          // contactId
        let alias: String
    }

    var body: some View {
        NavigationStack {
            ZStack {
                Color.runBackground.ignoresSafeArea()

                VStack(spacing: 0) {
                    memberSection

                    Button {
                        // An admin must hand the role to someone before leaving
                        // (else nobody can ever change the member list). Force the
                        // choice when there's an eligible successor; if there's
                        // none reachable, fall back to the plain confirm.
                        let eligible = members.contains { !$0.isSelf && $0.resolved }
                        if isAdmin && eligible { showChooseAdmin = true }
                        else { showLeaveConfirm = true }
                    } label: {
                        Text(L10n.groupInfoLeaveGroup)
                            .font(.runeHeadline)
                            .foregroundColor(.red)
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 14)
                            .background(Color.runSurface)
                            .cornerRadius(12)
                            .padding(.horizontal)
                    }
                    .disabled(working)
                    .accessibilityIdentifier("group_info_leave_button")
                    .padding(.bottom, 12)
                }
            }
            .navigationTitle(groupName)
            .navigationBarTitleDisplayMode(.inline)
            .runNavigationBarChrome()
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button(L10n.commonDone) { onDismiss() }
                        .foregroundColor(Color.runTextPrimary)
                        .accessibilityIdentifier("group_info_back")
                }
            }
            .onAppear { reload() }
            // Member actions (admin only): remove / transfer admin. Transfer
            // is offered only for RESOLVED members — an unreachable admin
            // could never coordinate the group. A Rune menu card (tap-outside
            // dismisses), mirroring Android's member-action overlay.
            .overlay { memberActionOverlay }
            // Unread warning appended on every leave path (see ContactListView's
            // leave dialog): a member who has not read our texts yet drops them on
            // arrival once the leave notice removed us from their roster.
            .runeDialog(isPresented: $showLeaveConfirm, title: L10n.groupInfoLeaveConfirmTitleIos,
                        message: (isAdmin
                            ? L10n.groupInfoLeaveConfirmAdminMessage
                            : L10n.groupInfoLeaveConfirmMessage)
                            + "\n\n" + L10n.groupInfoLeaveUnreadWarning,
                        // Destructive LAST (safety rule — see RuneDialog in UIComponents).
                        actions: [
                            .secondary(L10n.commonCancel) { },
                            RuneDialogAction(L10n.groupInfoLeaveConfirmAction, color: .runeDanger, a11yId: "group_info_leave_confirm") { leave() },
                        ])
            .runeDialog(isPresented: $transferFailed, title: L10n.groupInfoTransferFailedTitle,
                        message: L10n.groupInfoTransferFailedMessage,
                        actions: [RuneDialogAction(L10n.commonOk, a11yId: "group_info_transfer_failed_ok") { }])
            .sheet(isPresented: $showAddPicker) {
                addPicker
            }
            .sheet(isPresented: $showChooseAdmin) {
                chooseAdminPicker
            }
        }
        .preferredColorScheme(.dark)
    }

    /// The scrollable member list: the admin's add-member row, then one row per member.
    private var memberSection: some View {
        ScrollView {
            LazyVStack(spacing: 0) {
                adminActions
                ForEach(members) { member in
                    memberRow(member)
                }
            }
        }
        .accessibilityIdentifier("group_info_member_list")
    }

    /// Admin-only rows above the member list (today: "Add member").
    @ViewBuilder
    private var adminActions: some View {
        if isAdmin {
            Button {
                showAddPicker = true
            } label: {
                HStack(spacing: 12) {
                    Image(systemName: "person.badge.plus")
                        .foregroundColor(Color.runTextPrimary)
                        .frame(width: 40, height: 40)
                        .background(Color.runSurface)
                        .clipShape(Circle())
                    Text(L10n.groupInfoAddMember)
                        .font(.runeBody)
                        .foregroundColor(Color.runTextPrimary)
                    Spacer()
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 10)
                .contentShape(Rectangle())
            }
            .disabled(working)
            .accessibilityIdentifier("add_group_member_button")
        }
    }

    /// The admin's member-action card (make admin / remove), shown over the screen.
    @ViewBuilder
    private var memberActionOverlay: some View {
        if let member = actionMember {
            ZStack {
                Color.black.opacity(0.8)
                    .ignoresSafeArea()
                    .onTapGesture { actionMember = nil }
                RuneCard {
                    Text(member.alias)
                        .font(.runeHeadline)
                        .foregroundColor(.runTextPrimary)
                        .lineLimit(1)
                        .truncationMode(.tail)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.horizontal, 24)
                        .padding(.vertical, 10)
                    if member.resolved {
                        Button {
                            let m = member
                            actionMember = nil
                            transferAdmin(to: m)
                        } label: {
                            Text(L10n.groupInfoMakeAdmin)
                                .font(.runeBody)
                                .foregroundColor(.runTextPrimary)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .padding(.horizontal, 24)
                                .padding(.vertical, 14)
                        }
                        .accessibilityIdentifier("member_action_make_admin")
                    }
                    Button {
                        let m = member
                        actionMember = nil
                        remove(m)
                    } label: {
                        Text(L10n.groupInfoRemoveFromGroup)
                            .font(.runeBody)
                            .foregroundColor(.runError)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(.horizontal, 24)
                            .padding(.vertical, 14)
                    }
                    .accessibilityIdentifier("member_action_remove")
                }
                .padding(48)
            }
        }
    }

    // Admin-leave: pick the successor. Lists resolved members with the user's
    // private mnemonic so they can tell who's who before handing over control.
    private var chooseAdminPicker: some View {
        NavigationStack {
            ZStack {
                Color.runBackground.ignoresSafeArea()
                VStack(spacing: 8) {
                    Text(L10n.groupInfoChooseAdminSubtitleIos)
                        .font(.runeCaption)
                        .foregroundColor(Color.runTextSecondary)
                        .padding(.horizontal)
                        .padding(.top, 12)
                    ScrollView {
                        LazyVStack(spacing: 0) {
                            ForEach(members.filter { !$0.isSelf && $0.resolved }) { member in
                                Button {
                                    chooseAdminAndLeave(member)
                                } label: {
                                    HStack(spacing: 12) {
                                        ZStack {
                                            Circle().fill(Color(hex: 0x5C6BC0)).frame(width: 40, height: 40)
                                            Text(member.alias.prefix(1).uppercased())
                                                .font(.runeHeadline).foregroundColor(.white)
                                        }
                                        VStack(alignment: .leading, spacing: 2) {
                                            Text(member.alias)
                                                .font(.runeBody).foregroundColor(Color.runTextPrimary)
                                                .lineLimit(1).truncationMode(.tail)
                                            if !member.mnemonic.isEmpty {
                                                Text(member.mnemonic)
                                                    .font(.runeCaption2).foregroundColor(Color.runTextSecondary)
                                                    .lineLimit(2)
                                                    .accessibilityIdentifier("choose_admin_mnemonic_\(member.id)")
                                            }
                                        }
                                        Spacer()
                                    }
                                    .padding(.horizontal, 16).padding(.vertical, 12)
                                    .contentShape(Rectangle())
                                }
                                .disabled(working)
                                .accessibilityIdentifier("choose_admin_row_\(member.id)")
                            }
                        }
                    }
                }
            }
            .navigationTitle(L10n.groupInfoChooseAdminNavTitle)
            .navigationBarTitleDisplayMode(.inline)
            .runNavigationBarChrome()
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button(L10n.commonCancel) { showChooseAdmin = false }
                        .foregroundColor(Color.runTextPrimary)
                }
            }
        }
        .coveredDarkSheet()
    }

    @ViewBuilder
    private func memberRow(_ member: MemberDisplay) -> some View {
        Button {
            // Only the admin gets member actions, never on their own row.
            if isAdmin && !member.isSelf && !working { actionMember = member }
        } label: {
            HStack(spacing: 12) {
                ZStack {
                    Circle()
                        .fill(member.resolved ? Color(hex: 0x5C6BC0) : Color.runSurface)
                        .frame(width: 40, height: 40)
                    Text(member.resolved ? member.alias.prefix(1).uppercased() : "?")
                        .font(.runeHeadline)
                        .foregroundColor(.white)
                }
                VStack(alignment: .leading, spacing: 2) {
                    Text(member.alias)
                        .font(.runeBody)
                        .foregroundColor(member.resolved ? Color.runTextPrimary : Color.runTextSecondary)
                        .lineLimit(1)
                        .truncationMode(.tail)
                    if !member.resolved {
                        Text(L10n.groupInfoNoVerifiedPairing)
                            .font(.runeCaption2)
                            .foregroundColor(Color.runTextSecondary)
                    } else if !member.mnemonic.isEmpty {
                        // The user's own private memory of who this member is —
                        // vault-local, never sent anywhere; shown here because
                        // aliases are pseudonyms and a group is exactly where
                        // you need to remember who's who.
                        Text(member.mnemonic)
                            .font(.runeCaption2)
                            .foregroundColor(Color.runTextSecondary)
                            .lineLimit(2)
                            .accessibilityIdentifier("group_member_mnemonic_\(member.id)")
                    }
                }
                Spacer()
                if member.isAdmin {
                    Text(L10n.groupInfoAdminBadge)
                        .font(.runeCaption)
                        .foregroundColor(Color.runTextPrimary)
                        .padding(.horizontal, 10)
                        .padding(.vertical, 4)
                        .background(Color.runSurface)
                        .cornerRadius(6)
                        .accessibilityIdentifier("group_admin_badge_\(member.id)")
                }
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 10)
            .contentShape(Rectangle())
        }
        .accessibilityIdentifier("group_member_info_row_\(member.id)")
    }

    private var addPicker: some View {
        NavigationStack {
            ZStack {
                Color.runBackground.ignoresSafeArea()
                VStack(spacing: 8) {
                    Text(L10n.groupInfoAddMemberPrecondition)
                        .font(.runeCaption)
                        .foregroundColor(Color.runTextSecondary)
                        .padding(.horizontal)
                        .padding(.top, 12)
                    if eligibleToAdd.isEmpty {
                        Text(L10n.groupInfoAddMemberEmpty)
                            .font(.runeBody)
                            .foregroundColor(Color.runTextSecondary)
                            .multilineTextAlignment(.center)
                            .padding(24)
                            .accessibilityIdentifier("add_member_empty_state")
                        Spacer()
                    } else {
                        ScrollView {
                            LazyVStack(spacing: 0) {
                                ForEach(eligibleToAdd) { candidate in
                                    Button {
                                        showAddPicker = false
                                        add(candidate)
                                    } label: {
                                        HStack {
                                            Text(candidate.alias)
                                                .font(.runeBody)
                                                .foregroundColor(Color.runTextPrimary)
                                                .lineLimit(1)
                                                .truncationMode(.tail)
                                            Spacer()
                                        }
                                        .padding(.horizontal, 16)
                                        .padding(.vertical, 12)
                                        .contentShape(Rectangle())
                                    }
                                    .accessibilityIdentifier("add_member_row_\(candidate.id)")
                                }
                            }
                        }
                    }
                }
            }
            .navigationTitle(L10n.groupInfoAddMember)
            .navigationBarTitleDisplayMode(.inline)
            .runNavigationBarChrome()
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button(L10n.commonCancel) { showAddPicker = false }
                        .foregroundColor(Color.runTextPrimary)
                }
            }
        }
        .coveredDarkSheet()
    }

    // MARK: logic

    private func reload() {
        guard let vault = appState.vault else { return }
        guard let group = vault.getGroup(groupId: groupId) else {
            // Left or removed while the sheet was open.
            onLeft()
            return
        }
        groupName = group.name
        isAdmin = group.isAdmin
        let rows = vault.getGroupMembers(groupId: groupId)
        members = rows.map { m in
            let isSelf = m.memberId == group.myMemberId
            // getContact() carries a raw sharedSecret;
            // project alias/mnemonic/resolved into locals, THEN wipe — never let
            // the record (or its secret) escape this scope.
            let contact = m.contactId.flatMap { vault.getContact(contactId: $0) }
            let alias = isSelf ? L10n.groupInfoYou : (contact?.alias ?? L10n.groupInfoNotReachable)
            let mnemonic = contact?.mnemonic ?? ""
            let resolved = isSelf || contact != nil
            contact?.sharedSecret.secureWipe()
            return MemberDisplay(
                id: m.memberId,
                contactId: m.contactId,
                alias: alias,
                mnemonic: mnemonic,
                isSelf: isSelf,
                isAdmin: m.memberId == group.adminMemberId,
                resolved: resolved
            )
        }.sorted { a, b in
            if a.isSelf != b.isSelf { return a.isSelf }
            if a.isAdmin != b.isAdmin { return a.isAdmin }
            return a.alias < b.alias
        }
        let memberContactIds = Set(rows.compactMap { $0.contactId })
        // Wipe the UNFILTERED source list —
        // the filtered-out records (the group's own members) still carry a
        // live sharedSecret. Mirrors Android's GroupInfoScreen.kt.
        let allContacts = vault.getAllContacts()
        eligibleToAdd = allContacts
            .filter { !memberContactIds.contains($0.contactId) &&
                      MessageManagerKt.contactFullyPaired(vault: vault, contactId: $0.contactId) }
            .map { Candidate(id: $0.contactId, alias: $0.alias) }
        for contact in allContacts { contact.sharedSecret.secureWipe() }
    }

    private func runOp(_ op: @escaping () async -> Void) {
        guard !working else { return }
        working = true
        Task { @MainActor in
            await op()
            working = false
            reload()
        }
    }

    private func add(_ candidate: Candidate) {
        runOp { _ = await appState.addGroupMember(groupId: groupId, contactId: candidate.id) }
    }

    private func remove(_ member: MemberDisplay) {
        actionMember = nil
        runOp { _ = await appState.removeGroupMember(groupId: groupId, memberId: member.id) }
    }

    private func transferAdmin(to member: MemberDisplay) {
        actionMember = nil
        runOp { _ = await appState.transferGroupAdmin(groupId: groupId, newAdminMemberId: member.id) }
    }

    private func leave() {
        guard !working else { return }
        working = true
        Task { @MainActor in
            await appState.leaveGroup(groupId: groupId)
            working = false
            onLeft()
        }
    }

    /// Admin handoff + leave: transfer the role FIRST (must persist while we're
    /// still admin and the group still exists locally), then leave.
    ///
    /// The transfer's success MUST gate the leave.
    /// transferGroupAdmin returns false when the vault write fails (GroupManager
    /// .transferAdmin: insertGroup throws, "transferAdmin persist failed") — and
    /// on that path NO new roster is broadcast, so no peer ever learns of a new
    /// admin. If we left anyway, every remaining member's stored adminMemberId
    /// would keep pointing at us (now departed) and nobody would be flagged admin
    /// (their handleLeave only re-rosters when the RECEIVER is admin) — the exact
    /// frozen, no-admin state this two-step flow exists to prevent. So on failure
    /// we DON'T leave: we stay admin locally (fail-closed), tell the user, and let
    /// them retry. Shared-layer gap (out of scope here): GroupManager itself does
    /// not retry/rollback the transfer, and the Android caller only handles the
    /// thrown-exception case, not the false return — both should mirror this gate.
    private func chooseAdminAndLeave(_ member: MemberDisplay) {
        guard !working else { return }
        working = true
        showChooseAdmin = false
        Task { @MainActor in
            let transferred = await appState.transferGroupAdmin(groupId: groupId, newAdminMemberId: member.id)
            guard transferred else {
                // Fail-closed: keep the admin role local, surface the error, don't leave.
                working = false
                reload()
                transferFailed = true
                return
            }
            await appState.leaveGroup(groupId: groupId)
            working = false
            onLeft()
        }
    }
}

// MARK: - Group bubble

/// NO-PARK: a PRIVATE (received) or PRIVATE_SENT bubble — a 1:1 text shown in the
/// group screen, visible only to us. Distinct colour family + padlock + label.
/// The sent side's delivery mark deliberately carries NO `group_delivery_status`
/// id (e2e reads the LAST of those for the group fan-out).
private struct PrivateBubble: View {
    let message: GroupConversationView.GroupChatMessage
    let onReply: () -> Void

    private var sent: Bool { message.kind == .privateSent }

    var body: some View {
        HStack {
            if sent { Spacer(minLength: 60) }
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 5) {
                    Image(systemName: "lock.fill")
                        .font(.system(size: 10))
                        .foregroundColor(Color.runPrivateAccent)
                    if sent {
                        Text(L10n.groupPrivateTo(message.senderAlias))
                            .font(.runeCaption2)
                            .foregroundColor(Color.runPrivateAccent)
                    } else {
                        Text(L10n.groupPrivateFrom(message.senderAlias))
                            .font(.runeCaption2)
                            .foregroundColor(Color.runPrivateAccent)
                            .accessibilityIdentifier("group_private_label")
                    }
                }
                Text(message.text)
                    .font(.runeBody)
                    .foregroundColor(.white)
                HStack(spacing: 8) {
                    if !sent {
                        Button(action: onReply) {
                            Text(L10n.groupPrivateReply)
                                .font(.runeCaption)
                                .foregroundColor(Color.runPrivateAccent)
                        }
                        .buttonStyle(.plain)
                        .accessibilityIdentifier("group_private_reply")
                    }
                    Spacer(minLength: 0)
                    if message.timestamp > 0 {
                        Text(markedBubbleTime(message.timestamp))
                            .font(.system(size: 9))
                            .foregroundColor(Color(hex: 0x666666))
                    }
                    if sent {
                        Text(message.delivered == 1 ? "✓" : "·")
                            .font(.runeCaption2)
                            .foregroundColor(Color.runTextSecondary)
                    }
                }
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 10)
            .background(sent ? Color.runPrivateBubbleSent : Color.runPrivateBubble)
            .clipShape(RoundedRectangle(cornerRadius: 18))
            .accessibilityElement(children: .contain)
            .accessibilityIdentifier(sent ? "group_private_sent_bubble" : "group_private_bubble")
            if !sent { Spacer(minLength: 60) }
        }
    }
}

private struct GroupBubble: View {
    let message: GroupConversationView.GroupChatMessage

    private static let senderColors: [Color] = [
        Color(hex: 0x5C6BC0), Color(hex: 0x26A69A), Color(hex: 0xEF5350),
        Color(hex: 0xAB47BC), Color(hex: 0x42A5F5), Color(hex: 0xFF7043),
        Color(hex: 0x66BB6A), Color(hex: 0xEC407A), Color(hex: 0x8D6E63),
        Color(hex: 0x78909C),
    ]

    var body: some View {
        if message.isScreenshotNotice {
            // Same centered/muted style as a system notice, but a DISTINCT a11y
            // id so e2e can target it specifically (see drainScreenshotNotices).
            Text(message.text)
                .font(.runeCaption)
                .foregroundColor(Color.runTextSecondary)
                .frame(maxWidth: .infinity, alignment: .center)
                .padding(.vertical, 4)
                .accessibilityIdentifier("screenshot_notice_group")
        } else if message.isSystem {
            // Centered, muted system notice — no bubble, no avatar/attribution.
            Text(message.text)
                .font(.runeCaption)
                .foregroundColor(Color.runTextSecondary)
                .frame(maxWidth: .infinity, alignment: .center)
                .padding(.vertical, 4)
                .accessibilityIdentifier("group_system_message")
        } else {
            bubble
        }
    }

    private var bubble: some View {
        HStack {
            if message.isSent { Spacer(minLength: 60) }

            VStack(alignment: message.isSent ? .trailing : .leading, spacing: 4) {
                VStack(alignment: .leading, spacing: 2) {
                    if !message.isSent {
                        Text(message.senderAlias)
                            .font(.runeCaption2)
                            .foregroundColor(senderColor)
                    }
                    Text(message.text)
                        .font(.runeBody)
                        .foregroundColor(.white)
                }
                .padding(.horizontal, 14)
                .padding(.vertical, 10)
                .background(message.isSent ? Color.runSentBubble : Color.runReceivedBubble)
                .clipShape(RoundedRectangle(cornerRadius: 18))
                .accessibilityIdentifier(message.isSent ? "group_bubble_sent" : "group_bubble_received")

                HStack(spacing: 4) {
                    if !message.membershipOk {
                        Text(L10n.groupMemberListDiffers)
                            .font(.system(size: 9))
                            .foregroundColor(.red)
                    }
                    if message.timestamp > 0 {
                        Text(Self.formatTime(message.timestamp))
                            .font(.system(size: 9))
                            .foregroundColor(Color(hex: 0x666666))
                    }
                    if message.isSent {
                        deliveryMark
                    }
                }
                .padding(.horizontal, 4)
            }

            if !message.isSent { Spacer(minLength: 60) }
        }
    }

    // e2e: every branch below carries the SAME a11y id — the indicator's text
    // IS the state ("·" pending / "✓" all delivered / "d/t" partial), so tests
    // read the label of the LAST group_delivery_status element. Id must stay
    // byte-identical to the Android testTag (GroupConversationScreen.kt).
    @ViewBuilder
    private var deliveryMark: some View {
        if let delivered = message.delivered, let total = message.total {
            let undelivered = (total - delivered) + (message.unreachable ?? 0)
            if undelivered > 0 {
                // Refused copies + members with no resolved contact (no retry, no
                // backfill) — surfaced honestly, in words.
                Text(L10n.groupDeliveryNotDelivered(Int(undelivered))).font(.runeCaption2).foregroundColor(.red)
                    .accessibilityIdentifier("group_delivery_status")
            } else if total > 0 {
                Text("✓").font(.runeCaption2).foregroundColor(Color.runTextSecondary)
                    .accessibilityIdentifier("group_delivery_status")
            } else {
                // Nobody addressable (0/0).
                Text("\(delivered)/\(total)").font(.runeCaption2).foregroundColor(.red)
                    .accessibilityIdentifier("group_delivery_status")
            }
        } else {
            Text("·").font(.runeCaption2).foregroundColor(Color.runTextSecondary)
                .accessibilityIdentifier("group_delivery_status")
        }
    }

    private var senderColor: Color {
        let idx = avatarColorIndex(message.senderContactId, count: Self.senderColors.count)
        return Self.senderColors[idx]
    }

    private static func formatTime(_ millis: Int64) -> String {
        let date = Date(timeIntervalSince1970: Double(millis) / 1000.0)
        let fmt = DateFormatter()
        fmt.timeStyle = .short
        fmt.dateStyle = .none
        return fmt.string(from: date)
    }
}

// Screenshot-notice display time: locale-appropriate short time for a capture
// today, "Yesterday <time>" when the calendar day differs — the notice's 24h
// TTL means "differs" can only ever mean yesterday, never further back.
// File-scope (not nested in GroupBubble) so GroupConversationView.startPolling()
// can precompute the full notice string once, on append — mirrors
// ConversationView.swift.
fileprivate func formatNoticeTime(_ millis: Int64) -> String {
    let date = Date(timeIntervalSince1970: Double(millis) / 1000.0)
    let fmt = DateFormatter()
    fmt.timeStyle = .short
    fmt.dateStyle = .none
    let sameDay = Calendar.current.isDate(date, inSameDayAs: Date())
    let time = fmt.string(from: date)
    return sameDay ? time : L10n.commonTimeYesterday(time)
}

import SwiftUI
import UIKit
import Combine
@preconcurrency import shared

// ---------------------------------------------------------------------------
// AppState+Conversations.swift — conversation I/O: the 1:1 send loop and the
// send / delete-contact / reset-relay-access API, the RETRIEVE-ACK pending drains
// (1:1 and group), the group unread refresh, the screenshot-notice surfaces, and
// the Groups API (create / poll / send / read / leave / members / admin / invites).
// Only the stored `redrivenMessageIds` set stays in AppState.swift (extensions
// cannot add stored properties).
// Extension members of the @MainActor AppState class stay main-actor isolated.
// The androidApp source guards read AppState.swift + every AppState+*.swift
// together (SourceScan.kt `iosAppStateSources()`), so their whole-file checks
// keep covering this code.
// ---------------------------------------------------------------------------

extension AppState {
    // MARK: - Messaging (1:1 send, delete, reset relay access)

    /// One send attempt, classified (SendOutcome: SENT / TRANSPORT_FAILED / FAILED).
    /// [redriveToken] = the UI bubble id: a transport-class failure under it is
    /// PARKED (TransportFailedSends, 15 min, RAM-only) for the transport-back
    /// re-drive, a later success under it un-parks, and the same id on every
    /// attempt upserts the one entry. No transport at all (Tor up, manager not
    /// wired yet) parks directly, exactly like Android's
    /// sendMessageInBackground `messageManager == null` branch. nil token = the
    /// old never-parks contract.
    ///
    /// [sessionEpoch] = `TransportFailedSends.shared.sessionEpoch` captured by the
    /// CALLER when the user tapped Send (before its `Task {`): a send loop that
    /// outlives a lock / wipe must not re-park its plaintext + contactId into the
    /// ledger after the lock's endSession() — the epoch-carrying `record` refuses an
    /// epoch that has ended (Android: sendMessageInBackground's captured epoch).
    func sendMessage(contactId: String, text: String, redriveToken: String? = nil, sessionEpoch: Int64) async -> SendOutcome {
        let msgManager = controller.messageManager
        // Fires on the re-drive's (Kotlin Default) thread — hop before touching
        // the @Published set.
        let onRedriven: (() -> Void)? = redriveToken.map { token in
            { [weak self] in hopToMain { self?.redrivenMessageIds.insert(token) } }
        }
        return await Task.detached(priority: .userInitiated) { () -> SendOutcome in
            guard let msgManager else {
                if let redriveToken {
                    TransportFailedSends.companion.shared.record(
                        token: redriveToken, contactId: contactId, plaintext: text,
                        noPush: false, onRedriven: onRedriven, sessionEpoch: sessionEpoch)
                    return SendOutcome.transportFailed
                }
                return SendOutcome.failed
            }
            // noPush: false — today's behavior (relay pushes iff the peer's
            // destination inbox has a registered token; docs/RELAY_SPEC.md (push)).
            return msgManager.sendMessageWithOutcome(
                contactId: contactId, plaintext: text, noPush: false,
                redriveToken: redriveToken, onRedriven: onRedriven)
        }.value
    }

    /// True while the session a send started in is still the live one: the vault
    /// is unlocked AND no lock / wipe has bumped the TransportFailedSends epoch
    /// since [sendEpoch] was captured (Android: RunViewModel.sessionStillCurrent).
    /// Send loops check it before every attempt and before their epilogue's
    /// contactId-keyed writes.
    func isSendSessionCurrent(_ sendEpoch: Int64) -> Bool {
        isUnlocked && TransportFailedSends.companion.shared.sessionEpoch == sendEpoch
    }

    /// Positive evidence only (MessageManager.noteTransportLost — never a probe
    /// miss): true once the live transport is known dead, so a 3-attempt send loop
    /// stops after the attempt in flight and leaves the parked send to the re-drive.
    func isTransportLost() -> Bool {
        controller.messageManager?.isTransportLost() ?? false
    }

    /// How a 1:1 delivery loop ended. `.sessionEnded`: a lock / wipe ended the session
    /// the send started in, so the caller must write nothing back. `.cancelled`: the
    /// caller's Task was cancelled between attempts.
    enum DirectSendLoopResult { case delivered, failed, sessionEnded, cancelled }

    static let directSendMaxAttempts = 3

    /// THE 1:1 delivery loop, shared by ConversationView's composer and the group
    /// screen's private reply (Android: RunViewModel.sendMessageInBackground, which its
    /// private reply also uses). The ratchet-refusal gate comes first (P1-1 step B: a
    /// durable role-collision refusal makes ZERO HTTP attempts). Then up to
    /// [directSendMaxAttempts] attempts with a random 1–5 s backoff that hides retry
    /// cadence from a network observer. It stops early on a landed re-drive (a further
    /// attempt would be a duplicate) or on positive transport-death evidence (never a
    /// probe miss: the parked send waits for the transport-back re-drive). Every
    /// attempt re-checks [isSendSessionCurrent]. No epilogue: the flag refreshes and
    /// bubble updates stay with the caller. [redriveToken] = the UI bubble id (see
    /// [sendMessage]); [logTag] / [what] only word the log lines (counts only, never
    /// an identifier).
    func runDirectSendLoop(contactId: String, text: String, redriveToken: String,
                           sessionEpoch: Int64, logTag: String, what: String) async -> DirectSendLoopResult {
        let maxRetries = AppState.directSendMaxAttempts
        if controller.ratchetRefused(contactId: contactId) {
            LogBuffer.shared.append(level: "W", tag: logTag,
                message: "\(what) refused — secure channel not established, 0 attempts made")
            return .failed
        }
        for attempt in 1...maxRetries {
            if Task.isCancelled { return .cancelled }
            guard isSendSessionCurrent(sessionEpoch) else { return .sessionEnded }
            // A transport-back re-drive landed the parked attempt during the
            // backoff: delivered, and another attempt would be a duplicate.
            if redrivenMessageIds.contains(redriveToken) { return .delivered }
            // The same token on every attempt ⇒ one ledger entry; the bubble flips
            // through redrivenMessageIds if the re-drive lands it.
            let outcome = await sendMessage(contactId: contactId, text: text,
                                            redriveToken: redriveToken, sessionEpoch: sessionEpoch)
            if outcome == SendOutcome.sent { return .delivered }
            LogBuffer.shared.append(level: "W", tag: logTag,
                message: "\(what) attempt \(attempt)/\(maxRetries) failed")
            if outcome == SendOutcome.transportFailed, isTransportLost() {
                LogBuffer.shared.append(level: "W", tag: logTag,
                    message: "\(what) loop stopped after \(attempt) attempt(s) — transport known down, parked for the transport-back re-drive")
                break
            }
            if attempt < maxRetries {
                let delaySeconds = 1.0 + Double.random(in: 0...4.0)
                try? await Task.sleep(nanoseconds: UInt64(delaySeconds * 1_000_000_000))
            }
        }
        return .failed
    }

    /// NO-PARK (2026-10-06): a private reply from a GROUP screen to one member — the
    /// EXISTING 1:1 send (no new wire format) through [runDirectSendLoop], then the
    /// same post-send flag refreshes as the 1:1 screen. True = the relay accepted it.
    /// [sessionEpoch]: captured at tap time by the caller, exactly as for
    /// [sendMessage]; once the session it started in has ended the refreshes are
    /// skipped, so a lock / wipe mid-backoff neither re-parks the reply nor re-plants
    /// the contactId into the notice maps.
    func sendPrivateReply(contactId: String, text: String, redriveToken: String, sessionEpoch: Int64) async -> Bool {
        let result = await runDirectSendLoop(contactId: contactId, text: text, redriveToken: redriveToken,
                                             sessionEpoch: sessionEpoch, logTag: "GroupChat", what: "private reply")
        guard result != .sessionEnded, isSendSessionCurrent(sessionEpoch) else { return false }
        refreshForwardSecrecyStalled(contactId: contactId)
        refreshRatchetRefused(contactId: contactId)
        return result == .delivered
    }

    /// Delete a contact locally AND best-effort DELETE its two inbound
    /// inboxes on the relay (caps snapshotted before the rows go), so a deleted
    /// contact doesn't leave live, drainable inboxes parked on the relay. The
    /// local delete is never gated on Tor — the returned Bool reports IT, and the
    /// relay cleanup runs detached behind the row already disappearing. Mirrors
    /// Android's RunViewModel.deleteContactInBackground.
    func deleteContactPurgingRelay(contactId: String) async -> Bool {
        let controller = self.controller
        return await Task.detached(priority: .userInitiated) {
            controller.deleteContactAndPurgeRelay(contactId: contactId)
        }.value
    }

    /// "Reset relay access": rotates the READ capability on both of this
    /// contact's inbound inboxes, so a vault copied while the phone was unlocked
    /// stops granting remote drain / delete / rotate / push-register rights.
    /// Non-destructive. A false result is "not proven done", never data loss: the
    /// durable pending marker survives and the control poll reconciles it.
    func resetRelayAccess(contactId: String) async -> Bool {
        let controller = self.controller
        return await Task.detached(priority: .userInitiated) {
            controller.resetRelayAccess(contactId: contactId)
        }.value
    }

    // MARK: - Pending drains, screenshot notices, Groups API

    /// The 1:1 conversation poll — RETRIEVE-ACK (2026-11-03). Decrypts this contact's
    /// text inbox and group inbox WITHOUT persisting or acking and returns the
    /// uncommitted [PendingDrain] (nil if there is no GroupManager yet). The screen
    /// appends `messages` to its list and THEN calls [commitDrain]; if the messages
    /// will not be shown it calls [abandonDrain] (dropping it is also safe: the relay
    /// re-delivers after its lease). Parked items come first in `messages` and leave
    /// the buffer only on commit. A group text drained alongside is a GROUP_ECHO item
    /// (NO-PARK, 2026-10-06).
    func pollDirectPending(contactId: String) async -> PendingDrain<DirectItem>? {
        let groupManager = controller.groupManager
        // Establish the Block set on this ON-DEMAND path too, so an
        // early conversation open (before the background loop's first tick, ~3–7 s
        // post-unlock) doesn't poll a blocked contact's inbox unfiltered.
        groupManager?.blockedContacts = { BlockStore.blocked() }
        return await Task.detached(priority: .background) {
            groupManager?.pollDirectPending(contactId: contactId)
        }.value
    }

    /// RETRIEVE-ACK: the screen's items are on screen — persist the ratchet /
    /// anti-replay state and fire the (never awaited) ack. Runs OFF main (vault
    /// write) and is awaited by the caller before the next poll of the same
    /// conversation. NEVER call this from a teardown / scenePhase path: an
    /// uncommitted drain is exactly what protects the message across a lock.
    func commitDrain<T: AnyObject>(_ drain: PendingDrain<T>) async {
        await Task.detached(priority: .userInitiated) { drain.commit() }.value
    }

    /// RETRIEVE-ACK: the drain's messages will never be shown — roll it back (off main).
    func abandonDrain<T: AnyObject>(_ drain: PendingDrain<T>) {
        Task.detached(priority: .utility) { drain.abandon() }
    }

    /// NO-PARK: a screen just took a GROUP_ECHO item, i.e. a group text was shown in
    /// a 1:1 (or another group). The shared count already gave that unit back
    /// (GroupUnreadTally.shownElsewhere via GroupManager), but the published map only refreshed
    /// on the control loop's next cycle (60–90 s idle), so the group row kept a dot
    /// with nothing behind it. Republish now. Off-main: groupUnreadCounts can read
    /// the vault.
    func refreshGroupUnreadCounts() {
        guard let gm = controller.groupManager else { return }
        Task.detached(priority: .utility) { [weak self] in
            var counts: [String: Int] = [:]
            for (k, v) in gm.groupUnreadCounts() {
                counts[k] = (v as? Int) ?? ((v as? NSNumber)?.intValue ?? 0)
            }
            await MainActor.run {
                guard let self, self.isUnlocked else { return }
                if self.groupUnreadCounts != counts { self.groupUnreadCounts = counts }
            }
        }
    }

    /// THE RECEIVE SURFACE for a "screenshot taken" notice bubble — shared by
    /// both the 1:1 and group conversation screens (`conversationId` is a
    /// contactId or a groupId respectively; see
    /// GroupManager.drainScreenshotNotices). Destructive: a drained notice
    /// renders once. Resolves the sender's alias from the vault, so — like
    /// [pollMessages]/[pollGroup] — this hops off the main thread.
    func drainScreenshotNotices(conversationId: String) async -> [ScreenshotNotice] {
        let gm = controller.groupManager
        return await Task.detached(priority: .background) {
            gm?.drainScreenshotNotices(conversationId: conversationId) as? [ScreenshotNotice] ?? []
        }.value
    }

    /// THE LOAD-ON-OPEN SURFACE (docs/screenshot-notice-persistence-design.md
    /// §0/§6) — every UNEXPIRED persisted notice for one conversation, oldest
    /// first, non-destructive. Call ONCE when a conversation screen opens,
    /// BEFORE the poll loop starts; [drainScreenshotNotices] then appends only
    /// newly-arrived notices on each subsequent tick. Same background hop as
    /// [drainScreenshotNotices] — it resolves the sender's alias from the vault.
    func loadScreenshotNotices(conversationId: String) async -> [ScreenshotNotice] {
        let gm = controller.groupManager
        return await Task.detached(priority: .background) {
            gm?.screenshotNotices(conversationId: conversationId) as? [ScreenshotNotice] ?? []
        }.value
    }

    // -----------------------------------------------------------------------
    // Groups — see GroupManager (shared) for the protocol & security model.
    // All calls hop off the main thread: they do crypto, vault I/O, and
    // jittered fan-out network sends.
    // -----------------------------------------------------------------------

    func createGroup(name: String, memberContactIds: [String]) async -> String? {
        let gm = controller.groupManager
        return await Task.detached(priority: .userInitiated) {
            gm?.createGroup(name: name, memberContactIds: memberContactIds)
        }.value
    }

    /// The group conversation poll — RETRIEVE-ACK (2026-11-03). The fan-out (members'
    /// GETs concurrent, GROUP-FANOUT) decrypts WITHOUT persisting or acking and
    /// returns the uncommitted [PendingDrain] (nil if there is no GroupManager yet).
    /// Same contract as [pollDirectPending]: append, then [commitDrain]; [abandonDrain]
    /// if the result will not be shown. Carries the group's own texts plus PRIVATE
    /// (1:1) and GROUP_ECHO (other group) items.
    func pollGroupPending(groupId: String) async -> PendingDrain<GroupMessage>? {
        let gm = controller.groupManager
        // Opening a group with a blocked co-member must not poll
        // their inbox — set the Block set on this on-demand path (the background loop
        // may not have run yet). GroupManager then skips blocked members.
        gm?.blockedContacts = { BlockStore.blocked() }
        return await Task.detached(priority: .background) {
            gm?.pollGroupPending(groupId: groupId)
        }.value
    }

    /// NO-PARK: another group's echoed text no longer counts on its row. Call after
    /// appending a drain's items.
    func noteShownGroupEchoes(_ items: [GroupMessage]) {
        if items.contains(where: { $0.isGroupEcho }) { refreshGroupUnreadCounts() }
    }

    /// NO-PARK (1:1 twin of [noteShownGroupEchoes]).
    func noteShownDirectEchoes(_ items: [DirectItem]) {
        if items.contains(where: { $0.isGroupEcho }) { refreshGroupUnreadCounts() }
    }

    func sendGroupMessage(groupId: String, text: String) async -> GroupSendResult? {
        let gm = controller.groupManager
        return await Task.detached(priority: .userInitiated) {
            gm?.sendGroupMessage(groupId: groupId, text: text)
        }.value
    }

    /// Clears a contact's unread badge the instant its conversation opens.
    /// The conversation poll drains the relay queue, so the next /peek sweep
    /// would clear it anyway — this just removes the poll-cycle lag.
    @MainActor
    func markContactRead(_ contactId: String) {
        unreadCounts.removeValue(forKey: contactId)
    }

    /// Clears a group's unread dot the instant its conversation opens. pollGroup
    /// also clears it shared-side; this removes the poll-cycle lag in the UI.
    @MainActor
    func markGroupRead(_ groupId: String) {
        groupUnreadCounts.removeValue(forKey: groupId)
        controller.groupManager?.markGroupRead(groupId: groupId)
    }

    func leaveGroup(groupId: String) async {
        let gm = controller.groupManager
        await Task.detached(priority: .userInitiated) {
            // onLocalDelete fires the instant the group is gone from the
            // vault — the contact list refreshes immediately while the
            // best-effort leave notices keep fanning out (seconds per
            // member over Tor) inside this detached task.
            gm?.leaveGroup(groupId: groupId, onLocalDelete: {
                DispatchQueue.main.async {
                    NotificationCenter.default.post(name: .contactsChanged, object: nil)
                }
            })
        }.value
    }

    func addGroupMember(groupId: String, contactId: String) async -> Bool {
        let gm = controller.groupManager
        return await Task.detached(priority: .userInitiated) {
            gm?.addMember(groupId: groupId, contactId: contactId) ?? false
        }.value
    }

    func removeGroupMember(groupId: String, memberId: String) async -> Bool {
        let gm = controller.groupManager
        return await Task.detached(priority: .userInitiated) {
            gm?.removeMember(groupId: groupId, memberId: memberId) ?? false
        }.value
    }

    func transferGroupAdmin(groupId: String, newAdminMemberId: String) async -> Bool {
        let gm = controller.groupManager
        return await Task.detached(priority: .userInitiated) {
            gm?.transferAdmin(groupId: groupId, newAdminMemberId: newAdminMemberId) ?? false
        }.value
    }

    // --- GROUP-1 consent gate: group invites awaiting accept/decline ---

    /// Invites parked awaiting the user's decision (polled by the contact list).
    func pendingGroupInvites() -> [GroupInvite] {
        controller.groupManager?.pendingInvites() ?? []
    }

    /// "Later" on a group invite: the dialog closes without deciding, the invite
    /// stays pending, and the consent surface stops auto-presenting it this
    /// session (GroupInvitePresentation.kt in commonMain is the shared rule).
    func deferGroupInvite(groupId: String) {
        deferredGroupInviteIds.insert(groupId)
    }

    /// Drops deferred ids whose invite is no longer pending (a re-invite then
    /// presents afresh). Call only after a successful pending-list read.
    func pruneDeferredGroupInvites(pendingIds: [String]) {
        deferredGroupInviteIds = GroupInvitePresentation.shared.pruneDeferred(
            pendingIds: pendingIds, deferredIds: deferredGroupInviteIds)
    }

    /// "Later" on a referral offer: the dialog closes without deciding, the offer
    /// stays pending and is not auto-presented again this session (same shared rule
    /// as group invites: GroupInvitePresentation.kt).
    func deferReferralOffer(introId: String) {
        deferredReferralOfferIds.insert(introId)
    }

    /// Approve un-defers first so a failed accept re-presents as Retry.
    func undeferReferralOffer(introId: String) {
        deferredReferralOfferIds.remove(introId)
    }

    /// Drops deferred introIds whose offer is no longer pending. Call only after a
    /// successful pending-list read.
    func pruneDeferredReferralOffers(pendingIds: [String]) {
        deferredReferralOfferIds = GroupInvitePresentation.shared.pruneDeferred(
            pendingIds: pendingIds, deferredIds: deferredReferralOfferIds)
    }

    /// Accept a parked group invite: persists the group + members and fans out
    /// our KIND_JOIN (disclosing our group tag) — off the main thread, as it
    /// does vault writes + a network fan-out.
    func acceptGroupInvite(groupId: String) async -> Bool {
        let gm = controller.groupManager
        let ok = await Task.detached(priority: .userInitiated) {
            gm?.acceptInvite(groupId: groupId) ?? false
        }.value
        NotificationCenter.default.post(name: .contactsChanged, object: nil)
        return ok
    }

    /// Decline a parked group invite: persists a decline tombstone (a vault
    /// write) via `putMeta` — off the main thread, mirroring acceptGroupInvite
    /// above. Fire-and-forget from the caller's perspective (the dialog
    /// dismisses immediately on tap); the tombstone write finishes on the
    /// detached task.
    func declineGroupInvite(groupId: String) {
        let gm = controller.groupManager
        Task.detached(priority: .userInitiated) {
            gm?.declineInvite(groupId: groupId)
        }
    }
}

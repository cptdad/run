package com.vg.run

// ---------------------------------------------------------------------------
// The per-contact / per-group `_meta` PURGE lists both VaultDatabase actuals
// (`DatabaseManager`, `IosVaultDatabase`) and the commonTest InMemoryVault iterate
// on deleteContact / deleteGroup: the exact-key [ratchetMetaKeysForContact] and
// the residue classifiers. Any new per-contact / per-group `_meta` key MUST be
// added here, or it leaks across a delete / re-pair. (Moved verbatim out of
// MessageManager.kt, 2026-11-06.)
// ---------------------------------------------------------------------------

/**
 * Every PER-CONTACT `_meta` key [VaultDatabase.deleteContact] must
 * purge — Double-Ratchet / session state AND the pending
 * read-capability rotation markers. [VaultDatabase.deleteContact] erases the
 * contacts/inboxes/messages rows but NOT these `_meta` rows, so before this a
 * deleted (or re-paired) contact left orphaned key material resident in the
 * encrypted vault until a full wipe. Both VaultDatabase actuals iterate this on
 * deleteContact, so any NEW per-contact `_meta` key MUST be added here or it leaks
 * across a delete/re-pair. Every entry CALLS its key builder
 * ([VaultRatchetStore.stateKey], the `MessageManager.dr…Key` helpers) — never a
 * hand-copied string, so a renamed key cannot silently leak its old rows. One ratchet
 * chain per contact (all three inboxes ride the text chain), so `dr/{id}/text` is the
 * only serialized-state key.
 *
 * The name is historical — it is no longer ratchet-only — but both `actual`s
 * reference it, so it is deliberately NOT renamed.
 *
 * It is NOT the whole delete-contact purge set. THREE sibling classifiers run in
 * the same loop in both actuals and any new key must be added to whichever fits:
 * [isGroupMetaResidueForContact] (group throttles, key-scoped),
 * [isReferralMetaResidueForContact] (referral handshake records — keyed by introId,
 * so the contact reference lives in the VALUE and the classifier takes it) and
 * [isScreenshotNoticeResidueForContact] (persisted screenshot notices — keyed by
 * conversation + sender + receive time, so the variable suffix makes an exact-key
 * list impossible; this is why they are NOT enumerated here).
 */
internal fun ratchetMetaKeysForContact(contactId: String): List<String> = listOf(
    VaultRatchetStore.stateKey(contactId, MessageManager.RATCHET_TEXT_CHANNEL),  // DoubleRatchet serialized state
    MessageManager.drRxCounterKey(contactId), // RETIRED receive count — no longer written; kept so a delete purges a legacy one
    MessageManager.drOnKey(contactId),      // send-activation flag
    MessageManager.drIntentKey(contactId),  // ratchet-capable flag
    MessageManager.drRxSeenKey(contactId),  // peer-confirmed flag
    MessageManager.channelTagSeenKey(contactId),  // channel-tag-seen flag
    MessageManager.inboxBoundSeenKey(contactId), // destination-inbox-bound flag
    MessageManager.drRecvLockKey(contactId),// ratchet-receive lock
    MessageManager.drLegacyFallbackKey(contactId), // consecutive-legacy-fallback count
    MessageManager.drRatUnackedKey(contactId), // consecutive-unacked-receive count
    MessageManager.drRefusedKey(contactId), // role-collision refusal latch — a
    // re-pair is the documented way out of a refusal, so it MUST NOT outlive the contact
    MessageManager.drRoleOrderKey(contactId),     // immutable role-order bit — a
    // re-pair mints NEW pairing secrets, so the old ordering must not be inherited by the
    // new contact that reuses the id (and a stale one over a fresh secret would flip the role)
    MessageManager.drPeerRoleRuleV2Key(contactId), // peer-runs-rule-v2 evidence
    MessageManager.drCtlCapKey(contactId),        // peer seals integrity control on the ratchet (send gate)
    MessageManager.drRecvLockGraceKey(contactId), // text channels owed the lock's grace after a control-armed lock
    MessageManager.drCtlCapStepKey(contactId),    // step ordinal of the newest in-order advert (downgrade proof)
    MessageManager.drCtlDeferredKey(contactId),   // deferred sealed control wires — ratchet ciphertext
    MessageManager.drCtlWatermarkKey(contactId),  // peer's ratchet-proven control commitment (receive lock) —
    // both describe THIS pairing's peer build and ratchet; a re-paired contact must re-earn them
    MaximumShieldPolicy.peerClaimKey(contactId),  // Maximum shield: this contact reported Maximum
    MaximumShieldPolicy.sentMarkerKey(contactId), // Maximum shield: last level announced to this contact — a
    // re-paired peer is a NEW device that has heard nothing, so the marker must not outlive the contact
    MessageManager.groupBackfillKey(contactId),   // group-inbox backfill throttle — a
    // re-pair is one of only two things that re-arm the budget (the other is the pairing
    // actually converging), so it MUST die with the contact or a re-paired peer would
    // inherit an exhausted budget and stay on the legacy group route forever
    GroupUnreadMarkerStore.keyFor(contactId),     // persisted `gi` unread attribution — which
    // groups this sender's still-pending group texts belong to; a re-paired peer is a new
    // pairing with an empty group inbox, so it must not inherit dots. Per CONTACT, so it is
    // here and not in GroupMetaKeys: a group delete DETACHES its units (GroupManager)
    // instead, and the restore detaches any unit whose group is gone.
    // DELIBERATELY NOT carried by a device move (MoveMetaPolicy.deniedPrefixes).
    // The pending read-cap rotation markers, one per inbound inbox. Each holds
    // a LIVE capability candidate, so leaving one behind on delete would be a new
    // capability leak in the vault (exactly the residue class this list exists for).
) + MessageManager.OWNED_READ_DIRECTIONS.map { MessageManager.capPendingKey(contactId, it) }

/**
 * The single source of truth for the GroupManager `_meta` key prefixes,
 * mirrored here (GroupManager keeps them `private`) so the purge classifiers
 * below and the writers cannot drift apart. Any NEW group `_meta` prefix MUST be
 * added here and folded into the classifiers, not enumerated in a per-platform
 * list.
 *
 * Deliberately absent: `group_admin:<groupId>` — the anti-eclipse tombstone
 * (`GroupManager.adminMetaKey`) that must SURVIVE a leave/delete so a later
 * different-admin re-invite to the same groupId is flagged. Purging it would
 * silently disarm that defense; see the classifiers.
 *
 * Also deliberately absent: `grp_declined` — the per-offer decline
 * tombstone (`GroupManager.DECLINED_INVITE_META`), a vault SINGLETON holding only
 * one-way `declineTokenFor` hashes (no reconstructible group/contact id, the same
 * reasoning as the referral `ref_done2` list and the `update_nudge_v1` throttle).
 * It MUST survive a contact/group delete — that persistence is the whole point of
 * a per-offer decline — and is erased only by a full-vault wipe. No residue
 * predicate may match it (pinned in
 * `GroupInviteDeclineTest.declineTombstone_survivesContactAndGroupDelete_diesOnlyOnWipe`).
 */
internal object GroupMetaKeys {
    /** `grp_inv_rl:<contactId>` — per-contact received-invite rate-limit list. */
    const val INVITE_RL_PREFIX = "grp_inv_rl:"
    /** `grp_roster_rl:<groupId>:<contactId>` — admin-side per-member roster-fanout throttle. */
    const val ROSTER_RL_PREFIX = "grp_roster_rl:"
    /**
     * `grp_ctl_pend:<groupId>:<contactId>` — a durable
     * UNDELIVERED membership-control obligation (roster or leave) the control
     * sweep redrives. Value `<kind>|<epoch>|<hash>|<attempts>|<firstSeenMs>`; the
     * roster body itself is re-derived from live vault state at redrive time.
     */
    const val CTL_PEND_PREFIX = "grp_ctl_pend:"
}

/**
 * True when [key] is a GROUP-scoped `_meta` residue for [groupId] that
 * [VaultDatabase.deleteGroup] must purge. Both `VaultDatabase` actuals classify
 * with THIS function (enumerate `_meta`, delete the matches) so Android and iOS
 * purge the identical set.
 *
 * A predicate rather than an exact-key list because `grp_roster_rl` is keyed per
 * (group, contact): the per-member suffix is unbounded and survives a member
 * removal (and predates this fix), so no fixed enumeration can name every key.
 *
 * The trailing `:` after `groupId` is load-bearing — groupIds are Base64Url (no
 * `:`), so `grp_roster_rl:<groupId>:` is an unambiguous boundary that a
 * prefix-sharing sibling groupId (e.g. "AB" vs "ABC") cannot straddle.
 *
 * `group_admin:<groupId>` is intentionally NOT matched (see [GroupMetaKeys]).
 */
internal fun isGroupMetaResidueForGroup(key: String, groupId: String): Boolean =
    key.startsWith(GroupMetaKeys.ROSTER_RL_PREFIX + groupId + ":") ||
        key.startsWith(GroupMetaKeys.CTL_PEND_PREFIX + groupId + ":")

/**
 * True when [key] is a CONTACT-scoped group `_meta` residue for
 * [contactId] that [VaultDatabase.deleteContact] must purge — IN ADDITION to
 * [ratchetMetaKeysForContact]. Covers the per-contact invite throttle
 * (`grp_inv_rl:<contactId>`) and the roster throttle across ALL groups
 * (`grp_roster_rl:<anyGroupId>:<contactId>`, including groups already left whose
 * residue predates this fix).
 *
 * `endsWith(":" + contactId)` is exact: contactIds carry no `:`, so the final
 * `:`-delimited segment of a roster key IS the contactId — a different contact's
 * key can never match. `group_admin:<groupId>` is never matched (its value is a
 * contactId but it is a deliberate group tombstone; see [GroupMetaKeys]).
 */
internal fun isGroupMetaResidueForContact(key: String, contactId: String): Boolean =
    key == GroupMetaKeys.INVITE_RL_PREFIX + contactId ||
        (key.startsWith(GroupMetaKeys.ROSTER_RL_PREFIX) && key.endsWith(":" + contactId)) ||
        (key.startsWith(GroupMetaKeys.CTL_PEND_PREFIX) && key.endsWith(":" + contactId))

/**
 * The `_meta` namespace the PERSISTED screenshot notices own
 * ([ScreenshotNoticeStore]) — the same single-source-of-truth arrangement as
 * [GroupMetaKeys], so the writer and the purge classifiers below cannot drift.
 *
 * One row per received notice:
 *   key   `ssn:<conversationId>:<senderContactId>:<receivedAtMs>`
 *   value `<takenAtMs>|<isGroup 0/1>|<seen 0/1>`
 *
 * conversationIds are contactIds (UUID) or groupIds (Base64Url) and
 * senderContactIds are UUIDs — none of them may contain `:`, which is what makes
 * the segments below an unambiguous boundary (the store's `isStorableId` gate
 * refuses to write anything else).
 */
internal object ScreenshotNoticeMetaKeys {
    /** `ssn:` — the cheap prefix gate every purge/GC scan applies first. */
    const val PREFIX = "ssn:"
}

/**
 * True when [key] is a persisted screenshot notice that [VaultDatabase.deleteGroup]
 * must purge for [groupId] — the group sibling of [isGroupMetaResidueForGroup], and
 * iterated in the SAME loop by `DatabaseManager.deleteGroup` (Android) and
 * `IosVaultDatabase.deleteGroup` (iOS).
 *
 * The trailing `:` after [groupId] is load-bearing for exactly the reason it is in
 * [isGroupMetaResidueForGroup]: groupIds are Base64Url (no `:`), so
 * `ssn:<groupId>:` cannot be straddled by a prefix-sharing sibling groupId
 * ("AB" vs "ABC").
 */
internal fun isScreenshotNoticeResidueForGroup(key: String, groupId: String): Boolean =
    groupId.isNotEmpty() && key.startsWith(ScreenshotNoticeMetaKeys.PREFIX + groupId + ":")

/**
 * True when [key] is a persisted screenshot notice that [VaultDatabase.deleteContact]
 * must purge for [contactId] — IN ADDITION to [ratchetMetaKeysForContact],
 * [isGroupMetaResidueForContact] and [isReferralMetaResidueForContact].
 *
 * BOTH id positions match, and that is deliberate:
 *  - the CONVERSATION segment — the deleted contact's own 1:1 notices; and
 *  - the SENDER segment — notices that contact left inside GROUPS the user is
 *    still in. Without this second test, deleting a contact would leave rows
 *    naming them as the screenshotter in every shared group until they expired.
 *
 * A predicate rather than an exact-key list because the key carries a variable
 * `receivedAtMs` suffix (and, for the group case, an unbounded set of
 * conversationIds), so no fixed enumeration can name every key — the same reason
 * `grp_roster_rl` needs one.
 */
internal fun isScreenshotNoticeResidueForContact(key: String, contactId: String): Boolean {
    if (contactId.isEmpty() || !key.startsWith(ScreenshotNoticeMetaKeys.PREFIX)) return false
    val parts = key.split(':')
    // "ssn" | conversationId | senderContactId | receivedAtMs — anything else is
    // not a key this namespace ever wrote and is left alone.
    if (parts.size != 4) return false
    return parts[1] == contactId || parts[2] == contactId
}

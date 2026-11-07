package com.vg.run

// The public data types GroupManager's API hands to both platforms' UI. Pure
// declarations; the protocol and its state live in GroupManager.kt.

/**
 * NO-PARK: what a received item in a conversation screen's buffer IS,
 * relative to the screen whose poll fetched it. Every fetched message is shown in
 * that screen — nothing is held back for "its" conversation.
 */
enum class ReceivedItemKind {
    /** The screen's own traffic: a group text in its group, a 1:1 text in its 1:1. */
    OWN,
    /** A 1:1 text from [GroupMessage.senderContactId] that a GROUP poll fetched —
     *  shown in that group's screen, visible only to us. Never a group message. */
    PRIVATE,
    /** A group text that a poll of ANOTHER conversation fetched (the sender's 1:1
     *  screen, or a different group's screen) — shown there, marked with its group.
     *  Never a 1:1 message. */
    GROUP_ECHO,
}

/** A group-screen item accepted for display. Ephemeral — never persisted.
 *  [kind] OWN: a text of [groupId]. PRIVATE: a 1:1 text from [senderContactId]
 *  ([groupId] is the screen's group). GROUP_ECHO: a text of ANOTHER group —
 *  [groupId]/[groupName] name THAT group, not the screen's. */
data class GroupMessage(
    val groupId: String,
    val senderContactId: String,
    val senderAlias: String,
    val text: String,
    val timestamp: Long,
    val counter: Long,
    val sequenceGap: Boolean,
    // False when the sender's membership hash differs from ours — the sender
    // has a different view of the member list (splitting / stale roster).
    val membershipOk: Boolean,
    // True for a locally-generated system notice (e.g. "X left the group") —
    // not a real peer text; rendered centered/muted, no bubble or attribution.
    val isSystem: Boolean = false,
    // Channel-namespaced de-dupe id from the underlying
    // ReceivedMessage, so a ratchet group message can't collide with a legacy one from
    // the same sender. Empty for system notices (the UI keys those by timestamp).
    val dedupeId: String = "",
    val kind: ReceivedItemKind = ReceivedItemKind.OWN,
    // The name of [groupId] (empty for system notices / PRIVATE items).
    val groupName: String = "",
) {
    // Swift-friendly kind tests (a Kotlin enum entry named PRIVATE does not export cleanly).
    val isPrivate: Boolean get() = kind == ReceivedItemKind.PRIVATE
    val isGroupEcho: Boolean get() = kind == ReceivedItemKind.GROUP_ECHO
}

/** NO-PARK: a 1:1-screen item. [kind] OWN: a 1:1 text from
 *  [contactId]. GROUP_ECHO: a group text of [groupId]/[groupName] that this 1:1
 *  screen's poll fetched from [contactId]'s inboxes — shown here, marked, and never
 *  counted as a 1:1 message. Ephemeral — never persisted. */
data class DirectItem(
    val contactId: String,
    val text: String,
    val timestamp: Long,
    val dedupeId: String,
    val kind: ReceivedItemKind = ReceivedItemKind.OWN,
    val groupId: String = "",
    val groupName: String = "",
) {
    val isGroupEcho: Boolean get() = kind == ReceivedItemKind.GROUP_ECHO
}

/** Result of [GroupManager.ingest]: the items for the screen the caller is
 *  viewing (a 1:1 screen's [direct], a group screen's [group]). Controls were
 *  applied; nothing is held for another conversation. */
data class IngestResult(
    val direct: List<DirectItem>,
    val group: List<GroupMessage>,
)

/**
 * Outcome of a fan-out send: how many member copies the relay accepted out of the
 * members that COULD be addressed ([total]), plus the members that could not be
 * addressed at all ([unreachable] — on the admin's roster but with no resolved
 * contact on this phone yet, e.g. a fresh group whose admin is offline so the
 * joiners never learned each other's inboxes). `unreachable` members count
 * toward [undelivered], so a sender never sees "✓" while a member got nothing. There is no backfill: a copy that did not go now never goes.
 */
data class GroupSendResult(val delivered: Int, val total: Int, val unreachable: Int = 0) {
    val allDelivered: Boolean get() = total > 0 && delivered == total && unreachable == 0
    /** Members who did NOT get this text: refused/failed copies plus the unaddressable ones. */
    val undelivered: Int get() = (total - delivered) + unreachable
}

/** Consent gate: a group invite awaiting the user's decision. Parked
 *  in RAM on receipt and mirrored to `GroupInviteStore` (rehydrated in `init`,
 *  like ReferralOffer) — NO group is created and NO contact-tag is disclosed
 *  until the user calls acceptInvite. Carries both the display fields the consent prompt shows and
 *  everything acceptInvite needs to actually join. */
data class GroupInvite(
    val groupId: String,
    val inviterContactId: String,
    val inviterAlias: String,
    val groupName: String,
    val epoch: Long,
    val adminMemberId: String,
    val myMemberId: String,
    val memberIds: List<String>,
    // True when this device has PREVIOUSLY held this groupId under a
    // DIFFERENT admin-of-record (a surviving group_admin:<id> tombstone names another
    // contact). "admin" is trust-on-first-invite with no groupId→creator binding, so
    // a co-member can re-invite a victim after they leave/are-removed and install
    // itself as admin. This flag lets the consent UI warn loudly so the user isn't
    // silently eclipsed. [priorAdminAlias] labels the prior admin when resolvable.
    val adminMismatch: Boolean = false,
    val priorAdminAlias: String? = null,
)

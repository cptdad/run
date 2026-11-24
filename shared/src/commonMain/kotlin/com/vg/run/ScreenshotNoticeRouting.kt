package com.vg.run

// ---------------------------------------------------------------------------
// RÚN-07 — a screenshot notice for EVERY conversation whose text is on the
// captured screen (owner decision 2026-11-23: the inline rows from other
// conversations stay; the notice covers them instead).
//
// A conversation screen can show text from other conversations (NO-PARK): a
// private 1:1 text inside a group, a text of group B inside group A or inside a
// 1:1, our own private reply in the group, a text of a group we are only invited
// to. The iOS screen hands the shared layer the ORIGIN of every row in its list
// ([ScreenshotOrigin]) plus its own conversation; [planScreenshotNotices] turns
// that into one notice per distinct conversation, using only the two notice kinds
// that already exist on the wire (no protocol change):
//   - a 1:1 origin       → the 1:1 notice (MessageManager.sendScreenshotNotice);
//   - a group on this phone → the group notice fanned out to its resolved members;
//   - a group NOT on this phone whose invite FROM THAT SENDER is still parked here
//     (an invite we have not answered, so only its inviter can have sent the row) →
//     the same group notice to that sender alone,
//     with an empty membership hash. On the inviter's phone the group exists and we
//     are a resolved member (createGroup / addMember record the invitee's contact),
//     so it is stored under THAT group; the empty hash makes the receiver skip its
//     membership-view check (no false ack, no re-roster).
// The receiver stores each notice under the conversation the kind names, so the
// notice is attributed to the conversation whose text was captured, never to the
// screen the capturer happened to have open. Blocked contacts get nothing. A group
// that is not on this phone and has no parked invite from the row's sender (one we
// LEFT or DECLINED whose rows are still on screen) gets no notice at all.
// ---------------------------------------------------------------------------

/**
 * One conversation whose text was in the captured screen's list. [isGroup] false:
 * [conversationId] is the 1:1 contactId. [isGroup] true: [conversationId] is the
 * groupId and [senderContactId] the contact the row came from (used only when that
 * group is not on this phone — the invited-only case); empty for the open group.
 */
data class ScreenshotOrigin(
    val conversationId: String,
    val isGroup: Boolean,
    val senderContactId: String,
)

/** Counts only: how many distinct conversations a screenshot addressed, and how many
 *  of them at least one copy reached. Never identifiers. */
data class ScreenshotNoticeOutcome(val conversations: Int, val reached: Int)

/** One notice to send, per distinct conversation. */
internal sealed class ScreenshotNoticeTarget {
    data class Direct(val contactId: String) : ScreenshotNoticeTarget()
    data class Group(val groupId: String, val memberContactIds: List<String>, val membershipHash: String) : ScreenshotNoticeTarget()
    data class InvitedGroup(val groupId: String, val senderContactId: String) : ScreenshotNoticeTarget()
}

/** A group this phone holds: its resolved members other than us, and our membership hash. */
internal class LocalGroupTargets(val memberContactIds: List<String>, val membershipHash: String)

/**
 * Pure: the notices one screenshot sends. One per distinct conversation (1:1 by
 * contactId, group by groupId, invited group by (groupId, sender)); blocked contacts
 * are excluded everywhere; a contact this phone no longer has gets no 1:1 notice.
 * [localGroup] returns null for a group that is not on this phone; such a group is
 * addressed only to a row sender for whom [invitePendingFrom] is true (a parked invite
 * from exactly that contact for exactly that group).
 */
internal fun planScreenshotNotices(
    origins: List<ScreenshotOrigin>,
    blocked: Set<String>,
    contactExists: (String) -> Boolean,
    localGroup: (groupId: String) -> LocalGroupTargets?,
    invitePendingFrom: (groupId: String, senderContactId: String) -> Boolean,
): List<ScreenshotNoticeTarget> {
    val direct = LinkedHashSet<String>()
    val groupSenders = LinkedHashMap<String, LinkedHashSet<String>>()
    for (o in origins) {
        if (o.conversationId.isEmpty()) continue
        if (o.isGroup) groupSenders.getOrPut(o.conversationId) { LinkedHashSet() }.add(o.senderContactId)
        else direct.add(o.conversationId)
    }
    val out = mutableListOf<ScreenshotNoticeTarget>()
    for (cid in direct) {
        if (cid in blocked || !contactExists(cid)) continue
        out.add(ScreenshotNoticeTarget.Direct(cid))
    }
    for ((gid, senders) in groupSenders) {
        val local = localGroup(gid)
        if (local != null) {
            val targets = local.memberContactIds.filter { it !in blocked }.distinct()
            if (targets.isNotEmpty()) out.add(ScreenshotNoticeTarget.Group(gid, targets, local.membershipHash))
            continue
        }
        for (sender in senders) {
            if (sender.isEmpty() || sender in blocked || !contactExists(sender)) continue
            if (!invitePendingFrom(gid, sender)) continue   // left / declined / never invited
            out.add(ScreenshotNoticeTarget.InvitedGroup(gid, sender))
        }
    }
    return out
}

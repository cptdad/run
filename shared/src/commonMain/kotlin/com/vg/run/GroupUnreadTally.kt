package com.vg.run

import com.vg.run.GroupManager.Companion.MAX_PENDING_ACTIVITY_PER_MEMBER
import kotlin.time.TimeSource

// ---------------------------------------------------------------------------
// GroupUnreadTally — GroupManager's session-scoped unread tallies, under one
// lock of their own (never nested with any other; SyncLock is non-reentrant on
// iOS) and never held across SQLCipher: this class touches no vault. Every input
// that needs the vault (screenshot-notice counts, the screen buffers' own-item
// counts, the presence-bump group lookup) is read by GroupManager BEFORE it calls
// in. Logs keep the "GroupManager" tag.
//
// Unread attribution. Each pairing has a THIRD inbox for group text, so for a
// converged pairing the group/contact split is structural (a text-inbox /peek is
// a count with no decrypt and could not tell a group text from a 1:1 text); the
// sender's KIND_ACTIVITY notice says WHICH group, and keeps a LEGACY peer's texts
// (still on the text inbox) subtractable.
//   • groupUnread[groupId]            → drives the GROUP dot; cleared when the
//                                         group conversation is opened.
//   • groupPendingByContact[contactId] → the LEGACY COMPENSATOR: how many group
//                                         texts are sitting, un-consumed, on that
//                                         contact's TEXT inbox; subtracted from the
//                                         CONTACT dot. Written only for a
//                                         KIND_ACTIVITY notice WITHOUT `gi`, i.e.
//                                         a group text really sitting on that
//                                         contact's TEXT inbox (a legacy peer).
// The maps below are the group-inbox mechanism, and NONE of them is an
// input to [contactCountsFrom] or [primeUnreadCountFor] at any point — that is the
// invariant this whole design exists for, and it is pinned by
// `GroupTextNeverOnContactTest` plus a source guard
// (`GroupTextNeverOnContactSourceGuardTest`, which scans THIS file).
//   • groupInboxPendingByContact[contactId] → the last /peek depth of that
//                                         contact's inbound-grp inbox. Drives
//                                         the GROUP presence bump only.
//   • grpNoticedByContact[contactId]      → how many `gi` notices from that
//                                         contact are still unattributed-for,
//                                         i.e. how much of the depth above is
//                                         already accounted to a named group.
//   • restoredUnits[contactId]            → which of those `gi` units came from the
//                                         VAULT at session start (oldest first,
//                                         groupId or null = detached), so a DEFINITE
//                                         peek can heal them ([retractRestored]).
//   • unattributedSinceMs[contactId]      → the NOTICE GRACE: when (monotonic) that
//                                         contact's depth was first seen exceeding its
//                                         notices, and
//     noticeCheckedAfterGrace             → whether a control-inbox check of that
//                                         contact that STARTED at least
//                                         [NOTICE_LANDING_GRACE_MS] later has come back
//                                         without the notice. The presence bump waits
//                                         for these ([unattributedContacts]).
// These maps are RAM, session-scoped, and die in [scrub]. The `gi` attribution is
// ALSO mirrored into the encrypted vault (owner decision 2026-11-12) — but NOT by
// this class: GroupManager writes it through GroupUnreadMarkerStore, outside this
// lock, in lockstep with the calls below, and hands it back once per session via
// [restore]. Only contactId/groupId/count/minute-stamp is persisted, never message
// content, and the legacy compensator stays RAM-only.
// ---------------------------------------------------------------------------
internal class GroupUnreadTally(
    /**
     * MONOTONIC milliseconds for the notice grace. Called under [lock], so it must
     * be a pure clock read (never the vault). Injectable for tests; production is
     * [monotonicNowMs] (immune to wall-clock steps).
     */
    private val nowMs: () -> Long = ::monotonicNowMs,
) {
    internal companion object {
        private const val TAG = "GroupManager"

        /**
         * How long after an unattributed group-inbox depth is first seen a control
         * check must START before its "no notice there" counts. The sender posts the
         * `gi` notice ONE inter-send jitter gap (250–2000 ms, [sleepInterSendJitter])
         * after the text POST completed, and the notice POST itself is one more onion
         * round trip — so a check that starts ~3 s after the depth was seen (the next
         * FAST control cycle) can still beat the notice to the relay. 15 s covers the
         * 2 s gap plus a ~13 s POST on a slow circuit.
         */
        const val NOTICE_LANDING_GRACE_MS = 15_000L

        /**
         * The fallback's backstop: an unattributed depth that has stood this long
         * lights the bump even if no qualifying control check of that contact ever
         * came back (its control drain keeps failing). Two idle control cycles
         * (2 × 60–90 s) — longer than the event path's worst case, so it only ever
         * decides when the control path is broken.
         */
        const val FALLBACK_CEILING_MS = 180_000L

        private val MONO_ORIGIN = TimeSource.Monotonic.markNow()

        fun monotonicNowMs(): Long = MONO_ORIGIN.elapsedNow().inWholeMilliseconds
    }

    private val lock = SyncLock()
    private val groupUnread = mutableMapOf<String, Int>()
    private val groupPendingByContact = mutableMapOf<String, Int>()
    private val groupInboxPendingByContact = mutableMapOf<String, Int>()
    private val grpNoticedByContact = mutableMapOf<String, Int>()
    private val restoredUnits = mutableMapOf<String, MutableList<String?>>()
    private val unattributedSinceMs = mutableMapOf<String, Long>()
    private val noticeCheckedAfterGrace = mutableSetOf<String>()

    /**
     * Keeps the notice-grace state of [contactId] in step with its two group-inbox
     * tallies. Becoming unattributed starts the clock (once — a growing depth does
     * not restart it); ceasing to be unattributed (the notice arrived, the depth
     * went to 0, the inbox drained) resets it, so the next unattributed text waits
     * afresh. Caller holds [lock].
     */
    private fun reconcileGraceLocked(contactId: String) {
        val unattributed = (groupInboxPendingByContact[contactId] ?: 0) > (grpNoticedByContact[contactId] ?: 0)
        if (unattributed) {
            if (contactId !in unattributedSinceMs) {
                unattributedSinceMs[contactId] = nowMs()
                noticeCheckedAfterGrace.remove(contactId)
            }
        } else {
            unattributedSinceMs.remove(contactId)
            noticeCheckedAfterGrace.remove(contactId)
        }
    }

    /** The timestamp a control sweep stamps itself with BEFORE its first request;
     *  hand it back to [controlInboxChecked]. Same clock as the grace. */
    fun controlSweepStartedAtMs(): Long = nowMs()

    /**
     * A control sweep that started at [sweepStartedAtMs] positively covered
     * [contactId]'s control inbox — a peek ANSWERED 0, or a drain came back
     * non-empty (so its fetch succeeded, and whatever it carried has already been
     * applied). A failed peek/fetch is never reported here. If that sweep started at
     * least [NOTICE_LANDING_GRACE_MS] after the contact's depth was first seen
     * unattributed, the notice had time to land and did not: the fallback is now
     * due. An earlier sweep proves nothing (the notice may still have been in
     * flight) and is ignored. A contact that is not unattributed is a no-op.
     */
    fun controlInboxChecked(contactId: String, sweepStartedAtMs: Long) = lock.withLock {
        val since = unattributedSinceMs[contactId] ?: return@withLock
        if (sweepStartedAtMs - since >= NOTICE_LANDING_GRACE_MS) noticeCheckedAfterGrace.add(contactId)
    }

    /**
     * One accepted KIND_ACTIVITY notice from [senderContactId] for [groupId]
     * (GroupManager.handleActivity has already checked group + membership + age).
     * [onGroupInbox] is the `gi` marker: PRESENT counts into [grpNoticedByContact],
     * ABSENT into the legacy [groupPendingByContact].
     *
     * Bound how far ONE member can push these counters. An authenticated member
     * could otherwise spam KIND_ACTIVITY to inflate the group dot AND — because
     * [contactCountsFrom] subtracts the legacy per-contact pending count from that
     * sender's /peek total — suppress the 1:1 badge for their own direct messages.
     *
     * The ceiling is on OUTSTANDING pending notices, deliberately NOT a time window:
     * members legitimately send several group texts within seconds, and a time gate
     * would drop the dot for real messages (it broke four GroupManagerTest cases
     * that send back-to-back notices — correctly). Draining a group text decrements
     * the same counter ([consumed]), so an honest conversation never approaches
     * this, while a flood stops mattering once it does.
     *
     * THE CEILING IS ON THE SUM OF THE TWO TALLIES, not on each separately. The
     * third inbox split one counter into two (`gi` present / absent) and both are
     * driven by the SAME peer-chosen field, so a per-tally ceiling would let one
     * member alternate the marker and push `groupUnread` to 2 × the bound — the
     * ceiling is on how far ONE member may push the group dot, and splitting the
     * state must not double the budget.
     *
     * Returns whether the notice was COUNTED — false when the ceiling ignored it,
     * and GroupManager persists the `gi` attribution only for a counted notice.
     */
    fun noteActivity(senderContactId: String, groupId: String, onGroupInbox: Boolean): Boolean = lock.withLock {
        val legacyPending = groupPendingByContact[senderContactId] ?: 0
        val grpPending = grpNoticedByContact[senderContactId] ?: 0
        if (legacyPending + grpPending >= MAX_PENDING_ACTIVITY_PER_MEMBER) {
            platformLogWarn(TAG, "activity ceiling hit for a member — ignoring the notice")
            return@withLock false
        }
        groupUnread[groupId] = (groupUnread[groupId] ?: 0) + 1
        if (onGroupInbox) {
            grpNoticedByContact[senderContactId] = grpPending + 1
            // Attribution caught up → a waiting fallback never shows.
            reconcileGraceLocked(senderContactId)
        } else groupPendingByContact[senderContactId] = legacyPending + 1
        true
    }

    /**
     * Session start: [senderContactId]'s still-pending `gi` units, as the vault
     * mirror held them (oldest first; a null groupId is DETACHED — it accounts for
     * one blob on that contact's group inbox but lights no group). Each grouped
     * unit counts into its group's dot exactly as a live notice would, and every
     * unit counts into the `gi`-notice tally, so the presence bump does not fire
     * for that depth. From here on a restored unit is a live unit (drain, consume,
     * open all treat it the same); the only difference is that a DEFINITE peek may
     * heal it ([retractRestored]).
     *
     * The per-member ceiling still holds: only as many of the NEWEST units as fit
     * under it are taken. Returns how many were restored.
     */
    fun restore(senderContactId: String, groupIds: List<String?>): Int = lock.withLock {
        val legacyPending = groupPendingByContact[senderContactId] ?: 0
        val grpPending = grpNoticedByContact[senderContactId] ?: 0
        val room = MAX_PENDING_ACTIVITY_PER_MEMBER - legacyPending - grpPending
        if (room <= 0 || groupIds.isEmpty()) return@withLock 0
        val take = if (groupIds.size > room) groupIds.subList(groupIds.size - room, groupIds.size) else groupIds
        for (g in take) if (g != null) groupUnread[g] = (groupUnread[g] ?: 0) + 1
        grpNoticedByContact[senderContactId] = grpPending + take.size
        restoredUnits.getOrPut(senderContactId) { mutableListOf() }.addAll(take)
        reconcileGraceLocked(senderContactId)
        take.size
    }

    /**
     * A DEFINITE peek answered [depth] for [contactId]'s group inbox. If more
     * RESTORED units are outstanding than that, the oldest surplus describes texts
     * that are no longer on the relay (expired, or drained in a session whose
     * clear did not land): retract them from the group dot and the notice tally.
     * Live units noted in this session are never touched here (the drain stays
     * their authority, exactly as before), and comparing against the WHOLE depth
     * is the conservative side — it can only under-heal. Returns the retracted count.
     */
    fun retractRestored(contactId: String, depth: Int): Int = lock.withLock {
        val list = restoredUnits[contactId] ?: return@withLock 0
        val excess = list.size - (if (depth > 0) depth else 0)
        if (excess <= 0) return@withLock 0
        repeat(excess) {
            val g = list.removeAt(0)
            if (g != null) {
                val n = (groupUnread[g] ?: 0) - 1
                if (n > 0) groupUnread[g] = n else groupUnread.remove(g)
            }
        }
        if (list.isEmpty()) restoredUnits.remove(contactId)
        val left = (grpNoticedByContact[contactId] ?: 0) - excess
        if (left > 0) grpNoticedByContact[contactId] = left else grpNoticedByContact.remove(contactId)
        reconcileGraceLocked(contactId)
        excess
    }

    // A restored unit of [groupId] stops lighting it (the RAM dot was cleared or
    // given back by the caller) but keeps accounting. Caller holds [lock].
    private fun detachRestoredLocked(contactId: String?, groupId: String, all: Boolean) {
        for ((c, list) in restoredUnits) {
            if (contactId != null && c != contactId) continue
            for (i in list.indices) {
                if (list[i] == groupId) {
                    list[i] = null
                    if (!all) return
                }
            }
        }
    }

    /**
     * A group text from [contactId] was just pulled off the relay (returned to a
     * conversation or buffered): it is no longer pending on that inbox.
     *
     * [fromGroupInbox] names WHICH inbox it left, and the two are separate tallies
     * for the same reason they are separate on the way in ([noteActivity]): the
     * text-inbox one compensates a CONTACT dot, the group-inbox one accounts a
     * GROUP presence bump, and mixing them would let a drain on one channel silence
     * the other.
     */
    fun consumed(contactId: String, fromGroupInbox: Boolean) = lock.withLock {
        fun dec(m: MutableMap<String, Int>) {
            val n = (m[contactId] ?: 0) - 1
            if (n > 0) m[contactId] = n else m.remove(contactId)
        }
        if (fromGroupInbox) {
            dec(grpNoticedByContact); dec(groupInboxPendingByContact)
            // Never more restored units than `gi` units outstanding.
            val list = restoredUnits[contactId]
            if (list != null) {
                val cap = grpNoticedByContact[contactId] ?: 0
                while (list.size > cap) list.removeAt(0)
                if (list.isEmpty()) restoredUnits.remove(contactId)
            }
            reconcileGraceLocked(contactId)
        } else dec(groupPendingByContact)
    }

    /**
     * NO-PARK: a text of [groupId] was just shown as a GROUP_ECHO in the screen
     * that fetched it (a 1:1, or another group). Its KIND_ACTIVITY notice may
     * already have bumped [groupUnread] for it, and nothing is left behind in that
     * group for the dot to point at — so give that unit back (floored at 0). A
     * notice that lands AFTER the echo still lights the dot until the group is
     * opened, the same bounded over-light a lost text already has.
     */
    fun shownElsewhere(groupId: String, senderContactId: String) = lock.withLock {
        val n = (groupUnread[groupId] ?: 0) - 1
        if (n > 0) groupUnread[groupId] = n else groupUnread.remove(groupId)
        // The unit given back must not be retracted from the dot a second time.
        detachRestoredLocked(senderContactId, groupId, all = false)
    }

    /**
     * [contactId]'s GROUP inbox was just drained. THE DRAIN IS AUTHORITATIVE, for
     * BOTH group-inbox tallies. The inbox is now empty, so its /peek depth is zero
     * — and so is the number of `gi` notices still describing anything in it.
     * Clearing the depth ALONE would leave a stale NOTICE count standing, and
     * `unattributed = depth − noticed` would then read ZERO for the next real group
     * text and silently swallow its presence bump: a dark group dot with a message
     * behind it. A notice outlives its text by design (7-day control retention
     * against a group text's 24 h), so this is the ordinary case, not a corner one.
     * Neither tally may outlive the inbox it describes.
     */
    fun groupInboxDrained(contactId: String) = lock.withLock {
        groupInboxPendingByContact.remove(contactId)
        grpNoticedByContact.remove(contactId)
        restoredUnits.remove(contactId)
        // Nothing left to attribute: the notice grace resets with the inbox.
        unattributedSinceMs.remove(contactId)
        noticeCheckedAfterGrace.remove(contactId)
    }

    /** [contactId]'s TEXT inbox was just drained completely by its 1:1 screen:
     *  nothing of theirs is left on the relay, so the legacy group-pending tally
     *  is authoritatively zero. */
    fun textInboxDrained(contactId: String) = lock.withLock {
        groupPendingByContact.remove(contactId)
    }

    /** Clear a group's unread count — its conversation was opened. */
    fun markGroupRead(groupId: String) = lock.withLock {
        groupUnread.remove(groupId)
        // Restored units of this group keep ACCOUNTING (as live ones do — the
        // `gi` tally is untouched here) but must never be retracted from a dot the
        // open already cleared, which could steal a later live notice's unit.
        detachRestoredLocked(null, groupId, all = true)
    }

    /** Publishes a sweep's GROUP-inbox depths. A depth the relay did not answer for
     *  is simply absent (unknown ≠ empty), so the previous value stands. */
    fun notePeekedGroupInboxDepths(depths: Map<String, Int>) {
        if (depths.isEmpty()) return
        lock.withLock {
            for ((contactId, n) in depths) {
                if (n > 0) groupInboxPendingByContact[contactId] = n
                else groupInboxPendingByContact.remove(contactId)
                // First sight of an unattributed depth starts the notice grace;
                // a depth back at (or below) what is attributed resets it.
                reconcileGraceLocked(contactId)
            }
        }
    }

    /**
     * The contacts whose presence-bump FALLBACK is due: their group-inbox depth
     * exceeds the `gi` notices already attributed to a named group,
     * `unattributed(c) = max(0, groupInboxPending[c] - grpNoticed[c]) > 0`,
     * AND that has stood long enough that the notice would have arrived if it was
     * going to (the NOTICE GRACE):
     *
     * ```
     * due(c) = unattributed(c) && ( checkedAfterGrace(c)                     // event
     *                               || now - since(c) >= FALLBACK_CEILING_MS ) // backstop
     * ```
     *
     * `checkedAfterGrace(c)` = a control check of c that STARTED at least
     * [NOTICE_LANDING_GRACE_MS] after `since(c)` came back without the notice
     * ([controlInboxChecked]). The sender ships text, then the notice one jitter gap
     * later; a peek in between used to light EVERY group shared with the sender
     * until the notice drained (device, 2026-11-13). A notice that lands during the
     * wait attributes normally and resets the grace, so the bump never shows.
     * The input to GroupManager's presence bump.
     */
    fun unattributedContacts(): Set<String> = lock.withLock {
        val now = nowMs()
        groupInboxPendingByContact.keys.filter { c ->
            val unattributed = (groupInboxPendingByContact[c] ?: 0) > (grpNoticedByContact[c] ?: 0)
            if (!unattributed) return@filter false
            reconcileGraceLocked(c)   // belt and braces: never "due" without a start time
            val since = unattributedSinceMs[c] ?: now
            c in noticeCheckedAfterGrace || now - since >= FALLBACK_CEILING_MS
        }.toSet()
    }

    /**
     * The per-group dot from the notice tally plus the three terms GroupManager
     * read outside this lock: [buffered] (each group screen's own untaken items),
     * [unseen] (unseen persisted screenshot notices) and [bump] (the presence-bumped
     * groups).
     */
    fun groupCountsWith(
        buffered: Map<String, Int>,
        unseen: Map<String, Int>,
        bump: Set<String>,
    ): Map<String, Int> = lock.withLock {
        val out = mutableMapOf<String, Int>()
        for ((groupId, n) in groupUnread) if (n > 0) out[groupId] = n
        // max(…), never +: a buffered text and its KIND_ACTIVITY notice describe
        // the SAME message. The buffered term is what closes a pre-existing dark
        // dot — without it a group text a SIBLING poll parked in RAM would rely
        // on its notice alone, and a notice can be lost.
        for ((groupId, n) in buffered) {
            val cur = out[groupId] ?: 0
            out[groupId] = if (n > cur) n else cur
        }
        for ((groupId, n) in unseen) out[groupId] = (out[groupId] ?: 0) + n
        // The no-notice fallback: +1, never n. See GroupManager.presenceBumpedGroups.
        for (groupId in bump) out[groupId] = (out[groupId] ?: 0) + 1
        out
    }

    /**
     * THE contact-dot arithmetic, and the whole of it. Isolated from the sweep that
     * feeds it so that **the contact-dot invariant is checkable by reading one
     * function**: the only inputs are the TEXT-inbox depths, the legacy compensator
     * and the screenshot notices, and no group-inbox symbol may ever appear here.
     * `GroupTextNeverOnContactTest` and its source guard pin exactly that.
     *
     * ```
     * count(c) = textPeek(c) - legacyGroupPending(c) + unseenScreenshotNotices(c)
     * ```
     *
     * `legacyGroupPending` is [groupPendingByContact] — written ONLY for a
     * KIND_ACTIVITY notice WITHOUT `gi`, i.e. only for a group text that really is
     * queued on that contact's TEXT inbox (a legacy peer, or one still inside the
     * backfill window). It is clamped so it can never exceed what is actually on
     * the relay, which also HEALS the tally downward as texts expire. For a
     * converged new↔new pairing it is provably always zero — delete the machinery
     * in release N+2.
     *
     * The notice term is a UNION, not a filter: the sweep only reports contacts
     * with a non-zero relay count, so a contact whose only unread thing is a
     * screenshot notice is absent from [raw] entirely and must still light up.
     * Blocked contacts are excluded from both terms. [unseen] was read from the
     * vault by the caller, outside this lock.
     */
    fun contactCountsFrom(
        raw: Map<String, Int>,
        unseen: Map<String, Int>,
        blockedContactIds: Set<String>,
    ): Map<String, Int> {
        val out = lock.withLock {
            val acc = mutableMapOf<String, Int>()
            for ((contactId, total) in raw) {
                val pending = (groupPendingByContact[contactId] ?: 0)
                val groupPart = if (pending > total) total else pending
                if (groupPart < pending) groupPendingByContact[contactId] = groupPart  // heal down
                val direct = total - groupPart
                if (direct > 0) acc[contactId] = direct
            }
            acc
        }
        for ((contactId, n) in unseen) {
            if (contactId in blockedContactIds) continue
            out[contactId] = (out[contactId] ?: 0) + n
        }
        return out
    }

    /**
     * The unread count one contact's peek turns into, shared by the batch pass and
     * the fan-out so the two can never drift: the relay's raw TEXT-inbox pending
     * total MINUS the LEGACY group-text compensator PLUS that contact's unseen
     * persisted screenshot notices — the same three terms [contactCountsFrom]
     * applies, and the same rule: **no group-inbox symbol may ever appear in
     * this body.** Clamped at zero; read-only — the downward heal of a stale
     * pending tally belongs to the authoritative steady-state sweep.
     */
    fun primeUnreadCountFor(contactId: String, raw: Int, unseen: Map<String, Int>): Int {
        val pending = lock.withLock { groupPendingByContact[contactId] ?: 0 }
        val direct = if (raw > pending) raw - pending else 0
        return direct + (unseen[contactId] ?: 0)
    }

    // Session end (GroupManager.scrubInMemory): all seven are contactIds/groupIds +
    // counts/timestamps — the same class of session state — and die in the same breath. The
    // vault mirror is untouched here (that is the point of it); GroupManager owns it.
    fun scrub() = lock.withLock {
        groupUnread.clear(); groupPendingByContact.clear()
        groupInboxPendingByContact.clear(); grpNoticedByContact.clear()
        restoredUnits.clear()
        unattributedSinceMs.clear(); noticeCheckedAfterGrace.clear()
    }
}

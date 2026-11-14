package com.vg.run

import com.vg.run.GroupManager.Companion.MAX_PENDING_CONTENT_PER_KEY
import com.vg.run.GroupManager.Companion.MAX_PENDING_CONTENT_TOTAL
import com.vg.run.GroupManager.Companion.MAX_PENDING_SCREENSHOT_NOTICES_PER_CONVERSATION
import com.vg.run.GroupManager.Companion.MAX_PENDING_UNRESOLVED_GROUP_TEXTS
import com.vg.run.GroupManager.Companion.MAX_PENDING_UNRESOLVED_PER_SENDER
import com.vg.run.GroupManager.Companion.PENDING_UNRESOLVED_GROUP_TEXT_TTL_MS

// ---------------------------------------------------------------------------
// ConversationBuffers — GroupManager's in-RAM conversation buffers: the
// per-screen hand-off buffers (POLL-HANDOFF-1 / NO-PARK), the unresolved-sender
// buffer and the RAM screenshot-notice buffer. ONE lock for all of them (the one
// the UI thread takes in the two `take*ScreenItems` calls), never held across
// SQLCipher: the only vault reads ([groupOf] / [membersOf] / [toMessage]) happen
// in [flushResolvedGroupTexts], outside it. The caps stay in GroupManager's
// companion (tests address them as `GroupManager.X`); logs keep the
// "GroupManager" tag.
//
// NO-PARK: the screen buffers hold ONLY what the keyed screen's own poll fetched
// (plus locally generated system notices for a group), between that poll and
// the screen's synchronous take. A 1:1 text fetched by a group poll is a PRIVATE
// item of THAT group screen; a group text fetched by a 1:1 (or another group's)
// poll is a GROUP_ECHO item of THAT screen. Nothing is ever held for ANOTHER
// conversation: a parked copy dies on lock/relaunch, and the drain has already
// consumed the relay copy.
//
// Known limitation: a poll whose screen is torn down mid-drain (lock, Android
// Group Info navigation) still leaves its items here until that same screen's
// next take; [scrub] (GroupManager.scrubInMemory) clears them on lock/wipe.
// ---------------------------------------------------------------------------
internal class ConversationBuffers(
    private val clock: () -> Long,
    private val groupOf: (String) -> GroupRecord?,
    private val membersOf: (String) -> List<GroupMemberRecord>,
    private val toMessage: (contactId: String, groupId: String, g: GroupRecord, members: List<GroupMemberRecord>, rm: ReceivedMessage) -> GroupMessage,
    // Replays a parked activity notice once its group + sender have resolved
    // (GroupManager → GroupUnreadTally.noteActivity). Kept as a callback for the
    // same reason [toMessage] is: this class never touches the vault or the tally
    // directly, so the one lock it owns is never nested with either — the replay
    // runs OUTSIDE [lock], like [flushResolvedGroupTexts]'s [toGroupScreen].
    // [noticeAtMs] is the notice's minute-rounded stamp, carried through so the
    // replay can persist the same `gi` attribution a live notice would.
    private val applyNotice: (groupId: String, senderContactId: String, onGroupInbox: Boolean, noticeAtMs: Long) -> Unit,
) {
    private companion object {
        const val TAG = "GroupManager"
    }

    private val lock = SyncLock()
    private val groupScreenItems  = mutableMapOf<String, MutableList<GroupMessage>>() // group screen's groupId →
    private val directScreenItems = mutableMapOf<String, MutableList<DirectItem>>()   // 1:1 screen's contactId →

    // Log the buffer-capacity warning at most once per overflow episode (a
    // flood can trip the cap thousands of times a second) — reset in
    // [scrub] so a fresh session can warn again if it happens again.
    private var screenItemsOverflowWarned = false
    // Same one-line-per-episode discipline for the unresolved-sender buffer, which
    // a flooding sender can trip on every arrival.
    private var pendingUnresolvedOverflowWarned = false
    // …and for the parked activity-notice buffer below.
    private var pendingActivityOverflowWarned = false

    // Unresolved-sender buffer: decryptable group texts whose sender is not YET a
    // resolved member on this device (member↔member resolution still in flight).
    // Keyed by "groupId<NUL>contactId" ([unresolvedKey] / [splitUnresolvedKey];
    // U+0000 separator, written as an escape so the source stays grep-able);
    // re-attributed on each roster apply / group open and pruned by TTL. Guarded by [lock] (same lock as the other content buffers,
    // so [scrub] empties it in the same critical section). Bounded so an
    // unresolved/removed sender cannot park unbounded plaintext.
    private data class PendingGroupText(val rm: ReceivedMessage, val bufferedAt: Long)
    private val pendingUnresolvedGroupText = mutableMapOf<String, MutableList<PendingGroupText>>()

    // Parked activity-notice buffer: a KIND_ACTIVITY notice whose group this device
    // has not JOINED yet (an invite still parked for consent) or whose SENDER is not
    // YET a resolved member (member↔member resolution in flight). A notice is
    // consumed off the relay the instant it is drained, so dropping it on arrival
    // would lose the GROUP unread dot for a sender's FIRST message into the group
    // for good. It is parked instead — keyed exactly like [pendingUnresolvedGroupText]
    // ("groupId<NUL>senderContactId"), bounded by the SAME caps, TTL-pruned — and
    // replayed by [flushResolvedActivityNotices] on the roster apply / invite accept
    // that resolves it. Holds only (onGroupInbox, the notice's minute stamp) per
    // notice: no plaintext, no alias, no counter. Guarded by [lock]; emptied by [scrub].
    private data class PendingActivity(val onGroupInbox: Boolean, val noticeAtMs: Long, val bufferedAt: Long)
    private val pendingActivityNotices = mutableMapOf<String, MutableList<PendingActivity>>()

    private fun unresolvedKey(groupId: String, contactId: String) = groupId + "\u0000" + contactId

    // (groupId, contactId) of a key built by [unresolvedKey].
    private fun splitUnresolvedKey(key: String): Pair<String, String> {
        val sep = key.indexOf('\u0000')
        return key.substring(0, sep) to key.substring(sep + 1)
    }

    // "X took a screenshot" notices awaiting their conversation, keyed by
    // conversationId (contactId for 1:1, groupId for a group). Guarded by
    // [lock] — the same lock as the other content buffers, so
    // [scrub] empties it in the same critical section. Bounded per
    // conversation.
    //
    // This buffer is the FAST PATH only — "arrived while you have the conversation
    // open". It is still session-scoped and still dies with the session; the copy
    // that survives lock/background/process death is the durable `_meta` row
    // GroupManager's `screenshotStore` writes on receipt (and which a wipe crypto-erases with the
    // rest of the vault).
    private val pendingScreenshotNotices = mutableMapOf<String, MutableList<ScreenshotNotice>>()

    /**
     * Shared eviction for [groupScreenItems]/[directScreenItems] — see
     * [MAX_PENDING_CONTENT_PER_KEY]. Enforces a per-key ceiling (this key's own
     * oldest entry is dropped once IT is full) and a global ceiling across every
     * key in [map] (the oldest entry of whichever key currently holds the most is
     * dropped — the realistic flood target, so eviction actually relieves the
     * pressure that caused it rather than punishing an unrelated quiet
     * conversation). Unlike the screenshot-notice buffer, which rejects the
     * INCOMING item, this evicts the OLDEST parked entry instead: a parked
     * message is already "arrived but not yet looked at," so dropping the oldest
     * is the least-surprise direction (mirrors ReferralManager.handleAccept's
     * stash eviction). Must be called under [lock]. Returns true iff an
     * eviction happened, so the caller can rate-limit its warning log.
     *
     * [perKeyMax]/[totalMax] default to the screen-buffer bounds;
     * the unresolved-sender buffer passes its own, much smaller pair. The
     * eviction ORDER is the starvation-freedom property and must not be "reject the
     * incoming item": whichever key holds the most gives up its oldest entry, so a
     * flooding sender can only ever destroy its own parked blobs.
     */
    private fun <T> evictForCapacityLocked(
        map: MutableMap<String, MutableList<T>>,
        key: String,
        perKeyMax: Int = MAX_PENDING_CONTENT_PER_KEY,
        totalMax: Int = MAX_PENDING_CONTENT_TOTAL,
    ): Boolean {
        var evicted = false
        val perKey = map.getOrPut(key) { mutableListOf() }
        if (perKey.size >= perKeyMax) {
            perKey.removeAt(0)
            evicted = true
        }
        if (map.values.sumOf { it.size } >= totalMax) {
            map.entries.maxByOrNull { it.value.size }
                ?.value
                ?.takeIf { it.isNotEmpty() }
                ?.removeAt(0)
            evicted = true
        }
        return evicted
    }

    /** Hands [gm] to the GROUP screen [screenGroupId] (POLL-HANDOFF-1). */
    fun toGroupScreen(screenGroupId: String, gm: GroupMessage) = lock.withLock {
        val evicted = evictForCapacityLocked(groupScreenItems, screenGroupId)
        groupScreenItems.getValue(screenGroupId).add(gm)
        noteScreenOverflowLocked(evicted)
    }

    /** Hands [item] to the 1:1 screen [screenContactId] (POLL-HANDOFF-1). */
    fun toDirectScreen(screenContactId: String, item: DirectItem) = lock.withLock {
        val evicted = evictForCapacityLocked(directScreenItems, screenContactId)
        directScreenItems.getValue(screenContactId).add(item)
        noteScreenOverflowLocked(evicted)
    }

    private fun noteScreenOverflowLocked(evicted: Boolean) {
        if (evicted && !screenItemsOverflowWarned) {
            screenItemsOverflowWarned = true
            platformLogWarn(TAG, "screen buffer at capacity — evicted the oldest untaken item(s)")
        }
    }

    /** THE TAKE for a group screen: everything its polls fetched (OWN group texts,
     *  PRIVATE 1:1 texts, GROUP_ECHO texts of other groups) plus its system
     *  notices, in arrival order. RAM-only, non-suspending. */
    fun takeGroupScreenItems(groupId: String): List<GroupMessage> = lock.withLock {
        groupScreenItems.remove(groupId) ?: emptyList()
    }

    /** A left / removed-from group: drop its own screen items AND every echo of it
     *  sitting in another screen's buffer. */
    fun purgeGroupFromScreens(groupId: String) = lock.withLock {
        groupScreenItems.remove(groupId)
        for (list in groupScreenItems.values) list.removeAll { it.isGroupEcho && it.groupId == groupId }
        for (list in directScreenItems.values) list.removeAll { it.isGroupEcho && it.groupId == groupId }
    }

    fun bufferScreenshotNotice(notice: ScreenshotNotice) = lock.withLock {
        val list = pendingScreenshotNotices.getOrPut(notice.conversationId) { mutableListOf() }
        if (list.size >= MAX_PENDING_SCREENSHOT_NOTICES_PER_CONVERSATION) {
            platformLogWarn(TAG, "screenshot-notice buffer full for a conversation — dropping")
            return@withLock
        }
        list.add(notice)
    }

    fun drainScreenshotNotices(conversationId: String): List<ScreenshotNotice> = lock.withLock {
        pendingScreenshotNotices.remove(conversationId) ?: emptyList()
    }

    /** THE TAKE for a 1:1 screen: its own 1:1 texts and GROUP_ECHO items, in
     *  arrival order. RAM-only, non-suspending. */
    fun takeDirectScreenItems(contactId: String): List<DirectItem> = lock.withLock {
        directScreenItems.remove(contactId) ?: emptyList()
    }

    // The group dot's buffered term: per group screen, how many of its OWN items
    // (not PRIVATE 1:1 texts, not GROUP_ECHOs of another group — NO-PARK) are
    // waiting for the take.
    fun ownGroupCounts(): Map<String, Int> = lock.withLock {
        groupScreenItems.mapValues { (_, items) -> items.count { it.kind == ReceivedItemKind.OWN } }
            .filterValues { it > 0 }
    }

    // Session end (GroupManager.scrubInMemory).
    fun scrub() = lock.withLock {
        groupScreenItems.clear(); directScreenItems.clear(); pendingUnresolvedGroupText.clear()
        pendingActivityNotices.clear()
        // A fresh session should be able to warn again if it happens again.
        screenItemsOverflowWarned = false
        pendingUnresolvedOverflowWarned = false
        pendingActivityOverflowWarned = false
        // Screenshot notices carry a peer alias + contactId — social-graph
        // state in the same class as the buffers above, so it goes in the same
        // critical section. The DURABLE `ssn:` rows are deliberately NOT touched
        // here: this runs on ordinary lock/background, where dropping them would
        // lose a notice the user has not yet seen. They live inside the
        // encrypted vault, which the wipe paths crypto-erase wholesale, and they
        // hold no alias and no text.
        pendingScreenshotNotices.clear()
    }

    /** The 1:1 screen's already-parked items first, then [fresh]; the parked ones
     *  leave the buffer only when the drain is committed (shown). */
    fun parkedDirectOnly(
        contactId: String, mgr: MessageManager?,
        fresh: List<DirectItem> = emptyList(), parts: List<MessageManager.PendingPart> = emptyList(),
    ): PendingDrain<DirectItem> {
        val parked = lock.withLock { directScreenItems[contactId]?.toList() ?: emptyList() }
        return PendingDrain(parked + fresh, parts, mgr, onCommitted = if (parked.isEmpty()) null else {
            { lock.withLock { removeTakenLocked(directScreenItems, contactId, parked) } }
        })
    }

    /** Group-screen twin of [parkedDirectOnly]. */
    fun parkedGroupOnly(
        groupId: String, mgr: MessageManager?,
        fresh: List<GroupMessage> = emptyList(), parts: List<MessageManager.PendingPart> = emptyList(),
    ): PendingDrain<GroupMessage> {
        val parked = lock.withLock { groupScreenItems[groupId]?.toList() ?: emptyList() }
        return PendingDrain(parked + fresh, parts, mgr, onCommitted = if (parked.isEmpty()) null else {
            { lock.withLock { removeTakenLocked(groupScreenItems, groupId, parked) } }
        })
    }

    /** Removes exactly the [taken] entries (by identity) from [map]'s [key] list. */
    private fun <T> removeTakenLocked(map: MutableMap<String, MutableList<T>>, key: String, taken: List<T>) {
        val list = map[key] ?: return
        for (t in taken) {
            val i = list.indexOfFirst { it === t }
            if (i >= 0) list.removeAt(i)
        }
        if (list.isEmpty()) map.remove(key)
    }

    /**
     * Unresolved-sender buffer: park a decryptable group text whose sender isn't yet a resolved member.
     *
     * Bounded per (group, sender) AND globally, evicting
     * the OLDEST entry of whichever key holds the most — never rejecting the
     * arrival: a global-only cap that refused new texts would let one removed member
     * hold every slot and starve each honest sender whose resolution is still in
     * flight, and a refused arrival off a destructive drain is a permanently lost
     * message.
     */
    fun bufferUnresolvedGroupText(groupId: String, contactId: String, rm: ReceivedMessage) = lock.withLock {
        val key = unresolvedKey(groupId, contactId)
        val evicted = evictForCapacityLocked(
            pendingUnresolvedGroupText, key,
            perKeyMax = MAX_PENDING_UNRESOLVED_PER_SENDER,
            totalMax = MAX_PENDING_UNRESOLVED_GROUP_TEXTS,
        )
        pendingUnresolvedGroupText.getValue(key).add(PendingGroupText(rm, clock()))
        if (evicted && !pendingUnresolvedOverflowWarned) {
            pendingUnresolvedOverflowWarned = true
            platformLogWarn(TAG, "unresolved group-text buffer at capacity — evicted the oldest parked text(s)")
        }
    }

    /** Unresolved-sender buffer: re-attempt attribution of buffered unresolved-sender group texts.
     *  A now-resolved sender's texts are surfaced (into their group's screen buffer,
     *  taken when the group screen next polls); expired/orphaned entries are pruned. Cheap local
     *  reads; called after each roster apply and at group open. toGroupScreen is invoked
     *  OUTSIDE the lock (SyncLock is non-reentrant on iOS).
     *
     *  This lock is the one the UI thread takes in [takeGroupScreenItems] /
     *  [takeDirectScreenItems], so it is never held across SQLCipher: the parked
     *  entries are SNAPSHOT under it, resolved against the vault outside it, and the
     *  outcome is applied under it again to the CURRENT list, by identity. An entry
     *  that arrived after the snapshot is kept untouched; one that was evicted or
     *  scrubbed meanwhile is simply absent, so nothing a [scrub] dropped can
     *  be resurrected or delivered. */
    fun flushResolvedGroupTexts() {
        val now = clock()
        val snapshot: List<Pair<String, List<PendingGroupText>>> = lock.withLock {
            pendingUnresolvedGroupText.map { (key, list) -> key to list.toList() }
        }
        if (snapshot.isEmpty()) return
        // Vault reads, outside the lock.
        val groupGone = HashSet<String>()
        val ready = HashMap<String, List<Pair<PendingGroupText, GroupMessage>>>()
        for ((key, list) in snapshot) {
            val (gid, cid) = splitUnresolvedKey(key)
            val g = groupOf(gid)
            if (g == null) { groupGone.add(key); continue }
            val members = membersOf(gid)
            if (members.none { it.contactId == cid }) continue   // still unresolved
            ready[key] = list
                .filter { now - it.bufferedAt <= PENDING_UNRESOLVED_GROUP_TEXT_TTL_MS }
                .map { it to toMessage(cid, gid, g, members, it.rm) }
        }
        val deliver = mutableListOf<GroupMessage>()
        lock.withLock {
            for ((key, seen) in snapshot) {
                val current = pendingUnresolvedGroupText[key] ?: continue
                if (key in groupGone) { pendingUnresolvedGroupText.remove(key); continue }   // group gone
                val resolved = ready[key]
                val kept = mutableListOf<PendingGroupText>()
                for (p in current) {
                    if (seen.none { it === p }) { kept.add(p); continue }   // arrived after the snapshot
                    val message = resolved?.firstOrNull { it.first === p }?.second
                    when {
                        now - p.bufferedAt > PENDING_UNRESOLVED_GROUP_TEXT_TTL_MS -> { /* expired → drop */ }
                        message != null -> deliver.add(message)
                        else -> kept.add(p)
                    }
                }
                if (kept.isEmpty()) pendingUnresolvedGroupText.remove(key) else pendingUnresolvedGroupText[key] = kept
            }
        }
        for (gm in deliver) toGroupScreen(gm.groupId, gm)
    }

    /**
     * Parked activity-notice buffer: park a KIND_ACTIVITY notice whose group we have
     * not joined yet, or whose sender is not yet a resolved member. Bounded per
     * (group, sender) AND globally with the SAME caps and the SAME oldest-of-the-
     * biggest-key eviction as [bufferUnresolvedGroupText], so a flooding sender can
     * only ever destroy its own parked notices and never starve an honest one.
     */
    fun bufferActivityNotice(groupId: String, senderContactId: String, onGroupInbox: Boolean, noticeAtMs: Long) = lock.withLock {
        val key = unresolvedKey(groupId, senderContactId)
        val evicted = evictForCapacityLocked(
            pendingActivityNotices, key,
            perKeyMax = MAX_PENDING_UNRESOLVED_PER_SENDER,
            totalMax = MAX_PENDING_UNRESOLVED_GROUP_TEXTS,
        )
        pendingActivityNotices.getValue(key).add(PendingActivity(onGroupInbox, noticeAtMs, clock()))
        if (evicted && !pendingActivityOverflowWarned) {
            pendingActivityOverflowWarned = true
            platformLogWarn(TAG, "parked activity-notice buffer at capacity — evicted the oldest parked notice(s)")
        }
    }

    /**
     * Parked activity-notice buffer: replay every parked notice whose group now
     * EXISTS and whose sender is now a RESOLVED member — i.e. the roster apply /
     * invite accept just made it attributable. Each replay re-runs
     * [GroupUnreadTally.noteActivity] (through [applyNotice]) so the GROUP dot lights
     * for that sender's first message. Called after each roster apply and at invite
     * accept, exactly where [flushResolvedGroupTexts] is.
     *
     * Same lock discipline as [flushResolvedGroupTexts]: SNAPSHOT under [lock],
     * resolve against the vault OUTSIDE it (SyncLock is non-reentrant on iOS and must
     * never be held across SQLCipher), then re-apply to the CURRENT list by identity.
     * An entry that arrived after the snapshot is kept untouched; one scrubbed
     * meanwhile is simply absent. A still-unjoined group or still-unresolved sender
     * is KEPT until it resolves or its TTL expires; it is never dropped early, and it
     * is never a drainable message, so the only state it holds is a one-bit flag.
     * [applyNotice] runs OUTSIDE the lock.
     */
    fun flushResolvedActivityNotices() {
        val now = clock()
        val snapshot: List<Pair<String, List<PendingActivity>>> = lock.withLock {
            pendingActivityNotices.map { (key, list) -> key to list.toList() }
        }
        if (snapshot.isEmpty()) return
        // Vault reads, outside the lock.
        val resolved = HashSet<String>()   // keys whose (group, sender) are now attributable
        for ((key, _) in snapshot) {
            val (gid, cid) = splitUnresolvedKey(key)
            if (groupOf(gid) == null) continue                            // not joined yet — keep
            if (membersOf(gid).none { it.contactId == cid }) continue     // sender still unresolved — keep
            resolved.add(key)
        }
        val replay = mutableListOf<Pair<Triple<String, String, Boolean>, Long>>()   // ((groupId, senderContactId, onGroupInbox), noticeAtMs)
        lock.withLock {
            for ((key, seen) in snapshot) {
                val current = pendingActivityNotices[key] ?: continue
                val (gid, cid) = splitUnresolvedKey(key)
                val ready = key in resolved
                val kept = mutableListOf<PendingActivity>()
                for (p in current) {
                    if (seen.none { it === p }) { kept.add(p); continue }   // arrived after the snapshot
                    when {
                        now - p.bufferedAt > PENDING_UNRESOLVED_GROUP_TEXT_TTL_MS -> { /* expired → drop */ }
                        ready -> replay.add(Triple(gid, cid, p.onGroupInbox) to p.noticeAtMs)
                        else -> kept.add(p)
                    }
                }
                if (kept.isEmpty()) pendingActivityNotices.remove(key) else pendingActivityNotices[key] = kept
            }
        }
        for ((t, at) in replay) applyNotice(t.first, t.second, t.third, at)
    }
}

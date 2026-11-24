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
// NO-PARK: a conversation screen's poll RETURNS what it fetched (PendingDrain);
// nothing it fetches is parked for ANOTHER conversation. A 1:1 text fetched by a
// group poll is a PRIVATE item of THAT group screen; a group text fetched by a 1:1
// (or another group's) poll is a GROUP_ECHO item of THAT screen.
//
// What IS held here, and when it burns (RÚN-05; docs/vault-relay-internals.md
// "What a conversation buffer holds and when it burns"):
//  - a text whose sender is not confirmed yet (an unresolved group member, or a
//    group whose invite has not arrived): until it is handed on, or
//    PENDING_UNRESOLVED_GROUP_TEXT_TTL_MS after it was parked — enforced on every
//    read, and physically pruned by [pruneExpired] on each control sweep and each
//    conversation-screen poll (not on a timer: in a gap where neither runs it stays
//    in RAM until the next one or the scrub);
//  - a confirmed sender's text handed to a screen buffer (a resolved member, an
//    invite that arrived, system notices): until a screen of that key shows it AND
//    commits (`parked*Only` → commit), or the session ends;
//  - EVERYTHING ends at [scrub] (lock / background / wipe), which also SEALS the
//    instance: every later write is refused, so a poll or callback that finishes
//    after the session ended cannot park plaintext in it. A GroupManager — and so
//    this instance — is built per unlocked session and never reused after its scrub.
// A text the relay hands out twice (an abandoned screen poll, then the re-delivery)
// is held ONCE: holds dedupe on (sender, [ReceivedMessage.blobKey]) by REFRESHING the
// held entry (its stamp and, for an awaiting-invite text, its screen become the newest
// fetch's — that fetch's drain may be the one that acks the relay copy), and a held
// copy is dropped the moment the same blob is shown fresh ([forgetHeldCopies]).
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

    // Set by [scrub] and never cleared: the session this instance belongs to has
    // ended, and every write is refused from then on (RÚN-05). Guarded by [lock].
    private var sealed = false
    private var sealedWriteLogged = false

    /** True (and logs once, count-free) when the session has ended. Under [lock]. */
    private fun refusedLocked(): Boolean {
        if (!sealed) return false
        if (!sealedWriteLogged) {
            sealedWriteLogged = true
            platformLog(TAG, "conversation buffer write refused — the session has ended")
        }
        return true
    }

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

    // Texts of a not-yet-joined group that were SHOWN (as an echo) before the notice
    // announcing them was drained — per "groupId<NUL>senderContactId", how many
    // notices are still owed. The next notice for that key is spent against it
    // instead of being parked, so the join does not light a dot on an empty group.
    // Counts only, capped per key; guarded by [lock]; emptied by [scrub].
    private val shownAheadOfNotice = mutableMapOf<String, Int>()

    // Awaiting-invite buffer: a decryptable group text for a group this device does
    // not know AT ALL — no group row and no invite awaiting an answer. Usually that
    // is a group we left or declined, and the text is rightly never shown. But it is
    // also what the FIRST text of a brand-new group looks like when the screen's
    // drain (the sender's text inbox) beats the control sweep that carries the
    // invite: the push for that text is what makes the user open the app and tap
    // the sender. The drain acks what it fetched, so dropping the text there loses
    // it for good. It is held here instead — same key, caps, eviction and TTL as
    // [pendingUnresolvedGroupText] — together with the screen that fetched it
    // (null = the sender's 1:1 screen), and handed to that screen the moment an
    // invite for exactly this group arrives FROM THAT SENDER
    // ([takeTextsAwaitingInvite]). Anything else expires unseen. Guarded by [lock];
    // emptied by [scrub].
    private data class PendingUninvited(val rm: ReceivedMessage, val screenGroupId: String?, val bufferedAt: Long)
    private val pendingUninvitedGroupText = mutableMapOf<String, MutableList<PendingUninvited>>()

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
        if (refusedLocked()) return@withLock
        val evicted = evictForCapacityLocked(groupScreenItems, screenGroupId)
        groupScreenItems.getValue(screenGroupId).add(gm)
        noteScreenOverflowLocked(evicted)
    }

    /** Hands [item] to the 1:1 screen [screenContactId] (POLL-HANDOFF-1). */
    fun toDirectScreen(screenContactId: String, item: DirectItem) = lock.withLock {
        if (refusedLocked()) return@withLock
        val evicted = evictForCapacityLocked(directScreenItems, screenContactId)
        directScreenItems.getValue(screenContactId).add(item)
        noteScreenOverflowLocked(evicted)
    }

    /**
     * The blob [blobKey] from [senderContactId] was just decrypted again and is being
     * shown FRESH (the relay re-delivered it after a poll that was never committed):
     * drop every copy of it still held here, so it is shown once. Safe against loss:
     * a fresh copy exists only because the relay still holds that blob (a committed
     * blob is deleted on the relay and a re-served one no longer decrypts), so if this
     * new copy is not shown either, the relay hands it out again. An empty key matches
     * nothing.
     */
    fun forgetHeldCopies(senderContactId: String, blobKey: String) {
        if (blobKey.isEmpty()) return
        lock.withLock {
            removeHeldLocked(pendingUnresolvedGroupText, senderContactId) { it.rm.blobKey == blobKey }
            removeHeldLocked(pendingUninvitedGroupText, senderContactId) { it.rm.blobKey == blobKey }
            for (list in groupScreenItems.values) {
                list.removeAll { it.senderContactId == senderContactId && it.blobKey == blobKey }
            }
            groupScreenItems.entries.removeAll { it.value.isEmpty() }
            for (list in directScreenItems.values) {
                list.removeAll { it.contactId == senderContactId && it.blobKey == blobKey }
            }
            directScreenItems.entries.removeAll { it.value.isEmpty() }
        }
    }

    /** Removes the entries matching [drop] from every "groupId<NUL>[senderContactId]"
     *  key of [map] (an empty key goes too). Must be called under [lock]. */
    private fun <T> removeHeldLocked(
        map: MutableMap<String, MutableList<T>>, senderContactId: String, drop: (T) -> Boolean,
    ) {
        val entries = map.entries.iterator()
        while (entries.hasNext()) {
            val e = entries.next()
            if (splitUnresolvedKey(e.key).second != senderContactId) continue
            e.value.removeAll(drop)
            if (e.value.isEmpty()) entries.remove()
        }
    }

    /**
     * When [map]'s [key] already holds a text with this non-empty blob identity, REPLACE
     * that entry in place with [fresh] (new stamp, new screen) and return true; else
     * false. Replaced, not mutated: a flush that snapshotted the old entry finds it gone
     * and treats the new one as a later arrival, so neither copy is delivered twice.
     * Must be called under [lock].
     */
    private fun <T> refreshHeldLocked(
        map: MutableMap<String, MutableList<T>>, key: String, blobKey: String, keyOf: (T) -> String, fresh: () -> T,
    ): Boolean {
        if (blobKey.isEmpty()) return false
        val list = map[key] ?: return false
        val i = list.indexOfFirst { keyOf(it) == blobKey }
        if (i < 0) return false
        list[i] = fresh()
        return true
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
        if (refusedLocked()) return@withLock
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

    /** How many decrypted TEXTS this instance holds right now, in every buffer
     *  (screen buffers, unresolved-sender, awaiting-invite). Count only — tests. */
    fun heldTextCount(): Int = lock.withLock {
        groupScreenItems.values.sumOf { it.size } + directScreenItems.values.sumOf { it.size } +
            pendingUnresolvedGroupText.values.sumOf { it.size } + pendingUninvitedGroupText.values.sumOf { it.size }
    }

    // Session end (GroupManager.scrubInMemory): empties every buffer AND seals the
    // instance — no write is accepted afterwards (see the header).
    fun scrub() = lock.withLock {
        sealed = true
        groupScreenItems.clear(); directScreenItems.clear(); pendingUnresolvedGroupText.clear()
        pendingActivityNotices.clear()
        pendingUninvitedGroupText.clear()
        shownAheadOfNotice.clear()
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
        if (refusedLocked()) return@withLock
        val key = unresolvedKey(groupId, contactId)
        // The same blob again (the relay re-delivered what an abandoned poll decrypted):
        // held once — but REFRESHED, never skipped. This decrypt may be the one whose
        // drain commits (acks the relay copy), so from now on the held copy is the only
        // one and its TTL must run from now, not from the abandoned first decrypt.
        if (refreshHeldLocked(pendingUnresolvedGroupText, key, rm.blobKey, { it.rm.blobKey }) { PendingGroupText(rm, clock()) }) {
            return@withLock
        }
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
     * Awaiting-invite buffer: hold a group text for a group this device does not
     * know, fetched by [screenGroupId]'s poll (null = [contactId]'s 1:1 screen).
     * Expired entries of every key are pruned on the way in, so a sender whose
     * invite never comes cannot keep plaintext here past the TTL by sending more.
     * Never rejects the arrival (same eviction as [bufferUnresolvedGroupText]).
     */
    fun bufferTextAwaitingInvite(groupId: String, contactId: String, rm: ReceivedMessage, screenGroupId: String?) = lock.withLock {
        if (refusedLocked()) return@withLock
        val now = clock()
        pruneExpiredLocked(pendingUninvitedGroupText, now) { it.bufferedAt }
        val key = unresolvedKey(groupId, contactId)
        // Same blob again: refresh, don't skip — the stamp AND the screen become this
        // (newest) fetch's, so the text goes to the screen the user is in now, with a
        // TTL that runs from the decrypt whose drain may be the one that commits.
        if (refreshHeldLocked(pendingUninvitedGroupText, key, rm.blobKey, { it.rm.blobKey }) { PendingUninvited(rm, screenGroupId, now) }) {
            return@withLock
        }
        evictForCapacityLocked(
            pendingUninvitedGroupText, key,
            perKeyMax = MAX_PENDING_UNRESOLVED_PER_SENDER,
            totalMax = MAX_PENDING_UNRESOLVED_GROUP_TEXTS,
        )
        pendingUninvitedGroupText.getValue(key).add(PendingUninvited(rm, screenGroupId, now))
    }

    /**
     * Drops every expired entry of the three TTL-bound buffers (unresolved-sender
     * texts, awaiting-invite texts, parked activity notices) across ALL keys. The reads
     * already refuse an expired entry; this is the physical removal, run by the
     * control sweep and the conversation-screen polls (GroupManager.pruneExpiredPending)
     * so an expired text does not wait for an unrelated event (a roster, the next
     * arrival). Not a timer. RAM only, no vault; returns how many were dropped.
     */
    fun pruneExpired(): Int = lock.withLock {
        // The common case holds nothing: no clock read, no walk.
        if (pendingUnresolvedGroupText.isEmpty() && pendingUninvitedGroupText.isEmpty() && pendingActivityNotices.isEmpty()) {
            return@withLock 0
        }
        val now = clock()
        pruneExpiredLocked(pendingUnresolvedGroupText, now) { it.bufferedAt } +
            pruneExpiredLocked(pendingUninvitedGroupText, now) { it.bufferedAt } +
            pruneExpiredLocked(pendingActivityNotices, now) { it.bufferedAt }
    }

    /** Drops [map] entries older than the TTL (strictly `>`, like every read), across
     *  all keys. Must be called under [lock]; returns how many went. */
    private fun <T> pruneExpiredLocked(map: MutableMap<String, MutableList<T>>, now: Long, bufferedAt: (T) -> Long): Int {
        var dropped = 0
        val entries = map.entries.iterator()
        while (entries.hasNext()) {
            val e = entries.next()
            val before = e.value.size
            e.value.removeAll { now - bufferedAt(it) > PENDING_UNRESOLVED_GROUP_TEXT_TTL_MS }
            dropped += before - e.value.size
            if (e.value.isEmpty()) entries.remove()
        }
        return dropped
    }

    /**
     * Awaiting-invite buffer: an invite for [groupId] from [inviterContactId] was
     * just parked — TAKE (remove) every unexpired text that contact sent for that
     * group, oldest first, each with the screen that fetched it. Texts the same
     * group got from any OTHER contact stay held and expire: before we join, only
     * the inviter can be told apart from a stranger.
     */
    fun takeTextsAwaitingInvite(groupId: String, inviterContactId: String): List<Pair<ReceivedMessage, String?>> = lock.withLock {
        val now = clock()
        val list = pendingUninvitedGroupText.remove(unresolvedKey(groupId, inviterContactId)) ?: return@withLock emptyList()
        list.filter { now - it.bufferedAt <= PENDING_UNRESOLVED_GROUP_TEXT_TTL_MS }.map { it.rm to it.screenGroupId }
    }

    /**
     * Parked activity-notice buffer: a text of the not-yet-joined [groupId] from
     * [senderContactId] was just SHOWN in another screen, so the notice that
     * announced it has nothing left to point at — forget the oldest one, or the
     * join would light a dot on an empty group. When none is parked the notice has
     * simply not been drained yet (text inbox before control inbox): remember that
     * one is owed, and [bufferActivityNotice] spends the next arrival against it.
     */
    fun spendActivityNoticeForShownText(groupId: String, senderContactId: String) = lock.withLock {
        if (refusedLocked()) return@withLock
        val key = unresolvedKey(groupId, senderContactId)
        val list = pendingActivityNotices[key]
        if (list != null && list.isNotEmpty()) {
            list.removeAt(0)
            if (list.isEmpty()) pendingActivityNotices.remove(key)
        } else {
            val owed = shownAheadOfNotice[key] ?: 0
            if (owed < MAX_PENDING_UNRESOLVED_PER_SENDER) shownAheadOfNotice[key] = owed + 1
        }
    }

    /**
     * Parked activity-notice buffer: park a KIND_ACTIVITY notice whose group we have
     * not joined yet, or whose sender is not yet a resolved member. Bounded per
     * (group, sender) AND globally with the SAME caps and the SAME oldest-of-the-
     * biggest-key eviction as [bufferUnresolvedGroupText], so a flooding sender can
     * only ever destroy its own parked notices and never starve an honest one.
     */
    fun bufferActivityNotice(groupId: String, senderContactId: String, onGroupInbox: Boolean, noticeAtMs: Long) = lock.withLock {
        if (refusedLocked()) return@withLock
        val key = unresolvedKey(groupId, senderContactId)
        // The text this notice announces was already shown ([spendActivityNoticeForShownText]).
        val owed = shownAheadOfNotice[key] ?: 0
        if (owed > 0) {
            if (owed == 1) shownAheadOfNotice.remove(key) else shownAheadOfNotice[key] = owed - 1
            return@withLock
        }
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

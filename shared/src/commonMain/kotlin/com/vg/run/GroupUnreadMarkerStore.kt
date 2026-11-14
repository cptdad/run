package com.vg.run

import com.vg.run.GroupManager.Companion.MAX_PENDING_ACTIVITY_PER_MEMBER

// ---------------------------------------------------------------------------
// GroupUnreadMarkerStore — the DURABLE half of the group unread attribution.
//
// WHY THIS EXISTS (prod bug, owner decision 2026-11-12 "store in vault"). A
// sender's KIND_ACTIVITY notice with the `gi` marker is the ONLY thing that says
// WHICH group a text on the pairwise GROUP inbox belongs to. The notice is
// consumed off the relay when the control inbox drains, and its effect lived only
// in RAM ([GroupUnreadTally]). After a session teardown (every background on
// Android, every lock on iOS) the next session saw only the `/peek` depth of that
// contact's group inbox, so `unattributed = depth − noticed > 0` and the presence
// bump lit EVERY group shared with that sender — a user with one new group message
// got a dot on all of their groups. This store mirrors, per sender contact, which
// group(s) its still-pending `gi` notices named, so the next session restores the
// right dot instead.
//
// WHAT IT STORES, exactly (no plaintext, no alias, no capability, no key material):
//   key   `grp-unread/<contactId>`
//   value `v1;<groupId>=<ms>,<ms>;<groupId>=<ms>;*=<ms>`
// One `<ms>` per still-pending `gi` notice ("unit"), minute-rounded, grouped by
// the groupId it named. `*` is a DETACHED unit: the notice still accounts for one
// blob on that contact's group inbox (so it still suppresses the presence bump),
// but it no longer lights any group — the group was opened, left/deleted, or the
// sender is no longer a member of it. At most [MAX_UNITS] units per contact (the
// same per-member ceiling the RAM tally applies).
//
// LIFECYCLE (GroupManager drives every call, in lockstep with the RAM tally):
//   record       — a `gi` notice the tally COUNTED (never one the ceiling ignored)
//   clear        — that contact's group inbox was drained (authoritative)
//   removeOne    — one group text from that contact was consumed / shown elsewhere
//   detachGroup  — the group was opened, left or deleted
//   detachMember — the sender was removed from / left the group
//   healTo       — a DEFINITE peek answered a depth below the unit count
//   restore      — once per session, at GroupManager construction
// TTL: a unit older than [MARKER_TTL_MS] (a group text's relay lifetime) is
// dropped on every write and at restore; a unit stamped in the future beyond
// [FUTURE_SKEW_MS] is dropped too, so no unit can outlive its text indefinitely.
//
// PURGE COUPLING: the key is per contact and is in `ratchetMetaKeysForContact`
// (ContactMetaPurge.kt), the single list both VaultDatabase actuals iterate on
// deleteContact. It is deliberately NOT a `GroupMetaKeys` key: a group delete does
// not delete it, GroupManager DETACHES that group's units instead (a text for a
// left group still sits on the sender's group inbox and must keep suppressing the
// bump on the groups we still share), and restore detaches any unit whose group or
// membership is gone, so no groupId survives its group past the next session.
// Device move: NOT exported — see MoveMetaPolicy.deniedPrefixes.
//
// FAIL-SOFT, NEVER FAIL-CLOSED. Every method swallows its own errors (class name
// logged, nothing else) and degrades to "no persisted attribution", which is the
// pre-existing behaviour: the presence bump. On iOS `putMeta` throws on a locked
// keybag; a unread dot is never worth taking down the control drain. A missing or
// undecodable value is ignored and deleted. Nothing here is ever an input to a
// wipe, a lock, a credential or a contact-row decision.
//
// THREADING. Every read-modify-write runs inside ONE [VaultDatabase.withTransaction].
// The only lock is [indexLock], which guards a RAM index and is NEVER held across a
// vault call. Callers must not invoke this while holding the GroupUnreadTally lock
// or any other SyncLock (non-reentrant on iOS), nor from inside a vault
// transaction of their own.
// ---------------------------------------------------------------------------
internal class GroupUnreadMarkerStore(
    private val vault: VaultDatabase,
    private val clock: () -> Long = { currentTimeMillis() },
) {
    /** One still-pending `gi` notice. [groupId] null = detached (accounts, lights nothing). */
    internal data class MarkerUnit(val groupId: String?, val atMs: Long)

    companion object {
        private const val TAG = "GroupUnreadMarkerStore"

        /** `grp-unread/` — HYPHEN on purpose: the move allowlist's `grp_` must not match it. */
        internal const val PREFIX = "grp-unread/"
        private const val VERSION = "v1"
        private const val DETACHED = "*"

        /**
         * A group TEXT carries no `?ttl` and expires on the relay's 24 h default, so
         * no unit may describe a text older than that.
         */
        internal const val MARKER_TTL_MS: Long = 24L * 60 * 60 * 1000

        /** A stamp further in the future than this is untrustworthy (clock stepped back) and dropped. */
        internal const val FUTURE_SKEW_MS: Long = 5L * 60 * 1000

        /** Same bound the RAM tally applies per member ([GroupUnreadTally.noteActivity]). */
        internal const val MAX_UNITS = MAX_PENDING_ACTIVITY_PER_MEMBER

        /** Hard ceiling on a value we are willing to parse (99 units fit in ~4 KiB). */
        private const val MAX_VALUE_CHARS = 16 * 1024

        private const val MINUTE_MS = 60_000L

        internal fun keyFor(contactId: String): String = PREFIX + contactId

        /**
         * Ids are embedded verbatim between the value's delimiters, so anything
         * carrying one of them (or empty) is refused. contactIds are UUIDs and
         * groupIds Base64Url, so this never rejects a real id.
         */
        internal fun isStorableId(id: String): Boolean =
            id.isNotEmpty() && id.length <= 128 &&
                id.none { it == ';' || it == '=' || it == ',' || it == '*' || it == ':' || it == '|' || it == '/' }

        /**
         * The stamp a unit carries: the sender's claimed envelope time when it is
         * positive and not in our future, otherwise our clock; minute-rounded
         * either way (the envelope time already is), so the vault holds nothing
         * finer than the wire did. The claimed time is the better anchor for the
         * TTL — a text expires 24 h after it was POSTED, not after we drained its
         * notice — and a peer can only make its own unit expire EARLIER with it.
         */
        internal fun stampFor(claimedSentAtMs: Long, nowMs: Long): Long {
            val t = if (claimedSentAtMs in 1..nowMs) claimedSentAtMs else nowMs
            return t - (t % MINUTE_MS)
        }

        /** Units oldest-first. Inverse of [decode]. */
        internal fun encode(units: List<MarkerUnit>): String {
            val sorted = units.sortedBy { it.atMs }
            val byGroup = LinkedHashMap<String, MutableList<Long>>()
            for (u in sorted) byGroup.getOrPut(u.groupId ?: DETACHED) { mutableListOf() }.add(u.atMs)
            val sb = StringBuilder(VERSION)
            for ((g, stamps) in byGroup) {
                sb.append(';').append(g).append('=').append(stamps.joinToString(","))
            }
            return sb.toString()
        }

        /**
         * STRICT decode, oldest-first. Anything this store never writes — a wrong
         * version, an empty or duplicated section, a bad id, a non-positive or
         * non-numeric stamp, more than [MAX_UNITS] units — answers null, and the
         * caller deletes the row as residue. Never throws.
         */
        internal fun decode(value: String): List<MarkerUnit>? {
            if (value.length > MAX_VALUE_CHARS) return null
            val sections = value.split(';')
            if (sections.isEmpty() || sections[0] != VERSION || sections.size < 2) return null
            val seen = HashSet<String>()
            val out = mutableListOf<MarkerUnit>()
            for (i in 1 until sections.size) {
                val s = sections[i]
                val eq = s.indexOf('=')
                if (eq <= 0 || eq == s.length - 1) return null
                val g = s.substring(0, eq)
                if (g != DETACHED && !isStorableId(g)) return null
                if (!seen.add(g)) return null
                for (part in s.substring(eq + 1).split(',')) {
                    if (part.isEmpty() || part.length > 15 || part.any { it !in '0'..'9' }) return null
                    val ms = part.toLongOrNull() ?: return null
                    if (ms <= 0L) return null
                    out.add(MarkerUnit(if (g == DETACHED) null else g, ms))
                    if (out.size > MAX_UNITS) return null
                }
            }
            return out.sortedBy { it.atMs }
        }

        internal fun isLive(u: MarkerUnit, nowMs: Long): Boolean =
            nowMs - u.atMs <= MARKER_TTL_MS && u.atMs <= nowMs + FUTURE_SKEW_MS
    }

    // RAM index: contactId → groupIds that contact's marker holds GROUPED units for
    // (empty set = only detached units). `null` = UNKNOWN (before [restore], or its
    // enumeration failed): every operation then asks the vault directly. It exists
    // so the hot paths — a drain per member per group poll, a detach per group open —
    // cost zero vault I/O in the steady state where no marker exists. Contact/group
    // ids: social-graph state, cleared by [scrub] with the rest of the session.
    private val indexLock = SyncLock()
    private var index: MutableMap<String, MutableSet<String>>? = null

    private fun mayHave(contactId: String): Boolean =
        indexLock.withLock { index?.containsKey(contactId) ?: true }

    private fun indexSet(contactId: String, units: List<MarkerUnit>) = indexLock.withLock {
        val idx = index ?: return@withLock
        if (units.isEmpty()) idx.remove(contactId)
        else idx[contactId] = units.mapNotNullTo(mutableSetOf()) { it.groupId }
    }

    /** Contacts that may hold units for [groupId]; null = unknown (scan the vault). */
    private fun candidatesFor(groupId: String): List<String>? = indexLock.withLock {
        index?.filter { (_, groups) -> groupId in groups }?.keys?.toList()
    }

    /** Session end: the index is contactIds + groupIds and dies with the session. */
    fun scrub() = indexLock.withLock { index = null }

    /**
     * Read-modify-write of one contact's marker inside ONE transaction. A corrupt
     * value reads as empty, so it is overwritten (or deleted when the change leaves
     * nothing). Never throws.
     */
    private fun rewrite(contactId: String, what: String, change: (List<MarkerUnit>) -> List<MarkerUnit>) {
        if (!isStorableId(contactId)) return
        val key = keyFor(contactId)
        try {
            var result: List<MarkerUnit> = emptyList()
            vault.withTransaction {
                val raw = vault.getMeta(key)
                val current = raw?.let { decode(it) } ?: emptyList()
                val next = change(current)
                if (next.isEmpty()) {
                    if (raw != null) vault.deleteMeta(key)
                } else {
                    val enc = encode(next)
                    if (enc != raw) vault.putMeta(key, enc)
                }
                result = next
            }
            indexSet(contactId, result)
        } catch (e: Exception) {
            platformLogWarn(TAG, "$what failed — the presence bump stays the fallback: ${e::class.simpleName}")
        }
    }

    /** One `gi` notice from [contactId] naming [groupId] that the RAM tally COUNTED. */
    fun record(contactId: String, groupId: String, atMs: Long) {
        if (!isStorableId(groupId)) return
        val now = clock()
        val unit = MarkerUnit(groupId, atMs)
        rewrite(contactId, "unread marker write") { cur ->
            val live = cur.filter { isLive(it, now) }
            // A unit already past the TTL describes a text the relay no longer holds.
            (if (isLive(unit, now)) live + unit else live)
                .sortedBy { it.atMs }
                .takeLast(MAX_UNITS)
        }
    }

    /** [contactId]'s group inbox was drained: nothing of it is left to attribute. */
    fun clear(contactId: String) {
        if (!isStorableId(contactId) || !mayHave(contactId)) return
        try {
            val key = keyFor(contactId)
            if (vault.getMeta(key) != null) vault.deleteMeta(key)
            indexSet(contactId, emptyList())
        } catch (e: Exception) {
            platformLogWarn(TAG, "unread marker clear failed: ${e::class.simpleName}")
        }
    }

    /** One group text of [groupId] from [contactId] was consumed / shown elsewhere. */
    fun removeOne(contactId: String, groupId: String) {
        if (!mayHave(contactId)) return
        rewrite(contactId, "unread marker shrink") { cur ->
            val i = cur.indexOfFirst { it.groupId == groupId }
            if (i < 0) cur else cur.filterIndexed { j, _ -> j != i }
        }
    }

    /** [contactId]'s units for [groupId] stop lighting that group but keep accounting. */
    fun detachMember(contactId: String, groupId: String) {
        if (!mayHave(contactId)) return
        rewrite(contactId, "unread marker detach") { cur ->
            cur.map { if (it.groupId == groupId) it.copy(groupId = null) else it }
        }
    }

    /** Every contact's units for [groupId] stop lighting it (opened, left or deleted). */
    fun detachGroup(groupId: String) {
        val contacts = candidatesFor(groupId) ?: scanContacts() ?: return
        for (c in contacts) detachMember(c, groupId)
    }

    /**
     * A DEFINITE peek answered [depth] for [contactId]'s group inbox. If the marker
     * claims more units than that, keep only the NEWEST [depth] (the oldest texts
     * are the ones that expired first); a depth of 0 deletes the marker. Only ever
     * called with an answered depth — an unknown peek never reaches here.
     */
    fun healTo(contactId: String, depth: Int) {
        if (!mayHave(contactId)) return
        if (depth <= 0) { clear(contactId); return }
        // Steady state (depth covers every unit): one read, no transaction, no write.
        val raw = try { vault.getMeta(keyFor(contactId)) } catch (e: Exception) {
            platformLogWarn(TAG, "unread marker heal read failed: ${e::class.simpleName}")
            return
        } ?: run { indexSet(contactId, emptyList()); return }
        val units = decode(raw)
        if (units != null && units.size <= depth) return
        rewrite(contactId, "unread marker heal") { cur -> if (cur.size > depth) cur.takeLast(depth) else cur }
    }

    private fun scanContacts(): List<String>? = try {
        vault.metaKeys().filter { it.startsWith(PREFIX) }.map { it.substring(PREFIX.length) }
    } catch (e: Exception) {
        platformLogWarn(TAG, "unread marker scan failed: ${e::class.simpleName}")
        null
    }

    /**
     * ONCE per session (GroupManager construction): every marker, pruned and
     * validated, oldest-first per contact. Per row: undecodable, or for a contact
     * that no longer exists ⇒ DELETED (residue); expired / future units dropped;
     * a unit whose group is gone or whose sender is no longer a resolved member of
     * it ⇒ DETACHED; an emptied row ⇒ deleted; a changed row ⇒ rewritten.
     *
     * Fail soft at every level: an enumeration failure returns nothing (the index
     * stays UNKNOWN, so later operations still reach the vault); a row whose read
     * or validation throws is skipped, left untouched, and kept in the index as
     * "may have". Never throws.
     */
    fun restore(
        contactExists: (String) -> Boolean,
        isMember: (contactId: String, groupId: String) -> Boolean,
    ): Map<String, List<MarkerUnit>> {
        val now = clock()
        val keys = try {
            vault.metaKeys().filter { it.startsWith(PREFIX) }
        } catch (e: Exception) {
            platformLogWarn(TAG, "unread marker restore skipped — enumeration failed: ${e::class.simpleName}")
            return emptyMap()
        }
        val idx = mutableMapOf<String, MutableSet<String>>()
        val out = mutableMapOf<String, List<MarkerUnit>>()
        for (key in keys) {
            val c = key.substring(PREFIX.length)
            try {
                val raw = vault.getMeta(key) ?: continue
                val units = if (isStorableId(c)) decode(raw) else null
                if (units == null || !contactExists(c)) {
                    vault.deleteMeta(key)
                    platformLogWarn(TAG, "unusable unread marker deleted")
                    continue
                }
                val kept = units
                    .filter { isLive(it, now) }
                    .map { u -> if (u.groupId != null && !isMember(c, u.groupId)) u.copy(groupId = null) else u }
                    .takeLast(MAX_UNITS)
                if (kept.isEmpty()) {
                    vault.deleteMeta(key)
                    continue
                }
                val enc = encode(kept)
                if (enc != raw) vault.putMeta(key, enc)
                idx[c] = kept.mapNotNullTo(mutableSetOf()) { it.groupId }
                out[c] = kept
            } catch (e: Exception) {
                platformLogWarn(TAG, "unread marker restore of one row failed: ${e::class.simpleName}")
                // Unknown state: keep it reachable so a later drain/heal still clears it.
                idx[c] = mutableSetOf()
            }
        }
        indexLock.withLock { index = idx }
        return out
    }
}

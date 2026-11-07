package com.vg.run

// ---------------------------------------------------------------------------
// ScreenshotNoticeStore — the `_meta` namespace that makes a received
// "screenshot taken" notice survive the destructive control drain, the session
// teardown that follows every backgrounding, and process death.
//
// WHY THIS EXISTS (docs/screenshot-notice-persistence-design.md §0). The notice
// rides a push-suppressed control envelope, so it is delivered only by the
// app-wide background control sweep — a DESTRUCTIVE relay drain. Before this it
// was then parked in a RAM-only per-conversation buffer that
// `GroupManager.scrubInMemory()` clears on lock/background. Unless the receiver
// had that exact conversation open at drain time the notice was gone for good:
// nothing on the relay (already deleted) and nothing on the device. That is the
// production bug this store fixes.
//
// WHERE IT LIVES. The ENCRYPTED VAULT's `_meta` table, exactly like the Double
// Ratchet's `dr-*` state and the referral handshake records — NOT the platform
// KeyValueStore/Keychain, and deliberately NOT a new table: a schema bump would
// make the vault file unopenable by an older binary ("Can't downgrade"), while
// `_meta` reuses the purge machinery both `VaultDatabase` actuals already
// iterate. No migration is needed or performed; an install with no `ssn:` rows
// simply has nothing to show.
//
// WHAT IT STORES, exactly: key `ssn:<conversationId>:<senderContactId>:<receivedAtMs>`,
// value `<takenAtMs>|<isGroup 0/1>|<seen 0/1>`. No alias, no text, no capability,
// no key material — ids the vault already holds in its own tables plus two
// timestamps. Bounded at [MAX_PER_CONVERSATION] rows per conversation and
// self-expiring after [SCREENSHOT_NOTICE_TTL_MS]; pruned on write, on read, and
// on the background control sweep (SessionManagers).
//
// PURGE COUPLING (the rule from docs/vault-relay-internals.md): these keys are
// classified by `isScreenshotNoticeResidueForContact` / `…ForGroup` in
// ContactMetaPurge.kt beside `GroupMetaKeys`, and BOTH actuals plus the commonTest
// `InMemoryVault` iterate them on deleteContact/deleteGroup. They are NOT in
// `ratchetMetaKeysForContact` — that is an EXACT-key list and these keys carry a
// variable `receivedAt` suffix, so only a predicate can name them all.
//
// NOTIFICATIONS ARE UNCHANGED: a notice is sent with `X-No-Push`, so it never
// wakes a device and never raises a banner. Persisting it does not promote it to
// a message; it only means the conversation can still render it later.
//
// FAIL-SOFT, NEVER FAIL-CLOSED. Every method swallows its own errors and
// degrades to "no persisted notices". On iOS `putMeta` genuinely throws when the
// keybag is locked mid-write, and a screenshot courtesy notice is never worth
// taking down a poll loop — the caller keeps the RAM-only behaviour for the open
// screen. Nothing here is ever an input to a wipe, a lock, or a credential
// decision.
// ---------------------------------------------------------------------------

/**
 * How long a received screenshot notice stays visible. Anchored on the LOCAL
 * receive time, never on the sender's claimed capture time — see
 * [ScreenshotNoticeStore.clampTakenAt] and the ScreenshotNotice.kt header.
 */
const val SCREENSHOT_NOTICE_TTL_MS: Long = 24L * 60 * 60 * 1000

/**
 * One persisted notice as it round-trips through `_meta`. [takenAt] is the
 * already-clamped DISPLAY time; [receivedAt] is our clock and the only value
 * ordering and expiry are derived from.
 */
internal data class StoredScreenshotNotice(
    val conversationId: String,
    val isGroup: Boolean,
    val senderContactId: String,
    val takenAt: Long,
    val receivedAt: Long,
    val seen: Boolean,
) {
    val expiresAt: Long get() = receivedAt + SCREENSHOT_NOTICE_TTL_MS
}

/**
 * Durable, bounded, self-expiring storage for received screenshot notices.
 *
 * Owned by [GroupManager] (the single surface for both the 1:1 and the group
 * notice, and the one that already holds the vault). Holds NO cache of its own:
 * every method reads the vault, so lock/wipe needs no participation from it and
 * `scrubInMemory` has nothing here to clear.
 *
 * [clock] is injectable purely for tests; production always passes the default.
 * Blocking vault I/O — call from the same background context as the polls.
 *
 * THREADING: no lock of its own. `record` performs its evict+insert inside ONE
 * [VaultDatabase.withTransaction], and every caller must invoke it OUTSIDE
 * the [ConversationBuffers] lock — [SyncLock] is non-reentrant on iOS and a vault
 * write under it would serialise the buffers behind SQLCipher.
 */
internal class ScreenshotNoticeStore(
    private val vault: VaultDatabase,
    private val clock: () -> Long = { currentTimeMillis() },
) {
    companion object {
        private const val TAG = "ScreenshotNoticeStore"

        /**
         * Ceiling on PERSISTED notices per conversation; the oldest is evicted on
         * insert. Mirrors [GroupManager.MAX_PENDING_SCREENSHOT_NOTICES_PER_CONVERSATION]
         * (the RAM buffer's bound) for the same reason: a member is authenticated
         * but not trusted, and without a bound one could grow the vault — and the
         * UI's render list — without limit. Far above honest use; a screenshot is a
         * rare, deliberate user action.
         */
        internal const val MAX_PER_CONVERSATION = 16

        /**
         * How far into the future a sender's claimed capture time may sit and still
         * be believed (then clamped to our receive time). Covers ordinary clock skew
         * plus the envelope's minute rounding; anything beyond it is treated as a
         * bogus clock and the display falls back to our own receive time.
         */
        internal const val CLOCK_SKEW_TOLERANCE_MS = 5L * 60 * 1000

        /** Bound on the 1-ms collision walk (see [record]); far above any real burst. */
        private const val MAX_COLLISION_BUMPS = 64

        /**
         * The DISPLAY time for a notice: the sender's claimed capture time when it is
         * plausible, our receive time otherwise.
         *
         * Accepted iff `0 < claimed <= receivedAt + CLOCK_SKEW_TOLERANCE_MS` and
         * `receivedAt - claimed <= SCREENSHOT_NOTICE_TTL_MS`; a value inside the
         * tolerance but still in the future is clamped down to [receivedAt] so a
         * notice can never render with a time the device has not reached yet.
         *
         * This is EXACTLY the trust a received text bubble already places in the
         * peer's clock, and it is display-only: expiry, ordering, unread and every
         * security decision use [receivedAt].
         */
        internal fun clampTakenAt(claimed: Long, receivedAt: Long): Long = when {
            claimed <= 0L -> receivedAt
            claimed > receivedAt + CLOCK_SKEW_TOLERANCE_MS -> receivedAt
            receivedAt - claimed > SCREENSHOT_NOTICE_TTL_MS -> receivedAt
            claimed > receivedAt -> receivedAt
            else -> claimed
        }

        /**
         * Ids are embedded verbatim in a `:`-delimited key, so anything carrying a
         * `:` (or empty) would make the key ambiguous for the purge classifiers.
         * contactIds are UUIDs and groupIds Base64Url, so this never rejects a real
         * id — it is the shape gate that keeps a malformed one out of the namespace
         * entirely (mirrors ReferralStore.isValidIntroId), degrading to RAM-only.
         */
        internal fun isStorableId(id: String): Boolean =
            id.isNotEmpty() && !id.contains(':') && !id.contains('|') && id.length <= 128

        internal fun keyFor(conversationId: String, senderContactId: String, receivedAt: Long): String =
            ScreenshotNoticeMetaKeys.PREFIX + conversationId + ":" + senderContactId + ":" + receivedAt

        /**
         * LENIENT decode. Anything that does not fully validate returns null and the
         * caller GCs the key — a corrupt row is "no notice", never an error and never
         * a throw.
         */
        internal fun decode(key: String, value: String?): StoredScreenshotNotice? {
            if (!key.startsWith(ScreenshotNoticeMetaKeys.PREFIX)) return null
            val parts = key.split(':')
            if (parts.size != 4) return null
            val conversationId = parts[1]
            val senderContactId = parts[2]
            val receivedAt = parts[3].toLongOrNull() ?: return null
            if (conversationId.isEmpty() || senderContactId.isEmpty() || receivedAt <= 0L) return null
            val fields = (value ?: return null).split('|')
            val takenAt = fields.getOrNull(0)?.toLongOrNull() ?: return null
            return StoredScreenshotNotice(
                conversationId = conversationId,
                isGroup = fields.getOrNull(1) == "1",
                senderContactId = senderContactId,
                takenAt = takenAt,
                receivedAt = receivedAt,
                seen = fields.getOrNull(2) == "1",
            )
        }

        internal fun encode(takenAt: Long, isGroup: Boolean, seen: Boolean): String =
            "$takenAt|${if (isGroup) 1 else 0}|${if (seen) 1 else 0}"
    }

    /** Every `ssn:` key currently in the vault; empty on any read failure. */
    private fun allKeys(): List<String> = try {
        vault.metaKeys().filter { it.startsWith(ScreenshotNoticeMetaKeys.PREFIX) }
    } catch (e: Exception) {
        platformLogWarn(TAG, "meta key scan failed: ${e::class.simpleName}"); emptyList()
    }

    private fun keysFor(conversationId: String): List<String> {
        val prefix = ScreenshotNoticeMetaKeys.PREFIX + conversationId + ":"
        return allKeys().filter { it.startsWith(prefix) }
    }

    // Reads one row, keeping the two null-shaped outcomes apart (the
    // [readMetaForGc] rule, shared with [GroupInviteStore]):
    //  - `first == false`: the READ ITSELF failed. Ambiguous absence: the row is left
    //    strictly alone (never deleted, never shown) and read again next time, so a
    //    transient vault error cannot destroy a durable notice.
    //  - `first == true, second == null`: the value was read and does not decode (or
    //    the row is gone). Positive evidence it can never be shown, so callers GC it.
    private fun readRow(key: String): Pair<Boolean, StoredScreenshotNotice?> =
        when (val r = vault.readMetaForGc(key, TAG, "screenshot notice row")) {
            MetaRead.Unreadable -> false to null
            is MetaRead.Read -> true to decode(key, r.raw)
        }

    private fun deleteQuietly(key: String) {
        try { vault.deleteMeta(key) } catch (_: Exception) { /* best effort */ }
    }

    /**
     * Persists one received notice and returns it, or null when nothing could be
     * written (bad id shape, or the vault refused — on iOS `putMeta` throws on a
     * locked keybag). A null is FAIL-SOFT by design: the caller keeps its RAM-only
     * behaviour for the open screen and the notice is simply not durable.
     *
     * [senderClaimedTakenAtMs] is the envelope's `"t"` verbatim — untrusted, and
     * used only through [clampTakenAt] for display.
     *
     * Evict-then-insert runs inside ONE [VaultDatabase.withTransaction] so a torn
     * write can never drop the caps' worth of older rows without adding the new
     * one. Expired rows in this conversation are pruned in the same transaction.
     * MUST NOT be called while holding the [ConversationBuffers] lock.
     */
    fun record(
        conversationId: String,
        isGroup: Boolean,
        senderContactId: String,
        senderClaimedTakenAtMs: Long,
    ): StoredScreenshotNotice? {
        if (!isStorableId(conversationId) || !isStorableId(senderContactId)) {
            platformLogWarn(TAG, "screenshot notice not persisted — unstorable id shape")
            return null
        }
        val now = clock()
        if (now <= 0L) return null
        val existing = keysFor(conversationId)
        // Distinct key per notice; a same-millisecond burst walks forward 1 ms at a
        // time rather than overwriting an earlier notice.
        var receivedAt = now
        var bumps = 0
        while (keyFor(conversationId, senderContactId, receivedAt) in existing && bumps < MAX_COLLISION_BUMPS) {
            receivedAt += 1
            bumps += 1
        }
        val key = keyFor(conversationId, senderContactId, receivedAt)
        if (key in existing) {
            platformLogWarn(TAG, "screenshot notice not persisted — key collision walk exhausted")
            return null
        }
        val record = StoredScreenshotNotice(
            conversationId = conversationId,
            isGroup = isGroup,
            senderContactId = senderContactId,
            takenAt = clampTakenAt(senderClaimedTakenAtMs, receivedAt),
            receivedAt = receivedAt,
            seen = false,
        )
        // Decide the eviction set BEFORE the transaction: pure reads, so the
        // transaction holds nothing but the deletes plus the insert.
        val live = mutableListOf<StoredScreenshotNotice>()
        val doomed = mutableListOf<String>()
        for (k in existing) {
            val (readOk, rec) = readRow(k)
            if (!readOk) continue
            if (rec == null || rec.expiresAt <= now) doomed.add(k) else live.add(rec)
        }
        live.sortWith(compareBy({ it.receivedAt }, { it.senderContactId }))
        val overflow = live.size - (MAX_PER_CONVERSATION - 1)
        if (overflow > 0) {
            for (i in 0 until overflow) {
                doomed.add(keyFor(conversationId, live[i].senderContactId, live[i].receivedAt))
            }
        }
        return try {
            vault.withTransaction {
                for (k in doomed) vault.deleteMeta(k)
                vault.putMeta(key, encode(record.takenAt, record.isGroup, record.seen))
            }
            record
        } catch (e: Throwable) {
            // iOS: a locked keybag / SQLCipher refusal throws here. Never fatal.
            platformLogWarn(TAG, "screenshot notice not persisted: ${e::class.simpleName}")
            null
        }
    }

    /**
     * The unexpired notices for one conversation, oldest first, and a prune of that
     * conversation's expired/corrupt rows as a side effect. Ordered by
     * `(receivedAt, key)` so the sequence is stable even for two notices that
     * landed in the same millisecond.
     *
     * Non-destructive with respect to LIVE notices — unlike
     * `GroupManager.drainScreenshotNotices`, this may be called again (e.g. on
     * every conversation open) and returns the same rows until they expire.
     */
    fun list(conversationId: String): List<StoredScreenshotNotice> {
        if (!isStorableId(conversationId)) return emptyList()
        val now = clock()
        val out = mutableListOf<Pair<String, StoredScreenshotNotice>>()
        for (key in keysFor(conversationId)) {
            val (readOk, rec) = readRow(key)
            if (!readOk) continue
            if (rec == null || rec.expiresAt <= now) { deleteQuietly(key); continue }
            out.add(key to rec)
        }
        out.sortWith(compareBy({ it.second.receivedAt }, { it.first }))
        return out.map { it.second }
    }

    /**
     * Marks every unexpired notice in one conversation as seen — called when that
     * conversation is polled, i.e. the user is looking at it. Clears the unseen
     * term [unseenCounts] contributes to the unread dot. Expired rows encountered
     * on the way are pruned.
     *
     * Cheap in the steady state: one key scan and ZERO writes once everything is
     * already seen. Fail-soft — an unwritable "seen" flag only costs a stale dot.
     */
    fun markSeen(conversationId: String) {
        if (!isStorableId(conversationId)) return
        val now = clock()
        val updates = mutableListOf<Pair<String, StoredScreenshotNotice>>()
        for (key in keysFor(conversationId)) {
            val (readOk, rec) = readRow(key)
            if (!readOk) continue
            if (rec == null || rec.expiresAt <= now) { deleteQuietly(key); continue }
            if (!rec.seen) updates.add(key to rec)
        }
        if (updates.isEmpty()) return
        try {
            vault.withTransaction {
                for ((key, rec) in updates) vault.putMeta(key, encode(rec.takenAt, rec.isGroup, true))
            }
        } catch (e: Throwable) {
            platformLogWarn(TAG, "screenshot notice markSeen failed: ${e::class.simpleName}")
        }
    }

    /**
     * conversationId → number of UNSEEN, unexpired notices. Read-only (expired rows
     * are skipped, not deleted — [list] / [pruneExpired] own the GC) so the unread
     * sweep never writes.
     */
    fun unseenCounts(): Map<String, Int> = countUnseen(null)

    /** As [unseenCounts], restricted to group ([isGroup] true) or 1:1 conversations. */
    fun unseenCounts(isGroup: Boolean): Map<String, Int> = countUnseen(isGroup)

    private fun countUnseen(isGroup: Boolean?): Map<String, Int> {
        val now = clock()
        val out = mutableMapOf<String, Int>()
        for (key in allKeys()) {
            val rec = readRow(key).second ?: continue
            if (rec.seen || rec.expiresAt <= now) continue
            if (isGroup != null && rec.isGroup != isGroup) continue
            out[rec.conversationId] = (out[rec.conversationId] ?: 0) + 1
        }
        return out
    }

    /**
     * Deletes every expired or undecodable `ssn:` row, across all conversations.
     * There is no timer: this rides the background control sweep (SessionManagers),
     * whose first pass runs seconds after unlock, and the per-conversation prunes in
     * [record] / [list] cover everything between sweeps. Never throws.
     */
    fun pruneExpired() {
        val now = clock()
        for (key in allKeys()) {
            val (readOk, rec) = readRow(key)
            if (!readOk) continue
            if (rec == null || rec.expiresAt <= now) deleteQuietly(key)
        }
    }
}

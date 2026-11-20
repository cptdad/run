package com.vg.run

/**
 * Which contacts' TEXT inboxes may hold a blob that OUR OWN drain has leased and whose
 * lease has not provably ended (2026-11-18). A leased blob is invisible to `/peek`
 * (retrieve-ack, `docs/vault-relay-internals.md`), so while one of these is
 * outstanding a peek that answers 0 does not prove the inbox empty: the lease can
 * still end WITHOUT the blob being deleted — an ack lost over Tor, a partially
 * committed screen drain, an abandoned screen poll — and the blob comes back. The
 * legacy compensator's heal ([GroupUnreadTally.contactCountsFrom]) must not act on
 * such a peek, or a returning legacy group text would light the CONTACT row.
 *
 * - **In flight**: [beginFetch] runs BEFORE the leasing GET of a contact's text
 *   inbox — the relay starts the lease when it SERVES the GET, before the client
 *   has parsed anything — and the mark counts as an unsettled lease until resolved.
 * - **Resolved**: a clean "nothing leased" answer ([resolveClean]: an HTTP status
 *   that is not 2xx, an empty inbox, a relay that deleted at fetch) clears the mark;
 *   blobs under a lease token ([resolveLeased]) turn it into that lease; an answer
 *   the client never saw or could not read ([resolveUnseen]: transport failure,
 *   unparseable body, a lease token it cannot use) keeps it as an unsettled lease.
 * - **Settled**: any `POST /ack` carrying the token answered 200 ([settled]) — the
 *   relay deleted the listed ids and RELEASED the rest of the token.
 * - **Bounded**: every unsettled entry stops counting [LEASE_GUARD_MS] after it was
 *   recorded (the relay's own lease, 60 s by default, has ended by then and the blob
 *   is visible to a peek again), and at most [MAX_UNSEEN_STREAK] CONSECUTIVE unseen
 *   outcomes per contact are recorded, so a drain loop that keeps failing blocks the
 *   heal for at most ~[LEASE_GUARD_MS] after its third failure, not for as long as it
 *   fails. Any clean or leased answer resets that streak.
 *
 * PROCESS-wide, not per [MessageManager]: a Tor restart rebuilds the manager without
 * a scrub while the leases it took are still running (the same reason as
 * `PendingLegacyRegistry`). RAM only — contact ids and lease tokens — and emptied by
 * [scrub], which BOTH platforms call unconditionally at lock and at wipe (through
 * [MessageManager.endProcessReceiveSession]) as well as from
 * [MessageManager.scrubInMemory]. [scrub] bumps a session epoch that every write
 * checks, so a drain still in flight across a lock (on a manager nobody scrubbed —
 * Android drops it without a scrub when Tor fails) cannot repopulate it. Never logged.
 */
internal object TextLeaseLedger {
    /** Longer than the relay's lease (60 s default) with margin for the round trip. */
    const val LEASE_GUARD_MS = 120_000L

    /** Consecutive unseen fetch outcomes per contact that still count. */
    const val MAX_UNSEEN_STREAK = 3

    /** How long a contact's last take/settle event is kept for [blocksHeal]'s
     *  generation check — far longer than any sweep runs. */
    private const val EVENT_KEEP_MS = 600_000L

    /** One fetch in flight. Opaque to callers; carries the session [epoch]. */
    class Mark internal constructor(internal val key: String, internal val contactId: String, internal val epoch: Long)

    private class Entry(val contactId: String, val atMs: Long)
    private class Event(val gen: Long, val atMs: Long)

    private val lock = SyncLock()
    /** A lease token, or an in-flight mark's key, → its contact. */
    private val entries = mutableMapOf<String, Entry>()
    private val lastEvent = mutableMapOf<String, Event>()
    private val unseenStreak = mutableMapOf<String, Int>()
    private var gen = 0L
    private var seq = 0L
    private var epoch = 0L

    /** MONOTONIC milliseconds. Test seam; read under [lock], so a pure clock read. */
    internal var clockMs: () -> Long = { GroupUnreadTally.monotonicNowMs() }

    /** A sweep reads this BEFORE its first peek and hands it to [blocksHeal]. */
    fun generation(): Long = lock.withLock { gen }

    /**
     * The RECEIVE-SESSION epoch: bumped by every [scrub] (lock, wipe, a manager
     * scrub). A [MessageManager] captures it at CONSTRUCTION — both platforms build
     * a new manager per transport inside an unlocked session and none survives a
     * lock — and every write it makes to this ledger or to the uncommitted-legacy
     * registry is refused once the epoch has moved on, so a manager dropped without
     * a scrub (Android, Tor Failed/Idle) cannot write either back after the session
     * end. A same-session reconnect builds its manager under the SAME epoch, so the
     * old manager's leases and pending drains stay valid exactly as before.
     */
    fun sessionEpoch(): Long = lock.withLock { epoch }

    fun isCurrentSession(sessionEpoch: Long): Boolean = lock.withLock { sessionEpoch == epoch }

    /** BEFORE the leasing GET of [contactId]'s text inbox; null (no mark) for a
     *  manager from an ended session ([sessionEpoch]). */
    fun beginFetch(contactId: String, sessionEpoch: Long): Mark? = lock.withLock {
        if (sessionEpoch != epoch) return@withLock null
        seq++
        // NUL-prefixed: can never collide with a relay token (base64url, validated).
        val key = "\u0000$seq"
        entries[key] = Entry(contactId, clockMs())
        Mark(key, contactId, epoch)
    }

    /** The relay answered without leasing anything. */
    fun resolveClean(mark: Mark) = lock.withLock {
        if (mark.epoch != epoch) return@withLock
        entries.remove(mark.key)
        unseenStreak.remove(mark.contactId)
    }

    /** The relay leased blobs under [token]: the mark becomes that lease. */
    fun resolveLeased(mark: Mark, token: String) = lock.withLock {
        if (mark.epoch != epoch) return@withLock
        entries.remove(mark.key)
        unseenStreak.remove(mark.contactId)
        val now = clockMs()
        entries[token] = Entry(mark.contactId, now)
        noteEventLocked(mark.contactId, now)
    }

    /** The answer was never seen or could not be read: blobs may be leased. Kept as
     *  an unsettled lease (from when the fetch began) — within the streak bound. */
    fun resolveUnseen(mark: Mark) = lock.withLock {
        if (mark.epoch != epoch) return@withLock
        val n = (unseenStreak[mark.contactId] ?: 0) + 1
        unseenStreak[mark.contactId] = n
        if (n > MAX_UNSEEN_STREAK) entries.remove(mark.key)
    }

    fun settled(token: String) = lock.withLock {
        val t = entries.remove(token) ?: return@withLock
        noteEventLocked(t.contactId, clockMs())
    }

    private fun noteEventLocked(contactId: String, now: Long) {
        gen++
        lastEvent[contactId] = Event(gen, now)
    }

    /**
     * May a peek of [contactId]'s text inbox, issued by a sweep that read
     * [sweepGeneration] before its first request, heal the legacy compensator? No
     * while one of our leases on it may still be in force (an unsettled lease, or a
     * fetch in flight or unseen), and no when a lease was taken or settled since the
     * sweep began (the peek may predate a release that made a blob visible again).
     * Conservative: the next sweep decides.
     */
    fun blocksHeal(contactId: String, sweepGeneration: Long): Boolean = lock.withLock {
        val now = clockMs()
        entries.entries.removeAll { now < it.value.atMs || now - it.value.atMs >= LEASE_GUARD_MS }
        lastEvent.entries.removeAll { now < it.value.atMs || now - it.value.atMs >= EVENT_KEEP_MS }
        if ((lastEvent[contactId]?.gen ?: Long.MIN_VALUE) > sweepGeneration) return@withLock true
        entries.values.any { it.contactId == contactId }
    }

    /** Session end (lock / wipe / manager scrub): forget everything, and refuse
     *  every write from a fetch that began before this. */
    fun scrub() = lock.withLock {
        epoch++
        entries.clear()
        lastEvent.clear()
        unseenStreak.clear()
    }
}

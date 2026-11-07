package com.vg.run

import kotlin.concurrent.Volatile

/**
 * RAM-ONLY ledger of 1:1 TEXT sends whose LAST failure was TRANSPORT-class, so
 * the next transport-back event can re-drive them without the user long-pressing
 * Retry ([MessageManager.redriveTransportFailures]).
 *
 * Why RAM and not the vault: the vault schema has NO message table (v9,
 * `docs/vault-relay-internals.md`), the store listing says messages are never
 * written to disk, and `LegacyMessageTableRemovalTest` guards it. A re-drive needs
 * the plaintext, so the only place it may wait is where the failed bubble already
 * lives — process RAM, for the life of the session. [clear] runs from
 * [MessageManager.scrubInMemory] AND — because entries are recorded exactly when
 * there is NO manager (Android `sendMessageInBackground`, iOS `AppState.sendMessage`
 * park directly when `messageManager == null`, and Tor Failed/Idle/restart null the
 * manager without scrubbing so a parked send survives a transport outage inside the
 * unlocked session) — unconditionally from every platform lock / wipe seam
 * (`RunViewModel.lockSession` / `performEmergencyWipe`, `IosAppController.lock()` /
 * `emergencyWipe()` and Swift `AppState.lock()` / `emergencyWipe()` — all via
 * [endSession]), independent of whether a manager exists at that moment.
 * [REDRIVE_WINDOW_MS] + [MAX_ENTRIES] bound what a long session can hold.
 *
 * Why a SHARED instance: a `MessageManager` is rebuilt whenever the transport is
 * (Tor self-heal, new SOCKS port), and the sends that need re-driving are exactly
 * the ones that failed on the instance that just died. [shared] outlives any one
 * instance; tests inject their own.
 *
 * Keyed by a caller-chosen [Entry.token] (the UI bubble id): a manual Retry of the
 * same bubble while the transport is still down UPSERTS rather than appends, so one
 * message can never be re-driven twice, and a send that eventually LANDS under
 * that token removes it ([MessageManager.sendMessageWithOutcome]).
 *
 * SESSION EPOCH: a send that started in one unlocked session can finish after
 * that session's lock (the POST is a blocking call, so cancelling its coroutine
 * does not stop it, and Tor dying under it is exactly a TRANSPORT failure). Its
 * late [record] would re-park the PLAINTEXT after the lock's clear, where nothing
 * clears it again until the next session ends. So every writer — Kotlin
 * (`MessageManager.sendMessageWithOutcome`, Android `sendMessageInBackground`) and
 * Swift (`AppState.sendMessage`, which receives the epoch its caller captured when
 * the user tapped Send) — captures [sessionEpoch] when the send STARTS and passes
 * it to [record]; [beginSession] /
 * [endSession] bump the epoch (and clear), and a record carrying an older epoch is
 * dropped. The check runs under the same lock as the bump, so a record racing an
 * [endSession] either lands before its clear or is refused — never after it.
 *
 * Thread-safe; never throws; holds no identifier beyond what the conversation
 * screen already holds.
 */
class TransportFailedSends internal constructor(
    /** Wall clock; injectable so the 15-minute window is unit-testable. */
    internal var clock: () -> Long = { currentTimeMillis() },
) {
    class Entry internal constructor(
        val token: String,
        val contactId: String,
        val plaintext: String,
        val noPush: Boolean,
        /** When the LATEST transport-class failure of this message was recorded. */
        val failedAtMs: Long,
        /** Invoked (once, on the re-drive's thread) when a re-drive LANDS. */
        val onRedriven: (() -> Unit)?,
    )

    private val lock = SyncLock()
    // Insertion order = failure order; an upsert moves the entry to the end.
    private val entries = LinkedHashMap<String, Entry>()

    // Written only under [lock]; @Volatile so [sessionEpoch] reads it lock-free.
    @Volatile
    private var epoch: Long = 0L

    /** The current session's epoch. Capture it when a send STARTS; pass it to [record]. */
    val sessionEpoch: Long get() = epoch

    /** A new unlocked session starts: bump the epoch and drop anything left over. */
    fun beginSession() = lock.withLock {
        epoch++
        entries.clear()
    }

    /** The session ends (lock / wipe): bump the epoch so a send still in flight
     *  cannot re-park after this, and clear. Idempotent apart from the bump. */
    fun endSession() = lock.withLock {
        epoch++
        entries.clear()
    }

    /**
     * Records (or refreshes) a transport-failed send under [token]. Oldest entries
     * are evicted past [MAX_ENTRIES] — a bound on RAM, not a delivery promise.
     * A no-op when [sessionEpoch] is not the current epoch (the send's session has
     * ended since it started — see the class kdoc).
     */
    fun record(
        token: String,
        contactId: String,
        plaintext: String,
        noPush: Boolean,
        onRedriven: (() -> Unit)?,
        sessionEpoch: Long,
    ) {
        val entry = Entry(token, contactId, plaintext, noPush, clock(), onRedriven)
        lock.withLock {
            if (sessionEpoch != epoch) return@withLock
            entries.remove(token)
            entries[token] = entry
            while (entries.size > MAX_ENTRIES) {
                val oldest = entries.keys.firstOrNull() ?: break
                entries.remove(oldest)
            }
        }
    }

    /** Drops [token] (landed, or deleted by the user). True if it was present. */
    fun remove(token: String): Boolean = lock.withLock { entries.remove(token) != null }

    /**
     * Atomically takes EVERY entry out of the ledger and returns the ones still
     * inside [REDRIVE_WINDOW_MS]; older ones are dropped (the user's failed bubble
     * is untouched — manual Retry still works). Taking, not reading, is what makes
     * a re-drive happen at most ONCE per message per transport-back event even when
     * two callers race.
     */
    fun takeEligible(): List<Entry> {
        val now = clock()
        val taken = lock.withLock {
            val all = entries.values.toList()
            entries.clear()
            all
        }
        return taken.filter { now - it.failedAtMs <= REDRIVE_WINDOW_MS }
    }

    fun size(): Int = lock.withLock { entries.size }

    /** Teardown without ending the session: called from
     *  [MessageManager.scrubInMemory]. Every platform lock / wipe seam calls
     *  [endSession] instead, which also bumps the epoch. Does NOT bump the epoch. */
    fun clear() = lock.withLock { entries.clear() }

    companion object {
        /** A failure older than this is not re-driven automatically. */
        const val REDRIVE_WINDOW_MS: Long = 15L * 60 * 1000
        /** RAM bound; oldest evicted first. */
        const val MAX_ENTRIES: Int = 64

        /** The one production ledger, shared by every MessageManager instance. */
        val shared: TransportFailedSends = TransportFailedSends()
    }
}

/** What a 1:1 text send came to — see [MessageManager.sendMessageWithOutcome]. */
enum class SendOutcome {
    /** The relay accepted the append (2xx). */
    SENT,
    /**
     * TRANSPORT-class: every POST attempt threw or got no HTTP status (connection
     * refused/reset, SOCKS failure, timeout, host unreachable), or the transport was
     * already known down. Never a relay 4xx/5xx, never a local/crypto refusal.
     */
    TRANSPORT_FAILED,
    /** Anything else: a relay response that was not 2xx, or a local refusal. */
    FAILED,
}

package com.vg.run

import com.vg.run.GroupManager.Companion.REROSTER_MIN_INTERVAL_MS

// ---------------------------------------------------------------------------
// UnconvergedMembers — the ADMIN-side divergence set that drives the bounded
// hash-mismatch re-roster (GroupManager.rerosterUnconvergedMembers).
//
// (group, member) pairs whose last message carried a membershipHash that is NOT
// ours, i.e. members the ADMIN has positive evidence have not converged, plus
// their per-member re-roster throttle. Session-scoped RAM on purpose: the
// evidence is a message, so a fresh session re-learns it from the member's next
// one, and nothing here is worth a vault write per received blob. The re-roster
// throttle is pruned once its interval has elapsed, so both maps stay bounded.
//
// Its own lock (never nested with any other; SyncLock is non-reentrant on iOS),
// no vault access. The caller re-validates admin role, membership and contact
// against the vault for every pair [takeDue] hands out. The NUL-joined key never
// leaves this class. Cleared by GroupManager.scrubInMemory.
// ---------------------------------------------------------------------------
internal class UnconvergedMembers(private val clock: () -> Long) {
    companion object {
        internal const val MAX_REROSTERS_PER_SWEEP = 4
        private const val MAX_UNCONVERGED_RECORDS = 128
    }

    private val lock = SyncLock()
    private val unconverged = mutableMapOf<String, Long>()
    private val lastRerosterAtMs = mutableMapOf<String, Long>()

    private fun key(groupId: String, contactId: String) = groupId + "\u0000" + contactId

    fun mark(groupId: String, contactId: String) = lock.withLock {
        val key = key(groupId, contactId)
        if (key in unconverged) return@withLock
        if (unconverged.size >= MAX_UNCONVERGED_RECORDS) {
            unconverged.minByOrNull { it.value }?.key?.let { unconverged.remove(it) }
        }
        unconverged[key] = clock()
    }

    fun clear(groupId: String, contactId: String) = lock.withLock {
        unconverged.remove(key(groupId, contactId))
    }

    // The (groupId, contactId) pairs due for a re-roster at [now], at most
    // [MAX_REROSTERS_PER_SWEEP], in a SECURE random order (the relay observes the
    // send order). Taking one moves it out of the set and stamps its throttle.
    fun takeDue(now: Long): List<Pair<String, String>> {
        val ready = lock.withLock {
            // Drop throttle stamps that no longer gate anything (keeps the map bounded).
            for ((k, at) in lastRerosterAtMs.entries.toList()) {
                if (now < at || now - at >= REROSTER_MIN_INTERVAL_MS) lastRerosterAtMs.remove(k)
            }
            val picked = unconverged.keys.filter { it !in lastRerosterAtMs }
                .secureShuffled()
                .take(MAX_REROSTERS_PER_SWEEP)
            for (k in picked) { unconverged.remove(k); lastRerosterAtMs[k] = now }
            picked
        }
        // Only keys built by [key] are ever stored, so every one splits; a group id
        // never contains NUL (base64url) and a contact id is never empty.
        return ready.mapNotNull { k ->
            val sep = k.indexOf('\u0000')
            if (sep <= 0 || sep == k.length - 1) null else k.substring(0, sep) to k.substring(sep + 1)
        }
    }

    fun scrub() = lock.withLock { unconverged.clear(); lastRerosterAtMs.clear() }
}

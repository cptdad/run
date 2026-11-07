package com.vg.run

/**
 * The ONE per-contact mutex every read-modify-write of a `ContactRecord`
 * row must hold.
 *
 * Why it is a top-level object rather than a `MessageManager` field: all four
 * anti-replay counters (inbound/outbound × text/ctl) plus `inboundEpoch` live in
 * the SAME row, and `VaultDatabase.insertContact` is a WHOLE-ROW upsert on both
 * platforms — so any read-modify-write that is not serialised against the counter
 * paths writes back its own stale snapshot of the counters. `MessageManager`'s
 * `counterLock` already covered send-vs-poll, but the contact EDIT paths
 * ([ContactEdits.rollAlias] / [ContactEdits.updateMnemonic], driven from a user tap
 * on both platforms) live outside any `MessageManager` instance and structurally
 * could not take a private field. The background control poll runs for the whole
 * unlocked session, so "user rolls an alias while a poll is in flight" is a routine
 * race, not a corner case, and its two outcomes are both security-relevant:
 *
 *  - a rolled-back INBOUND baseline reopens the replay window — the counter is the
 *    ENTIRE replay defense (messages are never persisted, so there is no secondary
 *    dedupe store), and a retaining relay's re-served blob then decrypts and
 *    resurfaces;
 *  - a rolled-back OUTBOUND counter makes the next send reuse a counter the peer's
 *    strict-monotonic check drops → silent message loss.
 *
 * Contract for every writer: (a) take the lock for `contactId`, (b) RE-READ the row
 * INSIDE it, (c) copy + write, still inside it. Never hold it across network I/O.
 *
 * Locks are created on demand and never removed: a `SyncLock` holds no secrets, the
 * set is bounded by the contacts touched in this process, and removing one while a
 * thread waits would hand two threads different mutexes. Non-reentrant on iOS
 * (NSLock), so a critical section must not re-enter. Where both are taken the order
 * is always `MessageManager.sendOrderLock` → this one; nothing takes them the other
 * way round, so there is no deadlock.
 */
internal object ContactRowLocks {
    private val guard = SyncLock()
    private val locks = mutableMapOf<String, SyncLock>()

    fun forContact(contactId: String): SyncLock =
        guard.withLock { locks.getOrPut(contactId) { SyncLock() } }

    // The per-(contact, direction) READ-cap rotation locks. A SEPARATE
    // registry from [forContact] on purpose — different granularity, and a
    // rotation critical section DOES span network I/O by design (the PUT + the
    // /peek probes are what it serialises), so merging it with the counter lock
    // would stall every send/poll counter write behind a Tor round-trip.
    //
    // Shared here for the same reason as [forContact]: both platforms
    // recreate MessageManager on a Tor reconnect via a bare unawaited cancel of
    // the old poll job, so an instance-private registry let a dying instance
    // mid-rotation race the NEW instance's poll-loop reconcile for the same
    // (contact, direction) on two disjoint locks — the loser resolves neither
    // cap and the surviving marker wedges the contact on BUSY, exactly the
    // failure the rotation lock exists to prevent. Directions come from a fixed
    // no-`/` set, so the composite key is unambiguous; even a collision would
    // only over-serialise, never under-lock. Same lifecycle rules as [locks]:
    // created on demand, never removed, hold no secrets.
    private val rotationGuard = SyncLock()
    private val rotationLocks = mutableMapOf<String, SyncLock>()

    fun forRotation(contactId: String, direction: String): SyncLock =
        rotationGuard.withLock { rotationLocks.getOrPut("$contactId/$direction") { SyncLock() } }
}

/**
 * Contact-edit read-modify-write hoisted to commonMain so BOTH platforms run
 * the ONE persist that preserves the shared secret AND the anti-replay
 * counters/epoch. iOS previously hand-enumerated all 13 ContactRecord
 * fields in THREE places (ContactListView.saveMnemonic/rollAlias,
 * AddContactView.saveMnemonicAndDismiss) — any new ContactRecord field silently
 * zeroed there. [ContactRecord.copy] carries every field forward, so a field can
 * never be dropped again. Called from Kotlin (ContactListScreen, AddContactScreen)
 * and Swift (ContactEdits.shared.*).
 *
 * `copy` only preserves what the READ saw. Both edits therefore re-read the row
 * INSIDE [ContactRowLocks.forContact], the same mutex `MessageManager`'s send/poll
 * counter critical sections take, so a concurrent counter advance can no longer be
 * lost (nor an edit clobbered by a poll). This is the only reason these two
 * functions are the mandatory entry point — do not re-inline a
 * `getContact`/`insertContact` pair at a call site.
 */
object ContactEdits {

    /**
     * Persists a mnemonic (the user's private who-is-this note) change for
     * [contactId]. No-op if the contact is gone. Write failures are swallowed —
     * a cosmetic memory edit isn't worth surfacing a transient vault error for.
     */
    fun updateMnemonic(vault: VaultDatabase, contactId: String, mnemonic: String) {
        val trimmed = mnemonic.trim()
        ContactRowLocks.forContact(contactId).withLock {
            // Re-read INSIDE the lock: the snapshot the UI is holding may be minutes
            // old, and the row's counters may have advanced since.
            val contact = vault.getContact(contactId)
            if (contact != null) {
                try {
                    vault.insertContact(contact.copy(mnemonic = trimmed))
                } catch (_: Exception) { /* non-critical edit */ }
            }
        }
    }

    /**
     * Rolls a fresh vault-local alias (a pseudonym never sent anywhere) for
     * [contactId] and persists it. Returns the updated record so the caller can
     * refresh an open menu live; returns the unchanged record on a write failure,
     * or null if the contact is gone. A draw equal to the current alias is
     * re-rolled (bounded) so the action always visibly changes something.
     */
    fun rollAlias(vault: VaultDatabase, contactId: String): ContactRecord? =
        ContactRowLocks.forContact(contactId).withLock {
            // Re-read INSIDE the lock — see [ContactRowLocks]. The alias draw is a
            // few CSPRNG bytes, no I/O, so the critical section stays short.
            val contact = vault.getContact(contactId) ?: return@withLock null
            var newAlias = ContactAliasGenerator.generate()
            var guard = 0
            while (newAlias == contact.alias && guard++ < 8) {
                newAlias = ContactAliasGenerator.generate()
            }
            val updated = contact.copy(alias = newAlias, aliasLastRotated = currentTimeMillis())
            try {
                vault.insertContact(updated)
                updated
            } catch (_: Exception) {
                contact
            }
        }
}

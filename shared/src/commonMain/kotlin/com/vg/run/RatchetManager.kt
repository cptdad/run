package com.vg.run

// ---------------------------------------------------------------------------
// RatchetManager — the integration layer between DoubleRatchet and the message
// path. It owns NO platform code: persistence is delegated to a RatchetStore so
// this whole layer is exercised end to end in commonTest with an in-memory
// store, and the live wiring only has to supply a vault-backed RatchetStore.
//
// Bootstrap ordering (see DoubleRatchet): the primitive is asymmetric — the
// role-assigned initiator ("Alice") can send immediately; the responder ("Bob")
// has no sending chain until he has received once. What the LIVE wiring actually
// does (do NOT overstate — there is no "Bob buffers until bootstrapped"
// protocol):
//   - [tryEncrypt] returns a ratchet envelope once a sending chain exists.
//   - When Bob has NO sending chain yet, [tryEncrypt] returns null and the caller
//     (the ratchet send helper in MessageManager) does NOT buffer/queue — it FALLS THROUGH to
//     the LEGACY static AES-GCM envelope (peer auto-detects by wire format). So a
//     responder's first pre-ratchet outbound ships WITHOUT forward secrecy;
//     forward secrecy engages once the ratchet has received once (first-inbound-
//     gated enablement + self-describing wire keep this legacy-interoperable).
//   - That fallthrough is no longer silent OR unbounded in
//     visibility — MessageManager counts consecutive fallbacks per contact
//     (`dr-legacyfb/{id}`) and exposes forwardSecrecyStalled(), because a relay that
//     drops the initiator's ratchet blobs can otherwise hold the responder on the
//     static envelope forever.
//   - Past that threshold it IS now a gate. A
//     SUSTAINED fallthrough is no longer a bootstrap cost but a peer-forced role
//     collision (or a relay pinning the downgrade), which is permanent and
//     self-reinforcing — so MessageManager latches `dr-refused/{id}` and the legacy
//     TEXT send fails instead of shipping plaintext-equivalent traffic the user
//     believes is ratcheted. The same latch is armed by the opposite-direction
//     detector `dr-rat-unacked/{id}` (both sides holding sending chains, so
//     [tryEncrypt] never returns null and no fallback is ever counted). One inbound
//     ratchet blob that DECRYPTS clears all of it. Nothing here ever wipes or
//     re-inits the persisted ratchet: a refusal blocks sends only.
//   - (2026-09-18) WHICH role a fresh init takes is no longer a
//     function of the peer-supplied outbound inbox id whenever both sides are
//     known to run rule v2 (`rv:2`). [loadOrInit] then takes the role the caller
//     resolved from IMMUTABLE pairing inputs (the two secret halves / the two
//     X25519 pubkeys, via ratchetSelfIsBobFromRoleOrder) instead of
//     ratchetSelfIsBob's id comparison. Absent evidence ⇒ the id rule, unchanged.
//     An already-persisted ratchet is NEVER re-roled: the blob is the role.
//
// Every operation is load → mutate → persist under a lock, because a contact's
// text and control channels poll on different coroutines and a 1:1 send can race
// an inbound drain. State lives only in the (encrypted) store between calls.
// ---------------------------------------------------------------------------

// The log tag of every line this file writes.
private const val LOG_TAG = "RatchetManager"

/** Per-(contact, channel) persistence for serialized ratchet state, backed by the vault. */
internal interface RatchetStore {
    fun load(contactId: String, channel: String): ByteArray?
    fun save(contactId: String, channel: String, blob: ByteArray)
}

/**
 * Vault-backed [RatchetStore]: serialized ratchet state lives base64'd in the
 * encrypted `_meta` table under `dr/{contactId}/{channel}`, alongside every
 * other secret column. The blob holds key material — it only ever rests inside
 * the already-encrypted vault, and [RatchetManager] wipes the plaintext copy
 * after each save (see [RatchetManager.persist]).
 */
internal class VaultRatchetStore(private val vault: VaultDatabase) : RatchetStore {
    internal companion object {
        /** The `_meta` key of one serialized ratchet state. The ONE builder — the
         *  purge list ([ratchetMetaKeysForContact]) calls it too. */
        fun stateKey(contactId: String, channel: String) = "dr/$contactId/$channel"
    }
    private fun key(contactId: String, channel: String) = stateKey(contactId, channel)
    override fun load(contactId: String, channel: String): ByteArray? =
        vault.getMeta(key(contactId, channel))?.let { decodeBase64(it) }
    override fun save(contactId: String, channel: String, blob: ByteArray) {
        vault.putMeta(key(contactId, channel), encodeBase64(blob))
    }
}

internal class RatchetManager(
    private val store: RatchetStore,
    // Invoked when a corrupt/undeserializable persisted ratchet is
    // silently re-initialized. The caller clears the sticky dr-rxlock (+ dr-on) so
    // the pair re-bootstraps via legacy — otherwise, with the lock armed, the poll
    // path drops every legacy blob AND the re-inited (send-chainless) ratchet's
    // output → a permanently dead conversation with no relay-404 re-pair signal.
    private val onCorruptReinit: (contactId: String, channel: String) -> Unit = { _, _ -> },
) {
    /**
     * ONE lock for every contact and both channels, deliberately.
     *
     * [decryptBatch] holds it for a whole
     * drain, so junk aimed at one contact stalled every other conversation's ratchet
     * ops. Sharding it per (contactId, channel) was considered and REJECTED:
     *  - [scrubInMemory] is documented as a LOCK-FENCE — acquiring this lock is what
     *    guarantees no in-flight op still holds live key material when a lock/panic
     *    wipe tears the session down. A shard map can only be fenced by walking it,
     *    which fences each shard at a different instant and never the whole layer.
     *  - the map would be keyed by contactId, i.e. a new in-RAM identifier surface
     *    that every wipe path would have to clear, for a benefit the budget already
     *    delivers.
     *  - it would newly allow two drains to write the vault concurrently, which is a
     *    concurrency question about two platform actuals, not about this file.
     * The harm was the DURATION of the hold, and the work budget + the consecutive
     * failure cutoff in [decryptBatch] bound that directly: a junk drain now stops
     * after 8 rejected blobs instead of grinding all 2048.
     */
    private val lock = SyncLock()

    /**
     * Injectable wall-clock seam, forwarded into every
     * [DoubleRatchet] this manager loads or inits. It drives ONE thing — the skipped
     * message-key age-out ([DoubleRatchet.SKIPPED_KEY_TTL_MS]) — and production NEVER
     * sets it (the default is the real clock). It exists so a 24 h window can be driven
     * in a unit test without real waits, exactly like `ReferralManager.clockMs`.
     *
     * Passed as `{ clockMs() }` rather than as the current value, so a ratchet built by
     * one op always reads whatever this var holds at the moment it asks the time.
     */
    internal var clockMs: () -> Long = { currentTimeMillis() }

    /**
     * Injectable per-drain work meter, same shape and
     * rationale as [clockMs] — production NEVER sets it (the default mints a fresh
     * [RatchetWorkBudget] per [decryptBatch] call, which is the whole point of a
     * PER-DRAIN ceiling). It exists so a test can hold the instance and assert what a
     * drain actually spent, which no observable output of the batch reveals.
     */
    internal var workBudgetFactory: () -> RatchetWorkBudget = { RatchetWorkBudget() }

    /**
     * Teardown hook to drop live ratchet key
     * material from RAM on lock / panic-wipe, so a deliberately-kept-alive process
     * doesn't leave secrets resident — the parity call the platform teardown sites
     * already make on [GroupManager.scrubInMemory] and [ReferralManager.scrubInMemory].
     *
     * WHAT THIS CAN AND CANNOT REACH. RatchetManager is deliberately STATELESS
     * between calls: every op is load → mutate → persist → drop under [lock], so it
     * holds NO long-lived DoubleRatchet field for this method to zero.
     *
     * Do NOT re-derive "so there is nothing to
     * do" from that. Originally the transient DoubleRatchet each op built was dropped
     * UNWIPED, leaving its root key, DH private key, both chain keys and up to
     * [DoubleRatchet.MAX_SKIPPED_STORE] skipped message keys as heap residue; and
     * because [hasRatchetedPastBootstrap] runs on EVERY non-control poll (~1 Hz with
     * a conversation open) a single session scattered hundreds of independent copies.
     * On the panic-wipe path — where the process is deliberately kept ALIVE on the
     * deniability screen — those were the only surviving copies of the chain keys
     * after the DB key was crypto-erased. The fix is at the DROP SITES, not here:
     * every op ([tryEncrypt], [decrypt], [isBootstrapped], [decryptBatch],
     * [hasRatchetedPastBootstrap]) now calls [DoubleRatchet.wipe] in a `finally`
     * that runs strictly AFTER its `persist(...)` — wiping BEFORE the persist would
     * serialize zeroed keys into the vault and destroy the ratchet. Every reachable
     * byte array (loaded blob, serialized snapshot) is likewise fill(0)'d in the
     * loadOrInit / persist / decryptBatch finally blocks.
     *
     * So THIS method is genuinely a lock-fence: acquiring [lock] blocks until any
     * in-flight op has persisted AND wiped its transient ratchet, after which no
     * live key material remains in this layer. Idempotent. Keep it — dropping it
     * would remove the only barrier against a teardown racing a mid-flight op.
     *
     * WHO MUST CALL THIS: RatchetManager is owned by MessageManager (private field,
     * no accessor), so MessageManager forwards here via [MessageManager.scrubInMemory],
     * and the platform teardown sites call it immediately BEFORE `messageManager =
     * null` — Android RunViewModel.performEmergencyWipe() + onCleared(), iOS
     * IosAppController.lock() + emergencyWipe() — next to the existing
     * groupManager?.scrubInMemory() / referralManager?.scrubInMemory() calls.
     */
    fun scrubInMemory() = lock.withLock {
        // Lock-fence: every op wipes its own transient DoubleRatchet in a finally
        // after persist, so by the time we hold [lock] no op is mid-flight.
        // See the note above before "simplifying" this away.
        //
        // Retrieve-ack (2026-11-03): the ONE long-lived key material this layer now
        // holds is the uncommitted-advance overlay ([pendingLineage]) — serialized
        // ratchet states a conversation screen decrypted but has not yet committed.
        // Teardown DISCARDS them (zeroed, never persisted, no release hook fired:
        // a lock/wipe must cause no network I/O), which is exactly the contract: no
        // commit ⇒ nothing persisted ⇒ the relay re-delivers after its lease and the
        // blobs decrypt again on the next session.
        for (key in pendingLineage.keys.toList()) discardFromLocked(key, 0, hooks = null)
        pendingLineage.clear()
    }

    // -----------------------------------------------------------------------
    // Retrieve-ack (2026-11-03): UNCOMMITTED advances for the conversation screens.
    //
    // The relay no longer deletes on fetch; it leases, and deletes on our ack. A
    // conversation screen must ack only once a message is ON SCREEN, and must
    // persist the ratchet advance at that same point — otherwise a teardown between
    // decrypt and render persists the advance, the re-delivery is rejected as a
    // duplicate (its one-shot key is gone) and the message is lost anyway. So
    // [decryptBatch] has a `persist = false` mode: the advance is kept HERE, in RAM
    // only, as a [PendingTicket], and is written to the store only by
    // [commitPending]. THE RULE for everything else that touches the same ratchet
    // while a ticket is uncommitted (docs/vault-relay-internals.md "Retrieve-ack"):
    //  1. a later persist=false drain of the SAME drain group (one screen poll —
    //     a contact's text inbox then its group inbox) BUILDS ON the head, so the
    //     chain stays linear and one commit of the head covers both;
    //  2. a persist=false drain of ANOTHER group (the next screen poll found the
    //     previous one still uncommitted: abandoned by a back press / navigation
    //     mid-poll) DISCARDS the stale lineage first and decrypts from the store —
    //     the stale drain's blobs are released (owner hook) and come back on the
    //     next poll, where the skipped-key cache opens them out of order;
    //  3. a persisting drain (persist = true: the background control sweep) NEVER
    //     builds on or overwrites an uncommitted advance — every one of its wires is
    //     reported NOT_PROCESSED ([DecryptBatchReport.notProcessed]), the caller
    //     does not ack them, and the relay hands them back on the next sweep;
    //  4. a SEND ([tryEncrypt]) / single [decrypt] DISCARDS the lineage first (it
    //     must persist, and persisting on top of an unshown advance would commit it
    //     — a lost message); the discarded drain's blobs are released and
    //     re-delivered, so the worst case is a message shown twice, never lost;
    //  5. an advance older than [PENDING_ADVANCE_MAX_AGE_MS] is discarded at the
    //     next touch of that ratchet (an abandoned screen poll nobody released), well
    //     inside the relay's 60 s lease so the re-delivery meets the rolled-back
    //     state;
    //  6. read-only probes ([hasRatchetedPastBootstrap], [hasSentAtLeast],
    //     [isBootstrapped]) read the STORE — an uncommitted advance is invisible to
    //     them, which only ever delays a lock arming or a send-chain probe by one
    //     drain (the conservative direction).
    // The lock still never spans network I/O: release hooks only LAUNCH an async
    // ack and are run after [lock] is released.
    // -----------------------------------------------------------------------

    /** Lifecycle of one uncommitted advance. */
    internal enum class PendingState { PENDING, COMMITTED, DISCARDED }

    /**
     * One uncommitted ratchet advance made by a `persist = false` [decryptBatch].
     * Holds the serialized state AFTER that drain (key material — RAM only, zeroed on
     * commit / discard / [scrubInMemory]). [drainGroup] is the caller's drain-group
     * identity (rule 1/2 above), compared by reference — an opaque screen-poll token,
     * unrelated to group messaging.
     */
    internal class PendingTicket internal constructor(
        internal val contactId: String,
        internal val channel: String,
        internal val drainGroup: Any,
        internal var snapshot: ByteArray?,
        internal val createdAtMs: Long,
        /**
         * SHA-256 of the STORE blob this lineage was built on. [commitPending] is a
         * compare-and-swap: if the store no longer holds that exact state, someone
         * persisted in between — another [RatchetManager] on the same vault (a Tor
         * restart rebuilds MessageManager WITHOUT a scrub, so an old instance's screen
         * may commit late) — and writing this snapshot would roll that advance back
         * (a DH fork if a send already used it). Then the advance is DISCARDED
         * instead: its blobs are re-delivered and decrypt from the newer state.
         */
        internal var storeFingerprint: ByteArray?,
    ) {
        /** Mutated and read under [RatchetManager.lock] only. */
        internal var state: PendingState = PendingState.PENDING

        /**
         * Set by the owner right after the drain: releases that drain's relay lease
         * (`POST /ack` with no ids) when this advance is DISCARDED by rule 2/4/5, so
         * its blobs come back on the next poll instead of after the lease. Invoked
         * outside [RatchetManager.lock]; never invoked by [scrubInMemory].
         */
        internal var onDiscarded: (() -> Unit)? = null
    }

    private fun pendingKey(contactId: String, channel: String) = "$contactId/$channel"

    /** `pendingKey → lineage` (oldest first). An in-RAM contact-id surface: emptied
     *  by [scrubInMemory]. Guarded by [lock]. */
    private val pendingLineage = mutableMapOf<String, MutableList<PendingTicket>>()

    /** Discards lineage[fromIndex..] (newest first), zeroing each snapshot. Under [lock]. */
    private fun discardFromLocked(key: String, fromIndex: Int, hooks: MutableList<() -> Unit>?) {
        val lineage = pendingLineage[key] ?: return
        while (lineage.size > fromIndex) {
            val t = lineage.removeAt(lineage.size - 1)
            t.state = PendingState.DISCARDED
            t.snapshot?.secureWipe()
            t.snapshot = null
            t.storeFingerprint = null
            val hook = t.onDiscarded
            t.onDiscarded = null
            if (hook != null && hooks != null) hooks.add(hook)
        }
        if (lineage.isEmpty()) pendingLineage.remove(key)
    }

    /** Rule 5. A clock that stepped BACKWARDS past a ticket also expires it — fail
     *  toward re-delivery, never toward an advance that outlives its bound. */
    private fun expirePendingLocked(key: String, hooks: MutableList<() -> Unit>) {
        val lineage = pendingLineage[key] ?: return
        val now = clockMs()
        val idx = lineage.indexOfFirst { now < it.createdAtMs || now - it.createdAtMs >= PENDING_ADVANCE_MAX_AGE_MS }
        if (idx >= 0) {
            platformLogWarn(LOG_TAG, "ratchet: ${lineage.size - idx} uncommitted advance(s) expired — re-delivery follows")
            discardFromLocked(key, idx, hooks)
        }
    }

    private fun runHooks(hooks: List<() -> Unit>) {
        for (h in hooks) try { h() } catch (_: Exception) { /* a release is best-effort */ }
    }

    /**
     * Persists [ticket]'s advance (and therefore every earlier advance of its
     * lineage, which it was built on). Idempotent. Returns true when the advance is
     * now in the store — committed here, or already by an earlier commit of a later
     * ticket built on it — and false when it was DISCARDED (the caller must then NOT
     * ack the blobs it decrypted: they are re-delivered and decrypt again) or the
     * store write failed (left PENDING; rule 5 retires it).
     */
    fun commitPending(ticket: PendingTicket): Boolean = lock.withLock {
        when (ticket.state) {
            PendingState.COMMITTED -> return@withLock true
            PendingState.DISCARDED -> return@withLock false
            PendingState.PENDING -> {}
        }
        val key = pendingKey(ticket.contactId, ticket.channel)
        val lineage = pendingLineage[key]
        val idx = lineage?.indexOf(ticket) ?: -1
        val snap = ticket.snapshot
        if (lineage == null || idx < 0 || snap == null) {
            ticket.state = PendingState.DISCARDED
            return@withLock false
        }
        val current = try { storeFingerprint(ticket.contactId, ticket.channel) } catch (_: Exception) { null }
        val expected = ticket.storeFingerprint
        if (current == null || expected == null || !current.contentEquals(expected)) {
            platformLogWarn(LOG_TAG, "ratchet: the stored state moved under an uncommitted advance — discarded, re-delivery follows")
            discardFromLocked(key, 0, hooks = null)   // the caller does not ack; the lease releases
            return@withLock false
        }
        try {
            store.save(ticket.contactId, ticket.channel, snap)
        } catch (e: Exception) {
            platformLogWarn(LOG_TAG, "ratchet: commit of an uncommitted advance failed: ${e::class.simpleName}")
            return@withLock false
        }
        val committedFp = sha256(snap)
        for (i in 0..idx) {
            val t = lineage[i]
            t.state = PendingState.COMMITTED
            t.snapshot?.secureWipe()
            t.snapshot = null
            t.storeFingerprint = null
            t.onDiscarded = null
        }
        repeat(idx + 1) { lineage.removeAt(0) }
        // Descendants still pending were built on what is now in the store.
        for (t in lineage) t.storeFingerprint = committedFp
        if (lineage.isEmpty()) pendingLineage.remove(key)
        true
    }

    /** SHA-256 of the persisted blob (null = none). The blob copy is zeroed. */
    private fun storeFingerprint(contactId: String, channel: String): ByteArray? {
        val blob = store.load(contactId, channel) ?: return null
        return try { sha256(blob) } finally { blob.secureWipe() }
    }

    /** True once [ticket] is in the store (see [commitPending]); false while pending or discarded. */
    fun isCommitted(ticket: PendingTicket): Boolean = lock.withLock { ticket.state == PendingState.COMMITTED }

    /**
     * The caller will never show what [ticket]'s drain decrypted (the screen went
     * away): discard it and every advance built on it. Never persists. Does NOT fire
     * [PendingTicket.onDiscarded] — the caller releases its own leases. Idempotent.
     */
    fun abandonPending(ticket: PendingTicket) {
        val hooks = mutableListOf<() -> Unit>()
        lock.withLock {
            if (ticket.state != PendingState.PENDING) return@withLock
            val key = pendingKey(ticket.contactId, ticket.channel)
            val idx = pendingLineage[key]?.indexOf(ticket) ?: -1
            if (idx < 0) { ticket.state = PendingState.DISCARDED; return@withLock }
            ticket.onDiscarded = null
            // Descendants built on [ticket] (same drain group) are released by their
            // own hooks — collected here and run after the lock.
            discardFromLocked(key, idx, hooks)
        }
        runHooks(hooks)
    }

    /** Is an uncommitted advance live for this ratchet (rule 3 pre-check)? Expires first. */
    fun hasUncommittedAdvance(contactId: String, channel: String): Boolean {
        val hooks = mutableListOf<() -> Unit>()
        val live = lock.withLock {
            val key = pendingKey(contactId, channel)
            expirePendingLocked(key, hooks)
            pendingLineage[key] != null
        }
        runHooks(hooks)
        return live
    }

    /** Rules 4 + 5 for a persisting single op: drop every uncommitted advance of this ratchet. */
    private fun discardForPersistLocked(contactId: String, channel: String, why: String, hooks: MutableList<() -> Unit>) {
        val key = pendingKey(contactId, channel)
        val n = pendingLineage[key]?.size ?: 0
        if (n == 0) return
        platformLogWarn(LOG_TAG, "ratchet: $n uncommitted advance(s) discarded by a $why — re-delivery follows")
        discardFromLocked(key, 0, hooks)
    }

    /**
     * True iff the persisted ratchet for [contactId]/[channel] has
     * advanced past the sharedSecret-forgeable bootstrap window (>= 2 receiving DH
     * steps). Returns false when there is no state or it is unreadable. Gates
     * dr-rxlock arming so a single forged bootstrap message cannot trip the lock.
     */
    fun hasRatchetedPastBootstrap(contactId: String, channel: String): Boolean = lock.withLock {
        val blob = store.load(contactId, channel) ?: return@withLock false
        // The loaded blob is an independent plaintext
        // duplicate of the persisted ratchet key material (root key, DH private key,
        // cached skipped message keys) — deserialize only COPIES ranges out of it.
        // Wipe the transient copy once we're done, on the success AND failure paths.
        // The DESERIALIZED ratchet holds those same secrets in
        // its own fields, and this probe is the HOTTEST drop site in the app —
        // MessageManager.maybeArmRecvLock calls it on every non-control poll (~1 Hz
        // while a conversation is open) — so dropping it unwiped scattered hundreds of
        // copies per session. This path NEVER persists, so the wipe is unconditionally
        // safe here (no serialize reads the object after it).
        var live: DoubleRatchet? = null
        try {
            val ratchet = DoubleRatchet.deserialize(blob, nowMs = { clockMs() })
            live = ratchet
            ratchet.hasRatchetedPastBootstrap()
        } catch (_: Exception) {
            false
        } finally {
            live?.wipe()
            blob.secureWipe()
        }
    }

    /**
     * True iff the persisted ratchet for
     * [contactId]/[channel] has sent at least [n] messages on its CURRENT sending
     * chain, i.e. since the peer's ratchet last provably answered (a receiving DH step
     * resets the counter). False when there is no state, no sending chain, or the state
     * is unreadable — absence is never evidence, which is what keeps this from arming
     * the refusal on a fresh or damaged vault.
     *
     * Read-only: it NEVER persists and never re-inits, so it cannot be the thing that
     * freezes a role. Mirrors [hasRatchetedPastBootstrap] exactly, wipe discipline
     * included (the deserialized state and the loaded blob both leave RAM here).
     */
    fun hasSentAtLeast(contactId: String, channel: String, n: Int): Boolean = lock.withLock {
        val blob = store.load(contactId, channel) ?: return@withLock false
        var live: DoubleRatchet? = null
        try {
            val ratchet = DoubleRatchet.deserialize(blob, nowMs = { clockMs() })
            live = ratchet
            ratchet.canSend() && ratchet.hasSentAtLeast(n)
        } catch (_: Exception) {
            false
        } finally {
            live?.wipe()
            blob.secureWipe()
        }
    }

    /**
     * Encrypt [plaintext] for [contactId] on [channel], returning the relay wire
     * blob — or null if this device is the responder and the ratchet is not yet
     * bootstrapped (the caller falls through to the legacy envelope — see the header).
     */
    fun tryEncrypt(
        contactId: String, channel: String, sharedSecret: ByteArray,
        myInboundInboxId: String, myOutboundInboxId: String, plaintext: ByteArray,
        selfIsBobOverride: Boolean? = null,
    ): ByteArray? {
        val hooks = mutableListOf<() -> Unit>()
        try {
            return lock.withLock { tryEncryptLocked(contactId, channel, sharedSecret, myInboundInboxId, myOutboundInboxId, plaintext, selfIsBobOverride, hooks) }
        } finally {
            runHooks(hooks)
        }
    }

    private fun tryEncryptLocked(
        contactId: String, channel: String, sharedSecret: ByteArray,
        myInboundInboxId: String, myOutboundInboxId: String, plaintext: ByteArray,
        selfIsBobOverride: Boolean?, hooks: MutableList<() -> Unit>,
    ): ByteArray? {
        // Retrieve-ack rule 4: a send persists, so it must never sit on top of an
        // advance the screen has not shown yet.
        discardForPersistLocked(contactId, channel, "send", hooks)
        val ratchet = loadOrInit(contactId, channel, sharedSecret, myInboundInboxId, myOutboundInboxId, selfIsBobOverride)
        return try {
            val wire = ratchet.encrypt(plaintext).encodeWire()
            persist(contactId, channel, ratchet)
            wire
        } catch (_: RatchetException) {
            // Responder with no sending chain yet — not an error, just "not ready".
            null
        } finally {
            // Zero this op's transient ratchet before dropping
            // it, so its root/DH-private/chain/skipped keys leave RAM now instead of at
            // GC. ORDER IS LOAD-BEARING: `finally` runs strictly AFTER the persist above
            // — wiping first would serialize all-zero keys into the vault and destroy the
            // ratchet. `wire` is an independent array (encodeWire copies the header's
            // PUBLIC half + the ciphertext), so it survives the wipe intact.
            ratchet.wipe()
        }
    }

    /** Decrypt a relay [wireBlob]; advances and persists the ratchet. Throws on tamper/replay. */
    fun decrypt(
        contactId: String, channel: String, sharedSecret: ByteArray,
        myInboundInboxId: String, myOutboundInboxId: String, wireBlob: ByteArray,
        selfIsBobOverride: Boolean? = null,
    ): ByteArray {
        val hooks = mutableListOf<() -> Unit>()
        try {
            return lock.withLock { decryptLocked(contactId, channel, sharedSecret, myInboundInboxId, myOutboundInboxId, wireBlob, selfIsBobOverride, hooks) }
        } finally {
            runHooks(hooks)
        }
    }

    private fun decryptLocked(
        contactId: String, channel: String, sharedSecret: ByteArray,
        myInboundInboxId: String, myOutboundInboxId: String, wireBlob: ByteArray,
        selfIsBobOverride: Boolean?, hooks: MutableList<() -> Unit>,
    ): ByteArray {
        discardForPersistLocked(contactId, channel, "single decrypt", hooks)   // rule 4
        val ratchet = loadOrInit(contactId, channel, sharedSecret, myInboundInboxId, myOutboundInboxId, selfIsBobOverride)
        return try {
            val rm = decodeRatchetWire(wireBlob)
            val plain = ratchet.decrypt(rm.header, rm.ciphertext)
            persist(contactId, channel, ratchet)
            plain
        } finally {
            // Same drop-site wipe as [tryEncrypt] — AFTER persist, never before.
            // On the throw paths (tamper / replay / malformed wire) nothing was
            // persisted and the mutated state is discarded exactly as before, now
            // zeroed on the way out. `plain` is the AEAD output, not ratchet state.
            ratchet.wipe()
        }
    }

    /** What one [decryptBatch] did to the skipped-key cache, and which wires it deferred. */
    class DecryptBatchReport {
        var skippedBefore: Int = 0
        var skippedAfter: Int = 0
        /** Deferred wire indices and why. */
        val deferred: MutableMap<Int, DoubleRatchet.SkipDamage> = linkedMapOf()
        /** Per DECRYPTED wire index: was it opened from a cached skipped key (out of
         *  order / withheld), and the receiving-step ordinal right after it. */
        val decrypted: MutableMap<Int, WireOrigin> = mutableMapOf()
        /**
         * Retrieve-ack: wire indices this drain did NOT process — the tail after the
         * consecutive-failure cutoff, a blob refused only because the per-drain work
         * budget ran out (a fresh drain's budget may well open it), and every wire of
         * a persisting drain that met an uncommitted advance (rule 3). The caller must
         * NOT ack these: the relay hands them back on the next drain. Every other
         * null result (tamper, replay/duplicate, malformed) WAS processed and is acked.
         */
        val notProcessed: MutableSet<Int> = mutableSetOf()
        /** Retrieve-ack: the advance a `persist = false` drain left uncommitted, or
         *  null when it advanced nothing (or ran in persist mode). */
        var pendingTicket: PendingTicket? = null
        /** Retrieve-ack: the uncommitted head a `persist = false` drain built ON (same
         *  drain group), or null when it decrypted from the store. Its rejections are
         *  only final once that base is committed. */
        var baseTicket: PendingTicket? = null
    }

    /** Where a decrypted wire sat in the peer's chain history. */
    class WireOrigin(val fromSkippedKey: Boolean, val receivingStep: Int)

    /**
     * Reliability/DoS: decrypt a whole drain of wire blobs against
     * ONE loaded ratchet — loaded once, persisted once. The per-blob [decrypt]
     * reloaded the entire ratchet from SQLCipher (`getMeta` read + `deserialize`)
     * for EVERY blob before the AEAD even rejected a forgery, so a malicious relay
     * could stuff up to `MAX_BLOBS_PER_POLL` ratchet-tagged junk blobs per ~1 Hz
     * poll and amplify DB/CPU/battery. This removes that per-blob reload.
     *
     * Isolation is preserved: [DoubleRatchet.decrypt] mutates ratchet state (skip
     * keys / DH-ratchet) BEFORE it verifies the tag, so a forged blob would poison
     * the shared in-memory ratchet for later REAL blobs. We keep a serialized
     * snapshot of the last-good state, roll back to it on ANY failure, and
     * re-checkpoint only after a genuine decrypt — so a forgery advances nothing
     * (matching the old per-blob discard-on-failure). Returns one entry per wire in
     * order; null = dropped (tamper / replay / malformed / too short / past the
     * cutoff below).
     *
     * The drain is BUDGETED. Two independent
     * bounds, both of which honest traffic is structurally incapable of hitting:
     *
     *  - a [RatchetWorkBudget] shared by every blob in this batch (and carried across
     *    the rollbacks), charging DH steps and skipped-key derivations and REFUNDING
     *    every attempt that authenticated. `MAX_SKIP` bounds one decrypt; nothing
     *    bounded the sum, and the rollback made each of up to `MAX_BLOBS_PER_POLL`
     *    forged blobs repeat the full ~1026 HMAC + 3 X25519 price.
     *  - [MAX_CONSECUTIVE_FAILURES_PER_BATCH] consecutive rejections end the batch.
     *
     * WHY ENDING THE BATCH IS SAFE. (Retrieve-ack, 2026-11-03: the tail past the cutoff
     * is now reported in [DecryptBatchReport.notProcessed], is NOT acked, and comes back
     * on the next drain — so it is no longer lost at all. The original reasoning, kept
     * for the pre-lease relay:) The wires in a drain all come from ONE inbox and
     * are already gone from the relay, so "stop early" can only lose blobs that were
     * (a) the attacker's own junk, or (b) real blobs behind a genuine chain desync —
     * and a desync is not something a later blob in the same drain repairs (the
     * rollback restores the same state before each one, so every subsequent blob
     * meets identical conditions). The one actor who could exploit the cutoff to
     * destroy honest messages is a hostile relay ordering junk in front of them, and
     * a hostile relay can simply not deliver them instead — no new capability. Real
     * messages never fail, so a legitimate backlog never advances the counter at all.
     *
     * The SAME argument, and the same residual, cover the work budget: injecting the
     * 8 distinct new-ratchet-key forgeries it takes to exhaust the DH ceiling requires
     * a write capability for this inbox, i.e. the peer or the relay — and either can
     * already withhold the message it would go on to starve. In exchange, an honest
     * drain is untouched (a real drain holds AT MOST ONE receiving DH step: the peer's
     * ratchet key only changes when the peer receives from us, and ours only changes
     * when we decrypt a new peer key, so while we are not draining the peer can
     * ratchet exactly once).
     */
    fun decryptBatch(
        contactId: String, channel: String, sharedSecret: ByteArray,
        myInboundInboxId: String, myOutboundInboxId: String, wires: List<ByteArray>,
        selfIsBobOverride: Boolean? = null,
        // DEFER (never decrypt) a wire whose decrypt would destroy or refuse
        // something the receive path still needs — see
        // [DoubleRatchet.wouldDamageSkippedKeys]. Its index lands in
        // [DecryptBatchReport.deferred] and its result is null. Off by default.
        deferDamaging: Boolean = false,
        // Optional out-parameter (skipped-key counts before/after + deferrals).
        report: DecryptBatchReport? = null,
        // Only wires up to this size are ever deferred; a larger one
        // goes through the ordinary decrypt-or-reject, so junk cannot bloat the store.
        maxDeferrableWireBytes: Int = Int.MAX_VALUE,
        // Retrieve-ack: false = keep the advance UNCOMMITTED in RAM (a
        // [PendingTicket] in [report], persisted only by [commitPending]) — the
        // conversation-screen mode. [drainGroup] (required then) is the drain-group
        // identity of rules 1/2. True = today's behaviour, persisted before return.
        persist: Boolean = true,
        drainGroup: Any? = null,
    ): List<ByteArray?> {
        require(persist || drainGroup != null) { "an uncommitted drain needs a drain group" }
        val hooks = mutableListOf<() -> Unit>()
        try {
            return lock.withLock {
                decryptBatchLocked(
                    contactId, channel, sharedSecret, myInboundInboxId, myOutboundInboxId, wires,
                    selfIsBobOverride, deferDamaging, report, maxDeferrableWireBytes, persist, drainGroup, hooks,
                )
            }
        } finally {
            runHooks(hooks)
        }
    }

    private fun decryptBatchLocked(
        contactId: String, channel: String, sharedSecret: ByteArray,
        myInboundInboxId: String, myOutboundInboxId: String, wires: List<ByteArray>,
        selfIsBobOverride: Boolean?, deferDamaging: Boolean, report: DecryptBatchReport?,
        maxDeferrableWireBytes: Int, persist: Boolean, drainGroup: Any?,
        hooks: MutableList<() -> Unit>,
    ): List<ByteArray?> {
        val key = pendingKey(contactId, channel)
        expirePendingLocked(key, hooks)                                   // rule 5
        pendingLineage[key]?.let { lineage ->
            if (persist) {
                // Rule 3: never build on (or overwrite) an advance a screen has not
                // shown yet. Nothing is loaded, nothing is spent, nothing is written.
                if (wires.isNotEmpty()) {
                    platformLogWarn(LOG_TAG, "ratchet: ${wires.size} blob(s) left for the next drain (a conversation screen holds an uncommitted advance)")
                }
                report?.notProcessed?.addAll(wires.indices)
                return List(wires.size) { null }
            }
            // Rule 2 (another drain group), and a defensive bound on rule 1.
            if (lineage.last().drainGroup !== drainGroup || lineage.size >= MAX_PENDING_LINEAGE) {
                platformLogWarn(LOG_TAG, "ratchet: ${lineage.size} stale uncommitted advance(s) discarded by a newer screen poll — re-delivery follows")
                discardFromLocked(key, 0, hooks)
            }
        }
        val base = if (persist) null else pendingLineage[key]?.last()
        report?.baseTicket = base
        val budget = workBudgetFactory()
        val baseSnapshot = base?.snapshot
        var ratchet = (if (baseSnapshot != null) DoubleRatchet.deserialize(baseSnapshot, nowMs = { clockMs() })
            else loadOrInit(contactId, channel, sharedSecret, myInboundInboxId, myOutboundInboxId, selfIsBobOverride))
            .also { it.workBudget = budget }
        // The compare-and-swap reference for a new advance: inherited along a chain,
        // else the store blob as loadOrInit left it (after any init / prune persist).
        val storeFp: ByteArray? = if (persist) null
            else base?.storeFingerprint?.copyOf() ?: try { storeFingerprint(contactId, channel) } catch (_: Exception) { null }
        report?.skippedBefore = ratchet.skippedKeyCount()
        var snapshot = ratchet.serialize()          // last-good state to roll back to
        var advanced = false
        var consecutiveFailures = 0
        var cutoff = false
        val results = ArrayList<ByteArray?>(wires.size)
        try {
            for (wire in wires) {
                // Past the cutoff: no decode, no crypto — the remaining wires are
                // reported as undecryptable, which is what the caller already does with
                // every other drop (MessageManager logs the count + the cleartext
                // header indices of each).
                if (cutoff) { report?.notProcessed?.add(results.size); results.add(null); continue }
                val rm = try {
                    decodeRatchetWire(wire)
                } catch (_: Exception) {
                    // A malformed wire is deliberately NEUTRAL for the cutoff: it costs no
                    // crypto at all (a length check + two copyOfRange), so it is not worth
                    // spending any of the honest-traffic margin on.
                    results.add(null); continue   // malformed / too short
                }
                // A pure header-vs-state check — no crypto, so neutral for the
                // cutoff and the work budget, exactly like a malformed wire above.
                if (deferDamaging && wire.size <= maxDeferrableWireBytes) {
                    val damage = ratchet.wouldDamageSkippedKeys(rm.header)
                    if (damage != DoubleRatchet.SkipDamage.NONE) {
                        report?.deferred?.put(results.size, damage)
                        results.add(null)
                        continue
                    }
                }
                val fromSkipped = ratchet.hasSkippedKeyFor(rm.header)
                budget.beginAttempt()
                val refusalsBefore = budget.refusals()
                try {
                    val index = results.size
                    results.add(ratchet.decrypt(rm.header, rm.ciphertext))   // mutates `ratchet`
                    report?.decrypted?.put(index, WireOrigin(fromSkipped, ratchet.receivingStepCount()))
                    budget.refundAttempt()   // authenticated ⇒ this work was not wasted
                    consecutiveFailures = 0
                    advanced = true
                    snapshot.secureWipe()
                    snapshot = ratchet.serialize()   // re-checkpoint after a genuine message
                } catch (_: Exception) {
                    // Forged / replayed: `decrypt` already mutated `ratchet` (skip keys /
                    // DH-ratchet) before the AEAD rejected it — roll back so the forgery
                    // can't corrupt a later real blob's chain. `deserialize` is read-only
                    // on `snapshot`, so repeated rollbacks reuse the same snapshot.
                    //
                    // The discarded poisoned `ratchet` holds a
                    // freshly-generated DH private key + derived root/chain/skipped keys.
                    // Zero them before dropping the reference so they leave RAM now, not at
                    // GC (DoubleRatchet.wipe() added for exactly this discard path).
                    ratchet.wipe()
                    // The budget is a property of the DRAIN, so re-attach it to the
                    // restored instance — otherwise every rollback would hand the attacker
                    // a fresh allowance and the ceiling would be vacuous.
                    ratchet = DoubleRatchet.deserialize(snapshot, nowMs = { clockMs() })
                        .also { it.workBudget = budget }
                    // Retrieve-ack: refused by the spent per-drain budget, not by the
                    // AEAD — a fresh drain's budget may open it, so it is not acked.
                    if (budget.refusals() > refusalsBefore) report?.notProcessed?.add(results.size)
                    results.add(null)
                    consecutiveFailures += 1
                    if (consecutiveFailures >= MAX_CONSECUTIVE_FAILURES_PER_BATCH) {
                        cutoff = true
                        // Counts only — no contact id, no inbox id, no header field.
                        platformLogWarn(
                            LOG_TAG,
                            "ratchet drain cutoff after $consecutiveFailures consecutive failures " +
                                "(${results.size} of ${wires.size} blobs processed; budget spent: " +
                                "${budget.spentDhSteps()} DH, ${budget.spentChainDerivations()} derivations)",
                        )
                    }
                }
            }
            if (advanced) {
                if (persist) {
                    persist(contactId, channel, ratchet)
                } else {
                    // Retrieve-ack: the advance stays in RAM until [commitPending].
                    val ticket = PendingTicket(contactId, channel, drainGroup!!, ratchet.serialize(), clockMs(), storeFp)
                    pendingLineage.getOrPut(key) { mutableListOf() }.add(ticket)
                    report?.pendingTicket = ticket
                }
            }
            report?.skippedAfter = ratchet.skippedKeyCount()
        } finally {
            // Zero the FINAL live ratchet too — the rollback
            // path above already wipes each poisoned one it discards, but the object
            // the drain ends on was previously dropped unwiped. `ratchet` is a var, so
            // this reads whatever instance is current (post-rollback included), and the
            // `finally` runs strictly AFTER `if (advanced) persist(...)` — wiping before
            // that would persist all-zero keys. The decrypted plaintexts in `results`
            // are independent arrays and are unaffected.
            ratchet.wipe()
            snapshot.secureWipe()
        }
        return results
    }

    /** True once this device can send on [channel] (Alice always; Bob after first receive). */
    fun isBootstrapped(
        contactId: String, channel: String, sharedSecret: ByteArray,
        myInboundInboxId: String, myOutboundInboxId: String,
        selfIsBobOverride: Boolean? = null,
    ): Boolean = lock.withLock {
        // Cheap probe: Alice has a sending chain from init; Bob only after his first
        // receive — `canSend()` reports exactly that.
        val ratchet = loadOrInit(contactId, channel, sharedSecret, myInboundInboxId, myOutboundInboxId, selfIsBobOverride)
        try {
            ratchet.canSend()
        } finally {
            // This probe never persists of its own accord (loadOrInit's fresh-init
            // branch already persisted before returning), so the wipe is safe and, as
            // everywhere else, runs after any persist rather than before it.
            ratchet.wipe()
        }
    }

    /**
     * The role for a FRESH init.
     *
     * [selfIsBobOverride] is the caller's already-resolved v2 answer (`parity XOR
     * secret order` — see [ratchetSelfIsBobFromRoleOrder]), or null when this
     * pairing has no proof the peer runs the v2 rule, in which case the legacy
     * id-order rule is used UNCHANGED. Threaded per call rather than held as a
     * field because this manager is deliberately stateless between calls and the
     * answer is per-contact.
     *
     * Two things this does NOT change, both load-bearing:
     *  - it is only ever consulted when NO state is persisted, so an existing
     *    pairing's role is whatever its blob already says. No blob format change,
     *    no migration, nothing to re-derive;
     *  - a role a v2 pairing computes here is a pure function of values fixed at
     *    pairing, so the re-init that follows [onCorruptReinit] lands on exactly
     *    the same role — which the id-order rule cannot promise, because the
     *    outbound row it reads is peer-supplied and mutable.
     */
    private fun loadOrInit(
        contactId: String, channel: String, sharedSecret: ByteArray,
        myInboundInboxId: String, myOutboundInboxId: String,
        selfIsBobOverride: Boolean?,
    ): DoubleRatchet {
        store.load(contactId, channel)?.let { blob ->
            try {
                val loaded = DoubleRatchet.deserialize(blob, nowMs = { clockMs() })
                // The load already dropped expired (and over-cap legacy) skipped
                // keys from RAM — write the pruned state back NOW so they leave the
                // VAULT too. Without this a pairing that goes silent after an expiry
                // would keep the dead keys at rest until its next real message.
                // Best-effort and non-fatal: a failed persist just retries next op, and
                // it runs strictly before the caller's own persist/wipe ordering.
                if (loaded.droppedExpiredSkippedOnLoad()) {
                    try { persist(contactId, channel, loaded) } catch (_: Exception) {}
                }
                return loaded
            } catch (e: Exception) {
                // Corrupt/truncated persisted ratchet state — a LOCAL disk anomaly
                // (the vault is encrypted + authenticated, so this is never
                // attacker-injected). Fail GRACEFULLY: fall through and re-init a
                // fresh ratchet instead of crash-looping (an uncaught Kotlin
                // exception SIGABRTs iOS). The self-describing wire + legacy
                // fallback let the peer recover.
                platformLogError(LOG_TAG, "corrupt ratchet state ($channel) — reinitializing: ${e::class.simpleName}")
                // Let the caller clear the sticky dr-rxlock/dr-on so
                // the re-inited pair re-bootstraps via legacy instead of the armed
                // lock silently dropping every recoverable blob.
                onCorruptReinit(contactId, channel)
            } finally {
                // The loaded blob is an independent
                // plaintext duplicate of the persisted ratchet key material (root
                // key, DH private key, cached skipped message keys) — deserialize
                // only COPIES ranges out of it. Wipe the transient copy on BOTH the
                // success (return above) and corrupt-reinit paths, matching persist().
                // (VaultRatchetStore.load hands back a fresh decodeBase64 array, so
                // this wipes our copy, never the at-rest ciphertext.)
                blob.secureWipe()
            }
        }
        val selfIsBob = selfIsBobOverride ?: ratchetSelfIsBob(myInboundInboxId, myOutboundInboxId)
        val ratchet = if (selfIsBob)
            DoubleRatchet.initAsBob(sharedSecret, nowMs = { clockMs() })
        else DoubleRatchet.initAsAlice(sharedSecret, nowMs = { clockMs() })
        persist(contactId, channel, ratchet)   // persist the fresh state so role is stable
        return ratchet
    }

    private fun persist(contactId: String, channel: String, ratchet: DoubleRatchet) {
        val blob = ratchet.serialize()
        try {
            store.save(contactId, channel, blob)
        } finally {
            blob.secureWipe()
        }
    }

    internal companion object {
        /**
         * Consecutive rejected blobs that end a drain.
         *
         * A real message NEVER lands here — it authenticates — so an honest backlog of
         * any size (a week offline, hundreds of messages, a direction change in the
         * middle) leaves this counter at 0 for the whole batch. It is reset by every
         * successful decrypt, so junk interleaved with real traffic only ends the drain
         * once 8 rejections arrive back to back.
         *
         * 8 is chosen above the plausible honest run of rejections: a duplicate blob
         * from an idempotent send-retry, or a couple of blobs the peer sent from a chain
         * we have already ratcheted past. Beyond that the state is a desync, and the
         * remaining blobs of the SAME drain cannot repair it — the rollback restores the
         * identical state before each one, so they all meet identical conditions.
         */
        const val MAX_CONSECUTIVE_FAILURES_PER_BATCH = 8

        /**
         * Retrieve-ack rule 5: how long an UNCOMMITTED advance may live before the
         * next touch of that ratchet discards it. A screen commits right after it
         * renders (milliseconds), so only an abandoned poll ever ages out. Must stay
         * well under the relay's lease (`RETRIEVE_LEASE_SECONDS`, 60 s on dev): the
         * blobs of an abandoned drain are re-delivered when the lease ends, and by
         * then the advance that consumed their keys must be gone, or they would be
         * rejected as duplicates — the very loss this mode exists to prevent.
         */
        const val PENDING_ADVANCE_MAX_AGE_MS = 15_000L

        /** Retrieve-ack rule 1 bound: one screen poll chains at most a text and a
         *  group drain per contact, so a longer lineage is a bug — discard it. */
        const val MAX_PENDING_LINEAGE = 8
    }
}

package com.vg.run

// ---------------------------------------------------------------------------
// ReferralManager — remote "vouching" contact introductions (referral.md).
//
// An existing contact (the INTRODUCER) who is paired with two people can
// introduce them to each other over the relay, so they become direct contacts
// without meeting in person. Security rests on X25519: each introducee sends
// only its PUBLIC key (relayed through the introducer), and derives the shared
// key from ECDH(myPriv, peerPub). A PASSIVE introducer routes the handshake but
// only ever sees public keys + inbox offers — she cannot derive the resulting
// key, so she cannot read the new contact's messages.
//
// THREAT-MODEL CAVEAT: this holds only against a passive introducer. An
// ACTIVELY-malicious introducer CAN MITM the pair — she relays each accept
// verbatim (handleAccept below) but nothing binds the ephemeral public key to
// the real peer, so she can substitute her own X25519 keypair toward each side,
// hold two ECDH sessions, and read everything. The low-order-point guard
// (x25519EcdhChecked) does NOT stop this — the attacker uses valid keypairs.
// This is a DOCUMENTED, ACCEPTED trade-off (referral.md "Decision C": transitive
// trust, no out-of-band verification), not an oversight — the user already
// trusts the introducer. Do not "strengthen" the wording back to an
// unconditional guarantee without re-opening Decision C.
//
// Handshake (direct, non-group control messages on the control channel):
//   1. ref-offer  — introducer → each introducee: "<peer> wants to connect via
//                   me" (peer's display alias + a random introId). Stored for
//                   CONSENT — never auto-pairs.
//   2. ref-accept — introducee → introducer, RELAYED verbatim to the other
//                   introducee: the sender's ephemeral X25519 public key + a
//                   freshly-minted inbox offer (inbox ids + the write-caps the
//                   peer needs to send to it).
//   3. finalize   — LOCAL: once an introducee has BOTH its own material (from
//                   accepting) and the peer's relayed accept, it derives
//                   sharedSecret = HKDF(ECDH(myPriv, peerPub)), writes the
//                   ContactRecord + four to six inbox records (each half of the
//                   group-text pair is optional), and the contact is
//                   immediately usable. Trust is TRANSITIVE: we already trust
//                   the introducer, so there is no out-of-band verification
//                   step — vouchedByContactId just records who introduced us.
//
// PERSISTENCE MODEL. The in-flight handshake is MIRRORED into the ENCRYPTED
// VAULT's `_meta` table (see [ReferralMetaKeys] / ReferralStore.kt), because a
// RAM-only handshake is not an ephemerality property — it is a data-loss
// bug. `scrubInMemory()` runs on ORDINARY BACKGROUNDING on both platforms and
// `createSessionManagers` rebuilds an EMPTY manager on unlock, while the relay's
// control drain deletes processed blobs (acked): an introducee killed or backgrounded after
// "accept sent" hit the terminal `pending`-miss below and could NEVER finalize,
// while its peer had already committed a TRUST_REFERRED_CONFIRMED contact whose
// outbound inboxes routed to inboxes nobody polls — a silent one-way black hole.
//
// The mirrored record includes the ephemeral X25519 PRIVATE key. That is a
// deliberate, bounded trade: the same vault already holds strictly more
// sensitive material (every Double-Ratchet chain key and every inbox READ
// capability — the inbox OWNER capability), the record is single-introduction,
// TTL-bounded (7 days idle, 28 days absolute — see REFERRAL_RECORD_TTL_MS /
// REFERRAL_RECORD_MAX_LIFETIME_MS), and it is deleted INSIDE the very
// `withTransaction` that commits the referred contact. `scrubInMemory()` still
// zeroes the RAM copy on every lock/wipe — the vault copy is only a recovery
// source, and a full wipe crypto-erases it with the rest of the vault.
//
// MESSAGES, wire format, control kinds and anti-replay are untouched by this.
// ---------------------------------------------------------------------------

/** An incoming referral awaiting the user's consent (surfaced to the UI).
 *  [receivedAt] is the local activity stamp, used only for the idle TTL that
 *  ages a never-answered offer out of RAM and out of the vault. It is RE-STAMPED
 *  when the peer's accept lands against it (refresh-on-activity), so a live
 *  half-handshake cannot expire under a slow human. */
data class ReferralOffer(
    val introId: String,
    val introducerContactId: String,
    val introducerAlias: String,
    val peerAlias: String,
    val receivedAt: Long = 0L,
    /** The FIRST receive stamp — never re-stamped, so refresh-on-activity
     *  cannot carry an un-consented offer past
     *  [REFERRAL_RECORD_MAX_LIFETIME_MS]. Not for display; trailing with a
     *  default so every existing construction site is unchanged. */
    val firstSeenAt: Long = receivedAt,
)

/**
 * Fired on the INTRODUCER when an introducee's ref-accept has been handled —
 * forwarded to the other party, or durably queued for redrive.
 *
 * PURE UI SIGNALLING, RAM-ONLY. Nothing about this type is persisted, nothing it
 * carries crosses the wire, and it introduces no `_meta` key: it exists so the
 * platform can show "<X> approved your introduction" / "introduction complete"
 * without polling the handshake maps. The aliases are read from the vault at fire
 * time (they may have rotated since the session was created), which is also why a
 * deleted contact fires nothing at all — see [ReferralManager.onIntroRelayed].
 *
 * [relayed] `false` is NOT a failure the user must act on: the accept is a durable
 * obligation redriven by the control sweep, so the honest copy for it is "queued",
 * never "lost". [complete] is true only on the fire that put BOTH parties in the
 * session's relayed set, i.e. the fire on which the introduction is done.
 */
data class ReferralRelayEvent(
    val introId: String,
    /** The introducee who just approved — the accept's SENDER. */
    val acceptedByContactId: String,
    /** Their alias, read from the vault at fire time. */
    val acceptedByAlias: String,
    /** The party the accept was forwarded (or queued) to. */
    val otherContactId: String,
    val otherAlias: String,
    /** true = `sendDirectControl` succeeded; false = queued as `ref_r` for redrive. */
    val relayed: Boolean,
    /** true when BOTH parties' accepts have now been relayed (the session is done). */
    val complete: Boolean,
)

class ReferralManager(
    private val vault: VaultDatabase,
    // Provider, not instance: MessageManager is recreated on Tor reconnect.
    private val messageManager: () -> MessageManager?,
) {
    companion object {
        private const val TAG = "ReferralManager"
        private const val MAX_ALIAS_CHARS = 64
        private const val HKDF_INFO = "run-referral-v1"

        // Wall-clock cap on the accept-time inbox mint (covers BOTH inboxes
        // mintInboxPair creates). mintInbox already retries transient Tor drops
        // internally (up to ~12 attempts × the HTTP timeout), which on a flaky
        // circuit can grind for many minutes and strand the user on
        // "Connecting…". This deadline aborts the grind cleanly so a failed
        // accept returns and the UI can offer a Retry.
        //
        // Sized to match the pairing mint's proven tolerance: the pairing screen's
        // mint ([MessageManager.mintInbox] via mintInboxPair) can grind for ~8 min
        // (12 internal transient retries) and succeeds on slow/degraded Tor circuits where a single
        // inbox-PAIR mint can take several minutes. Tighter deadlines (90s, then
        // 4 min) aborted before the mint could finish and restarted from
        // scratch, so the accept never completed while pairing did. 8 min lets
        // the accept-mint complete on the same circuits pairing survives, while
        // still bounding a truly dead one (the Retry escape covers that).
        private const val ACCEPT_MINT_DEADLINE_MS = 480_000L
        // Defensive bound on early peer-accepts held before our consent, so a
        // misbehaving introducer can't grow the stash without limit.
        private const val MAX_STASHED_ACCEPTS = 64
        // The IDLE TTL for EVERY handshake record — RAM map and vault mirror
        // alike (stashed accepts included, where on overflow the OLDEST entry is
        // evicted, not the incoming one, so a fresh genuine accept is never lost
        // to a backlog of stale ones).
        //
        // That idle TTL is [REFERRAL_RECORD_TTL_MS] (7 days), and the ABSOLUTE
        // ceiling refresh-on-activity may never carry a record past (measured from
        // the un-refreshable firstSeenAt) is [REFERRAL_RECORD_MAX_LIFETIME_MS]. Both
        // live in ReferralStore.kt so the codecs and the GC cannot drift; see their
        // kdocs for why the TTL is 7 days and why an idle TTL alone is not enough.
        // Introductions we've already finalized or declined. A referral offer
        // blob lingers in the introducer's relay inbox and is re-delivered on
        // later control polls; once an intro is completed, dropping the
        // re-delivery stops the consent alert from re-appearing for a contact we
        // already added. (On iOS a lingering `.alert` also blocks the settings
        // `.sheet` from presenting — the observed cross:multi3 flake.) Bounded:
        // an introId is a stable 128-bit correlator and re-delivery only recurs
        // within the relay's inbox retention.
        private const val MAX_COMPLETED_INTROS = 128

        // [ReferralRelayEvent]s that fired before the platform installed its hook
        // (a control sweep can run first). Deliberately tiny: this is a UI signal
        // with a live audience, not an obligation, and each entry pins two
        // ALIASES in RAM. Oldest-dropped, same direction as [capInsert].
        private const val MAX_PENDING_RELAY_EVENTS = 8

        // Bound the in-flight referral maps so a paired-but-
        // misbehaving introducer/peer can't inflate memory without limit (offers/pending
        // are normally consumed on accept/finalize; introSessions was never removed).
        // Insertion-ordered maps → evict the OLDEST when at cap for a new key.
        private const val MAX_OFFERS = 128
        private const val MAX_PENDING = 128
        private const val MAX_INTRO_SESSIONS = 128
        // Same bound for the introducer's un-relayed-accept obligations.
        private const val MAX_RELAY_REDRIVES = 128

        // The referral-offer sibling of GroupManager's
        // handleInvite caps (MAX_FORCED_GROUPS_PER_CONTACT / INVITE_RATE_WINDOW_MS /
        // MAX_INVITES_PER_WINDOW in GroupManager). Before this, handleOffer had
        // ONLY the global MAX_OFFERS=128 cap above, which is shared across every
        // introducer — a single misbehaving (or compromised) introducer could mint
        // 128 attacker-chosen introIds and either fill the consent queue outright or
        // (via the oldest-first eviction) push out every OTHER introducer's genuine
        // pending offer. These two bounds gate a NEW offer per-introducer, same shape
        // as the group path: a standing cap on currently-pending offers from that one
        // introducer, and an hourly sliding-window rate on top. There is no "already
        // joined" analogue for a referral (a settled introduction leaves `offers`
        // entirely), so pending count alone is the standing cap.
        internal const val MAX_OFFERS_PER_INTRODUCER = 8
        internal const val OFFER_RATE_WINDOW_MS = 60L * 60 * 1000   // 1 hour
        internal const val MAX_OFFERS_PER_INTRODUCER_PER_WINDOW = 8
        // The _meta key prefix lives in ReferralMetaKeys (ReferralStore.kt) —
        // it is ALSO the delete-contact purge classifier's match target
        // (isReferralMetaResidueForContact), so it has exactly one definition.

        // Bounded local re-roll attempts before falling
        // back to a numeric-suffix disambiguation — see [sanitizedPeerAlias]. At
        // 1,620 possible generated aliases this is astronomically unlikely to be
        // exhausted by chance; it only bites if the vault already holds a huge
        // number of contacts, or in a pathological test fixture.
        private const val MAX_ALIAS_REROLL_ATTEMPTS = 20

        // Bounded redrive budgets. ONE attempt per record per control sweep (the
        // sweep has its own cadence + per-contact jitter), so this is a cap on
        // total attempts, never a tight retry loop. Exhausting the budget stops
        // the retries but KEEPS the record: the accept material must stay
        // reusable, because `sendDirectControl == false` does not prove the blob
        // never landed and a fresh keypair would derive a secret the peer can
        // never match. The TTL is what finally reclaims it.
        //
        // These budgets are PER SESSION. [rehydrate] resets every persisted
        // attempt counter to 0 while KEEPING the record, because a budget spent
        // against a relay that was down for one session must not permanently
        // disarm the obligation for the life of the record — that turned a
        // transport outage into the same silent half-pair the redrives exist to
        // prevent. The overall bound is the record TTL, not the counter.
        private const val MAX_ACCEPT_SEND_ATTEMPTS = 12
        private const val MAX_RELAY_REDRIVE_ATTEMPTS = 12
        // The introducer's own OFFER leg, same shape and same per-session
        // reset. One attempt per sweep covers BOTH undelivered sides.
        private const val MAX_OFFER_SEND_ATTEMPTS = 12

        /** Insert [key]=[value], evicting the oldest entry first if already at [max]. */
        private fun <K, V> MutableMap<K, V>.capInsert(key: K, value: V, max: Int) {
            if (size >= max && key !in this) keys.firstOrNull()?.let { remove(it) }
            this[key] = value
        }

        internal fun newIntroId(): String = encodeBase64Url(generateSecureRandom(16))

        // Derive the referred contactId DETERMINISTICALLY from the
        // introId, so a re-driven finalize (peer re-delivery, or a retry after a torn/
        // rolled-back persist — even across an app restart) produces the SAME contactId.
        // The INSERT-OR-REPLACE writes then upsert idempotently instead of minting a
        // second, orphaned contact. Same 18-byte / base64url shape as the random id.
        internal fun referredContactIdFor(introId: String): String =
            encodeBase64Url(
                sha256("referral-contact|".encodeToByteArray() + introId.encodeToByteArray())
                    .copyOfRange(0, 18)
            )

        // The completed-intro tombstone never stores the RAW introId:
        // [referredContactIdFor] derives the referred contact's id DETERMINISTICALLY
        // (and salt-free) from that same introId — identically on the peer's device —
        // so a raw introId surviving a contact delete would be a computable
        // cross-device link to the relationship the user just erased. The dedupe guard only ever
        // needs EQUALITY (has this introId already been settled?), never the
        // preimage, so it stores THIS hash instead — a DIFFERENT domain-separated
        // derivation than [referredContactIdFor], so it can never be turned back
        // into the contact id. See [ReferralMetaKeys.COMPLETED_KEY_V2].
        internal fun doneTokenFor(introId: String): String =
            encodeBase64Url(
                sha256("referral-done|".encodeToByteArray() + introId.encodeToByteArray())
                    .copyOfRange(0, 18)
            )
    }

    private val lock = SyncLock()

    /**
     * Injectable wall-clock seam, for the MID-SESSION time evaluations ONLY:
     * [gcExpired]'s TTL sweep, [handleAccept]'s stash aging, and [acceptOffer]'s
     * mint deadline. Production NEVER sets it — the default is the real clock —
     * and it exists so the 7-day idle TTL / 28-day ceiling and the 8 min mint deadline can be driven in a
     * unit test without real waits. Same shape and same rationale as
     * `MessageManager.relayLostClockMs`.
     *
     * Deliberately NOT wired into [rehydrate]: that runs from `init`, before any
     * caller could install a fake, so a seam there would be dead code that only
     * blurred where this one applies. The record `createdAt` stamps stay on the
     * real clock too, so a test creates records normally and then moves this
     * clock forward — exactly the shape of a session that outlived the TTL.
     */
    internal var clockMs: () -> Long = { currentTimeMillis() }

    /**
     * Fired ONCE per SUCCESSFUL finalize — i.e. exactly when a referred contact
     * has been committed to the vault — so the platform can refresh its contact
     * list without polling. Nullable and best-effort: a throw from the hook is
     * caught and logged, never allowed to fail a finalize that already committed.
     *
     * Invoked OUTSIDE `lock` and AFTER the transaction has committed, so the hook
     * may re-enter this manager or read the vault freely. It is NOT fired for the
     * rejected finalizes (already-exists, inbox-in-use, malformed peer material,
     * a failed vault transaction) — nothing was written, so there is nothing for
     * a UI to show.
     *
     * REHYDRATE-TIME FINALIZES ARE COVERED. `rehydrate()` runs from `init`, before
     * any caller can assign this, so a finalize there would otherwise be silently
     * unannounced — precisely the case that matters most (the peer accepted while
     * we were dead). Such a finalize latches [pendingFinalizedNotice], which this
     * property's setter flushes the moment a hook is installed. Multiple deferred
     * finalizes collapse into ONE call: the signal carries no identity, it means
     * "your contact list changed".
     */
    var onIntroFinalized: (() -> Unit)? = null
        // The assignment AND the deferred-notice claim happen under `lock`, in the
        // same critical section [notifyIntroFinalized] uses to read the hook and
        // latch. Otherwise a finalize racing the assignment could latch a notice
        // the setter had already looked past, silently losing the one refresh
        // signal for a contact that really was committed. The hook itself is
        // invoked AFTER the lock is released (SyncLock is non-reentrant).
        set(value) {
            val owed = lock.withLock {
                field = value
                val claim = value != null && pendingFinalizedNotice
                if (claim) pendingFinalizedNotice = false   // one-shot; never re-delivered
                claim
            }
            if (owed) value?.let { invokeIntroFinalizedHook(it) }
        }

    /** Set when a finalize committed while [onIntroFinalized] was still null. */
    private var pendingFinalizedNotice = false

    /** Invokes the hook outside the lock, or latches the notice if none is set. */
    private fun notifyIntroFinalized() {
        val hook = lock.withLock {
            val h = onIntroFinalized
            if (h == null) pendingFinalizedNotice = true
            h
        }
        if (hook != null) invokeIntroFinalizedHook(hook)
    }

    /** A hook that throws must never fail a finalize that already committed. */
    private fun invokeIntroFinalizedHook(hook: () -> Unit) {
        try { hook() } catch (e: Exception) {
            platformLogWarn(TAG, "onIntroFinalized hook threw: ${e::class.simpleName}")
        }
    }

    /**
     * INTRODUCER-side UI signal: an introducee's accept has been handled — see
     * [ReferralRelayEvent]. Nullable and best-effort, exactly like
     * [onIntroFinalized]: a throw from the hook is caught and logged, never
     * allowed to fail the relay path it rides on. Invoked OUTSIDE `lock`, so the
     * hook may re-enter this manager or read the vault freely.
     *
     * WHAT IT DOES NOT DO: it writes nothing (no `_meta` key, no wire byte, no
     * control kind, no counter/epoch touch). It is derived state about work that
     * has already happened, and losing it can never strand an introduction — the
     * `ref_r` redrive obligation is the durable part and is untouched by any of
     * this.
     *
     * DEDUPE + DEFERRAL, both load-bearing:
     *  - a re-delivered accept (the relay re-serves a blob for its retention
     *    window) for a side we have ALREADY relayed fires nothing — the session's
     *    `relayed` set is read under the same lock as the session lookup and gates
     *    the fire, so one approval produces one event;
     *  - events that fire while this is null are latched in [pendingRelayEvents]
     *    (bounded, oldest dropped) and flushed by this setter, because the control
     *    sweep can relay an accept before platform code has installed the hook.
     *    Unlike [onIntroFinalized]'s one-bit notice these do NOT collapse: each
     *    event names a different party and a different outcome.
     */
    var onIntroRelayed: ((ReferralRelayEvent) -> Unit)? = null
        // Assignment + drain happen in the SAME critical section
        // [notifyIntroRelayed] uses to read the hook and latch — otherwise an
        // event racing the assignment could be latched just after the setter
        // looked past the list, and would then wait for the NEXT assignment that
        // may never come. The hooks run after the lock is released (SyncLock is
        // non-reentrant).
        set(value) {
            val owed = lock.withLock {
                field = value
                if (value == null || pendingRelayEvents.isEmpty()) {
                    emptyList()
                } else {
                    pendingRelayEvents.toList().also { pendingRelayEvents.clear() }
                }
            }
            if (value != null) for (event in owed) invokeIntroRelayedHook(value, event)
        }

    /** Events that fired while [onIntroRelayed] was still null. Holds ALIASES, so
     *  [scrubInMemory] clears it. Bounded by [MAX_PENDING_RELAY_EVENTS]. */
    private val pendingRelayEvents = mutableListOf<ReferralRelayEvent>()

    /** Invokes the hook outside the lock, or latches the event if none is set. */
    private fun notifyIntroRelayed(event: ReferralRelayEvent) {
        val hook = lock.withLock {
            val h = onIntroRelayed
            if (h == null) {
                while (pendingRelayEvents.size >= MAX_PENDING_RELAY_EVENTS) pendingRelayEvents.removeAt(0)
                pendingRelayEvents.add(event)
            }
            h
        }
        if (hook != null) invokeIntroRelayedHook(hook, event)
    }

    /** A hook that throws must never break the relay path that fired it. */
    private fun invokeIntroRelayedHook(hook: (ReferralRelayEvent) -> Unit, event: ReferralRelayEvent) {
        try { hook(event) } catch (e: Exception) {
            platformLogWarn(TAG, "onIntroRelayed hook threw: ${e::class.simpleName}")
        }
    }

    /**
     * Builds and delivers one [ReferralRelayEvent]. Callers have already RELEASED
     * `lock` (SyncLock is non-reentrant, the vault has its own lock, and the hook
     * may re-enter this manager).
     *
     * A party that is no longer in the vault fires NOTHING — there is nothing to
     * show for a contact the user has erased, and a placeholder alias would name a
     * relationship that was deliberately removed. Never throws: this is a UI
     * garnish on the control sweep's relay path, and a vault read that explodes
     * must not take that path down with it.
     */
    private fun fireIntroRelayed(
        introId: String,
        acceptedByContactId: String,
        otherContactId: String,
        relayed: Boolean,
        complete: Boolean,
    ) {
        val event = try {
            val acceptedByAlias = vault.getContact(acceptedByContactId)?.alias ?: return
            val otherAlias = vault.getContact(otherContactId)?.alias ?: return
            ReferralRelayEvent(
                introId = introId,
                acceptedByContactId = acceptedByContactId,
                acceptedByAlias = acceptedByAlias,
                otherContactId = otherContactId,
                otherAlias = otherAlias,
                relayed = relayed,
                complete = complete,
            )
        } catch (e: Exception) {
            platformLogWarn(TAG, "referral relay event: alias read failed — not surfaced: ${e::class.simpleName}")
            return
        }
        notifyIntroRelayed(event)
    }

    // Introducer role: introId → the two contacts being introduced. [relayed]
    // records which side's accept we have already forwarded; once BOTH are in it
    // the introduction is complete and the persisted record is dropped.
    //
    // [offered] is the offer-redrive half — the sides whose OFFER we have PROVABLY delivered.
    // Without it a dropped circuit would swallow one leg silently: the
    // introducer believes the introduction is under way and one introducee
    // never sees a prompt. An undelivered side is a durable obligation
    // redriven by [runMaintenance].
    //
    // [createdAt] is REFRESHABLE (refresh-on-activity): relaying an accept for this session
    // re-stamps it. [firstSeenAt] never moves and bounds that refreshing.
    private class IntroSession(
        val contactA: String,
        val contactB: String,
        val relayed: MutableSet<String> = mutableSetOf(),
        var createdAt: Long = currentTimeMillis(),
        val offered: MutableSet<String> = mutableSetOf(),
        var offerAttempts: Int = 0,
        val firstSeenAt: Long = createdAt,
    ) {
        fun bothOffersDelivered() = contactA in offered && contactB in offered
    }
    private val introSessions = mutableMapOf<String, IntroSession>()

    // Introducer role: an accept we could NOT forward (sendDirectControl==false /
    // threw). Keyed "<introId>:<toContactId>" — one obligation per direction, since
    // an introduction relays two accepts. Retried once per control sweep.
    private class RelayRedrive(
        val introId: String,
        val toContactId: String,
        val fromContactId: String,
        val body: String,
        var attempts: Int = 0,
        // Refreshed on every redrive attempt; bounded by [firstSeenAt].
        var createdAt: Long = currentTimeMillis(),
        val firstSeenAt: Long = createdAt,
    )
    private val relayRedrives = mutableMapOf<String, RelayRedrive>()
    private fun redriveKey(introId: String, toContactId: String) = "$introId:$toContactId"

    // Introducee role: introId → my pending handshake material.
    //
    // [sent] is the crash-window discriminator: the vault record is written
    // st=0 BEFORE the accept leaves and flipped to st=1 only once the relay has
    // accepted it. An entry that is not yet `sent` is NOT finalizable — a peer
    // accept arriving against it is stashed instead, so a referred contact is
    // only ever committed once both sides provably exchanged material.
    private class Pending(
        val introId: String,
        val introducerContactId: String,
        val peerAlias: String,
        var keypair: X25519Keypair? = null,
        var minted: MintedInboxPair? = null,
        var finalized: Boolean = false,
        var sent: Boolean = false,
        var sendAttempts: Int = 0,
        // Refreshed on a redrive attempt and when the peer's accept lands
        // against us; bounded by [firstSeenAt], which never moves.
        var createdAt: Long = currentTimeMillis(),
        val firstSeenAt: Long = createdAt,
    )
    private val pending = mutableMapOf<String, Pending>()
    private val offers = mutableMapOf<String, ReferralOffer>()
    // A peer's accept that arrived BEFORE we accepted (introId → raw body). The
    // two introducees mint + accept independently, so on a slow/contended link
    // one side's accept can be relayed to the other before that other has
    // accepted. Stash it and apply it the moment we accept, instead of dropping
    // it (which would leave the early accepter unable to ever finalize).
    // [fromContactId] is the introducer that relayed it — the contact reference
    // the delete-contact purge classifies on.
    private data class StashedAccept(val body: String, val stampMs: Long, val fromContactId: String)
    private val stashedAccepts = mutableMapOf<String, StashedAccept>()
    // HASHED (doneTokenFor) tokens of introIds we've finalized or declined — a
    // re-delivered offer/accept for one of these is dropped in handleOffer /
    // finalize so its consent alert never re-appears. Insertion-ordered so the
    // oldest evicts once over MAX_COMPLETED_INTROS. Must be called with `lock`
    // held (SyncLock is non-reentrant).
    // Persisted as ONE bounded `ref_done2` value: without it a relaunch re-presents
    // the consent dialog for an introduction the user already settled (the
    // documented cross:multi3 flake — on iOS a lingering `.alert` also blocks the
    // settings `.sheet`).
    //
    // This set holds `doneTokenFor(introId)`, NOT the raw introId. The
    // raw introId is a salt-free preimage of `referredContactIdFor(introId)` —
    // the referred contact's id, identical on the peer's device — so persisting
    // it verbatim left a computable cross-device link to a contact the user had
    // just deleted. The dedupe only ever needs equality, so a hash under a
    // DIFFERENT derivation closes the leak without changing the guard's
    // behaviour. Every membership check below hashes the candidate introId
    // before comparing.
    private val completedIntros = LinkedHashSet<String>()

    // True while the persisted v2 tombstone set could not be READ at rehydrate (a
    // throw, not an absent row). Until a read succeeds, [completedIntros] lacks the
    // stored tombstones, so a write of it would overwrite them; [persistCompleted]
    // therefore re-reads and merges first, and skips the write while that fails.
    private var completedV2Unreadable = false

    private fun markIntroCompleted(introId: String) {
        completedIntros.add(doneTokenFor(introId))
        while (completedIntros.size > MAX_COMPLETED_INTROS) {
            completedIntros.remove(completedIntros.iterator().next())
        }
        persistCompleted()
    }

    init {
        // Load whatever the previous session left behind. NEVER throws: a vault
        // read failure or a corrupt record must degrade to "no record", never to
        // a failed manager construction (which would take unlock down with it).
        try { rehydrate() } catch (e: Exception) {
            platformLogWarn(TAG, "referral rehydrate failed — continuing empty: ${e::class.simpleName}")
        }
    }

    /**
     * Scrub in-flight referral handshake state
     * from RAM. Until a handshake is finalized, declined, evicted or aged out by the
     * TTL GC ([gcExpired]) — the other places an ephemeral X25519 PRIVATE key is
     * wiped — an accepted-but-not-yet-finalized handshake (peer offline / abandoned /
     * dropped Tor circuit) keeps its 32-byte private key resident in [pending]; this
     * scrub is the lock-time fence for that window. Both platform callers tear this
     * manager down by NULLING the reference only (RunViewModel / IosAppController, on
     * lock AND on panic wipe), which never zeroes the bytes while the process is kept
     * alive on the deniability screen — so a live/AFU RAM image recovers the key and,
     * with the peer's cleartext ephemeral public key, the HKDF-bound shared secret. This
     * OVERWRITES every in-flight private key (fill(0), not just a dropped reference) and
     * then clears all handshake maps. Idempotent.
     *
     * WHO MUST CALL THIS: the platform teardown sites, immediately BEFORE `referralManager
     * = null` — Android `RunViewModel.performEmergencyWipe()` + `onCleared()`, iOS
     * `IosAppController.lock()` + `emergencyWipe()`.
     *
     * RAM-ONLY, BY DESIGN. It must NOT delete the vault-backed mirror
     * ([ReferralMetaKeys]) — this runs on ordinary backgrounding, and deleting the
     * records here would restore exactly the black hole the mirror exists to close.
     * A panic/inactivity wipe destroys them anyway: both platform wipes crypto-erase
     * the vault (Android deletes `run.db` after erasing the device key; iOS's
     * `wipeAllTables` clears `_meta` wholesale before the file goes), so the records
     * die with everything else and need no wipe-path enumeration of their own.
     */
    fun scrubInMemory() = lock.withLock {
        // [pendingFinalizedNotice] is deliberately NOT cleared: it is a one-bit
        // "your contact list changed" signal about a contact that is already
        // committed to the vault, not handshake material, and dropping it here
        // would lose the notification for a finalize that happened during a
        // rehydrate immediately before a lock.
        for (p in pending.values) p.keypair?.privateKey?.secureWipe()
        pending.clear()
        offers.clear()
        stashedAccepts.clear()
        introSessions.clear()
        relayRedrives.clear()
        completedIntros.clear()
        // Unlike [pendingFinalizedNotice] above, these DO go: each undelivered
        // [ReferralRelayEvent] holds two contact ALIASES and two contact ids, i.e.
        // exactly the identifying RAM residue this method exists to remove, and a
        // missed UI banner costs nothing (the relay/redrive state that matters is
        // durable in `_meta`).
        pendingRelayEvents.clear()
    }

    // -----------------------------------------------------------------------
    // Vault-backed persistence (ReferralStore.kt holds the keys + codecs).
    //
    // Every writer below is BEST-EFFORT and NON-THROWING: a `_meta` write failure
    // degrades this manager to RAM-only for the session (the referral still
    // completes in-session) rather than failing an accept the user just approved.
    // Every reader treats absent/corrupt as "no record" and GCs the key.
    // -----------------------------------------------------------------------

    private fun putRecord(key: String, value: String) {
        try { vault.putMeta(key, value) } catch (e: Exception) {
            platformLogWarn(TAG, "referral record persist failed: ${e::class.simpleName}")
        }
    }

    private fun dropRecord(key: String) {
        try { vault.deleteMeta(key) } catch (e: Exception) {
            platformLogWarn(TAG, "referral record delete failed: ${e::class.simpleName}")
        }
    }

    /** Mirrors one [Pending] (must hold [keypair] + [minted]). Caller holds `lock`. */
    private fun persistAccept(p: Pending) {
        if (!isValidIntroId(p.introId)) return
        val kp = p.keypair ?: return
        val minted = p.minted ?: return
        putRecord(
            ReferralMetaKeys.ACCEPT_PREFIX + p.introId,
            encodeStoredAccept(
                StoredAccept(
                    introducerContactId = p.introducerContactId,
                    peerAlias = p.peerAlias,
                    privateKey = kp.privateKey,
                    publicKey = kp.publicKey,
                    minted = minted,
                    sent = p.sent,
                    attempts = p.sendAttempts,
                    createdAt = p.createdAt,
                    firstSeenAt = p.firstSeenAt,
                )
            ),
        )
    }

    private fun persistOffer(o: ReferralOffer) {
        if (!isValidIntroId(o.introId)) return
        putRecord(
            ReferralMetaKeys.OFFER_PREFIX + o.introId,
            encodeStoredOffer(
                StoredOffer(
                    o.introducerContactId, o.introducerAlias, o.peerAlias,
                    o.receivedAt, o.firstSeenAt,
                )
            ),
        )
    }

    private fun persistSession(introId: String, s: IntroSession) {
        if (!isValidIntroId(introId)) return
        putRecord(
            ReferralMetaKeys.SESSION_PREFIX + introId,
            encodeStoredSession(
                StoredSession(
                    s.contactA, s.contactB, s.relayed.toSet(), s.createdAt,
                    s.offered.toSet(), s.offerAttempts, s.firstSeenAt,
                )
            ),
        )
    }

    private fun persistStash(introId: String, s: StashedAccept) {
        if (!isValidIntroId(introId)) return
        putRecord(
            ReferralMetaKeys.STASH_PREFIX + introId,
            encodeStoredStash(StoredStash(s.fromContactId, s.body, s.stampMs)),
        )
    }

    private fun persistRedrive(r: RelayRedrive) {
        if (!isValidIntroId(r.introId)) return
        putRecord(
            ReferralMetaKeys.REDRIVE_PREFIX + redriveKey(r.introId, r.toContactId),
            encodeStoredRedrive(
                StoredRedrive(
                    r.introId, r.toContactId, r.fromContactId, r.body,
                    r.attempts, r.createdAt, r.firstSeenAt,
                )
            ),
        )
    }

    // -----------------------------------------------------------------------
    // Refresh-on-activity.
    //
    // The idle TTL ([REFERRAL_RECORD_TTL_MS]) measures time SINCE THE LAST GENUINE EVENT
    // for an introduction, not time since it started: the two introducees accept
    // independently and either may be a slow human, so a handshake that is still
    // visibly moving must not be GC'd out from under itself and turned into a
    // half-pair. The three activity signals are (a) a redrive attempt for the
    // record, (b) a peer accept landing against a consent we have not answered
    // yet, and (c) an introducer relaying an accept for its session.
    //
    // Deliberately NOT refreshed by [rehydrate]: relaunching the app is not
    // activity for any particular introduction, and refreshing there would make
    // the TTL meaningless for anyone who opens the app daily.
    //
    // Every refresh is bounded by `firstSeenAt` + [REFERRAL_RECORD_MAX_LIFETIME_MS],
    // which nothing re-stamps — see REFERRAL_RECORD_MAX_LIFETIME_MS.
    // Callers hold `lock`.
    // -----------------------------------------------------------------------

    /** True while [firstSeenAt] still leaves room under the absolute ceiling. */
    private fun withinAbsoluteLifetime(firstSeenAt: Long, now: Long) =
        now - firstSeenAt <= REFERRAL_RECORD_MAX_LIFETIME_MS

    /** Re-stamps our own accept record for [introId], persisting the update. */
    private fun refreshAcceptLocked(introId: String, now: Long) {
        val p = pending[introId] ?: return
        if (!withinAbsoluteLifetime(p.firstSeenAt, now)) return
        p.createdAt = now
        persistAccept(p)
    }

    /** Re-stamps an un-consented offer, persisting the update. */
    private fun refreshOfferLocked(introId: String, now: Long) {
        val o = offers[introId] ?: return
        if (!withinAbsoluteLifetime(o.firstSeenAt, now)) return
        val refreshed = o.copy(receivedAt = now)
        offers[introId] = refreshed
        persistOffer(refreshed)
    }

    /** Re-stamps [ses] in RAM only; the caller persists (often together with
     *  another field change, so this stays a single `_meta` write). */
    private fun touchSessionLocked(ses: IntroSession) {
        val now = clockMs()
        if (withinAbsoluteLifetime(ses.firstSeenAt, now)) ses.createdAt = now
    }

    /**
     * Drops every introducee-side record for [introId] (accept material, stash,
     * offer). Used by the TERMINAL finalize branches — already-exists and
     * inbox-in-use — where nothing was written and the transaction cannot carry
     * the deletes. Non-throwing. Caller holds `lock`.
     */
    private fun dropHandshakeRecordsLocked(introId: String) {
        dropRecord(ReferralMetaKeys.ACCEPT_PREFIX + introId)
        dropRecord(ReferralMetaKeys.STASH_PREFIX + introId)
        dropRecord(ReferralMetaKeys.OFFER_PREFIX + introId)
    }

    /**
     * Caller holds `lock` (markIntroCompleted / declineOffer / finalize), OR is
     * [rehydrate] running from `init` before any concurrent caller could exist.
     * Writes ONLY the v2 (hashed) key — [ReferralMetaKeys.COMPLETED_KEY] (v1) is
     * legacy and read-only; see [ReferralMetaKeys.COMPLETED_KEY_V2].
     */
    private fun persistCompleted() {
        if (completedV2Unreadable) {
            val stored = try { vault.getMeta(ReferralMetaKeys.COMPLETED_KEY_V2) } catch (e: Exception) {
                platformLogWarn(TAG, "referral tombstones still unreadable — not overwriting: ${e::class.simpleName}")
                return
            }
            val merged = LinkedHashSet<String>()
            stored?.let { merged.addAll(decodeCompletedIntros(it, MAX_COMPLETED_INTROS)) }
            merged.addAll(completedIntros)
            completedIntros.clear()
            completedIntros.addAll(merged)
            while (completedIntros.size > MAX_COMPLETED_INTROS) {
                completedIntros.remove(completedIntros.iterator().next())
            }
            completedV2Unreadable = false
        }
        putRecord(
            ReferralMetaKeys.COMPLETED_KEY_V2,
            encodeCompletedIntros(completedIntros, MAX_COMPLETED_INTROS),
        )
    }

    /**
     * Rebuilds the in-RAM handshake maps from the vault. Runs once, from `init`.
     *
     * Rules, all brick-safe by construction:
     *  - anything that fails to decode, or whose introId is not key-safe, is
     *    DELETED (it can never be acted on, and leaving it would be residue);
     *  - anything past [REFERRAL_RECORD_TTL_MS] since its last activity, OR past
     *    [REFERRAL_RECORD_MAX_LIFETIME_MS] since it was first seen, is deleted;
     *  - every per-session attempt counter is RESET to 0 while the record
     *    itself is KEPT: a budget spent against a relay that was down for one
     *    session must not permanently disarm the obligation. The overall bound
     *    is the TTL above, not the counter;
     *  - over-cap namespaces drop their OLDEST records (same direction as
     *    [capInsert]'s eviction);
     *  - an offer whose introduction is already accepted-and-sent, or already
     *    completed, is dropped — the accept record supersedes it. An offer whose
     *    accept is still UNSENT is kept, which is exactly the live post-failed-send
     *    state (the offer stays so the UI can re-present a Retry).
     */
    private fun rehydrate() {
        val now = currentTimeMillis()
        val keys = try { vault.metaKeys() } catch (e: Exception) {
            platformLogWarn(TAG, "referral rehydrate: meta scan failed: ${e::class.simpleName}"); return
        }
        // Phase order is load-bearing: tombstones are migrated and loaded before
        // install (which drops completed intros), and the stash apply runs last,
        // once `pending` is fully built.
        val scanned = scanReferralRecords(keys, now)
        migrateCompletedTombstones(scanned.completedRawV1, scanned.completedRawV2, scanned.completedV2ReadFailed)
        trimRehydrated(scanned)
        installRehydrated(scanned)
        applyReadyStashes()
    }

    /** The decoded, still-live `ref_*` records of one [rehydrate] scan. */
    private class ScannedReferralRecords {
        val accepts = mutableListOf<Pair<String, StoredAccept>>()
        val storedOffers = mutableListOf<Pair<String, StoredOffer>>()
        val sessions = mutableListOf<Pair<String, StoredSession>>()
        val stashes = mutableListOf<Pair<String, StoredStash>>()
        val redrives = mutableListOf<Pair<String, StoredRedrive>>()
        var completedRawV1: String? = null
        var completedRawV2: String? = null
        // The v2 tombstone row exists but its READ threw (ambiguous, not absent).
        var completedV2ReadFailed = false
    }

    /** Rehydrate phase 1: decode every `ref_*` record; an undecodable or expired one
     *  is dropped from the vault here (an unknown `ref_*` key is left alone). A
     *  record whose READ throws is KEPT: that is ambiguous, not absent, and the next
     *  construction reads it again (the [GroupInviteStore] rule). */
    private fun scanReferralRecords(keys: Collection<String>, now: Long): ScannedReferralRecords {
        val out = ScannedReferralRecords()
        for (key in keys) {
            if (!isReferralMetaKey(key)) continue
            if (key == ReferralMetaKeys.COMPLETED_KEY) {
                out.completedRawV1 = try { vault.getMeta(key) } catch (_: Exception) { null }
                continue
            }
            if (key == ReferralMetaKeys.COMPLETED_KEY_V2) {
                try {
                    out.completedRawV2 = vault.getMeta(key)
                } catch (e: Exception) {
                    platformLogWarn(TAG, "referral tombstone read failed: ${e::class.simpleName}")
                    out.completedV2ReadFailed = true
                }
                continue
            }
            val raw = try { vault.getMeta(key) } catch (e: Exception) {
                // Ambiguous: the row is listed but could not be read. Deleting it
                // would destroy (for `ref_a:`) the ephemeral key and the minted read
                // caps of a live introduction. Keep it for the next construction.
                platformLogWarn(TAG, "referral record read failed — kept: ${e::class.simpleName}")
                continue
            }
            if (raw == null) { dropRecord(key); continue }
            val prefix = when {
                key.startsWith(ReferralMetaKeys.ACCEPT_PREFIX) -> ReferralMetaKeys.ACCEPT_PREFIX
                key.startsWith(ReferralMetaKeys.OFFER_PREFIX) -> ReferralMetaKeys.OFFER_PREFIX
                key.startsWith(ReferralMetaKeys.SESSION_PREFIX) -> ReferralMetaKeys.SESSION_PREFIX
                key.startsWith(ReferralMetaKeys.STASH_PREFIX) -> ReferralMetaKeys.STASH_PREFIX
                key.startsWith(ReferralMetaKeys.REDRIVE_PREFIX) -> ReferralMetaKeys.REDRIVE_PREFIX
                // An unknown `ref_*` key is not ours to interpret and not ours to
                // delete either (a future record type on a downgrade). Leave it.
                else -> { continue }
            }
            val suffix = key.substring(prefix.length)
            var kept = false
            when (prefix) {
                ReferralMetaKeys.ACCEPT_PREFIX -> decodeStoredAccept(raw)?.let {
                    if (isValidIntroId(suffix) && isRecordLive(now, it.createdAt, it.firstSeenAt)) {
                        out.accepts.add(suffix to it); kept = true
                    }
                }
                ReferralMetaKeys.OFFER_PREFIX -> decodeStoredOffer(raw)?.let {
                    if (isValidIntroId(suffix) && isRecordLive(now, it.createdAt, it.firstSeenAt)) {
                        out.storedOffers.add(suffix to it); kept = true
                    }
                }
                ReferralMetaKeys.SESSION_PREFIX -> decodeStoredSession(raw)?.let {
                    if (isValidIntroId(suffix) && isRecordLive(now, it.createdAt, it.firstSeenAt)) {
                        out.sessions.add(suffix to it); kept = true
                    }
                }
                ReferralMetaKeys.STASH_PREFIX -> decodeStoredStash(raw)?.let {
                    // A stash is never refreshed, so its createdAt IS its first-seen.
                    if (isValidIntroId(suffix) && isRecordLive(now, it.createdAt, it.createdAt)) {
                        out.stashes.add(suffix to it); kept = true
                    }
                }
                ReferralMetaKeys.REDRIVE_PREFIX -> decodeStoredRedrive(raw)?.let {
                    if (suffix == redriveKey(it.introId, it.toContactId) &&
                        isRecordLive(now, it.createdAt, it.firstSeenAt)
                    ) { out.redrives.add(suffix to it); kept = true }
                }
            }
            if (!kept) {
                platformLog(TAG, "referral record dropped on load (expired/unreadable)")
                dropRecord(key)
            }
        }

        return out
    }

    /** Rehydrate phase 2: load the completed-intro tombstones, migrating v1 → v2. */
    private fun migrateCompletedTombstones(v1Raw: String?, v2Raw: String?, v2ReadFailed: Boolean) {
        // Migration: v1 (`ref_done`) held RAW introIds — a salt-free preimage
        // of the referred contact's id (referredContactIdFor), so it survived a
        // contact delete as a computable cross-device correlator. Hash every v1
        // entry into the v2 (`ref_done2`) domain and drop v1 for good; a vault
        // that never had a v1 record (fresh install, or already migrated) skips
        // this entirely. Order: v1 first (oldest data), then v2, so a v2 that
        // already existed alongside a stray v1 (should never happen in normal
        // operation, but decoding must not assume it can't) keeps its own entries.
        var completedMigratedFromV1 = false
        v1Raw?.let {
            for (id in decodeCompletedIntros(it, MAX_COMPLETED_INTROS)) {
                completedIntros.add(doneTokenFor(id))
            }
            completedMigratedFromV1 = true
        }
        v2Raw?.let { completedIntros.addAll(decodeCompletedIntros(it, MAX_COMPLETED_INTROS)) }
        while (completedIntros.size > MAX_COMPLETED_INTROS) {
            completedIntros.remove(completedIntros.iterator().next())
        }
        if (v2ReadFailed) {
            // The v2 set could not be read: writing [completedIntros] now would
            // overwrite it with a set that lacks its entries, so the v1 migration
            // waits for a launch that can read v2 (v1 stays on disk until then).
            completedV2Unreadable = true
            return
        }
        if (completedMigratedFromV1) {
            persistCompleted()
            dropRecord(ReferralMetaKeys.COMPLETED_KEY)
        }
    }

    /** Rehydrate phase 3: sort oldest-first and drop each namespace's over-cap records. */
    private fun trimRehydrated(scanned: ScannedReferralRecords) {
        // Oldest-first so the trim below drops the oldest, mirroring capInsert.
        scanned.accepts.sortBy { it.second.createdAt }
        scanned.storedOffers.sortBy { it.second.createdAt }
        scanned.sessions.sortBy { it.second.createdAt }
        scanned.stashes.sortBy { it.second.createdAt }
        scanned.redrives.sortBy { it.second.createdAt }
        trimOverCap(scanned.accepts, MAX_PENDING, ReferralMetaKeys.ACCEPT_PREFIX)
        trimOverCap(scanned.storedOffers, MAX_OFFERS, ReferralMetaKeys.OFFER_PREFIX)
        trimOverCap(scanned.sessions, MAX_INTRO_SESSIONS, ReferralMetaKeys.SESSION_PREFIX)
        trimOverCap(scanned.stashes, MAX_STASHED_ACCEPTS, ReferralMetaKeys.STASH_PREFIX)
        trimOverCap(scanned.redrives, MAX_RELAY_REDRIVES, ReferralMetaKeys.REDRIVE_PREFIX)
    }

    /** Rehydrate phase 4: install the records into the RAM maps (per-session budgets
     *  reset to 0; a completed intro's record is dropped instead). */
    private fun installRehydrated(scanned: ScannedReferralRecords) {
        for ((introId, rec) in scanned.accepts) {
            if (doneTokenFor(introId) in completedIntros) { dropRecord(ReferralMetaKeys.ACCEPT_PREFIX + introId); continue }
            pending[introId] = Pending(
                introId = introId,
                introducerContactId = rec.introducerContactId,
                peerAlias = rec.peerAlias,
                keypair = X25519Keypair(rec.privateKey, rec.publicKey),
                minted = rec.minted,
                sent = rec.sent,
                // The budget is PER SESSION — see MAX_ACCEPT_SEND_ATTEMPTS.
                // The record is KEPT; only the counter starts over.
                sendAttempts = 0,
                createdAt = rec.createdAt,
                firstSeenAt = rec.firstSeenAt,
            )
        }
        for ((introId, rec) in scanned.storedOffers) {
            // The accept record supersedes the offer once the accept has provably
            // left; a still-unsent accept keeps the offer (the Retry affordance).
            if (doneTokenFor(introId) in completedIntros || pending[introId]?.sent == true) {
                dropRecord(ReferralMetaKeys.OFFER_PREFIX + introId); continue
            }
            offers[introId] = ReferralOffer(
                introId, rec.introducerContactId, rec.introducerAlias, rec.peerAlias,
                rec.createdAt, rec.firstSeenAt,
            )
        }
        for ((introId, rec) in scanned.sessions) {
            introSessions[introId] = IntroSession(
                rec.contactA, rec.contactB, rec.relayed.toMutableSet(), rec.createdAt,
                rec.offered.toMutableSet(),
                // Per-session offer budget, same rule as the two above.
                0,
                rec.firstSeenAt,
            )
        }
        for ((introId, rec) in scanned.stashes) {
            if (doneTokenFor(introId) in completedIntros) { dropRecord(ReferralMetaKeys.STASH_PREFIX + introId); continue }
            stashedAccepts[introId] = StashedAccept(rec.body, rec.createdAt, rec.fromContactId)
        }
        for ((key, rec) in scanned.redrives) {
            relayRedrives[key] = RelayRedrive(
                rec.introId, rec.toContactId, rec.fromContactId, rec.body,
                // Per-session budget, same rule as the accept redrive.
                0,
                rec.createdAt, rec.firstSeenAt,
            )
        }
        if (pending.isNotEmpty() || offers.isNotEmpty() || introSessions.isNotEmpty() ||
            stashedAccepts.isNotEmpty() || relayRedrives.isNotEmpty()
        ) {
            platformLog(
                TAG,
                "referral state rehydrated: ${pending.size} accepted, ${offers.size} offered, " +
                    "${introSessions.size} introducing, ${stashedAccepts.size} stashed, " +
                    "${relayRedrives.size} to relay",
            )
        }
    }

    /** Rehydrate phase 5: apply any stash whose own accept has already been sent. */
    private fun applyReadyStashes() {
        // A stash whose accept is already sent can be applied right away — the peer
        // accepted while we were dead. Done outside the map fill so `pending` is
        // fully built first (finalize re-enters this manager's state).
        //
        // The stash is NOT consumed before the finalize. Dropping it here would
        // mean a finalize that then failed for ANY reason — the retryable
        // vault-write branch, a transient decode/derive failure, process death
        // mid-transaction — destroyed the peer's accept and left this side
        // permanently unable to complete an introduction the peer had already
        // committed: the half-pair. finalizeFromPeerAccept deletes `ref_a` INSIDE
        // the same transaction that commits the contact (and drops the RAM entry
        // on its terminal branches), so consuming it here would buy nothing.
        for ((introId, p) in pending.toList()) {
            if (!p.sent || p.finalized) continue
            val stashed = stashedAccepts[introId] ?: continue
            if (stashed.fromContactId != p.introducerContactId) continue
            finalizeFromPeerAccept(p, stashed.body)
        }
    }

    /** Idle TTL AND absolute-ceiling gate, applied identically by [rehydrate]
     *  and [gcExpired] so the two can never disagree about what is still live. */
    private fun isRecordLive(now: Long, createdAt: Long, firstSeenAt: Long): Boolean =
        now - createdAt <= REFERRAL_RECORD_TTL_MS && now - firstSeenAt <= REFERRAL_RECORD_MAX_LIFETIME_MS

    /** Deletes the oldest over-cap records from [items] (already oldest-first). */
    private fun <T> trimOverCap(items: MutableList<Pair<String, T>>, max: Int, prefix: String) {
        while (items.size > max) {
            val (suffix, _) = items.removeAt(0)
            dropRecord(prefix + suffix)
        }
    }

    // -----------------------------------------------------------------------
    // Maintenance — TTL GC + the three bounded redrive obligations (offers,
    // unsent accepts, unrelayed accepts).
    //
    // Driven from the CONTROL SWEEP (GroupManager.pollAllControls →
    // SessionManagers wiring), which is the loop that already owns the referral
    // handshake's delivery cadence and its per-contact jitter. One attempt per
    // record per sweep: no tight loop, no timer of its own, and nothing runs
    // without a live transport.
    // -----------------------------------------------------------------------

    /**
     * One maintenance pass. Safe to call from any background poll; never throws.
     *
     * Network I/O is deliberately done OUTSIDE `lock`: the work items are
     * snapshotted under it, sent unlocked (a control send is a blocking Tor
     * round-trip, and [finalizeFromPeerAccept] re-acquires the lock), and the
     * outcome committed under it again.
     */
    fun runMaintenance() {
        try { gcExpired() } catch (e: Exception) {
            platformLogWarn(TAG, "referral GC failed: ${e::class.simpleName}")
        }
        try { pruneStaleOfferRateWindows() } catch (e: Exception) {
            platformLogWarn(TAG, "referral rate-window prune failed: ${e::class.simpleName}")
        }
        val mgr = messageManager() ?: return
        try { redriveUndeliveredOffers(mgr) } catch (e: Exception) {
            platformLogWarn(TAG, "referral offer redrive failed: ${e::class.simpleName}")
        }
        try { redriveUnsentAccepts(mgr) } catch (e: Exception) {
            platformLogWarn(TAG, "referral accept redrive failed: ${e::class.simpleName}")
        }
        try { redriveUnrelayedAccepts(mgr) } catch (e: Exception) {
            platformLogWarn(TAG, "referral relay redrive failed: ${e::class.simpleName}")
        }
    }

    /**
     * Every referral control send carries the 7-day relay retention
     * ([REFERRAL_CONTROL_TTL_SECONDS]). The relay's default is 24 h, so
     * without this an offer or a relayed accept could expire off the inbox a day
     * after it was posted while both ends of the handshake stayed live for a
     * week — the relay-side twin of the record TTL this fix also raised.
     *
     * Push is deliberately NOT suppressed: an offer raises a consent prompt and
     * an accept completes an introduction the user is waiting on, so these are
     * exactly the control kinds worth waking a device for now that inbound
     * control inboxes are push-registered ([allPushableInboxes]).
     *
     * The `?ttl` is a URL query parameter only — the sealed envelope, its
     * AEAD-bound fields and the counter/epoch anti-replay rules are untouched.
     */
    private fun sendReferralControl(
        mgr: MessageManager, toContactId: String, kind: String, body: String,
    ): Boolean = mgr.sendDirectControl(
        toContactId, kind, body, ttlSeconds = REFERRAL_CONTROL_TTL_SECONDS,
    )

    /**
     * INTRODUCER: re-sends an OFFER whose delivery was never confirmed.
     *
     * Without it one dropped circuit would silently swallow half the
     * introduction: the introducer sees success, one introducee never gets a
     * consent prompt, and nothing retries. The session record is written BEFORE the offers go out, so the
     * obligation is durable across a restart exactly like the accept redrives.
     *
     * The alias is re-read from the vault each attempt rather than snapshotted —
     * it may have rotated, and the offer body is the peer's DISPLAY alias only.
     * A party that no longer exists is skipped without consuming an attempt (the
     * `ref_s` record is purged wholesale by `deleteContact`'s classifier anyway).
     */
    private fun redriveUndeliveredOffers(mgr: MessageManager) {
        val work = lock.withLock {
            introSessions.entries
                .filter { !it.value.bothOffersDelivered() && it.value.offerAttempts < MAX_OFFER_SEND_ATTEMPTS }
                .map { (introId, s) -> Triple(introId, s.contactA, s.contactB) }
        }
        for ((introId, contactA, contactB) in work) {
            var attempted = false
            for ((target, other) in listOf(contactA to contactB, contactB to contactA)) {
                val alreadyDone = lock.withLock { introSessions[introId]?.offered?.contains(target) != false }
                if (alreadyDone) continue
                val alias = vault.getContact(other)?.alias
                if (alias == null || vault.getContact(target) == null) {
                    platformLogWarn(TAG, "referral offer redrive: a party is gone — skipped")
                    continue
                }
                attempted = true
                val sent = try {
                    sendReferralControl(
                        mgr, target, MessageManager.CONTROL_KIND_REFERRAL_OFFER,
                        offerBody(introId, alias),
                    )
                } catch (e: Exception) {
                    platformLogWarn(TAG, "referral offer re-send threw: ${e::class.simpleName}"); false
                }
                lock.withLock {
                    val live = introSessions[introId] ?: return@withLock
                    if (sent) {
                        platformLog(TAG, "referral offer delivered on a redrive")
                        live.offered.add(target)
                    }
                    // A redrive attempt is activity for this introduction either
                    // way — one write covers the stamp and the delivered set.
                    touchSessionLocked(live)
                    persistSession(introId, live)
                }
            }
            if (!attempted) continue
            lock.withLock {
                val live = introSessions[introId] ?: return@withLock
                live.offerAttempts += 1
                if (live.offerAttempts >= MAX_OFFER_SEND_ATTEMPTS) {
                    platformLogWarn(TAG, "referral offer redrive exhausted for this session — waiting on TTL")
                }
                persistSession(introId, live)
            }
        }
    }

    /** Ages every handshake map + its vault mirror out on the same two bounds
     *  [rehydrate] applies — the idle [REFERRAL_RECORD_TTL_MS] and the absolute
     *  [REFERRAL_RECORD_MAX_LIFETIME_MS] (via [isRecordLive]). */
    private fun gcExpired() {
        val now = clockMs()
        lock.withLock {
            for (introId in pending.filterValues { !isRecordLive(now, it.createdAt, it.firstSeenAt) }.keys.toList()) {
                pending.remove(introId)?.keypair?.privateKey?.secureWipe()
                dropRecord(ReferralMetaKeys.ACCEPT_PREFIX + introId)
            }
            for (introId in offers.filterValues { !isRecordLive(now, it.receivedAt, it.firstSeenAt) }.keys.toList()) {
                offers.remove(introId)
                dropRecord(ReferralMetaKeys.OFFER_PREFIX + introId)
            }
            // A stash is never refreshed, so its stamp IS its first-seen.
            for (introId in stashedAccepts.filterValues { !isRecordLive(now, it.stampMs, it.stampMs) }.keys.toList()) {
                stashedAccepts.remove(introId)
                dropRecord(ReferralMetaKeys.STASH_PREFIX + introId)
            }
            for (introId in introSessions.filterValues { !isRecordLive(now, it.createdAt, it.firstSeenAt) }.keys.toList()) {
                introSessions.remove(introId)
                dropRecord(ReferralMetaKeys.SESSION_PREFIX + introId)
            }
            for (key in relayRedrives.filterValues { !isRecordLive(now, it.createdAt, it.firstSeenAt) }.keys.toList()) {
                relayRedrives.remove(key)
                dropRecord(ReferralMetaKeys.REDRIVE_PREFIX + key)
            }
            // A stash must never outlive BOTH the offer and the pending it could
            // finalize against. A re-delivered peer-accept never re-stamps a live
            // stash, but one arriving after the stash aged out writes a NEW stash
            // stamped at that arrival (handleAccept), which can survive its offer's own
            // absolute ceiling and be left as orphaned residue once that offer (or
            // the staged pending) is reclaimed by the loops above. Prune any stash
            // that now has neither an offer nor a pending — the same co-removal
            // declineOffer and the MAX_OFFERS eviction perform, applied to the
            // TTL/ceiling teardown. A stash is only ever written while an offer or
            // pending exists, and a finalize deletes its own stash, so a stash with
            // neither is always an orphan — never a finalize still in flight.
            for (introId in stashedAccepts.keys.toList()) {
                if (introId !in offers && introId !in pending) {
                    stashedAccepts.remove(introId)
                    dropRecord(ReferralMetaKeys.STASH_PREFIX + introId)
                }
            }
        }
    }

    /**
     * Re-sends an accept whose delivery was never confirmed — the send returned
     * false, or the process died between the `st=0` persist and the confirmation.
     *
     * It re-sends THE SAME public key and THE SAME minted inbox pair. That is the
     * whole reason the material is persisted before the send: `false` from
     * `sendDirectControl` does not prove the blob never reached the relay, so a
     * fresh keypair here would derive a secret the peer can never match — the
     * mirror image of the black hole this work exists to close.
     */
    private fun redriveUnsentAccepts(mgr: MessageManager) {
        val work = lock.withLock {
            pending.values
                .filter { !it.sent && !it.finalized && it.sendAttempts < MAX_ACCEPT_SEND_ATTEMPTS }
                .mapNotNull { p ->
                    val kp = p.keypair ?: return@mapNotNull null
                    val minted = p.minted ?: return@mapNotNull null
                    Triple(p.introId, p.introducerContactId, acceptBody(p.introId, kp.publicKey, minted))
                }
        }
        for ((introId, introducer, body) in work) {
            val sent = try {
                sendReferralControl(mgr, introducer, MessageManager.CONTROL_KIND_REFERRAL_ACCEPT, body)
            } catch (e: Exception) {
                platformLogWarn(TAG, "referral accept re-send threw: ${e::class.simpleName}"); false
            }
            if (sent) {
                platformLog(TAG, "referral accept re-sent after an unconfirmed delivery")
                confirmAcceptSent(introId)
            } else {
                noteAcceptSendFailed(introId)
            }
        }
    }

    /**
     * INTRODUCER: retries an accept we could not forward. Without this the
     * ignored `sendDirectControl` return at the relay site silently swallowed the
     * whole introduction — the sender believed its accept was delivered, the other
     * introducee never received any material, and nothing ever retried.
     */
    private fun redriveUnrelayedAccepts(mgr: MessageManager) {
        val work = lock.withLock {
            relayRedrives.values
                .filter { it.attempts < MAX_RELAY_REDRIVE_ATTEMPTS }
                .map { Triple(it.introId, it.toContactId, it.fromContactId) to it.body }
        }
        for ((ids, body) in work) {
            val (introId, toContactId, fromContactId) = ids
            val sent = try {
                sendReferralControl(mgr, toContactId, MessageManager.CONTROL_KIND_REFERRAL_ACCEPT, body)
            } catch (e: Exception) {
                platformLogWarn(TAG, "referral relay re-send threw: ${e::class.simpleName}"); false
            }
            val key = redriveKey(introId, toContactId)
            if (sent) {
                platformLog(TAG, "referral accept relayed on a redrive")
                val complete = lock.withLock {
                    relayRedrives.remove(key)
                    dropRecord(ReferralMetaKeys.REDRIVE_PREFIX + key)
                    noteRelayDeliveredLocked(introId, fromContactId)
                }
                // The UI already saw this accept as "queued" when [handleAccept]
                // failed to forward it, so a redrive that merely lands is NOT news.
                // The one outcome worth a second event is the introduction becoming
                // COMPLETE — fired outside the lock, like every other hook here.
                if (complete) {
                    fireIntroRelayed(introId, fromContactId, toContactId, relayed = true, complete = true)
                }
            } else {
                lock.withLock {
                    val live = relayRedrives[key] ?: return@withLock
                    live.attempts += 1
                    // A redrive ATTEMPT is activity for this obligation: the
                    // idle TTL measures time since the last event, not since the
                    // failure that created the record. Bounded by firstSeenAt.
                    val now = clockMs()
                    if (withinAbsoluteLifetime(live.firstSeenAt, now)) live.createdAt = now
                    if (live.attempts >= MAX_RELAY_REDRIVE_ATTEMPTS) {
                        platformLogWarn(TAG, "referral relay redrive exhausted for this session — waiting on TTL")
                    }
                    persistRedrive(live)
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Introducer
    // -----------------------------------------------------------------------

    /**
     * Introduce two already-paired contacts.
     *
     * Returns the introId once the introduction is **durably QUEUED**, or null if
     * either contact is unknown / they are the same / there is no transport at
     * all. The returned id is no longer a claim that both offers were DELIVERED:
     * the session record — including which side's offer has provably
     * landed — is persisted BEFORE either send, both `sendDirectControl` results
     * are captured (a throw counts as "not delivered"), and any undelivered side
     * becomes a bounded obligation [runMaintenance] redrives on later control
     * sweeps and across restarts. Previously both results were discarded, so one
     * dropped circuit produced a permanent one-sided introduction that reported
     * success and never retried.
     *
     * A UI that wants to say more than "queued" must not infer delivery from this
     * return value.
     */
    fun startReferral(contactAId: String, contactBId: String): String? {
        if (contactAId == contactBId) return null
        val mgr = messageManager() ?: return null
        val a = vault.getContact(contactAId) ?: return null
        val b = vault.getContact(contactBId) ?: return null
        val introId = newIntroId()
        // Persisted BEFORE the offers go out. The session is the ONLY thing that
        // lets us relay each accept to the other party, so an introducer that is
        // backgrounded (or killed) between firing the referral and the first
        // accept coming back would otherwise strand both introducees permanently —
        // the accept would hit "accept from a non-party dropped"/unknown-introId.
        // It is also what makes an undelivered OFFER recoverable.
        lock.withLock {
            val session = IntroSession(contactAId, contactBId)
            evictOverCapSessionLocked(introId)
            introSessions.capInsert(introId, session, MAX_INTRO_SESSIONS)
            persistSession(introId, session)
        }
        // Each side is told the OTHER's alias. Both sends are best-effort and
        // NON-THROWING here: a failure is recorded as an obligation, not
        // surfaced, because the record is already durable.
        val sentA = trySendOffer(mgr, contactAId, introId, b.alias)
        val sentB = trySendOffer(mgr, contactBId, introId, a.alias)
        lock.withLock {
            val session = introSessions[introId] ?: return@withLock
            if (sentA) session.offered.add(contactAId)
            if (sentB) session.offered.add(contactBId)
            persistSession(introId, session)
        }
        if (!sentA || !sentB) {
            platformLogWarn(TAG, "referral offer not delivered to one/both sides — queued for redrive")
        }
        return introId
    }

    /** One offer send, folded to a Boolean. See [startReferral]. */
    private fun trySendOffer(mgr: MessageManager, toContactId: String, introId: String, peerAlias: String): Boolean =
        try {
            sendReferralControl(
                mgr, toContactId, MessageManager.CONTROL_KIND_REFERRAL_OFFER, offerBody(introId, peerAlias),
            )
        } catch (e: Exception) {
            platformLogWarn(TAG, "referral offer send threw: ${e::class.simpleName}"); false
        }

    /** Mirrors [capInsert]'s eviction target so the VAULT record of the entry
     *  capInsert is about to drop goes with it (else it is orphaned residue that
     *  only the TTL can reclaim). Caller holds `lock`. */
    private fun evictOverCapSessionLocked(incoming: String) {
        if (introSessions.size < MAX_INTRO_SESSIONS || incoming in introSessions) return
        introSessions.keys.firstOrNull()?.let { dropRecord(ReferralMetaKeys.SESSION_PREFIX + it) }
    }

    /** INTRODUCER: records that [fromContactId]'s accept has been forwarded, and
     *  drops the session once BOTH accepts have crossed. Returns true exactly when
     *  THIS call completed the introduction — the same condition under which the
     *  session is dropped — which is what [ReferralRelayEvent.complete] reports.
     *  A session that is already gone returns false (nothing was completed here).
     *  Caller holds `lock`. */
    private fun noteRelayDeliveredLocked(introId: String, fromContactId: String): Boolean {
        val session = introSessions[introId] ?: return false
        session.relayed.add(fromContactId)
        if (session.relayed.containsAll(listOf(session.contactA, session.contactB))) {
            introSessions.remove(introId)
            dropRecord(ReferralMetaKeys.SESSION_PREFIX + introId)
            return true
        } else {
            // Relaying one side's accept is the clearest possible evidence this
            // introduction is live — re-stamp so the OTHER side's leg is not aged
            // out from under it while it is still in flight.
            touchSessionLocked(session)
            persistSession(introId, session)
        }
        return false
    }

    // -----------------------------------------------------------------------
    // Introducee — consent + accept
    // -----------------------------------------------------------------------

    /** Referral offers awaiting the user's approval. */
    fun pendingOffers(): List<ReferralOffer> = lock.withLock { offers.values.toList() }

    fun declineOffer(introId: String) {
        // Drop the offer AND any early peer-accept stashed against it, so a
        // declined referral leaves no residue to be applied later. Record it as
        // completed so a re-delivery doesn't resurrect the just-declined offer.
        // The vault mirror follows the RAM state exactly — a decline that only
        // cleared RAM would come back at the next unlock.
        lock.withLock {
            offers.remove(introId)
            stashedAccepts.remove(introId)
            dropRecord(ReferralMetaKeys.OFFER_PREFIX + introId)
            dropRecord(ReferralMetaKeys.STASH_PREFIX + introId)
            // A declined referral may still have STAGED material: the user tapped
            // Approve, the send failed, the offer was re-presented, and this time
            // they declined. That staged record owns a live redrive obligation, so
            // it must go — otherwise a later control sweep would send an accept for
            // a referral the user just refused.
            pending.remove(introId)?.let {
                it.keypair?.privateKey?.secureWipe()
                dropRecord(ReferralMetaKeys.ACCEPT_PREFIX + introId)
            }
            markIntroCompleted(introId)
        }
    }

    /**
     * Approve a referral: mint an inbox pair, generate an ephemeral X25519
     * keypair, and send our accept (public key + inbox offer) to the introducer
     * to relay. Blocking on the PoW mint — call from a background dispatcher.
     */
    suspend fun acceptOffer(introId: String): Boolean {
        val offer = lock.withLock { offers[introId] } ?: return false
        val mgr = messageManager() ?: return false

        // RETRY REUSE. If an earlier attempt on this introId already staged
        // material (a send that returned false, or one interrupted by process
        // death and rehydrated from the vault), re-send THAT material rather than
        // minting fresh. `sendDirectControl == false` is not proof that the blob
        // never reached the relay, so a new keypair would derive a secret the peer
        // — who may already hold the first public key — can never match. Reuse
        // also skips a second PoW mint on an already-degraded circuit.
        val staged = lock.withLock {
            pending[introId]?.takeIf { !it.finalized && it.keypair != null && it.minted != null }
        }
        if (staged != null) {
            val kp = staged.keypair!!
            val minted = staged.minted!!
            val sent = sendReferralControl(
                mgr,
                offer.introducerContactId,
                MessageManager.CONTROL_KIND_REFERRAL_ACCEPT,
                acceptBody(introId, kp.publicKey, minted),
            )
            if (!sent) { noteAcceptSendFailed(introId); return false }
            confirmAcceptSent(introId)
            return true
        }

        // Bound the mint by a wall-clock deadline so a flaky Tor circuit fails
        // fast (returns false) instead of grinding through every internal retry
        // and stranding the user on "Connecting…". On failure the offer is left
        // pending so the UI can re-present it as a Retry.
        val deadline = clockMs() + ACCEPT_MINT_DEADLINE_MS
        // The abort predicate must read the SAME clock the deadline was computed
        // from, or the two disagree (see [clockMs]).
        val minted = mgr.mintInboxPair(PowAbort { clockMs() >= deadline }) ?: return false
        val keypair = x25519GenerateKeypair()
        // The fresh ephemeral X25519 private key must not
        // outlive a FAILED accept. stageAccept() takes ownership by inserting the
        // keypair into `pending`, where scrubInMemory()/finalize later wipe it. Until that
        // hand-off, EVERY early exit — a send that returns false OR throws — must overwrite
        // the 32 private-key bytes (fill(0)), else they become unreachable heap residue
        // scrubInMemory() can never find (the key was never inserted into `pending`).
        var handedOff = false
        try {
            // PERSIST BEFORE THE SEND (st=0). An accept blob that leaves the device
            // while the record does not reach the vault is unrecoverable: the peer
            // commits a TRUST_REFERRED_CONFIRMED contact routed at inboxes we no
            // longer own, and every later re-delivery of their accept hits the
            // terminal unknown-introId drop. Writing first makes the crash window
            // recoverable instead — a rehydrated st=0 record re-sends the SAME
            // material on the next control sweep ([redriveUnsentAccepts]).
            //
            // The Retry guarantee is PRESERVED: the offer is consumed only by
            // confirmAcceptSent, i.e. only once the accept actually left, so a
            // sustained Tor send-drop still leaves the offer in `offers` for the
            // UI's Retry (which now reuses the staged material, above).
            stageAccept(introId, offer, keypair, minted)
            handedOff = true
            val sent = sendReferralControl(
                mgr,
                offer.introducerContactId,
                MessageManager.CONTROL_KIND_REFERRAL_ACCEPT,
                acceptBody(introId, keypair.publicKey, minted),
            )
            if (!sent) { noteAcceptSendFailed(introId); return false }
            // confirmAcceptSent consumes the offer + applies any peer-accept that arrived
            // before us (finalizing immediately), so a referred contact may already exist here.
            confirmAcceptSent(introId)
            return true
        } finally {
            if (!handedOff) keypair.privateKey.secureWipe()
        }
    }

    /** Records our accepted material, then applies a stashed peer-accept if one
     *  arrived before we accepted (finalizing immediately). Split out from
     *  [acceptOffer] so tests can drive finalize with injected key material
     *  (no PoW mint) — it is exactly [stageAccept] + [confirmAcceptSent], i.e.
     *  the send is assumed to have succeeded. */
    internal fun registerAccepted(
        introId: String, offer: ReferralOffer, keypair: X25519Keypair, minted: MintedInboxPair,
    ) {
        stageAccept(introId, offer, keypair, minted)
        confirmAcceptSent(introId)
    }

    /**
     * Parks our freshly-minted handshake material in [pending] and mirrors it to
     * the vault as `st=0` — accepted locally, delivery NOT yet confirmed. The
     * offer is deliberately NOT consumed here (see [acceptOffer]'s Retry note) and a
     * peer accept arriving against an unsent entry is stashed, not finalized.
     */
    private fun stageAccept(
        introId: String, offer: ReferralOffer, keypair: X25519Keypair, minted: MintedInboxPair,
    ) = lock.withLock {
        // Before capInsert drops ANY existing Pending,
        // overwrite that handshake's ephemeral X25519 private key FIRST — capInsert
        // otherwise just drops the map reference (this[key] = value) and leaves the
        // 32 key bytes resident as unreachable heap garbage that scrubInMemory() can
        // no longer find. Two drop paths, both covered here:
        if (introId in pending) {
            // SAME-KEY overwrite — e.g. two concurrent
            // acceptOffer(introId) calls racing past the offer null-check. capInsert
            // replaces the existing Pending in place (no eviction), silently dropping
            // the first racer's live private key. Wipe it before the overwrite.
            pending[introId]?.keypair?.privateKey?.secureWipe()
        } else if (pending.size >= MAX_PENDING) {
            // Eviction: capInsert drops the OLDEST entry to make room for this new
            // introId. Mirror capInsert's eviction target (keys.firstOrNull()) exactly,
            // and take that entry's VAULT record with it so no orphan is left behind.
            pending.keys.firstOrNull()?.let {
                pending[it]?.keypair?.privateKey?.secureWipe()
                dropRecord(ReferralMetaKeys.ACCEPT_PREFIX + it)
            }
        }
        pending.capInsert(introId, Pending(introId, offer.introducerContactId, offer.peerAlias), MAX_PENDING)
        val p = pending[introId]!!
        p.keypair = keypair
        p.minted = minted
        persistAccept(p)
    }

    /**
     * The accept for [introId] provably reached the relay: flip the record to
     * `st=1`, consume the offer (RAM + vault), and apply a peer accept that was
     * stashed while we were still un-sent.
     */
    private fun confirmAcceptSent(introId: String) {
        val stashedBody = lock.withLock {
            val p = pending[introId] ?: return@withLock null
            p.sent = true
            p.sendAttempts = 0
            // Our accept provably reached the relay: activity for this
            // introduction, so the record is re-stamped before it starts
            // waiting on the peer's half.
            val now = clockMs()
            if (withinAbsoluteLifetime(p.firstSeenAt, now)) p.createdAt = now
            persistAccept(p)
            offers.remove(introId)
            dropRecord(ReferralMetaKeys.OFFER_PREFIX + introId)
            // The stash is READ, never consumed here. Removing it from RAM and
            // the vault BEFORE the finalize below would mean a finalize that
            // failed (the retryable vault-write branch, a transient derive
            // failure, or process death between the two) destroyed the peer's
            // accept — and with it this side's only way to complete an
            // introduction the peer had already committed. finalizeFromPeerAccept
            // deletes `ref_a` INSIDE the transaction that commits the contact and
            // drops the RAM entry on each of its terminal branches, so the delete
            // is atomic with the thing that makes it safe.
            //
            // SENDER GUARD (defense-in-depth): a stash may finalize us only when it
            // was relayed by the SAME introducer this pending was created for — the
            // exact check rehydrate's apply loop and handleAccept's live path already
            // enforce (`stashed.fromContactId != p.introducerContactId` /
            // `senderContactId != state.introducerContactId`). The sole stash writer
            // gates on that introducer too, so a mismatch is not reachable over the
            // wire today; this refuses to derive a referred contact from peer material
            // relayed by anyone else even if a future path (or a crafted `ref_a`
            // record) slipped one in. On a mismatch discard the bogus stash (RAM +
            // vault) and fall through to the NO-stash path: `p.sent` is already set,
            // so the genuine peer accept still finalizes afterward via handleAccept
            // live or rehydrate — the mismatch never bricks the pairing.
            val stashed = stashedAccepts[introId]
            if (stashed != null && stashed.fromContactId != p.introducerContactId) {
                platformLogWarn(TAG, "referral stashed accept not from my introducer — discarded")
                stashedAccepts.remove(introId)
                dropRecord(ReferralMetaKeys.STASH_PREFIX + introId)
                null
            } else {
                stashed?.body
            }
        }
        // Apply OUTSIDE the lock (finalizeFromPeerAccept re-acquires it for the
        // whole check-derive-persist). If the peer accepted first, this finalizes
        // us at once.
        if (stashedBody != null) {
            val state = lock.withLock { pending[introId] }
            if (state != null) finalizeFromPeerAccept(state, stashedBody)
        }
    }

    /**
     * The accept for [introId] did not leave. Bump the bounded attempt counter and
     * re-persist; the record and its material are KEPT so both the automatic
     * redrive and a user-driven retry re-send the identical public key. Only the
     * TTL reclaims it, and the budget starts over next session.
     */
    private fun noteAcceptSendFailed(introId: String) = lock.withLock {
        val p = pending[introId] ?: return@withLock
        p.sendAttempts += 1
        // A redrive ATTEMPT is activity for this record — bounded by
        // firstSeenAt so a permanently dead introducer cannot keep an ephemeral
        // X25519 private key alive indefinitely, one session's budget at a time.
        val now = clockMs()
        if (withinAbsoluteLifetime(p.firstSeenAt, now)) p.createdAt = now
        persistAccept(p)
        if (p.sendAttempts >= MAX_ACCEPT_SEND_ATTEMPTS) {
            platformLogWarn(TAG, "referral accept send budget exhausted for this session — retry is now user-driven")
        }
    }

    // -----------------------------------------------------------------------
    // Receive
    // -----------------------------------------------------------------------

    fun handleControl(senderContactId: String, kind: String, body: String) {
        when (kind) {
            MessageManager.CONTROL_KIND_REFERRAL_OFFER  -> handleOffer(senderContactId, body)
            MessageManager.CONTROL_KIND_REFERRAL_ACCEPT -> handleAccept(senderContactId, body)
            else -> platformLogWarn(TAG, "unknown referral kind dropped")
        }
    }

    private fun handleOffer(introducerContactId: String, body: String) {
        val introId = firstStringFieldAnywhere(body, "ii") ?: return
        val rawAlias = firstStringFieldAnywhere(body, "pa") ?: return
        // Only consider offers from a contact we already have (the introducer we
        // chose to pair with) — never a stranger.
        val introducer = vault.getContact(introducerContactId) ?: run {
            platformLogWarn(TAG, "referral offer from unknown contact dropped"); return
        }
        lock.withLock {
            // Ignore a dup / an introId already in flight or completed. The
            // completedIntros guard covers a re-delivery that arrives AFTER we
            // finalized or declined (by then it is in neither offers nor
            // pending), which would otherwise re-create the offer + re-raise the
            // consent alert for a contact we already have.
            if (introId in offers || introId in pending || doneTokenFor(introId) in completedIntros) return
            // Per-introducer cap + hourly rate, BEFORE the global-cap
            // eviction below runs and BEFORE anything is persisted. A dropped
            // offer leaves no trace at all — see [offerAllowed]'s kdoc.
            if (!offerAllowed(introducerContactId, currentTimeMillis())) {
                platformLogWarn(TAG, "referral offer dropped — introducer cap/rate exceeded")
                return
            }
            // Mirror capInsert's eviction target so the dropped offer's vault
            // record goes with it instead of becoming TTL-only residue.
            if (offers.size >= MAX_OFFERS) {
                // Fairness: prefer evicting the INSERTING introducer's own
                // oldest pending offer over any other introducer's. With the
                // per-introducer cap just above now bounding any single sender to
                // MAX_OFFERS_PER_INTRODUCER (well under MAX_OFFERS), reaching the
                // global cap here means many DIFFERENT introducers are each near
                // their own cap — a single sender must never be able to evict a
                // more-trusted introducer's pending consent prompt just by sending
                // one more offer. Falls back to the globally-oldest entry only if
                // this sender has none of their own yet (their very first offer
                // landing while every one of the 128 slots belongs to others).
                val evicted = offers.entries.firstOrNull { it.value.introducerContactId == introducerContactId }?.key
                    ?: offers.keys.firstOrNull()
                evicted?.let {
                    dropRecord(ReferralMetaKeys.OFFER_PREFIX + it)
                    // A stash must not outlive the offer it belonged to: an evicted
                    // offer can never finalize, so any peer-accept stashed against it
                    // is orphaned residue only the TTL would reclaim — co-remove it,
                    // exactly as declineOffer does. KEEP it when a live `pending`
                    // still owns this introId, though: that accept was already staged
                    // and confirmAcceptSent will apply the stash, so dropping it here
                    // would break an in-flight finalize.
                    if (it !in pending) {
                        stashedAccepts.remove(it)
                        dropRecord(ReferralMetaKeys.STASH_PREFIX + it)
                    }
                }
            }
            // `pa` is entirely introducer-controlled and becomes the new
            // contact's ALIAS verbatim at finalize — sanitize it HERE, at the one
            // point every offer (hostile or honest-but-old-client) passes through.
            val peerAlias = sanitizedPeerAlias(rawAlias)
            val offer = ReferralOffer(
                introId, introducerContactId, introducer.alias, peerAlias, currentTimeMillis(),
            )
            offers.capInsert(introId, offer, MAX_OFFERS)
            // Persist at RECEIPT: offer re-delivery from the introducer's inbox
            // exists but is NOT guaranteed within the relay's retention, so an
            // introducee that is backgrounded before consenting must still be able
            // to approve after a relaunch.
            persistOffer(offer)
        }
    }

    /**
     * The referral-offer sibling of
     * `GroupManager.inviteAllowed` — see [MAX_OFFERS_PER_INTRODUCER] /
     * [OFFER_RATE_WINDOW_MS] / [MAX_OFFERS_PER_INTRODUCER_PER_WINDOW]. Returns
     * true (and records the receipt in the rolling window) only if
     * [introducerContactId] is within BOTH the standing per-introducer pending
     * cap AND the hourly rate; false if either is exceeded, and a rejected
     * offer is not charged against the window (no new stamp; a window deny
     * still persists the pruned list). Must be
     * called under [lock] — reads [offers] directly.
     */
    // Deletes every `ref_off_rl:<introducerId>` row whose stamps are ALL outside
    // [OFFER_RATE_WINDOW_MS]. Such a row admits exactly like an absent one, so the
    // delete changes no admission; it only stops the time an introducer last sent an
    // offer (including one the user refused) from staying on disk after the window.
    // A row with a live stamp is untouched. The delete is made under [lock] (where
    // [offerAllowed] runs) and only if the row still holds the value judged stale.
    private fun pruneStaleOfferRateWindows() {
        val now = clockMs()
        for (key in vault.metaKeys()) {
            if (!key.startsWith(ReferralMetaKeys.OFFER_RATE_LIMIT_PREFIX)) continue
            val seen = vault.getMeta(key) ?: continue
            if (!RollingWindow.isSpent(seen, now, OFFER_RATE_WINDOW_MS)) continue
            lock.withLock {
                if (vault.getMeta(key) == seen) dropRecord(key)
            }
        }
    }

    private fun offerAllowed(introducerContactId: String, now: Long): Boolean {
        val pendingFromIntroducer = offers.values.count { it.introducerContactId == introducerContactId }
        if (pendingFromIntroducer >= MAX_OFFERS_PER_INTRODUCER) return false
        val key = ReferralMetaKeys.OFFER_RATE_LIMIT_PREFIX + introducerContactId
        // Brick-safety (matches every other _meta access in this class): a
        // failing store degrades the rate limit to RAM-only (effectively
        // "unlimited" for this session) rather than throwing out of handleOffer
        // and failing an offer the per-introducer STANDING cap above would
        // otherwise still gate.
        val stored = try { vault.getMeta(key) } catch (_: Exception) { null }
        val admission = RollingWindow.admit(stored, now, OFFER_RATE_WINDOW_MS, MAX_OFFERS_PER_INTRODUCER_PER_WINDOW)
        putRecord(key, admission.persist)
        return admission.allowed
    }

    /**
     * Returns an alias that (a) conforms to
     * [ContactAliasGenerator.matchesGeneratedFormat] — a `pa` from a hostile OR
     * merely out-of-date introducer is REPLACED with a freshly generated alias
     * rather than rejecting the whole offer (the introducer's client may just be
     * old), which also disposes of every exotic-Unicode/control-char/empty
     * input in one strict format check — and (b) does not visually collide
     * (case-insensitively, after [ContactAliasGenerator.normalizeForCompare])
     * with any EXISTING contact's alias, so a Sybil-named introduction can never
     * shadow a real contact in the UI. Re-rolls locally up to
     * [MAX_ALIAS_REROLL_ATTEMPTS] times on collision, then disambiguates with a
     * numeric suffix as a last resort (astronomically unlikely to be needed at
     * 1,620 possible generated aliases).
     */
    private fun sanitizedPeerAlias(rawAlias: String): String {
        val existing = vault.getAllContacts()
            .map { ContactAliasGenerator.normalizeForCompare(it.alias) }
            .toHashSet()
        var candidate = rawAlias.take(MAX_ALIAS_CHARS)
        if (!ContactAliasGenerator.matchesGeneratedFormat(candidate)) {
            candidate = ContactAliasGenerator.generate()
        }
        if (ContactAliasGenerator.normalizeForCompare(candidate) !in existing) return candidate
        repeat(MAX_ALIAS_REROLL_ATTEMPTS) {
            val rerolled = ContactAliasGenerator.generate()
            if (ContactAliasGenerator.normalizeForCompare(rerolled) !in existing) return rerolled
        }
        var suffixed = candidate
        var n = 2
        while (ContactAliasGenerator.normalizeForCompare(suffixed) in existing) {
            suffixed = "$candidate $n"
            n++
        }
        return suffixed
    }

    private fun handleAccept(senderContactId: String, body: String) {
        val introId = firstStringFieldAnywhere(body, "ii") ?: return

        // INTRODUCER role: relay this accept verbatim to the other party.
        //
        // [alreadyRelayed] is read under the SAME lock as the session lookup —
        // `relayed` is mutable shared state. A blob sits in our control inbox for
        // its relay retention and is re-delivered on later polls, and a malicious
        // contact can re-send its OWN already-relayed accept indefinitely, so this
        // gates the relay ATTEMPT itself, not just the UI signal below:
        // re-forwarding a leg that is already marked relayed would push-bomb the
        // OTHER party through us on every redelivery. A forward that genuinely
        // failed is never in `relayed`, so it is unaffected here and recovers
        // through the persisted `relayRedrives` sweep ([redriveUnrelayedAccepts]),
        // not through re-forwarding an inbound accept.
        var alreadyRelayed = false
        val session = lock.withLock {
            introSessions[introId]?.also { alreadyRelayed = senderContactId in it.relayed }
        }
        if (session != null) {
            if (alreadyRelayed) return
            relayAcceptAsIntroducer(session, senderContactId, introId, body)
            return
        }

        // INTRODUCEE role: the peer's accept, relayed to me by my introducer.
        // An entry that is present but NOT yet `sent` is deliberately treated as
        // "not accepted yet": our own material has not provably reached the peer,
        // so committing a contact now could pair us against a peer that never
        // finalizes. Stash and let confirmAcceptSent apply it.
        val state = lock.withLock { pending[introId]?.takeIf { it.sent } }
        if (state == null) {
            stashEarlyPeerAccept(introId, senderContactId, body)
            return
        }
        if (senderContactId != state.introducerContactId) {
            platformLogWarn(TAG, "referral accept not from my introducer dropped"); return
        }
        finalizeFromPeerAccept(state, body)
    }

    /** INTRODUCER role: forwards [body] verbatim to the OTHER party of [session], or
     *  records a persisted redrive obligation when the forward does not leave. The
     *  caller has already returned for a leg that is marked relayed. */
    private fun relayAcceptAsIntroducer(session: IntroSession, senderContactId: String, introId: String, body: String) {
        val other = when (senderContactId) {
            session.contactA -> session.contactB
            session.contactB -> session.contactA
            else -> { platformLogWarn(TAG, "accept from a non-party dropped"); return }
        }
        // A forward that never left (Tor drop / cold circuit / no outbound row
        // yet) must not swallow the introduction: record a bounded redrive
        // obligation — persisted, so it also survives the introducer being
        // backgrounded.
        val relayed = try {
            messageManager()?.let {
                sendReferralControl(it, other, MessageManager.CONTROL_KIND_REFERRAL_ACCEPT, body)
            } ?: false
        } catch (e: Exception) {
            platformLogWarn(TAG, "referral relay threw: ${e::class.simpleName}"); false
        }
        var complete = false
        lock.withLock {
            if (relayed) {
                complete = noteRelayDeliveredLocked(introId, senderContactId)
            } else {
                val key = redriveKey(introId, other)
                if (relayRedrives.size >= MAX_RELAY_REDRIVES && key !in relayRedrives) {
                    relayRedrives.keys.firstOrNull()?.let {
                        relayRedrives.remove(it)
                        dropRecord(ReferralMetaKeys.REDRIVE_PREFIX + it)
                    }
                }
                val r = RelayRedrive(introId, other, senderContactId, body)
                relayRedrives[key] = r
                persistRedrive(r)
                // An accept ARRIVED for this session — activity, even though
                // the forward failed. Without this the session could age
                // out while its own redrive obligation was still retrying.
                introSessions[introId]?.let {
                    touchSessionLocked(it)
                    persistSession(introId, it)
                }
                platformLogWarn(TAG, "referral relay failed — queued for redrive")
            }
        }
        // RAM-only UI signal, fired OUTSIDE the lock and AFTER the obligation
        // has been recorded, so the hook can never observe a half-committed
        // session. `relayed == false` still fires: from the introducer's side
        // the approval DID arrive and is durably queued, which is what the UI
        // must say. A re-delivery for a side already forwarded returned above,
        // before this point, so `alreadyRelayed` is always false here.
        fireIntroRelayed(introId, senderContactId, other, relayed, complete)
    }

    /**
     * INTRODUCEE role, before our own accept has provably left: if [senderContactId]
     * is the introducer who offered [introId], stash the peer's accept so
     * [confirmAcceptSent] / acceptOffer can apply it once we mint our own
     * material; otherwise drop it.
     */
    private fun stashEarlyPeerAccept(introId: String, senderContactId: String, body: String) {
        val expectedIntroducer = lock.withLock {
            offers[introId]?.introducerContactId ?: pending[introId]?.introducerContactId
        }
        if (expectedIntroducer == null) {
            platformLogWarn(TAG, "referral accept for unknown introId dropped"); return
        }
        if (senderContactId != expectedIntroducer) {
            platformLogWarn(TAG, "referral accept not from my introducer dropped"); return
        }
        lock.withLock {
            val now = clockMs()
            // Age out anything past its TTL first (housekeeping).
            val expired = stashedAccepts.filterValues { now - it.stampMs > REFERRAL_RECORD_TTL_MS }.keys.toList()
            for (id in expired) {
                stashedAccepts.remove(id); dropRecord(ReferralMetaKeys.STASH_PREFIX + id)
            }
            // At cap with a genuinely new introId → evict the OLDEST so this
            // fresh accept survives; dropping the incoming one would let stale
            // entries starve real ones.
            if (stashedAccepts.size >= MAX_STASHED_ACCEPTS && introId !in stashedAccepts) {
                stashedAccepts.minByOrNull { it.value.stampMs }?.key?.let {
                    stashedAccepts.remove(it); dropRecord(ReferralMetaKeys.STASH_PREFIX + it)
                }
            }
            // FIRST-SEEN sticks: a re-delivered accept keeps the stamp of the stash it
            // replaces (only an ABSENT stash is stamped `now`). The stamp is both the
            // stash's idle and its absolute bound (gcExpired/rehydrate pass it as
            // createdAt AND firstSeenAt), so re-stamping it here would let a relay
            // re-delivering every few days keep a stash alive indefinitely.
            val firstSeen = stashedAccepts[introId]?.stampMs ?: now
            val s = StashedAccept(body, firstSeen, senderContactId)
            stashedAccepts[introId] = s
            persistStash(introId, s)
            // The peer has provably accepted, so this introduction is
            // LIVE — re-stamp whichever of our own halves is waiting (an
            // un-consented offer, and/or staged-but-unsent accept material).
            // Without this the half that is merely waiting on a slow human
            // could age out while the other half already committed a
            // TRUST_REFERRED_CONFIRMED contact: the half-pair, exactly.
            refreshOfferLocked(introId, now)
            refreshAcceptLocked(introId, now)
        }
        platformLog(TAG, "referral peer-accept arrived before our consent — stashed")
    }

    /** Derives the shared key from a peer's relayed accept and persists the new
     *  referred contact (trustLevel TRUST_REFERRED_CONFIRMED — transitive trust,
     *  usable immediately) + its four to six inbox records. No-op if already finalized or
     *  our own accept material is missing. */
    private fun finalizeFromPeerAccept(state: Pending, body: String) {
        val committed = finalizeFromPeerAcceptInner(state, body)
        // Outside the lock, after the transaction committed — see [onIntroFinalized].
        if (committed) notifyIntroFinalized()
    }

    /**
     * Settles [state] as TERMINAL: marks it finalized, drops its RAM entries,
     * tombstones the introId (a re-delivered offer/accept is then dropped) and
     * wipes the ephemeral private key — in that order. [dropVaultRecords] is true
     * on the rejection branches, where nothing was written so the vault mirror
     * must be deleted here; false on success, where the commit transaction
     * already deleted `ref_p`/`ref_a`/`ref_o` atomically with the contact.
     * Caller holds [lock].
     */
    private fun settleIntroLocked(state: Pending, kp: X25519Keypair, dropVaultRecords: Boolean) {
        state.finalized = true; pending.remove(state.introId); stashedAccepts.remove(state.introId)
        if (dropVaultRecords) dropHandshakeRecordsLocked(state.introId)
        markIntroCompleted(state.introId)
        kp.privateKey.secureWipe()
    }

    /** The peer's half of a relayed accept, after every shape / collision check. */
    private class PeerAccept(
        val pub: ByteArray,
        val inbox: String,
        val wc: String,
        val ctlInbox: String,
        val ctlWc: String,
        /** Both-or-neither: [parsePeerAccept] drops a half-present pair. */
        val grpInbox: String?,
        val grpWc: String?,
    )

    /**
     * Parses and SHAPE-validates the peer's material in a relayed accept against
     * our own [minted] pair. Pure (no vault, no RAM state); returns null, after the
     * same warn line the inline checks always logged, on anything malformed.
     */
    private fun parsePeerAccept(body: String, minted: MintedInboxPair): PeerAccept? {
        val peerPubB64 = firstStringFieldAnywhere(body, "pk") ?: return null
        val peerInbox  = firstStringFieldAnywhere(body, "ib") ?: return null
        val peerWc     = firstStringFieldAnywhere(body, "wc") ?: return null
        val peerCtlInbox = firstStringFieldAnywhere(body, "cib") ?: return null
        val peerCtlWc    = firstStringFieldAnywhere(body, "cwc") ?: return null
        // OPTIONAL, both-or-neither: a peer on a pre-group-inbox build (or one
        // finalizing a stored accept minted before it) simply omits them, and the
        // referred contact then sends group text down the text inbox — the same
        // fallback every other carrier uses. A HALF-present pair is malformed and
        // drops the whole accept, exactly as a malformed ctl pair would.
        val peerGrpInbox = firstStringFieldAnywhere(body, "gib")
        val peerGrpWc    = firstStringFieldAnywhere(body, "gwc")
        if ((peerGrpInbox == null) != (peerGrpWc == null)) {
            platformLogWarn(TAG, "referral peer sent a half-present group inbox pair — dropped")
            return null
        }
        val peerPub = try { decodeBase64(peerPubB64) } catch (_: Exception) { return null }
        if (peerPub.size != 32) { platformLogWarn(TAG, "bad peer pubkey dropped"); return null }
        // SHAPE-validate the peer's inbox ids + write-caps
        // (not just non-empty) before persisting them for a TRUST_REFERRED_
        // CONFIRMED contact — otherwise a malformed value gets stored and the
        // new contact is permanently un-sendable (referral has no re-pair UX).
        // Mirror applyInboxAnnounce/parseMintResponse's isValidInboxId +
        // isValidCapability gate.
        if (!isValidInboxId(peerInbox) || !isValidInboxId(peerCtlInbox) ||
            !isValidCapability(peerWc) || !isValidCapability(peerCtlWc)) {
            platformLogWarn(TAG, "referral peer inbox/cap failed shape validation — dropped")
            return null
        }
        if (peerGrpInbox != null && peerGrpWc != null &&
            (!isValidInboxId(peerGrpInbox) || !isValidCapability(peerGrpWc))) {
            platformLogWarn(TAG, "referral peer group inbox/cap failed shape validation — dropped")
            return null
        }
        // And they must differ from OUR freshly-minted ids — a confused/hostile
        // peer echoing ours back would collide our own inbox rows. Extended to the
        // third id on BOTH sides: all of the peer's must be pairwise distinct and
        // none may equal any of ours.
        val ourIds = listOfNotNull(minted.main.inboxId, minted.ctl.inboxId, minted.grp?.inboxId)
        val peerIds = listOfNotNull(peerInbox, peerCtlInbox, peerGrpInbox)
        if (peerIds.any { it in ourIds }) {
            platformLogWarn(TAG, "referral peer inbox id collides with ours — dropped")
            return null
        }
        // The peer's OWN (up to three) inbox ids must also differ from each
        // other. A peer announcing the same id for its main and control inboxes
        // (with different caps) writes two outbound records sharing one inboxId —
        // the new contact's channel is then broken with no re-pair UX. Self-
        // sabotage only, but cheap to reject up front.
        if (peerIds.size != peerIds.toSet().size) {
            platformLogWarn(TAG, "referral peer announced the same id for two inboxes — dropped")
            return null
        }
        return PeerAccept(peerPub, peerInbox, peerWc, peerCtlInbox, peerCtlWc, peerGrpInbox, peerGrpWc)
    }

    /** ECDH(our ephemeral private key, [peerPub]) → HKDF bound to [introId]; null (after
     *  the warn) on a rejected peer key. The raw ECDH output is wiped here; the caller
     *  owns — and must wipe — the returned key. */
    private fun deriveReferralKey(kp: X25519Keypair, peerPub: ByteArray, introId: String): ByteArray? {
        // Derive the contact key from ECDH(myPriv, peerPub). x25519EcdhChecked
        // rejects a low-order peer key (all-zero shared secret) so a malicious
        // introducer can't force an introducer-known key — drop the handshake
        // on any failure rather than establishing a degenerate channel.
        return try {
            // Bind the derivation to THIS referral's introId
            // (a fresh per-referral identifier both parties share) so the derived
            // key is transcript-specific — defense-in-depth against any cross-
            // referral key confusion. Both sides compute the identical info from
            // the identical introId; a mismatched introId just fails the handshake
            // (introducer self-DoS), never derives a shared key.
            // Wipe the raw ECDH output once HKDF has consumed it,
            // matching DoubleRatchet/MessageManager key hygiene.
            val ecdh = x25519EcdhChecked(kp.privateKey, peerPub)
            try { hkdfSha256(ecdh, ByteArray(0), (HKDF_INFO + "|" + introId).encodeToByteArray(), 32) }
            finally { ecdh.secureWipe() }
        } catch (_: Exception) {
            platformLogWarn(TAG, "referral ECDH rejected (low-order/invalid peer key)")
            null
        }
    }

    private fun finalizeFromPeerAcceptInner(state: Pending, body: String): Boolean {
        // The WHOLE check-derive-persist-set runs under the lock (double-finalize
        // TOCTOU). Two callers race into here — the stashed-accept
        // apply from acceptOffer's IO coroutine and the background control poller —
        // and checking `finalized` at the top but setting it only at the bottom
        // would let BOTH pass the check and insert a SECOND, dangling referred
        // contact for one introduction. Holding the lock
        // across the check, the ECDH derive, the vault inserts, and the flip makes
        // the loser see finalized=true and return. Any early return / failure
        // leaves finalized=false so a later valid accept still retries. The lock is
        // held across the vault writes (a rare, ~ms one-time op); the vault has its
        // OWN separate lock and never calls back into ReferralManager, and both
        // callers release THIS lock before calling here, so there is no
        // re-entrancy/deadlock (note SyncLock is NSLock — non-reentrant — on iOS).
        lock.withLock {
            if (state.finalized) return false
            val kp = state.keypair ?: return false // haven't accepted yet — nothing to derive with
            val minted = state.minted ?: return false

            val peer = parsePeerAccept(body, minted) ?: return false
            val shared = deriveReferralKey(kp, peer.pub, state.introId) ?: return false

            // `shared` IS the new contact's message-encryption
            // key (ContactRecord.sharedSecret). SQLCipher copies the blob at insert time, so
            // once the persist below has run `shared` is pure RAM residue — and on the
            // already-exists and persist-failure exits it is never persisted at all. The
            // finally below wipes it on every exit from this block (the kp.privateKey
            // wipe already covers the ephemeral key).
            try {
                // Deterministic id (idempotent retry) — see [referredContactIdFor].
                val contactId = referredContactIdFor(state.introId)
                // NEVER let a referral finalize OVERWRITE an existing contact.
                // insertContact is INSERT-OR-REPLACE and contactId is deterministic from the
                // introId, so a benign re-driven finalize OR a malicious introducer who crafts
                // an introId colliding with a REAL contact's id would both replace that
                // contact's material (a hijack). The finalize is atomic (withTransaction below),
                // so a pre-existing row is always a COMPLETE contact — skip the persist, but
                // still run the normal cleanup (mark completed + wipe the ephemeral key) so
                // the re-drive settles instead of looping.
                if (vault.getContact(contactId) != null) {
                    platformLogWarn(TAG, "referral finalize: contact already exists — not overwriting")
                    settleIntroLocked(state, kp, dropVaultRecords = true)
                    return false
                }
                when (commitReferredContactLocked(state, kp, peer, minted, shared, contactId, body)) {
                    // TERMINAL, not retryable: settle exactly like the already-exists
                    // branch above — nothing was written, so no stranded contact/inbox
                    // rows are left behind. (`shared` is wiped by the enclosing finally.)
                    CommitOutcome.INBOX_IN_USE -> {
                        settleIntroLocked(state, kp, dropVaultRecords = true)
                        return false
                    }
                    // RETRYABLE: `finalized` stays false AND the vault mirror stays in
                    // place, so a later re-delivery (or the next launch) re-drives it.
                    CommitOutcome.FAILED -> return false
                    CommitOutcome.COMMITTED -> Unit
                }
                // The ephemeral referral private key has done its one job (deriving
                // `shared`); the commit transaction already deleted the vault mirror.
                settleIntroLocked(state, kp, dropVaultRecords = false)
                platformLog(TAG, "referral finalized: new vouched contact committed")
                // The ONE true-returning exit: the transaction above committed, so a
                // referred contact now exists. Every other exit returns false and the
                // [onIntroFinalized] hook stays silent.
                return true
            } finally {
                // Zero the derived contact key on the success, already-exists, AND
                // persist-failure exits — the SQLCipher copy is the only one that survives.
                shared.secureWipe()
            }
        }
    }

    private enum class CommitOutcome { COMMITTED, INBOX_IN_USE, FAILED }

    // The finalize's ONE atomic batch: the claim check (FIRST statement), the
    // contact row, its 4-6 inbox rows, the ratchet marker, the role inputs and the
    // deletion of the handshake mirror (`ref_p`/`ref_a`/`ref_o`; the introducer-side
    // `ref_s` session is not ours to delete). Caller holds
    // `lock` and owns [shared] (it wipes it on every exit). [INBOX_IN_USE] is
    // terminal (the conflict is deterministic in the ids); [FAILED] is retryable.
    private fun commitReferredContactLocked(
        state: Pending,
        kp: X25519Keypair,
        peer: PeerAccept,
        minted: MintedInboxPair,
        shared: ByteArray,
        contactId: String,
        body: String,
    ): CommitOutcome {
        val now = currentTimeMillis()
        val life = VaultSeedDefaults.INBOX_LIFETIME_MS
        try {
            // The contact row + its 4-6 inbox rows + the ratchet
            // marker are ONE atomic batch. A torn write (backgrounding / lock
            // contention) would leave an orphan contact with a live sharedSecret
            // and/or half its capability rows; withTransaction commits all-or-nothing.
            vault.withTransaction {
                // `inbox_ids` is keyed by inboxId with replace-on-conflict, so any
                // of the (four to six) ids below that already exists would SILENTLY overwrite
                // that row — reassigning a live contact's route to this referral and
                // destroying its capability. The guards above only compare the peer's
                // ids against THIS referral's own mint; they never look at the vault.
                // Checked INSIDE the transaction because `lock` is not held by the
                // control poller, so a pre-transaction check could race an inbox
                // announce. A rejection writes NOTHING (first statement + rollback).
                firstUnavailableInboxClaim(vault, inboxClaimsFor(contactId, minted, peer))
                    ?.let { throw InboxInUseException() }
                vault.insertContact(referredContactRecord(contactId, state, shared, now))
                insertReferredInboxRowsInTxn(contactId, minted, peer, now, life)
                // Mark ratchet-capable so the text channel gets
                // FORWARD SECRECY, exactly like the QR/paste path (PairingVault.
                // savePairedContact). Without this a referred contact stayed on the
                // static AES-GCM envelope forever (key = sha256(sharedSecret)), so a
                // later seizure would decrypt all its past + future traffic.
                MessageManager.markRatchetCapable(vault, contactId)
                // The referral path has no symmetric secret halves, so
                // the role order is tied to the two ephemeral X25519 PUBLIC keys —
                // the same construction, over the only pair of values that (a) both
                // devices hold, (b) are opposite on the two devices and (c) can
                // never change after this transaction. `kp.publicKey` is OURS,
                // `peer.pub` is the accept's `pk` we just derived against, so the two
                // devices see the same unordered pair and get complementary bits.
                // Written INSIDE this transaction so the role input cannot outlive a
                // rolled-back contact (or vice versa). Absent `rv` ⇒ id-order rule.
                MessageManager.recordRatchetRoleInputs(
                    vault, contactId, kp.publicKey, peer.pub,
                    peerRunsRoleRuleV2 = firstStringFieldAnywhere(body, ROLE_RULE_FIELD) == ROLE_RULE_V2,
                )
                // The handshake mirror dies INSIDE the same transaction that
                // commits the contact: either the contact exists and the
                // ephemeral private key is gone, or neither happened. A delete
                // outside would leave a live X25519 private key + our inbox
                // read-caps in `_meta` for up to the record TTL after the key
                // had already done its one job.
                vault.deleteMeta(ReferralMetaKeys.ACCEPT_PREFIX + state.introId)
                vault.deleteMeta(ReferralMetaKeys.STASH_PREFIX + state.introId)
                vault.deleteMeta(ReferralMetaKeys.OFFER_PREFIX + state.introId)
            }
        } catch (_: InboxInUseException) {
            // One of the claimed ids is already owned here.
            platformLogWarn(TAG, "referral finalize: an inbox id in this referral is already owned here — rejected")
            return CommitOutcome.INBOX_IN_USE
        } catch (e: Exception) {
            platformLogError(TAG, "referral finalize persist failed: ${e::class.simpleName}")
            return CommitOutcome.FAILED
        }
        return CommitOutcome.COMMITTED
    }

    // The referred contact's inbox rows, in the order they were always written:
    // our two minted inbound rows (our read caps), the peer's two outbound rows (its
    // write caps), then each half of the optional GROUP pair. Only ever called
    // inside [commitReferredContactLocked]'s transaction, after the claim check.
    private fun insertReferredInboxRowsInTxn(
        contactId: String, minted: MintedInboxPair, peer: PeerAccept, now: Long, life: Long,
    ) {
        // Inbound = our freshly-minted inboxes (we poll these, with our read-caps).
        vault.insertInboxId(InboxIdRecord(minted.main.inboxId, contactId, now, now + life, "inbound", minted.main.readCapability))
        vault.insertInboxId(InboxIdRecord(minted.ctl.inboxId, contactId, now, now + life, MessageManager.DIR_INBOUND_CTL, minted.ctl.readCapability))
        // Outbound = the peer's inboxes (we send here, with the peer's write-caps).
        vault.insertInboxId(InboxIdRecord(peer.inbox, contactId, now, now + life, "outbound", peer.wc))
        vault.insertInboxId(InboxIdRecord(peer.ctlInbox, contactId, now, now + life, MessageManager.DIR_OUTBOUND_CTL, peer.ctlWc))
        // The GROUP pair, each half independently optional: we may hold a
        // stored accept with no grp mint, and the peer may be on a build
        // that announces none. Either absence degrades to the text-inbox
        // fallback and never blocks the referral.
        minted.grp?.let {
            vault.insertInboxId(InboxIdRecord(it.inboxId, contactId, now, now + life, MessageManager.DIR_INBOUND_GRP, it.readCapability))
        }
        if (peer.grpInbox != null && peer.grpWc != null) {
            vault.insertInboxId(InboxIdRecord(peer.grpInbox, contactId, now, now + life, MessageManager.DIR_OUTBOUND_GRP, peer.grpWc))
        }
    }

    // The 4 + 0..2 inbox ids a referral finalize claims for [contactId]: our two
    // minted inbound rows, the peer's two outbound rows, and each half of the
    // optional GROUP pair (ours if we minted one, the peer's if it announced both
    // `gib` and its write cap). Pure; the order is the one the claim check reports in.
    private fun inboxClaimsFor(contactId: String, minted: MintedInboxPair, peer: PeerAccept): List<InboxClaim> =
        listOf(
            InboxClaim(minted.main.inboxId, contactId, "inbound"),
            InboxClaim(minted.ctl.inboxId, contactId, MessageManager.DIR_INBOUND_CTL),
            InboxClaim(peer.inbox, contactId, "outbound"),
            InboxClaim(peer.ctlInbox, contactId, MessageManager.DIR_OUTBOUND_CTL),
        ) + listOfNotNull(
            minted.grp?.let { InboxClaim(it.inboxId, contactId, MessageManager.DIR_INBOUND_GRP) },
            if (peer.grpInbox != null && peer.grpWc != null)
                InboxClaim(peer.grpInbox, contactId, MessageManager.DIR_OUTBOUND_GRP) else null,
        )

    // The referred contact's row. Writes nothing; it reads the vault only through
    // [sanitizedPeerAlias]'s collision check, so it is called inside the finalize
    // transaction, before the inserts.
    private fun referredContactRecord(contactId: String, state: Pending, shared: ByteArray, now: Long): ContactRecord =
        ContactRecord(
            contactId = contactId,
            sharedSecret = shared,
            // Transitive trust: the introducer is someone we already
            // trust, so a referred contact is usable immediately (no
            // verification step). vouchedByContactId records the
            // provenance for display.
            trustLevel = VaultSeedDefaults.TRUST_REFERRED_CONFIRMED,
            // Re-validated at INSERT too, not just at offer
            // receipt — a no-op for the normal path (handleOffer
            // already sanitized it), but it closes two gaps a
            // receipt-only check can't: (1) a contact added between
            // offer-receipt and finalize could have since collided
            // with the alias, and (2) a record rehydrated from
            // before the insert-time check existed may still carry a raw,
            // never-validated alias.
            alias = sanitizedPeerAlias(state.peerAlias),
            aliasLastRotated = now,
            vouchedByContactId = state.introducerContactId,
            vouchedAt = now,
        )

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private fun offerBody(introId: String, peerAlias: String): String =
        """{"ii":${jsonEscapeString(introId)},"pa":${jsonEscapeString(peerAlias)}}"""

    /**
     * The accept body carries the OPTIONAL role-rule marker
     * `"rv":"2"`, appended last.
     *
     * The ACCEPT is the right carrier and the OFFER is not: an offer is composed by
     * the INTRODUCER, so its `rv` would describe the introducer's build, which has
     * no bearing on which rule the two INTRODUCEES apply to each other. An accept is
     * the peer's own message, relayed verbatim, and it is the message
     * [finalizeFromPeerAcceptInner] already consumes to derive the contact — so the
     * evidence and the derivation arrive together, atomically.
     *
     * An older peer omits it, [firstStringFieldAnywhere] answers null, and both sides keep the id-order
     * rule. A malicious introducer can STRIP it (it relays the body), which downgrades
     * the pair to the id-order rule — i.e. to the status quo ante, not to a collision,
     * because it can only strip it symmetrically or make one side fail to finalize.
     */
    // `internal`, not `private`, ONLY so the optional `rv` marker can be pinned
    // directly: it is the one of the three carriers whose emitted
    // bytes have no round-trip in a test — the QR is pinned through
    // `PairingPayload.parse` and the announce through `applyInboxAnnounce`. Pure
    // string building, no state, and `internal` keeps it off the Swift surface.
    internal fun acceptBody(introId: String, pub: ByteArray, minted: MintedInboxPair): String {
        // The GROUP pair is OPTIONAL on the wire for exactly one reason: a
        // [StoredAccept] rehydrated from before the group inbox existed carries no
        // `grp`, and that record is a LIVE handshake — refusing it (or fabricating
        // an id) would strand the introduction. Absent ⇒ the peer writes no
        // `outbound-grp` row ⇒ group text rides the text inbox, i.e. today.
        val grpPart = minted.grp?.let {
            """"gib":${jsonEscapeString(it.inboxId)},"gwc":${jsonEscapeString(it.writeCapability)},"""
        } ?: ""
        return """{"ii":${jsonEscapeString(introId)},"pk":${jsonEscapeString(encodeBase64(pub))},""" +
            """"ib":${jsonEscapeString(minted.main.inboxId)},"wc":${jsonEscapeString(minted.main.writeCapability)},""" +
            """"cib":${jsonEscapeString(minted.ctl.inboxId)},"cwc":${jsonEscapeString(minted.ctl.writeCapability)},""" +
            grpPart +
            """${jsonEscapeString(ROLE_RULE_FIELD)}:${jsonEscapeString(ROLE_RULE_V2)}}"""
    }
}
